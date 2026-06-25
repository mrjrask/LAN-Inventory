#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Sequence, Tuple

OUTPUT_CSV = "network_inventory.csv"
# nmap populates this from the MAC address OUI when it can see the device MAC.
RASPBERRY_PI_MANUFACTURER_KEYWORDS = (
    "raspberry pi",
    "raspberry pi foundation",
    "raspberry pi trading",
)
RASPBERRY_PI_HOSTNAME_KEYWORDS = (
    "raspberrypi",
    "raspberry-pi",
    "raspberry_pi",
    "rpi",
)


def require_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        print(f"ERROR: Required tool '{tool}' not found. Install it first.", file=sys.stderr)
        sys.exit(2)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local IPv4 networks and inventory discovered LAN hosts."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Maximum seconds to allow each network scan to run. Skips the interactive prompt.",
    )
    parser.add_argument(
        "--raspberry-pis",
        "--pis",
        action="store_true",
        help="Show only likely Raspberry Pi devices with their IP addresses and hostnames.",
    )
    return parser.parse_args(argv)


def get_timeout_seconds(args: argparse.Namespace, default: int = 600) -> int:
    if args.timeout is None:
        return prompt_timeout_seconds(default=default)
    if args.timeout <= 0:
        raise ValueError("--timeout must be a positive integer.")
    return args.timeout


def prompt_timeout_seconds(default: int = 600) -> int:
    while True:
        raw = input(f"How many seconds should the scan run for? [{default}]: ").strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if val <= 0:
                print("Please enter a positive integer.")
                continue
            return val
        except ValueError:
            print("Please enter a valid integer (seconds).")


def _parse_default_interface(route_output: str) -> str:
    for line in route_output.splitlines():
        line = line.strip()
        if " dev " in line:
            parts = line.split()
            if "dev" in parts:
                dev_index = parts.index("dev")
                if dev_index + 1 < len(parts):
                    return parts[dev_index + 1]
    return ""


def _parse_ip_addr(ip_output: str) -> str:
    for line in ip_output.splitlines():
        line = line.strip()
        if " inet " not in line:
            continue
        parts = line.split()
        if "inet" in parts:
            inet_index = parts.index("inet")
            if inet_index + 1 < len(parts):
                return parts[inet_index + 1]
    return ""


def get_active_network_cidr() -> str:
    system = platform.system()
    if system != "Linux":
        raise RuntimeError(f"Unsupported platform: {system}")

    require_tool("ip")

    route_cp = subprocess.run(
        ["ip", "route", "show", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    interface = _parse_default_interface(route_cp.stdout)
    if not interface:
        raise RuntimeError("Could not determine default network interface.")

    ip_cp = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show", "dev", interface],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    inet = _parse_ip_addr(ip_cp.stdout)
    if not inet:
        raise RuntimeError(f"Could not determine IPv4 network for interface {interface}.")

    network = ipaddress.ip_interface(inet).network
    return str(network)


def _parse_ip_route_routes(route_output: str) -> List[ipaddress.IPv4Network]:
    networks: List[ipaddress.IPv4Network] = []
    for line in route_output.splitlines():
        line = line.strip()
        if not line or line.startswith("default"):
            continue
        destination = line.split()[0]
        if "/" not in destination:
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        networks.append(network)
    return networks


def get_scan_networks() -> List[str]:
    primary_network = ipaddress.ip_network(get_active_network_cidr(), strict=False)
    networks = {primary_network}

    route_cp = subprocess.run(
        ["ip", "route", "show"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    for network in _parse_ip_route_routes(route_cp.stdout):
        if network.is_loopback or network.is_unspecified:
            continue
        if not (network.is_private or network.is_link_local):
            continue
        networks.add(network)

    return [str(n) for n in sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))]


def run_nmap_scan(network: str, timeout_s: int) -> str:
    require_tool("nmap")

    cmd = ["nmap", "-sn", network, "-oX", "-"]

    def _run_scan(scan_cmd: List[str]) -> subprocess.CompletedProcess[str]:
        print(f"Running scan: {' '.join(scan_cmd)}")
        return subprocess.run(
            scan_cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )

    start = time.time()

    try:
        cp = _run_scan(cmd)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Scan exceeded timeout of {timeout_s} seconds")

    retry_triggers = (
        "Required key not available",
        "Destination address required",
    )
    should_retry_unprivileged = any(trigger in cp.stderr for trigger in retry_triggers)
    if should_retry_unprivileged:
        print(
            "Detected kernel policy/routing errors for raw ICMP probes; "
            "retrying with unprivileged TCP ping probes.",
            file=sys.stderr,
        )
        try:
            cp = _run_scan(
                [
                    "nmap",
                    "--unprivileged",
                    "-sn",
                    "-PS22,80,443",
                    "-PA22,80,443",
                    network,
                    "-oX",
                    "-",
                ]
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Scan exceeded timeout of {timeout_s} seconds")

    elapsed = time.time() - start

    if cp.returncode != 0 and not cp.stdout.strip():
        raise RuntimeError(
            f"nmap failed (exit {cp.returncode}).\n"
            f"stderr:\n{cp.stderr.strip()}"
        )

    if cp.stderr.strip():
        print(f"[nmap stderr]\n{cp.stderr.strip()}", file=sys.stderr)

    print(f"Scan completed in {elapsed:.1f} seconds. Parsing results...")
    return cp.stdout


def reverse_dns(ip: str) -> str:
    """
    Reverse DNS (PTR) lookup. Returns '' if none.
    """
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name or ""
    except Exception:
        return ""


def parse_nmap_xml(xml_text: str) -> List[Dict[str, str]]:
    root = ET.fromstring(xml_text)
    results: List[Dict[str, str]] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""

        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.get("addr", "") or ""
            elif addrtype == "mac":
                mac = addr.get("addr", "") or ""
                vendor = addr.get("vendor", "") or ""

        if not ip:
            continue

        # "hostname" from nmap (can be DNS, mDNS, NetBIOS depending on environment)
        nmap_hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                nmap_hostname = hn.get("name", "") or ""

        dns_name = reverse_dns(ip)

        results.append(
            {
                "ip_address": ip,
                "hostname": nmap_hostname,
                "dns_name": dns_name,
                "mac_address": mac,
                "manufacturer": vendor,
            }
        )

    def ip_sort_key(item: Dict[str, str]) -> Tuple[int, int, int, int]:
        ip_obj = ipaddress.ip_address(item["ip_address"])
        return tuple(int(o) for o in str(ip_obj).split("."))

    results.sort(key=ip_sort_key)
    return results


def is_likely_raspberry_pi(row: Dict[str, str]) -> bool:
    manufacturer = row.get("manufacturer", "").lower()
    hostname = row.get("hostname", "").lower()
    dns_name = row.get("dns_name", "").lower()

    return any(keyword in manufacturer for keyword in RASPBERRY_PI_MANUFACTURER_KEYWORDS) or any(
        keyword in name
        for keyword in RASPBERRY_PI_HOSTNAME_KEYWORDS
        for name in (hostname, dns_name)
    )


def filter_raspberry_pis(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [row for row in rows if is_likely_raspberry_pi(row)]


def print_raspberry_pi_summary(rows: List[Dict[str, str]]) -> None:
    if not rows:
        print("No likely Raspberry Pi devices found.")
        return

    print("\nLikely Raspberry Pi Devices:")
    for row in rows:
        hostname = row.get("hostname") or row.get("dns_name") or "(unknown hostname)"
        print(f"{row.get('ip_address', '')}\t{hostname}")


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    fieldnames = ["ip_address", "hostname", "dns_name", "mac_address", "manufacturer"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def print_table(rows: List[Dict[str, str]]) -> None:
    columns = [
        ("IP Address", "ip_address"),
        ("Hostname", "hostname"),
        ("DNS Name", "dns_name"),
        ("MAC Address", "mac_address"),
        ("Manufacturer", "manufacturer"),
    ]
    if not rows:
        print("No hosts found.")
        return

    max_col_width = 40
    widths: List[int] = []
    for title, key in columns:
        max_value_len = max(len(str(row.get(key, ""))) for row in rows)
        widths.append(min(max(len(title), max_value_len), max_col_width))

    def fit(text: str, width: int) -> str:
        if len(text) <= width:
            return text.ljust(width)
        if width <= 3:
            return text[:width]
        return f"{text[: width - 3]}...".ljust(width)

    header = " | ".join(fit(title, width) for (title, _), width in zip(columns, widths))
    separator = "-+-".join("-" * width for width in widths)
    print("\nDiscovered Hosts:")
    print(header)
    print(separator)
    for row in rows:
        line = " | ".join(
            fit(str(row.get(key, "")), width)
            for (_, key), width in zip(columns, widths)
        )
        print(line)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not is_root():
        print(
            "WARNING: Run as root for best MAC/manufacturer detection.\n"
            "         Example: sudo ./lan_inventory_scan_pi.py",
            file=sys.stderr,
        )

    try:
        timeout_s = get_timeout_seconds(args, default=600)
        networks = get_scan_networks()
        print(f"Scanning ranges: {', '.join(networks)}")

        combined: Dict[str, Dict[str, str]] = {}
        for network_cidr in networks:
            xml_data = run_nmap_scan(network_cidr, timeout_s)
            rows = parse_nmap_xml(xml_data)
            for row in rows:
                combined.setdefault(row["ip_address"], row)

        rows = sorted(
            combined.values(),
            key=lambda item: tuple(int(o) for o in item["ip_address"].split(".")),
        )
        if args.raspberry_pis:
            display_rows = filter_raspberry_pis(rows)
            print_raspberry_pi_summary(display_rows)
            print(
                f"Found {len(display_rows)} likely Raspberry Pi device(s) "
                f"out of {len(rows)} active hosts"
            )
        else:
            display_rows = rows
            print_table(display_rows)
            print(f"Discovered {len(rows)} active hosts")

        write_csv(display_rows, OUTPUT_CSV)
        print(f"CSV written to: {OUTPUT_CSV}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
