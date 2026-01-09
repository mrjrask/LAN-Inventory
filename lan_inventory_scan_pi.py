#!/usr/bin/env python3
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
from typing import Dict, List, Tuple

OUTPUT_CSV = "network_inventory.csv"


def require_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        print(f"ERROR: Required tool '{tool}' not found. Install it first.", file=sys.stderr)
        sys.exit(2)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


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

    print(f"Running scan: {' '.join(cmd)}")
    start = time.time()

    try:
        cp = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
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


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    fieldnames = ["ip_address", "hostname", "dns_name", "mac_address", "manufacturer"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def main() -> int:
    if not is_root():
        print(
            "WARNING: Run as root for best MAC/manufacturer detection.\n"
            "         Example: sudo ./lan_inventory_scan_pi.py",
            file=sys.stderr,
        )

    timeout_s = prompt_timeout_seconds(default=600)

    try:
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
        write_csv(rows, OUTPUT_CSV)

        print(f"Discovered {len(rows)} active hosts")
        print(f"CSV written to: {OUTPUT_CSV}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
