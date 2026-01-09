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
        print(f"ERROR: Required tool '{tool}' not found in PATH.", file=sys.stderr)
        sys.exit(2)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def prompt_timeout_seconds(default: int = 1200) -> int:
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
        if line.startswith("interface:"):
            return line.split("interface:", 1)[-1].strip()
    return ""


def _parse_ifconfig_inet(ifconfig_output: str) -> Tuple[str, int]:
    for line in ifconfig_output.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[1]
        netmask = parts[3]
        if not netmask.startswith("0x"):
            continue
        mask_int = int(netmask, 16)
        prefix_len = bin(mask_int).count("1")
        return ip, prefix_len
    return "", 0


def get_active_network_cidr() -> str:
    system = platform.system()
    if system != "Darwin":
        raise RuntimeError(f"Unsupported platform: {system}")

    require_tool("route")
    require_tool("ifconfig")

    route_cp = subprocess.run(
        ["route", "-n", "get", "default"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    interface = _parse_default_interface(route_cp.stdout)
    if not interface:
        raise RuntimeError("Could not determine default network interface.")

    ifconfig_cp = subprocess.run(
        ["ifconfig", interface],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    ip, prefix_len = _parse_ifconfig_inet(ifconfig_cp.stdout)
    if not ip or prefix_len <= 0:
        raise RuntimeError(f"Could not determine IPv4 network for interface {interface}.")

    network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
    return str(network)


def run_nmap_scan(network: str, timeout_s: int) -> str:
    require_tool("nmap")

    # More robust discovery mix for macOS / Wi-Fi environments:
    # -PR ARP ping (best for LAN MACs)
    # -PE/-PP ICMP variants
    # -PS443 TCP SYN ping to help when ICMP is blocked
    cmd = [
        "nmap",
        "-sn",
        "-PR",
        "-PE",
        "-PP",
        "-PS443",
        network,
        "-oX",
        "-",
    ]

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
            "NOTE: For best MAC/manufacturer detection, run with sudo:\n"
            "      sudo ./lan_inventory_scan_mac.py",
            file=sys.stderr,
        )

    timeout_s = prompt_timeout_seconds(default=1200)

    try:
        network_cidr = get_active_network_cidr()
        print(f"Scanning range: {network_cidr}")
        xml_data = run_nmap_scan(network_cidr, timeout_s)
        rows = parse_nmap_xml(xml_data)
        write_csv(rows, OUTPUT_CSV)

        print(f"Discovered {len(rows)} active hosts")
        print(f"CSV written to: {OUTPUT_CSV}")
        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
