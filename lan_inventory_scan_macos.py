#!/usr/bin/env python3
"""LAN inventory scanner tuned for macOS.

Same two-phase engine as the other platform entry points (fast discovery
sweep, then parallel hostname/DNS/route enrichment with a live progress
view -- see ``lan_inventory_core``/``lan_inventory_ui``), with macOS-native
network detection: ``route -n get`` for interface selection, ``ifconfig``
for addresses, and ``networksetup -listallhardwareports`` to tell Wi-Fi
apart from Ethernet (macOS interface names like ``en0`` don't reliably
indicate media type the way Linux's do).
"""
import argparse
import functools
import ipaddress
import os
import platform
import shutil
import subprocess
import sys
from typing import Dict, List, Sequence, Tuple

from lan_inventory_core import (
    DEFAULT_CHECKPOINT_PATH,
    DEFAULT_DISCOVERY_TIMEOUT,
    DEFAULT_ENRICH_TIMEOUT,
    DEFAULT_ENRICH_WORKERS,
    OUTPUT_CSV,
    expand_to_24_chunks,
    filter_raspberry_pis,
    is_root,
    print_raspberry_pi_summary,
    print_table,
    require_tool,
    sort_rows,
    write_csv,
)
from lan_inventory_ui import run_browser, run_interactive_scan


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local IPv4 networks and inventory discovered LAN hosts (macOS)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_DISCOVERY_TIMEOUT,
        help=f"Safety ceiling in seconds for the discovery pass (default: {DEFAULT_DISCOVERY_TIMEOUT}). "
        "Discovery is a bare ping sweep so this is rarely reached.",
    )
    parser.add_argument(
        "--enrich-timeout",
        type=int,
        default=DEFAULT_ENRICH_TIMEOUT,
        help=f"Safety ceiling in seconds for the hostname/DNS/route enrichment pass (default: {DEFAULT_ENRICH_TIMEOUT}).",
    )
    parser.add_argument(
        "--raspberry-pis",
        "--pis",
        action="store_true",
        help="Show only likely Raspberry Pi devices with their IP addresses and hostnames.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of /24 chunks to scan in parallel during discovery (default: 4).",
    )
    parser.add_argument(
        "--enrich-workers",
        type=int,
        default=DEFAULT_ENRICH_WORKERS,
        help=f"Number of hosts to enrich in parallel (default: {DEFAULT_ENRICH_WORKERS}).",
    )
    parser.add_argument(
        "--checkpoint",
        default=DEFAULT_CHECKPOINT_PATH,
        help=f"Path to resume checkpoint file (default: {DEFAULT_CHECKPOINT_PATH}).",
    )
    parser.add_argument("--no-resume", action="store_true", help="Ignore any existing checkpoint and start fresh.")
    parser.add_argument("--clear-checkpoint", action="store_true", help="Remove the checkpoint after a successful scan.")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Skip the interactive sort/search browser after the scan, even in a terminal.",
    )
    return parser.parse_args(argv)


def get_worker_count(args: argparse.Namespace) -> int:
    if args.workers <= 0:
        raise ValueError("--workers must be a positive integer.")
    return args.workers


# --------------------------------------------------------------------------
# macOS network detection
# --------------------------------------------------------------------------


def _parse_route_get_interface(route_output: str) -> str:
    for line in route_output.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return ""


def _parse_ifconfig_inet(ifconfig_output: str) -> Tuple[str, str]:
    for raw_line in ifconfig_output.splitlines():
        line = raw_line.strip()
        if not line.startswith("inet ") or line.startswith("inet6"):
            continue
        parts = line.split()
        ip = parts[1] if len(parts) > 1 else ""
        netmask = ""
        if "netmask" in parts:
            netmask = parts[parts.index("netmask") + 1]
        return ip, netmask
    return "", ""


def _netmask_to_prefixlen(netmask: str) -> int:
    if not netmask:
        raise ValueError("Missing netmask.")
    if netmask.startswith("0x"):
        return bin(int(netmask, 16)).count("1")
    return ipaddress.ip_network(f"0.0.0.0/{netmask}").prefixlen


def get_active_network_cidr() -> str:
    if platform.system() != "Darwin":
        raise RuntimeError(f"Unsupported platform: {platform.system()}")

    require_tool("route")
    require_tool("ifconfig")

    route_cp = subprocess.run(
        ["route", "-n", "get", "default"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    interface = _parse_route_get_interface(route_cp.stdout)
    if not interface:
        raise RuntimeError("Could not determine default network interface.")

    ifconfig_cp = subprocess.run(
        ["ifconfig", interface], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    ip, netmask = _parse_ifconfig_inet(ifconfig_cp.stdout)
    if not ip:
        raise RuntimeError(f"Could not determine IPv4 address for interface {interface}.")

    prefixlen = _netmask_to_prefixlen(netmask)
    return str(ipaddress.ip_interface(f"{ip}/{prefixlen}").network)


def get_scan_networks() -> List[str]:
    primary = ipaddress.ip_network(get_active_network_cidr(), strict=False)
    networks = {primary}

    list_cp = subprocess.run(["ifconfig", "-l"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    interfaces = list_cp.stdout.split()

    for interface in interfaces:
        cp = subprocess.run(["ifconfig", interface], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if "status: active" not in cp.stdout and interface not in ("lo0",):
            # Interfaces without a reported status (older macOS, virtual
            # interfaces) still get a chance via their inet address below.
            pass
        ip, netmask = _parse_ifconfig_inet(cp.stdout)
        if not ip or not netmask:
            continue
        try:
            network = ipaddress.ip_interface(f"{ip}/{_netmask_to_prefixlen(netmask)}").network
        except ValueError:
            continue
        if network.is_loopback or network.is_unspecified:
            continue
        if not (network.is_private or network.is_link_local):
            continue
        networks.add(network)

    return [str(n) for n in sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))]


@functools.lru_cache(maxsize=1)
def _load_hardware_port_map() -> Dict[str, str]:
    tool = shutil.which("networksetup")
    if tool is None:
        return {}

    cp = subprocess.run([tool, "-listallhardwareports"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    if cp.returncode != 0:
        return {}

    mapping: Dict[str, str] = {}
    port_name = ""
    for raw_line in cp.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Hardware Port:"):
            port_name = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            device = line.split(":", 1)[1].strip()
            if device:
                mapping[device] = port_name
    return mapping


def classify_interface_connection_type(interface: str, hardware_ports: Dict[str, str] = None) -> str:
    interface = interface.strip()
    if not interface:
        return "Unknown"

    if hardware_ports is None:
        hardware_ports = _load_hardware_port_map()

    port_name = hardware_ports.get(interface, "").lower()
    if "wi-fi" in port_name or "airport" in port_name:
        return "Wifi"
    if "ethernet" in port_name or "thunderbolt" in port_name or "usb" in port_name:
        return "Ethernet"
    return "Unknown"


def get_connection_type(ip: str) -> str:
    route_cp = subprocess.run(
        ["route", "-n", "get", ip], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )
    if route_cp.returncode != 0:
        return "Unknown"

    interface = _parse_route_get_interface(route_cp.stdout)
    return classify_interface_connection_type(interface)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not is_root():
        print(
            "WARNING: Run with sudo for best MAC/manufacturer detection.\n"
            "         Example: sudo ./lan_inventory_scan_macos.py",
            file=sys.stderr,
        )

    try:
        workers = get_worker_count(args)
        networks = get_scan_networks()
        print(f"Scanning ranges: {', '.join(networks)}")
        chunks = expand_to_24_chunks(networks)
        print(f"Expanded to /24 scan chunks: {', '.join(chunks)}")

        combined = run_interactive_scan(
            chunks=chunks,
            discovery_timeout=args.timeout,
            discovery_workers=workers,
            enrich_timeout=args.enrich_timeout,
            enrich_workers=args.enrich_workers,
            checkpoint_path=args.checkpoint,
            resume=not args.no_resume,
            get_connection_type=get_connection_type,
        )

        rows = sort_rows(list(combined.values()), "ip")
        if args.raspberry_pis:
            display_rows = filter_raspberry_pis(rows)
            print_raspberry_pi_summary(display_rows)
            print(f"Found {len(display_rows)} likely Raspberry Pi device(s) out of {len(rows)} active hosts")
        else:
            display_rows = rows
            print_table(display_rows)
            print(f"Discovered {len(rows)} active hosts")

        write_csv(display_rows, OUTPUT_CSV)
        print(f"CSV written to: {OUTPUT_CSV}")
        if args.clear_checkpoint and os.path.exists(args.checkpoint):
            os.remove(args.checkpoint)
            print(f"Removed checkpoint: {args.checkpoint}")

        if not args.no_browser and rows and sys.stdin.isatty():
            run_browser(rows)

        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
