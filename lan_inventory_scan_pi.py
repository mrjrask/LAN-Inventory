#!/usr/bin/env python3
"""LAN inventory scanner tuned for Linux / Raspberry Pi OS.

Two-phase, self-paced scan: a fast ping-sweep discovery pass finds every
live host, then a parallel enrichment pass resolves hostnames, DNS names,
and connection type for each one -- while a live progress view populates
the terminal as results arrive. No "how many seconds should this run"
prompt: the tool estimates its own budget from a small timing sample and
just gets on with it. Use ``--timeout``/``--enrich-timeout`` only if you
want a hard ceiling.
"""
import argparse
import ipaddress
import os
import platform
import subprocess
import sys
from typing import List, Sequence

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
        description="Scan local IPv4 networks and inventory discovered LAN hosts (Linux / Raspberry Pi)."
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
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Ignore any existing checkpoint and start a fresh scan.",
    )
    parser.add_argument(
        "--clear-checkpoint",
        action="store_true",
        help="Remove the checkpoint file after a successful scan.",
    )
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


def classify_interface_connection_type(interface: str) -> str:
    interface = interface.strip()
    if not interface:
        return "Unknown"

    wireless_path = os.path.join("/sys/class/net", interface, "wireless")
    if os.path.isdir(wireless_path) or interface.startswith(("wl", "wifi", "wlan")):
        return "Wifi"
    if interface.startswith(("en", "eth")):
        return "Ethernet"
    return "Unknown"


def _parse_route_get_interface(route_output: str) -> str:
    parts = route_output.split()
    if "dev" not in parts:
        return ""
    dev_index = parts.index("dev")
    if dev_index + 1 >= len(parts):
        return ""
    return parts[dev_index + 1]


def get_connection_type(ip: str) -> str:
    route_cp = subprocess.run(
        ["ip", "route", "get", ip],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if route_cp.returncode != 0:
        return "Unknown"

    interface = _parse_route_get_interface(route_cp.stdout)
    return classify_interface_connection_type(interface)


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


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not is_root():
        print(
            "WARNING: Run as root for best MAC/manufacturer detection.\n"
            "         Example: sudo ./lan_inventory_scan_pi.py",
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
