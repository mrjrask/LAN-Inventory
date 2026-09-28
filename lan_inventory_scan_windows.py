#!/usr/bin/env python3
"""LAN inventory scanner tuned for Windows.

Same two-phase engine as the other platform entry points (fast discovery
sweep, then parallel hostname/DNS/route enrichment with a live progress
view -- see ``lan_inventory_core``/``lan_inventory_ui``), with Windows-native
network detection via PowerShell's ``NetTCPIP``/``NetAdapter`` cmdlets.

Connection type is resolved without shelling out per host: spawning
PowerShell per discovered device would dominate the enrichment budget (a
PowerShell startup is far slower than a Linux/macOS ``ip route get`` or
``route -n get`` call), so this module loads every local interface's
subnet and media type once and classifies each host in pure Python by
checking which local subnet contains it.
"""
import argparse
import functools
import ipaddress
import json
import os
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
    sort_rows,
    write_csv,
)
from lan_inventory_ui import run_browser, run_interactive_scan

_INTERFACE_INFO_SCRIPT = r"""
$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object -Property RouteMetric
$defaultIfIndex = $null
if ($routes) { $defaultIfIndex = ($routes | Select-Object -First 1).ifIndex }
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object ifIndex, Name, PhysicalMediaType
$addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }
$result = foreach ($a in $addrs) {
    $adapter = $adapters | Where-Object { $_.ifIndex -eq $a.ifIndex } | Select-Object -First 1
    [PSCustomObject]@{
        IfIndex           = $a.ifIndex
        IPAddress         = $a.IPAddress
        PrefixLength      = $a.PrefixLength
        PhysicalMediaType = $adapter.PhysicalMediaType
        IsDefault         = ($a.ifIndex -eq $defaultIfIndex)
    }
}
$result | ConvertTo-Json -Compress
""".strip()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan local IPv4 networks and inventory discovered LAN hosts (Windows)."
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


def enable_ansi_console() -> None:
    """Turn on VT100 escape processing so the live progress view can redraw
    in place on the classic Windows console (Windows Terminal already
    supports this; conhost.exe on older builds needs it enabled)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


# --------------------------------------------------------------------------
# Windows network detection (PowerShell-backed, parsed in pure Python)
# --------------------------------------------------------------------------


def _run_powershell(script: str) -> str:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        raise RuntimeError("PowerShell was not found on PATH.")

    cp = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"PowerShell command failed: {cp.stderr.strip()}")
    return cp.stdout


def parse_interface_info_json(output: str) -> List[Dict[str, object]]:
    output = output.strip()
    if not output:
        return []
    data = json.loads(output)
    if isinstance(data, dict):
        return [data]
    return list(data)


def classify_physical_media_type(media_type: str) -> str:
    media_type = (media_type or "").lower()
    if "802.11" in media_type or "wireless" in media_type:
        return "Wifi"
    if "802.3" in media_type or "ethernet" in media_type:
        return "Ethernet"
    return "Unknown"


def _entry_to_network(entry: Dict[str, object]) -> Tuple[ipaddress.IPv4Network, str, bool]:
    ip = str(entry.get("IPAddress", ""))
    prefixlen = int(entry.get("PrefixLength", 0) or 0)
    network = ipaddress.ip_interface(f"{ip}/{prefixlen}").network
    connection_type = classify_physical_media_type(str(entry.get("PhysicalMediaType", "")))
    is_default = bool(entry.get("IsDefault", False))
    return network, connection_type, is_default


@functools.lru_cache(maxsize=1)
def _load_interfaces() -> List[Dict[str, object]]:
    return parse_interface_info_json(_run_powershell(_INTERFACE_INFO_SCRIPT))


def get_active_network_cidr() -> str:
    entries = _load_interfaces()
    if not entries:
        raise RuntimeError("Could not enumerate any IPv4 interfaces.")

    default_entries = [e for e in entries if e.get("IsDefault")]
    chosen = default_entries[0] if default_entries else entries[0]
    network, _connection_type, _is_default = _entry_to_network(chosen)
    return str(network)


def get_scan_networks() -> List[str]:
    entries = _load_interfaces()
    networks = set()
    for entry in entries:
        try:
            network, _connection_type, _is_default = _entry_to_network(entry)
        except ValueError:
            continue
        if network.is_loopback or network.is_unspecified:
            continue
        if not (network.is_private or network.is_link_local):
            continue
        networks.add(network)

    if not networks:
        networks.add(ipaddress.ip_network(get_active_network_cidr(), strict=False))

    return [str(n) for n in sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))]


def get_connection_type(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"

    for entry in _load_interfaces():
        try:
            network, connection_type, _is_default = _entry_to_network(entry)
        except ValueError:
            continue
        if addr in network:
            return connection_type
    return "Unknown"


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    enable_ansi_console()
    if not is_root():
        print(
            "WARNING: Run this from an elevated (Administrator) PowerShell/terminal for best "
            "MAC/manufacturer detection.",
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
