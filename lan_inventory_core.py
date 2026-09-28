#!/usr/bin/env python3
"""Shared, platform-independent engine for the LAN Inventory scanners.

Platform-specific entry points (``lan_inventory_scan_pi.py``,
``lan_inventory_scan_macos.py``, ``lan_inventory_scan_windows.py``) import
this module for everything that does not depend on the host OS: nmap
invocation/parsing, hostname enrichment, checkpointing, CSV output, and the
interactive result browser. Each entry point supplies its own
``get_connection_type`` (interface classification differs per OS) and
network-discovery routine.
"""
import concurrent.futures
import csv
import glob
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

OUTPUT_CSV = "network_inventory.csv"
DEFAULT_CHECKPOINT_PATH = ".lan_inventory_checkpoint.json"

# Default per-chunk discovery timeout. Discovery only pings hosts (nmap -sn
# -n, no DNS resolution) so a /24 normally finishes in a few seconds; this is
# a safety ceiling, not something most scans will ever approach.
DEFAULT_DISCOVERY_TIMEOUT = 120
# Ceiling for the enrichment phase (reverse DNS / mDNS / route lookups per
# discovered host). Enrichment time scales with host count, not subnet size,
# so this rarely matters either -- it exists purely as a safety valve.
DEFAULT_ENRICH_TIMEOUT = 180
DEFAULT_ENRICH_WORKERS = 16

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

# Common DHCP lease locations used by dnsmasq, NetworkManager shared
# connections, and systemd-networkd. These often contain hostnames for
# devices on hosted hotspot networks even when PTR DNS is absent.
DHCP_LEASE_GLOBS = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/NetworkManager/dnsmasq*.leases",
    "/var/lib/NetworkManager/*dnsmasq*.leases",
    "/run/NetworkManager/dnsmasq*.leases",
    "/run/NetworkManager/*dnsmasq*.leases",
    "/run/systemd/netif/leases/*",
)

CSV_FIELDNAMES = [
    "ip_address",
    "hostname",
    "dns_name",
    "mac_address",
    "manufacturer",
    "connection_type",
]

ConnectionTypeFn = Callable[[str], str]


def require_tool(tool: str) -> None:
    if shutil.which(tool) is None:
        print(f"ERROR: Required tool '{tool}' not found. Install it first.", file=sys.stderr)
        sys.exit(2)


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def format_duration(seconds: float) -> str:
    if seconds < 0 or seconds == float("inf"):
        return "unknown"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def expand_to_24_chunks(networks: Iterable[str]) -> List[str]:
    chunks: Set[ipaddress.IPv4Network] = set()
    for network_text in networks:
        network = ipaddress.ip_network(network_text, strict=False)
        if network.version != 4:
            continue
        if network.prefixlen <= 24:
            chunks.update(network.subnets(new_prefix=24))
        else:
            chunks.add(network)
    return [str(n) for n in sorted(chunks, key=lambda n: (int(n.network_address), n.prefixlen))]


def ip_sort_key(ip_text: str) -> Tuple[int, int, int, int]:
    return tuple(int(o) for o in str(ipaddress.ip_address(ip_text)).split("."))


# --------------------------------------------------------------------------
# Checkpointing (discovery phase only -- enrichment is cheap enough to redo)
# --------------------------------------------------------------------------


def load_checkpoint(path: str, resume: bool) -> Tuple[Set[str], Dict[str, Dict[str, str]]]:
    if not resume or not os.path.exists(path):
        return set(), {}

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    completed = set(data.get("completed_chunks", []))
    hosts = {
        ip: row
        for ip, row in data.get("hosts", {}).items()
        if isinstance(ip, str) and isinstance(row, dict)
    }
    print(
        f"Resuming from checkpoint: {len(completed)} completed chunk(s), "
        f"{len(hosts)} discovered host(s)."
    )
    return completed, hosts


def save_checkpoint(path: str, completed_chunks: Set[str], hosts: Dict[str, Dict[str, str]]) -> None:
    data = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "completed_chunks": sorted(
            completed_chunks,
            key=lambda n: int(ipaddress.ip_network(n, strict=False).network_address),
        ),
        "hosts": hosts,
    }
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(temp_path, path)


# --------------------------------------------------------------------------
# Phase 1: discovery (fast ping sweep, no DNS/route work)
# --------------------------------------------------------------------------


def run_nmap_discovery(network: str, timeout_s: float) -> str:
    """Run a bare host-discovery sweep (no ports, no DNS) and return nmap XML."""
    require_tool("nmap")

    # -n disables nmap's own (serial, often slow) reverse-DNS resolution --
    # we do our own resolution in the enrichment phase, in parallel, with a
    # short per-host timeout. This alone removes most of the stalls that used
    # to blow through the old 30s/600s timeouts.
    cmd = ["nmap", "-sn", "-n", network, "-oX", "-"]

    start = time.time()
    deadline = start + timeout_s

    def _remaining_timeout() -> float:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(cmd, timeout_s)
        return remaining

    def _run_scan(scan_cmd: List[str]) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(
            scan_cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_remaining_timeout(),
            check=False,
        )

    try:
        cp = _run_scan(cmd)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Discovery scan of {network} exceeded timeout of {format_duration(timeout_s)}")

    retry_triggers = (
        "Required key not available",
        "Destination address required",
    )
    should_retry_unprivileged = any(trigger in cp.stderr for trigger in retry_triggers)
    if should_retry_unprivileged:
        print(
            f"[{network}] Detected kernel policy/routing errors for raw ICMP probes; "
            "retrying with unprivileged TCP ping probes.",
            file=sys.stderr,
        )
        try:
            cp = _run_scan(
                [
                    "nmap",
                    "--unprivileged",
                    "-sn",
                    "-n",
                    "-PS22,80,443",
                    "-PA22,80,443",
                    network,
                    "-oX",
                    "-",
                ]
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Discovery scan of {network} exceeded timeout of {format_duration(timeout_s)}")

    if cp.returncode != 0 and not cp.stdout.strip():
        raise RuntimeError(f"nmap failed (exit {cp.returncode}).\nstderr:\n{cp.stderr.strip()}")

    if cp.stderr.strip():
        print(f"[nmap stderr]\n{cp.stderr.strip()}", file=sys.stderr)

    return cp.stdout


def parse_discovery_xml(xml_text: str) -> List[Dict[str, str]]:
    """Parse a discovery-only nmap XML doc into basic rows (no enrichment)."""
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

        results.append(
            {
                "ip_address": ip,
                "mac_address": mac,
                "manufacturer": vendor,
                "nmap_hostname": nmap_hostname,
            }
        )

    results.sort(key=lambda item: ip_sort_key(item["ip_address"]))
    return results


def discover_chunk(network: str, timeout_s: float) -> Tuple[str, List[Dict[str, str]]]:
    xml_data = run_nmap_discovery(network, timeout_s)
    return network, parse_discovery_xml(xml_data)


def discover_chunks(
    chunks: List[str],
    timeout_s: float,
    workers: int,
    checkpoint_path: str,
    resume: bool,
    on_chunk_done: Optional[Callable[[str, List[Dict[str, str]], int, int], None]] = None,
) -> Dict[str, Dict[str, str]]:
    completed_chunks, combined = load_checkpoint(checkpoint_path, resume=resume)
    pending_chunks = [chunk for chunk in chunks if chunk not in completed_chunks]

    if completed_chunks and not pending_chunks:
        print(
            "Checkpoint already contains every requested chunk; starting a fresh scan "
            "so completed results do not hide current network changes."
        )
        completed_chunks = set()
        combined = {}
        pending_chunks = list(chunks)
    elif completed_chunks:
        print(f"Skipping {len(chunks) - len(pending_chunks)} already completed chunk(s).")

    print(f"Discovering hosts in {len(pending_chunks)} /24 chunk(s) with {workers} worker(s)...")
    start_time = time.time()
    deadline = start_time + timeout_s
    finished_this_run = 0

    def remaining_budget() -> float:
        return deadline - time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        chunk_iter = iter(pending_chunks)
        future_to_chunk: Dict[concurrent.futures.Future, str] = {}

        def submit_next_chunk() -> bool:
            if remaining_budget() <= 0:
                return False
            try:
                next_chunk = next(chunk_iter)
            except StopIteration:
                return False
            future_to_chunk[executor.submit(discover_chunk, next_chunk, remaining_budget())] = next_chunk
            return True

        for _ in range(min(workers, len(pending_chunks))):
            submit_next_chunk()

        while future_to_chunk:
            done, _not_done = concurrent.futures.wait(
                future_to_chunk,
                timeout=max(0.0, remaining_budget()),
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                save_checkpoint(checkpoint_path, completed_chunks, combined)
                raise RuntimeError(
                    f"Discovery timeout of {format_duration(timeout_s)} exceeded. "
                    f"Checkpoint saved to {checkpoint_path}; rerun to resume."
                )

            for future in done:
                chunk = future_to_chunk.pop(future)
                try:
                    completed_chunk, rows = future.result()
                except Exception as exc:
                    save_checkpoint(checkpoint_path, completed_chunks, combined)
                    raise RuntimeError(
                        f"Chunk {chunk} failed: {exc}. "
                        f"Checkpoint saved to {checkpoint_path}; rerun to resume."
                    ) from exc

                for row in rows:
                    combined.setdefault(row["ip_address"], row)
                completed_chunks.add(completed_chunk)
                finished_this_run += 1
                save_checkpoint(checkpoint_path, completed_chunks, combined)
                if on_chunk_done is not None:
                    on_chunk_done(completed_chunk, rows, finished_this_run, len(pending_chunks))
                submit_next_chunk()

    return combined


# --------------------------------------------------------------------------
# Hostname resolution helpers (shared by every platform)
# --------------------------------------------------------------------------


def reverse_dns(ip: str) -> str:
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name or ""
    except Exception:
        return ""


def _clean_hostname(hostname: str) -> str:
    hostname = hostname.strip()
    if not hostname or hostname == "*":
        return ""
    return hostname


def _parse_dnsmasq_lease_line(line: str) -> Tuple[str, str]:
    parts = line.split()
    if len(parts) < 4:
        return "", ""
    return parts[2], _clean_hostname(parts[3])


def _parse_systemd_lease_text(text: str) -> Tuple[str, str]:
    ip = ""
    hostname = ""
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "ADDRESS":
            ip = value.strip()
        elif key == "HOSTNAME":
            hostname = _clean_hostname(value)
    return ip, hostname


def load_dhcp_lease_hostnames(lease_globs: Sequence[str] = DHCP_LEASE_GLOBS) -> Dict[str, str]:
    hostnames: Dict[str, str] = {}
    paths: Set[str] = set()
    for pattern in lease_globs:
        paths.update(glob.glob(pattern))

    for path in sorted(paths):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue

        if "ADDRESS=" in text or "HOSTNAME=" in text:
            ip, hostname = _parse_systemd_lease_text(text)
            if ip and hostname:
                hostnames.setdefault(ip, hostname)
            continue

        for line in text.splitlines():
            ip, hostname = _parse_dnsmasq_lease_line(line)
            if ip and hostname:
                hostnames.setdefault(ip, hostname)

    return hostnames


def resolve_avahi_address(ip: str) -> str:
    avahi_tool = shutil.which("avahi-resolve-address")
    if avahi_tool is None:
        return ""

    cp = subprocess.run(
        [avahi_tool, ip],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )
    if cp.returncode != 0:
        return ""

    parts = cp.stdout.strip().split()
    if len(parts) >= 2 and parts[0] == ip:
        return _clean_hostname(parts[1].rstrip("."))
    return ""


def _parse_avahi_browse_line(line: str) -> Tuple[str, str]:
    parts = line.split(";")
    if len(parts) < 8 or parts[0] != "=" or parts[2] != "IPv4":
        return "", ""
    hostname = _clean_hostname(parts[6].rstrip("."))
    ip = parts[7].strip()
    return ip, hostname


def load_avahi_browse_hostnames() -> Dict[str, str]:
    avahi_tool = shutil.which("avahi-browse")
    if avahi_tool is None:
        return {}

    try:
        cp = subprocess.run(
            [avahi_tool, "--all", "--resolve", "--terminate", "--parsable"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {}

    if cp.returncode != 0:
        return {}

    hostnames: Dict[str, str] = {}
    for line in cp.stdout.splitlines():
        ip, hostname = _parse_avahi_browse_line(line)
        if ip and hostname:
            hostnames.setdefault(ip, hostname)
    return hostnames


# --------------------------------------------------------------------------
# Phase 2: enrichment (per-host reverse DNS / mDNS / route classification)
# --------------------------------------------------------------------------


def enrich_host(
    basic_row: Dict[str, str],
    dhcp_lease_hostnames: Dict[str, str],
    avahi_browse_hostnames: Dict[str, str],
    get_connection_type: ConnectionTypeFn,
) -> Dict[str, str]:
    ip = basic_row["ip_address"]
    nmap_hostname = basic_row.get("nmap_hostname", "")

    dns_name = reverse_dns(ip)
    lease_hostname = dhcp_lease_hostnames.get(ip, "")
    avahi_hostname = avahi_browse_hostnames.get(ip, "")
    if not (dns_name or lease_hostname or nmap_hostname or avahi_hostname):
        avahi_hostname = resolve_avahi_address(ip)
    hostname = nmap_hostname or lease_hostname or avahi_hostname or dns_name

    return {
        "ip_address": ip,
        "hostname": hostname,
        "dns_name": dns_name,
        "mac_address": basic_row.get("mac_address", ""),
        "manufacturer": basic_row.get("manufacturer", ""),
        "connection_type": get_connection_type(ip),
    }


def enrich_hosts(
    basic_rows: List[Dict[str, str]],
    workers: int,
    timeout_s: float,
    get_connection_type: ConnectionTypeFn,
    on_host_done: Optional[Callable[[Dict[str, str], int, int], None]] = None,
) -> Dict[str, Dict[str, str]]:
    """Resolve hostname/DNS/connection-type for every discovered host.

    Runs the (network I/O bound) lookups for all hosts in a shared thread
    pool -- much faster than doing them serially inside the nmap XML parser,
    and lets the caller stream results to a live UI as each host finishes.
    """
    dhcp_lease_hostnames = load_dhcp_lease_hostnames()
    avahi_browse_hostnames = load_avahi_browse_hostnames()

    results: Dict[str, Dict[str, str]] = {}
    if not basic_rows:
        return results

    start_time = time.time()
    deadline = start_time + timeout_s
    total = len(basic_rows)
    finished = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_row = {
            executor.submit(
                enrich_host, row, dhcp_lease_hostnames, avahi_browse_hostnames, get_connection_type
            ): row
            for row in basic_rows
        }

        while future_to_row:
            remaining = max(0.0, deadline - time.time())
            done, _not_done = concurrent.futures.wait(
                future_to_row, timeout=remaining, return_when=concurrent.futures.FIRST_COMPLETED
            )
            if not done:
                # Enrichment timeout: keep whatever finished, fall back to
                # the bare discovery data (no hostname/route info) for the
                # rest rather than losing hosts outright.
                for pending_future, pending_row in future_to_row.items():
                    pending_future.cancel()
                    ip = pending_row["ip_address"]
                    results.setdefault(
                        ip,
                        {
                            "ip_address": ip,
                            "hostname": pending_row.get("nmap_hostname", ""),
                            "dns_name": "",
                            "mac_address": pending_row.get("mac_address", ""),
                            "manufacturer": pending_row.get("manufacturer", ""),
                            "connection_type": "Unknown",
                        },
                    )
                break

            for future in done:
                row = future_to_row.pop(future)
                try:
                    enriched = future.result()
                except Exception:
                    ip = row["ip_address"]
                    enriched = {
                        "ip_address": ip,
                        "hostname": row.get("nmap_hostname", ""),
                        "dns_name": "",
                        "mac_address": row.get("mac_address", ""),
                        "manufacturer": row.get("manufacturer", ""),
                        "connection_type": "Unknown",
                    }
                results[enriched["ip_address"]] = enriched
                finished += 1
                if on_host_done is not None:
                    on_host_done(enriched, finished, total)

    return results


def estimate_enrichment_seconds(
    basic_rows: List[Dict[str, str]],
    workers: int,
    get_connection_type: ConnectionTypeFn,
    sample_size: int = 5,
) -> float:
    """Time a small sample of hosts to project the full enrichment duration."""
    if not basic_rows:
        return 0.0

    sample = basic_rows[: max(1, min(sample_size, len(basic_rows)))]
    dhcp_lease_hostnames = load_dhcp_lease_hostnames()
    avahi_browse_hostnames = load_avahi_browse_hostnames()

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(sample)))) as executor:
        futures = [
            executor.submit(
                enrich_host, row, dhcp_lease_hostnames, avahi_browse_hostnames, get_connection_type
            )
            for row in sample
        ]
        concurrent.futures.wait(futures)
    elapsed = time.time() - start

    per_host = elapsed / len(sample)
    total_hosts = len(basic_rows)
    effective_workers = max(1, min(workers, total_hosts))
    return per_host * total_hosts / effective_workers


# --------------------------------------------------------------------------
# Raspberry Pi filtering
# --------------------------------------------------------------------------


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


# --------------------------------------------------------------------------
# Sorting / searching (pure functions shared by the live view and browser)
# --------------------------------------------------------------------------

SORTABLE_COLUMNS = [
    ("ip", "ip_address"),
    ("hostname", "hostname"),
    ("dns", "dns_name"),
    ("mac", "mac_address"),
    ("vendor", "manufacturer"),
    ("connection", "connection_type"),
]
_SORTABLE_COLUMN_KEYS = {name: field for name, field in SORTABLE_COLUMNS}


def sort_rows(rows: List[Dict[str, str]], column: str, reverse: bool = False) -> List[Dict[str, str]]:
    field = _SORTABLE_COLUMN_KEYS.get(column, column)
    if field == "ip_address":
        key_fn = lambda row: ip_sort_key(row.get("ip_address", "0.0.0.0"))
    else:
        key_fn = lambda row: str(row.get(field, "")).lower()
    return sorted(rows, key=key_fn, reverse=reverse)


def filter_rows(rows: List[Dict[str, str]], query: str) -> List[Dict[str, str]]:
    if not query:
        return list(rows)
    query = query.lower()
    return [row for row in rows if any(query in str(v).lower() for v in row.values())]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDNAMES})


def format_table(rows: List[Dict[str, str]]) -> str:
    columns = [
        ("IP Address", "ip_address"),
        ("Hostname", "hostname"),
        ("DNS Name", "dns_name"),
        ("MAC Address", "mac_address"),
        ("Manufacturer", "manufacturer"),
        ("Connection Type", "connection_type"),
    ]
    if not rows:
        return "No hosts found."

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
    lines = [header, separator]
    for row in rows:
        lines.append(
            " | ".join(fit(str(row.get(key, "")), width) for (_, key), width in zip(columns, widths))
        )
    return "\n".join(lines)


def print_table(rows: List[Dict[str, str]]) -> None:
    print("\nDiscovered Hosts:")
    print(format_table(rows))


def print_raspberry_pi_summary(rows: List[Dict[str, str]]) -> None:
    if not rows:
        print("No likely Raspberry Pi devices found.")
        return

    print("\nLikely Raspberry Pi Devices:")
    for row in rows:
        hostname = row.get("hostname") or row.get("dns_name") or "(unknown hostname)"
        connection_type = row.get("connection_type", "Unknown")
        print(f"{row.get('ip_address', '')}\t{hostname}\t{connection_type}")
