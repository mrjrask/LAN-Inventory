# LAN Inventory Scanner

Terminal-based Python scanners that discover devices on your local network and
generate a CSV inventory. There is one entry point per platform, sharing a
common engine:

| Script | Platform |
|------|----------|
| `lan_inventory_scan_pi.py` | Linux / Raspberry Pi OS (Bookworm & Trixie) |
| `lan_inventory_scan_macos.py` | macOS |
| `lan_inventory_scan_windows.py` | Windows |

No `pip install` is required for any of them -- everything is standard
library.

---

## How a scan works

The scan runs in two phases, fully automatically -- there's no "how many
seconds should this run?" prompt:

1. **Discovery.** A fast ping sweep (`nmap -sn`) finds every live host on
   your subnet(s) and reports its IP, MAC address, and vendor. This is a
   bare host-discovery pass with DNS resolution turned off, so it typically
   takes seconds, not minutes, even across several `/24` ranges.
2. **Enrichment.** Once the tool knows how many hosts exist, it times a
   small sample of them to estimate how long full detail-gathering
   (hostname resolution, reverse DNS, mDNS/Avahi, connection type) will
   take, prints that estimate, and then resolves every host in parallel.

While enrichment runs, a live progress bar and a table of already-resolved
hosts redraw in place in your terminal, so you see devices appear as they're
found instead of staring at a blank screen. When the scan finishes (or you
press Ctrl+C to stop early -- partial results are still written), you land in
an interactive browser over the results:

```
sort <column> [desc]   Sort by column: ip, hostname, dns, mac, vendor, connection
search <text>          Filter rows containing text in any column (case-insensitive)
clear                  Clear the current search filter
pis                    Show only likely Raspberry Pi devices
all                    Show all discovered hosts (clears the Raspberry Pi filter)
csv [path]             Write the currently filtered/sorted rows to a CSV file
help                   Show this help
quit / exit / q        Exit the browser
```

The browser is skipped automatically when stdin isn't a terminal (piped
input, CI, cron/systemd-timer runs), so scripted usage behaves exactly like
before: it prints the final table once and exits.

---

## Which Networks Are Scanned

Each entry point detects your machine's active IPv4 network(s) rather than
scanning a hardcoded range: it finds the subnet of your default-route
interface, then adds any other private (RFC 1918) or link-local routes it can
see (useful when you have multiple active interfaces, VLANs, or a
router-behind-a-router setup). Every network found is expanded into `/24`
chunks for discovery. Both phases print the ranges and chunks they're about
to use before scanning starts, so you always know what's in scope.

---

## Output

Every run writes:

```
network_inventory.csv
```

### CSV Columns

| Column | Description |
|------|-------------|
| `ip_address` | IPv4 address of the host |
| `hostname` | Hostname from nmap first, then local DHCP lease files, then Avahi/mDNS, then reverse DNS |
| `dns_name` | Reverse DNS (PTR record lookup); may be empty |
| `mac_address` | MAC address (best on local L2 networks) |
| `manufacturer` | Vendor derived from MAC OUI |
| `connection_type` | `Ethernet`, `Wifi`, or `Unknown` |

Example row:

```csv
192.168.1.42,my-printer,printer.local,AA:BB:CC:DD:EE:FF,HP,Ethernet
```

---

## Safety Notes

- These scripts perform **host discovery only**
- No ports are scanned
- No services are touched
- Safe for home and business networks where you have authorization

Do not run on networks you do not own or manage.

---

## Linux / Raspberry Pi

### Requirements

```bash
chmod +x install_pi_dependencies.sh
./install_pi_dependencies.sh
```

Or manually:

```bash
sudo apt update
sudo apt install -y nmap python3 iproute2
```

### Run

```bash
chmod +x lan_inventory_scan_pi.py
sudo ./lan_inventory_scan_pi.py
```

`sudo` is optional but strongly recommended -- without it, MAC addresses and
manufacturer/vendor detection are often unavailable.

---

## macOS

### Requirements

```bash
chmod +x install_macos_dependencies.sh
./install_macos_dependencies.sh
```

Or manually (via [Homebrew](https://brew.sh)):

```bash
brew install nmap
```

### Run

```bash
chmod +x lan_inventory_scan_macos.py
sudo ./lan_inventory_scan_macos.py
```

Network detection uses `route -n get` and `ifconfig`; Wi-Fi vs. Ethernet
classification uses `networksetup -listallhardwareports` (macOS interface
names like `en0` don't reliably indicate media type on their own).

---

## Windows

### Requirements

Run from an **elevated PowerShell prompt**:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_windows_dependencies.ps1
```

This installs `nmap` (which bundles the Npcap capture driver it needs) via
`winget` or Chocolatey, whichever is available. If neither is installed,
download nmap directly from <https://nmap.org/download.html#windows>.

### Run

```powershell
python .\lan_inventory_scan_windows.py
```

Network detection and Wi-Fi/Ethernet classification use PowerShell's
`Get-NetIPAddress`/`Get-NetAdapter`/`Get-NetRoute` cmdlets, loaded once per
run rather than once per host (spawning PowerShell per discovered device
would be far slower than the enrichment work it's classifying).

---

## Command-Line Flags

All three entry points accept the same flags; run `--help` on any of them for
the full built-in text.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-h`, `--help` | none | n/a | Prints help and exits. |
| `--timeout` | positive integer seconds | `120` | Safety ceiling for the discovery pass. Discovery is a bare ping sweep, so this is rarely approached -- it exists purely as a fallback, not something you need to tune. |
| `--enrich-timeout` | positive integer seconds | `180` | Safety ceiling for the hostname/DNS/route enrichment pass. |
| `--raspberry-pis`, `--pis` | none | disabled | Filters the terminal output and CSV to only likely Raspberry Pi devices. |
| `--workers` | positive integer | `4` | Number of `/24` chunks scanned in parallel during discovery. |
| `--enrich-workers` | positive integer | `16` | Number of hosts enriched in parallel. |
| `--checkpoint` | filesystem path | `.lan_inventory_checkpoint.json` | Where discovery progress is saved so an interrupted scan can resume. |
| `--no-resume` | none | disabled | Ignore any existing checkpoint and start a fresh scan. |
| `--clear-checkpoint` | none | disabled | Delete the checkpoint file after a successful scan. |
| `--no-browser` | none | disabled | Skip the interactive sort/search browser after the scan, even in a terminal. |

Common examples:

```bash
# Default: auto-paced discovery + enrichment, live progress, browse after
sudo ./lan_inventory_scan_pi.py

# More parallel discovery chunks
sudo ./lan_inventory_scan_pi.py --workers 8

# Save progress to a custom checkpoint path
sudo ./lan_inventory_scan_pi.py --checkpoint ./checkpoints/home-lan.json

# Start fresh even if a checkpoint exists, then remove it after success
sudo ./lan_inventory_scan_pi.py --no-resume --clear-checkpoint

# Output only likely Raspberry Pi devices, and skip the interactive browser
sudo ./lan_inventory_scan_pi.py --pis --no-browser
```

If a scan is interrupted (Ctrl+C, network drop, exceeding `--timeout`), the
discovery checkpoint lets you resume with the same command -- already
completed `/24` chunks are skipped.

---

## Why Root / Administrator Is Recommended

| Feature | Without elevated privileges | With elevated privileges |
|------|-------------|-----------|
| MAC addresses | Often missing | Reliable |
| Manufacturer | Often missing | Reliable |
| ARP discovery | Limited | Full |
| Host visibility | Reduced | Maximum |

---

## Hostname vs DNS Name (Important Distinction)

- **hostname**
  - Uses nmap-reported names first
  - Falls back to local DHCP lease files used by common hotspot setups (dnsmasq, NetworkManager shared connections, systemd-networkd)
  - Falls back again to Avahi/mDNS service discovery when `avahi-browse`/`avahi-resolve-address` are installed (Linux only)
  - Falls back to the reverse-DNS value when that is the only discovered name
- **dns_name**
  - Result of a strict reverse DNS (PTR) lookup
  - Often empty on home networks unless your router maintains PTR records

They may differ -- this is expected and intentional.

---

## Architecture

- `lan_inventory_core.py` -- platform-independent engine: nmap invocation and
  XML parsing, checkpointing, hostname enrichment, CSV output, sort/filter
  helpers.
- `lan_inventory_ui.py` -- the live progress view and the interactive
  sort/search browser, built on the standard library only (ANSI escape
  redraws + a small REPL), plus the discovery -> estimate -> enrichment
  orchestration shared by every platform entry point.
- `lan_inventory_scan_pi.py` / `lan_inventory_scan_macos.py` /
  `lan_inventory_scan_windows.py` -- platform-specific network detection and
  connection-type classification, plus each platform's CLI.

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```
