# LAN Inventory Scanner (Raspberry Pi)

This project provides a terminal-based Python script that scans an entire private IPv4 range
(`192.168.0.1` through `192.168.255.255`) and generates a CSV inventory of devices found on the local network.

The script:

- Prompts the user at launch for **how many seconds the scan should run** unless `--timeout` is provided
- Performs host discovery using **nmap**
- Splits broad IPv4 ranges into parallel `/24` scan chunks
- Shows scan progress, elapsed time, and ETA while chunks complete
- Saves a checkpoint after each chunk so interrupted scans can resume
- Captures:
  - IP address
  - Hostname (from nmap, local DHCP leases, reverse DNS, or mDNS/Avahi fallback)
  - DNS name (reverse DNS / PTR lookup)
  - MAC address
  - Manufacturer (vendor/OUI)
- Outputs a CSV file sorted by IP address
- Can filter output to likely Raspberry Pi devices with `--raspberry-pis` / `--pis`
- Prints a formatted terminal table for quick viewing
- Works best when run with **administrator/root privileges**

---

## Files

| Script | Platform |
|------|----------|
| `lan_inventory_scan_pi.py` | Raspberry Pi OS (Bookworm & Trixie) |
| `install_pi_dependencies.sh` | Raspberry Pi OS installer for scanner dependencies |

---

## Network Range Scanned

The scan range is fixed to:

```
192.168.0.0/16
```

This covers:

```
192.168.0.1 → 192.168.255.255
```

This ensures **maximum coverage** of typical home and small-business networks, even if multiple
`/24` subnets exist behind routers, VLANs, or mesh systems.

---

## Output

The script generates:

```
network_inventory.csv
```

### CSV Columns

| Column | Description |
|------|-------------|
| `ip_address` | IPv4 address of the host |
| `hostname` | Hostname from nmap first, then local DHCP lease files, then Avahi/mDNS service discovery or address resolution, then reverse DNS |
| `dns_name` | Reverse DNS (PTR record lookup); may be empty |
| `mac_address` | MAC address (best on local L2 networks) |
| `manufacturer` | Vendor derived from MAC OUI |

Example row:

```csv
192.168.1.42,my-printer,printer.local,AA:BB:CC:DD:EE:FF,HP
```

### CLI Table Output

In addition to CSV export, the script prints a formatted table in the terminal showing:

- IP Address
- Hostname
- DNS Name
- MAC Address
- Manufacturer

---

## Raspberry Pi Version

### Supported OS Versions

- Raspberry Pi OS **Bookworm**
- Raspberry Pi OS **Trixie**

### Requirements

Use the included installer script (recommended):

```bash
chmod +x install_pi_dependencies.sh
./install_pi_dependencies.sh
```

Or install manually:

```bash
sudo apt update
sudo apt install -y nmap python3 iproute2
```

### Script Name

```
lan_inventory_scan_pi.py
```

### Run

```bash
chmod +x lan_inventory_scan_pi.py
sudo ./lan_inventory_scan_pi.py
```


### Command-Line Flags

Run `./lan_inventory_scan_pi.py --help` to print the built-in help text. The scanner supports these flags:

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-h`, `--help` | none | n/a | Prints the command-line help and exits without scanning. |
| `--timeout` | positive integer seconds | interactive prompt, default prompt value `600` | Sets the total scan time budget in seconds and skips the launch prompt. The value must be greater than zero. |
| `--raspberry-pis`, `--pis` | none | disabled | Filters the terminal output and CSV to only likely Raspberry Pi devices. Matching uses Raspberry Pi MAC vendor/manufacturer data first, then common Raspberry Pi hostname and reverse-DNS patterns. |
| `--workers` | positive integer | `4` | Sets how many scan chunks run in parallel. Higher values can finish faster but may increase CPU, network, and router load. The value must be greater than zero. |
| `--checkpoint` | filesystem path | `.lan_inventory_checkpoint.json` | Chooses where scan progress is saved. Completed chunks and discovered hosts are written after each chunk so interrupted scans can resume. |
| `--no-resume` | none | disabled | Ignores any existing checkpoint file and starts a fresh scan. The checkpoint path is still used for saving progress during the new run. |
| `--clear-checkpoint` | none | disabled | Deletes the checkpoint file after a successful scan. This is useful when you do not want a completed checkpoint to remain after CSV output is written. |

Common examples:

```bash
# Run for ten minutes using the default checkpoint and four workers
sudo ./lan_inventory_scan_pi.py --timeout 600

# Run with more parallel scan chunks
sudo ./lan_inventory_scan_pi.py --timeout 600 --workers 8

# Save progress to a custom checkpoint path
sudo ./lan_inventory_scan_pi.py --timeout 600 --checkpoint ./checkpoints/home-lan.json

# Start fresh even if a checkpoint exists, then remove the checkpoint after success
sudo ./lan_inventory_scan_pi.py --timeout 600 --no-resume --clear-checkpoint

# Output only likely Raspberry Pi devices
sudo ./lan_inventory_scan_pi.py --timeout 600 --raspberry-pis
sudo ./lan_inventory_scan_pi.py --timeout 600 --pis
```

To skip the interactive timeout prompt:

```bash
sudo ./lan_inventory_scan_pi.py --timeout 600
```

Scan chunks run in parallel by default. Adjust concurrency with `--workers`:

```bash
sudo ./lan_inventory_scan_pi.py --timeout 600 --workers 8
```

The script writes a resume checkpoint to `.lan_inventory_checkpoint.json` after each completed chunk. If a scan is interrupted, rerun the same command to skip completed chunks and continue. Use `--no-resume` to ignore an existing checkpoint, `--checkpoint PATH` to choose a different checkpoint file, or `--clear-checkpoint` to delete the checkpoint after a successful scan:

```bash
sudo ./lan_inventory_scan_pi.py --timeout 600 --workers 8 --clear-checkpoint
```

To show only likely Raspberry Pi devices, with their IP addresses and hostnames, run:

```bash
sudo ./lan_inventory_scan_pi.py --raspberry-pis --timeout 600
```

The shorter alias is also supported:

```bash
sudo ./lan_inventory_scan_pi.py --pis --timeout 600
```

Yes: manufacturer matching helps a lot when nmap can see each device MAC address. Raspberry Pi filtering first checks whether the MAC vendor/manufacturer identifies Raspberry Pi hardware, then falls back to discovered hostname / reverse DNS names containing common Raspberry Pi names such as `raspberrypi`, `raspberry-pi`, `raspberry_pi`, or `rpi`.

At launch, without `--timeout`, the script will ask:

```
How many seconds should the scan run for? [600]:
```

Enter the desired timeout in seconds, or press **Enter** to accept the default.

---

## Why Root / sudo Is Strongly Recommended

Running without elevated privileges will still work, but with limitations:

| Feature | Without sudo | With sudo |
|------|-------------|-----------|
| MAC addresses | Often missing | Reliable |
| Manufacturer | Often missing | Reliable |
| ARP discovery | Limited | Full |
| Host visibility | Reduced | Maximum |

For best results, always use `sudo`.

---

## Hostname vs DNS Name (Important Distinction)

- **hostname**
  - Uses nmap-reported names first
  - Falls back to local DHCP lease files used by common Raspberry Pi hotspot setups (for example dnsmasq, NetworkManager shared connections, and systemd-networkd)
  - Falls back again to Avahi/mDNS service discovery when `avahi-browse` is installed, then per-host mDNS address resolution when `avahi-resolve-address` is installed
  - Falls back to the reverse-DNS value when that is the only discovered name
- **dns_name**
  - Result of a strict reverse DNS (PTR) lookup
  - Often empty on home networks unless your router maintains PTR records

They may differ — this is expected and intentional. On Raspberry Pi hotspot networks, reverse DNS is often empty, but the hotspot DHCP lease file can still provide the client hostname. The Raspberry Pi-only flag checks both values so it can still find devices when MAC vendor information is unavailable.

---

## Performance Expectations

A `/16` scan includes **65,536 possible addresses**.

Typical scan times:
- Small LAN: several minutes
- Busy or filtered networks: longer
- Wi-Fi environments: slower than wired

Implemented scanner features include parallel `/24` chunk scanning, progress / ETA output, and resume checkpointing. Future enhancements that can be added cleanly include SQLite output and scheduled scans with a systemd timer.

---

## Safety Notes

- This script performs **host discovery only**
- No ports are scanned
- No services are touched
- Safe for home and business networks where you have authorization

Do not run on networks you do not own or manage.

---

## Summary
