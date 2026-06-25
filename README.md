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
  - Hostname (as reported by nmap)
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
| `hostname` | Hostname reported by nmap (DNS, mDNS, NetBIOS, etc.) |
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

Yes: manufacturer matching helps a lot when nmap can see each device MAC address. Raspberry Pi filtering first checks whether the MAC vendor/manufacturer identifies Raspberry Pi hardware, then falls back to nmap hostname / reverse DNS names containing common Raspberry Pi names such as `raspberrypi`, `raspberry-pi`, `raspberry_pi`, or `rpi`.

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
  - Reported by nmap
  - May come from DNS, mDNS (`.local`), NetBIOS, or other discovery methods
- **dns_name**
  - Result of a strict reverse DNS (PTR) lookup
  - Often empty on home networks unless your router maintains PTR records

They may differ — this is expected and intentional. The Raspberry Pi-only flag checks both values so it can still find devices when MAC vendor information is unavailable.

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
