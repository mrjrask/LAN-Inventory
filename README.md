# LAN Inventory Scanner (Raspberry Pi & macOS)

This project provides two terminal-based Python scripts that scan an entire private IPv4 range
(`192.168.0.1` through `192.168.255.255`) and generate a CSV inventory of devices found on the local network.

Both scripts:

- Prompt the user at launch for **how many seconds the scan should run**
- Perform host discovery using **nmap**
- Capture:
  - IP address
  - Hostname (as reported by nmap)
  - DNS name (reverse DNS / PTR lookup)
  - MAC address
  - Manufacturer (vendor/OUI)
- Output a CSV file sorted by IP address
- Work best when run with **administrator/root privileges**

---

## Files

| Script | Platform |
|------|----------|
| `lan_inventory_scan_pi.py` | Raspberry Pi OS (Bookworm & Trixie) |
| `lan_inventory_scan_mac.py` | macOS (26.2 and newer) |

Both scripts are intentionally similar so results are consistent across platforms.

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

Both scripts generate:

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

---

## Raspberry Pi Version

### Supported OS Versions

- Raspberry Pi OS **Bookworm**
- Raspberry Pi OS **Trixie**

### Requirements

```bash
sudo apt update
sudo apt install -y nmap python3
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

At launch, the script will ask:

```
How many seconds should the scan run for? [600]:
```

Enter the desired timeout in seconds, or press **Enter** to accept the default.

---

## macOS Version

### Supported OS Versions

- macOS **26.2** and newer

### Requirements

Install Homebrew (if needed):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install dependencies:

```bash
brew install nmap python
```

### Script Name

```
lan_inventory_scan_mac.py
```

### Run

```bash
chmod +x lan_inventory_scan_mac.py
sudo ./lan_inventory_scan_mac.py
```

You will be prompted at launch for the scan duration (seconds).

---

## Why Root / sudo Is Strongly Recommended

Running without elevated privileges will still work, but with limitations:

| Feature | Without sudo | With sudo |
|------|-------------|-----------|
| MAC addresses | Often missing | Reliable |
| Manufacturer | Often missing | Reliable |
| ARP discovery | Limited | Full |
| Host visibility | Reduced | Maximum |

For best results on **both Raspberry Pi and macOS**, always use `sudo`.

---

## Hostname vs DNS Name (Important Distinction)

- **hostname**
  - Reported by nmap
  - May come from DNS, mDNS (`.local`), NetBIOS, or other discovery methods
- **dns_name**
  - Result of a strict reverse DNS (PTR) lookup
  - Often empty on home networks unless your router maintains PTR records

They may differ — this is expected and intentional.

---

## Performance Expectations

A `/16` scan includes **65,536 possible addresses**.

Typical scan times:
- Small LAN: several minutes
- Busy or filtered networks: longer
- Wi-Fi environments: slower than wired

If you want:
- Parallel `/24` chunk scanning
- Progress indicators / ETA
- Resume / checkpointing
- SQLite output instead of CSV
- Scheduled scans (systemd timer or macOS launchd)

These can be added cleanly.

---

## Safety Notes

- These scripts perform **host discovery only**
- No ports are scanned
- No services are touched
- Safe for home and business networks where you have authorization

Do not run on networks you do not own or manage.

---

## Summary

- One scan
- One CSV
- Maximum visibility
- Works on Raspberry Pi and macOS
- Explicit user-controlled scan duration

This is designed to be a **trustworthy inventory baseline** you can automate or extend.

