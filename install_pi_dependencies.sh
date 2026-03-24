#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Re-running with sudo to install Raspberry Pi dependencies..."
  exec sudo bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PI_SCRIPT="${SCRIPT_DIR}/lan_inventory_scan_pi.py"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: apt-get was not found. This installer is intended for Raspberry Pi OS (Debian-based)." >&2
  exit 1
fi

echo "Updating apt package index..."
apt-get update

echo "Installing dependencies (python3, nmap, iproute2)..."
apt-get install -y python3 nmap iproute2

if [[ -f "${PI_SCRIPT}" ]]; then
  chmod +x "${PI_SCRIPT}"
  echo "Made executable: ${PI_SCRIPT}"
fi

echo
cat <<'MSG'
Done. You can run the scanner with:
  sudo ./lan_inventory_scan_pi.py
MSG
