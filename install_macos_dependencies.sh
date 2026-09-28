#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_SCRIPT="${SCRIPT_DIR}/lan_inventory_scan_macos.py"

if ! command -v brew >/dev/null 2>&1; then
  echo "ERROR: Homebrew was not found. Install it from https://brew.sh and re-run this script." >&2
  exit 1
fi

echo "Installing dependencies (nmap)..."
brew install nmap

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 was not found; installing via Homebrew..."
  brew install python3
fi

if [[ -f "${MAC_SCRIPT}" ]]; then
  chmod +x "${MAC_SCRIPT}"
  echo "Made executable: ${MAC_SCRIPT}"
fi

echo
cat <<'MSG'
Done. You can run the scanner with:
  sudo ./lan_inventory_scan_macos.py

sudo is optional but strongly recommended: without it, macOS will often
hide MAC addresses and vendor/manufacturer info for discovered hosts.
MSG
