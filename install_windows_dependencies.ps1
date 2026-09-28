#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs dependencies for lan_inventory_scan_windows.py.

.DESCRIPTION
  Installs nmap (which bundles the Npcap packet-capture driver it needs
  for host discovery) via winget or Chocolatey, whichever is available.
  Run this from an elevated PowerShell prompt.
#>

$ErrorActionPreference = "Stop"

function Test-Command($name) {
    return [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

if (Test-Command "nmap") {
    Write-Host "nmap is already installed."
}
elseif (Test-Command "winget") {
    Write-Host "Installing nmap via winget..."
    winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
}
elseif (Test-Command "choco") {
    Write-Host "Installing nmap via Chocolatey..."
    choco install nmap -y
}
else {
    Write-Host "Neither winget nor Chocolatey was found." -ForegroundColor Yellow
    Write-Host "Install nmap (with Npcap) manually from https://nmap.org/download.html#windows and re-run this script."
    exit 1
}

if (-not (Test-Command "python")) {
    Write-Host "python was not found on PATH." -ForegroundColor Yellow
    Write-Host "Install Python 3 from https://www.python.org/downloads/windows/ (check 'Add python.exe to PATH')."
}

Write-Host ""
Write-Host "Done. Run the scanner from an elevated PowerShell prompt with:"
Write-Host "  python .\lan_inventory_scan_windows.py"
Write-Host ""
Write-Host "Administrator/elevated PowerShell is optional but strongly recommended:"
Write-Host "without it, Windows will often hide MAC addresses and vendor info for discovered hosts."
