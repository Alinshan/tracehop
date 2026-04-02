# Tracehop Windows Setup & Environment Automator
# Author: Alinshan
# Description: Installs Scoop, Nuclei, Ffuf, and Tracehop dependencies.

$ErrorActionPreference = "Stop"

Write-Host "`n[+] INITIALIZING TRACEHOP PENTEST ENVIRONMENT SETUP..." -ForegroundColor Cyan

# 1. Check for Scoop
if (!(Get-Command scoop -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Scoop not found. Installing Scoop (Package Manager for Windows)..." -ForegroundColor Yellow
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
    Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
    Write-Host "[+] Scoop installed successfully." -ForegroundColor Green
} else {
    Write-Host "[+] Scoop is already installed." -ForegroundColor Green
}

# 2. Install Pentest Tools via Scoop
Write-Host "[*] Installing Nuclei, Ffuf, Httpx, and Subfinder..." -ForegroundColor Cyan
scoop install nuclei ffuf httpx subfinder

# 3. Install Python Dependencies
Write-Host "[*] Installing Python dependencies (PySide6, PyYAML, Rich, etc)..." -ForegroundColor Cyan
pip install -r requirements.txt

# 4. Create Wordlists Directory
$wordlistDir = Join-Path $PSScriptRoot "wordlists"
if (!(Test-Path $wordlistDir)) {
    New-Item -ItemType Directory -Path $wordlistDir
    Write-Host "[+] Created wordlists directory." -ForegroundColor Green
}

# 5. Recommendation: Download SecLists
Write-Host "`n[TIP] For best results with Ffuf, download SecLists manually:" -ForegroundColor Green
Write-Host "      git clone https://github.com/danielmiessler/SecLists.git ./wordlists/SecLists" -ForegroundColor White

Write-Host "`n[+++] SETUP COMPLETE! YOU CAN NOW RUN TRACEHOP." -ForegroundColor Cyan
Write-Host "      Usage: python tracehop.py --gui" -ForegroundColor White
