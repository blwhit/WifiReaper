# WifiReaper
<img width="341" height="345" alt="image" src="https://github.com/user-attachments/assets/adaed175-c586-48b7-b641-73d57bb622d9" />

## Overview
Automatically discover and attack WiFi networks at scale. Mass deauthentication attacks to target WPA/WPA2 networks, and capture victim WiFi handshakes to be cracked for the cleartext password to the network.

## Features

- **Network Discovery**: Automatically scan and discover networks in range
- **Handshake Capture**: Execute deauth attacks to capture WPA/WPA2 handshakes
- **Continuous Attacking**: Run in a loop to continue cracking networks in range around the clock on intervals
- **Ready to Crack**: Uses hcxpcapngtool to validate captured handshakes and convert them to ready-to-crack Hashcat formats
- **Database**: Maintains local database of known cracked networks

## Requirements

- Kali Linux or compatible distribution
- WiFi adapter capable of monitor mode
- Required packages (auto-installed):
  - aircrack-ng
  - tshark
  - hcxtools

## Installation

1. Clone the repository:
```bash
git clone https://github.com/blwhit/WifiReaper.git
cd WifiReaper
```

2. Make the script executable:
```bash
chmod +x WifiReaper.sh
```

## Usage

### Basic Scanning
```bash
# Scan only (no attacks)
sudo ./WifiReaper.sh wlan0 --scan

# Single attack run
sudo ./WifiReaper.sh wlan0
```
##### Defaults to running a 60-second discovery scan, 10-second deauthentication attack per network, and 3 retry attempts on deauthentication attacks.

### Advanced Options
```bash
# Continuously scan and attack all networks with 5-minute intervals
sudo ./WifiReaper.sh wlan0 --loop --wait 5

# Exclude specific networks
sudo ./WifiReaper.sh wlan0 -e "MyNetwork" -e "AA:BB:CC:DD:EE:FF"

# Custom scan and attack timeouts
sudo ./WifiReaper.sh wlan0 -ST 45 -DT 8 -DA 1
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --scan` | Scan only mode (no attacks) |
| `-l, --loop` | Run continuously |
| `-w, --wait <min>` | Wait time between loop cycles |
| `-ST <seconds>` | Scan timeout (default: 60) |
| `-DT <seconds>` | Deauth timeout (default: 10) |
| `-DA <attempts>` | Deauth attempts per network (default: 3) |
| `-e, --exclude <network>` | Exclude network by ESSID or BSSID |
| `-i, --ignore` | Ignore cracked database |
| `-h, --help` | Show help message |

## Output Files

- **Captures**: Stored in `Data/WifiReaper_YYYY-MM-DD_HH-MM-SS/`
- **Converted Hashes**: Stored in `Reaped/` (`.hc22000` format)
- **Database**: `Data/wifireaper_cracked.db` (tracks successful captures)

## Notice

⚠️ **IMPORTANT**: This tool is for educational and authorized security testing purposes only. Only use on networks you own or have explicit permission to test. Unauthorized access to computer networks is illegal.
