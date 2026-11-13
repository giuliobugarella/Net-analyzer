# Net Analyzer

A network traffic analysis tool that detects malicious network activity patterns such as port scans and Denial of Service (DoS) attacks.

## Project Overview

Net Analyzer sniffs network traffic in real-time and applies intelligent detection algorithms to identify suspicious patterns. It generates alerts when threats are detected.

## Features

- **Port Scan Detection**: Identifies vertical port scans (TCP Connect/SYN scans) from the same source IP
- **DoS Attack Detection**: Detects both ICMP and TCP-based DoS attacks
- **Real-time Packet Analysis**: Continuous network traffic monitoring with per-second analysis
- **Multi-protocol Support**: Analyzes TCP, UDP, and ICMP traffic

## Project Structure

### Core Files

| File | Purpose |
|------|---------|
| **main.py** | Entry point; initializes detectors and starts the sniffer |
| **sniffer.py** | Captures network packets using Scapy and applies detection algorithms |
| **parser.py** | Parses raw packets into structured event dictionaries |
| **portscan_detector.py** | Detects vertical port scans by tracking unique ports per source-destination pair |
| **DoS_detector.py** | Detects DoS attacks by counting ICMP/TCP packets within time windows |
| **interfaccie.py** | Utility script to list available network interfaces |

## Configuration

Edit `main.py` to adjust detection thresholds:

```python
PORT_THRESH = 10        # Ports per connection to trigger alert
ICMP_THRESH = 100       # ICMP packets per second to trigger alert
TCP_THRESH = 200        # TCP packets per second to trigger alert
```

## Requirements

- Python 3.x
- Scapy library
- Npcap or WinPcap (for packet capture on Windows)

## Usage

1. **Find your network interface:**
   ```bash
   python interfaccie.py
   ```

2. **Update the interface in main.py** (copy the interface identifier)

3. **Run the analyzer:**
   ```bash
   python main.py
   ```

The tool will continuously monitor traffic and print alerts when threats are detected.

## Alert Types

- **PORT_SCAN**: Detected when a source IP contacts ≥10 unique ports on a destination within the time window
- **ICMP_DoS**: Detected when ICMP packet rate exceeds the threshold
- **TCP_DoS**: Detected when TCP packet rate exceeds the threshold

## Note

Requires administrator privileges to capture network traffic.
