# Network Traffic Analyzer 🔍📊

A Python-based network traffic analysis tool that captures, analyzes, and visualizes network packets to detect suspicious activity.

![Traffic Analysis Sample](traffic_report.png)

## Features ✨
- **Packet Capture**: Uses Scapy to sniff live network traffic
- **Threat Detection**: Identifies potential port scans, DDoS attacks, and suspicious connections
- **Traffic Visualization**: Generates pie charts and bar graphs of protocol distribution and top talkers
- **Custom Alerts**: Configurable thresholds for different attack patterns

## Installation ⚙️

### Prerequisites
- Python 3.8+
- Kali Linux or any Linux distribution
- Root privileges (for packet capture)

### Setup
```bash
# Clone the repository
git clone https://github.com/siddhanth36/network-analyzer.git
cd network-analyzer

# Install dependencies
sudo apt update
sudo apt install tshark
pip install -r requirements.txt

# usage
# Run with sudo privileges
sudo python3 traffic_analyzer.py
