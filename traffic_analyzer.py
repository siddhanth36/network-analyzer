#!/usr/bin/env python3
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
import time

# Configuration
INTERFACE = "eth0"  # Change to your network interface (use 'ip a' to check)
CAPTURE_TIME = 30  # Seconds to capture
THRESHOLD_ALERTS = {
    "port_scan": 50,  # Ports/sec threshold
    "ddos": 1000,     # Packets/sec threshold
}

def basic_sniffer():
    """Basic packet capture with Scapy"""
    print(f"🕸️ Sniffing on {INTERFACE} for {CAPTURE_TIME} seconds...")
    packets = sniff(iface=INTERFACE, timeout=CAPTURE_TIME)
    print(f"📦 Captured {len(packets)} packets")
    return packets

def analyze_traffic(packets):
    """Advanced traffic analysis"""
    stats = {
        "protocols": defaultdict(int),
        "suspicious": [],
        "top_talkers": defaultdict(int)
    }

    for pkt in packets:
        # Protocol breakdown
        if pkt.haslayer(IP):
            stats["top_talkers"][pkt[IP].src] += 1
            if pkt.haslayer(TCP):
                stats["protocols"]["TCP"] += 1
                # Detect port scans
                if pkt[TCP].flags == "S":  # SYN packet
                    stats["suspicious"].append(f"SYN scan from {pkt[IP].src}:{pkt[TCP].sport}")
            elif pkt.haslayer(UDP):
                stats["protocols"]["UDP"] += 1
            elif pkt.haslayer(ICMP):
                stats["protocols"]["ICMP"] += 1

    # Generate alerts
    pps = len(packets)/CAPTURE_TIME  # Packets per second
    if pps > THRESHOLD_ALERTS["ddos"]:
        stats["suspicious"].append(f"⚠️ DDoS alert: {pps:.1f} packets/sec")

    return stats

def visualize_results(stats):
    """Create traffic visualizations"""
    # Protocol pie chart
    plt.figure(figsize=(12, 4))
    plt.subplot(1, 2, 1)
    plt.pie(
        stats["protocols"].values(),
        labels=stats["protocols"].keys(),
        autopct="%1.1f%%"
    )
    plt.title("Protocol Distribution")

    # Top talkers bar chart
    top_5 = dict(sorted(stats["top_talkers"].items(), 
                       key=lambda x: x[1], reverse=True)[:5])
    plt.subplot(1, 2, 2)
    plt.bar(top_5.keys(), top_5.values())
    plt.title("Top 5 Talkers")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save and show
    plt.savefig("traffic_report.png")
    print("📊 Saved visualization to traffic_report.png")

def main():
    # Capture packets
    packets = basic_sniffer()
    
    # Analyze
    stats = analyze_traffic(packets)
    
    # Print results
    print("\n📊 Protocol Breakdown:")
    for proto, count in stats["protocols"].items():
        print(f"{proto}: {count} packets")
    
    print("\n🔍 Suspicious Activity:")
    for alert in stats["suspicious"][:5]:  # Show top 5 alerts
        print(alert)
    
    # Visualize
    visualize_results(stats)

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("❌ Run with sudo for packet capture!")
