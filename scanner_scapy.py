#!/usr/bin/env python3
"""
Scapy-based ARP Scanner
This script is intended to be run with sudo privileges to perform
low-level ARP scanning which might not be possible from the main user process.
"""
import sys
import json
import argparse
from scapy.all import ARP, Ether, srp
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

def get_mac_vendor_prefix(mac):
    """Simple prefix extraction for vendor lookup"""
    return mac.replace(":", "").upper()[:6]

def scan(target_ip, interface=None):
    """
    Perform ARP scan
    """
    # Create ARP request packet
    # hwsrc is automatically set to the interface's MAC if not specified
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        # Send packet and receive response
        # timeout: wait 2 seconds for response
        # verbose: 0 (silent)
        if interface:
            result = srp(packet, timeout=2, verbose=0, iface=interface)[0]
        else:
            result = srp(packet, timeout=2, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor_prefix": get_mac_vendor_prefix(received.hwsrc)
            })
        
        return devices
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scapy ARP Scanner")
    parser.add_argument("target", help="Target IP or CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--interface", "-i", help="Network interface to use")
    
    args = parser.parse_args()
    
    try:
        results = scan(args.target, args.interface)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
