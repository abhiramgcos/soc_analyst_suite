#!/usr/bin/env python3
"""
Automated Network Device Scanner: IP, MAC, Vendor, OS, Ports
Enhanced scanner with Scapy ARP, Nmap integration, and OUI lookup.
For Kubuntu/Jetson SOC integration. Run with sudo for best results.
"""
import subprocess
import threading
import time
import csv
import socket
import struct
import fcntl
import os
import sys
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Install with: pip install scapy")

try:
    import nmap
    PYTHON_NMAP_AVAILABLE = True
except ImportError:
    PYTHON_NMAP_AVAILABLE = False
    logger.warning("python-nmap not available. Install with: pip install python-nmap")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# =============================================================================
# OUI Database for MAC Vendor Lookup
# =============================================================================

# Common OUI prefixes (first 3 bytes of MAC address)
# Format: "XX:XX:XX" -> "Vendor Name"
OUI_DATABASE = {
    # Espressif (ESP32/ESP8266)
    "24:6F:28": "Espressif (ESP32/ESP8266)",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
    "A4:CF:12": "Espressif",
    "84:F3:EB": "Espressif",
    "CC:50:E3": "Espressif",
    "8C:AA:B5": "Espressif",
    "D8:BF:C0": "Espressif",
    "4C:11:AE": "Espressif",
    "08:3A:F2": "Espressif",
    "B4:E6:2D": "Espressif",
    "AC:67:B2": "Espressif",
    "EC:FA:BC": "Espressif",
    
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "D8:3A:DD": "Raspberry Pi Trading",
    "2C:CF:67": "Raspberry Pi Trading",
    
    # Arduino/Microchip
    "00:04:20": "Arduino/Microchip",
    
    # Microsoft
    "00:50:C2": "Microsoft",
    "00:50:F2": "Microsoft",
    "00:17:FA": "Microsoft",
    
    # Apple
    "00:03:93": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "A4:83:E7": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "5C:F9:38": "Apple",
    
    # Samsung
    "00:00:F0": "Samsung",
    "00:02:78": "Samsung",
    "00:09:18": "Samsung",
    "00:0D:AE": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:7D": "Samsung",
    "00:1E:E1": "Samsung",
    "00:1E:E2": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "78:2B:46": "Samsung",
    "94:35:0A": "Samsung",
    "A0:CC:2B": "Samsung",
    "50:01:BB": "Samsung",
    "18:3A:2D": "Samsung",
    
    # Google/Nest
    "F4:F5:D8": "Google",
    "94:B9:7E": "Google",
    "54:60:09": "Google",
    "18:B4:30": "Google Nest",
    "64:16:66": "Google Nest",
    
    # Amazon
    "44:65:0D": "Amazon",
    "FC:65:DE": "Amazon Echo",
    "50:DC:E7": "Amazon",
    "A0:02:DC": "Amazon",
    "84:D6:D0": "Amazon",
    "00:FC:8B": "Amazon",
    "F0:F0:A4": "Amazon",
    "74:C2:46": "Amazon",
    "68:54:FD": "Amazon",
    "40:B4:CD": "Amazon",
    
    # TP-Link
    "00:24:E4": "TP-Link",
    "14:CC:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "60:E3:27": "TP-Link",
    "B0:BE:76": "TP-Link",
    "68:FF:7B": "TP-Link",
    "18:D6:C7": "TP-Link",
    "AC:84:C6": "TP-Link",
    
    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0C:F1": "Intel",
    "00:0E:0C": "Intel",
    "00:0E:35": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:15:17": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:17:35": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    "00:1B:21": "Intel",
    "00:1B:77": "Intel",
    "00:1C:BF": "Intel",
    "00:1C:C0": "Intel",
    "00:1D:E0": "Intel",
    "00:1D:E1": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "B8:8A:60": "Intel",
    "3C:7C:3F": "Intel",
    
    # VMware/VirtualBox/QEMU
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V",
    
    # Xiaomi
    "EC:FA:BC": "Xiaomi",
    "64:B4:73": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "50:EC:50": "Xiaomi",
    
    # Philips Hue
    "00:17:88": "Philips Lighting (Hue)",
    
    # Tuya/Smart Life
    "D8:F1:5B": "Tuya Smart",
    
    # Sonoff/ITEAD
    "DC:4F:22": "Espressif (Sonoff)",
    
    # Shelly
    "8C:CE:4E": "Shelly",
    "E8:DB:84": "Shelly/Allterco",
}


def lookup_oui_vendor(mac: str) -> str:
    """
    Lookup vendor from MAC address using OUI database
    
    Args:
        mac: MAC address in format XX:XX:XX:XX:XX:XX
    
    Returns:
        Vendor name or "Unknown"
    """
    if not mac or len(mac) < 8:
        return "Unknown"
    
    # Normalize MAC format
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
    prefix = mac_clean[:8]  # First 3 octets (XX:XX:XX)
    
    return OUI_DATABASE.get(prefix, "Unknown")


def get_default_interface() -> Optional[str]:
    """Get the default network interface name"""
    try:
        # Try to get from route table
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Format: default via X.X.X.X dev eth0 ...
            parts = result.stdout.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass
    
    # Fallback to common interfaces
    for iface in ["eth0", "wlan0", "enp0s3", "wlp2s0"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    
    return None


def get_default_gateway() -> str:
    """Get local subnet based on default gateway"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Format: default via 192.168.1.1 dev eth0
            parts = result.stdout.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gateway = parts[idx + 1]
                    # Convert gateway to subnet
                    octets = gateway.split('.')
                    if len(octets) == 4:
                        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except Exception:
        pass
    
    return "192.168.1.0/24"


def get_interface_ip(interface: str) -> Optional[str]:
    """Get IP address of an interface"""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            import re
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


# =============================================================================
# ARP Scanning with Scapy
# =============================================================================

def arp_scan(subnet: str, interface: Optional[str] = None, timeout: int = 3) -> List[Dict]:
    """
    ARP scan to discover IP/MAC addresses on local network.
    Requires root privileges and Scapy.
    
    Args:
        subnet: Network to scan (e.g., "192.168.1.0/24")
        interface: Network interface to use (optional)
        timeout: Scan timeout in seconds
    
    Returns:
        List of devices with IP, MAC, and Vendor
    """
    if not SCAPY_AVAILABLE:
        logger.error("Scapy not available for ARP scan")
        return []
    
    devices = []
    
    try:
        # Configure Scapy
        conf.verb = 0  # Suppress output
        
        # Build ARP request
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        
        # Send and receive
        if interface:
            answered, _ = srp(packet, timeout=timeout, verbose=False, iface=interface)
        else:
            answered, _ = srp(packet, timeout=timeout, verbose=False)
        
        for sent, received in answered:
            mac = received.hwsrc.upper()
            vendor = lookup_oui_vendor(mac)
            
            devices.append({
                "ip": received.psrc,
                "mac": mac,
                "vendor": vendor,
                "source": "arp"
            })
        
        logger.info(f"ARP scan found {len(devices)} devices")
        
    except PermissionError:
        logger.error("ARP scan requires root privileges")
    except Exception as e:
        logger.error(f"ARP scan error: {e}")
    
    return devices


# =============================================================================
# Nmap Scanning
# =============================================================================

def nmap_scan_device(ip: str, options: str = "-sV --top-ports 100") -> Dict[str, Any]:
    """
    Run Nmap scan on a single IP for OS/port detection.
    
    Args:
        ip: Target IP address
        options: Nmap options
    
    Returns:
        Dict with OS, ports, services info
    """
    result = {
        "os": "Unknown",
        "ports": [],
        "services": [],
        "hostname": "",
        "device_type": "Unknown"
    }
    
    if PYTHON_NMAP_AVAILABLE:
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments=options)
            
            if ip in nm.all_hosts():
                host = nm[ip]
                
                # OS Detection
                if 'osmatch' in host and host['osmatch']:
                    result["os"] = host['osmatch'][0].get('name', 'Unknown')
                
                # Hostname
                if 'hostnames' in host and host['hostnames']:
                    for hn in host['hostnames']:
                        if hn.get('name'):
                            result["hostname"] = hn['name']
                            break
                
                # Ports
                if 'tcp' in host:
                    for port_num, port_info in host['tcp'].items():
                        port_data = {
                            "port": port_num,
                            "protocol": "tcp",
                            "state": port_info.get('state', 'unknown'),
                            "service": port_info.get('name', ''),
                            "version": port_info.get('version', ''),
                            "product": port_info.get('product', '')
                        }
                        result["ports"].append(port_data)
                        
                        if port_info.get('name'):
                            result["services"].append(f"{port_num}/{port_info['name']}")
                
                # Device type heuristics
                result["device_type"] = detect_device_type(result["ports"], result["os"])
            
            return result
            
        except Exception as e:
            logger.error(f"Nmap scan error for {ip}: {e}")
    else:
        # Fallback to subprocess
        try:
            cmd = ["nmap", "-oX", "-"] + options.split() + [ip]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0:
                # Parse XML output (simplified)
                from xml.etree import ElementTree as ET
                root = ET.fromstring(proc.stdout)
                # ... basic parsing
        except Exception as e:
            logger.error(f"Subprocess nmap error: {e}")
    
    return result


def detect_device_type(ports: List[Dict], os_info: str) -> str:
    """Detect device type based on open ports and OS info"""
    port_numbers = {p.get("port") for p in ports}
    
    # Device type signatures
    signatures = {
        "IP Camera": {554, 8554, 80, 8080, 443},
        "Printer": {9100, 631, 515},
        "Router/Gateway": {80, 443, 53, 22, 23},
        "NAS/Storage": {445, 139, 80, 443, 548, 111},
        "Smart TV": {8008, 8443, 9080, 7000},
        "Smart Speaker": {8008, 8443, 10001},
        "Smart Hub/IoT Gateway": {80, 443, 1883, 8883},
        "IoT Sensor": {1883, 8883, 5683},
        "Database Server": {3306, 5432, 1433, 27017, 6379},
        "Web Server": {80, 443, 8080, 8443},
        "SSH Server": {22},
    }
    
    for device_type, sig_ports in signatures.items():
        if sig_ports & port_numbers:
            return device_type
    
    # Check OS string
    os_lower = os_info.lower()
    if "linux" in os_lower:
        return "Linux Device"
    elif "windows" in os_lower:
        return "Windows Device"
    elif "android" in os_lower:
        return "Android Device"
    elif "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower:
        return "iOS Device"
    elif "router" in os_lower or "gateway" in os_lower:
        return "Router/Gateway"
    
    return "Unknown"


# =============================================================================
# Combined Scanning
# =============================================================================

def full_network_scan(
    subnet: str,
    interface: Optional[str] = None,
    nmap_options: str = "-sV --top-ports 50 -T4",
    include_nmap: bool = True,
    callback: Optional[Callable] = None
) -> List[Dict]:
    """
    Full network scan: ARP discovery + optional Nmap enrichment.
    
    Args:
        subnet: Network to scan
        interface: Network interface
        nmap_options: Options for Nmap scans
        include_nmap: Whether to run Nmap on discovered hosts
        callback: Optional callback function(device, index, total)
    
    Returns:
        List of enriched device dictionaries
    """
    logger.info(f"Starting full network scan on {subnet}")
    start_time = time.time()
    
    # Step 1: ARP scan for fast discovery
    devices = arp_scan(subnet, interface)
    
    if not devices:
        logger.warning("ARP scan found no devices, trying basic ping scan")
        # Fallback: use nmap ping scan
        try:
            cmd = ["nmap", "-sn", "-T4", subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                # Parse basic output
                import re
                for match in re.finditer(r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    hostname = match.group(1) or ""
                    ip = match.group(2)
                    devices.append({
                        "ip": ip,
                        "mac": "Unknown",
                        "vendor": "Unknown",
                        "hostname": hostname,
                        "source": "ping"
                    })
        except Exception as e:
            logger.error(f"Ping scan fallback failed: {e}")
    
    # Step 2: Enrich with Nmap (if enabled)
    if include_nmap and devices:
        total = len(devices)
        for idx, device in enumerate(devices):
            if callback:
                callback(device, idx, total)
            
            try:
                nmap_info = nmap_scan_device(device["ip"], nmap_options)
                device.update({
                    "os": nmap_info.get("os", "Unknown"),
                    "ports": nmap_info.get("ports", []),
                    "hostname": nmap_info.get("hostname") or device.get("hostname", ""),
                    "device_type": nmap_info.get("device_type", "Unknown"),
                    "services": nmap_info.get("services", [])
                })
            except Exception as e:
                logger.warning(f"Nmap enrichment failed for {device['ip']}: {e}")
            
            # Small delay to avoid overwhelming network
            time.sleep(0.1)
    
    elapsed = time.time() - start_time
    logger.info(f"Full scan completed: {len(devices)} devices in {elapsed:.1f}s")
    
    return devices


# =============================================================================
# Continuous Scanning
# =============================================================================

class ContinuousScanner:
    """Background continuous scanner with threading"""
    
    def __init__(
        self,
        subnet: str,
        interface: Optional[str] = None,
        interval: int = 300,
        on_scan_complete: Optional[Callable] = None,
        on_new_device: Optional[Callable] = None
    ):
        self.subnet = subnet
        self.interface = interface
        self.interval = interval
        self.on_scan_complete = on_scan_complete
        self.on_new_device = on_new_device
        
        self._running = False
        self._thread = None
        self._devices: Dict[str, Dict] = {}  # IP -> device info
        self._lock = threading.Lock()
    
    def start(self):
        """Start continuous scanning in background thread"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info(f"Continuous scanner started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop continuous scanning"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Continuous scanner stopped")
    
    def _scan_loop(self):
        """Main scanning loop"""
        while self._running:
            try:
                devices = full_network_scan(
                    self.subnet,
                    self.interface,
                    include_nmap=True
                )
                
                with self._lock:
                    for device in devices:
                        ip = device["ip"]
                        is_new = ip not in self._devices
                        self._devices[ip] = device
                        
                        if is_new and self.on_new_device:
                            self.on_new_device(device)
                
                if self.on_scan_complete:
                    self.on_scan_complete(devices)
                
            except Exception as e:
                logger.error(f"Scan loop error: {e}")
            
            # Sleep in small intervals to allow quick stopping
            for _ in range(self.interval):
                if not self._running:
                    break
                time.sleep(1)
    
    def get_devices(self) -> List[Dict]:
        """Get current device list"""
        with self._lock:
            return list(self._devices.values())


# =============================================================================
# Export Functions
# =============================================================================

def save_to_csv(devices: List[Dict], filename: str = "network_scan.csv"):
    """Save scan results to CSV file"""
    if not devices:
        return False
    
    if PANDAS_AVAILABLE:
        # Flatten ports for CSV
        flat_devices = []
        for d in devices:
            flat = d.copy()
            if "ports" in flat:
                flat["ports"] = ", ".join([f"{p.get('port')}/{p.get('service', '')}" for p in flat["ports"]])
            if "services" in flat:
                flat["services"] = ", ".join(flat["services"])
            flat_devices.append(flat)
        
        df = pd.DataFrame(flat_devices)
        df.to_csv(filename, index=False)
    else:
        # Manual CSV writing
        if devices:
            keys = list(devices[0].keys())
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                for d in devices:
                    row = d.copy()
                    if "ports" in row:
                        row["ports"] = str(row["ports"])
                    writer.writerow(row)
    
    logger.info(f"Saved {len(devices)} devices to {filename}")
    return True


def save_to_json(devices: List[Dict], filename: str = "network_scan.json"):
    """Save scan results to JSON file"""
    with open(filename, 'w') as f:
        json.dump(devices, f, indent=2, default=str)
    logger.info(f"Saved {len(devices)} devices to {filename}")
    return True


# =============================================================================
# Display Functions
# =============================================================================

def display_devices_rich(devices: List[Dict], title: str = "Network Devices"):
    """Display devices using Rich library"""
    if not RICH_AVAILABLE or not console:
        print(f"\n{title}")
        print("-" * 80)
        for d in devices:
            print(f"IP: {d.get('ip')}, MAC: {d.get('mac')}, Vendor: {d.get('vendor')}, OS: {d.get('os', 'N/A')}")
        return
    
    table = Table(title=title)
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="yellow")
    table.add_column("Vendor", style="green")
    table.add_column("OS", style="magenta")
    table.add_column("Ports", style="blue")
    
    for device in devices:
        ports_str = ", ".join(device.get("services", [])[:5])
        table.add_row(
            device.get("ip", ""),
            device.get("mac", "Unknown"),
            device.get("vendor", "Unknown"),
            device.get("os", "Unknown")[:30],
            ports_str[:40]
        )
    
    console.print(table)


# =============================================================================
# CLI Main
# =============================================================================

def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Device Scanner")
    parser.add_argument("subnet", nargs="?", help="Subnet to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-o", "--output", help="Output file (CSV or JSON)")
    parser.add_argument("-c", "--continuous", type=int, metavar="SECONDS",
                        help="Continuous scan interval")
    parser.add_argument("--no-nmap", action="store_true", help="Skip Nmap enrichment")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    
    # Determine subnet
    subnet = args.subnet or get_default_gateway()
    
    if RICH_AVAILABLE:
        console.print(f"[yellow]Scanning {subnet}...[/yellow]")
    else:
        print(f"Scanning {subnet}...")
    
    if args.continuous:
        # Continuous mode
        def on_complete(devices):
            display_devices_rich(devices)
            if args.output:
                if args.output.endswith('.json'):
                    save_to_json(devices, args.output)
                else:
                    save_to_csv(devices, args.output)
        
        scanner = ContinuousScanner(
            subnet,
            interface=args.interface,
            interval=args.continuous,
            on_scan_complete=on_complete
        )
        scanner.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            if RICH_AVAILABLE:
                console.print("\n[red]Stopped.[/red]")
            else:
                print("\nStopped.")
            scanner.stop()
    else:
        # Single scan
        devices = full_network_scan(
            subnet,
            interface=args.interface,
            include_nmap=not args.no_nmap
        )
        
        display_devices_rich(devices)
        
        if args.output:
            if args.output.endswith('.json'):
                save_to_json(devices, args.output)
            else:
                save_to_csv(devices, args.output)


if __name__ == "__main__":
    main()
