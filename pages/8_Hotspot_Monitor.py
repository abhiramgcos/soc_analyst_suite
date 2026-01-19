"""
Page 8: Hotspot Device Monitor
Monitor devices connected to your laptop hotspot with Suricata IDS integration
Includes fallback monitoring via tcpdump and nmap when Suricata is unavailable
"""
import streamlit as st
import pandas as pd
import subprocess
import json
import os
import sys
import re
import tempfile
import threading
import time as time_module
import requests
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SURICATA_EVE_PATH, HOTSPOT_INTERFACE, CAPTURE_INTERFACE, SUDO_PASSWORD

st.set_page_config(page_title="Hotspot Monitor", page_icon="📶", layout="wide")

st.markdown("# 📶 Hotspot Device Monitor")
st.markdown("Monitor devices connected to your laptop hotspot with **multiple detection methods**: Suricata IDS, tcpdump, and nmap.")

# =============================================================================
# Helper Functions
# =============================================================================

def check_tool_available(tool_name):
    """Check if a command-line tool is available"""
    try:
        result = subprocess.run(
            ["which", tool_name],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_suricata_status():
    """Check if Suricata is running using multiple methods for robustness"""
    methods_tried = []
    
    # Method 1: pgrep (most common)
    try:
        result = subprocess.run(
            ["pgrep", "-x", "suricata"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, "pgrep", result.stdout.strip().split('\n')
        methods_tried.append("pgrep")
    except Exception:
        methods_tried.append("pgrep (failed)")
    
    # Method 2: pidof
    try:
        result = subprocess.run(
            ["pidof", "suricata"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, "pidof", result.stdout.strip().split()
        methods_tried.append("pidof")
    except Exception:
        methods_tried.append("pidof (failed)")
    
    # Method 3: systemctl status
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "suricata"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "active" in result.stdout.strip():
            return True, "systemctl", []
        methods_tried.append("systemctl")
    except Exception:
        methods_tried.append("systemctl (failed)")
    
    # Method 4: Check PID file
    pid_file = "/var/run/suricata.pid"
    try:
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = f.read().strip()
                if pid and os.path.exists(f"/proc/{pid}"):
                    return True, "pid_file", [pid]
        methods_tried.append("pid_file")
    except Exception:
        methods_tried.append("pid_file (failed)")
    
    # Method 5: ps aux grep (last resort)
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'suricata' in line.lower() and 'grep' not in line.lower():
                # Extract PID (second column)
                parts = line.split()
                if len(parts) >= 2:
                    return True, "ps_aux", [parts[1]]
        methods_tried.append("ps_aux")
    except Exception:
        methods_tried.append("ps_aux (failed)")
    
    return False, "none", methods_tried


def get_suricata_pid_count():
    """Get number of Suricata processes running"""
    running, method, pids = get_suricata_status()
    if running and pids:
        return len(pids)
    return 0


def run_sudo_command(cmd_args, timeout=30):
    """Run a command with sudo, using password from config if available"""
    try:
        if SUDO_PASSWORD:
            # Use echo to pipe password to sudo -S
            full_cmd = f"echo '{SUDO_PASSWORD}' | sudo -S " + " ".join(cmd_args)
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        else:
            # Try without password (requires NOPASSWD in sudoers)
            result = subprocess.run(
                ["sudo"] + cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        return result
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        return None


def start_suricata(interface):
    """Start Suricata on specified interface"""
    try:
        # Check if already running - kill duplicates if multiple instances
        pid_count = get_suricata_pid_count()
        if pid_count > 1:
            # Multiple instances running - kill all and restart cleanly
            run_sudo_command(["killall", "-9", "suricata"], timeout=10)
            import time
            time.sleep(2)
        elif pid_count == 1:
            return True, "Suricata is already running"
        
        # Remove stale PID file if exists but process not running
        pid_file = "/var/run/suricata.pid"
        run_sudo_command(["rm", "-f", pid_file], timeout=5)
        
        # Also clean up any stale socket
        run_sudo_command(["rm", "-f", "/var/run/suricata-command.socket"], timeout=5)
        
        # Start Suricata in daemon mode
        result = run_sudo_command(
            ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", interface, "-D"],
            timeout=30
        )
        
        if result is None:
            return False, "Command timed out. Check SUDO_PASSWORD in .env file."
        
        if result.returncode == 0:
            return True, f"Suricata started on interface {interface}"
        else:
            stderr = result.stderr.strip()
            if "password" in stderr.lower() or "sudo" in stderr.lower():
                return False, "Sudo password required. Set SUDO_PASSWORD in .env file."
            if "pid file" in stderr.lower() or "already running" in stderr.lower():
                # Try removing PID and retry once
                run_sudo_command(["rm", "-f", pid_file], timeout=5)
                import time
                time.sleep(1)
                result2 = run_sudo_command(
                    ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", interface, "-D"],
                    timeout=30
                )
                if result2 and result2.returncode == 0:
                    return True, f"Suricata started on interface {interface}"
            return False, f"Failed to start: {stderr}"
    except Exception as e:
        return False, str(e)


def stop_suricata():
    """Stop Suricata"""
    try:
        result = run_sudo_command(["pkill", "suricata"], timeout=10)
        if result is None:
            return False, "Command timed out"
        return True, "Suricata stopped"
    except Exception as e:
        return False, str(e)


# =============================================================================
# Alternative Monitoring: tcpdump
# =============================================================================

def capture_traffic_tcpdump(interface, duration=10, packet_count=100):
    """Capture traffic using tcpdump as a fallback when Suricata is unavailable"""
    if not check_tool_available("tcpdump"):
        return None, "tcpdump not installed"
    
    traffic_data = []
    try:
        # Capture packets with tcpdump
        cmd = [
            "tcpdump", "-i", interface, "-c", str(packet_count),
            "-nn", "-q", "-l"  # numeric, quiet, line-buffered
        ]
        
        result = run_sudo_command(cmd, timeout=duration + 5)
        
        if result is None:
            return None, "tcpdump timed out"
        
        if result.returncode != 0 and not result.stdout:
            return None, f"tcpdump error: {result.stderr}"
        
        # Parse tcpdump output
        for line in result.stdout.strip().split('\n'):
            if not line or 'listening on' in line.lower() or 'packets captured' in line.lower():
                continue
            
            # Parse basic packet info
            packet = parse_tcpdump_line(line)
            if packet:
                traffic_data.append(packet)
        
        return traffic_data, f"Captured {len(traffic_data)} packets"
    
    except Exception as e:
        return None, str(e)


def parse_tcpdump_line(line):
    """Parse a single tcpdump output line"""
    try:
        # Example: 12:34:56.789 IP 192.168.1.1.443 > 192.168.1.2.54321: tcp 100
        parts = line.split()
        if len(parts) < 5:
            return None
        
        timestamp = parts[0]
        proto = parts[1] if len(parts) > 1 else "unknown"
        
        # Extract source and destination
        src_dest = None
        for i, p in enumerate(parts):
            if '>' in p or (i + 1 < len(parts) and parts[i + 1] == '>'):
                src_idx = i - 1 if '>' in p else i
                if src_idx >= 0 and src_idx + 2 < len(parts):
                    src = parts[src_idx].rstrip(':')
                    dest_idx = src_idx + 2 if parts[src_idx + 1] == '>' else src_idx + 1
                    if dest_idx < len(parts):
                        dest = parts[dest_idx].rstrip(':')
                        src_dest = (src, dest)
                break
        
        if not src_dest:
            return None
        
        src, dest = src_dest
        
        # Parse IP:port
        src_ip, src_port = parse_ip_port(src)
        dest_ip, dest_port = parse_ip_port(dest)
        
        return {
            "timestamp": timestamp,
            "proto": proto.upper(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "raw": line
        }
    except Exception:
        return None


def parse_ip_port(addr):
    """Parse IP and port from address like 192.168.1.1.443"""
    if not addr:
        return "unknown", 0
    
    # Handle IPv4 with port (last octet is port)
    parts = addr.split('.')
    if len(parts) >= 5:
        ip = '.'.join(parts[:4])
        try:
            port = int(parts[4])
        except:
            port = 0
        return ip, port
    elif len(parts) == 4:
        return addr, 0
    else:
        return addr, 0


def get_tcpdump_summary(interface, duration=5):
    """Get a quick traffic summary using tcpdump"""
    traffic, msg = capture_traffic_tcpdump(interface, duration=duration, packet_count=50)
    
    if traffic is None:
        return None, msg
    
    # Summarize traffic
    summary = defaultdict(lambda: {"packets": 0, "ips": set()})
    
    for pkt in traffic:
        proto = pkt.get("proto", "OTHER")
        summary[proto]["packets"] += 1
        summary[proto]["ips"].add(pkt.get("src_ip", ""))
        summary[proto]["ips"].add(pkt.get("dest_ip", ""))
    
    # Convert sets to counts
    result = {}
    for proto, data in summary.items():
        result[proto] = {
            "packets": data["packets"],
            "unique_ips": len(data["ips"] - {""})
        }
    
    return result, f"Analyzed {len(traffic)} packets"


# =============================================================================
# Alternative Monitoring: nmap
# =============================================================================

def get_hotspot_subnet(interface):
    """Get the subnet for the hotspot interface"""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0:
            # Parse inet line: inet 10.42.0.1/24 brd 10.42.0.255
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
                    if match:
                        return match.group(1)
        
        # Fallback: common hotspot subnets
        return "10.42.0.0/24"
    except Exception:
        return "10.42.0.0/24"


def nmap_discover_devices(interface=None, subnet=None):
    """Discover devices on the network using nmap (no root required for basic scan)"""
    if not check_tool_available("nmap"):
        return None, "nmap not installed. Install with: sudo apt install nmap"
    
    if not subnet and interface:
        subnet = get_hotspot_subnet(interface)
    elif not subnet:
        subnet = "10.42.0.0/24"
    
    devices = []
    try:
        # Try with sudo first for MAC address detection
        result = run_sudo_command(
            ["nmap", "-sn", "-T4", "--no-stylesheet", subnet],
            timeout=60
        )
        
        # If sudo fails, try without sudo (won't get MAC addresses)
        if result is None or (result.returncode != 0 and result.stderr):
            result = subprocess.run(
                ["nmap", "-sn", "-T4", "--no-stylesheet", subnet],
                capture_output=True, text=True, timeout=60
            )
        
        if result is None:
            return None, "nmap scan timed out"
        
        if result.returncode != 0:
            stderr = result.stderr if hasattr(result, 'stderr') and result.stderr else ""
            if "root" in stderr.lower() or "privileges" in stderr.lower():
                return None, "nmap requires root privileges. Set SUDO_PASSWORD in .env"
            return None, f"nmap failed: {stderr[:100]}"
        
        # Parse nmap output
        current_host = {}
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if line.startswith('Nmap scan report for'):
                # Save previous host
                if current_host.get('ip'):
                    devices.append(current_host)
                
                # Parse new host
                current_host = {}
                # Format: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
                match = re.search(r'for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    hostname = match.group(1) if match.group(1) else "Unknown"
                    ip = match.group(2)
                    current_host = {
                        "ip": ip,
                        "hostname": hostname,
                        "mac": "Unknown",
                        "vendor": "Unknown",
                        "source": "nmap"
                    }
            
            elif line.startswith('MAC Address:'):
                # Format: "MAC Address: XX:XX:XX:XX:XX:XX (Vendor)"
                match = re.search(r'MAC Address:\s+([A-F0-9:]+)\s*(?:\((.+)\))?', line)
                if match:
                    current_host["mac"] = match.group(1)
                    if match.group(2):
                        current_host["vendor"] = match.group(2)
        
        # Don't forget last host
        if current_host.get('ip'):
            devices.append(current_host)
        
        return devices, f"Found {len(devices)} devices via nmap"
    
    except subprocess.TimeoutExpired:
        return None, "nmap scan timed out"
    except Exception as e:
        return None, str(e)

def nmap_discover_devices_enhanced(interface=None, subnet=None):
    """Enhanced nmap discovery with service detection (uses sudo for better results)"""
    if not subnet and interface:
        subnet = get_hotspot_subnet(interface)
    elif not subnet:
        subnet = "10.42.0.0/24"
        
    try:
        # Use -sV for service detection instead of -O (OS detection requires root)
        # -F: Fast mode (top 100 ports)
        # --version-light: Light version detection (faster)
        cmd = ["nmap", "-sV", "-F", "--version-light", "--no-stylesheet", subnet]
        result = run_sudo_command(cmd, timeout=120)
        
        if result is None:
            return nmap_discover_devices(interface, subnet)  # Fallback to basic scan
        
        if result.returncode != 0:
            stderr = result.stderr if result.stderr else ""
            if "root" in stderr.lower() or "privileges" in stderr.lower():
                # Fall back to basic scan without sudo
                return nmap_discover_devices(interface, subnet)
            return nmap_discover_devices(interface, subnet)
            
        devices = []
        current_host = {}
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            
            if line.startswith('Nmap scan report for'):
                if current_host.get('ip'):
                    devices.append(current_host)
                current_host = {"source": "nmap-enhanced", "mac": "Unknown", "vendor": "Unknown"}
                
                match = re.search(r'for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    current_host["hostname"] = match.group(1) if match.group(1) else "Unknown"
                    current_host["ip"] = match.group(2)
                    
            elif line.startswith('MAC Address:'):
                match = re.search(r'MAC Address:\s+([A-F0-9:]+)\s*(?:\((.+)\))?', line)
                if match:
                    current_host["mac"] = match.group(1)
                    if match.group(2):
                        current_host["vendor"] = match.group(2)
                        
            elif line.startswith('Device type:'):
                current_host["device_type"] = line.split(':', 1)[1].strip()
                
            elif line.startswith('Running:'):
                current_host["os_running"] = line.split(':', 1)[1].strip()
                
            elif line.startswith('OS details:'):
                current_host["os_details"] = line.split(':', 1)[1].strip()
                
        if current_host.get('ip'):
            devices.append(current_host)
            
        return devices, f"Enhanced scan found {len(devices)} devices"
            
    except Exception as e:
        # Fallback to basic scan on any error
        return nmap_discover_devices(interface, subnet)


def nmap_port_scan(ip, ports="22,80,443,8080,3389"):
    """Quick port scan on a specific device (works without root for TCP connect scan)"""
    if not check_tool_available("nmap"):
        return None, "nmap not installed"
    
    try:
        # Try with sudo first for SYN scan (faster, more reliable)
        result = run_sudo_command(
            ["nmap", "-sS", "-T4", "-p", ports, "--open", "--no-stylesheet", ip],
            timeout=30
        )
        
        # If sudo fails, fall back to TCP connect scan (no root required)
        if result is None or result.returncode != 0:
            result = subprocess.run(
                ["nmap", "-sT", "-T4", "-p", ports, "--open", "--no-stylesheet", ip],
                capture_output=True, text=True, timeout=30
            )
        
        if result is None:
            return None, "Scan timed out"
        
        if result.returncode != 0:
            return None, f"Scan failed: {result.stderr[:100] if result.stderr else 'Unknown error'}"
        
        open_ports = []
        for line in result.stdout.split('\n'):
            # Match lines like: "22/tcp   open  ssh"
            match = re.search(r'(\d+)/(\w+)\s+open\s+(\S+)', line)
            if match:
                open_ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3)
                })
        
        return open_ports, f"Scanned {ip}"
    
    except subprocess.TimeoutExpired:
        return None, "Scan timed out"
    except Exception as e:
        return None, str(e)


# =============================================================================
# Tool Availability Check
# =============================================================================

def get_available_tools():
    """Check which monitoring tools are available"""
    tools = {
        "suricata": check_tool_available("suricata"),
        "tcpdump": check_tool_available("tcpdump"),
        "nmap": check_tool_available("nmap"),
        "arp": check_tool_available("arp"),
        "ip": check_tool_available("ip"),
        "python3": check_tool_available("python3"),
    }
    return tools


def scan_network_scapy(interface):
    """Run the helper scapy scanner script with sudo"""
    scanner_script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner_scapy.py")
    
    if not os.path.exists(scanner_script):
        return None, "Scanner script not found"
        
    try:
        # Get subnet for interface
        subnet = get_hotspot_subnet(interface)
        if not subnet:
            return None, "Could not determine subnet"
            
        cmd = ["python3", scanner_script, subnet, "--interface", interface]
        result = run_sudo_command(cmd, timeout=30)
        
        if result is None:
            return None, "Scan timed out"
            
        if result.returncode != 0:
            return None, f"Scan failed: {result.stderr}"
            
        try:
            devices = json.loads(result.stdout)
            if "error" in devices:
                return None, devices["error"]
                
             # Add extra fields
            for dev in devices:
                dev["hostname"] = get_hostname(dev["ip"])
                if "vendor" not in dev:
                     dev["vendor"] = get_mac_vendor(dev["mac"])
                dev["source"] = "Scapy"
                
            return devices, f"Scapy found {len(devices)} devices"
        except json.JSONDecodeError:
            return None, "Invalid JSON output from scanner"
            
    except Exception as e:
        return None, str(e)


def parse_ip_neighbor():
    """Parse 'ip neighbor' command output"""
    devices = []
    try:
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
        # 192.168.1.1 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                state = parts[-1]
                
                if state not in ["FAILED", "INCOMPLETE"]:
                    mac = "Unknown"
                    try:
                        lladdr_idx = parts.index("lladdr")
                        mac = parts[lladdr_idx + 1].upper()
                    except ValueError:
                        continue
                        
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": get_hostname(ip),
                        "vendor": get_mac_vendor(mac),
                        "source": "ip neigh"
                    })
        return devices
    except Exception:
        return []


def get_connected_devices(use_nmap_fallback=True, interface=None):
    """Get devices connected to hotspot via ARP, DHCP leases, and optionally nmap"""
    devices = []
    detection_methods = []
    
    # Method 1: ARP table
    try:
        result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 3 and parts[0] != "Address":
                ip = parts[0]
                mac = parts[2] if parts[2] != "(incomplete)" else "Unknown"
                if not ip.startswith("127.") and mac != "Unknown":
                    devices.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "hostname": get_hostname(ip),
                        "vendor": get_mac_vendor(mac.upper()),
                        "source": "ARP"
                    })
        if devices:
            detection_methods.append("ARP")
    except Exception:
        pass
        
    # Method 2: ip neighbor (modern Linux)
    neigh_devices = parse_ip_neighbor()
    if neigh_devices:
        for nd in neigh_devices:
            if not any(d["ip"] == nd["ip"] for d in devices):
                devices.append(nd)
            # Update info if Mac was unknown
            for d in devices:
                if d["ip"] == nd["ip"] and d["mac"] == "Unknown" and nd["mac"] != "Unknown":
                    d["mac"] = nd["mac"]
                    d["vendor"] = get_mac_vendor(nd["mac"])
                    
        if neigh_devices and "ARP" not in detection_methods:
             detection_methods.append("IP NEIGH")
    
    # Method 2: DHCP leases (for dnsmasq-based hotspot)
    lease_files = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/NetworkManager/dnsmasq-*.leases",
        "/tmp/dnsmasq.leases"
    ]
    
    dhcp_found = False
    for lease_file in lease_files:
        try:
            import glob
            for f in glob.glob(lease_file):
                with open(f, 'r') as lf:
                    for line in lf:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            mac = parts[1].upper()
                            ip = parts[2]
                            hostname = parts[3] if len(parts) > 3 else "Unknown"
                            # Check if already exists
                            if not any(d["ip"] == ip for d in devices):
                                devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "hostname": hostname,
                                    "vendor": get_mac_vendor(mac),
                                    "source": "DHCP"
                                })
                                dhcp_found = True
        except Exception:
            pass
    
    if dhcp_found:
        detection_methods.append("DHCP")
        
    # Method 4: Scapy Scan (if interface provided)
    if interface:
        # Only run if we don't have many devices yet or specifically requested
        # Because it requires sudo and might be slow
        pass # Only run explicitly via button to avoid slowness on load
    
    # Method 3: nmap scan as fallback (if no devices found or explicitly requested)
    if use_nmap_fallback and len(devices) == 0 and interface:
        nmap_devices, msg = nmap_discover_devices(interface=interface)
        if nmap_devices:
            for dev in nmap_devices:
                if not any(d["ip"] == dev["ip"] for d in devices):
                    devices.append(dev)
            detection_methods.append("nmap")
    
    # Store detection methods for display
    if 'detection_methods' not in st.session_state:
        st.session_state.detection_methods = []
    st.session_state.detection_methods = detection_methods
    
    return devices


def get_hostname(ip):
    """Resolve hostname from IP"""
    try:
        result = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            return parts[1] if len(parts) > 1 else "Unknown"
    except Exception:
        pass
    return "Unknown"


def get_mac_vendor(mac):
    """Get vendor from MAC address (first 3 octets)"""
    # Common IoT/device vendors - expand as needed
    vendors = {
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1A:22": "Raspberry Pi",
        "28:CD:C1": "Raspberry Pi",
        "D8:3A:DD": "Raspberry Pi",
        "2C:CF:67": "Raspberry Pi",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Hyper-V",
        "F4:F5:D8": "Google",
        "94:B9:7E": "Google",
        "54:60:09": "Google",
        "18:B4:30": "Nest",
        "64:16:66": "Nest",
        "B8:8A:60": "Intel",
        "3C:7C:3F": "Intel",
        "A4:83:E7": "Apple",
        "F0:18:98": "Apple",
        "AC:DE:48": "Apple",
        "00:1E:C2": "Apple",
        "5C:F9:38": "Apple",
        "78:2B:46": "Samsung",
        "94:35:0A": "Samsung",
        "A0:CC:2B": "Samsung",
        "50:01:BB": "Samsung",
        "18:3A:2D": "Samsung",
        "EC:FA:BC": "Xiaomi",
        "64:B4:73": "Xiaomi",
        "78:11:DC": "Xiaomi",
        "34:80:B3": "Xiaomi",
        "50:EC:50": "Xiaomi",
        "00:17:88": "Philips Hue",
        "00:24:E4": "TP-Link",
        "14:CC:20": "TP-Link",
        "50:C7:BF": "TP-Link",
        "60:E3:27": "TP-Link",
        "B0:BE:76": "TP-Link",
        "68:FF:7B": "TP-Link",
        "18:D6:C7": "TP-Link",
        "AC:84:C6": "TP-Link",
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
        "00:04:20": "ESP/Arduino",
        "24:0A:C4": "Espressif",
        "30:AE:A4": "Espressif",
        "24:6F:28": "Espressif",
        "A4:CF:12": "Espressif",
        "84:F3:EB": "Espressif",
        "CC:50:E3": "Espressif",
        "8C:AA:B5": "Espressif",
        "D8:BF:C0": "Espressif",
        "4C:11:AE": "Espressif",
        "08:3A:F2": "Espressif",
        "B4:E6:2D": "Espressif",
        "EC:FA:BC": "Espressif",
    }
    
    if mac and len(mac) >= 17:
        prefix = mac[:8].upper()
        vendor = vendors.get(prefix)
        if vendor:
            return vendor
            
        # Try online lookup with caching
        return get_mac_vendor_online(mac)
        
    return "Unknown"

@st.cache_data(ttl=3600*24)
def get_mac_vendor_online(mac):
    """Get MAC vendor from online API"""
    try:
        url = f"https://api.macvendors.co/{mac}"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass
    return "Unknown"


def read_suricata_alerts(eve_path, limit=100, device_ips=None):
    """Read recent alerts from Suricata EVE JSON log"""
    alerts = []
    
    if not os.path.exists(eve_path):
        return alerts
    
    try:
        # Read last portion of file
        with open(eve_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, 2)  # End of file
            file_size = f.tell()
            chunk_size = min(file_size, 512 * 1024)  # Read last 512KB
            f.seek(max(0, file_size - chunk_size))
            
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if data.get("event_type") == "alert":
                        alert = data.get("alert", {})
                        src_ip = data.get("src_ip", "")
                        dest_ip = data.get("dest_ip", "")
                        
                        # Filter by device IPs if specified
                        if device_ips:
                            if src_ip not in device_ips and dest_ip not in device_ips:
                                continue
                        
                        alerts.append({
                            "timestamp": data.get("timestamp", ""),
                            "signature": alert.get("signature", "Unknown"),
                            "severity": alert.get("severity", 4),
                            "category": alert.get("category", "Unknown"),
                            "src_ip": src_ip,
                            "src_port": data.get("src_port", 0),
                            "dest_ip": dest_ip,
                            "dest_port": data.get("dest_port", 0),
                            "proto": data.get("proto", "TCP"),
                        })
                except json.JSONDecodeError:
                    continue
            
            # Sort by timestamp descending and limit
            alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return alerts[:limit]
    except Exception as e:
        st.error(f"Error reading EVE log: {e}")
        return alerts


def read_flow_stats(eve_path, device_ips=None):
    """Read flow statistics from Suricata EVE log"""
    flows = defaultdict(lambda: {"bytes_sent": 0, "bytes_recv": 0, "packets": 0, "connections": 0})
    
    if not os.path.exists(eve_path):
        return dict(flows)
    
    try:
        with open(eve_path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, 2)
            file_size = f.tell()
            chunk_size = min(file_size, 1024 * 1024)
            f.seek(max(0, file_size - chunk_size))
            
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if data.get("event_type") == "flow":
                        src_ip = data.get("src_ip", "")
                        dest_ip = data.get("dest_ip", "")
                        flow = data.get("flow", {})
                        
                        if device_ips:
                            if src_ip in device_ips:
                                flows[src_ip]["bytes_sent"] += flow.get("bytes_toserver", 0)
                                flows[src_ip]["bytes_recv"] += flow.get("bytes_toclient", 0)
                                flows[src_ip]["packets"] += flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
                                flows[src_ip]["connections"] += 1
                            elif dest_ip in device_ips:
                                flows[dest_ip]["bytes_recv"] += flow.get("bytes_toserver", 0)
                                flows[dest_ip]["bytes_sent"] += flow.get("bytes_toclient", 0)
                                flows[dest_ip]["packets"] += flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
                                flows[dest_ip]["connections"] += 1
                except json.JSONDecodeError:
                    continue
    except Exception:
        pass
    
    return dict(flows)


def get_severity_badge(severity):
    """Return colored badge for severity"""
    colors = {
        1: ("🔴", "Critical"),
        2: ("🟠", "High"),
        3: ("🟡", "Medium"),
        4: ("🟢", "Low")
    }
    icon, label = colors.get(severity, ("⚪", "Unknown"))
    return f"{icon} {label}"


def format_bytes(bytes_val):
    """Format bytes to human readable"""
# Format bytes to human readable
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"

# =============================================================================
# Sidebar Controls
# =============================================================================

with st.sidebar:
    st.markdown("### 🛠️ Available Tools")
    
    # Check available tools
    tools = get_available_tools()
    tool_cols = st.columns(3)
    with tool_cols[0]:
        if tools["suricata"]:
            st.markdown("✅ Suricata")
        else:
            st.markdown("❌ Suricata")
    with tool_cols[1]:
        if tools["tcpdump"]:
            st.markdown("✅ tcpdump")
        else:
            st.markdown("❌ tcpdump")
    with tool_cols[2]:
        if tools["nmap"]:
            st.markdown("✅ nmap")
        else:
            st.markdown("❌ nmap")
    
    st.markdown("---")
    st.markdown("### ⚙️ Suricata Controls")
    
    # More robust status check
    suricata_running, detection_method, pids = get_suricata_status()
    
    if suricata_running:
        st.success(f"✅ Suricata Running (via {detection_method})")
        if pids:
            st.caption(f"PID(s): {', '.join(pids[:3])}")
    else:
        st.warning("⚠️ Suricata Not Running")
        if tools["tcpdump"]:
            st.info("💡 tcpdump available as fallback")
    
    interface = st.text_input(
        "Monitor Interface",
        value=HOTSPOT_INTERFACE,
        help="Network interface to monitor (hotspot interface)"
    )
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶️ Start", use_container_width=True, disabled=suricata_running):
            success, msg = start_suricata(interface)
            if success:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
    
    with col2:
        if st.button("⏹️ Stop", use_container_width=True, disabled=not suricata_running):
            success, msg = stop_suricata()
            if success:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
    
    st.markdown("---")
    st.markdown("### 📁 EVE Log")
    st.code(SURICATA_EVE_PATH, language=None)
    
    if os.path.exists(SURICATA_EVE_PATH):
        size = os.path.getsize(SURICATA_EVE_PATH)
        st.caption(f"Size: {format_bytes(size)}")
    else:
        st.caption("File not found")
    
    st.markdown("---")
    st.markdown("### 🔍 Quick Scans")
    
    if st.button("📡 tcpdump Capture (5s)", use_container_width=True, disabled=not tools["tcpdump"]):
        with st.spinner("Capturing traffic..."):
            summary, msg = get_tcpdump_summary(interface, duration=5)
            if summary:
                st.session_state.tcpdump_result = summary
                st.success(msg)
            else:
                st.error(msg)
    
    if st.button("🔎 nmap Device Scan", use_container_width=True, disabled=not tools["nmap"]):
        with st.spinner("Scanning network (Quick)..."):
            devices_found, msg = nmap_discover_devices(interface=interface)
            if devices_found:
                st.session_state.nmap_devices = devices_found
                st.success(msg)
            else:
                st.error(msg)
                
    if st.button("🧬 Deep Scan (Scapy + Nmap OS)", use_container_width=True):
         with st.spinner("Running deep scan (this may take a moment)..."):
            # Run Scapy
            scapy_devs, s_msg = scan_network_scapy(interface)
            if scapy_devs:
                st.session_state.scapy_devices = scapy_devs
                st.success(s_msg)
                
            # Run Nmap OS detection
            if tools["nmap"]:
                nmap_devs, n_msg = nmap_discover_devices_enhanced(interface=interface)
                if nmap_devs:
                     st.session_state.nmap_devices = nmap_devs
                     if "os_details" in nmap_devs[0]:
                         st.info(n_msg + " with OS details")
            
            st.rerun()

# =============================================================================
# Main Content
# =============================================================================

# Refresh button
col1, col2, col3 = st.columns([1, 1, 4])
with col1:
    refresh = st.button("🔄 Refresh", use_container_width=True)
with col2:
    auto_refresh = st.checkbox("Auto-refresh", value=False)

if auto_refresh:
    st.markdown(
        """
        <script>
            setTimeout(function(){
                window.location.reload();
            }, 10000);
        </script>
        """,
        unsafe_allow_html=True
    )

st.markdown("---")

# =============================================================================
# Connected Devices Section
# =============================================================================

st.markdown("### 📱 Connected Devices")

# Use nmap as fallback if no devices found via ARP/DHCP
devices = get_connected_devices(use_nmap_fallback=True, interface=interface)

# Show detection methods used
if hasattr(st.session_state, 'detection_methods') and st.session_state.detection_methods:
    methods_str = ", ".join(st.session_state.detection_methods)
    st.caption(f"Detection methods: {methods_str}")

# Show nmap devices if available in session state
if 'nmap_devices' in st.session_state and st.session_state.nmap_devices:
    # Merge nmap devices with existing
    # Merge nmap devices with existing
    for nmap_dev in st.session_state.nmap_devices:
        existing = next((d for d in devices if d["ip"] == nmap_dev["ip"]), None)
        if existing:
            # Update with better info
             if nmap_dev.get("mac") != "Unknown": existing["mac"] = nmap_dev["mac"]
             if nmap_dev.get("vendor") != "Unknown": existing["vendor"] = nmap_dev["vendor"]
             if nmap_dev.get("os_details"): existing["os"] = nmap_dev["os_details"]
             if nmap_dev.get("device_type"): existing["type"] = nmap_dev.get("device_type")
        else:
            devices.append(nmap_dev)

# Show Scapy devices
if 'scapy_devices' in st.session_state and st.session_state.scapy_devices:
     for s_dev in st.session_state.scapy_devices:
        existing = next((d for d in devices if d["ip"] == s_dev["ip"]), None)
        if existing:
            if s_dev.get("mac") and existing.get("mac") == "Unknown":
                existing["mac"] = s_dev["mac"]
                existing["vendor"] = s_dev["vendor"]
        else:
            devices.append(s_dev)

if devices:
    device_ips = [d["ip"] for d in devices]
    
    # Get traffic stats for each device
    flow_stats = read_flow_stats(SURICATA_EVE_PATH, device_ips)
    
    # Create device cards
    cols = st.columns(min(len(devices), 3))
    
    for idx, device in enumerate(devices):
        with cols[idx % 3]:
            ip = device["ip"]
            stats = flow_stats.get(ip, {})
            
            with st.container():
                st.markdown(f"""
                <div style="background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%); 
                            padding: 15px; border-radius: 10px; margin-bottom: 10px;
                            border-left: 4px solid #4CAF50;">
                    <h4 style="margin:0; color: #fff;">🖥️ {device['hostname']}</h4>
                    <p style="margin: 5px 0; color: #b0c4de; font-size: 14px;">
                        <strong>IP:</strong> {ip}<br>
                        <strong>MAC:</strong> {device['mac']}<br>
                        <strong>Vendor:</strong> {device['vendor']}
                    </p>
                    <hr style="border-color: #4a6fa5; margin: 10px 0;">
                    <p style="margin: 0; color: #98fb98; font-size: 13px;">
                        📤 Sent: {format_bytes(stats.get('bytes_sent', 0))}<br>
                        📥 Recv: {format_bytes(stats.get('bytes_recv', 0))}<br>
                        📦 Packets: {stats.get('packets', 0):,}<br>
                        🔗 Connections: {stats.get('connections', 0)}
                    </p>
                </div>
                """, unsafe_allow_html=True)
    
    # Device table
    st.markdown("#### 📋 Device Details")
    df_devices = pd.DataFrame(devices)
    
    # Add traffic stats to dataframe
    df_devices["Bytes Sent"] = df_devices["ip"].apply(lambda x: format_bytes(flow_stats.get(x, {}).get("bytes_sent", 0)))
    df_devices["Bytes Recv"] = df_devices["ip"].apply(lambda x: format_bytes(flow_stats.get(x, {}).get("bytes_recv", 0)))
    df_devices["Connections"] = df_devices["ip"].apply(lambda x: flow_stats.get(x, {}).get("connections", 0))
    
    st.dataframe(
        df_devices.rename(columns={
            "ip": "IP Address",
            "mac": "MAC Address", 
            "hostname": "Hostname",
            "vendor": "Vendor",
            "source": "Detection"
        }),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No devices detected. Make sure your hotspot is active and devices are connected.")
    st.markdown("""
    **To create a hotspot on Linux:**
    ```bash
    # Using NetworkManager
    nmcli device wifi hotspot ifname wlp0s20f3 ssid MyHotspot password "mypassword"
    
    # Or use GNOME Settings → Wi-Fi → Turn On Wi-Fi Hotspot
    ```
    """)
    device_ips = []

st.markdown("---")

# =============================================================================
# Traffic Monitoring Section (Suricata + tcpdump fallback)
# =============================================================================

st.markdown("### 🚨 Traffic Monitoring & Security Alerts")

# Get current status
suricata_status, detection_method, pids = get_suricata_status()
tools = get_available_tools()

# Create tabs for different monitoring methods
tab1, tab2, tab3 = st.tabs(["📊 Suricata IDS", "📡 tcpdump Capture", "🔎 nmap Results"])

with tab1:
    if not suricata_status:
        st.warning("⚠️ Suricata is not running. Start it from the sidebar to monitor traffic.")
        if tools["tcpdump"]:
            st.info("💡 **Alternative:** Use the tcpdump tab for quick traffic capture, or click 'tcpdump Capture' in the sidebar.")
    elif not os.path.exists(SURICATA_EVE_PATH):
        st.warning(f"⚠️ EVE log not found at: {SURICATA_EVE_PATH}")
    else:
        # Get alerts filtered by connected device IPs
        alerts = read_suricata_alerts(SURICATA_EVE_PATH, limit=50, device_ips=device_ips if devices else None)
        
        if alerts:
            # Alert statistics
            col1, col2, col3, col4 = st.columns(4)
            
            severity_counts = defaultdict(int)
            for a in alerts:
                severity_counts[a["severity"]] += 1
            
            with col1:
                st.metric("Total Alerts", len(alerts))
            with col2:
                st.metric("🔴 Critical", severity_counts.get(1, 0))
            with col3:
                st.metric("🟠 High", severity_counts.get(2, 0))
            with col4:
                st.metric("🟡 Medium", severity_counts.get(3, 0))
            
            # Alerts table
            st.markdown("#### Recent Alerts")
            
            df_alerts = pd.DataFrame(alerts)
            df_alerts["Severity"] = df_alerts["severity"].apply(get_severity_badge)
            df_alerts["Time"] = pd.to_datetime(df_alerts["timestamp"]).dt.strftime("%H:%M:%S")
            
            # Reorder columns for display
            display_cols = ["Time", "Severity", "signature", "category", "src_ip", "src_port", "dest_ip", "dest_port", "proto"]
            df_display = df_alerts[display_cols].rename(columns={
                "signature": "Signature",
                "category": "Category",
                "src_ip": "Source IP",
                "src_port": "Src Port",
                "dest_ip": "Dest IP",
                "dest_port": "Dst Port",
                "proto": "Protocol"
            })
            
            st.dataframe(df_display, use_container_width=True, hide_index=True)
            
            # Alert details expander
            with st.expander("🔍 View Alert Details"):
                for alert in alerts[:10]:
                    severity = get_severity_badge(alert["severity"])
                    st.markdown(f"""
                    **{severity}** | {alert['timestamp'][:19]}  
                    **Signature:** {alert['signature']}  
                    **Category:** {alert['category']}  
                    **Flow:** {alert['src_ip']}:{alert['src_port']} → {alert['dest_ip']}:{alert['dest_port']} ({alert['proto']})
                    
                    ---
                    """)
        else:
            st.info("No alerts detected yet. Suricata is monitoring traffic...")

with tab2:
    st.markdown("#### 📡 tcpdump Traffic Capture")
    
    if not tools["tcpdump"]:
        st.error("❌ tcpdump is not installed. Install with: `sudo apt install tcpdump`")
    else:
        st.info("tcpdump provides quick traffic capture when Suricata is unavailable.")
        
        # Show tcpdump results from session state
        if 'tcpdump_result' in st.session_state and st.session_state.tcpdump_result:
            st.markdown("##### Last Capture Results")
            
            result = st.session_state.tcpdump_result
            cols = st.columns(len(result))
            
            for idx, (proto, data) in enumerate(result.items()):
                with cols[idx % len(cols)]:
                    st.metric(proto, f"{data['packets']} pkts", f"{data['unique_ips']} IPs")
        
        # Quick capture button
        capture_duration = st.slider("Capture duration (seconds)", 3, 30, 5)
        if st.button("🎯 Start Capture", use_container_width=True):
            with st.spinner(f"Capturing traffic for {capture_duration}s..."):
                traffic, msg = capture_traffic_tcpdump(interface, duration=capture_duration, packet_count=200)
                if traffic:
                    st.success(msg)
                    
                    # Display traffic
                    df_traffic = pd.DataFrame(traffic)
                    if not df_traffic.empty:
                        display_df = df_traffic[["timestamp", "proto", "src_ip", "src_port", "dest_ip", "dest_port"]].head(50)
                        st.dataframe(display_df, use_container_width=True, hide_index=True)
                else:
                    st.error(msg)

with tab3:
    st.markdown("#### 🔎 nmap Network Scan Results")
    
    if not tools["nmap"]:
        st.error("❌ nmap is not installed. Install with: `sudo apt install nmap`")
    else:
        st.info("nmap provides network device discovery and port scanning.")
        
        # Show nmap results from session state
        if 'nmap_devices' in st.session_state and st.session_state.nmap_devices:
            st.markdown("##### Discovered Devices")
            
            df_nmap = pd.DataFrame(st.session_state.nmap_devices)
            st.dataframe(df_nmap, use_container_width=True, hide_index=True)
            
            # Port scan individual device
            st.markdown("##### Quick Port Scan")
            if st.session_state.nmap_devices:
                ip_options = [d["ip"] for d in st.session_state.nmap_devices]
                selected_ip = st.selectbox("Select device to scan", ip_options)
                
                if st.button(f"Scan ports on {selected_ip}"):
                    with st.spinner("Scanning ports..."):
                        ports, msg = nmap_port_scan(selected_ip)
                        if ports:
                            st.success(f"Found {len(ports)} open ports")
                            st.dataframe(pd.DataFrame(ports), use_container_width=True, hide_index=True)
                        else:
                            st.info("No open ports found (or scan failed)")
        else:
            st.info("No scan results yet. Click 'nmap Device Scan' in the sidebar to discover devices.")

st.markdown("---")

# =============================================================================
# Quick Commands Section
# =============================================================================

with st.expander("🛠️ Quick Commands & Help"):
    st.markdown("""
    ### Starting Suricata Manually
    ```bash
    # Start Suricata on your hotspot interface
    sudo suricata -c /etc/suricata/suricata.yaml -i wlp0s20f3
    
    # Run in daemon mode
    sudo suricata -c /etc/suricata/suricata.yaml -i wlp0s20f3 -D
    
    # View live alerts
    sudo tail -f /var/log/suricata/fast.log
    ```
    
    ### Creating a Hotspot
    ```bash
    # Create hotspot with NetworkManager
    nmcli device wifi hotspot ifname wlp0s20f3 ssid "MyHotspot" password "securepassword"
    
    # Stop hotspot
    nmcli connection down Hotspot
    ```
    
    ### Checking Connected Devices
    ```bash
    # View ARP table
    arp -n
    
    # View DHCP leases (if using dnsmasq)
    cat /var/lib/misc/dnsmasq.leases
    ```
    
    ### Suricata Rule Management
    ```bash
    # Update rules
    sudo suricata-update
    
    # Test configuration
    sudo suricata -T -c /etc/suricata/suricata.yaml
    ```
    """)

# =============================================================================
# Footer
# =============================================================================

st.markdown("---")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | EVE Path: {SURICATA_EVE_PATH}")
