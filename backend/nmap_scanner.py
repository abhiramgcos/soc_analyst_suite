"""
IoT SOC Analyst Suite - Nmap Network Scanner Integration
Scans networks and extracts device information with risk scoring
"""
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# Risk scoring weights for common IoT vulnerable ports/services
PORT_RISK_SCORES = {
    21: 8.0,    # FTP - often has default credentials
    22: 3.0,    # SSH - generally secure but notable
    23: 9.0,    # Telnet - unencrypted, very risky
    25: 5.0,    # SMTP
    53: 4.0,    # DNS
    80: 4.0,    # HTTP - unencrypted web
    110: 5.0,   # POP3
    139: 7.0,   # NetBIOS
    143: 5.0,   # IMAP
    443: 2.0,   # HTTPS - encrypted, lower risk
    445: 7.0,   # SMB - common attack vector
    554: 6.0,   # RTSP - IP camera streaming
    1433: 8.0,  # MSSQL
    1883: 7.0,  # MQTT - IoT protocol, often insecure
    3306: 7.0,  # MySQL
    3389: 8.0,  # RDP
    5000: 5.0,  # UPnP
    5900: 7.0,  # VNC
    8080: 5.0,  # HTTP Alternate
    8443: 3.0,  # HTTPS Alternate
    8883: 4.0,  # MQTT over TLS
    9100: 5.0,  # Printer
    49152: 4.0, # UPnP
}

# Service-based risk adjustments
SERVICE_RISK_MODIFIERS = {
    "telnet": 2.0,
    "ftp": 1.5,
    "vnc": 1.5,
    "http": 1.0,
    "rtsp": 1.3,
    "mqtt": 1.4,
    "ssh": 0.8,
    "https": 0.5,
}

# Device type detection based on open ports and services
DEVICE_TYPE_SIGNATURES = {
    "IP Camera": [554, 8554, 8080, 80],
    "Printer": [9100, 631, 515],
    "Router": [80, 443, 53, 22],
    "Smart TV": [8008, 8443, 9080],
    "NAS": [445, 139, 80, 443, 548],
    "Smart Speaker": [8008, 8443],
    "Smart Hub": [80, 443, 1883],
    "IoT Sensor": [1883, 8883, 5683],
}


def scan_network(
    subnet: str,
    nmap_path: str = "nmap",
    options: str = "-sV -O -T4 --open"
) -> Dict[str, Any]:
    """
    Run Nmap scan on a subnet
    
    Args:
        subnet: Network to scan (e.g., "192.168.1.0/24")
        nmap_path: Path to nmap executable
        options: Nmap command line options
    
    Returns:
        Dict with 'success', 'devices', 'error', 'scan_time' keys
    """
    result = {
        "success": False,
        "devices": [],
        "error": None,
        "scan_time": None,
        "hosts_up": 0,
        "hosts_down": 0
    }
    
    try:
        start_time = datetime.now()
        
        # Build command
        cmd = [nmap_path] + options.split() + ["-oX", "-", subnet]
        logger.info(f"Running Nmap: {' '.join(cmd)}")
        
        # Run scan
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if process.returncode != 0 and not process.stdout:
            result["error"] = f"Nmap failed: {process.stderr}"
            return result
        
        # Parse XML output
        devices = parse_nmap_xml(process.stdout)
        
        result["success"] = True
        result["devices"] = devices
        result["scan_time"] = (datetime.now() - start_time).total_seconds()
        result["hosts_up"] = len(devices)
        
        logger.info(f"Scan completed: {len(devices)} devices found")
        
    except subprocess.TimeoutExpired:
        result["error"] = "Scan timed out (10 minutes)"
    except FileNotFoundError:
        result["error"] = f"Nmap not found at '{nmap_path}'. Please install Nmap."
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"Nmap scan error: {e}")
    
    return result


def parse_nmap_xml(xml_output: str) -> List[Dict]:
    """
    Parse Nmap XML output into device dictionaries
    """
    devices = []
    
    try:
        root = ET.fromstring(xml_output)
        
        for host in root.findall(".//host"):
            # Check if host is up
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            
            device = {
                "ip": "",
                "mac": "Unknown",
                "hostname": "",
                "device_type": "Unknown",
                "os": "Unknown",
                "ports": [],
                "risk_score": 0.0,
                "tags": [],
                "vendor": "Unknown"
            }
            
            # Get IP address
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    device["ip"] = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    device["mac"] = addr.get("addr", "Unknown")
                    device["vendor"] = addr.get("vendor", "Unknown")
            
            if not device["ip"]:
                continue
            
            # Get hostname
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hostname_elem = hostnames.find("hostname")
                if hostname_elem is not None:
                    device["hostname"] = hostname_elem.get("name", "")
            
            # Get OS detection
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    device["os"] = osmatch.get("name", "Unknown")
            
            # Get open ports and services
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    
                    port_info = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", "tcp"),
                        "service": "",
                        "version": "",
                        "product": ""
                    }
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["version"] = service.get("version", "")
                        port_info["product"] = service.get("product", "")
                    
                    device["ports"].append(port_info)
            
            # Calculate risk score
            device["risk_score"] = calculate_risk_score(device)
            
            # Detect device type
            device["device_type"] = detect_device_type(device)
            
            # Add tags
            device["tags"] = generate_device_tags(device)
            
            devices.append(device)
        
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
    except Exception as e:
        logger.error(f"Error parsing Nmap output: {e}")
    
    return devices


def calculate_risk_score(device: Dict) -> float:
    """
    Calculate risk score (0-10) based on open ports and services
    """
    if not device.get("ports"):
        return 1.0  # Minimal risk if no open ports
    
    total_score = 0.0
    max_port_score = 0.0
    
    for port_info in device["ports"]:
        port_num = port_info.get("port", 0)
        service = port_info.get("service", "").lower()
        
        # Get base port risk
        port_score = PORT_RISK_SCORES.get(port_num, 3.0)
        
        # Apply service modifier
        for svc, modifier in SERVICE_RISK_MODIFIERS.items():
            if svc in service:
                port_score *= modifier
                break
        
        total_score += port_score
        max_port_score = max(max_port_score, port_score)
    
    # Calculate weighted score
    # Use combination of max risk port and average
    num_ports = len(device["ports"])
    avg_score = total_score / num_ports if num_ports > 0 else 0
    
    # Risk increases with more open ports
    port_count_penalty = min(num_ports * 0.2, 2.0)
    
    final_score = (max_port_score * 0.6) + (avg_score * 0.3) + port_count_penalty
    
    # Clamp to 0-10 range
    return round(min(max(final_score, 0), 10), 1)


def detect_device_type(device: Dict) -> str:
    """
    Detect device type based on open ports and services
    """
    open_ports = [p.get("port") for p in device.get("ports", [])]
    services = [p.get("service", "").lower() for p in device.get("ports", [])]
    
    # Check for RTSP (camera signature)
    if 554 in open_ports or 8554 in open_ports or "rtsp" in services:
        return "IP Camera"
    
    # Check signatures
    for device_type, signature_ports in DEVICE_TYPE_SIGNATURES.items():
        matched = sum(1 for p in signature_ports if p in open_ports)
        if matched >= 2:  # At least 2 matching ports
            return device_type
    
    # Check OS-based detection
    os_lower = device.get("os", "").lower()
    if "router" in os_lower or "openwrt" in os_lower:
        return "Router"
    if "windows" in os_lower:
        return "Windows PC"
    if "linux" in os_lower:
        return "Linux Device"
    if "android" in os_lower:
        return "Android Device"
    if "ios" in os_lower or "iphone" in os_lower:
        return "iOS Device"
    
    # Check vendor-based
    vendor = device.get("vendor", "").lower()
    if any(cam in vendor for cam in ["hikvision", "dahua", "axis", "foscam"]):
        return "IP Camera"
    if any(router in vendor for router in ["cisco", "netgear", "tp-link", "asus"]):
        return "Router"
    
    return "Unknown"


def generate_device_tags(device: Dict) -> List[str]:
    """
    Generate tags for a device based on its characteristics
    """
    tags = []
    
    # Risk-based tags
    risk = device.get("risk_score", 0)
    if risk >= 7:
        tags.append("high-risk")
    elif risk >= 4:
        tags.append("medium-risk")
    else:
        tags.append("low-risk")
    
    # Device type tags
    device_type = device.get("device_type", "").lower()
    if device_type != "unknown":
        tags.append(device_type.replace(" ", "-").lower())
    
    # IoT tag
    iot_types = ["camera", "sensor", "speaker", "hub", "smart"]
    if any(t in device_type.lower() for t in iot_types):
        tags.append("iot")
    
    # Service-based tags
    services = [p.get("service", "") for p in device.get("ports", [])]
    if "http" in services or "https" in services:
        tags.append("web-interface")
    if "ssh" in services:
        tags.append("ssh-enabled")
    if "telnet" in services:
        tags.append("telnet-enabled")
        tags.append("insecure")
    if "rtsp" in services:
        tags.append("streaming")
    
    return list(set(tags))


def quick_scan(subnet: str, nmap_path: str = "nmap") -> Dict[str, Any]:
    """
    Perform a quick ping scan to discover hosts
    """
    return scan_network(subnet, nmap_path, "-sn -T4")


def intensive_scan(subnet: str, nmap_path: str = "nmap") -> Dict[str, Any]:
    """
    Perform intensive scan with vulnerability scripts
    """
    return scan_network(
        subnet, 
        nmap_path, 
        "-sV -sC -O -A -T4 --open --script=vuln"
    )


def scan_single_host(ip: str, nmap_path: str = "nmap") -> Dict[str, Any]:
    """
    Perform detailed scan on a single host
    """
    result = scan_network(ip, nmap_path, "-sV -sC -O -A -T4 -p-")
    if result["success"] and result["devices"]:
        return {
            "success": True,
            "device": result["devices"][0],
            "scan_time": result["scan_time"]
        }
    return {
        "success": False,
        "device": None,
        "error": result.get("error", "No device found")
    }
