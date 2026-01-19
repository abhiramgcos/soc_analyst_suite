"""
IoT SOC Analyst Suite - Configuration
All settings and API keys centralized here
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# =============================================================================
# MongoDB Configuration
# =============================================================================
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "iot_soc")

# Collection names
COLLECTION_DEVICES = "devices"
COLLECTION_FIRMWARE = "firmware_assignments"
COLLECTION_SURICATA = "suricata_alerts"
COLLECTION_CVE_CACHE = "cve_cache"
COLLECTION_TRAFFIC = "traffic_logs"

# =============================================================================
# Suricata Configuration
# =============================================================================
# Path to Suricata EVE JSON log
SURICATA_EVE_PATH = os.getenv(
    "SURICATA_EVE_PATH",
    "/var/log/suricata/eve.json"  # Linux default
)

# Suricata config path
SURICATA_CONFIG_PATH = os.getenv(
    "SURICATA_CONFIG_PATH",
    "/etc/suricata/suricata.yaml"
)

# =============================================================================
# Nmap Configuration
# =============================================================================
NMAP_PATH = os.getenv("NMAP_PATH", "nmap")  # Assumes nmap is in PATH
DEFAULT_SUBNET = os.getenv("DEFAULT_SUBNET", "192.168.1.0/24")
NMAP_SCAN_OPTIONS = "-sV -O -T4 --open"  # Service version, OS detection, faster timing

# Risk scoring weights for services
HIGH_RISK_PORTS = {
    21: 8,    # FTP
    23: 9,    # Telnet
    25: 5,    # SMTP
    139: 7,   # NetBIOS
    445: 7,   # SMB
    1433: 8,  # MSSQL
    3306: 7,  # MySQL
    3389: 8,  # RDP
    5900: 7,  # VNC
    8080: 5,  # HTTP Proxy
}

# =============================================================================
# Firmware Analyzer API
# =============================================================================
FIRMWARE_ANALYZER_URL = os.getenv(
    "FIRMWARE_ANALYZER_URL",
    "http://localhost:8000"
)
FIRMWARE_ANALYZER_TIMEOUT = 30  # seconds

# =============================================================================
# NVD API Configuration
# =============================================================================
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # Get from https://nvd.nist.gov/developers/request-an-api-key
NVD_RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6.0  # Seconds between requests

# =============================================================================
# Scapy / Traffic Analysis
# =============================================================================
# Network interface for packet capture (use 'ip addr' to find yours)
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "wlp0s20f3")  # Linux WiFi interface
HOTSPOT_INTERFACE = os.getenv("HOTSPOT_INTERFACE", "wlp0s20f3")  # Hotspot interface
CAPTURE_TIMEOUT = 60  # seconds
MAX_PACKETS_DISPLAY = 1000

# =============================================================================
# UI Configuration
# =============================================================================
APP_TITLE = "🛡️ IoT SOC Analyst Suite"
APP_ICON = "🛡️"
PAGE_LAYOUT = "wide"

# Theme colors
THEME_PRIMARY = "#1f77b4"
THEME_SUCCESS = "#2ecc71"
THEME_WARNING = "#f39c12"
THEME_DANGER = "#e74c3c"
THEME_INFO = "#3498db"

# Auto-refresh intervals (milliseconds)
AUTO_REFRESH_SURICATA = 5000  # 5 seconds
AUTO_REFRESH_DASHBOARD = 10000  # 10 seconds

# =============================================================================
# Logging
# =============================================================================
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# =============================================================================
# Export Configuration
# =============================================================================
EXPORT_DIR = Path(os.getenv("EXPORT_DIR", "./exports"))
EXPORT_DIR.mkdir(exist_ok=True)

# =============================================================================
# Session Defaults
# =============================================================================
DEFAULT_PAGE_SIZE = 50
MAX_ALERTS_DISPLAY = 500

# =============================================================================
# System Authentication (for sudo commands)
# =============================================================================
# WARNING: Store this securely, preferably in .env file, not in code!
SUDO_PASSWORD = os.getenv("SUDO_PASSWORD", "")
