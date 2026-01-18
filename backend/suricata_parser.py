"""
IoT SOC Analyst Suite - Suricata EVE JSON Parser
"""
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional
from threading import Thread, Event

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {
    1: ("Critical", "🔴"),
    2: ("High", "🟠"),
    3: ("Medium", "🟡"),
    4: ("Low", "🟢"),
}

ALERT_CATEGORIES = {
    "ET MALWARE": "malware",
    "ET TROJAN": "malware",
    "ET EXPLOIT": "exploit",
    "ET SCAN": "reconnaissance",
    "ET DOS": "denial-of-service",
    "ET WEB": "web-attack",
    "ET POLICY": "policy-violation",
    "SURICATA": "protocol-anomaly",
}


def parse_eve_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single EVE JSON line into an alert dictionary"""
    try:
        data = json.loads(line.strip())
        if data.get("event_type") != "alert":
            return None
        
        alert = data.get("alert", {})
        parsed = {
            "timestamp": data.get("timestamp"),
            "signature": alert.get("signature", "Unknown"),
            "signature_id": alert.get("signature_id"),
            "severity": alert.get("severity", 4),
            "category": alert.get("category", "Unknown"),
            "action": alert.get("action", "allowed"),
            "src_ip": data.get("src_ip", ""),
            "src_port": data.get("src_port"),
            "dest_ip": data.get("dest_ip", ""),
            "dest_port": data.get("dest_port"),
            "proto": data.get("proto", "TCP").upper(),
            "app_proto": data.get("app_proto", ""),
            "flow_id": data.get("flow_id"),
            "raw": data
        }
        
        sev = parsed["severity"]
        parsed["severity_label"], parsed["severity_icon"] = SEVERITY_LABELS.get(sev, ("Unknown", "⚪"))
        parsed["alert_type"] = categorize_alert(parsed["signature"])
        return parsed
    except Exception:
        return None


def categorize_alert(signature: str) -> str:
    sig_upper = signature.upper()
    for prefix, category in ALERT_CATEGORIES.items():
        if sig_upper.startswith(prefix):
            return category
    return "other"


def get_severity_label(severity: int) -> str:
    return SEVERITY_LABELS.get(severity, ("Unknown", "⚪"))[0]


def get_severity_icon(severity: int) -> str:
    return SEVERITY_LABELS.get(severity, ("Unknown", "⚪"))[1]


def read_eve_file(path: str, limit: int = 1000) -> List[Dict]:
    """Read alerts from EVE JSON file"""
    alerts = []
    if not os.path.exists(path):
        return alerts
    
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, 2)
            file_size = f.tell()
            chunk_size = min(file_size, 1024 * 1024)
            f.seek(max(0, file_size - chunk_size))
            
            for line in f:
                alert = parse_eve_line(line)
                if alert:
                    alerts.append(alert)
        
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    except Exception as e:
        logger.error(f"Error reading EVE file: {e}")
    
    return alerts[:limit]


class EVEWatcher:
    """Real-time watcher for Suricata EVE JSON file"""
    
    def __init__(self, eve_path: str, callback: Callable[[Dict], None], poll_interval: float = 1.0):
        self.eve_path = eve_path
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_event = Event()
        self._thread: Optional[Thread] = None
        self._last_position = 0
    
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = Thread(target=self._watch_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
    
    def _watch_loop(self):
        while not self._stop_event.is_set():
            try:
                if os.path.exists(self.eve_path):
                    with open(self.eve_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self._last_position)
                        for line in f:
                            alert = parse_eve_line(line)
                            if alert:
                                self.callback(alert)
                        self._last_position = f.tell()
            except Exception as e:
                logger.error(f"EVE watcher error: {e}")
            time.sleep(self.poll_interval)


def filter_alerts(alerts: List[Dict], severity: Optional[int] = None, 
                  src_ip: Optional[str] = None, signature_pattern: Optional[str] = None) -> List[Dict]:
    """Filter alerts based on criteria"""
    filtered = []
    for alert in alerts:
        if severity is not None and alert.get("severity") != severity:
            continue
        if src_ip and alert.get("src_ip") != src_ip:
            continue
        if signature_pattern and signature_pattern.lower() not in alert.get("signature", "").lower():
            continue
        filtered.append(alert)
    return filtered
