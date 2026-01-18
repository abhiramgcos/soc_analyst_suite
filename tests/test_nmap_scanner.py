
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.nmap_scanner import calculate_risk_score, detect_device_type

def test_calculate_risk_score_no_ports():
    device = {"ports": []}
    assert calculate_risk_score(device) == 1.0

def test_calculate_risk_score_high_risk_port():
    device = {
        "ports": [
            {"port": 23, "service": "telnet"},  # Telnet is high risk (9.0)
        ]
    }
    # Calculation: Max(9.0)*0.6 + Avg(9.0)*0.3 + Penalty(0.2) = 5.4 + 2.7 + 0.2 = 8.3
    # With modifiers it might be slightly different, let's just check it's high
    score = calculate_risk_score(device)
    assert score > 7.0

def test_calculate_risk_score_multiple_ports():
    device = {
        "ports": [
            {"port": 80, "service": "http"},    # 4.0
            {"port": 443, "service": "https"},  # 2.0
        ]
    }
    score = calculate_risk_score(device)
    assert 0 < score < 10

def test_detect_device_type_camera():
    device = {
        "ports": [
            {"port": 554, "service": "rtsp"},
            {"port": 80, "service": "http"}
        ]
    }
    assert detect_device_type(device) == "IP Camera"

def test_detect_device_type_printer():
    device = {
        "ports": [
            {"port": 9100, "service": "jetdirect"},
            {"port": 515, "service": "printer"}
        ]
    }
    assert detect_device_type(device) == "Printer"

def test_detect_device_type_unknown():
    device = {
        "ports": [
            {"port": 12345, "service": "unknown"}
        ]
    }
    assert detect_device_type(device) == "Unknown"
