
import pytest
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.suricata_parser import parse_eve_line, categorize_alert

def test_parse_eve_line_valid():
    sample_json = json.dumps({
        "timestamp": "2023-10-27T10:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.100",
        "src_port": 12345,
        "dest_ip": "1.1.1.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "ET MALWARE Test Signature",
            "category": "A Network Trojan was detected",
            "severity": 1
        }
    })
    
    parsed = parse_eve_line(sample_json)
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.100"
    assert parsed["severity"] == 1
    assert parsed["signature"] == "ET MALWARE Test Signature"
    assert parsed["alert_type"] == "malware"

def test_parse_eve_line_not_alert():
    sample_json = json.dumps({
        "timestamp": "2023-10-27T10:00:00.000000+0000",
        "event_type": "stats"
    })
    
    parsed = parse_eve_line(sample_json)
    assert parsed is None

def test_categorize_alert():
    assert categorize_alert("ET MALWARE Generic Trojan") == "malware"
    assert categorize_alert("ET EXPLOIT Possible SQL Injection") == "exploit"
    assert categorize_alert("SURICATA STREAM Packet with invalid timestamp") == "protocol-anomaly"
    assert categorize_alert("Some unknown signature") == "other"
