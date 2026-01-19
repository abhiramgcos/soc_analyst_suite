"""
Page 1: Network Discovery
Scan and discover IoT devices on the network using Nmap
"""
import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DEFAULT_SUBNET, NMAP_PATH
from backend.db import list_devices, upsert_device, delete_device, get_device_stats
from backend.nmap_scanner import scan_network, quick_scan, scan_with_scapy
import requests

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

st.set_page_config(page_title="Network Discovery", page_icon="🔍", layout="wide")

st.markdown("# 🔍 Network Discovery")
st.markdown("Discover and catalog IoT devices on your network using Nmap scanning.")

# Scan controls
st.markdown("### 📡 Network Scan")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    subnet = st.text_input("Target Subnet", value=DEFAULT_SUBNET, placeholder="192.168.1.0/24")

with col2:
    scan_type = st.selectbox("Scan Type", ["Quick (Ping)", "Standard (Service Detection)", "Intensive", "Deep Scan (OS + Scapy)"])

with col3:
    st.markdown("<br>", unsafe_allow_html=True)
    scan_button = st.button("🚀 Start Scan", type="primary", use_container_width=True)

# Initialize session state
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "scan_in_progress" not in st.session_state:
    st.session_state.scan_in_progress = False

# Handle scan
if scan_button and not st.session_state.scan_in_progress:
    st.session_state.scan_in_progress = True
    
    with st.spinner(f"Scanning {subnet}... This may take a few minutes."):
        if scan_type == "Quick (Ping)":
            result = quick_scan(subnet)
        else:
            if scan_type == "Deep Scan (OS + Scapy)":
                options = "-sV -O -A -T4 --open"
            else:
                 options = "-sV -O -T4 --open" if scan_type == "Standard (Service Detection)" else "-sV -sC -O -A -T4 --open"
            
            result = scan_network(subnet, options=options)
            
            # If Deep Scan, also run Scapy to ensure we get MACs even if Nmap failed (e.g. different subnet/layer 2 issues)
            if scan_type == "Deep Scan (OS + Scapy)" and result["success"]:
                 st.info("Running parallel Scapy scan for accurate MAC detection...")
                 scapy_devices = scan_with_scapy(subnet)
                 
                 # Merge Scapy results
                 if scapy_devices:
                     for s_dev in scapy_devices:
                         # Find matching device in result
                         existing = next((d for d in result["devices"] if d["ip"] == s_dev["ip"]), None)
                         if existing:
                             if existing["mac"] == "Unknown":
                                 existing["mac"] = s_dev.get("mac", "Unknown")
                                 existing["vendor"] = s_dev.get("vendor", "Unknown")
                         else:
                             # Add new device found only by Scapy
                             result["devices"].append({
                                 "ip": s_dev["ip"],
                                 "mac": s_dev.get("mac", "Unknown"),
                                 "hostname": "",
                                 "device_type": "Unknown",
                                 "os": "Unknown",
                                 "ports": [],
                                 "risk_score": 0.0,
                                 "tags": ["scapy-discovered"],
                                 "vendor": s_dev.get("vendor", "Unknown")
                             })
    
                     st.write(f"Scapy scan enriched {len(scapy_devices)} devices")
    
    st.session_state.scan_in_progress = False
    st.session_state.scan_results = result
    
    if result["success"]:
        # Save devices to database
        saved_count = 0
        for device in result["devices"]:
            # Enrich vendor if unknown
            if device.get("mac") and len(device["mac"]) > 8 and (not device.get("vendor") or device["vendor"] == "Unknown"):
                 vendor = get_mac_vendor_online(device["mac"])
                 if vendor != "Unknown":
                     device["vendor"] = vendor
            
            if upsert_device(device):
                saved_count += 1
        st.success(f"✅ Scan complete! Found {len(result['devices'])} devices, saved {saved_count} to database.")
    else:
        st.error(f"❌ Scan failed: {result.get('error', 'Unknown error')}")

# Show scan results if available
if st.session_state.scan_results and st.session_state.scan_results["success"]:
    result = st.session_state.scan_results
    st.markdown(f"**Last Scan:** {len(result['devices'])} devices in {result.get('scan_time', 0):.1f}s")

st.markdown("---")

# Device inventory from database
st.markdown("### 📋 Device Inventory")

col1, col2 = st.columns([3, 1])
with col2:
    if st.button("🔄 Refresh List", use_container_width=True):
        st.rerun()

devices = list_devices()

if devices:
    # Create DataFrame
    df = pd.DataFrame(devices)
    
    # Select and rename columns for display
    display_cols = ["ip", "mac", "hostname", "device_type", "os", "risk_score", "last_seen"]
    available_cols = [c for c in display_cols if c in df.columns]
    df_display = df[available_cols].copy()
    
    # Format columns
    if "last_seen" in df_display.columns:
        df_display["last_seen"] = pd.to_datetime(df_display["last_seen"]).dt.strftime("%Y-%m-%d %H:%M")
    
    if "risk_score" in df_display.columns:
        df_display["risk_score"] = df_display["risk_score"].apply(lambda x: f"{x:.1f}")
    
    # Risk color coding
    def risk_color(val):
        try:
            score = float(val)
            if score >= 7:
                return "🔴 " + val
            elif score >= 4:
                return "🟡 " + val
            else:
                return "🟢 " + val
        except:
            return val
    
    if "risk_score" in df_display.columns:
        df_display["risk_score"] = df_display["risk_score"].apply(risk_color)
    
    st.dataframe(df_display, use_container_width=True, hide_index=True)
    
    # Device details expander
    st.markdown("### 🔎 Device Details")
    
    selected_ip = st.selectbox("Select Device", options=[d["ip"] for d in devices])
    
    selected_device = next((d for d in devices if d["ip"] == selected_ip), None)
    
    if selected_device:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Basic Info**")
            st.json({
                "IP": selected_device.get("ip"),
                "MAC": selected_device.get("mac"),
                "Hostname": selected_device.get("hostname") or "N/A",
                "Type": selected_device.get("device_type"),
                "OS": selected_device.get("os"),
                "Vendor": selected_device.get("vendor", "Unknown"),
                "Risk Score": selected_device.get("risk_score")
            })
        
        with col2:
            st.markdown("**Open Ports**")
            ports = selected_device.get("ports", [])
            if ports:
                port_df = pd.DataFrame(ports)
                st.dataframe(port_df, use_container_width=True, hide_index=True)
            else:
                st.info("No open ports detected")
        
        # Tags
        tags = selected_device.get("tags", [])
        if tags:
            st.markdown("**Tags:** " + " ".join([f"`{t}`" for t in tags]))
        
        # Delete button
        if st.button("🗑️ Delete Device", key=f"delete_{selected_ip}"):
            if delete_device(selected_device["_id"]):
                st.success("Device deleted")
                st.rerun()
else:
    st.info("No devices in database. Run a network scan to discover devices.")

# Statistics
st.markdown("---")
st.markdown("### 📊 Device Statistics")

stats = get_device_stats()
if stats:
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Devices", stats.get("total_devices", 0))
    with col2:
        st.metric("High Risk", stats.get("high_risk", 0))
    with col3:
        st.metric("Medium Risk", stats.get("medium_risk", 0))
    with col4:
        st.metric("Low Risk", stats.get("low_risk", 0))
