"""
Page 2: Suricata Alerts
Real-time Suricata IDS alert monitoring
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SURICATA_EVE_PATH
from backend.db import get_suricata_alerts, insert_suricata_alert, get_alert_stats
from backend.suricata_parser import read_eve_file, get_severity_icon

st.set_page_config(page_title="Suricata Alerts", page_icon="⚠️", layout="wide")

st.markdown("# ⚠️ Suricata Alerts")
st.markdown("Real-time monitoring of Suricata IDS alerts from your network.")

# Controls
col1, col2, col3, col4 = st.columns([1, 1, 1, 1])

with col1:
    severity_filter = st.selectbox("Severity", ["All", "Critical (1)", "High (2)", "Medium (3)", "Low (4)"])

with col2:
    time_range = st.selectbox("Time Range", ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 7 Days", "All Time"])

with col3:
    src_ip_filter = st.text_input("Source IP", placeholder="Filter by source IP")

with col4:
    st.markdown("<br>", unsafe_allow_html=True)
    col4a, col4b = st.columns(2)
    with col4a:
        refresh = st.button("🔄 Refresh", use_container_width=True)
    with col4b:
        load_eve = st.button("📥 Load EVE", use_container_width=True)

# Load alerts from EVE file into database
if load_eve:
    with st.spinner("Loading alerts from EVE file..."):
        alerts = read_eve_file(SURICATA_EVE_PATH, limit=500)
        if alerts:
            count = 0
            for alert in alerts:
                if insert_suricata_alert(alert):
                    count += 1
            st.success(f"Loaded {count} new alerts from EVE file")
        else:
            st.warning(f"No alerts found in {SURICATA_EVE_PATH}")

st.markdown("---")

# Build filters
filters = {}

if severity_filter != "All":
    filters["severity"] = int(severity_filter.split("(")[1].replace(")", ""))

time_map = {
    "Last Hour": 1,
    "Last 6 Hours": 6,
    "Last 24 Hours": 24,
    "Last 7 Days": 168
}

start_time = None
if time_range in time_map:
    start_time = datetime.utcnow() - timedelta(hours=time_map[time_range])

# Get alerts from database
alerts = get_suricata_alerts(
    severity=filters.get("severity"),
    src_ip=src_ip_filter if src_ip_filter else None,
    start_time=start_time,
    limit=500
)

# Statistics
st.markdown("### 📊 Alert Statistics (24h)")
stats = get_alert_stats(hours=24)

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Alerts", stats.get("total_alerts", 0))
with col2:
    st.metric("🔴 Critical", stats.get("critical", 0))
with col3:
    st.metric("🟠 High", stats.get("high", 0))
with col4:
    st.metric("🟡 Medium", stats.get("medium", 0))
with col5:
    st.metric("🟢 Low", stats.get("low", 0))

st.markdown("---")

# Alerts table
st.markdown(f"### 📋 Alerts ({len(alerts)} shown)")

if alerts:
    # Create display DataFrame
    display_data = []
    for alert in alerts:
        display_data.append({
            "Severity": f"{get_severity_icon(alert.get('severity', 4))} {alert.get('severity', 4)}",
            "Timestamp": alert.get("timestamp", "")[:19] if alert.get("timestamp") else "",
            "Signature": alert.get("signature", "Unknown")[:60],
            "Source": f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}",
            "Destination": f"{alert.get('dest_ip', '')}:{alert.get('dest_port', '')}",
            "Protocol": alert.get("proto", "TCP"),
            "Category": alert.get("category", "Unknown")
        })
    
    df = pd.DataFrame(display_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # Alert details
    st.markdown("### 🔎 Alert Details")
    
    selected_idx = st.selectbox("Select Alert", range(len(alerts)), format_func=lambda i: f"{alerts[i].get('signature', 'Unknown')[:50]}...")
    
    if selected_idx is not None:
        selected_alert = alerts[selected_idx]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Alert Info**")
            st.json({
                "Signature": selected_alert.get("signature"),
                "Signature ID": selected_alert.get("signature_id"),
                "Severity": selected_alert.get("severity"),
                "Category": selected_alert.get("category"),
                "Action": selected_alert.get("action"),
                "Timestamp": selected_alert.get("timestamp")
            })
        
        with col2:
            st.markdown("**Network Info**")
            st.json({
                "Source IP": selected_alert.get("src_ip"),
                "Source Port": selected_alert.get("src_port"),
                "Destination IP": selected_alert.get("dest_ip"),
                "Destination Port": selected_alert.get("dest_port"),
                "Protocol": selected_alert.get("proto"),
                "App Protocol": selected_alert.get("app_proto")
            })
        
        # Raw JSON
        with st.expander("📄 Raw Alert Data"):
            st.json(selected_alert.get("raw", selected_alert))
else:
    st.info("No alerts found. Click 'Load EVE' to import alerts from Suricata log file.")
    st.markdown(f"**EVE Path:** `{SURICATA_EVE_PATH}`")
