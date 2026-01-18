"""
Page 6: Security Dashboard
Comprehensive security posture overview with metrics and visualizations
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.db import (
    get_device_stats, get_alert_stats, get_device_type_distribution,
    get_alerts_by_hour, get_top_signatures, get_top_source_ips,
    list_devices, get_recent_alerts
)

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

st.set_page_config(page_title="Security Dashboard", page_icon="🛡️", layout="wide")

st.markdown("# 🛡️ Security Dashboard")
st.markdown("Real-time security posture overview for your IoT network.")

# Auto-refresh option
col1, col2 = st.columns([3, 1])
with col2:
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

st.markdown("---")

# Get stats
device_stats = get_device_stats()
alert_stats = get_alert_stats(hours=24)

# ===== KPI Metrics Row =====
st.markdown("### 📊 Key Metrics")

col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric(
        "Total Devices",
        device_stats.get("total_devices", 0),
        help="All discovered IoT devices"
    )

with col2:
    high_risk = device_stats.get("high_risk", 0)
    st.metric(
        "🔴 High Risk",
        high_risk,
        delta=f"+{high_risk}" if high_risk > 0 else None,
        delta_color="inverse"
    )

with col3:
    st.metric(
        "📊 Avg Risk Score",
        f"{device_stats.get('avg_risk_score', 0):.1f}/10"
    )

with col4:
    st.metric(
        "⚠️ Alerts (24h)",
        alert_stats.get("total_alerts", 0)
    )

with col5:
    critical = alert_stats.get("critical", 0)
    st.metric(
        "🔴 Critical",
        critical,
        delta=f"+{critical}" if critical > 0 else None,
        delta_color="inverse"
    )

with col6:
    # Calculate security score (inverse of risk)
    avg_risk = device_stats.get("avg_risk_score", 0)
    security_score = max(0, 100 - (avg_risk * 10))
    st.metric("🛡️ Security Score", f"{security_score:.0f}%")

st.markdown("---")

# ===== Charts Row =====
if PLOTLY_AVAILABLE:
    st.markdown("### 📈 Security Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk distribution gauge
        st.markdown("#### Device Risk Distribution")
        
        high = device_stats.get("high_risk", 0)
        medium = device_stats.get("medium_risk", 0)
        low = device_stats.get("low_risk", 0)
        
        if high + medium + low > 0:
            fig = go.Figure(data=[go.Pie(
                labels=["High Risk", "Medium Risk", "Low Risk"],
                values=[high, medium, low],
                hole=0.5,
                marker_colors=["#e74c3c", "#f39c12", "#2ecc71"]
            )])
            fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No device data available")
    
    with col2:
        # Alert severity breakdown
        st.markdown("#### Alert Severity (24h)")
        
        alert_data = {
            "Severity": ["Critical", "High", "Medium", "Low"],
            "Count": [
                alert_stats.get("critical", 0),
                alert_stats.get("high", 0),
                alert_stats.get("medium", 0),
                alert_stats.get("low", 0)
            ],
            "Color": ["#e74c3c", "#f39c12", "#f1c40f", "#2ecc71"]
        }
        
        if sum(alert_data["Count"]) > 0:
            fig = px.bar(
                alert_data, x="Severity", y="Count",
                color="Severity",
                color_discrete_map={
                    "Critical": "#e74c3c",
                    "High": "#f39c12",
                    "Medium": "#f1c40f",
                    "Low": "#2ecc71"
                }
            )
            fig.update_layout(height=300, showlegend=False, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No alert data available")
    
    # Alert timeline
    st.markdown("#### Alert Trend (24h)")
    
    alerts_by_hour = get_alerts_by_hour(hours=24)
    
    if alerts_by_hour:
        timeline_df = pd.DataFrame(alerts_by_hour)
        timeline_df.columns = ["Hour", "Count"]
        
        fig = px.area(timeline_df, x="Hour", y="Count",
                     color_discrete_sequence=["#3498db"])
        fig.update_layout(height=250, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alert timeline data available")

st.markdown("---")

# ===== Top Threats =====
st.markdown("### 🎯 Top Threats")

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Top Alert Signatures")
    top_sigs = get_top_signatures(limit=5)
    
    if top_sigs:
        for i, sig in enumerate(top_sigs, 1):
            st.markdown(f"**{i}.** {sig.get('_id', 'Unknown')[:50]}... ({sig.get('count', 0)})")
    else:
        st.info("No signature data")

with col2:
    st.markdown("#### Top Source IPs")
    top_ips = get_top_source_ips(limit=5)
    
    if top_ips:
        for i, ip in enumerate(top_ips, 1):
            st.markdown(f"**{i}.** `{ip.get('_id', 'Unknown')}` ({ip.get('count', 0)} alerts)")
    else:
        st.info("No source IP data")

st.markdown("---")

# ===== Recent Activity =====
st.markdown("### 🕐 Recent Activity")

recent_alerts = get_recent_alerts(minutes=60, limit=10)

if recent_alerts:
    for alert in recent_alerts[:5]:
        severity_icons = {1: "🔴", 2: "🟠", 3: "🟡", 4: "🟢"}
        icon = severity_icons.get(alert.get("severity", 4), "⚪")
        sig = alert.get("signature", "Unknown")[:60]
        src = alert.get("src_ip", "?")
        dst = alert.get("dest_ip", "?")
        ts = str(alert.get("timestamp", ""))[:19]
        
        st.markdown(f"{icon} **{ts}** | {src} → {dst} | {sig}")
else:
    st.info("No recent alerts")

# ===== Device Types =====
st.markdown("---")
st.markdown("### 📱 Device Breakdown")

device_types = get_device_type_distribution()

if device_types and PLOTLY_AVAILABLE:
    type_df = pd.DataFrame(device_types)
    type_df.columns = ["Type", "Count"]
    
    fig = px.treemap(type_df, path=["Type"], values="Count",
                    color_discrete_sequence=px.colors.qualitative.Set3)
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig, use_container_width=True)
elif device_types:
    for dt in device_types:
        st.markdown(f"- **{dt.get('_id', 'Unknown')}**: {dt.get('count', 0)} devices")
else:
    st.info("No device type data available")
