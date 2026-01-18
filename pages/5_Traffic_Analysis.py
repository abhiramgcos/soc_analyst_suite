"""
Page 5: Traffic Analysis
Network traffic insights and packet analysis using Scapy
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CAPTURE_INTERFACE

# Try to import visualization libraries
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

st.set_page_config(page_title="Traffic Analysis", page_icon="📡", layout="wide")

st.markdown("# 📡 Traffic Analysis")
st.markdown("Analyze network traffic patterns and identify anomalies.")

if not PLOTLY_AVAILABLE:
    st.warning("⚠️ Install plotly for visualizations: `pip install plotly`")

st.markdown("---")

# Traffic capture controls
st.markdown("### 🎯 Traffic Capture")

col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    interface = st.text_input("Network Interface", value=CAPTURE_INTERFACE, help="Network interface to capture from")

with col2:
    capture_duration = st.number_input("Duration (seconds)", min_value=5, max_value=300, value=30)

with col3:
    st.markdown("<br>", unsafe_allow_html=True)
    capture_btn = st.button("🔴 Start Capture", type="primary", use_container_width=True)

# Simulated traffic data for demonstration
if "traffic_data" not in st.session_state:
    import random
    
    # Generate sample traffic data
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "MQTT"]
    ips = [f"192.168.1.{i}" for i in range(1, 50)]
    
    sample_data = []
    base_time = datetime.now() - timedelta(hours=1)
    
    for i in range(500):
        sample_data.append({
            "timestamp": (base_time + timedelta(seconds=i*7)).isoformat(),
            "src_ip": random.choice(ips),
            "dst_ip": random.choice(ips + ["8.8.8.8", "1.1.1.1", "151.101.1.69"]),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22, 1883, 8080, 554]),
            "protocol": random.choice(protocols),
            "bytes": random.randint(64, 15000),
            "packets": random.randint(1, 50)
        })
    
    st.session_state.traffic_data = sample_data

if capture_btn:
    st.info(f"⚠️ Live capture requires Scapy and admin privileges. Showing sample data.")

st.markdown("---")

# Traffic statistics
st.markdown("### 📊 Traffic Statistics")

traffic_data = st.session_state.traffic_data
df = pd.DataFrame(traffic_data)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Packets", df["packets"].sum())
with col2:
    st.metric("Total Bytes", f"{df['bytes'].sum() / 1024 / 1024:.2f} MB")
with col3:
    st.metric("Unique Sources", df["src_ip"].nunique())
with col4:
    st.metric("Unique Destinations", df["dst_ip"].nunique())

st.markdown("---")

# Visualizations
if PLOTLY_AVAILABLE:
    st.markdown("### 📈 Traffic Visualizations")
    
    tab1, tab2, tab3 = st.tabs(["Protocol Distribution", "Top Talkers", "Traffic Timeline"])
    
    with tab1:
        protocol_counts = df.groupby("protocol")["packets"].sum().reset_index()
        fig = px.pie(protocol_counts, values="packets", names="protocol", 
                     title="Packets by Protocol",
                     color_discrete_sequence=px.colors.qualitative.Set2)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            top_src = df.groupby("src_ip")["bytes"].sum().nlargest(10).reset_index()
            fig = px.bar(top_src, x="bytes", y="src_ip", orientation="h",
                        title="Top 10 Source IPs by Bytes",
                        color="bytes", color_continuous_scale="Blues")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            top_dst = df.groupby("dst_ip")["bytes"].sum().nlargest(10).reset_index()
            fig = px.bar(top_dst, x="bytes", y="dst_ip", orientation="h",
                        title="Top 10 Destination IPs by Bytes",
                        color="bytes", color_continuous_scale="Oranges")
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["minute"] = df["timestamp"].dt.floor("min")
        timeline = df.groupby("minute")["bytes"].sum().reset_index()
        
        fig = px.line(timeline, x="minute", y="bytes",
                     title="Traffic Volume Over Time",
                     labels={"bytes": "Bytes", "minute": "Time"})
        fig.update_traces(fill="tozeroy")
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Traffic table
st.markdown("### 📋 Recent Traffic")

display_df = df[["timestamp", "src_ip", "dst_ip", "protocol", "dst_port", "bytes", "packets"]].head(100)
display_df.columns = ["Timestamp", "Source", "Destination", "Protocol", "Port", "Bytes", "Packets"]

st.dataframe(display_df, use_container_width=True, hide_index=True)

# Export
col1, col2 = st.columns([1, 3])
with col1:
    if st.button("📥 Export Traffic Data"):
        csv = df.to_csv(index=False)
        st.download_button("Download CSV", csv, "traffic_data.csv", "text/csv")
