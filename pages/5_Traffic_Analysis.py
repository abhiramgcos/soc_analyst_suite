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

# Try to import Scapy
SCAPY_AVAILABLE = False
HAS_ROOT = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    pass


def capture_live_traffic(interface: str, duration: int, packet_count: int = 1000) -> list:
    """Capture live traffic using Scapy"""
    captured_packets = []
    
    def packet_callback(pkt):
        if IP in pkt:
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "OTHER",
                "bytes": len(pkt),
                "packets": 1
            }
            
            if TCP in pkt:
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = pkt[TCP].sport
                packet_info["dst_port"] = pkt[TCP].dport
                # Identify HTTP/HTTPS
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    packet_info["protocol"] = "HTTP"
                elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    packet_info["protocol"] = "HTTPS"
            elif UDP in pkt:
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = pkt[UDP].sport
                packet_info["dst_port"] = pkt[UDP].dport
                # Identify DNS
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    packet_info["protocol"] = "DNS"
            elif ICMP in pkt:
                packet_info["protocol"] = "ICMP"
            
            captured_packets.append(packet_info)
    
    try:
        # Suppress Scapy warnings
        conf.verb = 0
        sniff(iface=interface, prn=packet_callback, timeout=duration, count=packet_count, store=0)
    except Exception as e:
        st.error(f"Capture error: {str(e)}")
    
    return captured_packets

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

# Check capture capabilities
if not SCAPY_AVAILABLE:
    st.warning("⚠️ Scapy not installed. Install with: `pip install scapy`")
elif not HAS_ROOT:
    st.warning("⚠️ Live capture requires root privileges. Run with: `sudo streamlit run app.py`")

# Generate sample traffic data for initial display
def generate_sample_data():
    import random
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
    return sample_data

if "traffic_data" not in st.session_state:
    st.session_state.traffic_data = generate_sample_data()

if capture_btn:
    if SCAPY_AVAILABLE and HAS_ROOT:
        with st.spinner(f"🔴 Capturing traffic on {interface} for {capture_duration} seconds..."):
            captured = capture_live_traffic(interface, capture_duration)
            if captured:
                st.session_state.traffic_data = captured
                st.success(f"✅ Captured {len(captured)} packets!")
            else:
                st.warning("⚠️ No packets captured. Check interface name or network activity.")
    else:
        st.info("⚠️ Live capture not available. Showing sample data.")

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
