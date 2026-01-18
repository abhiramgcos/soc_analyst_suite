"""
IoT SOC Analyst Suite - Main Application
Production-ready Streamlit dashboard for IoT security monitoring
"""
import streamlit as st
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import APP_TITLE, APP_ICON, PAGE_LAYOUT
from backend.db import is_connected, get_device_stats, get_alert_stats

# Page configuration
st.set_page_config(
    page_title="IoT SOC Analyst Suite",
    page_icon=APP_ICON,
    layout=PAGE_LAYOUT,
    initial_sidebar_state="expanded",
    menu_items={
        'About': "IoT SOC Analyst Suite - Complete security monitoring for IoT networks"
    }
)

# Custom CSS for better styling
st.markdown("""
<style>
    /* Main theme */
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    
    /* Status indicators */
    .status-connected {
        color: #2ecc71;
        font-weight: 600;
    }
    .status-disconnected {
        color: #e74c3c;
        font-weight: 600;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        border-radius: 10px;
        padding: 1.5rem;
        color: white;
        text-align: center;
    }
    
    /* Sidebar styling */
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    }
    
    /* Table styling */
    .dataframe {
        font-size: 0.9rem;
    }
    
    /* Alert colors */
    .alert-critical { color: #e74c3c; font-weight: bold; }
    .alert-high { color: #f39c12; font-weight: bold; }
    .alert-medium { color: #f1c40f; }
    .alert-low { color: #2ecc71; }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)


def render_sidebar():
    """Render the sidebar with navigation and status"""
    with st.sidebar:
        st.markdown(f"# {APP_ICON} IoT SOC Suite")
        st.markdown("---")
        
        # Connection status
        st.markdown("### 📡 System Status")
        
        if is_connected():
            st.markdown('<p class="status-connected">✅ MongoDB Connected</p>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="status-disconnected">❌ MongoDB Disconnected</p>', unsafe_allow_html=True)
            st.warning("Please ensure MongoDB is running on localhost:27017")
        
        st.markdown("---")
        
        # Quick stats
        st.markdown("### 📊 Quick Stats")
        
        device_stats = get_device_stats()
        alert_stats = get_alert_stats(hours=24)
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Devices", device_stats.get("total_devices", 0))
            st.metric("High Risk", device_stats.get("high_risk", 0))
        with col2:
            st.metric("Alerts (24h)", alert_stats.get("total_alerts", 0))
            st.metric("Critical", alert_stats.get("critical", 0))
        
        st.markdown("---")
        
        # Navigation info
        st.markdown("### 📖 Navigation")
        st.markdown("""
        - **Network Discovery**: Scan and discover IoT devices
        - **Suricata Alerts**: Real-time IDS alerts
        - **CVE Scanning**: Vulnerability database lookup
        - **Firmware Analysis**: Analyze device firmware
        - **Traffic Analysis**: Network traffic insights
        - **Security Dashboard**: Overall security posture
        - **Reports**: Generate security reports
        """)


def render_home_page():
    """Render the home page with overview"""
    st.markdown('<h1 class="main-header">🛡️ IoT SOC Analyst Suite</h1>', unsafe_allow_html=True)
    
    st.markdown("""
    Welcome to the **IoT Security Operations Center Analyst Suite** - a comprehensive platform 
    for monitoring and securing your IoT network infrastructure.
    """)
    
    # Quick action cards
    st.markdown("### 🚀 Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.info("🔍 **Network Scan**\n\nDiscover devices on your network")
        if st.button("Start Scan", key="quick_scan"):
            st.switch_page("pages/1_Network_Discovery.py")
    
    with col2:
        st.warning("⚠️ **View Alerts**\n\nCheck latest Suricata alerts")
        if st.button("View Alerts", key="quick_alerts"):
            st.switch_page("pages/2_Suricata_Alerts.py")
    
    with col3:
        st.error("🔒 **CVE Lookup**\n\nSearch vulnerability database")
        if st.button("Search CVEs", key="quick_cve"):
            st.switch_page("pages/3_CVE_Scanning.py")
    
    with col4:
        st.success("📦 **Firmware**\n\nAnalyze device firmware")
        if st.button("Analyze FW", key="quick_fw"):
            st.switch_page("pages/4_Firmware_Analysis.py")
    
    st.markdown("---")
    
    # System overview
    st.markdown("### 📈 System Overview")
    
    device_stats = get_device_stats()
    alert_stats = get_alert_stats(hours=24)
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Devices",
            device_stats.get("total_devices", 0),
            help="All discovered IoT devices"
        )
    
    with col2:
        st.metric(
            "High Risk Devices",
            device_stats.get("high_risk", 0),
            delta=None,
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            "Alerts (24h)",
            alert_stats.get("total_alerts", 0)
        )
    
    with col4:
        st.metric(
            "Critical Alerts",
            alert_stats.get("critical", 0),
            delta=None,
            delta_color="inverse"
        )
    
    with col5:
        avg_risk = device_stats.get("avg_risk_score", 0)
        st.metric(
            "Avg Risk Score",
            f"{avg_risk:.1f}" if avg_risk else "N/A"
        )
    
    st.markdown("---")
    
    # Network topology info
    st.markdown("### 🌐 Network Topology")
    st.markdown("""
    ```
    Internet → [Ethernet1] → Windows Laptop (SOC Dashboard) → [Ethernet2] → Access Point → IoT Devices
                                     ↓
                              Suricata IDS (monitors Ethernet2)
    ```
    """)
    
    st.info("""
    **Configuration Notes:**
    - Suricata monitors Ethernet2 in IDS mode using Npcap
    - All IoT traffic is visible to Suricata and Scapy
    - MongoDB stores all device data and alerts
    """)


def main():
    """Main application entry point"""
    render_sidebar()
    render_home_page()


if __name__ == "__main__":
    main()
