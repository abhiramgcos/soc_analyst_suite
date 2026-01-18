"""
Page 7: Reports
Generate and export security reports in various formats
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.db import (
    list_devices, get_suricata_alerts, get_device_stats, 
    get_alert_stats, get_firmware_assignments
)
from config import EXPORT_DIR

st.set_page_config(page_title="Reports", page_icon="📋", layout="wide")

st.markdown("# 📋 Security Reports")
st.markdown("Generate comprehensive security reports for your IoT network.")

st.markdown("---")

# Report type selection
st.markdown("### 📝 Report Configuration")

col1, col2, col3 = st.columns(3)

with col1:
    report_type = st.selectbox(
        "Report Type",
        [
            "Executive Summary",
            "Device Inventory",
            "Alert Analysis",
            "Vulnerability Report",
            "Firmware Status",
            "Full Security Assessment"
        ]
    )

with col2:
    time_range = st.selectbox(
        "Time Range",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
    )
    
    time_map = {
        "Last 24 Hours": 24,
        "Last 7 Days": 168,
        "Last 30 Days": 720,
        "All Time": None
    }
    hours = time_map[time_range]

with col3:
    export_format = st.selectbox(
        "Export Format",
        ["CSV", "JSON", "Markdown"]
    )

generate_btn = st.button("📊 Generate Report", type="primary")

st.markdown("---")

# Generate report
if generate_btn:
    with st.spinner("Generating report..."):
        device_stats = get_device_stats()
        alert_stats = get_alert_stats(hours=hours or 8760)
        
        start_time = None
        if hours:
            start_time = datetime.utcnow() - timedelta(hours=hours)
        
        if report_type == "Executive Summary":
            st.markdown("## 📊 Executive Summary Report")
            st.markdown(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
            st.markdown(f"*Period: {time_range}*")
            
            st.markdown("### Key Findings")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Devices", device_stats.get("total_devices", 0))
                st.metric("High Risk Devices", device_stats.get("high_risk", 0))
            with col2:
                st.metric("Total Alerts", alert_stats.get("total_alerts", 0))
                st.metric("Critical Alerts", alert_stats.get("critical", 0))
            with col3:
                avg_risk = device_stats.get("avg_risk_score", 0)
                st.metric("Avg Risk Score", f"{avg_risk:.1f}/10")
                security_score = max(0, 100 - (avg_risk * 10))
                st.metric("Security Score", f"{security_score:.0f}%")
            
            st.markdown("### Recommendations")
            if device_stats.get("high_risk", 0) > 0:
                st.warning(f"⚠️ {device_stats.get('high_risk')} high-risk devices require immediate attention")
            if alert_stats.get("critical", 0) > 0:
                st.error(f"🔴 {alert_stats.get('critical')} critical alerts need investigation")
            
            report_data = {
                "report_type": "Executive Summary",
                "generated": datetime.now().isoformat(),
                "period": time_range,
                "device_stats": device_stats,
                "alert_stats": alert_stats
            }
        
        elif report_type == "Device Inventory":
            st.markdown("## 📱 Device Inventory Report")
            
            devices = list_devices(limit=500)
            
            if devices:
                df = pd.DataFrame(devices)
                cols = ["ip", "mac", "hostname", "device_type", "os", "risk_score", "last_seen"]
                available_cols = [c for c in cols if c in df.columns]
                df = df[available_cols]
                
                st.dataframe(df, use_container_width=True, hide_index=True)
                report_data = df.to_dict(orient="records")
            else:
                st.info("No devices found")
                report_data = []
        
        elif report_type == "Alert Analysis":
            st.markdown("## ⚠️ Alert Analysis Report")
            
            alerts = get_suricata_alerts(start_time=start_time, limit=500)
            
            if alerts:
                st.markdown(f"**Total Alerts:** {len(alerts)}")
                
                # Severity breakdown
                severity_counts = {}
                for a in alerts:
                    sev = a.get("severity", 4)
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                st.markdown("### Severity Breakdown")
                for sev in sorted(severity_counts.keys()):
                    icons = {1: "🔴 Critical", 2: "🟠 High", 3: "🟡 Medium", 4: "🟢 Low"}
                    st.markdown(f"- {icons.get(sev, 'Unknown')}: {severity_counts[sev]}")
                
                # Top signatures
                sig_counts = {}
                for a in alerts:
                    sig = a.get("signature", "Unknown")
                    sig_counts[sig] = sig_counts.get(sig, 0) + 1
                
                st.markdown("### Top 10 Signatures")
                for sig, count in sorted(sig_counts.items(), key=lambda x: -x[1])[:10]:
                    st.markdown(f"- **{count}x** {sig[:60]}...")
                
                df = pd.DataFrame(alerts)
                report_data = df.to_dict(orient="records")
            else:
                st.info("No alerts in selected time range")
                report_data = []
        
        elif report_type == "Firmware Status":
            st.markdown("## 📦 Firmware Analysis Status Report")
            
            assignments = get_firmware_assignments(limit=100)
            
            if assignments:
                status_counts = {}
                for a in assignments:
                    status = a.get("analysis_status", "pending")
                    status_counts[status] = status_counts.get(status, 0) + 1
                
                st.markdown("### Status Summary")
                for status, count in status_counts.items():
                    icons = {"pending": "⏳", "running": "🔄", "completed": "✅", "failed": "❌"}
                    st.markdown(f"- {icons.get(status, '')} {status.title()}: {count}")
                
                df = pd.DataFrame(assignments)
                cols = ["ip", "firmware_version", "analysis_status", "progress", "created_at"]
                available_cols = [c for c in cols if c in df.columns]
                st.dataframe(df[available_cols], use_container_width=True, hide_index=True)
                
                report_data = df.to_dict(orient="records")
            else:
                st.info("No firmware assignments")
                report_data = []
        
        else:
            st.markdown("## 🔒 Full Security Assessment")
            st.info("Comprehensive report combining all data sources")
            
            report_data = {
                "generated": datetime.now().isoformat(),
                "device_stats": device_stats,
                "alert_stats": alert_stats,
                "devices": list_devices(limit=100),
                "alerts": get_suricata_alerts(start_time=start_time, limit=100),
                "firmware": get_firmware_assignments(limit=50)
            }
            
            st.json(report_data)
        
        # Export button
        st.markdown("---")
        st.markdown("### 📥 Export Report")
        
        if export_format == "CSV" and isinstance(report_data, list):
            csv_data = pd.DataFrame(report_data).to_csv(index=False)
            st.download_button(
                "⬇️ Download CSV",
                csv_data,
                f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv",
                "text/csv"
            )
        elif export_format == "JSON":
            json_data = json.dumps(report_data, indent=2, default=str)
            st.download_button(
                "⬇️ Download JSON",
                json_data,
                f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json",
                "application/json"
            )
        elif export_format == "Markdown":
            md_content = f"# {report_type}\n\n"
            md_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            md_content += f"Period: {time_range}\n\n"
            md_content += "```json\n" + json.dumps(report_data, indent=2, default=str)[:5000] + "\n```"
            
            st.download_button(
                "⬇️ Download Markdown",
                md_content,
                f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.md",
                "text/markdown"
            )
        
        st.success("✅ Report generated successfully!")
