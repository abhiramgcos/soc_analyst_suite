"""
Page 3: CVE Scanning
Vulnerability scanning using NVD database via nvdlib
"""
import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NVD_API_KEY
from backend.db import list_devices

# Try to import nvdlib
try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False

st.set_page_config(page_title="CVE Scanning", page_icon="🔒", layout="wide")

st.markdown("# 🔒 CVE Scanning")
st.markdown("Search the National Vulnerability Database for known vulnerabilities in your IoT devices.")

if not NVDLIB_AVAILABLE:
    st.error("❌ nvdlib is not installed. Run: `pip install nvdlib`")
    st.stop()

# Search options
st.markdown("### 🔍 Search Options")

col1, col2 = st.columns(2)

with col1:
    search_type = st.radio("Search By", ["Keyword", "Product/Vendor (CPE)", "CVE ID"])

with col2:
    if NVD_API_KEY:
        st.success("✅ NVD API Key configured")
    else:
        st.warning("⚠️ No API key - rate limited to 5 requests/30s")

# Search input
if search_type == "Keyword":
    keyword = st.text_input("Keyword Search", placeholder="e.g., apache, telnet, camera")
    search_value = keyword
elif search_type == "Product/Vendor (CPE)":
    col1, col2 = st.columns(2)
    with col1:
        vendor = st.text_input("Vendor", placeholder="e.g., hikvision")
    with col2:
        product = st.text_input("Product", placeholder="e.g., ds-2cd2xx")
    search_value = f"{vendor} {product}".strip()
else:
    cve_id = st.text_input("CVE ID", placeholder="e.g., CVE-2021-36260")
    search_value = cve_id

# Severity filter
col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    min_severity = st.selectbox("Min CVSS Score", [0.0, 4.0, 7.0, 9.0], format_func=lambda x: f"{x}+" if x > 0 else "Any")
with col2:
    limit = st.number_input("Max Results", min_value=5, max_value=100, value=20)

search_button = st.button("🔍 Search CVEs", type="primary")

st.markdown("---")

# Session state for results
if "cve_results" not in st.session_state:
    st.session_state.cve_results = []

# Perform search
if search_button and search_value:
    with st.spinner("Searching NVD database..."):
        try:
            kwargs = {"key": NVD_API_KEY} if NVD_API_KEY else {}
            
            if search_type == "CVE ID":
                # Direct CVE lookup
                results = nvdlib.searchCVE(cveId=search_value, **kwargs)
            else:
                # Keyword search
                results = nvdlib.searchCVE(keywordSearch=search_value, **kwargs)
            
            # Convert to list and filter by severity
            cve_list = []
            for cve in results:
                try:
                    # Get CVSS score
                    cvss_score = 0.0
                    cvss_version = "N/A"
                    
                    if hasattr(cve, 'v31score') and cve.v31score:
                        cvss_score = cve.v31score
                        cvss_version = "3.1"
                    elif hasattr(cve, 'v30score') and cve.v30score:
                        cvss_score = cve.v30score
                        cvss_version = "3.0"
                    elif hasattr(cve, 'v2score') and cve.v2score:
                        cvss_score = cve.v2score
                        cvss_version = "2.0"
                    
                    if cvss_score >= min_severity:
                        cve_list.append({
                            "id": cve.id,
                            "description": cve.descriptions[0].value if cve.descriptions else "N/A",
                            "cvss_score": cvss_score,
                            "cvss_version": cvss_version,
                            "severity": "Critical" if cvss_score >= 9 else "High" if cvss_score >= 7 else "Medium" if cvss_score >= 4 else "Low",
                            "published": cve.published[:10] if hasattr(cve, 'published') else "N/A",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve.id}"
                        })
                except Exception as e:
                    continue
                
                if len(cve_list) >= limit:
                    break
            
            st.session_state.cve_results = cve_list
            st.success(f"Found {len(cve_list)} vulnerabilities")
            
        except Exception as e:
            st.error(f"Search failed: {str(e)}")

# Display results
st.markdown("### 📋 Vulnerability Results")

if st.session_state.cve_results:
    results = st.session_state.cve_results
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    critical = len([c for c in results if c["severity"] == "Critical"])
    high = len([c for c in results if c["severity"] == "High"])
    medium = len([c for c in results if c["severity"] == "Medium"])
    low = len([c for c in results if c["severity"] == "Low"])
    
    with col1:
        st.metric("🔴 Critical", critical)
    with col2:
        st.metric("🟠 High", high)
    with col3:
        st.metric("🟡 Medium", medium)
    with col4:
        st.metric("🟢 Low", low)
    
    # Results table
    df = pd.DataFrame(results)
    df = df[["id", "severity", "cvss_score", "published", "description"]]
    df["description"] = df["description"].apply(lambda x: x[:100] + "..." if len(x) > 100 else x)
    
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    # CVE details
    st.markdown("### 🔎 CVE Details")
    
    selected_cve = st.selectbox("Select CVE", [c["id"] for c in results])
    
    cve_data = next((c for c in results if c["id"] == selected_cve), None)
    
    if cve_data:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"### {cve_data['id']}")
            st.markdown(cve_data["description"])
            st.markdown(f"[View on NVD]({cve_data['url']})")
        
        with col2:
            severity_color = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            st.markdown(f"**Severity:** {severity_color.get(cve_data['severity'], '')} {cve_data['severity']}")
            st.markdown(f"**CVSS Score:** {cve_data['cvss_score']} (v{cve_data['cvss_version']})")
            st.markdown(f"**Published:** {cve_data['published']}")
    
    # Export
    st.markdown("---")
    if st.button("📥 Export to CSV"):
        csv = pd.DataFrame(results).to_csv(index=False)
        st.download_button("Download CSV", csv, "cve_results.csv", "text/csv")
else:
    st.info("Enter a search term and click 'Search CVEs' to find vulnerabilities.")

# Quick scan from devices
st.markdown("---")
st.markdown("### 🎯 Quick Device Scan")

devices = list_devices()
if devices:
    device_options = [f"{d['ip']} - {d.get('device_type', 'Unknown')}" for d in devices]
    selected_device = st.selectbox("Scan Device for CVEs", device_options)
    
    if st.button("🔍 Scan Selected Device"):
        device_idx = device_options.index(selected_device)
        device = devices[device_idx]
        
        services = [p.get("service", "") for p in device.get("ports", [])]
        products = [p.get("product", "") for p in device.get("ports", [])]
        
        search_terms = services + products + [device.get("os", "")]
        search_terms = [t for t in search_terms if t and t != "Unknown"]
        
        if search_terms:
            st.info(f"Searching for: {', '.join(search_terms[:5])}")
        else:
            st.warning("No identifiable services or products found for this device")
else:
    st.info("No devices in database. Discover devices first in Network Discovery.")
