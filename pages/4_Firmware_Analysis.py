"""
Page 4: Firmware Analysis - CRITICAL PAGE
Complete firmware analysis with progress tracking, device selection, and analyzer integration
"""
import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import FIRMWARE_ANALYZER_URL
from backend.db import (
    list_devices, 
    create_firmware_assignment, 
    get_firmware_assignments,
    get_firmware_assignment_by_id,
    update_firmware_task_id,
    update_firmware_progress,
    delete_firmware_assignment
)
from backend.fastapi_client import (
    submit_firmware_analysis,
    check_analysis_status,
    get_progress_url,
    is_analyzer_available
)

st.set_page_config(page_title="Firmware Analysis", page_icon="📦", layout="wide")

st.markdown("# 📦 Firmware Analysis")
st.markdown("Analyze IoT device firmware for vulnerabilities and security issues.")

# Check analyzer service status
analyzer_status = is_analyzer_available(FIRMWARE_ANALYZER_URL)

col1, col2 = st.columns([3, 1])
with col2:
    if analyzer_status:
        st.success("✅ Analyzer Online")
    else:
        st.error("❌ Analyzer Offline")
        st.caption(f"URL: {FIRMWARE_ANALYZER_URL}")

st.markdown("---")

# ===== Section 1: Device Selection & Firmware Assignment =====
st.markdown("### 🎯 Assign Firmware to Device")

devices = list_devices()

if not devices:
    st.warning("⚠️ No devices in database. Discover devices first in Network Discovery.")
else:
    # Device dropdown with formatted display
    device_options = {
        f"{d['ip']} | {d.get('mac', 'N/A')[:17]} | {d.get('hostname', 'N/A')[:15]} | {d.get('device_type', 'Unknown')}": d
        for d in devices
    }
    
    col1, col2 = st.columns([3, 1])
    with col1:
        selected_device_key = st.selectbox(
            "Select Device",
            options=list(device_options.keys()),
            help="Select a device to assign firmware for analysis"
        )
    with col2:
        st.metric("Devices Found", len(devices))
    
    selected_device = device_options[selected_device_key]
    
    # Firmware assignment form
    st.markdown("#### Firmware Details")
    
    col1, col2 = st.columns(2)
    with col1:
        firmware_version = st.text_input(
            "Firmware Version",
            placeholder="e.g., 1.2.3",
            help="Version number of the firmware"
        )
    with col2:
        firmware_url = st.text_input(
            "Firmware URL",
            placeholder="https://example.com/firmware.bin",
            help="Direct download URL to firmware binary"
        )
    
    # Save assignment button
    if st.button("💾 Save Assignment", type="primary", disabled=not (firmware_version and firmware_url)):
        assignment_id = create_firmware_assignment(
            device_id=selected_device["_id"],
            ip=selected_device["ip"],
            mac=selected_device.get("mac", "Unknown"),
            firmware_version=firmware_version,
            firmware_url=firmware_url
        )
        
        if assignment_id:
            st.success(f"✅ Firmware assignment saved! ID: {assignment_id[:8]}...")
            st.rerun()
        else:
            st.error("❌ Failed to save assignment. Check database connection.")

st.markdown("---")

# ===== Section 2: Firmware Queue with Progress Tracking =====
st.markdown("### 📋 Firmware Analysis Queue")

col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    if st.button("🔄 REFRESH STATUS", type="primary", use_container_width=True):
        # Refresh all running tasks
        assignments = get_firmware_assignments()
        refreshed = 0
        for assignment in assignments:
            if assignment.get("task_id") and assignment.get("analysis_status") == "running":
                status_result = check_analysis_status(assignment["task_id"], FIRMWARE_ANALYZER_URL)
                if "error" not in status_result:
                    update_firmware_progress(
                        assignment["task_id"],
                        status_result.get("status", "running"),
                        status_result.get("progress", 0),
                        status_result.get("results")
                    )
                    refreshed += 1
        if refreshed > 0:
            st.toast(f"Refreshed {refreshed} tasks")
        st.rerun()

with col2:
    status_filter = st.selectbox("Filter", ["All", "pending", "running", "completed", "failed"])

# Get assignments
filter_status = None if status_filter == "All" else status_filter
assignments = get_firmware_assignments(status=filter_status, limit=50)

if assignments:
    # Build queue table
    queue_data = []
    for a in assignments:
        task_id = a.get("task_id", "")
        status = a.get("analysis_status", "pending")
        progress = a.get("progress", 0)
        
        # Status icon
        status_icons = {
            "pending": "⏳",
            "running": "🔄",
            "completed": "✅",
            "failed": "❌"
        }
        status_display = f"{status_icons.get(status, '❓')} {status}"
        
        # Progress bar text
        if status == "completed":
            progress_text = "100%"
        elif status == "failed":
            progress_text = "Error"
        else:
            progress_text = f"{progress}%"
        
        # Format time
        created = a.get("created_at")
        if created:
            if isinstance(created, str):
                time_str = created[:16]
            else:
                time_str = created.strftime("%Y-%m-%d %H:%M")
        else:
            time_str = "N/A"
        
        queue_data.append({
            "ID": a["_id"][:8] + "...",
            "Task ID": task_id[:8] + "..." if task_id else "Not sent",
            "Status": status_display,
            "Progress": progress_text,
            "Device IP": a.get("ip", "N/A"),
            "Version": a.get("firmware_version", "N/A"),
            "Created": time_str,
            "_full_id": a["_id"],
            "_task_id": task_id,
            "_status": status
        })
    
    df = pd.DataFrame(queue_data)
    display_df = df[["ID", "Task ID", "Status", "Progress", "Device IP", "Version", "Created"]]
    
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    
    # Action buttons for each assignment
    st.markdown("### ⚡ Actions")
    
    selected_idx = st.selectbox(
        "Select Assignment",
        range(len(assignments)),
        format_func=lambda i: f"{assignments[i]['ip']} - v{assignments[i].get('firmware_version', 'N/A')} ({assignments[i].get('analysis_status', 'pending')})"
    )
    
    selected_assignment = assignments[selected_idx]
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # Send to analyzer (only if pending)
        can_send = selected_assignment.get("analysis_status") == "pending" and analyzer_status
        if st.button("🚀 Send to Analyzer", disabled=not can_send, use_container_width=True):
            with st.spinner("Submitting to analyzer..."):
                result = submit_firmware_analysis(
                    device_ip=selected_assignment["ip"],
                    device_mac=selected_assignment.get("mac", "Unknown"),
                    firmware_version=selected_assignment.get("firmware_version", ""),
                    firmware_url=selected_assignment.get("firmware_url", ""),
                    base_url=FIRMWARE_ANALYZER_URL
                )
                
                if result.get("task_id"):
                    update_firmware_task_id(selected_assignment["_id"], result["task_id"])
                    st.success(f"✅ Submitted! Task ID: {result['task_id'][:8]}...")
                    st.rerun()
                else:
                    st.error(f"❌ Failed: {result.get('error', 'Unknown error')}")
    
    with col2:
        # Check status (only if has task_id)
        can_check = bool(selected_assignment.get("task_id"))
        if st.button("🔄 Check Status", disabled=not can_check, use_container_width=True):
            task_id = selected_assignment["task_id"]
            status_result = check_analysis_status(task_id, FIRMWARE_ANALYZER_URL)
            
            if "error" not in status_result:
                update_firmware_progress(
                    task_id,
                    status_result.get("status", "running"),
                    status_result.get("progress", 0),
                    status_result.get("results")
                )
                st.success(f"Status: {status_result.get('status')} ({status_result.get('progress', 0)}%)")
                st.rerun()
            else:
                st.error(f"Error: {status_result.get('error')}")
    
    with col3:
        # Open dashboard link
        if selected_assignment.get("task_id"):
            dashboard_url = get_progress_url(selected_assignment["task_id"], FIRMWARE_ANALYZER_URL)
            st.link_button("🔗 Open Dashboard", dashboard_url, use_container_width=True)
        else:
            st.button("🔗 Open Dashboard", disabled=True, use_container_width=True)
    
    with col4:
        # Delete assignment
        if st.button("🗑️ Delete", use_container_width=True):
            if delete_firmware_assignment(selected_assignment["_id"]):
                st.success("Deleted")
                st.rerun()
    
    st.markdown("---")
    
    # ===== Section 3: Detailed Results =====
    st.markdown("### 📊 Analysis Results")
    
    if selected_assignment.get("analyzer_response"):
        with st.expander(f"📄 Results for Task {selected_assignment.get('task_id', 'N/A')[:12]}...", expanded=True):
            st.json(selected_assignment["analyzer_response"])
    elif selected_assignment.get("analysis_status") == "completed":
        st.info("Analysis completed but no detailed results available.")
    elif selected_assignment.get("analysis_status") == "running":
        st.info("⏳ Analysis in progress... Click 'Refresh Status' to check for updates.")
        
        # Show progress bar
        progress = selected_assignment.get("progress", 0)
        st.progress(progress / 100, text=f"Progress: {progress}%")
    elif selected_assignment.get("analysis_status") == "failed":
        st.error("❌ Analysis failed. Check analyzer logs for details.")
    else:
        st.info("Assignment pending. Click 'Send to Analyzer' to start analysis.")

else:
    st.info("No firmware assignments in queue. Select a device above and assign firmware.")

# ===== Footer with help =====
st.markdown("---")
with st.expander("ℹ️ How to use Firmware Analysis"):
    st.markdown("""
    **Workflow:**
    1. **Select Device** - Choose a discovered device from the dropdown
    2. **Enter Firmware Details** - Provide version and download URL
    3. **Save Assignment** - Store in database (status: pending)
    4. **Send to Analyzer** - Submit to FastAPI analyzer service
    5. **Refresh Status** - Poll for progress updates
    6. **View Results** - Expand results section when complete
    
    **Task ID Links:**
    - Click "Open Dashboard" to view the analyzer's web interface
    - Task IDs are clickable links to `{FIRMWARE_ANALYZER_URL}/dashboard/{{task_id}}`
    
    **Status Meanings:**
    - ⏳ **pending** - Assignment saved, not yet sent to analyzer
    - 🔄 **running** - Analysis in progress
    - ✅ **completed** - Analysis finished successfully
    - ❌ **failed** - Analysis encountered an error
    """)
