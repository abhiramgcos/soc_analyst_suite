"""
Firmware Analyzer - FastAPI Service
Minimal working template for IoT firmware analysis
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Dict, Optional, Any
import uuid
from datetime import datetime
import asyncio
import random

app = FastAPI(
    title="IoT Firmware Analyzer",
    description="Analyze IoT device firmware for vulnerabilities",
    version="1.0.0"
)

# In-memory storage for demo (use Redis/MongoDB in production)
tasks: Dict[str, Dict[str, Any]] = {}


class FirmwareRequest(BaseModel):
    """Request model for firmware analysis"""
    device_ip: str
    device_mac: str
    firmware_version: str
    firmware_url: str


class FirmwareResponse(BaseModel):
    """Response model after submitting firmware"""
    task_id: str
    status: str
    progress_url: str


class StatusResponse(BaseModel):
    """Response model for status check"""
    task_id: str
    status: str
    progress: int
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


async def analyze_firmware_task(task_id: str, firmware_url: str):
    """
    Background task that simulates firmware analysis
    In production, integrate with emba or other analysis tools
    """
    try:
        tasks[task_id]["status"] = "running"
        tasks[task_id]["started_at"] = datetime.utcnow().isoformat()
        
        # Simulate analysis stages
        stages = [
            (10, "Downloading firmware..."),
            (25, "Extracting filesystem..."),
            (40, "Scanning for known CVEs..."),
            (55, "Analyzing binaries..."),
            (70, "Checking for hardcoded credentials..."),
            (85, "Generating report..."),
            (100, "Analysis complete")
        ]
        
        for progress, stage in stages:
            await asyncio.sleep(random.uniform(2, 5))  # Simulate work
            tasks[task_id]["progress"] = progress
            tasks[task_id]["current_stage"] = stage
        
        # Generate mock results
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["completed_at"] = datetime.utcnow().isoformat()
        tasks[task_id]["results"] = {
            "firmware_url": firmware_url,
            "vulnerabilities_found": random.randint(0, 5),
            "severity_breakdown": {
                "critical": random.randint(0, 2),
                "high": random.randint(0, 3),
                "medium": random.randint(0, 4),
                "low": random.randint(0, 5)
            },
            "components": [
                {"name": "busybox", "version": "1.31.0", "cves": ["CVE-2021-28831"]},
                {"name": "openssl", "version": "1.0.2u", "cves": ["CVE-2020-1971"]},
                {"name": "dropbear", "version": "2019.78", "cves": []}
            ],
            "hardcoded_credentials": [
                {"type": "password", "location": "/etc/shadow", "value": "admin:$1$..."}
            ],
            "interesting_strings": ["admin", "password", "debug", "telnet"],
            "open_ports_in_firmware": [22, 23, 80, 443],
            "analysis_duration_seconds": random.randint(30, 120)
        }
        
    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["error"] = str(e)


@app.get("/")
async def root():
    """Root endpoint with API info"""
    return {
        "service": "IoT Firmware Analyzer",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "analyze": "POST /analyze_firmware",
            "status": "GET /status/{task_id}",
            "dashboard": "GET /dashboard/{task_id}"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/analyze_firmware", response_model=FirmwareResponse)
async def analyze_firmware(request: FirmwareRequest, background_tasks: BackgroundTasks):
    """
    Submit firmware for analysis
    Returns task_id for status tracking
    """
    task_id = str(uuid.uuid4())
    
    # Initialize task
    tasks[task_id] = {
        "task_id": task_id,
        "status": "accepted",
        "progress": 0,
        "device_ip": request.device_ip,
        "device_mac": request.device_mac,
        "firmware_version": request.firmware_version,
        "firmware_url": request.firmware_url,
        "created_at": datetime.utcnow().isoformat(),
        "current_stage": "Queued for analysis"
    }
    
    # Start background analysis
    background_tasks.add_task(analyze_firmware_task, task_id, request.firmware_url)
    
    return FirmwareResponse(
        task_id=task_id,
        status="accepted",
        progress_url=f"/status/{task_id}"
    )


@app.get("/status/{task_id}", response_model=StatusResponse)
async def get_status(task_id: str):
    """
    Get analysis status and results by task_id
    """
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = tasks[task_id]
    
    return StatusResponse(
        task_id=task_id,
        status=task.get("status", "unknown"),
        progress=task.get("progress", 0),
        results=task.get("results"),
        error=task.get("error")
    )


@app.get("/dashboard/{task_id}", response_class=HTMLResponse)
async def dashboard(task_id: str):
    """
    Web dashboard for viewing analysis progress and results
    """
    if task_id not in tasks:
        return HTMLResponse(content="<h1>Task Not Found</h1>", status_code=404)
    
    task = tasks[task_id]
    status = task.get("status", "unknown")
    progress = task.get("progress", 0)
    
    # Status colors
    status_colors = {
        "accepted": "#3498db",
        "running": "#f39c12",
        "completed": "#2ecc71",
        "failed": "#e74c3c"
    }
    color = status_colors.get(status, "#95a5a6")
    
    # Build results HTML
    results_html = ""
    if task.get("results"):
        results = task["results"]
        results_html = f"""
        <div class="results">
            <h2>📊 Analysis Results</h2>
            <div class="stats">
                <div class="stat">
                    <span class="number">{results.get('vulnerabilities_found', 0)}</span>
                    <span class="label">Vulnerabilities</span>
                </div>
                <div class="stat">
                    <span class="number">{results.get('severity_breakdown', {}).get('critical', 0)}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat">
                    <span class="number">{len(results.get('components', []))}</span>
                    <span class="label">Components</span>
                </div>
            </div>
            <h3>Components Found</h3>
            <ul>
            {''.join([f"<li><b>{c['name']}</b> v{c['version']} - CVEs: {', '.join(c['cves']) or 'None'}</li>" for c in results.get('components', [])])}
            </ul>
            <h3>Hardcoded Credentials</h3>
            <ul>
            {''.join([f"<li>{c['type']} in {c['location']}</li>" for c in results.get('hardcoded_credentials', [])])}
            </ul>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Firmware Analysis - {task_id[:8]}</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
            .container {{ max-width: 800px; margin: 0 auto; }}
            h1 {{ color: #667eea; }}
            .status {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: {color}; color: white; font-weight: bold; }}
            .progress-bar {{ background: #2d2d44; border-radius: 10px; height: 30px; overflow: hidden; margin: 20px 0; }}
            .progress-fill {{ background: linear-gradient(90deg, #667eea, #764ba2); height: 100%; width: {progress}%; transition: width 0.5s; display: flex; align-items: center; justify-content: center; font-weight: bold; }}
            .info {{ background: #2d2d44; padding: 15px; border-radius: 10px; margin: 10px 0; }}
            .results {{ background: #2d2d44; padding: 20px; border-radius: 10px; margin-top: 20px; }}
            .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
            .stat {{ background: #1a1a2e; padding: 20px; border-radius: 10px; text-align: center; flex: 1; }}
            .stat .number {{ display: block; font-size: 2em; color: #667eea; }}
            .stat .label {{ color: #888; }}
            ul {{ padding-left: 20px; }}
            li {{ margin: 5px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔬 Firmware Analysis Dashboard</h1>
            <p><b>Task ID:</b> <code>{task_id}</code></p>
            <p><b>Status:</b> <span class="status">{status.upper()}</span></p>
            
            <div class="progress-bar">
                <div class="progress-fill">{progress}%</div>
            </div>
            
            <div class="info">
                <p><b>Device:</b> {task.get('device_ip', 'N/A')} ({task.get('device_mac', 'N/A')})</p>
                <p><b>Firmware:</b> v{task.get('firmware_version', 'N/A')}</p>
                <p><b>Stage:</b> {task.get('current_stage', 'N/A')}</p>
            </div>
            
            {results_html}
            
            <p style="color:#666; margin-top:30px; font-size:0.9em;">
                Page auto-refreshes every 5 seconds | Created: {task.get('created_at', 'N/A')}
            </p>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@app.get("/tasks")
async def list_tasks():
    """List all tasks (for debugging)"""
    return {"tasks": list(tasks.keys()), "count": len(tasks)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
