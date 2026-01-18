# 🛡️ IoT SOC Analyst Suite

A production-ready **Streamlit application** with MongoDB backend for IoT Security Operations Center analysis. Combines network discovery, Suricata IDS, CVE scanning, firmware analysis, and live monitoring.

## 🎯 Features

- **Network Discovery** - Nmap-based device scanning with risk scoring
- **Suricata Alerts** - Real-time IDS alert monitoring from EVE JSON
- **CVE Scanning** - NVD database vulnerability lookup via nvdlib
- **Firmware Analysis** - FastAPI analyzer integration with progress tracking
- **Traffic Analysis** - Network traffic visualization with Plotly
- **Security Dashboard** - Comprehensive security posture overview
- **Reports** - Generate and export security reports (CSV/JSON/MD)

## 📁 Project Structure

```
soc_analyst_suite/
├── app.py                      # Main Streamlit application
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── backend/
│   ├── __init__.py
│   ├── db.py                   # MongoDB CRUD operations
│   ├── nmap_scanner.py         # Nmap integration
│   ├── suricata_parser.py      # EVE JSON parsing
│   └── fastapi_client.py       # Firmware analyzer client
├── pages/
│   ├── 1_Network_Discovery.py
│   ├── 2_Suricata_Alerts.py
│   ├── 3_CVE_Scanning.py
│   ├── 4_Firmware_Analysis.py
│   ├── 5_Traffic_Analysis.py
│   ├── 6_Security_Dashboard.py
│   └── 7_Reports.py
└── firmware_analyzer/
    └── main.py                 # FastAPI analyzer service
```

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- MongoDB (running on localhost:27017)
- Nmap (optional, for network scanning)
- Suricata (optional, for IDS alerts)

### Installation

```bash
# Navigate to project directory
cd soc_analyst_suite

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
# Or on Windows: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Add uv to PATH (restart shell or run one of these):
source $HOME/.local/bin/env       # bash/zsh
source $HOME/.local/bin/env.fish  # fish

# Create virtual environment
uv venv

# Activate virtual environment
# Linux/Mac (bash/zsh):
source .venv/bin/activate

# Linux/Mac (fish shell):
source .venv/bin/activate.fish

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Windows (CMD):
.venv\Scripts\activate.bat

# Install dependencies
uv pip install -r requirements.txt
```

> **Note:** `uv` is a fast Python package installer written in Rust. It's 10-100x faster than pip. If you prefer pip, use `python -m venv .venv && pip install -r requirements.txt` instead.

### Start MongoDB

```bash
# Using Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Or install MongoDB locally and start the service
```

### Run the Application

```bash
# Terminal 1: Start FastAPI Analyzer (optional)
cd firmware_analyzer
uvicorn main:app --reload --port 8000

# Terminal 2: Start Streamlit App
cd soc_analyst_suite
streamlit run app.py
```

Access the application at: **http://localhost:8501**

## ⚙️ Configuration


The application uses a `.env` file for configuration.

1.  **Create your environment file:**
    ```bash
    cp .env.example .env
    ```

2.  **Edit `.env`** to match your environment:
    ```ini
    # MongoDB
    MONGODB_URI="mongodb://localhost:27017"

    # Suricata Log Path
    SURICATA_EVE_PATH="/var/log/suricata/eve.json"

    # NVD API Key (Optional)
    NVD_API_KEY="your-api-key-here"
    ```


## 📊 MongoDB Collections

| Collection | Description |
|------------|-------------|
| `devices` | Discovered IoT devices with risk scores |
| `firmware_assignments` | Firmware analysis tasks and results |
| `suricata_alerts` | IDS alerts from Suricata |

## 🔧 Network Topology

```
Internet → [Ethernet1] → Windows Laptop → [Ethernet2] → Access Point → IoT Devices
                              ↓
                        Suricata IDS
                       (monitors Ethernet2)
```

## 📱 Firmware Analysis Workflow

1. **Select Device** from discovered devices dropdown
2. **Enter Firmware** version and download URL
3. **Save Assignment** to database (status: pending)
4. **Send to Analyzer** via FastAPI service
5. **Refresh Status** to poll progress
6. **View Results** when analysis completes

## 🖥️ FastAPI Analyzer Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/analyze_firmware` | POST | Submit firmware for analysis |
| `/status/{task_id}` | GET | Check analysis status |
| `/dashboard/{task_id}` | GET | Web dashboard view |

## 📋 Environment Variables

```bash
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DATABASE="iot_soc"
export SURICATA_EVE_PATH="/var/log/suricata/eve.json"
export FIRMWARE_ANALYZER_URL="http://localhost:8000"
export NVD_API_KEY="your-api-key"
```

## 🔒 Production Deployment

For production, consider:

1. **MongoDB Authentication** - Enable auth and use credentials
2. **HTTPS** - Use SSL/TLS for all services
3. **Authentication** - Add Streamlit auth (streamlit-authenticator)
4. **Rate Limiting** - Protect API endpoints
5. **Logging** - Configure proper logging
6. **Docker** - Containerize all services

## 📝 License

MIT License - Free for educational and commercial use.

## 👨‍💻 Author

Built for B.Tech CSE cybersecurity coursework.
