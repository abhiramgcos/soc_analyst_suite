"""
IoT SOC Analyst Suite - FastAPI Firmware Analyzer Client
Communicates with the firmware analyzer service
"""
import logging
from typing import Any, Dict, Optional
import httpx
from datetime import datetime

logger = logging.getLogger(__name__)

# Default timeout for API calls
DEFAULT_TIMEOUT = 30.0


class FirmwareAnalyzerClient:
    """Client for firmware analyzer FastAPI service"""
    
    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
    
    def submit_firmware(
        self,
        device_ip: str,
        device_mac: str,
        firmware_version: str,
        firmware_url: str
    ) -> Dict[str, Any]:
        """
        Submit firmware for analysis
        
        Returns:
            Dict with task_id, status, progress_url or error
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url}/analyze_firmware",
                    json={
                        "device_ip": device_ip,
                        "device_mac": device_mac,
                        "firmware_version": firmware_version,
                        "firmware_url": firmware_url
                    }
                )
                response.raise_for_status()
                return response.json()
        except httpx.ConnectError:
            return {"success": False, "error": "Cannot connect to firmware analyzer service"}
        except httpx.TimeoutException:
            return {"success": False, "error": "Request timed out"}
        except httpx.HTTPStatusError as e:
            return {"success": False, "error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            logger.error(f"Submit firmware error: {e}")
            return {"success": False, "error": str(e)}
    
    def check_status(self, task_id: str) -> Dict[str, Any]:
        """
        Check analysis status by task_id
        
        Returns:
            Dict with status, progress, results
        """
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(f"{self.base_url}/status/{task_id}")
                response.raise_for_status()
                return response.json()
        except httpx.ConnectError:
            return {"success": False, "error": "Cannot connect to analyzer service"}
        except httpx.TimeoutException:
            return {"success": False, "error": "Request timed out"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"success": False, "error": "Task not found"}
            return {"success": False, "error": f"HTTP error: {e.response.status_code}"}
        except Exception as e:
            logger.error(f"Check status error: {e}")
            return {"success": False, "error": str(e)}
    
    def get_dashboard_url(self, task_id: str) -> str:
        """Get URL to analyzer dashboard for a task"""
        return f"{self.base_url}/dashboard/{task_id}"
    
    def health_check(self) -> bool:
        """Check if analyzer service is running"""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except Exception:
            return False


# Singleton instance
_client: Optional[FirmwareAnalyzerClient] = None


def get_client(base_url: str = "http://localhost:8000") -> FirmwareAnalyzerClient:
    """Get or create firmware analyzer client"""
    global _client
    if _client is None or _client.base_url != base_url:
        _client = FirmwareAnalyzerClient(base_url)
    return _client


def submit_firmware_analysis(
    device_ip: str,
    device_mac: str,
    firmware_version: str,
    firmware_url: str,
    base_url: str = "http://localhost:8000"
) -> Dict[str, Any]:
    """Convenience function to submit firmware for analysis"""
    client = get_client(base_url)
    return client.submit_firmware(device_ip, device_mac, firmware_version, firmware_url)


def check_analysis_status(task_id: str, base_url: str = "http://localhost:8000") -> Dict[str, Any]:
    """Convenience function to check analysis status"""
    client = get_client(base_url)
    return client.check_status(task_id)


def get_progress_url(task_id: str, base_url: str = "http://localhost:8000") -> str:
    """Get clickable URL to analyzer dashboard"""
    return f"{base_url}/dashboard/{task_id}"


def is_analyzer_available(base_url: str = "http://localhost:8000") -> bool:
    """Check if firmware analyzer is running"""
    client = get_client(base_url)
    return client.health_check()
