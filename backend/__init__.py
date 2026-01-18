"""
IoT SOC Analyst Suite - Backend Module
"""
from .db import (
    get_db,
    upsert_device,
    list_devices,
    get_device_by_id,
    create_firmware_assignment,
    get_firmware_assignment,
    get_firmware_assignments,
    update_firmware_progress,
    insert_suricata_alert,
    get_suricata_alerts,
    get_device_stats,
    get_alert_stats,
)

__all__ = [
    "get_db",
    "upsert_device",
    "list_devices",
    "get_device_by_id",
    "create_firmware_assignment",
    "get_firmware_assignment",
    "get_firmware_assignments",
    "update_firmware_progress",
    "insert_suricata_alert",
    "get_suricata_alerts",
    "get_device_stats",
    "get_alert_stats",
]
