"""
IoT SOC Analyst Suite - MongoDB Database Operations
Complete CRUD operations for devices, firmware assignments, and Suricata alerts
"""
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from bson import ObjectId
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    MONGODB_URI,
    MONGODB_DATABASE,
    COLLECTION_DEVICES,
    COLLECTION_FIRMWARE,
    COLLECTION_SURICATA,
)

logger = logging.getLogger(__name__)

# Global database connection
_client: Optional[MongoClient] = None
_db = None


def get_db():
    """
    Get or create MongoDB database connection (singleton pattern)
    Returns the database instance or None if connection fails
    """
    global _client, _db
    
    if _db is not None:
        return _db
    
    try:
        _client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000
        )
        # Test connection
        _client.admin.command('ping')
        _db = _client[MONGODB_DATABASE]
        
        # Create indexes for better performance
        _create_indexes(_db)
        
        logger.info(f"Connected to MongoDB: {MONGODB_DATABASE}")
        return _db
        
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"MongoDB connection failed: {e}")
        return None


def _create_indexes(db):
    """Create database indexes for performance"""
    try:
        # Devices collection indexes
        db[COLLECTION_DEVICES].create_index([("ip", ASCENDING)], unique=True)
        db[COLLECTION_DEVICES].create_index([("mac", ASCENDING)])
        db[COLLECTION_DEVICES].create_index([("last_seen", DESCENDING)])
        db[COLLECTION_DEVICES].create_index([("risk_score", DESCENDING)])
        
        # Firmware assignments indexes
        db[COLLECTION_FIRMWARE].create_index([("task_id", ASCENDING)], unique=True, sparse=True)
        db[COLLECTION_FIRMWARE].create_index([("device_id", ASCENDING)])
        db[COLLECTION_FIRMWARE].create_index([("analysis_status", ASCENDING)])
        db[COLLECTION_FIRMWARE].create_index([("created_at", DESCENDING)])
        
        # Suricata alerts indexes
        db[COLLECTION_SURICATA].create_index([("timestamp", DESCENDING)])
        db[COLLECTION_SURICATA].create_index([("severity", ASCENDING)])
        db[COLLECTION_SURICATA].create_index([("src_ip", ASCENDING)])
        db[COLLECTION_SURICATA].create_index([("dest_ip", ASCENDING)])
        db[COLLECTION_SURICATA].create_index([("signature", ASCENDING)])
        
    except Exception as e:
        logger.warning(f"Index creation warning: {e}")


def is_connected() -> bool:
    """Check if database is connected"""
    db = get_db()
    if db is None:
        return False
    try:
        db.client.admin.command('ping')
        return True
    except Exception:
        return False


# =============================================================================
# Device Operations
# =============================================================================

def upsert_device(device_data: Dict[str, Any]) -> Optional[str]:
    """
    Insert or update a device based on IP address
    Returns the device ID (string) or None on failure
    """
    db = get_db()
    if db is None:
        return None
    
    try:
        device_data["last_seen"] = datetime.utcnow()
        
        # Ensure required fields
        if "ip" not in device_data:
            logger.error("Device must have an IP address")
            return None
        
        # Set defaults
        device_data.setdefault("mac", "Unknown")
        device_data.setdefault("hostname", "")
        device_data.setdefault("device_type", "Unknown")
        device_data.setdefault("os", "Unknown")
        device_data.setdefault("ports", [])
        device_data.setdefault("risk_score", 0.0)
        device_data.setdefault("tags", [])
        
        result = db[COLLECTION_DEVICES].update_one(
            {"ip": device_data["ip"]},
            {"$set": device_data},
            upsert=True
        )
        
        if result.upserted_id:
            return str(result.upserted_id)
        else:
            # Return existing device ID
            existing = db[COLLECTION_DEVICES].find_one({"ip": device_data["ip"]})
            return str(existing["_id"]) if existing else None
            
    except Exception as e:
        logger.error(f"Failed to upsert device: {e}")
        return None


def list_devices(
    filters: Optional[Dict] = None,
    sort_by: str = "last_seen",
    sort_order: int = DESCENDING,
    limit: int = 100
) -> List[Dict]:
    """
    List all devices with optional filtering
    Returns list of device dictionaries
    """
    db = get_db()
    if db is None:
        return []
    
    try:
        query = filters or {}
        cursor = db[COLLECTION_DEVICES].find(query).sort(sort_by, sort_order).limit(limit)
        
        devices = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            devices.append(doc)
        
        return devices
        
    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        return []


def get_device_by_id(device_id: str) -> Optional[Dict]:
    """Get a single device by its ID"""
    db = get_db()
    if db is None:
        return None
    
    try:
        doc = db[COLLECTION_DEVICES].find_one({"_id": ObjectId(device_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    except Exception as e:
        logger.error(f"Failed to get device {device_id}: {e}")
        return None


def get_device_by_ip(ip: str) -> Optional[Dict]:
    """Get a single device by its IP address"""
    db = get_db()
    if db is None:
        return None
    
    try:
        doc = db[COLLECTION_DEVICES].find_one({"ip": ip})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    except Exception as e:
        logger.error(f"Failed to get device by IP {ip}: {e}")
        return None


def delete_device(device_id: str) -> bool:
    """Delete a device by ID"""
    db = get_db()
    if db is None:
        return False
    
    try:
        result = db[COLLECTION_DEVICES].delete_one({"_id": ObjectId(device_id)})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Failed to delete device {device_id}: {e}")
        return False


# =============================================================================
# Firmware Assignment Operations
# =============================================================================

def create_firmware_assignment(
    device_id: str,
    ip: str,
    mac: str,
    firmware_version: str,
    firmware_url: str
) -> Optional[str]:
    """
    Create a new firmware assignment for a device
    Returns the assignment ID or None on failure
    """
    db = get_db()
    if db is None:
        return None
    
    try:
        assignment = {
            "device_id": ObjectId(device_id),
            "ip": ip,
            "mac": mac,
            "firmware_version": firmware_version,
            "firmware_url": firmware_url,
            "analysis_status": "pending",
            "task_id": None,
            "progress": 0,
            "analyzer_response": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        result = db[COLLECTION_FIRMWARE].insert_one(assignment)
        return str(result.inserted_id)
        
    except Exception as e:
        logger.error(f"Failed to create firmware assignment: {e}")
        return None


def get_firmware_assignment(task_id: str) -> Optional[Dict]:
    """Get a firmware assignment by task ID"""
    db = get_db()
    if db is None:
        return None
    
    try:
        doc = db[COLLECTION_FIRMWARE].find_one({"task_id": task_id})
        if doc:
            doc["_id"] = str(doc["_id"])
            doc["device_id"] = str(doc["device_id"])
        return doc
    except Exception as e:
        logger.error(f"Failed to get firmware assignment {task_id}: {e}")
        return None


def get_firmware_assignment_by_id(assignment_id: str) -> Optional[Dict]:
    """Get a firmware assignment by its MongoDB ID"""
    db = get_db()
    if db is None:
        return None
    
    try:
        doc = db[COLLECTION_FIRMWARE].find_one({"_id": ObjectId(assignment_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
            doc["device_id"] = str(doc["device_id"])
        return doc
    except Exception as e:
        logger.error(f"Failed to get firmware assignment by ID {assignment_id}: {e}")
        return None


def get_firmware_assignments(
    status: Optional[str] = None,
    limit: int = 50
) -> List[Dict]:
    """Get all firmware assignments with optional status filter"""
    db = get_db()
    if db is None:
        return []
    
    try:
        query = {}
        if status:
            query["analysis_status"] = status
        
        cursor = db[COLLECTION_FIRMWARE].find(query).sort("created_at", DESCENDING).limit(limit)
        
        assignments = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            doc["device_id"] = str(doc["device_id"])
            assignments.append(doc)
        
        return assignments
        
    except Exception as e:
        logger.error(f"Failed to get firmware assignments: {e}")
        return []


def update_firmware_task_id(assignment_id: str, task_id: str) -> bool:
    """Update the task_id for a firmware assignment (after sending to analyzer)"""
    db = get_db()
    if db is None:
        return False
    
    try:
        result = db[COLLECTION_FIRMWARE].update_one(
            {"_id": ObjectId(assignment_id)},
            {
                "$set": {
                    "task_id": task_id,
                    "analysis_status": "running",
                    "updated_at": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Failed to update task_id: {e}")
        return False


def update_firmware_progress(
    task_id: str,
    status: str,
    progress: int = 0,
    results: Optional[Dict] = None
) -> bool:
    """
    Update firmware analysis progress
    status: pending, running, completed, failed
    progress: 0-100
    results: analyzer response JSON
    """
    db = get_db()
    if db is None:
        return False
    
    try:
        update_data = {
            "analysis_status": status,
            "progress": progress,
            "updated_at": datetime.utcnow()
        }
        
        if results is not None:
            update_data["analyzer_response"] = results
        
        result = db[COLLECTION_FIRMWARE].update_one(
            {"task_id": task_id},
            {"$set": update_data}
        )
        
        return result.modified_count > 0
        
    except Exception as e:
        logger.error(f"Failed to update firmware progress: {e}")
        return False


def delete_firmware_assignment(assignment_id: str) -> bool:
    """Delete a firmware assignment"""
    db = get_db()
    if db is None:
        return False
    
    try:
        result = db[COLLECTION_FIRMWARE].delete_one({"_id": ObjectId(assignment_id)})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Failed to delete firmware assignment: {e}")
        return False


# =============================================================================
# Suricata Alert Operations
# =============================================================================

def insert_suricata_alert(alert: Dict) -> Optional[str]:
    """Insert a Suricata alert"""
    db = get_db()
    if db is None:
        return None
    
    try:
        # Ensure timestamp is datetime
        if "timestamp" in alert and isinstance(alert["timestamp"], str):
            alert["timestamp"] = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
        else:
            alert["timestamp"] = datetime.utcnow()
        
        result = db[COLLECTION_SURICATA].insert_one(alert)
        return str(result.inserted_id)
        
    except Exception as e:
        logger.error(f"Failed to insert Suricata alert: {e}")
        return None


def insert_suricata_alerts_bulk(alerts: List[Dict]) -> int:
    """Bulk insert Suricata alerts"""
    db = get_db()
    if db is None:
        return 0
    
    try:
        if not alerts:
            return 0
        
        for alert in alerts:
            if "timestamp" in alert and isinstance(alert["timestamp"], str):
                alert["timestamp"] = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
            else:
                alert["timestamp"] = datetime.utcnow()
        
        result = db[COLLECTION_SURICATA].insert_many(alerts)
        return len(result.inserted_ids)
        
    except Exception as e:
        logger.error(f"Failed to bulk insert Suricata alerts: {e}")
        return 0


def get_suricata_alerts(
    severity: Optional[int] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    signature: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100
) -> List[Dict]:
    """Get Suricata alerts with filters"""
    db = get_db()
    if db is None:
        return []
    
    try:
        query = {}
        
        if severity is not None:
            query["severity"] = severity
        if src_ip:
            query["src_ip"] = src_ip
        if dest_ip:
            query["dest_ip"] = dest_ip
        if signature:
            query["signature"] = {"$regex": signature, "$options": "i"}
        
        if start_time or end_time:
            query["timestamp"] = {}
            if start_time:
                query["timestamp"]["$gte"] = start_time
            if end_time:
                query["timestamp"]["$lte"] = end_time
        
        cursor = db[COLLECTION_SURICATA].find(query).sort("timestamp", DESCENDING).limit(limit)
        
        alerts = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            alerts.append(doc)
        
        return alerts
        
    except Exception as e:
        logger.error(f"Failed to get Suricata alerts: {e}")
        return []


def get_recent_alerts(minutes: int = 60, limit: int = 100) -> List[Dict]:
    """Get alerts from the last N minutes"""
    from datetime import timedelta
    start_time = datetime.utcnow() - timedelta(minutes=minutes)
    return get_suricata_alerts(start_time=start_time, limit=limit)


# =============================================================================
# Statistics and Aggregations
# =============================================================================

def get_device_stats() -> Dict:
    """Get device statistics for dashboard"""
    db = get_db()
    if db is None:
        return {}
    
    try:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_devices": {"$sum": 1},
                    "avg_risk_score": {"$avg": "$risk_score"},
                    "high_risk": {
                        "$sum": {"$cond": [{"$gte": ["$risk_score", 7]}, 1, 0]}
                    },
                    "medium_risk": {
                        "$sum": {"$cond": [
                            {"$and": [
                                {"$gte": ["$risk_score", 4]},
                                {"$lt": ["$risk_score", 7]}
                            ]}, 1, 0
                        ]}
                    },
                    "low_risk": {
                        "$sum": {"$cond": [{"$lt": ["$risk_score", 4]}, 1, 0]}
                    }
                }
            }
        ]
        
        result = list(db[COLLECTION_DEVICES].aggregate(pipeline))
        
        if result:
            stats = result[0]
            del stats["_id"]
            return stats
        
        return {
            "total_devices": 0,
            "avg_risk_score": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0
        }
        
    except Exception as e:
        logger.error(f"Failed to get device stats: {e}")
        return {}


def get_device_type_distribution() -> List[Dict]:
    """Get device count by type"""
    db = get_db()
    if db is None:
        return []
    
    try:
        pipeline = [
            {"$group": {"_id": "$device_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        return list(db[COLLECTION_DEVICES].aggregate(pipeline))
    except Exception as e:
        logger.error(f"Failed to get device type distribution: {e}")
        return []


def get_alert_stats(hours: int = 24) -> Dict:
    """Get alert statistics for dashboard"""
    db = get_db()
    if db is None:
        return {}
    
    try:
        from datetime import timedelta
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_time}}},
            {
                "$group": {
                    "_id": None,
                    "total_alerts": {"$sum": 1},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$severity", 1]}, 1, 0]}},
                    "high": {"$sum": {"$cond": [{"$eq": ["$severity", 2]}, 1, 0]}},
                    "medium": {"$sum": {"$cond": [{"$eq": ["$severity", 3]}, 1, 0]}},
                    "low": {"$sum": {"$cond": [{"$gte": ["$severity", 4]}, 1, 0]}}
                }
            }
        ]
        
        result = list(db[COLLECTION_SURICATA].aggregate(pipeline))
        
        if result:
            stats = result[0]
            del stats["_id"]
            return stats
        
        return {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
    except Exception as e:
        logger.error(f"Failed to get alert stats: {e}")
        return {}


def get_alerts_by_hour(hours: int = 24) -> List[Dict]:
    """Get alert count grouped by hour"""
    db = get_db()
    if db is None:
        return []
    
    try:
        from datetime import timedelta
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_time}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d %H:00",
                            "date": "$timestamp"
                        }
                    },
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"_id": 1}}
        ]
        
        return list(db[COLLECTION_SURICATA].aggregate(pipeline))
        
    except Exception as e:
        logger.error(f"Failed to get alerts by hour: {e}")
        return []


def get_top_signatures(limit: int = 10) -> List[Dict]:
    """Get most common alert signatures"""
    db = get_db()
    if db is None:
        return []
    
    try:
        pipeline = [
            {"$group": {"_id": "$signature", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]
        return list(db[COLLECTION_SURICATA].aggregate(pipeline))
    except Exception as e:
        logger.error(f"Failed to get top signatures: {e}")
        return []


def get_top_source_ips(limit: int = 10) -> List[Dict]:
    """Get most common source IPs in alerts"""
    db = get_db()
    if db is None:
        return []
    
    try:
        pipeline = [
            {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": limit}
        ]
        return list(db[COLLECTION_SURICATA].aggregate(pipeline))
    except Exception as e:
        logger.error(f"Failed to get top source IPs: {e}")
        return []
