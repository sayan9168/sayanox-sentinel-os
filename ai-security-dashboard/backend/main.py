"""
AI-Powered System Resource & Security Intelligence Dashboard
Backend FastAPI Application with WebSocket streaming and async workers
Phase 3 Upgrade: Autonomous Enterprise Capabilities
"""

import asyncio
import json
import logging
import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
from playwright.async_api import async_playwright

# Import Phase 3 modules
from remediation.engine import remediation_engine, RemediationRule
from fim.service import fim_service
from firewall.manager import firewall_manager
from backup.service import backup_manager
from gui.streamer import gui_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "database", "security_dashboard.db")
SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "skills")

# Ensure database directory exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# Pydantic Models
class SystemMetrics(BaseModel):
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    network_sent_mb: float
    network_recv_mb: float
    disk_usage_percent: float
    process_count: int


class ThreatAlert(BaseModel):
    id: Optional[int] = None
    title: str
    source: str
    severity: str  # low, medium, high, critical
    description: str
    url: str
    published_date: str
    detected_at: str


class SkillEntry(BaseModel):
    name: str
    description: str
    code_path: str
    created_at: str


# Database initialization
def init_database():
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # System metrics history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            memory_used_gb REAL,
            memory_total_gb REAL,
            network_sent_mb REAL,
            network_recv_mb REAL,
            disk_usage_percent REAL,
            process_count INTEGER
        )
    """)
    
    # Threat alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            source TEXT,
            severity TEXT,
            description TEXT,
            url TEXT,
            published_date TEXT,
            detected_at TEXT NOT NULL
        )
    """)
    
    # Skills log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS skills_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            code_path TEXT,
            created_at TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown events."""
    # Startup
    init_database()
    logger.info("Application started - Database initialized")
    yield
    # Shutdown
    logger.info("Application shutting down")


# Initialize FastAPI app
app = FastAPI(
    title="AI Security Intelligence Dashboard API",
    description="Real-time system monitoring and threat detection API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connected WebSocket clients
connected_clients: List[WebSocket] = []


async def collect_system_metrics() -> Dict[str, Any]:
    """Collect real-time system metrics using psutil."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        net = psutil.net_io_counters()
        disk = psutil.disk_usage('/')
        
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_percent": round(cpu_percent, 2),
            "memory_percent": round(memory.percent, 2),
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "network_sent_mb": round(net.bytes_sent / (1024**2), 2),
            "network_recv_mb": round(net.bytes_recv / (1024**2), 2),
            "disk_usage_percent": round(disk.percent, 2),
            "process_count": len(psutil.pids())
        }
        
        # Store metrics in database
        store_metrics(metrics)
        
        return metrics
    except Exception as e:
        logger.error(f"Error collecting metrics: {e}")
        return {}


def store_metrics(metrics: Dict[str, Any]):
    """Store system metrics in SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO system_metrics 
            (timestamp, cpu_percent, memory_percent, memory_used_gb, memory_total_gb,
             network_sent_mb, network_recv_mb, disk_usage_percent, process_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metrics.get("timestamp"),
            metrics.get("cpu_percent"),
            metrics.get("memory_percent"),
            metrics.get("memory_used_gb"),
            metrics.get("memory_total_gb"),
            metrics.get("network_sent_mb"),
            metrics.get("network_recv_mb"),
            metrics.get("disk_usage_percent"),
            metrics.get("process_count")
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing metrics: {e}")


def store_threat(threat: Dict[str, Any]):
    """Store threat alert in SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO threat_alerts 
            (title, source, severity, description, url, published_date, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.get("title"),
            threat.get("source"),
            threat.get("severity"),
            threat.get("description"),
            threat.get("url"),
            threat.get("published_date"),
            threat.get("detected_at")
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing threat: {e}")


def store_skill(skill: Dict[str, Any]):
    """Store skill entry in SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO skills_log (name, description, code_path, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            skill.get("name"),
            skill.get("description"),
            skill.get("code_path"),
            skill.get("created_at")
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error storing skill: {e}")


async def broadcast_metrics(metrics: Dict[str, Any]):
    """Broadcast metrics to all connected WebSocket clients."""
    if not connected_clients:
        return
    
    message = json.dumps({"type": "metrics", "data": metrics})
    disconnected = []
    
    for client in connected_clients:
        try:
            await client.send_text(message)
        except Exception:
            disconnected.append(client)
    
    # Remove disconnected clients
    for client in disconnected:
        connected_clients.remove(client)


async def metrics_broadcast_loop():
    """Background task to collect and broadcast metrics every 2 seconds."""
    while True:
        try:
            metrics = await collect_system_metrics()
            if metrics:
                await broadcast_metrics(metrics)
        except Exception as e:
            logger.error(f"Error in broadcast loop: {e}")
        await asyncio.sleep(2)


@app.on_event("startup")
async def start_background_tasks():
    """Start background tasks on application startup."""
    asyncio.create_task(metrics_broadcast_loop())
    logger.info("Background metrics collection started")


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "AI Security Intelligence Dashboard API", "version": "1.0.0"}


@app.get("/api/v1/metrics", response_model=SystemMetrics)
async def get_latest_metrics():
    """Get the latest system metrics snapshot."""
    metrics = await collect_system_metrics()
    if not metrics:
        raise HTTPException(status_code=500, detail="Failed to collect metrics")
    return metrics


@app.get("/api/v1/metrics/history")
async def get_metrics_history(limit: int = 100):
    """Get historical system metrics."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM system_metrics ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        columns = ["id", "timestamp", "cpu_percent", "memory_percent", 
                   "memory_used_gb", "memory_total_gb", "network_sent_mb",
                   "network_recv_mb", "disk_usage_percent", "process_count"]
        
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.error(f"Error fetching metrics history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/threats", response_model=List[ThreatAlert])
async def get_threats(limit: int = 50):
    """Get stored threat alerts."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM threat_alerts ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        columns = ["id", "title", "source", "severity", "description", 
                   "url", "published_date", "detected_at"]
        
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/threats", response_model=ThreatAlert)
async def add_threat(threat: ThreatAlert):
    """Add a new threat alert."""
    threat_dict = threat.model_dump()
    threat_dict["detected_at"] = datetime.utcnow().isoformat()
    store_threat(threat_dict)
    return threat


@app.get("/api/v1/skills", response_model=List[SkillEntry])
async def get_skills():
    """Get logged skills from database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM skills_log ORDER BY id DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        columns = ["id", "name", "description", "code_path", "created_at"]
        
        return [dict(zip(columns, row)) for row in rows]
    except Exception as e:
        logger.error(f"Error fetching skills: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/metrics")
async def websocket_metrics_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics streaming."""
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"Client connected. Total clients: {len(connected_clients)}")
    
    try:
        while True:
            # Keep connection alive, client will receive broadcasts
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        logger.info(f"Client disconnected. Total clients: {len(connected_clients)}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# =====================
# PHASE 3 API ENDPOINTS
# =====================

class ThreatWithRemediation(ThreatAlert):
    """Threat alert with remediation status."""
    auto_remediated: bool = False
    remediation_results: List[Dict[str, Any]] = []


@app.post("/api/v1/threats/auto-remediate", response_model=List[Dict[str, Any]])
async def trigger_auto_remediation(threat: ThreatAlert):
    """
    Trigger autonomous remediation for a high-severity threat.
    This is called automatically when threats are added with high/critical severity.
    """
    threat_dict = threat.model_dump()
    results = await remediation_engine.evaluate_threat(threat_dict)
    return results


@app.get("/api/v1/remediation/rules")
async def get_remediation_rules():
    """Get all registered autonomous remediation rules."""
    return {"rules": remediation_engine.get_rules()}


@app.post("/api/v1/remediation/rules/{rule_id}/toggle")
async def toggle_remediation_rule(rule_id: str, enabled: bool):
    """Enable or disable a specific remediation rule."""
    if enabled:
        success = remediation_engine.enable_rule(rule_id)
    else:
        success = remediation_engine.disable_rule(rule_id)
    
    if success:
        return {"success": True, "rule_id": rule_id, "enabled": enabled}
    raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")


@app.get("/api/v1/remediation/log")
async def get_remediation_log(limit: int = 50):
    """Get recent autonomous remediation actions."""
    return {"log": remediation_engine.get_remediation_log(limit)}


# FIM Endpoints
@app.post("/api/v1/fim/watch")
async def add_fim_watch_path(path: str, recursive: bool = True):
    """Add a path to FIM monitoring."""
    fim_service.add_watch_path(path, recursive)
    return {"success": True, "path": path, "recursive": recursive}


@app.post("/api/v1/fim/baseline")
async def create_fim_baseline(paths: Optional[List[str]] = None):
    """Create or update FIM baseline hashes."""
    result = fim_service.create_baseline(paths)
    return result


@app.get("/api/v1/fim/audit")
async def get_fim_audit_log(limit: int = 100, violations_only: bool = False):
    """Get FIM audit log entries."""
    return {"entries": fim_service.get_audit_log(limit, violations_only)}


@app.get("/api/v1/fim/status")
async def get_fim_status():
    """Get FIM service status."""
    return fim_service.get_baseline_status()


@app.post("/api/v1/fim/start")
async def start_fim_service():
    """Start the FIM monitoring service."""
    fim_service.start()
    return {"success": True, "message": "FIM service started"}


@app.post("/api/v1/fim/stop")
async def stop_fim_service():
    """Stop the FIM monitoring service."""
    fim_service.stop()
    return {"success": True, "message": "FIM service stopped"}


# Firewall Endpoints
@app.post("/api/v1/firewall/block")
async def block_ip(ip_address: str, description: str = "Blocked by Security Dashboard"):
    """Block an IP address using OS firewall."""
    result = firewall_manager.block_ip(ip_address, description)
    if result.get("success"):
        return result
    raise HTTPException(status_code=500, detail=result.get("error", "Failed to block IP"))


@app.post("/api/v1/firewall/unblock")
async def unblock_ip(ip_address: str):
    """Unblock an IP address."""
    result = firewall_manager.unblock_ip(ip_address)
    return result


@app.get("/api/v1/firewall/rules")
async def get_firewall_rules():
    """Get all stored firewall rules."""
    return {"rules": firewall_manager.get_stored_rules()}


@app.get("/api/v1/firewall/rules/live")
async def get_live_firewall_rules():
    """Get live firewall rules from OS."""
    return {"rules": firewall_manager.list_rules()}


@app.delete("/api/v1/firewall/flush")
async def flush_firewall_rules():
    """Flush all application-created firewall rules."""
    result = firewall_manager.flush_rules()
    return result


# Backup Endpoints
@app.post("/api/v1/backup/create")
async def create_backup(include_chromadb: bool = True, compress: bool = True):
    """Create a new backup of critical data."""
    result = backup_manager.create_backup(include_chromadb, compress)
    return result


@app.get("/api/v1/backup/list")
async def list_backups():
    """List all available backups."""
    return {"backups": backup_manager.list_backups()}


@app.post("/api/v1/backup/restore")
async def restore_backup(backup_path: str):
    """Restore from a backup archive."""
    result = backup_manager.restore_backup(backup_path)
    if result.get("success"):
        return result
    raise HTTPException(status_code=500, detail=result.get("error", "Failed to restore"))


@app.delete("/api/v1/backup/delete/{filename}")
async def delete_backup(filename: str):
    """Delete a specific backup."""
    result = backup_manager.delete_backup(filename)
    return result


@app.post("/api/v1/backup/cleanup")
async def cleanup_old_backups(keep_count: int = 10):
    """Clean up old backups."""
    result = backup_manager.cleanup_old_backups(keep_count)
    return result


@app.get("/api/v1/backup/stats")
async def get_backup_stats():
    """Get backup storage statistics."""
    return backup_manager.get_storage_stats()


# GUI Streaming Endpoints
@app.get("/api/v1/gui/status")
async def get_gui_status():
    """Get GUI streaming status."""
    return gui_manager.get_gui_status()


@app.post("/api/v1/gui/start")
async def start_gui_stream(password: Optional[str] = None):
    """Start VNC/desktop streaming server."""
    result = gui_manager.start_vnc_server(password)
    return result


@app.post("/api/v1/gui/stop")
async def stop_gui_stream():
    """Stop VNC/desktop streaming server."""
    result = gui_manager.stop_vnc_server()
    return result


@app.get("/api/v1/gui/screenshot")
async def take_screenshot():
    """Take a desktop screenshot."""
    result = gui_manager.take_screenshot()
    return result


@app.post("/api/v1/gui/input/keypress")
async def simulate_keypress(keys: str):
    """Simulate keyboard input."""
    result = gui_manager.simulate_keypress(keys)
    return result


@app.post("/api/v1/gui/input/click")
async def simulate_click(button: str = "left"):
    """Simulate mouse click."""
    result = gui_manager.simulate_click(button)
    return result


@app.post("/api/v1/gui/input/mouse")
async def move_mouse(x: int, y: int):
    """Move mouse to coordinates."""
    result = gui_manager.move_mouse(x, y)
    return result


# Enhanced threat creation with auto-remediation trigger
@app.post("/api/v1/threats", response_model=ThreatWithRemediation)
async def add_threat_with_remediation(threat: ThreatAlert):
    """Add a new threat alert and trigger auto-remediation if high severity."""
    threat_dict = threat.model_dump()
    threat_dict["detected_at"] = datetime.utcnow().isoformat()
    store_threat(threat_dict)
    
    # Auto-trigger remediation for high/critical severity
    auto_remediated = False
    remediation_results = []
    
    if threat.severity.lower() in ["high", "critical"]:
        remediation_results = await remediation_engine.evaluate_threat(threat_dict)
        auto_remediated = len(remediation_results) > 0
    
    return ThreatWithRemediation(
        **threat.model_dump(),
        auto_remediated=auto_remediated,
        remediation_results=remediation_results
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
