"""
Sayanox Sentinel OS - Autonomous System Security, PC Operations & Threat Mitigation Platform
Backend FastAPI Application with WebSocket streaming and async workers
Phase 4 Enterprise Upgrade: ML Anomaly Detection, Honeypot, Network Scanning, PWA Support
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
from fastapi.responses import JSONResponse, FileResponse, Response
from pydantic import BaseModel
import uvicorn
from playwright.async_api import async_playwright

# Import Phase 3 modules
from remediation.engine import remediation_engine, RemediationRule
from fim.service import fim_service
from firewall.manager import firewall_manager
from backup.service import backup_manager
from gui.streamer import gui_manager

# Import Phase 4 modules
from anomaly.detector import anomaly_detector
from honeypot.worker import honeypot_worker
from network.scanner import packet_sniffer, nmap_scanner

# Import Phase 5 advanced modules
from ransomware.canary import canary_guardian
from sentinel.killswitch import (
    kill_switch, LEVEL_PAUSE, LEVEL_ISOLATE, LEVEL_HALT, LEVEL_FREEZE,
)
from sentinel.nlp import threat_nlp
from sentinel.correlator import incident_correlator

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
    detected_at: Optional[str] = None  # Auto-filled with current UTC time if omitted


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

    # Phase 5: Ransomware canary events + kill switch audit ledger tables
    canary_guardian.db_path = DB_PATH
    canary_guardian._init_db()
    kill_switch.db_path = DB_PATH
    kill_switch._init_db()
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
    title="Sayanox Sentinel OS API",
    description="Autonomous System Security, PC Operations & Threat Mitigation Platform API",
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

# Phase 4: Packet sniffer WebSocket clients
packet_sniffer_clients: List[WebSocket] = []


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
        
        # Add sample to anomaly detector for ML training
        anomaly_detector.add_sample(metrics)
        
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
                
                # Check for anomalies with ML model (every 10 cycles to reduce overhead)
                if hasattr(metrics_broadcast_loop, 'cycle_count'):
                    metrics_broadcast_loop.cycle_count += 1
                else:
                    metrics_broadcast_loop.cycle_count = 1
                
                if metrics_broadcast_loop.cycle_count % 10 == 0:
                    anomaly_result = anomaly_detector.detect_anomaly(metrics)
                    if anomaly_result.get('is_anomaly'):
                        logger.warning(f"ML Anomaly detected: {anomaly_result}")
                        # Create threat alert for anomaly
                        threat = {
                            'title': f"ML Anomaly Detection Alert - {anomaly_result['severity'].upper()}",
                            'source': 'AnomalyDetector',
                            'severity': anomaly_result['severity'],
                            'description': f"System behavior anomaly detected. Score: {anomaly_result['anomaly_score']:.4f}",
                            'url': '',
                            'published_date': datetime.utcnow().isoformat(),
                            'detected_at': datetime.utcnow().isoformat()
                        }
                        store_threat(threat)
        except Exception as e:
            logger.error(f"Error in broadcast loop: {e}")
        await asyncio.sleep(2)


@app.on_event("startup")
async def start_background_tasks():
    """Start background tasks on application startup."""
    asyncio.create_task(metrics_broadcast_loop())
    logger.info("Background metrics collection started")
    
    # Setup honeypot firewall callback
    def firewall_block_callback(ip_address: str):
        """Callback to block IPs detected by honeypot."""
        try:
            firewall_manager.block_ip(ip_address, "Blocked by Honeypot - Sayanox Sentinel OS")
        except Exception as e:
            logger.error(f"Error blocking IP from honeypot: {e}")
    
    honeypot_worker.firewall_callback = firewall_block_callback
    
    # Start honeypot in background
    asyncio.create_task(start_honeypot())
    
    # Start packet sniffer in background
    asyncio.create_task(start_packet_sniffer())

    # ---- Phase 5: wire kill switch degradation ladder to real subsystems ----
    def _ks_pause():
        """L1: pause autonomous workers."""
        try:
            fim_service.stop()
        except Exception as e:
            logger.error(f"Kill switch pause (FIM) error: {e}")

    def _ks_isolate():
        """L2: network isolation via firewall."""
        try:
            firewall_manager.isolate_network()
        except AttributeError:
            logger.warning("Firewall manager has no isolate_network; skipping L2")
        except Exception as e:
            logger.error(f"Kill switch isolate error: {e}")

    def _ks_halt():
        """L3: halt honeypot/sniffer automation."""
        try:
            asyncio.create_task(honeypot_worker.stop())
            asyncio.create_task(packet_sniffer.stop())
        except Exception as e:
            logger.error(f"Kill switch halt error: {e}")

    def _ks_freeze():
        """L4: freeze remediation engine into safe mode."""
        try:
            rules = remediation_engine.get_rules()
            rule_list = rules.get("rules", []) if isinstance(rules, dict) else rules
            for rule in rule_list:
                rule_id = rule.get("id") if isinstance(rule, dict) else getattr(rule, "id", None)
                if rule_id:
                    remediation_engine.disable_rule(rule_id)
        except Exception as e:
            logger.error(f"Kill switch freeze error: {e}")

    kill_switch.register_hook(LEVEL_PAUSE, _ks_pause)
    kill_switch.register_hook(LEVEL_ISOLATE, _ks_isolate)
    kill_switch.register_hook(LEVEL_HALT, _ks_halt)
    kill_switch.register_hook(LEVEL_FREEZE, _ks_freeze)

    # ---- Phase 5: correlate ransomware findings into incidents ----
    def _canary_to_incident(finding):
        event_map = {
            "CANARY_TRIPPED": "canary_tripped",
            "ENCRYPTION_STORM": "encryption_storm",
            "HIGH_ENTROPY_WRITE": "high_entropy_write",
            "SUSPICIOUS_EXTENSION": "suspicious_process",
        }
        etype = event_map.get(finding.get("type", ""), "anomaly_detected")
        incident_correlator.ingest(etype, {
            "file_path": finding.get("file"),
            "detail": finding.get("detail"),
        })

    canary_guardian.register_callback(_canary_to_incident)

    # Start ransomware canary watchdog in background thread
    canary_guardian.start(interval=5)

    logger.info("Phase 4 Enterprise modules initialized")
    logger.info("Phase 5 Advanced modules initialized (Canary/KillSwitch/NLP/Correlator)")


async def start_honeypot():
    """Start the honeypot worker."""
    await asyncio.sleep(2)  # Delay to let main server start
    try:
        await honeypot_worker.start()
    except Exception as e:
        logger.error(f"Error starting honeypot: {e}")


async def start_packet_sniffer():
    """Start the packet sniffer."""
    await asyncio.sleep(3)  # Delay to let main server start
    try:
        await packet_sniffer.start()
    except Exception as e:
        logger.error(f"Error starting packet sniffer: {e}")


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Sayanox Sentinel OS API", "version": "1.0.0"}


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
async def block_ip(ip_address: str, description: str = "Blocked by Sayanox Sentinel OS"):
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


# =====================
# PHASE 4 API ENDPOINTS
# =====================

class NmapScanRequest(BaseModel):
    """Request model for nmap scans."""
    host: str
    scan_type: str = "quick"  # quick, full, custom
    ports: Optional[str] = None
    arguments: Optional[str] = None


@app.get("/api/v1/anomaly/status")
async def get_anomaly_status():
    """Get ML anomaly detector status."""
    return anomaly_detector.get_model_status()


@app.post("/api/v1/anomaly/train")
async def train_anomaly_model(min_samples: int = 50):
    """Manually trigger ML model training."""
    success = anomaly_detector.train(min_samples)
    return {"success": success, "message": "Training completed" if success else "Training failed"}


@app.post("/api/v1/anomaly/reset")
async def reset_anomaly_model():
    """Reset the anomaly detection model."""
    anomaly_detector.reset()
    return {"success": True, "message": "Model reset complete"}


@app.get("/api/v1/honeypot/status")
async def get_honeypot_status():
    """Get honeypot worker status."""
    return honeypot_worker.get_status()


@app.post("/api/v1/honeypot/start")
async def start_honeypot_endpoint(ports: Optional[List[int]] = None):
    """Start the honeypot worker."""
    asyncio.create_task(honeypot_worker.start(ports))
    return {"success": True, "message": "Honeypot starting"}


@app.post("/api/v1/honeypot/stop")
async def stop_honeypot_endpoint():
    """Stop the honeypot worker."""
    await honeypot_worker.stop()
    return {"success": True, "message": "Honeypot stopped"}


@app.get("/api/v1/honeypot/logs")
async def get_honeypot_logs(limit: int = 100):
    """Get honeypot connection logs."""
    return {"logs": honeypot_worker.get_connection_logs(limit)}


@app.post("/api/v1/honeypot/logs/clear")
async def clear_honeypot_logs():
    """Clear honeypot logs."""
    honeypot_worker.clear_logs()
    return {"success": True}


@app.post("/api/v1/honeypot/port/add")
async def add_honeypot_port(port: int):
    """Add a decoy port to the honeypot."""
    honeypot_worker.add_decoy_port(port)
    return {"success": True, "port": port}


@app.delete("/api/v1/honeypot/port/remove")
async def remove_honeypot_port(port: int):
    """Remove a decoy port from the honeypot."""
    honeypot_worker.remove_decoy_port(port)
    return {"success": True, "port": port}


@app.websocket("/ws/packets")
async def websocket_packets_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time network packet streaming."""
    await websocket.accept()
    packet_sniffer_clients.append(websocket)
    logger.info(f"Packet sniffer client connected. Total: {len(packet_sniffer_clients)}")
    
    async def send_packet(packet_info: Dict[str, Any]):
        try:
            await websocket.send_json({"type": "packet", "data": packet_info})
        except Exception:
            pass
    
    packet_sniffer.add_websocket_callback(send_packet)
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
            elif data == "get_packets":
                packets = packet_sniffer.get_captured_packets(50)
                await websocket.send_json({"type": "packets", "data": packets})
    except WebSocketDisconnect:
        packet_sniffer_clients.remove(websocket)
        logger.info(f"Packet sniffer client disconnected. Total: {len(packet_sniffer_clients)}")
    except Exception as e:
        logger.error(f"Packet WebSocket error: {e}")
        if websocket in packet_sniffer_clients:
            packet_sniffer_clients.remove(websocket)


@app.get("/api/v1/network/packets")
async def get_captured_packets(limit: int = 100):
    """Get recently captured network packets."""
    return {"packets": packet_sniffer.get_captured_packets(limit)}


@app.post("/api/v1/network/sniffer/start")
async def start_sniffer():
    """Start the packet sniffer."""
    asyncio.create_task(packet_sniffer.start())
    return {"success": True, "message": "Packet sniffer starting"}


@app.post("/api/v1/network/sniffer/stop")
async def stop_sniffer():
    """Stop the packet sniffer."""
    await packet_sniffer.stop()
    return {"success": True, "message": "Packet sniffer stopped"}


@app.get("/api/v1/network/sniffer/status")
async def get_sniffer_status():
    """Get packet sniffer status."""
    return packet_sniffer.get_status()


@app.post("/api/v1/network/scan", response_model=Dict[str, Any])
async def perform_nmap_scan(request: NmapScanRequest):
    """Perform an nmap network scan."""
    if request.scan_type == "quick":
        result = nmap_scanner.quick_scan(request.host)
    elif request.scan_type == "full":
        result = nmap_scanner.full_scan(request.host)
    else:
        result = nmap_scanner.scan_host(
            request.host, 
            ports=request.ports or "21,22,23,25,80,443",
            arguments=request.arguments or "-sV"
        )
    return result


@app.get("/api/v1/network/scan/history")
async def get_scan_history(limit: int = 20):
    """Get nmap scan history."""
    return {"history": nmap_scanner.get_scan_history(limit)}


@app.post("/api/v1/network/scan/network-range")
async def scan_network_range(network: str, ports: str = "22,80,443"):
    """Scan a network range for hosts."""
    results = nmap_scanner.scan_network_range(network, ports)
    return {"results": results}


@app.get("/api/v1/network/scanner/status")
async def get_scanner_status():
    """Get nmap scanner status."""
    return nmap_scanner.get_status()


# =====================
# PHASE 5 ADVANCED API ENDPOINTS
# =====================

class KillSwitchRequest(BaseModel):
    """Kill switch activation request."""
    level: int  # 1=pause, 2=isolate, 3=halt, 4=freeze
    reason: str = ""
    pin: Optional[str] = None


class KillSwitchPinRequest(BaseModel):
    pin: str


class NLPAnalysisRequest(BaseModel):
    text: str


class CorrelateEventRequest(BaseModel):
    event_type: str
    source_ip: Optional[str] = None
    file_path: Optional[str] = None
    process: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


# ---- Ransomware Canary Guardian ----
@app.get("/api/v1/ransomware/status")
async def get_ransomware_status():
    """Get ransomware canary guardian status."""
    return canary_guardian.get_status()


@app.post("/api/v1/ransomware/watch")
async def add_ransomware_watch(directory: str):
    """Protect a directory: plant canary files and start watching."""
    result = canary_guardian.add_watch_directory(directory)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed"))
    return result


@app.get("/api/v1/ransomware/alerts")
async def get_ransomware_alerts(limit: int = 50):
    """Get live ransomware detection alerts."""
    return {"alerts": canary_guardian.get_alerts(limit)}


@app.get("/api/v1/ransomware/events")
async def get_ransomware_events(limit: int = 100):
    """Get persisted ransomware event log."""
    return {"events": canary_guardian.get_events(limit)}


@app.post("/api/v1/ransomware/sweep")
async def trigger_ransomware_sweep():
    """Force an immediate canary + entropy sweep."""
    findings = canary_guardian.sweep_once()
    return {"findings": findings, "count": len(findings)}


@app.post("/api/v1/ransomware/lockdown/clear")
async def clear_ransomware_lockdown():
    """Clear ransomware lockdown after incident review."""
    return canary_guardian.clear_lockdown()


# ---- AI Kill Switch ----
@app.get("/api/v1/killswitch/status")
async def get_killswitch_status():
    """Get kill switch arm state, active level and audit ledger."""
    return kill_switch.get_status()


@app.post("/api/v1/killswitch/pin")
async def set_killswitch_pin(request: KillSwitchPinRequest):
    """Configure the kill-switch PIN (required for L2+ isolation)."""
    if len(request.pin) < 4:
        raise HTTPException(status_code=400, detail="PIN too short")
    kill_switch.set_pin(request.pin)
    return {"success": True, "message": "Kill switch PIN configured"}


@app.post("/api/v1/killswitch/activate")
async def activate_killswitch(request: KillSwitchRequest):
    """Engage the AI kill switch ladder (L1 pause -> L4 full freeze)."""
    result = kill_switch.activate(
        level=request.level, actor="api", reason=request.reason, pin=request.pin
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed"))
    return result


@app.post("/api/v1/killswitch/stand-down")
async def standdown_killswitch(request: Optional[KillSwitchPinRequest] = None):
    """Release the kill switch and resume all autonomous operations."""
    result = kill_switch.stand_down(actor="api", pin=request.pin if request else None)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed"))
    return result


@app.get("/api/v1/killswitch/ledger")
async def get_killswitch_ledger():
    """Get immutable kill switch audit ledger entries."""
    return {"ledger": kill_switch.activation_history}


# ---- Threat Intel NLP ----
@app.get("/api/v1/nlp/status")
async def get_nlp_status():
    """Get threat NLP engine status."""
    return threat_nlp.get_status()


@app.post("/api/v1/nlp/analyze")
async def analyze_threat_text(request: NLPAnalysisRequest):
    """Run full NLP pipeline: IOC extraction, CVSS estimate, MITRE mapping."""
    analysis = threat_nlp.analyze(request.text)
    return {"analysis": analysis}


@app.post("/api/v1/nlp/iocs")
async def extract_iocs_only(request: NLPAnalysisRequest):
    """Extract only indicators of compromise from raw intel text."""
    return {"iocs": threat_nlp.extract_iocs(request.text)}


# ---- Incident Correlation Engine ----
@app.get("/api/v1/incidents/stats")
async def get_incident_stats():
    """Get correlation engine statistics."""
    return incident_correlator.get_stats()


@app.post("/api/v1/incidents/ingest")
async def ingest_security_event(request: CorrelateEventRequest):
    """Ingest a raw security event and receive its incident correlation."""
    details = request.details or {}
    if request.source_ip:
        details["source_ip"] = request.source_ip
    if request.file_path:
        details["file_path"] = request.file_path
    if request.process:
        details["process"] = request.process
    result = incident_correlator.ingest(request.event_type, details)
    if not result.get("accepted"):
        raise HTTPException(status_code=400, detail=result.get("error", "Rejected"))
    return result


@app.get("/api/v1/incidents")
async def list_incidents(status: Optional[str] = None, limit: int = 50):
    """List correlated incidents ranked by attack-chain score."""
    return {"incidents": incident_correlator.get_incidents(status, limit)}


@app.get("/api/v1/incidents/{incident_id}")
async def get_incident_detail(incident_id: int):
    """Get one incident with full narrative timeline."""
    inc = incident_correlator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    view = {k: v for k, v in inc.items() if k != "events"}
    return view


@app.post("/api/v1/incidents/{incident_id}/close")
async def close_incident(incident_id: int, resolution: str = "manual"):
    """Manually close an incident."""
    result = incident_correlator.close(incident_id, resolution)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "Not found"))
    return result


@app.get("/manifest.json")
async def get_manifest():
    """Serve PWA manifest.json for installable web app."""
    manifest = {
        "name": "Sayanox Sentinel OS",
        "short_name": "Sentinel",
        "description": "Autonomous System Security & Threat Mitigation Platform",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0a14",
        "theme_color": "#00ccff",
        "orientation": "any",
        "icons": [
            {
                "src": "/icon-192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "/icon-512.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ]
    }
    return JSONResponse(content=manifest)


@app.get("/service-worker.js")
async def get_service_worker():
    """Serve PWA service worker for offline support."""
    service_worker = """
// Sayanox Sentinel OS Service Worker
const CACHE_NAME = 'sayanox-v1';
const ASSETS = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => {
      return Promise.all(
        names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))
      );
    })
  );
});
"""
    return Response(content=service_worker, media_type="application/javascript")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
