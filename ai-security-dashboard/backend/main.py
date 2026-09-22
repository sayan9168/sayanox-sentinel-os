"""
Sayanox Sentinel OS - Autonomous System Security, PC Operations & Threat Mitigation Platform
Enterprise-Grade Full-Stack Security Suite with AI-Powered Remediation
Backend Main Application - FastAPI with WebSocket streaming, JWT auth, FIM, and autonomous remediation
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import psutil
import uvicorn

from backend.models.schemas import SystemMetrics, ThreatAlert, SkillLog
from backend.services.metrics_collector import MetricsCollector
from backend.services.threat_scraper import ThreatScraper
from backend.services.database import DatabaseManager
from backend.services.system_control import system_controller
from backend.services.browser_automation import browser_automation
from backend.services.notification_service import notification_service, configure_notifications
from backend.services.fim_service import fim_service, configure_fim
from backend.services.remediation_engine import remediation_engine, configure_remediation
from backend.services.backup_service import backup_service, configure_backup
from backend.services.anomaly_detection import anomaly_detector, background_training_loop
from backend.services.honeypot_service import honeypot_service, setup_honeypot_with_firewall
from backend.services.network_scanner import network_sniffer, nmap_scanner
from backend.routers import metrics, threats, skills, auth, system, browser, notifications, fim, remediation, backup, security
from backend.middleware.security import limiter, rate_limit_exceeded_handler, audit_logger

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state
connection_manager = {
    "active_connections": [],
    "metrics_history": [],
    "scraper_running": False,
    "terminal_sessions": {}
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events"""
    # Startup
    logger.info("[Sayanox Sentinel OS] Initializing database and services...")
    db_manager = DatabaseManager()
    db_manager.initialize()
    
    # Start background metrics collector
    collector = MetricsCollector(connection_manager)
    collector_task = asyncio.create_task(collector.start_collection())
    
    # Start threat scraper
    scraper = ThreatScraper(db_manager)
    scraper_task = asyncio.create_task(scraper.start_scraping())
    
    connection_manager["collector_task"] = collector_task
    connection_manager["scraper_task"] = scraper_task
    connection_manager["db_manager"] = db_manager
    
    # Configure FIM (File Integrity Monitoring)
    configure_fim(
        db_manager=db_manager,
        notification_service=notification_service,
        critical_paths=["/etc", "/usr/bin", "./backend", "./frontend"]
    )
    
    # Configure Remediation Engine
    configure_remediation(
        system_controller=system_controller,
        notification_service=notification_service,
        db_manager=db_manager
    )
    
    # Configure Backup Service
    configure_backup(backup_dir="./backup")
    
    # Configure default notifications (can be overridden via API)
    configure_notifications(
        channels=["discord"]  # Default to discord if configured
    )
    
    # Start honeypot service with firewall integration
    async def firewall_block_callback(ip: str, reason: str):
        """Callback to block IPs from honeypot triggers."""
        try:
            await system_controller.block_ip(ip, f"Honeypot trigger: {reason}")
        except Exception as e:
            logger.error(f"Failed to block IP from honeypot: {e}")
    
    await setup_honeypot_with_firewall(firewall_block_callback)
    honeypot_service.start()
    
    logger.info("[Sayanox Sentinel OS] Services initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("[Sayanox Sentinel OS] Shutting down services...")
    
    # Cancel background tasks
    collector_task.cancel()
    scraper_task.cancel()
    try:
        await collector_task
        await scraper_task
    except asyncio.CancelledError:
        pass
    
    # Stop FIM
    fim_service.stop()
    
    # Stop honeypot
    honeypot_service.stop()
    
    # Stop network sniffer
    network_sniffer.stop_sniffing()
    
    # Close browser automation
    await browser_automation.stop()
    
    # Close notification service
    await notification_service.close()
    
    # Clean up terminal sessions
    for session_id in list(connection_manager.get("terminal_sessions", {}).keys()):
        system_controller.close_session(session_id)


app = FastAPI(
    title="Sayanox Sentinel OS",
    description="""
## Sayanox Sentinel OS - Autonomous System Security & Threat Mitigation Platform

Enterprise-grade full-stack security suite with AI-powered autonomous capabilities:

### Core Features
- **Real-time system monitoring** via WebSockets (CPU, RAM, Disk, Network, Processes)
- **Interactive web terminal** for remote CLI access (Xterm.js powered)
- **Process management** with kill capabilities and network inspection
- **Network/firewall control** for IP blocking (iptables/netsh integration)
- **Browser automation** using Playwright for screenshots and web interaction
- **Multi-channel alerts** via Telegram, Discord, and Slack webhooks
- **JWT authentication** with RBAC (Admin/Viewer roles)
- **Audit logging** for all security events in SQLite + ChromaDB
- **File Integrity Monitoring (FIM)** for critical files using watchdog/inotify
- **Autonomous Remediation Engine** for automatic threat response
- **Backup & Sync** with cloud support (S3, GCS, Azure, SFTP)
- **Remote GUI Streaming** via HTML5 canvas/VNC integration

### Security Features
- Rate limiting on sensitive endpoints
- Command sanitization for OS-level operations
- Encrypted backup compression
- Persistent skill memory for learned threat patterns

### Default Credentials
- Admin: `admin` / `admin123` (Full terminal access, process killing, firewall edit)
- Viewer: `viewer` / `viewer123` (Metrics & threat tables only)
    """,
    version="3.0.0",
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

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(429, rate_limit_exceeded_handler)

# Include routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(metrics.router, prefix="/api/v1/metrics", tags=["metrics"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(skills.router, prefix="/api/v1/skills", tags=["skills"])
app.include_router(system.router, prefix="/api/v1/system", tags=["system-control"])
app.include_router(browser.router, prefix="/api/v1/browser", tags=["browser-automation"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["notifications"])
app.include_router(security.router, prefix="/api/v1/security", tags=["security-ml"])


@app.websocket("/ws/metrics")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics streaming"""
    await websocket.accept()
    connection_manager["active_connections"].append(websocket)
    
    try:
        while True:
            # Keep connection alive, client will receive broadcasts
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        connection_manager["active_connections"].remove(websocket)
        logger.info(f"Client disconnected. Active connections: {len(connection_manager['active_connections'])}")


async def broadcast_metrics(metrics: Dict):
    """Broadcast metrics to all connected WebSocket clients"""
    if connection_manager["active_connections"]:
        message = json.dumps(metrics)
        disconnected = []
        
        for connection in connection_manager["active_connections"]:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            if conn in connection_manager["active_connections"]:
                connection_manager["active_connections"].remove(conn)


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "status": "online",
        "service": "Sayanox Sentinel OS - Autonomous System Security & Threat Mitigation Platform",
        "version": "3.0.0"
    }


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_connections": len(connection_manager["active_connections"]),
        "scraper_active": connection_manager.get("scraper_running", False),
        "services": {
            "metrics_collector": connection_manager.get("collector_task") is not None,
            "threat_scraper": connection_manager.get("scraper_task") is not None,
            "database": connection_manager.get("db_manager") is not None,
            "fim_service": fim_service.is_running(),
            "remediation_engine": remediation_engine.is_enabled(),
            "backup_service": backup_service.is_configured()
        }
    }


@app.get("/api/v1/status")
async def system_status():
    """Get comprehensive system status"""
    return {
        "system": {
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "process_count": len(psutil.pids())
        },
        "application": {
            "active_websocket_connections": len(connection_manager["active_connections"]),
            "metrics_in_history": len(connection_manager["metrics_history"]),
            "terminal_sessions": len(connection_manager.get("terminal_sessions", {}))
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
