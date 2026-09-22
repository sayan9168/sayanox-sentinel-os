"""
AI-Powered System Resource & Security Intelligence Dashboard
Enterprise-Grade Autonomous PC Operations Suite
Backend Main Application - FastAPI with WebSocket streaming, JWT auth, and system control
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
from backend.routers import metrics, threats, skills, auth, system, browser, notifications
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
    logger.info("Initializing database and services...")
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
    
    # Configure default notifications (can be overridden via API)
    configure_notifications(
        channels=["discord"]  # Default to discord if configured
    )
    
    logger.info("Services initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down services...")
    
    # Cancel background tasks
    collector_task.cancel()
    scraper_task.cancel()
    try:
        await collector_task
        await scraper_task
    except asyncio.CancelledError:
        pass
    
    # Close browser automation
    await browser_automation.stop()
    
    # Close notification service
    await notification_service.close()
    
    # Clean up terminal sessions
    for session_id in list(connection_manager.get("terminal_sessions", {}).keys()):
        system_controller.close_session(session_id)


app = FastAPI(
    title="Autonomous PC Operations & Security Intelligence Suite",
    description="""
## Enterprise-Grade AI Security Dashboard

Full-stack autonomous system with:
- **Real-time system monitoring** via WebSockets
- **Interactive web terminal** for remote CLI access
- **Process management** with kill capabilities
- **Network/firewall control** for IP blocking
- **Browser automation** for screenshots and web interaction
- **Multi-channel alerts** (Telegram, Discord, Slack)
- **JWT authentication** with RBAC (Admin/Viewer roles)
- **Audit logging** for all security events

### Default Credentials
- Admin: `admin` / `admin123`
- Viewer: `viewer` / `viewer123`
    """,
    version="2.0.0",
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
        "service": "Autonomous PC Operations & Security Intelligence Suite",
        "version": "2.0.0"
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
            "metrics_collector": not connection_manager.get("collector_task", None) is None,
            "threat_scraper": not connection_manager.get("scraper_task", None) is None,
            "database": connection_manager.get("db_manager") is not None
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
