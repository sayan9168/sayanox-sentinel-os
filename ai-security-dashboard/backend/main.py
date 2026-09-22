"""
AI-Powered System Resource & Security Intelligence Dashboard
Backend Main Application - FastAPI with WebSocket streaming
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
from backend.routers import metrics, threats, skills

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global state
connection_manager = {
    "active_connections": [],
    "metrics_history": [],
    "scraper_running": False
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
    
    yield
    
    # Shutdown
    logger.info("Shutting down services...")
    collector_task.cancel()
    scraper_task.cancel()
    try:
        await collector_task
        await scraper_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="AI Security Intelligence Dashboard",
    description="Real-time system monitoring and threat detection dashboard",
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

# Include routers
app.include_router(metrics.router, prefix="/api/v1/metrics", tags=["metrics"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(skills.router, prefix="/api/v1/skills", tags=["skills"])


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
    return {"status": "online", "service": "AI Security Intelligence Dashboard"}


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_connections": len(connection_manager["active_connections"]),
        "scraper_active": connection_manager.get("scraper_running", False)
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
