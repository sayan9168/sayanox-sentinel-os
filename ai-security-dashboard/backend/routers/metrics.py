"""
Metrics API Router
Endpoints for system metrics retrieval
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict
from datetime import datetime

from backend.models.schemas import SystemMetrics, MetricsHistoryResponse

router = APIRouter()


@router.get("/current", response_model=SystemMetrics)
async def get_current_metrics():
    """Get current system metrics snapshot"""
    # This will be populated by WebSocket in real-time
    # For REST fallback, return latest from history
    from backend.main import connection_manager
    
    if connection_manager["metrics_history"]:
        latest = connection_manager["metrics_history"][-1]
        return SystemMetrics(**latest)
    
    # Return default if no data
    return SystemMetrics(
        cpu_percent=0.0,
        memory_percent=0.0,
        memory_used=0,
        memory_total=0,
        disk_percent=0.0,
        network_sent=0,
        network_recv=0,
        process_count=0
    )


@router.get("/history", response_model=MetricsHistoryResponse)
async def get_metrics_history(hours: int = 24, limit: int = 100):
    """Get historical metrics data"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if db_manager:
        data = db_manager.get_metrics_history(hours=hours, limit=limit)
        
        if not data:
            # Fallback to in-memory history
            data = connection_manager["metrics_history"][-limit:]
        
        time_range = {
            "start": data[0]["timestamp"] if data else datetime.utcnow().isoformat(),
            "end": data[-1]["timestamp"] if data else datetime.utcnow().isoformat()
        }
        
        return MetricsHistoryResponse(
            data=[SystemMetrics(**m) for m in data],
            count=len(data),
            time_range=time_range
        )
    
    # Fallback to in-memory only
    data = connection_manager["metrics_history"][-limit:]
    return MetricsHistoryResponse(
        data=[SystemMetrics(**m) for m in data] if data else [],
        count=len(data),
        time_range={"start": "", "end": ""}
    )


@router.get("/summary")
async def get_metrics_summary():
    """Get aggregated metrics summary"""
    from backend.main import connection_manager
    
    history = connection_manager["metrics_history"]
    
    if not history:
        return {
            "cpu_avg": 0.0,
            "memory_avg": 0.0,
            "disk_avg": 0.0,
            "samples": 0
        }
    
    recent = history[-50:]  # Last 50 samples
    
    return {
        "cpu_avg": round(sum(m["cpu_percent"] for m in recent) / len(recent), 2),
        "memory_avg": round(sum(m["memory_percent"] for m in recent) / len(recent), 2),
        "disk_avg": round(sum(m["disk_percent"] for m in recent) / len(recent), 2),
        "samples": len(recent),
        "peak_cpu": max(m["cpu_percent"] for m in recent),
        "peak_memory": max(m["memory_percent"] for m in recent)
    }
