"""
FIM (File Integrity Monitoring) API Router
Provides endpoints for monitoring file system integrity
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, Dict, Any, List
from datetime import datetime

from backend.routers.auth import get_current_user, require_role
from backend.services.fim_service import fim_service
from backend.middleware.security import limiter

router = APIRouter()


@router.get("/status")
@limiter.limit("30/minute")
async def get_fim_status(request, current_user: dict = Depends(get_current_user)):
    """Get FIM service status"""
    return fim_service.get_status()


@router.post("/paths/add")
@limiter.limit("10/minute")
async def add_monitored_path(
    request,
    path_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Add a path to FIM monitoring"""
    path = path_data.get("path")
    recursive = path_data.get("recursive", True)
    
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path is required"
        )
    
    success = fim_service.add_monitored_path(path, recursive=recursive)
    
    if success:
        return {"message": f"Added {path} to monitoring"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to add {path} - path may not exist"
        )


@router.post("/paths/remove")
@limiter.limit("10/minute")
async def remove_monitored_path(
    request,
    path_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Remove a path from FIM monitoring"""
    path = path_data.get("path")
    
    if not path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path is required"
        )
    
    success = fim_service.remove_monitored_path(path)
    
    if success:
        return {"message": f"Removed {path} from monitoring"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Path not found in monitored paths"
        )


@router.get("/alerts")
@limiter.limit("30/minute")
async def get_fim_alerts(
    request,
    limit: int = 100,
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get FIM alerts"""
    return fim_service.get_alerts(limit=limit, alert_type=alert_type, severity=severity)


@router.get("/stats")
@limiter.limit("30/minute")
async def get_fim_stats(request, current_user: dict = Depends(get_current_user)):
    """Get FIM statistics"""
    status = fim_service.get_status()
    alerts = fim_service.get_alerts(limit=100)
    
    # Calculate stats
    by_type = {}
    by_severity = {}
    for alert in alerts:
        atype = alert.get("alert_type", "UNKNOWN")
        asev = alert.get("severity", "UNKNOWN")
        by_type[atype] = by_type.get(atype, 0) + 1
        by_severity[asev] = by_severity.get(asev, 0) + 1
    
    return {
        "running": status["running"],
        "monitored_paths_count": len(status["monitored_paths"]),
        "monitored_files_count": status["monitored_files_count"],
        "total_alerts": len(alerts),
        "by_type": by_type,
        "by_severity": by_severity,
        "recent_alerts": status["recent_alerts"][:5]
    }
