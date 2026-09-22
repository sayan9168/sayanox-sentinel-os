"""
Threats API Router
Endpoints for security threat management
"""

from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from backend.models.schemas import ThreatAlert, ThreatsResponse

router = APIRouter()


@router.get("/", response_model=ThreatsResponse)
async def get_threats(
    limit: int = Query(default=50, le=500),
    severity: Optional[str] = Query(default=None)
):
    """Get all threat alerts, optionally filtered by severity"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return ThreatsResponse(
            threats=[],
            count=0,
            severity_breakdown={}
        )
    
    threats_data = db_manager.get_threats(limit=limit, severity=severity)
    severity_breakdown = db_manager.get_severity_breakdown()
    
    return ThreatsResponse(
        threats=[ThreatAlert(**t) for t in threats_data],
        count=len(threats_data),
        severity_breakdown=severity_breakdown
    )


@router.get("/critical", response_model=List[ThreatAlert])
async def get_critical_threats(limit: int = 20):
    """Get only critical severity threats"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return []
    
    threats_data = db_manager.get_threats(limit=limit, severity="CRITICAL")
    return [ThreatAlert(**t) for t in threats_data]


@router.get("/recent", response_model=List[ThreatAlert])
async def get_recent_threats(limit: int = 10):
    """Get most recent threats"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return []
    
    threats_data = db_manager.get_threats(limit=limit)
    return [ThreatAlert(**t) for t in threats_data]


@router.get("/stats")
async def get_threat_stats():
    """Get threat statistics and breakdown"""
    from backend.main import connection_manager
    
    db_manager = connection_manager.get("db_manager")
    
    if not db_manager:
        return {
            "total": 0,
            "by_severity": {},
            "by_source": {}
        }
    
    all_threats = db_manager.get_threats(limit=1000)
    severity_breakdown = db_manager.get_severity_breakdown()
    
    # Count by source
    source_counts = {}
    for threat in all_threats:
        source = threat.get("source", "Unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    
    return {
        "total": len(all_threats),
        "by_severity": severity_breakdown,
        "by_source": source_counts,
        "cve_count": sum(1 for t in all_threats if t.get("cve_id"))
    }
