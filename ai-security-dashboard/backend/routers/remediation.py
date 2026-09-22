"""
Autonomous Remediation API Router
Provides endpoints for managing automatic threat response rules
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, Dict, Any, List
from datetime import datetime

from backend.routers.auth import get_current_user, require_role
from backend.services.remediation_engine import remediation_engine, RemediationRule, ThreatSeverity
from backend.middleware.security import limiter

router = APIRouter()


@router.get("/status")
@limiter.limit("30/minute")
async def get_remediation_status(request, current_user: dict = Depends(get_current_user)):
    """Get remediation engine status and statistics"""
    return remediation_engine.get_statistics()


@router.get("/rules")
@limiter.limit("30/minute")
async def get_rules(request, current_user: dict = Depends(get_current_user)):
    """Get all remediation rules with their status"""
    return {"rules": remediation_engine.get_rules_status()}


@router.post("/rules/enable/{rule_id}")
@limiter.limit("10/minute")
async def enable_rule(
    request,
    rule_id: str,
    current_user: dict = Depends(require_role("admin"))
):
    """Enable a specific remediation rule"""
    success = remediation_engine.enable_rule(rule_id)
    
    if success:
        return {"message": f"Rule {rule_id} enabled"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found"
        )


@router.post("/rules/disable/{rule_id}")
@limiter.limit("10/minute")
async def disable_rule(
    request,
    rule_id: str,
    current_user: dict = Depends(require_role("admin"))
):
    """Disable a specific remediation rule"""
    success = remediation_engine.disable_rule(rule_id)
    
    if success:
        return {"message": f"Rule {rule_id} disabled"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found"
        )


@router.post("/rules/add")
@limiter.limit("5/minute")
async def add_rule(
    request,
    rule_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Add a custom remediation rule"""
    try:
        rule = RemediationRule(
            id=rule_data.get("id", f"custom_{datetime.utcnow().timestamp()}"),
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            trigger_conditions=rule_data.get("trigger_conditions", {}),
            actions=rule_data.get("actions", []),
            severity_threshold=rule_data.get("severity_threshold", "HIGH"),
            cooldown_seconds=rule_data.get("cooldown_seconds", 300),
            max_executions=rule_data.get("max_executions", 5)
        )
        
        remediation_engine.add_rule(rule)
        return {"message": f"Rule '{rule.name}' added successfully", "rule_id": rule.id}
        
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required field: {e}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/rules/{rule_id}")
@limiter.limit("5/minute")
async def remove_rule(
    request,
    rule_id: str,
    current_user: dict = Depends(require_role("admin"))
):
    """Remove a remediation rule"""
    success = remediation_engine.remove_rule(rule_id)
    
    if success:
        return {"message": f"Rule {rule_id} removed"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id} not found"
        )


@router.get("/logs")
@limiter.limit("30/minute")
async def get_remediation_logs(
    request,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get remediation execution logs"""
    return {"logs": remediation_engine.get_execution_log(limit=limit)}


@router.post("/evaluate")
@limiter.limit("20/minute")
async def evaluate_threat(
    request,
    threat_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Manually evaluate a threat against remediation rules (for testing)"""
    results = await remediation_engine.evaluate_threat(threat_data)
    
    return {
        "threat_evaluated": threat_data.get("title", "Unknown"),
        "rules_triggered": len(results),
        "results": [
            {
                "success": r.success,
                "action": r.action,
                "target": r.target,
                "message": r.message
            }
            for r in results
        ]
    }
