"""
System Control API Router
Terminal execution, process management, network control, and firewall rules
"""

import uuid
from fastapi import APIRouter, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from typing import Optional, Dict, Any
import json
import asyncio

from backend.routers.auth import get_current_user, require_role
from backend.middleware.security import (
    validate_command, sanitize_command, audit_logger, limiter
)
from backend.services.system_control import system_controller

router = APIRouter()

# Active terminal sessions
terminal_sessions: Dict[str, dict] = {}


@router.post("/terminal/create")
@limiter.limit("10/minute")
async def create_terminal_session(
    request,
    current_user: dict = Depends(require_role("admin"))
):
    """Create a new interactive terminal session (admin only)"""
    session_id = str(uuid.uuid4())[:8]
    
    session = system_controller.create_pty_session(session_id, current_user["username"])
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create terminal session"
        )
    
    terminal_sessions[session_id] = {
        "session": session,
        "user": current_user["username"]
    }
    
    audit_logger.log_event(
        event_type="TERMINAL_SESSION",
        user=current_user["username"],
        action="SESSION_CREATED",
        details={"session_id": session_id}
    )
    
    return {
        "session_id": session_id,
        "message": "Terminal session created"
    }


@router.websocket("/ws/terminal/{session_id}")
async def terminal_websocket(websocket: WebSocket, session_id: str):
    """WebSocket for interactive terminal communication"""
    await websocket.accept()
    
    session_data = terminal_sessions.get(session_id)
    if not session_data:
        await websocket.send_json({"error": "Session not found"})
        await websocket.close()
        return
    
    try:
        while True:
            # Receive data from client
            data = await websocket.receive_text()
            message = json.loads(data)
            
            msg_type = message.get("type")
            
            if msg_type == "input":
                # Send input to terminal
                command = message.get("data", "")
                system_controller.write_to_session(session_id, command)
                
            elif msg_type == "resize":
                # Resize terminal
                rows = message.get("rows", 24)
                cols = message.get("cols", 80)
                system_controller.resize_session(session_id, rows, cols)
            
            elif msg_type == "close":
                # Close session
                system_controller.close_session(session_id)
                terminal_sessions.pop(session_id, None)
                break
            
            # Read output from terminal
            output = system_controller.read_from_session(session_id)
            if output:
                await websocket.send_json({
                    "type": "output",
                    "data": output
                })
                
    except WebSocketDisconnect:
        # Clean up on disconnect
        system_controller.close_session(session_id)
        terminal_sessions.pop(session_id, None)


@router.post("/terminal/{session_id}/close")
async def close_terminal_session(
    session_id: str,
    current_user: dict = Depends(require_role("admin"))
):
    """Close a terminal session"""
    if session_id in terminal_sessions:
        system_controller.close_session(session_id)
        terminal_sessions.pop(session_id, None)
        return {"message": f"Session {session_id} closed"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Session not found"
    )


@router.post("/command/execute")
@limiter.limit("30/minute")
async def execute_command(
    request,
    command_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """
    Execute a shell command with validation
    Requires admin role for dangerous commands
    """
    command = command_data.get("command", "")
    timeout = command_data.get("timeout", 30)
    
    # Validate command
    is_valid, error_msg = validate_command(command, current_user["role"])
    if not is_valid:
        audit_logger.log_event(
            event_type="COMMAND_BLOCKED",
            user=current_user["username"],
            action="COMMAND_VALIDATION_FAILED",
            details={"command": command[:100], "reason": error_msg}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg
        )
    
    # Sanitize and execute
    sanitized_command = sanitize_command(command)
    success, stdout, stderr = await system_controller.execute_command(
        sanitized_command, 
        timeout=timeout
    )
    
    # Log execution
    audit_logger.log_command_execution(
        user=current_user["username"],
        command=sanitized_command,
        success=success,
        output_length=len(stdout) + len(stderr)
    )
    
    return {
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "command": sanitized_command
    }


@router.post("/process/kill")
async def kill_process(
    request,
    process_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Kill a process by PID (admin only)"""
    pid = process_data.get("pid")
    force = process_data.get("force", False)
    
    if not pid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PID is required"
        )
    
    success, message = await system_controller.kill_process(pid, force)
    
    if success:
        # Get process name for logging
        proc_info = await system_controller.get_process_info(pid)
        process_name = proc_info.get("name", "unknown") if isinstance(proc_info, dict) else "unknown"
        
        audit_logger.log_process_kill(
            user=current_user["username"],
            pid=pid,
            process_name=process_name
        )
    
    return {"success": success, "message": message}


@router.get("/process/list")
@limiter.limit("30/minute")
async def list_processes(request, current_user: dict = Depends(get_current_user)):
    """List all running processes"""
    result = await system_controller.get_process_info()
    return result


@router.get("/process/{pid}")
@limiter.limit("60/minute")
async def get_process_info(request, pid: int, current_user: dict = Depends(get_current_user)):
    """Get detailed information about a specific process"""
    result = await system_controller.get_process_info(pid)
    
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"]
        )
    
    return result


@router.get("/network/connections")
@limiter.limit("30/minute")
async def get_network_connections(request, current_user: dict = Depends(get_current_user)):
    """Get current network connections"""
    result = await system_controller.get_network_connections()
    return result


@router.get("/network/ports")
@limiter.limit("30/minute")
async def get_open_ports(request, current_user: dict = Depends(get_current_user)):
    """Get list of open/listening ports"""
    result = await system_controller.get_open_ports()
    return result


@router.post("/firewall/block")
async def block_ip(
    request,
    ip_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Block an IP address using firewall rules (admin only)"""
    ip_address = ip_data.get("ip")
    reason = ip_data.get("reason", "Security threat")
    
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address is required"
        )
    
    success, message = await system_controller.block_ip(ip_address, reason)
    
    if success:
        audit_logger.log_ip_block(
            user=current_user["username"],
            ip_address=ip_address,
            reason=reason
        )
    
    return {"success": success, "message": message}


@router.post("/firewall/unblock")
async def unblock_ip(
    request,
    ip_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Unblock an IP address (admin only)"""
    ip_address = ip_data.get("ip")
    
    if not ip_address:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IP address is required"
        )
    
    success, message = await system_controller.unblock_ip(ip_address)
    return {"success": success, "message": message}
