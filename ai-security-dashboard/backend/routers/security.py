"""
Sayanox Sentinel OS - ML Anomaly Detection & Network Security Router
Endpoints for anomaly detection, honeypot, and network scanning.
"""

from fastapi import APIRouter, HTTPException, Depends, WebSocket, WebSocketDisconnect
from typing import Dict, List, Optional
from datetime import datetime

from backend.services.anomaly_detection import anomaly_detector, background_training_loop, background_metrics_feeder
from backend.services.honeypot_service import honeypot_service, setup_honeypot_with_firewall
from backend.services.network_scanner import network_sniffer, nmap_scanner, analyze_packet_for_threats

router = APIRouter()


# ==================== ANOMALY DETECTION ENDPOINTS ====================

@router.get("/anomaly/status")
async def get_anomaly_status():
    """Get ML anomaly detection status and training progress."""
    return {
        "status": "active",
        "training": anomaly_detector.get_training_status(),
        "recent_anomalies": anomaly_detector.get_anomaly_history(limit=10),
        "baseline_stats": anomaly_detector.get_baseline_stats()
    }


@router.get("/anomaly/history")
async def get_anomaly_history(limit: int = 50):
    """Get anomaly detection history."""
    return {
        "anomalies": anomaly_detector.get_anomaly_history(limit),
        "total_count": len(anomaly_detector.anomaly_history)
    }


@router.post("/anomaly/reset")
async def reset_anomaly_model():
    """Reset and retrain the anomaly detection model."""
    success = anomaly_detector.reset_model()
    if success:
        return {"status": "success", "message": "Model reset and retraining initiated"}
    else:
        raise HTTPException(status_code=500, detail="Failed to reset model")


@router.post("/anomaly/detect")
async def detect_anomaly(metrics: Dict):
    """Manually trigger anomaly detection on provided metrics."""
    is_anomaly, score, details = anomaly_detector.detect_anomaly(metrics)
    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": score,
        "details": details,
        "timestamp": datetime.now().isoformat()
    }


# ==================== HONEYPOT ENDPOINTS ====================

@router.get("/honeypot/status")
async def get_honeypot_status():
    """Get honeypot service status."""
    return honeypot_service.get_stats()


@router.get("/honeypot/connections")
async def get_honeypot_connections(limit: int = 50):
    """Get recent honeypot connection attempts."""
    return {
        "connections": honeypot_service.get_connection_history(limit),
        "blocked_ips": honeypot_service.get_blocked_ips()
    }


@router.post("/honeypot/start")
async def start_honeypot(ports: Optional[List[int]] = None):
    """Start the honeypot service."""
    try:
        if ports:
            for port in ports:
                honeypot_service.add_decoy_port(port)
        
        if not honeypot_service.is_running:
            honeypot_service.start()
        
        return {"status": "success", "message": "Honeypot started", "ports": honeypot_service.decoy_ports}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/honeypot/stop")
async def stop_honeypot():
    """Stop the honeypot service."""
    honeypot_service.stop()
    return {"status": "success", "message": "Honeypot stopped"}


@router.post("/honeypot/port/add")
async def add_decoy_port(port: int):
    """Add a decoy port to monitor."""
    success = honeypot_service.add_decoy_port(port)
    if success:
        return {"status": "success", "message": f"Port {port} added to honeypot"}
    else:
        raise HTTPException(status_code=400, detail="Port already configured")


@router.delete("/honeypot/port/remove")
async def remove_decoy_port(port: int):
    """Remove a decoy port from monitoring."""
    success = honeypot_service.remove_decoy_port(port)
    if success:
        return {"status": "success", "message": f"Port {port} removed from honeypot"}
    else:
        raise HTTPException(status_code=400, detail="Port not found")


@router.post("/honeypot/clear")
async def clear_honeypot_history():
    """Clear honeypot connection history."""
    honeypot_service.clear_history()
    return {"status": "success", "message": "Honeypot history cleared"}


# ==================== NETWORK SNIFFER ENDPOINTS ====================

@router.get("/sniffer/status")
async def get_sniffer_status():
    """Get network sniffer status."""
    return network_sniffer.get_stats()


@router.get("/sniffer/packets")
async def get_captured_packets(
    limit: int = 100,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None
):
    """Get recently captured packets with optional filtering."""
    return {
        "packets": network_sniffer.get_recent_packets(
            limit=limit,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    }


@router.post("/sniffer/start")
async def start_sniffer(interface: Optional[str] = None, count: int = 0):
    """Start packet sniffing."""
    success = network_sniffer.start_sniffing(interface=interface, count=count)
    if success:
        return {"status": "success", "message": "Packet sniffing started"}
    else:
        raise HTTPException(status_code=500, detail="Failed to start sniffer. Ensure CAP_NET_RAW capability.")


@router.post("/sniffer/stop")
async def stop_sniffer():
    """Stop packet sniffing."""
    network_sniffer.stop_sniffing()
    return {"status": "success", "message": "Packet sniffing stopped"}


@router.post("/sniffer/clear")
async def clear_packet_history():
    """Clear captured packet history."""
    network_sniffer.clear_history()
    return {"status": "success", "message": "Packet history cleared"}


@router.websocket("/ws/sniffer")
async def websocket_sniffer(websocket: WebSocket):
    """WebSocket endpoint for real-time packet streaming."""
    await websocket.accept()
    
    async def packet_callback(packet):
        try:
            await websocket.send_json(packet.to_dict())
        except:
            pass
    
    network_sniffer.add_packet_callback(packet_callback)
    
    try:
        while True:
            data = await websocket.receive_text()
            if data == "start":
                network_sniffer.start_sniffing()
            elif data == "stop":
                network_sniffer.stop_sniffing()
            elif data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        network_sniffer.remove_packet_callback(packet_callback)


# ==================== NMAP SCANNER ENDPOINTS ====================

@router.get("/nmap/status")
async def get_nmap_status():
    """Get Nmap scanner status."""
    return nmap_scanner.get_stats()


@router.post("/nmap/scan")
async def perform_scan(
    host: str,
    ports: str = "1-1024",
    arguments: str = "-sV -sC"
):
    """Perform an Nmap scan on a target host."""
    result = await nmap_scanner.scan_host(host, ports, arguments)
    
    if 'error' in result and result['error'] == 'Nmap not available':
        raise HTTPException(status_code=503, detail="Nmap scanner not available")
    
    return result


@router.post("/nmap/scan/quick")
async def perform_quick_scan(host: str):
    """Perform a quick Nmap scan of common ports."""
    return await nmap_scanner.quick_scan(host)


@router.post("/nmap/scan/full")
async def perform_full_scan(host: str):
    """Perform a comprehensive Nmap scan."""
    return await nmap_scanner.full_scan(host)


@router.get("/nmap/history")
async def get_scan_history(limit: int = 20):
    """Get recent Nmap scan results."""
    return {
        "scans": nmap_scanner.get_scan_history(limit)
    }


@router.get("/nmap/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get a specific scan result by ID."""
    result = nmap_scanner.get_scan_result(scan_id)
    if result:
        return result
    else:
        raise HTTPException(status_code=404, detail="Scan result not found")


# ==================== THREAT ANALYSIS ENDPOINTS ====================

@router.post("/analyze/packet")
async def analyze_packet(packet_data: Dict):
    """Analyze a packet for potential threats."""
    # Create a mock packet for analysis
    from backend.services.network_scanner import CapturedPacket
    from datetime import datetime
    
    packet = CapturedPacket(
        timestamp=datetime.now(),
        src_ip=packet_data.get('src_ip', '0.0.0.0'),
        dst_ip=packet_data.get('dst_ip', '0.0.0.0'),
        src_port=packet_data.get('src_port', 0),
        dst_port=packet_data.get('dst_port', 0),
        protocol=packet_data.get('protocol', 'TCP'),
        size=packet_data.get('size', 0),
        payload=bytes.fromhex(packet_data.get('payload', '')) if packet_data.get('payload') else b""
    )
    
    threats = await analyze_packet_for_threats(packet)
    return {
        "threats_found": len(threats) > 0,
        "threats": threats,
        "packet": packet.to_dict()
    }
