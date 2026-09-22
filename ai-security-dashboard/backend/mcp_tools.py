"""
MCP (Model Context Protocol) Tool Wrappers
Provides standardized interfaces for terminal system checks and automation
"""

import asyncio
import json
import logging
import os
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MCPToolWrapper:
    """Model Context Protocol wrapper for system tools."""
    
    def __init__(self):
        self.tools = {
            "system_check": self.system_check,
            "network_scan": self.network_scan,
            "process_list": self.process_list,
            "disk_analysis": self.disk_analysis,
            "security_audit": self.security_audit
        }
    
    async def execute_tool(self, tool_name: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute a named tool with given parameters."""
        if tool_name not in self.tools:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "available_tools": list(self.tools.keys())
            }
        
        try:
            result = await self.tools[tool_name](params or {})
            return {
                "success": True,
                "tool": tool_name,
                "timestamp": datetime.utcnow().isoformat(),
                "data": result
            }
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def system_check(self, params: Dict) -> Dict[str, Any]:
        """Perform basic system health check."""
        import psutil
        
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        
        return {
            "cpu_usage_percent": cpu_percent,
            "memory_usage_percent": memory.percent,
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "disk_usage_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 2),
            "network_sent_mb": round(net.bytes_sent / (1024**2), 2),
            "network_recv_mb": round(net.bytes_recv / (1024**2), 2),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "status": "healthy" if cpu_percent < 80 and memory.percent < 80 else "warning"
        }
    
    async def network_scan(self, params: Dict) -> Dict[str, Any]:
        """Scan network connections."""
        import psutil
        
        connections = psutil.net_connections(kind='inet')
        
        active_connections = []
        for conn in connections[:20]:  # Limit to 20
            active_connections.append({
                "family": "IPv4" if conn.family == 2 else "IPv6",
                "type": "TCP" if conn.type == 1 else "UDP",
                "local_address": f"{conn.laddr.address}:{conn.laddr.port}" if conn.laddr else "N/A",
                "remote_address": f"{conn.raddr.address}:{conn.raddr.port}" if conn.raddr else "N/A",
                "status": conn.status,
                "pid": conn.pid
            })
        
        return {
            "total_connections": len(connections),
            "active_connections": active_connections,
            "listening_ports": len([c for c in connections if c.status == 'LISTEN'])
        }
    
    async def process_list(self, params: Dict) -> Dict[str, Any]:
        """List running processes."""
        import psutil
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent'])[:30]:
            try:
                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "cpu_percent": proc.info['cpu_percent'] or 0,
                    "memory_percent": proc.info['memory_percent'] or 0
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return {
            "total_processes": len(list(psutil.process_iter())),
            "top_processes": sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:10]
        }
    
    async def disk_analysis(self, params: Dict) -> Dict[str, Any]:
        """Analyze disk usage."""
        import psutil
        
        partitions = psutil.disk_partitions()
        disk_info = []
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "filesystem": partition.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "percent_used": usage.percent
                })
            except PermissionError:
                continue
        
        return {
            "partitions": disk_info,
            "io_counters": {
                "read_count": psutil.disk_io_counters().read_count if psutil.disk_io_counters() else 0,
                "write_count": psutil.disk_io_counters().write_count if psutil.disk_io_counters() else 0,
                "read_bytes_mb": round(psutil.disk_io_counters().read_bytes / (1024**2), 2) if psutil.disk_io_counters() else 0,
                "write_bytes_mb": round(psutil.disk_io_counters().write_bytes / (1024**2), 2) if psutil.disk_io_counters() else 0
            }
        }
    
    async def security_audit(self, params: Dict) -> Dict[str, Any]:
        """Perform basic security audit checks."""
        import psutil
        
        findings = []
        risk_level = "low"
        
        # Check for processes running as root
        root_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                if proc.info['username'] == 'root':
                    root_processes.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if len(root_processes) > 20:
            findings.append({
                "type": "info",
                "message": f"High number of root processes: {len(root_processes)}",
                "recommendation": "Review unnecessary root processes"
            })
        
        # Check for listening ports
        connections = psutil.net_connections(kind='inet')
        listening_ports = [c for c in connections if c.status == 'LISTEN']
        
        common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL"}
        open_common_ports = []
        
        for conn in listening_ports:
            if conn.laddr and conn.laddr.port in common_ports:
                open_common_ports.append({
                    "port": conn.laddr.port,
                    "service": common_ports[conn.laddr.port],
                    "address": conn.laddr.address
                })
        
        if open_common_ports:
            findings.append({
                "type": "info",
                "message": f"Common service ports detected: {len(open_common_ports)}",
                "details": open_common_ports,
                "recommendation": "Ensure these services are properly secured"
            })
        
        # Determine overall risk level
        if len(findings) > 3:
            risk_level = "medium"
        
        return {
            "risk_level": risk_level,
            "findings_count": len(findings),
            "findings": findings,
            "root_processes_count": len(root_processes),
            "listening_ports_count": len(listening_ports),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Return schema for all available tools."""
        return [
            {
                "name": "system_check",
                "description": "Perform basic system health check including CPU, memory, disk, and network metrics",
                "parameters": {}
            },
            {
                "name": "network_scan",
                "description": "Scan active network connections and listening ports",
                "parameters": {}
            },
            {
                "name": "process_list",
                "description": "List running processes with resource usage",
                "parameters": {"limit": "Maximum number of processes to return (default: 30)"}
            },
            {
                "name": "disk_analysis",
                "description": "Analyze disk usage across all partitions",
                "parameters": {}
            },
            {
                "name": "security_audit",
                "description": "Perform basic security audit checks",
                "parameters": {}
            }
        ]


# Singleton instance
mcp_wrapper = MCPToolWrapper()


async def main():
    """Test MCP tools."""
    print("Available MCP Tools:")
    for tool in mcp_wrapper.get_tools_schema():
        print(f"  - {tool['name']}: {tool['description']}")
    
    print("\nRunning system_check...")
    result = await mcp_wrapper.execute_tool("system_check")
    print(json.dumps(result, indent=2))
    
    print("\nRunning security_audit...")
    result = await mcp_wrapper.execute_tool("security_audit")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
