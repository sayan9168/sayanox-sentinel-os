"""
Terminal Control Engine - Full OS Control
Provides secure terminal execution, process management, and firewall controls
"""

import os
import re
import shlex
import subprocess
import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Dangerous command patterns that require admin access
DANGEROUS_PATTERNS = {
    RiskLevel.CRITICAL: [
        r"\brm\s+(-rf?|--recursive)\s+/",  # rm -rf /
        r"\bmkfs\.",                        # Format disk
        r"\bdd\s+",                         # dd command
        r"\bchmod\s+-R\s+777\s+/",          # chmod -R 777 /
        r"\bsudo\s+rm",                     # sudo rm
        r">\s*/etc/",                       # Redirect to /etc/
        r"\breboot\b",                      # Reboot
        r"\bshutdown\b",                    # Shutdown
        r"\bpkill\s+-9\s+",                 # Force kill all
        r"\b:\(\)\{\s*:\|\:&\s*\};:",       # Fork bomb
    ],
    RiskLevel.HIGH: [
        r"\bkill\s+-9",                     # Kill -9
        r"\btaskkill\s+/F",                 # Windows force kill
        r"\biptables\b",                    # Firewall rules
        r"\bnetsh\s+",                      # Windows network config
        r"\buser(add|del|mod)\b",           # User management
        r"\bpasswd\b",                      # Password change
        r"\bsudo\b",                        # Sudo usage
        r"\bvisudo\b",                      # Edit sudoers
        r"\bcurl.*\|\s*(ba)?sh",            # Curl pipe to shell
        r"\bwget.*\|\s*(ba)?sh",            # Wget pipe to shell
    ],
    RiskLevel.MEDIUM: [
        r"\bpsql\s+",                       # Database access
        r"\bmysql\s+",                      # MySQL access
        r"\bmongo\b",                       # MongoDB access
        r"\bredis-cli\b",                   # Redis access
        r"\bdocker\s+(rm|rmi|stop)",        # Docker destructive ops
        r"\bkubectl\s+delete",              # K8s delete
        r"\bgit\s+reset\s+--hard",          # Git hard reset
    ]
}

# Safe commands for viewer role
SAFE_COMMANDS = [
    r"\bls\b", r"\bdir\b", r"\bcat\b", r"\bhead\b", r"\btail\b",
    r"\bgrep\b", r"\bfind\b", r"\bwhich\b", r"\bwhereis\b",
    r"\buname\b", r"\bhostname\b", r"\bwhoami\b", r"\bid\b",
    r"\bdate\b", r"\bcal\b", r"\becho\b", r"\bprintf\b",
    r"\bps\b", r"\btop\b", r"\bhtop\b", r"\bfree\b",
    r"\bdf\b", r"\bdu\b", r"\buptime\b", r"\bw\b",
    r"\bnetstat\b", r"\bss\b", r"\bip\b", r"\bifconfig\b",
    r"\bping\b", r"\btraceroute\b", r"\bdig\b", r"\bnslookup\b",
    r"\bcurl\b", r"\bwget\b", r"\btar\b", r"\bzip\b", r"\bunzip\b",
]


@dataclass
class CommandResult:
    """Result of command execution."""
    command: str
    stdout: str
    stderr: str
    return_code: int
    execution_time_ms: float
    risk_level: str
    timestamp: str


class TerminalEngine:
    """Secure terminal execution engine with command sanitization."""
    
    def __init__(self):
        self.max_execution_time = 30  # seconds
        self.max_output_length = 50000  # characters
    
    def classify_command_risk(self, command: str) -> RiskLevel:
        """Classify command risk level based on patterns."""
        cmd_lower = command.lower()
        
        for risk_level, patterns in DANGEROUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, cmd_lower, re.IGNORECASE):
                    return risk_level
        
        return RiskLevel.LOW
    
    def is_safe_command(self, command: str) -> bool:
        """Check if command is in the safe list."""
        cmd_lower = command.lower()
        for pattern in SAFE_COMMANDS:
            if re.match(pattern, cmd_lower):
                return True
        return False
    
    def sanitize_command(self, command: str) -> Tuple[bool, str]:
        """
        Sanitize and validate command.
        Returns (is_valid, sanitized_command or error_message)
        """
        if not command.strip():
            return False, "Empty command"
        
        # Check for null bytes
        if '\x00' in command:
            return False, "Null bytes not allowed"
        
        # Check for command chaining attempts
        dangerous_chars = [';', '&&', '||', '|', '`', '$(', '${']
        for char in dangerous_chars:
            if char in command and not self.is_safe_command(command):
                # Allow piping for safe commands
                if char in ['|'] and self.is_safe_command(command.split('|')[0].strip()):
                    continue
                return False, f"Command chaining with '{char}' requires admin access"
        
        return True, command
    
    async def execute_command(
        self, 
        command: str, 
        timeout: Optional[int] = None,
        shell: bool = False
    ) -> CommandResult:
        """Execute a shell command securely."""
        start_time = datetime.utcnow()
        risk_level = self.classify_command_risk(command).value
        
        # Validate command
        is_valid, result = self.sanitize_command(command)
        if not is_valid:
            return CommandResult(
                command=command,
                stdout="",
                stderr=result,
                return_code=-1,
                execution_time_ms=0,
                risk_level=risk_level,
                timestamp=start_time.isoformat()
            )
        
        try:
            # Parse command
            if shell:
                args = command
            else:
                args = shlex.split(command)
            
            # Execute with timeout
            timeout = timeout or self.max_execution_time
            
            process = await asyncio.create_subprocess_shell(
                command if shell else args[0] if args else "echo 'No command'",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=shell or len(args) == 1
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                # Decode output
                stdout_str = stdout.decode('utf-8', errors='replace')[:self.max_output_length]
                stderr_str = stderr.decode('utf-8', errors='replace')[:self.max_output_length]
                
                end_time = datetime.utcnow()
                execution_time = (end_time - start_time).total_seconds() * 1000
                
                return CommandResult(
                    command=command,
                    stdout=stdout_str,
                    stderr=stderr_str,
                    return_code=process.returncode or 0,
                    execution_time_ms=execution_time,
                    risk_level=risk_level,
                    timestamp=start_time.isoformat()
                )
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"Command timed out after {timeout} seconds",
                    return_code=-2,
                    execution_time_ms=timeout * 1000,
                    risk_level=risk_level,
                    timestamp=start_time.isoformat()
                )
                
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                execution_time_ms=0,
                risk_level=risk_level,
                timestamp=start_time.isoformat()
            )


class ProcessManager:
    """Process management operations."""
    
    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
        """Get information about a specific process."""
        import psutil
        try:
            proc = psutil.Process(pid)
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "status": proc.status(),
                "username": proc.username(),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_percent": proc.memory_percent(),
                "memory_rss": proc.memory_info().rss,
                "create_time": datetime.fromtimestamp(proc.create_time()).isoformat(),
                "cmdline": " ".join(proc.cmdline()),
                "cwd": proc.cwd(),
                "num_threads": proc.num_threads(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
            logger.error(f"Error getting process info: {e}")
            return None
    
    @staticmethod
    def list_processes(limit: int = 50) -> List[Dict[str, Any]]:
        """List running processes sorted by memory usage."""
        import psutil
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                processes.append({
                    "pid": proc.info['pid'],
                    "name": proc.info['name'] or "unknown",
                    "cpu_percent": proc.info['cpu_percent'] or 0,
                    "memory_percent": proc.info['memory_percent'] or 0,
                    "username": proc.info['username'] or "unknown"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by memory usage and limit
        processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        return processes[:limit]
    
    @staticmethod
    def kill_process(pid: int, force: bool = False) -> Dict[str, Any]:
        """Kill a process by PID."""
        import psutil
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            if force:
                proc.kill()  # SIGKILL
            else:
                proc.terminate()  # SIGTERM
            
            # Wait for process to terminate
            gone, alive = psutil.wait_procs([proc], timeout=5)
            
            return {
                "success": len(gone) > 0,
                "pid": pid,
                "name": proc_name,
                "killed": len(gone) > 0,
                "still_alive": len(alive) > 0,
                "message": f"Process {pid} ({proc_name}) terminated" if len(gone) > 0 else f"Process {pid} still alive"
            }
        except psutil.NoSuchProcess:
            return {"success": False, "pid": pid, "error": "Process not found"}
        except psutil.AccessDenied:
            return {"success": False, "pid": pid, "error": "Access denied"}
        except Exception as e:
            logger.error(f"Error killing process: {e}")
            return {"success": False, "pid": pid, "error": str(e)}
    
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        """Get active network connections."""
        import psutil
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    "family": "IPv4" if conn.family == 2 else "IPv6",
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "local_address": f"{conn.laddr.address}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_address": f"{conn.raddr.address}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                    "process_name": psutil.Process(conn.pid).name() if conn.pid else None
                })
        except (psutil.AccessDenied, Exception) as e:
            logger.error(f"Error getting network connections: {e}")
        
        return connections


class FirewallManager:
    """Firewall rule management for Linux (iptables) and Windows (netsh)."""
    
    def __init__(self):
        self.is_linux = os.uname().sysname == "Linux" if hasattr(os, 'uname') else False
        self.is_windows = os.name == 'nt'
    
    def block_ip(self, ip_address: str, port: Optional[int] = None) -> CommandResult:
        """Block an IP address via firewall."""
        if self.is_linux:
            if port:
                cmd = f"iptables -A INPUT -s {ip_address} -p tcp --dport {port} -j DROP"
            else:
                cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
        elif self.is_windows:
            if port:
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}_{port}" dir=in action=block remoteip={ip_address}'
            else:
                cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address}'
        else:
            return CommandResult(
                command=f"block_ip {ip_address}",
                stdout="",
                stderr="Unsupported operating system for firewall management",
                return_code=-1,
                execution_time_ms=0,
                risk_level=RiskLevel.HIGH.value,
                timestamp=datetime.utcnow().isoformat()
            )
        
        # Execute using terminal engine
        engine = TerminalEngine()
        return asyncio.run(engine.execute_command(cmd, shell=True))
    
    def unblock_ip(self, ip_address: str, port: Optional[int] = None) -> CommandResult:
        """Unblock an IP address via firewall."""
        if self.is_linux:
            if port:
                cmd = f"iptables -D INPUT -s {ip_address} -p tcp --dport {port} -j DROP"
            else:
                cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
        elif self.is_windows:
            if port:
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip_address}_{port}"'
            else:
                cmd = f'netsh advfirewall firewall delete rule name="Block_{ip_address}"'
        else:
            return CommandResult(
                command=f"unblock_ip {ip_address}",
                stdout="",
                stderr="Unsupported operating system for firewall management",
                return_code=-1,
                execution_time_ms=0,
                risk_level=RiskLevel.HIGH.value,
                timestamp=datetime.utcnow().isoformat()
            )
        
        engine = TerminalEngine()
        return asyncio.run(engine.execute_command(cmd, shell=True))
    
    def list_firewall_rules(self) -> CommandResult:
        """List current firewall rules."""
        if self.is_linux:
            cmd = "iptables -L -n -v"
        elif self.is_windows:
            cmd = "netsh advfirewall firewall show rule name=all"
        else:
            return CommandResult(
                command="list_firewall_rules",
                stdout="",
                stderr="Unsupported operating system for firewall management",
                return_code=-1,
                execution_time_ms=0,
                risk_level=RiskLevel.LOW.value,
                timestamp=datetime.utcnow().isoformat()
            )
        
        engine = TerminalEngine()
        return asyncio.run(engine.execute_command(cmd, shell=True))


# Singleton instances
terminal_engine = TerminalEngine()
process_manager = ProcessManager()
firewall_manager = FirewallManager()
