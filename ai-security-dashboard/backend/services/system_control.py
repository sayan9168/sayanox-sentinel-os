"""
System Control Service
Terminal execution, process management, network control, and firewall rules
"""

import asyncio
import subprocess
import os
import signal
import platform
import logging
import pty
import select
import struct
import fcntl
import termios
from typing import Optional, Dict, Any, AsyncGenerator, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TerminalSession:
    """Represents an active terminal session"""
    id: str
    pid: int
    fd: int
    created_at: datetime
    last_activity: datetime
    user: str


class SystemController:
    """
    Low-level system controller for terminal execution,
    process management, and network/firewall control
    """
    
    def __init__(self):
        self.sessions: Dict[str, TerminalSession] = {}
        self.is_windows = platform.system() == "Windows"
    
    async def execute_command(self, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """
        Execute a shell command and return (success, stdout, stderr)
        """
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                success = process.returncode == 0
                return (
                    success,
                    stdout.decode('utf-8', errors='replace'),
                    stderr.decode('utf-8', errors='replace')
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return False, "", f"Command timed out after {timeout} seconds"
                
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return False, "", str(e)
    
    def create_pty_session(self, session_id: str, user: str) -> Optional[TerminalSession]:
        """
        Create a new PTY (pseudo-terminal) session for interactive terminal
        """
        if self.is_windows:
            # Windows doesn't support PTY the same way
            logger.warning("PTY not fully supported on Windows")
            return None
        
        try:
            # Create master/slave PTY pair
            master_fd, slave_fd = pty.openpty()
            
            # Fork process
            pid = os.fork()
            
            if pid < 0:
                os.close(master_fd)
                os.close(slave_fd)
                return None
            
            elif pid == 0:
                # Child process
                os.close(master_fd)
                os.setsid()
                os.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                
                # Redirect stdin/stdout/stderr to slave
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                
                os.close(slave_fd)
                
                # Start bash shell
                os.execvp("/bin/bash", ["/bin/bash", "--login"])
            
            else:
                # Parent process
                os.close(slave_fd)
                
                # Set non-blocking mode
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                session = TerminalSession(
                    id=session_id,
                    pid=pid,
                    fd=master_fd,
                    created_at=datetime.utcnow(),
                    last_activity=datetime.utcnow(),
                    user=user
                )
                self.sessions[session_id] = session
                
                return session
                
        except Exception as e:
            logger.error(f"Failed to create PTY session: {e}")
            return None
    
    def write_to_session(self, session_id: str, data: str) -> bool:
        """Write data to a PTY session"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        try:
            os.write(session.fd, data.encode())
            session.last_activity = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Write error: {e}")
            return False
    
    def read_from_session(self, session_id: str, max_bytes: int = 4096) -> str:
        """Read available data from a PTY session"""
        session = self.sessions.get(session_id)
        if not session:
            return ""
        
        try:
            # Check if data is available
            ready, _, _ = select.select([session.fd], [], [], 0.1)
            if not ready:
                return ""
            
            output = os.read(session.fd, max_bytes)
            return output.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Read error: {e}")
            return ""
    
    def resize_session(self, session_id: str, rows: int, cols: int) -> bool:
        """Resize a PTY session"""
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        try:
            winsize = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(session.fd, termios.TIOCSWINSZ, winsize)
            return True
        except Exception as e:
            logger.error(f"Resize error: {e}")
            return False
    
    def close_session(self, session_id: str) -> bool:
        """Close a PTY session"""
        session = self.sessions.pop(session_id, None)
        if not session:
            return False
        
        try:
            os.kill(session.pid, signal.SIGTERM)
            os.close(session.fd)
            return True
        except Exception as e:
            logger.error(f"Close session error: {e}")
            return False
    
    async def kill_process(self, pid: int, force: bool = False) -> Tuple[bool, str]:
        """
        Kill a process by PID
        """
        try:
            if force:
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGTERM)
            
            # Wait briefly for process to terminate
            await asyncio.sleep(0.1)
            
            try:
                os.kill(pid, 0)  # Check if process still exists
                return False, "Process still running"
            except OSError:
                return True, f"Process {pid} terminated successfully"
                
        except ProcessLookupError:
            return False, f"Process {pid} not found"
        except PermissionError:
            return False, f"Permission denied to kill process {pid}"
        except Exception as e:
            return False, str(e)
    
    async def get_process_info(self, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Get detailed process information
        """
        import psutil
        
        if pid:
            try:
                proc = psutil.Process(pid)
                return {
                    "pid": proc.pid,
                    "name": proc.name(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": proc.memory_percent(),
                    "username": proc.username(),
                    "cmdline": proc.cmdline(),
                    "created_time": proc.create_time()
                }
            except psutil.NoSuchProcess:
                return {"error": f"Process {pid} not found"}
        else:
            # List all processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
                try:
                    processes.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "status": proc.info['status'],
                        "username": proc.info['username']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return {"processes": processes}
    
    async def get_network_connections(self) -> Dict[str, Any]:
        """
        Get current network connections
        """
        import psutil
        
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    "family": "IPv4" if conn.family == 2 else "IPv6",
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid
                })
            except (psutil.AccessDenied, AttributeError):
                pass
        
        return {"connections": connections[:100]}  # Limit to 100
    
    async def block_ip(self, ip_address: str, reason: str = "Security threat") -> Tuple[bool, str]:
        """
        Block an IP address using firewall rules
        """
        if self.is_windows:
            return await self._block_ip_windows(ip_address, reason)
        else:
            return await self._block_ip_linux(ip_address, reason)
    
    async def _block_ip_linux(self, ip_address: str, reason: str) -> Tuple[bool, str]:
        """Block IP using iptables on Linux"""
        # Check if iptables is available
        result = await self.execute_command("which iptables")
        if not result[0]:
            return False, "iptables not found"
        
        # Add DROP rule
        cmd = f"iptables -C INPUT -s {ip_address} -j DROP 2>/dev/null || iptables -A INPUT -s {ip_address} -j DROP"
        success, stdout, stderr = await self.execute_command(cmd)
        
        if success:
            logger.info(f"Blocked IP {ip_address}: {reason}")
            return True, f"IP {ip_address} blocked successfully"
        else:
            return False, f"Failed to block IP: {stderr}"
    
    async def _block_ip_windows(self, ip_address: str, reason: str) -> Tuple[bool, str]:
        """Block IP using netsh on Windows"""
        # Check if rule exists, if not create it
        rule_name = f"Block_{ip_address.replace('.', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        success, stdout, stderr = await self.execute_command(cmd)
        
        if success or "OK." in stdout:
            logger.info(f"Blocked IP {ip_address}: {reason}")
            return True, f"IP {ip_address} blocked successfully"
        else:
            return False, f"Failed to block IP: {stderr or stdout}"
    
    async def unblock_ip(self, ip_address: str) -> Tuple[bool, str]:
        """
        Unblock an IP address
        """
        if self.is_windows:
            rule_name = f"Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP 2>/dev/null || true"
        
        success, stdout, stderr = await self.execute_command(cmd)
        return success, f"IP {ip_address} unblocked" if success else f"Failed: {stderr}"
    
    async def get_open_ports(self) -> Dict[str, Any]:
        """
        Get list of open/listening ports
        """
        import psutil
        
        listening_ports = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN':
                try:
                    listening_ports.append({
                        "port": conn.laddr.port if conn.laddr else None,
                        "address": conn.laddr.ip if conn.laddr else None,
                        "pid": conn.pid
                    })
                except (psutil.AccessDenied, AttributeError):
                    pass
        
        return {"listening_ports": listening_ports}


# Global controller instance
system_controller = SystemController()
