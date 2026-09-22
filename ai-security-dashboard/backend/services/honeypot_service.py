"""
Sayanox Sentinel OS - Honeypot Service
Lightweight deception technology that monitors decoy ports for intrusion attempts.
"""

import asyncio
import logging
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import deque
import os

logger = logging.getLogger(__name__)


class HoneypotConnection:
    """Represents a connection attempt to a honeypot port."""
    
    def __init__(self, remote_ip: str, remote_port: int, local_port: int, timestamp: datetime):
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.local_port = local_port
        self.timestamp = timestamp
        self.duration: float = 0.0
        self.data_received: bytes = b""
        self.is_blocked: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'remote_ip': self.remote_ip,
            'remote_port': self.remote_port,
            'local_port': self.local_port,
            'timestamp': self.timestamp.isoformat(),
            'duration': self.duration,
            'data_received': self.data_received.hex()[:100] if self.data_received else "",
            'is_blocked': self.is_blocked
        }


class HoneypotService:
    """
    Lightweight honeypot service that binds to decoy ports
    and logs any connection attempts for threat detection.
    """
    
    # Default decoy ports (commonly targeted by attackers)
    DEFAULT_DECOY_PORTS = [23, 2323, 4444, 5555, 6666, 8080, 9999]
    
    def __init__(self, firewall_callback: Optional[Callable] = None):
        self.decoy_ports: List[int] = []
        self.servers: Dict[int, socket.socket] = {}
        self.connection_threads: Dict[int, threading.Thread] = {}
        self.is_running: bool = False
        
        # Connection history
        self.connection_history: deque = deque(maxlen=1000)
        self.blocked_ips: set = set()
        
        # Callback for automatic IP blocking
        self.firewall_callback = firewall_callback
        
        # Auto-block threshold (connections from same IP before blocking)
        self.auto_block_threshold = 3
        self.ip_connection_count: Dict[str, int] = {}
        
        # Stats
        self.stats = {
            'total_connections': 0,
            'unique_ips': 0,
            'blocked_ips': 0
        }
    
    def add_decoy_port(self, port: int) -> bool:
        """Add a decoy port to monitor."""
        if port in self.decoy_ports:
            return False
        
        self.decoy_ports.append(port)
        logger.info(f"Added decoy port: {port}")
        
        # Start monitoring if already running
        if self.is_running:
            self._start_port_listener(port)
        
        return True
    
    def remove_decoy_port(self, port: int) -> bool:
        """Remove a decoy port from monitoring."""
        if port not in self.decoy_ports:
            return False
        
        self.decoy_ports.remove(port)
        
        # Stop monitoring if running
        if self.is_running and port in self.servers:
            self._stop_port_listener(port)
        
        logger.info(f"Removed decoy port: {port}")
        return True
    
    def _start_port_listener(self, port: int):
        """Start listening on a specific port."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)  # Allow periodic checks
            
            self.servers[port] = server_socket
            
            # Start connection handler thread
            thread = threading.Thread(
                target=self._handle_connections,
                args=(port, server_socket),
                daemon=True
            )
            thread.start()
            self.connection_threads[port] = thread
            
            logger.info(f"Honeypot listening on port {port}")
            
        except Exception as e:
            logger.error(f"Failed to start honeypot on port {port}: {e}")
    
    def _stop_port_listener(self, port: int):
        """Stop listening on a specific port."""
        if port in self.servers:
            try:
                self.servers[port].close()
                del self.servers[port]
                
                if port in self.connection_threads:
                    del self.connection_threads[port]
                
                logger.info(f"Stopped honeypot on port {port}")
            except Exception as e:
                logger.error(f"Failed to stop honeypot on port {port}: {e}")
    
    def _handle_connections(self, port: int, server_socket: socket.socket):
        """Handle incoming connections to a honeypot port."""
        while self.is_running:
            try:
                client_socket, addr = server_socket.accept()
                remote_ip = addr[0]
                remote_port = addr[1]
                
                logger.warning(f"Honeypot triggered on port {port} from {remote_ip}:{remote_port}")
                
                # Create connection record
                connection = HoneypotConnection(
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    local_port=port,
                    timestamp=datetime.now()
                )
                
                # Track IP connection count
                self.ip_connection_count[remote_ip] = self.ip_connection_count.get(remote_ip, 0) + 1
                
                # Check if auto-block threshold reached
                if self.ip_connection_count[remote_ip] >= self.auto_block_threshold:
                    self._auto_block_ip(remote_ip, connection)
                
                # Handle connection in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, remote_ip, remote_port, connection),
                    daemon=True
                )
                client_thread.start()
                
                # Update stats
                self.stats['total_connections'] += 1
                self.stats['unique_ips'] = len(set(c.remote_ip for c in self.connection_history))
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    logger.error(f"Error handling connection on port {port}: {e}")
    
    def _handle_client(self, client_socket: socket.socket, remote_ip: str, 
                       remote_port: int, connection: HoneypotConnection):
        """Handle individual client connection."""
        start_time = datetime.now()
        
        try:
            client_socket.settimeout(5.0)
            
            # Receive any data sent
            while self.is_running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    connection.data_received += data
                    logger.debug(f"Received data from {remote_ip}: {data[:50]}")
                    
                except socket.timeout:
                    break
            
        except Exception as e:
            logger.debug(f"Client connection ended: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            connection.duration = (datetime.now() - start_time).total_seconds()
            self.connection_history.append(connection)
            
            logger.info(f"Connection from {remote_ip} lasted {connection.duration:.2f}s")
    
    def _auto_block_ip(self, ip: str, connection: HoneypotConnection):
        """Automatically block an IP that triggered honeypot multiple times."""
        if ip in self.blocked_ips:
            return
        
        self.blocked_ips.add(ip)
        connection.is_blocked = True
        self.stats['blocked_ips'] = len(self.blocked_ips)
        
        logger.warning(f"Auto-blocking IP {ip} after multiple honeypot triggers")
        
        # Trigger firewall callback if available
        if self.firewall_callback:
            try:
                asyncio.create_task(self.firewall_callback(ip, "honeypot_trigger"))
            except Exception as e:
                logger.error(f"Failed to trigger firewall block: {e}")
    
    async def block_ip(self, ip: str, reason: str = "honeypot_trigger") -> bool:
        """Block an IP address (called by firewall callback)."""
        # This is called asynchronously from the firewall service
        logger.info(f"Blocking IP {ip} due to {reason}")
        return True
    
    def start(self):
        """Start all honeypot listeners."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Use default ports if none configured
        if not self.decoy_ports:
            self.decoy_ports = self.DEFAULT_DECOY_PORTS.copy()
        
        # Start listeners for all configured ports
        for port in self.decoy_ports:
            self._start_port_listener(port)
        
        logger.info(f"Honeypot service started with {len(self.decoy_ports)} decoy ports")
    
    def stop(self):
        """Stop all honeypot listeners."""
        self.is_running = False
        
        # Close all servers
        for port in list(self.servers.keys()):
            self._stop_port_listener(port)
        
        logger.info("Honeypot service stopped")
    
    def get_connection_history(self, limit: int = 50) -> List[Dict]:
        """Get recent connection attempts."""
        sorted_connections = sorted(
            self.connection_history,
            key=lambda x: x.timestamp,
            reverse=True
        )
        return [c.to_dict() for c in sorted_connections[:limit]]
    
    def get_stats(self) -> Dict:
        """Get honeypot statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'decoy_ports': self.decoy_ports,
            'active_listeners': len(self.servers)
        }
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs."""
        return list(self.blocked_ips)
    
    def clear_history(self):
        """Clear connection history."""
        self.connection_history.clear()
        self.ip_connection_count.clear()
        logger.info("Honeypot history cleared")


# Global instance
honeypot_service = HoneypotService()


async def setup_honeypot_with_firewall(firewall_callback: Callable):
    """Setup honeypot with firewall integration."""
    global honeypot_service
    honeypot_service = HoneypotService(firewall_callback=firewall_callback)
    return honeypot_service
