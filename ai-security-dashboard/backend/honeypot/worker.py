"""
Deception Technology / Honeypot Module for Sayanox Sentinel OS
Phase 4 Enterprise Upgrade: Lightweight honeypot that binds to decoy ports and triggers firewall blocks
"""

import asyncio
import logging
import socket
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class HoneypotWorker:
    """
    Lightweight honeypot worker that binds to decoy ports.
    When external IPs attempt to connect, logs the threat and triggers firewall block.
    """
    
    # Default decoy ports (commonly targeted by attackers)
    DEFAULT_DECOY_PORTS = [23, 2323, 4444, 5555, 6666, 8080, 9999]
    
    def __init__(self, firewall_callback: Optional[Callable[[str], None]] = None):
        """
        Initialize the honeypot worker.
        
        Args:
            firewall_callback: Function to call with IP address for blocking
        """
        self.decoy_ports: List[int] = []
        self.servers: Dict[int, asyncio.Server] = {}
        self.is_running = False
        self.connection_logs: List[Dict[str, Any]] = []
        self.firewall_callback = firewall_callback
        self.max_logs = 1000
        
    def add_decoy_port(self, port: int):
        """Add a decoy port to monitor."""
        if port not in self.decoy_ports:
            self.decoy_ports.append(port)
            logger.info(f"Added decoy port: {port}")
    
    def remove_decoy_port(self, port: int):
        """Remove a decoy port from monitoring."""
        if port in self.decoy_ports:
            self.decoy_ports.remove(port)
            logger.info(f"Removed decoy port: {port}")
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
        """
        Handle incoming connection to a decoy port.
        Logs the attempt and triggers firewall block.
        """
        try:
            peer_addr = writer.get_extra_info('peername')
            if peer_addr:
                ip_address = peer_addr[0]
                
                # Log the connection attempt
                log_entry = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'source_ip': ip_address,
                    'source_port': peer_addr[1],
                    'decoy_port': port,
                    'action': 'blocked'
                }
                
                logger.warning(f"HONEYPOT TRIGGERED: Connection attempt from {ip_address} to port {port}")
                
                # Store log
                self.connection_logs.append(log_entry)
                if len(self.connection_logs) > self.max_logs:
                    self.connection_logs = self.connection_logs[-self.max_logs:]
                
                # Trigger firewall block
                if self.firewall_callback:
                    try:
                        self.firewall_callback(ip_address)
                        logger.info(f"Firewall block triggered for {ip_address}")
                    except Exception as e:
                        logger.error(f"Error triggering firewall block: {e}")
                
                # Send fake response to keep attacker engaged briefly
                writer.write(b"Welcome to Sayanox Security System...\n")
                await writer.drain()
                
                # Close connection after brief delay
                await asyncio.sleep(0.5)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error handling honeypot connection: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    async def start_server(self, port: int):
        """Start honeypot server on a specific port."""
        try:
            server = await asyncio.start_server(
                lambda r, w: self.handle_connection(r, w, port),
                '0.0.0.0',
                port
            )
            self.servers[port] = server
            logger.info(f"Honeypot listening on port {port}")
            return True
        except OSError as e:
            logger.warning(f"Could not bind to port {port}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error starting honeypot on port {port}: {e}")
            return False
    
    async def stop_server(self, port: int):
        """Stop honeypot server on a specific port."""
        if port in self.servers:
            self.servers[port].close()
            await self.servers[port].wait_closed()
            del self.servers[port]
            logger.info(f"Honeypot stopped on port {port}")
    
    async def start(self, ports: Optional[List[int]] = None):
        """
        Start all honeypot servers.
        
        Args:
            ports: List of ports to monitor (uses default if not specified)
        """
        if self.is_running:
            logger.warning("Honeypot is already running")
            return
        
        ports_to_use = ports or self.DEFAULT_DECOY_PORTS.copy()
        
        # Add any custom ports
        for port in self.decoy_ports:
            if port not in ports_to_use:
                ports_to_use.append(port)
        
        self.is_running = True
        
        # Start servers for each port
        tasks = [self.start_server(port) for port in ports_to_use]
        await asyncio.gather(*tasks)
        
        logger.info(f"Honeypot started on {len(self.servers)} ports")
    
    async def stop(self):
        """Stop all honeypot servers."""
        if not self.is_running:
            return
        
        # Stop all servers
        tasks = []
        for port in list(self.servers.keys()):
            tasks.append(self.stop_server(port))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        self.is_running = False
        logger.info("Honeypot stopped")
    
    def get_connection_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent connection logs."""
        return self.connection_logs[-limit:]
    
    def clear_logs(self):
        """Clear connection logs."""
        self.connection_logs = []
        logger.info("Honeypot logs cleared")
    
    def get_status(self) -> Dict[str, Any]:
        """Get honeypot status."""
        return {
            'is_running': self.is_running,
            'active_ports': list(self.servers.keys()),
            'configured_ports': self.decoy_ports + self.DEFAULT_DECOY_PORTS,
            'total_connections': len(self.connection_logs),
            'recent_attempts': self.connection_logs[-10:] if self.connection_logs else []
        }


# Singleton instance (firewall callback will be set during initialization)
honeypot_worker = HoneypotWorker()
