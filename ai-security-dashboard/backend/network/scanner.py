"""
Deep Packet Sniffing & Nmap Scanner Module for Sayanox Sentinel OS
Phase 4 Enterprise Upgrade: Network traffic analysis and vulnerability scanning
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from collections import deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Mock classes for when scapy is not available
    class IP: pass
    class TCP: pass
    class UDP: pass
    class ICMP: pass

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Deep packet sniffer using scapy for real-time network traffic analysis.
    Exposes captured packets via WebSocket for live viewing.
    """
    
    def __init__(self, max_packets: int = 1000):
        self.is_running = False
        self.captured_packets: deque = deque(maxlen=max_packets)
        self.websocket_callbacks: List[Callable] = []
        self.sniff_thread: Optional[asyncio.Task] = None
        
    def add_websocket_callback(self, callback: Callable):
        """Add a callback to be called when packets are captured."""
        self.websocket_callbacks.append(callback)
    
    def _process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process a captured packet and extract relevant information."""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            packet_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': 'Unknown',
                'length': len(packet),
                'info': {}
            }
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['info'] = {
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': str(tcp_layer.flags),
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack
                }
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['info'] = {
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'length': udp_layer.len
                }
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['info'] = {
                    'type': packet[ICMP].type,
                    'code': packet[ICMP].code
                }
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    async def _sniff_loop(self):
        """Background loop for packet sniffing."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, packet sniffing disabled")
            return
        
        def packet_callback(packet):
            packet_info = self._process_packet(packet)
            if packet_info:
                self.captured_packets.append(packet_info)
                
                # Notify all WebSocket callbacks
                for callback in self.websocket_callbacks:
                    try:
                        asyncio.create_task(callback(packet_info))
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")
        
        try:
            # Start sniffing in a blocking manner (runs in background thread)
            sniff(
                prn=packet_callback,
                filter="ip",  # Only capture IP packets
                store=False,  # Don't store packets in memory
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
    
    async def start(self):
        """Start the packet sniffer."""
        if self.is_running:
            logger.warning("Packet sniffer is already running")
            return
        
        if not SCAPY_AVAILABLE:
            logger.warning("Cannot start sniffer: scapy not installed")
            return
        
        self.is_running = True
        logger.info("Starting packet sniffer...")
        
        # Run sniffing in a separate thread via asyncio
        import threading
        sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        sniff_thread.start()
        
        logger.info("Packet sniffer started")
    
    async def stop(self):
        """Stop the packet sniffer."""
        self.is_running = False
        logger.info("Packet sniffer stopped")
    
    def get_captured_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recently captured packets."""
        return list(self.captured_packets)[-limit:]
    
    def clear_packets(self):
        """Clear captured packets."""
        self.captured_packets.clear()
        logger.info("Packet buffer cleared")
    
    def get_status(self) -> Dict[str, Any]:
        """Get sniffer status."""
        return {
            'is_running': self.is_running,
            'scapy_available': SCAPY_AVAILABLE,
            'packets_captured': len(self.captured_packets),
            'websocket_callbacks': len(self.websocket_callbacks)
        }


class NmapScanner:
    """
    Nmap scanner integration for network vulnerability scanning.
    Allows React UI to trigger active local network scans.
    """
    
    def __init__(self):
        self.scan_history: List[Dict[str, Any]] = []
        self.max_history = 100
        
    def scan_host(self, host: str, ports: str = "21,22,23,25,80,443,3306,3389,8080", 
                  arguments: str = "-sV -O") -> Dict[str, Any]:
        """
        Scan a specific host for open ports and services.
        
        Args:
            host: Target IP address or hostname
            ports: Comma-separated list of ports to scan
            arguments: Nmap arguments (default: service version + OS detection)
            
        Returns:
            Scan results dictionary
        """
        if not NMAP_AVAILABLE:
            return {
                'success': False,
                'error': 'python-nmap not installed',
                'host': host
            }
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host, ports=ports, arguments=arguments)
            
            result = {
                'success': True,
                'host': host,
                'scan_time': datetime.utcnow().isoformat(),
                'results': {}
            }
            
            if host in nm.all_hosts():
                host_data = nm[host]
                result['results'] = {
                    'hostname': host_data.hostname(),
                    'state': host_data.state(),
                    'protocols': list(host_data.all_protocols()),
                    'open_ports': [],
                    'os_info': host_data.os_info() if host_data.has_os() else {}
                }
                
                # Extract open ports and services
                for proto in host_data.all_protocols():
                    if proto in ['tcp', 'udp']:
                        for port, data in host_data[proto].items():
                            if data['state'] == 'open':
                                result['results']['open_ports'].append({
                                    'port': port,
                                    'protocol': proto,
                                    'state': data['state'],
                                    'service': data.get('name', 'unknown'),
                                    'version': data.get('product', '') + ' ' + data.get('version', ''),
                                    'extra_info': data.get('extrainfo', '')
                                })
            
            # Store in history
            self.scan_history.append(result)
            if len(self.scan_history) > self.max_history:
                self.scan_history = self.scan_history[-self.max_history:]
            
            return result
            
        except Exception as e:
            logger.error(f"Nmap scan error for {host}: {e}")
            return {
                'success': False,
                'error': str(e),
                'host': host
            }
    
    def quick_scan(self, host: str) -> Dict[str, Any]:
        """
        Perform a quick scan of common ports.
        
        Args:
            host: Target IP address or hostname
            
        Returns:
            Quick scan results
        """
        return self.scan_host(host, ports="21,22,23,25,53,80,110,143,443,993,995,3306,3389,5432,8080", arguments="-F")
    
    def full_scan(self, host: str) -> Dict[str, Any]:
        """
        Perform a comprehensive scan with service detection.
        
        Args:
            host: Target IP address or hostname
            
        Returns:
            Full scan results
        """
        return self.scan_host(host, ports="1-1024", arguments="-sV -O -A")
    
    def scan_network_range(self, network: str, ports: str = "22,80,443") -> List[Dict[str, Any]]:
        """
        Scan a network range for hosts.
        
        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            ports: Ports to scan
            
        Returns:
            List of scan results for each host
        """
        if not NMAP_AVAILABLE:
            return [{'success': False, 'error': 'python-nmap not installed'}]
        
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, ports=ports, arguments="-T4 -F")
            
            results = []
            for host in nm.all_hosts():
                host_data = nm[host]
                open_ports = []
                
                for proto in host_data.all_protocols():
                    if proto in ['tcp', 'udp']:
                        for port, data in host_data[proto].items():
                            if data['state'] == 'open':
                                open_ports.append(port)
                
                results.append({
                    'host': host,
                    'hostname': host_data.hostname(),
                    'state': host_data.state(),
                    'open_ports': open_ports
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Network scan error for {network}: {e}")
            return [{'success': False, 'error': str(e)}]
    
    def get_scan_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scan history."""
        return self.scan_history[-limit:]
    
    def clear_history(self):
        """Clear scan history."""
        self.scan_history = []
        logger.info("Nmap scan history cleared")
    
    def get_status(self) -> Dict[str, Any]:
        """Get scanner status."""
        return {
            'nmap_available': NMAP_AVAILABLE,
            'scans_performed': len(self.scan_history),
            'recent_scans': self.scan_history[-5:]
        }


# Singleton instances
packet_sniffer = PacketSniffer()
nmap_scanner = NmapScanner()
