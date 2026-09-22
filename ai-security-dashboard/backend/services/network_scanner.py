"""
Sayanox Sentinel OS - Network Sniffer & Nmap Scanner Service
Deep packet inspection and network vulnerability scanning capabilities.
"""

import asyncio
import logging
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import deque
import json
import re

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Scapy not available, packet sniffing disabled")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("python-nmap not available, Nmap scanning disabled")

logger = logging.getLogger(__name__)


class CapturedPacket:
    """Represents a captured network packet."""
    
    def __init__(self, timestamp: datetime, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, protocol: str, 
                 size: int, flags: str = "", payload: bytes = b""):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.flags = flags
        self.payload = payload
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'flags': self.flags,
            'payload_preview': self.payload[:50].hex() if self.payload else ""
        }


class NetworkSnifferService:
    """
    Deep packet inspection service using scapy.
    Captures and analyzes raw network packets in real-time.
    """
    
    def __init__(self, max_packets: int = 1000):
        self.is_running: bool = False
        self.sniff_thread: Optional[threading.Thread] = None
        self.packet_history: deque = deque(maxlen=max_packets)
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'bytes_captured': 0
        }
        
        # Protocol filters
        self.filter_protocols = ['tcp', 'udp', 'icmp']
        self.port_filters: List[int] = []  # Empty = capture all ports
        
        # Callbacks for real-time analysis
        self.packet_callbacks: List[Callable] = []
    
    def _packet_callback(self, packet):
        """Process each captured packet."""
        try:
            if not self.is_running:
                return
            
            # Extract packet info
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                protocol = "OTHER"
                src_port = 0
                dst_port = 0
                flags = ""
                payload = b""
                
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                    self.stats['tcp_packets'] += 1
                    
                    if Raw in packet:
                        payload = bytes(packet[Raw].load)
                        
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    self.stats['udp_packets'] += 1
                    
                    if Raw in packet:
                        payload = bytes(packet[Raw].load)
                        
                elif ICMP in packet:
                    protocol = "ICMP"
                    self.stats['icmp_packets'] += 1
                else:
                    self.stats['other_packets'] += 1
                
                # Apply port filter if configured
                if self.port_filters and dst_port not in self.port_filters:
                    return
                
                # Create packet record
                captured = CapturedPacket(
                    timestamp=datetime.now(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    size=len(packet),
                    flags=flags,
                    payload=payload
                )
                
                self.packet_history.append(captured)
                self.stats['total_packets'] += 1
                self.stats['bytes_captured'] += len(packet)
                
                # Notify callbacks
                for callback in self.packet_callbacks:
                    try:
                        callback(captured)
                    except Exception as e:
                        logger.error(f"Packet callback error: {e}")
                        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_sniffing(self, interface: str = None, count: int = 0):
        """Start packet sniffing."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available")
            return False
        
        if self.is_running:
            return True
        
        self.is_running = True
        
        # Build BPF filter
        bpf_filter = None
        if self.port_filters:
            port_filter = " or ".join([f"port {p}" for p in self.port_filters])
            bpf_filter = port_filter
        
        try:
            self.sniff_thread = threading.Thread(
                target=self._run_sniffer,
                args=(interface, count, bpf_filter),
                daemon=True
            )
            self.sniff_thread.start()
            
            logger.info(f"Started packet sniffing (interface={interface}, filter={bpf_filter})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start sniffer: {e}")
            self.is_running = False
            return False
    
    def _run_sniffer(self, interface: str, count: int, bpf_filter: str):
        """Run the scapy sniffer in a thread."""
        try:
            sniff(
                iface=interface,
                prn=self._packet_callback,
                store=False,
                count=count,
                filter=bpf_filter,
                stop_filter=lambda x: not self.is_running
            )
        except PermissionError:
            logger.error("Permission denied: Run with sudo or CAP_NET_RAW capability")
        except Exception as e:
            if self.is_running:
                logger.error(f"Sniffer error: {e}")
    
    def stop_sniffing(self):
        """Stop packet sniffing."""
        self.is_running = False
        
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2.0)
            self.sniff_thread = None
        
        logger.info("Stopped packet sniffing")
    
    def add_packet_callback(self, callback: Callable):
        """Add a callback for real-time packet analysis."""
        self.packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback: Callable):
        """Remove a packet callback."""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)
    
    def get_recent_packets(self, limit: int = 100, 
                          protocol: str = None,
                          src_ip: str = None,
                          dst_ip: str = None) -> List[Dict]:
        """Get recent packets with optional filtering."""
        packets = list(self.packet_history)
        
        # Apply filters
        if protocol:
            packets = [p for p in packets if p.protocol == protocol.upper()]
        if src_ip:
            packets = [p for p in packets if p.src_ip == src_ip]
        if dst_ip:
            packets = [p for p in packets if p.dst_ip == dst_ip]
        
        # Sort by timestamp descending
        packets.sort(key=lambda x: x.timestamp, reverse=True)
        
        return [p.to_dict() for p in packets[:limit]]
    
    def get_stats(self) -> Dict:
        """Get sniffer statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'scapy_available': SCAPY_AVAILABLE,
            'filter_protocols': self.filter_protocols,
            'port_filters': self.port_filters
        }
    
    def clear_history(self):
        """Clear packet history."""
        self.packet_history.clear()
        logger.info("Packet history cleared")


class NmapScannerService:
    """
    Network vulnerability scanning service using python-nmap.
    Provides active network reconnaissance capabilities.
    """
    
    def __init__(self):
        self.scans: Dict[str, Dict] = {}
        self.scan_history: deque = deque(maxlen=100)
        
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                logger.error(f"Failed to initialize nmap: {e}")
                self.nm = None
        else:
            self.nm = None
    
    async def scan_host(self, host: str, ports: str = "1-1024", 
                       arguments: str = "-sV -sC") -> Dict:
        """
        Perform an Nmap scan on a target host.
        
        Args:
            host: Target IP or hostname
            ports: Port range (e.g., "1-1024", "22,80,443")
            arguments: Nmap arguments (-sV for version, -sC for scripts)
        """
        if not self.nm:
            return {'error': 'Nmap not available'}
        
        scan_id = f"{host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            logger.info(f"Starting Nmap scan on {host} (ports: {ports})")
            
            # Run scan in executor to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.nm.scan(hosts=host, ports=ports, arguments=arguments)
            )
            
            # Parse results
            result = self._parse_scan_result(host)
            result['scan_id'] = scan_id
            result['target'] = host
            result['ports_scanned'] = ports
            result['timestamp'] = datetime.now().isoformat()
            
            self.scan_history.append(result)
            self.scans[scan_id] = result
            
            logger.info(f"Nmap scan completed: {len(result.get('open_ports', []))} open ports found")
            
            return result
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {
                'scan_id': scan_id,
                'target': host,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_scan_result(self, host: str) -> Dict:
        """Parse Nmap scan results."""
        result = {
            'host': host,
            'hostname': '',
            'state': 'unknown',
            'open_ports': [],
            'closed_ports': 0,
            'filtered_ports': 0,
            'services': {},
            'os_match': None,
            'vulnerabilities': []
        }
        
        try:
            if host not in self.nm.all_hosts():
                return result
            
            scan_info = self.nm[host]
            
            # Host state
            if 'status' in scan_info:
                result['state'] = scan_info['status'].get('state', 'unknown')
            
            # Hostname
            if 'hostnames' in scan_info and scan_info['hostnames']:
                result['hostname'] = scan_info['hostnames'][0].get('name', '')
            
            # Ports and services
            if 'tcp' in scan_info:
                for port, data in scan_info['tcp'].items():
                    port_info = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': data.get('state', 'unknown'),
                        'service': data.get('name', ''),
                        'version': data.get('version', ''),
                        'product': data.get('product', ''),
                        'extrainfo': data.get('extrainfo', '')
                    }
                    
                    if data.get('state') == 'open':
                        result['open_ports'].append(port_info)
                        
                        # Track services
                        if data.get('name'):
                            result['services'][port] = {
                                'name': data.get('name'),
                                'version': f"{data.get('product', '')} {data.get('version', '')}".strip()
                            }
                    else:
                        result['closed_ports'] += 1
            
            if 'udp' in scan_info:
                for port, data in scan_info['udp'].items():
                    if data.get('state') == 'open':
                        result['open_ports'].append({
                            'port': port,
                            'protocol': 'udp',
                            'state': 'open',
                            'service': data.get('name', '')
                        })
            
            # OS detection
            if 'osmatch' in scan_info and scan_info['osmatch']:
                os_matches = scan_info['osmatch']
                if os_matches:
                    result['os_match'] = {
                        'name': os_matches[0].get('name', 'Unknown'),
                        'accuracy': os_matches[0].get('accuracy', 0)
                    }
            
            # Check for common vulnerabilities based on services
            result['vulnerabilities'] = self._check_common_vulns(result['services'])
            
        except Exception as e:
            logger.error(f"Error parsing scan result: {e}")
        
        return result
    
    def _check_common_vulns(self, services: Dict) -> List[Dict]:
        """Check for common vulnerabilities based on detected services."""
        vulns = []
        
        vulnerable_versions = {
            'ftp': ['vsftpd 2.3.4'],  # Backdoor
            'ssh': ['OpenSSH 7.0'],   # Various CVEs
            'http': ['Apache 2.4.49', 'Apache 2.4.50'],  # Path traversal
            'smb': ['Samba 4.11', 'Samba 4.12'],  # EternalBlue related
        }
        
        for port, service_info in services.items():
            service_name = service_info.get('name', '').lower()
            version = service_info.get('version', '').lower()
            
            if service_name in vulnerable_versions:
                for vuln_version in vulnerable_versions[service_name]:
                    if vuln_version.lower() in version:
                        vulns.append({
                            'port': port,
                            'service': service_name,
                            'version': version,
                            'potential_vulnerability': vuln_version,
                            'severity': 'high' if service_name in ['smb', 'ftp'] else 'medium'
                        })
        
        return vulns
    
    async def quick_scan(self, host: str) -> Dict:
        """Perform a quick scan of common ports."""
        return await self.scan_host(host, ports="1-100", arguments="-F")
    
    async def full_scan(self, host: str) -> Dict:
        """Perform a comprehensive scan."""
        return await self.scan_host(
            host, 
            ports="1-65535", 
            arguments="-sV -sC -O --script=vuln"
        )
    
    def get_scan_history(self, limit: int = 20) -> List[Dict]:
        """Get recent scan results."""
        scans = list(self.scan_history)
        scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return scans[:limit]
    
    def get_scan_result(self, scan_id: str) -> Optional[Dict]:
        """Get a specific scan result by ID."""
        return self.scans.get(scan_id)
    
    def get_stats(self) -> Dict:
        """Get scanner statistics."""
        return {
            'nmap_available': NMAP_AVAILABLE and self.nm is not None,
            'total_scans': len(self.scans),
            'recent_scans': len(self.scan_history)
        }


# Global instances
network_sniffer = NetworkSnifferService()
nmap_scanner = NmapScannerService()


async def analyze_packet_for_threats(packet: CapturedPacket):
    """Analyze captured packets for potential threats."""
    threats = []
    
    # Check for suspicious ports
    suspicious_ports = [4444, 5555, 6666, 31337, 12345]  # Common backdoor ports
    if packet.dst_port in suspicious_ports or packet.src_port in suspicious_ports:
        threats.append({
            'type': 'suspicious_port',
            'port': packet.dst_port or packet.src_port,
            'severity': 'high'
        })
    
    # Check for known malicious patterns in payload
    if packet.payload:
        malicious_patterns = [
            b'/bin/sh',
            b'/bin/bash',
            b'cmd.exe',
            b'powershell',
            b'wget http',
            b'curl http'
        ]
        
        for pattern in malicious_patterns:
            if pattern in packet.payload.lower():
                threats.append({
                    'type': 'malicious_payload',
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'severity': 'critical'
                })
                break
    
    return threats
