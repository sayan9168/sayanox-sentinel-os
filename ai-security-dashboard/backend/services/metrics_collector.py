"""
System Metrics Collector Service
Collects CPU, Memory, Disk, Network metrics using psutil
"""

import asyncio
import logging
import psutil
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Asynchronous system metrics collector"""
    
    def __init__(self, connection_manager: Dict, collection_interval: float = 2.0):
        self.connection_manager = connection_manager
        self.collection_interval = collection_interval
        self._running = False
    
    async def collect_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used = memory.used
            memory_total = memory.total
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network metrics
            net_io = psutil.net_io_counters()
            network_sent = net_io.bytes_sent
            network_recv = net_io.bytes_recv
            
            # Process count
            process_count = len(psutil.pids())
            
            timestamp = datetime.utcnow().isoformat()
            
            return {
                "timestamp": timestamp,
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(memory_percent, 2),
                "memory_used": memory_used,
                "memory_total": memory_total,
                "disk_percent": round(disk_percent, 2),
                "network_sent": network_sent,
                "network_recv": network_recv,
                "process_count": process_count
            }
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return self._get_default_metrics()
    
    def _get_default_metrics(self) -> Dict[str, Any]:
        """Return default metrics on error"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "memory_used": 0,
            "memory_total": 0,
            "disk_percent": 0.0,
            "network_sent": 0,
            "network_recv": 0,
            "process_count": 0
        }
    
    async def start_collection(self):
        """Start continuous metrics collection and broadcasting"""
        self._running = True
        logger.info(f"Starting metrics collection (interval: {self.collection_interval}s)")
        
        while self._running:
            try:
                # Collect metrics
                metrics = await self.collect_metrics()
                
                # Store in history
                self.connection_manager["metrics_history"].append(metrics)
                
                # Keep only last 500 entries in memory
                if len(self.connection_manager["metrics_history"]) > 500:
                    self.connection_manager["metrics_history"] = \
                        self.connection_manager["metrics_history"][-500:]
                
                # Broadcast to WebSocket clients
                await self._broadcast(metrics)
                
                # Log to database periodically (every 10 collections)
                if len(self.connection_manager["metrics_history"]) % 10 == 0:
                    await self._log_to_database(metrics)
                
            except asyncio.CancelledError:
                logger.info("Metrics collection cancelled")
                break
            except Exception as e:
                logger.error(f"Collection error: {e}")
            
            await asyncio.sleep(self.collection_interval)
    
    async def _broadcast(self, metrics: Dict[str, Any]):
        """Broadcast metrics to all connected WebSocket clients"""
        import json
        from fastapi import WebSocket
        
        if self.connection_manager.get("active_connections"):
            message = json.dumps(metrics)
            disconnected = []
            
            for connection in self.connection_manager["active_connections"]:
                try:
                    await connection.send_text(message)
                except Exception:
                    disconnected.append(connection)
            
            # Clean up disconnected clients
            for conn in disconnected:
                if conn in self.connection_manager["active_connections"]:
                    self.connection_manager["active_connections"].remove(conn)
    
    async def _log_to_database(self, metrics: Dict[str, Any]):
        """Log metrics to database"""
        try:
            db_manager = self.connection_manager.get("db_manager")
            if db_manager:
                db_manager.insert_metric(metrics)
        except Exception as e:
            logger.error(f"Error logging metrics to database: {e}")
    
    def stop(self):
        """Stop the metrics collector"""
        self._running = False
        logger.info("Metrics collector stopped")
