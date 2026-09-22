"""
File Integrity Monitoring Service
Monitors critical directories and files for unauthorized modifications using watchdog/inotify
"""

import os
import time
import hashlib
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent, FileMovedEvent
import threading

logger = logging.getLogger(__name__)


@dataclass
class FileRecord:
    """Represents a monitored file's baseline state"""
    path: str
    size: int
    hash_md5: str
    hash_sha256: str
    modified_time: float
    created_time: float
    permissions: str
    
    @classmethod
    def from_file(cls, filepath: str) -> Optional['FileRecord']:
        """Create a file record from an actual file"""
        try:
            stat_info = os.stat(filepath)
            
            # Calculate hashes
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                content = f.read(8192)
                while content:
                    md5_hash.update(content)
                    sha256_hash.update(content)
                    content = f.read(8192)
            
            return cls(
                path=filepath,
                size=stat_info.st_size,
                hash_md5=md5_hash.hexdigest(),
                hash_sha256=sha256_hash.hexdigest(),
                modified_time=stat_info.st_mtime,
                created_time=stat_info.st_ctime,
                permissions=oct(stat_info.st_mode)[-3:]
            )
        except Exception as e:
            logger.error(f"Failed to create file record for {filepath}: {e}")
            return None


@dataclass
class IntegrityAlert:
    """Represents a file integrity violation alert"""
    id: str
    file_path: str
    alert_type: str  # MODIFIED, CREATED, DELETED, MOVED
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    old_record: Optional[FileRecord]
    new_record: Optional[FileRecord]
    timestamp: str
    user: Optional[str] = None
    process: Optional[str] = None


class IntegrityMonitorHandler(FileSystemEventHandler):
    """Custom event handler for file system events"""
    
    def __init__(self, monitor_callback: Callable[[IntegrityAlert], None]):
        self.monitor_callback = monitor_callback
        self.file_records: Dict[str, FileRecord] = {}
    
    def _create_alert(self, file_path: str, alert_type: str, severity: str, 
                      description: str, old_record: Optional[FileRecord] = None,
                      new_record: Optional[FileRecord] = None) -> IntegrityAlert:
        """Create and dispatch an integrity alert"""
        alert = IntegrityAlert(
            id=f"{alert_type}_{int(time.time() * 1000)}_{os.path.basename(file_path)}",
            file_path=file_path,
            alert_type=alert_type,
            severity=severity,
            description=description,
            old_record=old_record,
            new_record=new_record,
            timestamp=datetime.utcnow().isoformat()
        )
        self.monitor_callback(alert)
        return alert
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Check if this is a monitored file
        if file_path in self.file_records:
            old_record = self.file_records[file_path]
            new_record = FileRecord.from_file(file_path)
            
            if new_record:
                # Check if content actually changed
                if new_record.hash_sha256 != old_record.hash_sha256:
                    self._create_alert(
                        file_path=file_path,
                        alert_type="MODIFIED",
                        severity="HIGH",
                        description=f"File content modified. SHA256 changed from {old_record.hash_sha256[:16]}... to {new_record.hash_sha256[:16]}...",
                        old_record=old_record,
                        new_record=new_record
                    )
                    # Update record
                    self.file_records[file_path] = new_record
                elif new_record.size != old_record.size:
                    self._create_alert(
                        file_path=file_path,
                        alert_type="MODIFIED",
                        severity="MEDIUM",
                        description=f"File size changed from {old_record.size} to {new_record.size} bytes",
                        old_record=old_record,
                        new_record=new_record
                    )
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # New file in monitored directory
        if file_path not in self.file_records:
            new_record = FileRecord.from_file(file_path)
            if new_record:
                self._create_alert(
                    file_path=file_path,
                    alert_type="CREATED",
                    severity="MEDIUM",
                    description=f"New file created in monitored directory",
                    new_record=new_record
                )
                self.file_records[file_path] = new_record
    
    def on_deleted(self, event):
        """Handle file deletion events"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        if file_path in self.file_records:
            old_record = self.file_records.pop(file_path)
            self._create_alert(
                file_path=file_path,
                alert_type="DELETED",
                severity="CRITICAL",
                description=f"Monitored file deleted",
                old_record=old_record
            )
    
    def on_moved(self, event):
        """Handle file move events"""
        if event.is_directory:
            return
        
        src_path = event.src_path
        dst_path = event.dest_path
        
        if src_path in self.file_records:
            old_record = self.file_records.pop(src_path)
            self._create_alert(
                file_path=src_path,
                alert_type="MOVED",
                severity="HIGH",
                description=f"File moved from {src_path} to {dst_path}",
                old_record=old_record
            )


class FileIntegrityMonitor:
    """
    Main file integrity monitoring service
    Uses watchdog for cross-platform file system monitoring
    """
    
    def __init__(self, db_manager=None, notification_service=None):
        self.db_manager = db_manager
        self.notification_service = notification_service
        self.observer: Optional[Observer] = None
        self.handler: Optional[IntegrityMonitorHandler] = None
        self.monitored_paths: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[IntegrityAlert] = []
        self._running = False
        self._lock = threading.Lock()
    
    def start(self):
        """Start the file integrity monitor"""
        if self._running:
            logger.warning("FIM already running")
            return
        
        self.handler = IntegrityMonitorHandler(self._on_alert)
        self.observer = Observer()
        
        # Start monitoring all registered paths
        for path, config in self.monitored_paths.items():
            self._watch_path(path, config.get('recursive', True))
        
        self.observer.start()
        self._running = True
        logger.info(f"FIM started, monitoring {len(self.monitored_paths)} paths")
    
    def stop(self):
        """Stop the file integrity monitor"""
        if self.observer and self._running:
            self.observer.stop()
            self.observer.join()
            self._running = False
            logger.info("FIM stopped")
    
    def add_monitored_path(self, path: str, recursive: bool = True, 
                           patterns: Optional[List[str]] = None,
                           severity_map: Optional[Dict[str, str]] = None):
        """Add a path to monitor"""
        abs_path = os.path.abspath(path)
        
        if not os.path.exists(abs_path):
            logger.warning(f"Path does not exist: {abs_path}")
            return False
        
        self.monitored_paths[abs_path] = {
            'recursive': recursive,
            'patterns': patterns or ['*'],
            'severity_map': severity_map or {}
        }
        
        # If already running, start watching this path
        if self._running and self.observer:
            self._watch_path(abs_path, recursive)
        
        # Initialize file records for existing files
        self._initialize_path(abs_path)
        
        logger.info(f"Added monitored path: {abs_path}")
        return True
    
    def remove_monitored_path(self, path: str):
        """Remove a path from monitoring"""
        abs_path = os.path.abspath(path)
        if abs_path in self.monitored_paths:
            del self.monitored_paths[abs_path]
            logger.info(f"Removed monitored path: {abs_path}")
            return True
        return False
    
    def _watch_path(self, path: str, recursive: bool = True):
        """Start watching a specific path"""
        if self.observer and self.handler:
            self.observer.schedule(self.handler, path, recursive=recursive)
    
    def _initialize_path(self, path: str):
        """Initialize file records for all existing files in a path"""
        if not self.handler:
            return
        
        try:
            for root, dirs, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        record = FileRecord.from_file(filepath)
                        if record:
                            self.handler.file_records[filepath] = record
                    except Exception as e:
                        logger.debug(f"Could not initialize {filepath}: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize path {path}: {e}")
    
    def _on_alert(self, alert: IntegrityAlert):
        """Handle integrity alerts"""
        with self._lock:
            self.alerts.append(alert)
            # Keep only last 1000 alerts in memory
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]
        
        logger.warning(f"FIM Alert [{alert.severity}]: {alert.alert_type} - {alert.file_path}")
        
        # Store in database
        if self.db_manager:
            try:
                self.db_manager.insert_fim_alert(alert)
            except Exception as e:
                logger.error(f"Failed to store FIM alert: {e}")
        
        # Send notification for high/critical alerts
        if self.notification_service and alert.severity in ('CRITICAL', 'HIGH'):
            try:
                import asyncio
                asyncio.create_task(
                    self.notification_service.send_alert(
                        alert_type="FIM_VIOLATION",
                        severity=alert.severity,
                        title=f"File Integrity Violation: {alert.alert_type}",
                        details={
                            "File": alert.file_path,
                            "Type": alert.alert_type,
                            "Description": alert.description,
                            "Timestamp": alert.timestamp
                        }
                    )
                )
            except Exception as e:
                logger.error(f"Failed to send FIM notification: {e}")
    
    def get_alerts(self, limit: int = 100, 
                   alert_type: Optional[str] = None,
                   severity: Optional[str] = None) -> List[Dict]:
        """Get recent integrity alerts"""
        with self._lock:
            alerts = list(self.alerts)
        
        # Filter
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        # Convert to dict and return most recent
        result = []
        for alert in alerts[-limit:][::-1]:
            result.append({
                'id': alert.id,
                'file_path': alert.file_path,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'description': alert.description,
                'timestamp': alert.timestamp
            })
        
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Get current FIM status"""
        return {
            'running': self._running,
            'monitored_paths': list(self.monitored_paths.keys()),
            'monitored_files_count': len(self.handler.file_records) if self.handler else 0,
            'alerts_count': len(self.alerts),
            'recent_alerts': self.get_alerts(limit=10)
        }
    
    def is_running(self) -> bool:
        """Check if FIM service is running"""
        return self._running


# Global FIM instance
fim_service = FileIntegrityMonitor()


def configure_fim(db_manager=None, notification_service=None, 
                  critical_paths: Optional[List[str]] = None):
    """Configure and start FIM service"""
    global fim_service
    
    fim_service.db_manager = db_manager
    fim_service.notification_service = notification_service
    
    # Default critical paths to monitor
    default_paths = [
        '/etc',
        '/usr/bin',
        '/usr/sbin',
        os.getcwd(),  # Application directory
    ]
    
    paths_to_monitor = critical_paths or default_paths
    
    for path in paths_to_monitor:
        if os.path.exists(path):
            fim_service.add_monitored_path(path, recursive=True)
    
    fim_service.start()
    return fim_service
