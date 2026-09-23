"""
File Integrity Monitoring (FIM) Module
Background file system watcher using watchdog for real-time audit of critical files
"""

import os
import hashlib
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent, FileMovedEvent
import json

logger = logging.getLogger(__name__)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "database", "security_dashboard.db")


class FileIntegrityRecord:
    """Represents a file integrity record with hash and metadata."""
    
    def __init__(self, filepath: str, file_hash: str, size: int, mtime: float):
        self.filepath = filepath
        self.file_hash = file_hash
        self.size = size
        self.mtime = mtime
        self.created_at = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filepath": self.filepath,
            "file_hash": self.file_hash,
            "size": self.size,
            "mtime": self.mtime,
            "created_at": self.created_at
        }


class FileIntegrityHandler(FileSystemEventHandler):
    """
    Watchdog event handler for file system changes.
    Creates audit entries for unauthorized modifications.
    """
    
    def __init__(self, fim_service: 'FileIntegrityMonitor'):
        super().__init__()
        self.fim_service = fim_service
    
    def _create_audit_entry(self, event_type: str, src_path: str, dest_path: Optional[str] = None):
        """Create an audit entry for a file system event."""
        try:
            # Calculate hash if file exists
            file_hash = None
            size = None
            if os.path.exists(src_path) and os.path.isfile(src_path):
                file_hash = self.fim_service.calculate_hash(src_path)
                size = os.path.getsize(src_path)
            
            audit_entry = {
                "event_type": event_type,
                "filepath": src_path,
                "dest_path": dest_path,
                "file_hash": file_hash,
                "size": size,
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "high" if self._is_critical_file(src_path) else "medium"
            }
            
            # Store in database
            self.fim_service.store_audit_entry(audit_entry)
            
            # Check against baseline
            if event_type in ["modified", "deleted"]:
                self.fim_service.check_integrity_violation(src_path, audit_entry)
            
            logger.info(f"FIM Audit: {event_type} - {src_path}")
            
        except Exception as e:
            logger.error(f"Error creating audit entry: {e}")
    
    def _is_critical_file(self, filepath: str) -> bool:
        """Check if the file is in a critical monitored directory."""
        critical_patterns = [
            "/etc/",
            "/usr/bin/",
            "/usr/sbin/",
            "/var/log/",
            "backend/main.py",
            "backend/auth/",
            ".env",
            "credentials"
        ]
        return any(pattern in filepath for pattern in critical_patterns)
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self._create_audit_entry("modified", event.src_path)
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self._create_audit_entry("created", event.src_path)
    
    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            self._create_audit_entry("deleted", event.src_path)
    
    def on_moved(self, event):
        """Handle file move events."""
        if not event.is_directory:
            self._create_audit_entry("moved", event.src_path, event.dest_path)


class FileIntegrityMonitor:
    """
    File Integrity Monitoring Service
    Monitors critical directories and files for unauthorized modifications
    """
    
    def __init__(self):
        self.observer: Optional[Observer] = None
        self.watched_paths: Set[str] = set()
        self.baseline_hashes: Dict[str, FileIntegrityRecord] = {}
        self.is_running = False
        self._load_baseline()
    
    def _load_baseline(self):
        """Load existing baseline hashes from database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Create FIM tables if they don't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fim_baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath TEXT UNIQUE NOT NULL,
                    file_hash TEXT NOT NULL,
                    size INTEGER,
                    mtime REAL,
                    created_at TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fim_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    dest_path TEXT,
                    file_hash TEXT,
                    size INTEGER,
                    timestamp TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    violation_detected INTEGER DEFAULT 0
                )
            """)
            
            # Load baseline
            cursor.execute("SELECT filepath, file_hash, size, mtime, created_at FROM fim_baseline")
            for row in cursor.fetchall():
                record = FileIntegrityRecord(row[0], row[1], row[2], row[3])
                record.created_at = row[4]
                self.baseline_hashes[row[0]] = record
            
            conn.close()
            logger.info(f"Loaded {len(self.baseline_hashes)} baseline file hashes")
            
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
    
    def calculate_hash(self, filepath: str, algorithm: str = "sha256") -> Optional[str]:
        """Calculate file hash using specified algorithm."""
        try:
            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                return None
            
            hasher = hashlib.new(algorithm)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def add_watch_path(self, path: str, recursive: bool = True):
        """Add a path to be monitored."""
        if os.path.exists(path):
            self.watched_paths.add(path)
            logger.info(f"Added watch path: {path} (recursive={recursive})")
        else:
            logger.warning(f"Path does not exist: {path}")
    
    def remove_watch_path(self, path: str) -> bool:
        """Remove a path from monitoring."""
        if path in self.watched_paths:
            self.watched_paths.remove(path)
            return True
        return False
    
    def create_baseline(self, paths: Optional[List[str]] = None):
        """Create or update baseline hashes for monitored paths."""
        paths_to_scan = paths if paths else list(self.watched_paths)
        new_count = 0
        updated_count = 0
        
        for path in paths_to_scan:
            if not os.path.exists(path):
                continue
            
            if os.path.isfile(path):
                self._index_file(path)
                new_count += 1
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    # Skip hidden directories and common non-essential dirs
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', '.git']]
                    
                    for file in files:
                        if not file.startswith('.'):
                            filepath = os.path.join(root, file)
                            self._index_file(filepath)
                            new_count += 1
        
        logger.info(f"Baseline created/updated: {new_count} files indexed")
        return {"files_indexed": new_count}
    
    def _index_file(self, filepath: str):
        """Index a single file in the baseline."""
        try:
            file_hash = self.calculate_hash(filepath)
            if file_hash:
                stat = os.stat(filepath)
                record = FileIntegrityRecord(filepath, file_hash, stat.st_size, stat.st_mtime)
                
                if filepath in self.baseline_hashes:
                    self.baseline_hashes[filepath] = record
                    self._update_baseline_db(record, is_new=False)
                else:
                    self.baseline_hashes[filepath] = record
                    self._update_baseline_db(record, is_new=True)
        except Exception as e:
            logger.error(f"Error indexing file {filepath}: {e}")
    
    def _update_baseline_db(self, record: FileIntegrityRecord, is_new: bool = True):
        """Update baseline in database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if is_new:
                cursor.execute("""
                    INSERT OR REPLACE INTO fim_baseline 
                    (filepath, file_hash, size, mtime, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (record.filepath, record.file_hash, record.size, record.mtime, record.created_at))
            else:
                cursor.execute("""
                    UPDATE fim_baseline 
                    SET file_hash = ?, size = ?, mtime = ?
                    WHERE filepath = ?
                """, (record.file_hash, record.size, record.mtime, record.filepath))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error updating baseline DB: {e}")
    
    def store_audit_entry(self, entry: Dict[str, Any]):
        """Store an audit entry in the database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO fim_audit_log 
                (event_type, filepath, dest_path, file_hash, size, timestamp, severity, violation_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry["event_type"],
                entry["filepath"],
                entry.get("dest_path"),
                entry.get("file_hash"),
                entry.get("size"),
                entry["timestamp"],
                entry.get("severity", "medium"),
                0
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error storing audit entry: {e}")
    
    def check_integrity_violation(self, filepath: str, current_entry: Dict[str, Any]) -> bool:
        """Check if a file change represents an integrity violation."""
        if filepath not in self.baseline_hashes:
            return False  # New file, not necessarily a violation
        
        baseline = self.baseline_hashes[filepath]
        current_hash = current_entry.get("file_hash")
        
        if current_hash and current_hash != baseline.file_hash:
            # Hash mismatch - potential tampering
            logger.warning(f"FIM VIOLATION: Hash mismatch for {filepath}")
            logger.warning(f"  Baseline: {baseline.file_hash}")
            logger.warning(f"  Current:  {current_hash}")
            
            # Mark as violation in audit log
            self._mark_violation(filepath, current_entry["timestamp"])
            return True
        
        return False
    
    def _mark_violation(self, filepath: str, timestamp: str):
        """Mark an audit entry as a violation."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE fim_audit_log 
                SET violation_detected = 1
                WHERE filepath = ? AND timestamp = ?
            """, (filepath, timestamp))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error marking violation: {e}")
    
    def start(self):
        """Start the file integrity monitoring service."""
        if self.is_running:
            logger.warning("FIM service already running")
            return
        
        event_handler = FileIntegrityHandler(self)
        self.observer = Observer()
        
        for path in self.watched_paths:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=True)
                logger.info(f"Started monitoring: {path}")
        
        self.observer.start()
        self.is_running = True
        logger.info("FIM service started")
    
    def stop(self):
        """Stop the file integrity monitoring service."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            logger.info("FIM service stopped")
    
    def get_audit_log(self, limit: int = 100, violations_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieve audit log entries."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if violations_only:
                cursor.execute("""
                    SELECT * FROM fim_audit_log 
                    WHERE violation_detected = 1
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
            else:
                cursor.execute("""
                    SELECT * FROM fim_audit_log 
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
            
            columns = ["id", "event_type", "filepath", "dest_path", "file_hash", "size", "timestamp", "severity", "violation_detected"]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving audit log: {e}")
            return []
    
    def get_baseline_status(self) -> Dict[str, Any]:
        """Get current baseline status."""
        return {
            "total_files": len(self.baseline_hashes),
            "watched_paths": list(self.watched_paths),
            "is_running": self.is_running
        }


# Global instance
fim_service = FileIntegrityMonitor()
