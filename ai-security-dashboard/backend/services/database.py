"""
SQLite Database Manager with Vector Storage Support
Handles system metrics, threat alerts, and skill logging
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from contextlib import contextmanager
import os

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages SQLite database for metrics, threats, and skills"""
    
    def __init__(self, db_path: str = "security_dashboard.db"):
        self.db_path = db_path
        self._ensure_db_directory()
    
    def _ensure_db_directory(self):
        """Ensure the database directory exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # System metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    cpu_percent REAL NOT NULL,
                    memory_percent REAL NOT NULL,
                    memory_used INTEGER NOT NULL,
                    memory_total INTEGER NOT NULL,
                    disk_percent REAL NOT NULL,
                    network_sent INTEGER NOT NULL,
                    network_recv INTEGER NOT NULL,
                    process_count INTEGER NOT NULL
                )
            """)
            
            # Threat alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    url TEXT,
                    cve_id TEXT,
                    affected_systems TEXT,
                    published_date TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Skills log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS skills_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT NOT NULL,
                    code_path TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp 
                ON system_metrics(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_severity 
                ON threat_alerts(severity)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_created 
                ON threat_alerts(created_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_skills_category 
                ON skills_log(category)
            """)
            
            conn.commit()
            logger.info("Database initialized successfully")
    
    def insert_metric(self, metric_data: Dict[str, Any]) -> int:
        """Insert a system metric record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_metrics 
                (timestamp, cpu_percent, memory_percent, memory_used, memory_total,
                 disk_percent, network_sent, network_recv, process_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metric_data.get("timestamp", datetime.utcnow().isoformat()),
                metric_data["cpu_percent"],
                metric_data["memory_percent"],
                metric_data["memory_used"],
                metric_data["memory_total"],
                metric_data["disk_percent"],
                metric_data["network_sent"],
                metric_data["network_recv"],
                metric_data["process_count"]
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_metrics_history(self, hours: int = 24, limit: int = 1000) -> List[Dict]:
        """Get metrics history for the specified time period"""
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM system_metrics 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (cutoff_time, limit))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def insert_threat(self, threat_data: Dict[str, Any]) -> int:
        """Insert a threat alert record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check for duplicate CVE
            if threat_data.get("cve_id"):
                cursor.execute("""
                    SELECT id FROM threat_alerts WHERE cve_id = ?
                """, (threat_data["cve_id"],))
                if cursor.fetchone():
                    logger.info(f"Duplicate CVE {threat_data['cve_id']}, skipping")
                    return -1
            
            cursor.execute("""
                INSERT INTO threat_alerts 
                (title, source, severity, description, url, cve_id, 
                 affected_systems, published_date, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat_data["title"],
                threat_data["source"],
                threat_data["severity"],
                threat_data["description"],
                threat_data.get("url"),
                threat_data.get("cve_id"),
                threat_data.get("affected_systems"),
                threat_data.get("published_date"),
                threat_data.get("created_at", datetime.utcnow().isoformat())
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_threats(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict]:
        """Get threat alerts, optionally filtered by severity"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute("""
                    SELECT * FROM threat_alerts 
                    WHERE severity = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (severity, limit))
            else:
                cursor.execute("""
                    SELECT * FROM threat_alerts 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of threats by severity level"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM threat_alerts 
                GROUP BY severity
            """)
            
            return {row["severity"]: row["count"] for row in cursor.fetchall()}
    
    def insert_skill(self, skill_data: Dict[str, Any]) -> int:
        """Insert a skill log record"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            metadata_json = None
            if skill_data.get("metadata"):
                metadata_json = json.dumps(skill_data["metadata"])
            
            cursor.execute("""
                INSERT INTO skills_log 
                (skill_name, category, description, code_path, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                skill_data["skill_name"],
                skill_data["category"],
                skill_data["description"],
                skill_data.get("code_path"),
                metadata_json,
                skill_data.get("created_at", datetime.utcnow().isoformat())
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_skills(self, category: Optional[str] = None) -> List[Dict]:
        """Get all logged skills, optionally filtered by category"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if category:
                cursor.execute("""
                    SELECT * FROM skills_log 
                    WHERE category = ? 
                    ORDER BY created_at DESC
                """, (category,))
            else:
                cursor.execute("""
                    SELECT * FROM skills_log 
                    ORDER BY created_at DESC
                """)
            
            rows = cursor.fetchall()
            result = []
            for row in rows:
                row_dict = dict(row)
                if row_dict.get("metadata"):
                    try:
                        row_dict["metadata"] = json.loads(row_dict["metadata"])
                    except json.JSONDecodeError:
                        pass
                result.append(row_dict)
            
            return result
    
    def get_skill_categories(self) -> List[str]:
        """Get all unique skill categories"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT category FROM skills_log
            """)
            return [row["category"] for row in cursor.fetchall()]
    
    def cleanup_old_metrics(self, days: int = 7) -> int:
        """Remove metrics older than specified days"""
        cutoff_time = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM system_metrics WHERE timestamp < ?
            """, (cutoff_time,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted
