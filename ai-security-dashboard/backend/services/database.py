"""
SQLite Database Manager with Vector Storage Support
Handles system metrics, threat alerts, skill logging, and FIM alerts
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
    """Manages SQLite database for metrics, threats, skills, and FIM alerts"""
    
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
            
            # FIM alerts table (new for Phase 3)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS fim_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL UNIQUE,
                    file_path TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    timestamp TEXT NOT NULL
                )
            """)
            
            # Audit log table for command/process/firewall actions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    user TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT,
                    success INTEGER DEFAULT 1,
                    timestamp TEXT NOT NULL
                )
            """)
            
            # Remediation log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    threat_title TEXT,
                    action_type TEXT NOT NULL,
                    target TEXT,
                    success INTEGER DEFAULT 1,
                    message TEXT,
                    timestamp TEXT NOT NULL
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
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_fim_alerts_type 
                ON fim_alerts(alert_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_events 
                ON audit_log(event_type, timestamp)
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
    
    def insert_fim_alert(self, alert) -> int:
        """Insert a file integrity monitoring alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO fim_alerts 
                    (alert_id, file_path, alert_type, severity, description, 
                     old_hash, new_hash, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.id,
                    alert.file_path,
                    alert.alert_type,
                    alert.severity,
                    alert.description,
                    alert.old_record.hash_sha256 if alert.old_record else None,
                    alert.new_record.hash_sha256 if alert.new_record else None,
                    alert.timestamp
                ))
                conn.commit()
                return cursor.lastrowid
            except Exception as e:
                logger.error(f"Failed to insert FIM alert: {e}")
                return -1
    
    def get_fim_alerts(self, limit: int = 100, 
                       alert_type: Optional[str] = None,
                       severity: Optional[str] = None) -> List[Dict]:
        """Get FIM alerts"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if alert_type:
                conditions.append("alert_type = ?")
                params.append(alert_type)
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM fim_alerts 
                WHERE {where_clause}
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (*params, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def insert_audit_event(self, event_type: str, user: str, action: str,
                          details: Optional[Dict] = None, success: bool = True) -> int:
        """Insert an audit log event"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            details_json = json.dumps(details) if details else None
            
            cursor.execute("""
                INSERT INTO audit_log 
                (event_type, user, action, details, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_type,
                user,
                action,
                details_json,
                1 if success else 0,
                datetime.utcnow().isoformat()
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_audit_logs(self, limit: int = 100, 
                       event_type: Optional[str] = None,
                       user: Optional[str] = None) -> List[Dict]:
        """Get audit log entries"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            conditions = []
            params = []
            
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
            if user:
                conditions.append("user = ?")
                params.append(user)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            cursor.execute(f"""
                SELECT * FROM audit_log 
                WHERE {where_clause}
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (*params, limit))
            
            results = []
            for row in cursor.fetchall():
                row_dict = dict(row)
                if row_dict.get("details"):
                    try:
                        row_dict["details"] = json.loads(row_dict["details"])
                    except json.JSONDecodeError:
                        pass
                results.append(row_dict)
            
            return results
    
    def insert_remediation_event(self, rule_id: str, rule_name: str,
                                threat_title: Optional[str], action_type: str,
                                target: str, success: bool, message: str) -> int:
        """Insert a remediation action log"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remediation_log 
                (rule_id, rule_name, threat_title, action_type, target, 
                 success, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id,
                rule_name,
                threat_title,
                action_type,
                target,
                1 if success else 0,
                message,
                datetime.utcnow().isoformat()
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_remediation_logs(self, limit: int = 100) -> List[Dict]:
        """Get remediation action logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM remediation_log 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
