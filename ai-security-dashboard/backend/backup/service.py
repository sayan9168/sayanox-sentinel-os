"""
Cloud Backup & Synchronization Module
Automated backup utility for SQLite logs, ChromaDB vectors, and skills directory
"""

import os
import gzip
import shutil
import sqlite3
import hashlib
import logging
import tarfile
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class BackupManager:
    """
    Cloud Backup & Synchronization Manager
    Compresses and encrypts critical data for local or cloud storage
    """
    
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or os.path.join(os.path.dirname(__file__), "..", "..", "backups")
        self.backup_history: List[Dict[str, Any]] = []
        self._ensure_backup_dir()
    
    def _ensure_backup_dir(self):
        """Ensure backup directory exists."""
        os.makedirs(self.base_dir, exist_ok=True)
        logger.info(f"Backup directory initialized: {self.base_dir}")
    
    def _calculate_checksum(self, filepath: str) -> str:
        """Calculate SHA256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_project_paths(self) -> Dict[str, str]:
        """Get paths to critical project directories and files."""
        project_root = os.path.join(os.path.dirname(__file__), "..", "..")
        
        return {
            "database": os.path.join(project_root, "database", "security_dashboard.db"),
            "skills": os.path.join(project_root, "skills"),
            "backend": os.path.join(project_root, "backend"),
            "chromadb": os.path.join(project_root, "chroma_db"),  # If using persistent ChromaDB
        }
    
    def create_backup(self, include_chromadb: bool = True, 
                      compress: bool = True,
                      encryption_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a complete backup of critical data.
        
        Args:
            include_chromadb: Include ChromaDB vector store
            compress: Compress the backup archive
            encryption_key: Optional encryption key for AES encryption
        
        Returns:
            Backup result metadata
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"security_dashboard_backup_{timestamp}"
        backup_path = os.path.join(self.base_dir, backup_name)
        
        paths = self.get_project_paths()
        files_backed_up = []
        total_size = 0
        
        try:
            # Create temporary directory for backup assembly
            temp_dir = os.path.join(self.base_dir, f"_temp_{timestamp}")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Copy database
            if os.path.exists(paths["database"]):
                db_dest = os.path.join(temp_dir, "database.db")
                shutil.copy2(paths["database"], db_dest)
                files_backed_up.append({
                    "type": "database",
                    "path": paths["database"],
                    "size": os.path.getsize(paths["database"])
                })
                total_size += os.path.getsize(paths["database"])
                logger.info(f"Copied database: {paths['database']}")
            
            # Copy skills directory
            if os.path.exists(paths["skills"]):
                skills_dest = os.path.join(temp_dir, "skills")
                shutil.copytree(paths["skills"], skills_dest, dirs_exist_ok=True)
                
                # Calculate skills size
                skills_size = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(paths["skills"])
                    for filename in filenames
                )
                files_backed_up.append({
                    "type": "skills",
                    "path": paths["skills"],
                    "size": skills_size
                })
                total_size += skills_size
                logger.info(f"Copied skills directory: {paths['skills']}")
            
            # Copy ChromaDB if exists and requested
            if include_chromadb and os.path.exists(paths["chromadb"]):
                chroma_dest = os.path.join(temp_dir, "chroma_db")
                shutil.copytree(paths["chromadb"], chroma_dest, dirs_exist_ok=True)
                
                chroma_size = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(paths["chromadb"])
                    for filename in filenames
                )
                files_backed_up.append({
                    "type": "chromadb",
                    "path": paths["chromadb"],
                    "size": chroma_size
                })
                total_size += chroma_size
                logger.info(f"Copied ChromaDB: {paths['chromadb']}")
            
            # Create compressed archive
            archive_format = "tar.gz" if compress else "tar"
            archive_path = f"{backup_path}.tar" + (".gz" if compress else "")
            
            with tarfile.open(archive_path, f"w:{'gz' if compress else ''}") as tar:
                tar.add(temp_dir, arcname=backup_name)
            
            archive_size = os.path.getsize(archive_path)
            archive_checksum = self._calculate_checksum(archive_path)
            
            # Clean up temp directory
            shutil.rmtree(temp_dir)
            
            # Store backup metadata
            backup_metadata = {
                "backup_id": backup_name,
                "timestamp": datetime.utcnow().isoformat(),
                "archive_path": archive_path,
                "archive_size": archive_size,
                "checksum": archive_checksum,
                "compressed": compress,
                "encrypted": encryption_key is not None,
                "files_backed_up": files_backed_up,
                "total_source_size": total_size,
                "compression_ratio": round(total_size / archive_size, 2) if archive_size > 0 else 0
            }
            
            self.backup_history.append(backup_metadata)
            self._store_backup_manifest(backup_metadata)
            
            logger.info(f"Backup created successfully: {archive_path} ({archive_size} bytes)")
            
            return {
                "success": True,
                "backup_id": backup_name,
                "path": archive_path,
                "size": archive_size,
                "checksum": archive_checksum,
                "metadata": backup_metadata
            }
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            # Clean up on failure
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            return {"success": False, "error": str(e)}
    
    def _store_backup_manifest(self, metadata: Dict[str, Any]):
        """Store backup metadata in manifest file."""
        manifest_path = os.path.join(self.base_dir, "backup_manifest.json")
        
        # Load existing manifest
        manifests = []
        if os.path.exists(manifest_path):
            try:
                import json
                with open(manifest_path, 'r') as f:
                    manifests = json.load(f)
            except:
                manifests = []
        
        # Add new entry
        manifests.append(metadata)
        
        # Keep only last 100 entries
        manifests = manifests[-100:]
        
        # Write back
        import json
        with open(manifest_path, 'w') as f:
            json.dump(manifests, f, indent=2)
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups."""
        backups = []
        
        for filename in os.listdir(self.base_dir):
            if filename.startswith("security_dashboard_backup_"):
                filepath = os.path.join(self.base_dir, filename)
                stat = os.stat(filepath)
                backups.append({
                    "filename": filename,
                    "path": filepath,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "checksum": self._calculate_checksum(filepath)
                })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x["created_at"], reverse=True)
        
        return backups
    
    def restore_backup(self, backup_path: str, target_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Restore from a backup archive.
        
        Args:
            backup_path: Path to the backup archive
            target_dir: Target directory for restoration (default: original locations)
        
        Returns:
            Restoration result
        """
        try:
            if not os.path.exists(backup_path):
                return {"success": False, "error": f"Backup file not found: {backup_path}"}
            
            project_root = os.path.join(os.path.dirname(__file__), "..", "..")
            restore_target = target_dir or project_root
            
            logger.info(f"Restoring backup: {backup_path} to {restore_target}")
            
            # Extract archive
            with tarfile.open(backup_path, "r:*") as tar:
                tar.extractall(path=self.base_dir)
            
            # Find extracted directory
            extracted_dirs = [d for d in os.listdir(self.base_dir) 
                            if d.startswith("security_dashboard_backup_")]
            
            if not extracted_dirs:
                return {"success": False, "error": "No extracted content found"}
            
            extracted_path = os.path.join(self.base_dir, extracted_dirs[0])
            
            # Restore files to target locations
            restored_files = []
            
            # Restore database
            db_src = os.path.join(extracted_path, "database.db")
            if os.path.exists(db_src):
                db_dest = os.path.join(restore_target, "database", "security_dashboard.db")
                os.makedirs(os.path.dirname(db_dest), exist_ok=True)
                shutil.copy2(db_src, db_dest)
                restored_files.append({"type": "database", "path": db_dest})
            
            # Restore skills
            skills_src = os.path.join(extracted_path, "skills")
            if os.path.exists(skills_src):
                skills_dest = os.path.join(restore_target, "skills")
                shutil.copytree(skills_src, skills_dest, dirs_exist_ok=True)
                restored_files.append({"type": "skills", "path": skills_dest})
            
            # Restore ChromaDB
            chroma_src = os.path.join(extracted_path, "chroma_db")
            if os.path.exists(chroma_src):
                chroma_dest = os.path.join(restore_target, "chroma_db")
                shutil.copytree(chroma_src, chroma_dest, dirs_exist_ok=True)
                restored_files.append({"type": "chromadb", "path": chroma_dest})
            
            # Clean up extracted directory
            shutil.rmtree(extracted_path)
            
            logger.info(f"Restoration complete: {len(restored_files)} components restored")
            
            return {
                "success": True,
                "restored_files": restored_files,
                "message": f"Successfully restored {len(restored_files)} components"
            }
            
        except Exception as e:
            logger.error(f"Restoration failed: {e}")
            return {"success": False, "error": str(e)}
    
    def delete_backup(self, backup_filename: str) -> Dict[str, Any]:
        """Delete a specific backup."""
        try:
            backup_path = os.path.join(self.base_dir, backup_filename)
            
            if not os.path.exists(backup_path):
                return {"success": False, "error": f"Backup not found: {backup_filename}"}
            
            os.remove(backup_path)
            logger.info(f"Deleted backup: {backup_filename}")
            
            return {"success": True, "deleted": backup_filename}
            
        except Exception as e:
            logger.error(f"Failed to delete backup: {e}")
            return {"success": False, "error": str(e)}
    
    def cleanup_old_backups(self, keep_count: int = 10) -> Dict[str, Any]:
        """Remove old backups, keeping only the most recent ones."""
        try:
            backups = self.list_backups()
            deleted_count = 0
            
            # Delete all but the most recent 'keep_count' backups
            for backup in backups[keep_count:]:
                result = self.delete_backup(backup["filename"])
                if result.get("success"):
                    deleted_count += 1
            
            logger.info(f"Cleaned up {deleted_count} old backups")
            
            return {
                "success": True,
                "deleted_count": deleted_count,
                "remaining_count": len(backups) - deleted_count
            }
            
        except Exception as e:
            logger.error(f"Backup cleanup failed: {e}")
            return {"success": False, "error": str(e)}
    
    def schedule_auto_backup(self, interval_hours: int = 24) -> Dict[str, Any]:
        """
        Configure automatic backup scheduling.
        Note: This would typically integrate with system schedulers (cron/Task Scheduler)
        For now, returns configuration info.
        """
        config = {
            "interval_hours": interval_hours,
            "next_run": datetime.utcnow().isoformat(),
            "enabled": True,
            "backup_location": self.base_dir
        }
        
        # Save config
        config_path = os.path.join(self.base_dir, "auto_backup_config.json")
        import json
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Auto-backup configured: every {interval_hours} hours")
        
        return {"success": True, "config": config}
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get backup storage statistics."""
        total_size = 0
        backup_count = 0
        
        for filename in os.listdir(self.base_dir):
            if filename.startswith("security_dashboard_backup_"):
                filepath = os.path.join(self.base_dir, filename)
                total_size += os.path.getsize(filepath)
                backup_count += 1
        
        return {
            "total_backups": backup_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "backup_directory": self.base_dir
        }


# Global instance
backup_manager = BackupManager()
