"""
Backup & Synchronization Service
Compresses and encrypts SQLite logs, ChromaDB vectors, and skills directory
Supports local storage and cloud endpoints
"""

import os
import shutil
import tarfile
import gzip
import hashlib
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass
import base64

logger = logging.getLogger(__name__)


@dataclass
class BackupManifest:
    """Manifest describing a backup archive"""
    backup_id: str
    created_at: str
    source_paths: List[str]
    archive_path: str
    archive_size: int
    checksum_sha256: str
    encryption_enabled: bool
    compression_level: int
    included_files: int
    total_size_bytes: int


class BackupService:
    """
    Automated backup service for security dashboard data
    Supports compression, encryption, and cloud synchronization
    """
    
    def __init__(self, backup_dir: str = "./backup"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.default_sources = {
            "database": "./security_dashboard.db",
            "skills": "./skills",
            "logs": "./logs",
            "config": "./backend/config"
        }
        
        self.backup_history: List[BackupManifest] = []
        self.cloud_config: Optional[Dict[str, Any]] = None
    
    def configure_cloud(self, provider: str, config: Dict[str, Any]):
        """Configure cloud backup destination"""
        self.cloud_config = {
            "provider": provider,  # s3, gcs, azure, sftp
            "config": config
        }
        logger.info(f"Cloud backup configured for {provider}")
    
    def create_backup(self, 
                     sources: Optional[Dict[str, str]] = None,
                     compression_level: int = 6,
                     encrypt: bool = False,
                     encryption_key: Optional[str] = None) -> BackupManifest:
        """
        Create a compressed backup archive
        
        Args:
            sources: Dictionary of name -> path mappings
            compression_level: Gzip compression level (1-9)
            encrypt: Whether to encrypt the backup
            encryption_key: Base64-encoded encryption key
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_id = f"backup_{timestamp}"
        
        sources = sources or self.default_sources
        existing_sources = {}
        total_files = 0
        total_size = 0
        
        # Verify source paths exist
        for name, path in sources.items():
            src_path = Path(path)
            if src_path.exists():
                existing_sources[name] = str(src_path)
                if src_path.is_file():
                    total_files += 1
                    total_size += src_path.stat().st_size
                elif src_path.is_dir():
                    file_count = sum(1 for _ in src_path.rglob("*") if _.is_file())
                    total_files += file_count
                    total_size += sum(f.stat().st_size for f in src_path.rglob("*") if f.is_file())
                    logger.info(f"Directory {path}: {file_count} files")
        
        if not existing_sources:
            raise ValueError("No valid source paths found")
        
        # Create archive
        archive_name = f"{backup_id}.tar.gz"
        archive_path = self.backup_dir / archive_name
        
        with tarfile.open(archive_path, "w:gz", compresslevel=compression_level) as tar:
            for name, path in existing_sources.items():
                # Add with arcname to preserve structure
                arcname = f"backup_{timestamp}/{name}"
                tar.add(path, arcname=arcname)
                logger.info(f"Added {name} ({path}) to backup")
        
        # Calculate checksum
        checksum = self._calculate_checksum(archive_path)
        archive_size = archive_path.stat().st_size
        
        # Optional encryption
        encryption_enabled = False
        if encrypt and encryption_key:
            try:
                encrypted_path = self._encrypt_file(archive_path, encryption_key)
                archive_path.unlink()  # Remove unencrypted
                archive_path = encrypted_path
                archive_name = f"{backup_id}.tar.gz.enc"
                encryption_enabled = True
                logger.info(f"Backup encrypted: {archive_name}")
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
        
        manifest = BackupManifest(
            backup_id=backup_id,
            created_at=datetime.utcnow().isoformat(),
            source_paths=list(existing_sources.values()),
            archive_path=str(archive_path),
            archive_size=archive_size,
            checksum_sha256=checksum,
            encryption_enabled=encryption_enabled,
            compression_level=compression_level,
            included_files=total_files,
            total_size_bytes=total_size
        )
        
        self.backup_history.append(manifest)
        
        # Keep only last 50 manifests in memory
        if len(self.backup_history) > 50:
            self.backup_history = self.backup_history[-50:]
        
        logger.info(f"Backup created: {archive_name} ({archive_size} bytes)")
        
        # Upload to cloud if configured
        if self.cloud_config:
            try:
                self._upload_to_cloud(archive_path, manifest)
            except Exception as e:
                logger.error(f"Cloud upload failed: {e}")
        
        return manifest
    
    def _calculate_checksum(self, filepath: Path) -> str:
        """Calculate SHA256 checksum of a file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _encrypt_file(self, input_path: Path, key: str) -> Path:
        """
        Simple XOR-based encryption for backup files
        Note: For production, use proper encryption like AES via cryptography library
        """
        output_path = input_path.with_suffix(input_path.suffix + ".enc")
        
        # Decode key or use default
        try:
            key_bytes = base64.b64decode(key)
        except Exception:
            key_bytes = key.encode()[:32].ljust(32, b'\0')
        
        # Simple XOR encryption (replace with proper crypto in production)
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            key_index = 0
            while chunk := f_in.read(4096):
                encrypted = bytes(b ^ key_bytes[key_index % len(key_bytes)] 
                                 for b in chunk)
                f_out.write(encrypted)
                key_index += len(chunk)
        
        return output_path
    
    def _decrypt_file(self, input_path: Path, key: str, output_path: Path) -> bool:
        """Decrypt an encrypted backup file"""
        try:
            # Decode key
            try:
                key_bytes = base64.b64decode(key)
            except Exception:
                key_bytes = key.encode()[:32].ljust(32, b'\0')
            
            # XOR decryption (same as encryption)
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                key_index = 0
                while chunk := f_in.read(4096):
                    decrypted = bytes(b ^ key_bytes[key_index % len(key_bytes)] 
                                     for b in chunk)
                    f_out.write(decrypted)
                    key_index += len(chunk)
            
            return True
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return False
    
    def _upload_to_cloud(self, archive_path: Path, manifest: BackupManifest):
        """Upload backup to configured cloud provider"""
        if not self.cloud_config:
            return
        
        provider = self.cloud_config.get("provider")
        config = self.cloud_config.get("config", {})
        
        if provider == "s3":
            self._upload_s3(archive_path, config)
        elif provider == "gcs":
            self._upload_gcs(archive_path, config)
        elif provider == "azure":
            self._upload_azure(archive_path, config)
        elif provider == "sftp":
            self._upload_sftp(archive_path, config)
        else:
            logger.warning(f"Unknown cloud provider: {provider}")
    
    def _upload_s3(self, archive_path: Path, config: Dict[str, Any]):
        """Upload to AWS S3"""
        try:
            import boto3
            
            bucket = config.get("bucket")
            region = config.get("region", "us-east-1")
            prefix = config.get("prefix", "backups/")
            
            s3_client = boto3.client(
                "s3",
                aws_access_key_id=config.get("access_key"),
                aws_secret_access_key=config.get("secret_key"),
                region_name=region
            )
            
            key = f"{prefix}{archive_path.name}"
            s3_client.upload_file(str(archive_path), bucket, key)
            logger.info(f"Uploaded to S3: s3://{bucket}/{key}")
            
        except ImportError:
            logger.warning("boto3 not installed, skipping S3 upload")
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
    
    def _upload_gcs(self, archive_path: Path, config: Dict[str, Any]):
        """Upload to Google Cloud Storage"""
        try:
            from google.cloud import storage
            
            bucket_name = config.get("bucket")
            prefix = config.get("prefix", "backups/")
            
            client = storage.Client.from_service_account_json(
                config.get("credentials_path")
            )
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(f"{prefix}{archive_path.name}")
            blob.upload_from_filename(str(archive_path))
            
            logger.info(f"Uploaded to GCS: gs://{bucket_name}/{blob.name}")
            
        except ImportError:
            logger.warning("google-cloud-storage not installed, skipping GCS upload")
        except Exception as e:
            logger.error(f"GCS upload failed: {e}")
    
    def _upload_azure(self, archive_path: Path, config: Dict[str, Any]):
        """Upload to Azure Blob Storage"""
        try:
            from azure.storage.blob import BlobServiceClient
            
            connection_string = config.get("connection_string")
            container = config.get("container", "backups")
            prefix = config.get("prefix", "backups/")
            
            client = BlobServiceClient.from_connection_string(connection_string)
            container_client = client.get_container_client(container)
            blob_name = f"{prefix}{archive_path.name}"
            
            with open(archive_path, "rb") as f:
                container_client.upload_blob(f, name=blob_name, overwrite=True)
            
            logger.info(f"Uploaded to Azure: {container}/{blob_name}")
            
        except ImportError:
            logger.warning("azure-storage-blob not installed, skipping Azure upload")
        except Exception as e:
            logger.error(f"Azure upload failed: {e}")
    
    def _upload_sftp(self, archive_path: Path, config: Dict[str, Any]):
        """Upload to SFTP server"""
        try:
            import paramiko
            
            hostname = config.get("hostname")
            port = config.get("port", 22)
            username = config.get("username")
            password = config.get("password")
            remote_path = config.get("remote_path", "/backups/")
            
            transport = paramiko.Transport((hostname, port))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            remote_file = f"{remote_path}{archive_path.name}"
            sftp.put(str(archive_path), remote_file)
            
            logger.info(f"Uploaded via SFTP: {remote_file}")
            
            sftp.close()
            transport.close()
            
        except ImportError:
            logger.warning("paramiko not installed, skipping SFTP upload")
        except Exception as e:
            logger.error(f"SFTP upload failed: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        backups = []
        
        # From history
        for manifest in self.backup_history:
            backups.append({
                "backup_id": manifest.backup_id,
                "created_at": manifest.created_at,
                "archive_path": manifest.archive_path,
                "archive_size": manifest.archive_size,
                "checksum": manifest.checksum_sha256,
                "encrypted": manifest.encryption_enabled,
                "files_count": manifest.included_files
            })
        
        # Also scan backup directory for any missed backups
        if self.backup_dir.exists():
            for backup_file in self.backup_dir.glob("backup_*.tar.gz*"):
                if not any(b["archive_path"] == str(backup_file) for b in backups):
                    stat = backup_file.stat()
                    backups.append({
                        "backup_id": backup_file.stem.split(".tar")[0],
                        "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "archive_path": str(backup_file),
                        "archive_size": stat.st_size,
                        "checksum": self._calculate_checksum(backup_file),
                        "encrypted": backup_file.suffix == ".enc",
                        "files_count": 0
                    })
        
        return sorted(backups, key=lambda x: x["created_at"], reverse=True)
    
    def restore_backup(self, backup_id: str, 
                      decrypt_key: Optional[str] = None,
                      restore_dir: Optional[str] = None) -> bool:
        """Restore a backup to a specified directory"""
        # Find the backup
        backup = None
        for b in self.list_backups():
            if b["backup_id"] == backup_id:
                backup = b
                break
        
        if not backup:
            logger.error(f"Backup not found: {backup_id}")
            return False
        
        archive_path = Path(backup["archive_path"])
        if not archive_path.exists():
            logger.error(f"Archive file not found: {archive_path}")
            return False
        
        # Decrypt if needed
        if backup["encrypted"]:
            if not decrypt_key:
                logger.error("Encryption key required for encrypted backup")
                return False
            
            decrypted_path = archive_path.with_suffix("")
            if not self._decrypt_file(archive_path, decrypt_key, decrypted_path):
                return False
            archive_path = decrypted_path
        
        # Extract
        restore_path = Path(restore_dir) if restore_dir else self.backup_dir / f"restore_{backup_id}"
        restore_path.mkdir(parents=True, exist_ok=True)
        
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=restore_path)
            
            logger.info(f"Backup restored to: {restore_path}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def cleanup_old_backups(self, keep_days: int = 30, keep_count: int = 10) -> int:
        """Remove old backups, keeping recent ones"""
        deleted = 0
        cutoff_date = datetime.utcnow().timestamp() - (keep_days * 86400)
        
        backups = self.list_backups()
        
        # Sort by date and remove old ones beyond keep_count
        for i, backup in enumerate(backups):
            backup_time = datetime.fromisoformat(backup["created_at"]).timestamp()
            
            if i >= keep_count and backup_time < cutoff_date:
                archive_path = Path(backup["archive_path"])
                if archive_path.exists():
                    try:
                        archive_path.unlink()
                        deleted += 1
                        logger.info(f"Deleted old backup: {archive_path.name}")
                    except Exception as e:
                        logger.error(f"Failed to delete {archive_path}: {e}")
        
        return deleted
    
    def get_status(self) -> Dict[str, Any]:
        """Get backup service status"""
        return {
            "backup_dir": str(self.backup_dir),
            "total_backups": len(self.backup_history),
            "cloud_configured": self.cloud_config is not None,
            "cloud_provider": self.cloud_config.get("provider") if self.cloud_config else None,
            "recent_backups": self.list_backups()[:5],
            "default_sources": self.default_sources
        }


# Global backup service instance
backup_service = BackupService()


def configure_backup(backup_dir: str = "./backup",
                    cloud_provider: Optional[str] = None,
                    cloud_config: Optional[Dict[str, Any]] = None) -> BackupService:
    """Configure and return the backup service"""
    global backup_service
    
    backup_service = BackupService(backup_dir=backup_dir)
    
    if cloud_provider and cloud_config:
        backup_service.configure_cloud(cloud_provider, cloud_config)
    
    return backup_service
