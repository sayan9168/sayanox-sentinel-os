"""
Backup API Router
Provides endpoints for backup creation, restoration, and management
"""

from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from typing import Optional, Dict, Any, List
from datetime import datetime

from backend.routers.auth import get_current_user, require_role
from backend.services.backup_service import backup_service, configure_backup
from backend.middleware.security import limiter

router = APIRouter()


@router.get("/status")
@limiter.limit("30/minute")
async def get_backup_status(request, current_user: dict = Depends(get_current_user)):
    """Get backup service status"""
    return backup_service.get_status()


@router.post("/create")
@limiter.limit("5/hour")
async def create_backup(
    request,
    backup_config: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Create a new backup archive"""
    try:
        sources = backup_config.get("sources") if backup_config else None
        compression_level = backup_config.get("compression_level", 6) if backup_config else 6
        encrypt = backup_config.get("encrypt", False) if backup_config else False
        encryption_key = backup_config.get("encryption_key") if backup_config else None
        
        manifest = backup_service.create_backup(
            sources=sources,
            compression_level=compression_level,
            encrypt=encrypt,
            encryption_key=encryption_key
        )
        
        return {
            "message": "Backup created successfully",
            "backup_id": manifest.backup_id,
            "archive_path": manifest.archive_path,
            "archive_size": manifest.archive_size,
            "encrypted": manifest.encryption_enabled,
            "files_count": manifest.included_files,
            "checksum": manifest.checksum_sha256
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Backup failed: {str(e)}"
        )


@router.get("/list")
@limiter.limit("30/minute")
async def list_backups(request, current_user: dict = Depends(get_current_user)):
    """List all available backups"""
    return {"backups": backup_service.list_backups()}


@router.post("/restore/{backup_id}")
@limiter.limit("2/day")
async def restore_backup(
    request,
    backup_id: str,
    restore_config: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Restore a backup to a specified directory"""
    decrypt_key = restore_config.get("decrypt_key") if restore_config else None
    restore_dir = restore_config.get("restore_dir") if restore_config else None
    
    success = backup_service.restore_backup(
        backup_id=backup_id,
        decrypt_key=decrypt_key,
        restore_dir=restore_dir
    )
    
    if success:
        return {"message": f"Backup {backup_id} restored successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to restore backup"
        )


@router.post("/cleanup")
@limiter.limit("1/day")
async def cleanup_old_backups(
    request,
    cleanup_config: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Remove old backups"""
    keep_days = cleanup_config.get("keep_days", 30) if cleanup_config else 30
    keep_count = cleanup_config.get("keep_count", 10) if cleanup_config else 10
    
    deleted = backup_service.cleanup_old_backups(
        keep_days=keep_days,
        keep_count=keep_count
    )
    
    return {
        "message": f"Cleaned up {deleted} old backups",
        "deleted_count": deleted
    }


@router.post("/configure/cloud")
@limiter.limit("5/day")
async def configure_cloud_backup(
    request,
    cloud_config: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Configure cloud backup destination"""
    provider = cloud_config.get("provider")
    config = cloud_config.get("config", {})
    
    if not provider:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provider is required (s3, gcs, azure, sftp)"
        )
    
    backup_service.configure_cloud(provider, config)
    
    return {
        "message": f"Cloud backup configured for {provider}",
        "provider": provider
    }


@router.get("/test-connection")
@limiter.limit("10/minute")
async def test_cloud_connection(request, current_user: dict = Depends(get_current_user)):
    """Test cloud backup connection"""
    if not backup_service.cloud_config:
        return {
            "connected": False,
            "message": "Cloud backup not configured"
        }
    
    # Try to list existing backups as a connection test
    try:
        backups = backup_service.list_backups()
        return {
            "connected": True,
            "provider": backup_service.cloud_config.get("provider"),
            "backups_count": len(backups)
        }
    except Exception as e:
        return {
            "connected": False,
            "provider": backup_service.cloud_config.get("provider"),
            "error": str(e)
        }
