"""
Notifications API Router
Configure and manage notification channels
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import Optional, List

from backend.routers.auth import get_current_user, require_role
from backend.middleware.security import limiter, audit_logger
from backend.services.notification_service import (
    notification_service, configure_notifications, NotificationConfig
)

router = APIRouter()


@router.get("/config")
async def get_notification_config(current_user: dict = Depends(get_current_user)):
    """Get current notification configuration"""
    config = notification_service.config
    
    # Return masked config (hide sensitive tokens)
    return {
        "telegram_configured": bool(config.telegram_bot_token),
        "discord_configured": bool(config.discord_webhook_url),
        "slack_configured": bool(config.slack_webhook_url),
        "enabled_channels": config.enabled_channels
    }


@router.post("/configure")
async def configure_notification_settings(
    config_data: dict,
    current_user: dict = Depends(require_role("admin"))
):
    """Configure notification channels (admin only)"""
    telegram_token = config_data.get("telegram_bot_token")
    telegram_chat = config_data.get("telegram_chat_id")
    discord_url = config_data.get("discord_webhook_url")
    slack_url = config_data.get("slack_webhook_url")
    channels = config_data.get("enabled_channels", [])
    
    configure_notifications(
        telegram_token=telegram_token,
        telegram_chat=telegram_chat,
        discord_url=discord_url,
        slack_url=slack_url,
        channels=channels
    )
    
    audit_logger.log_event(
        event_type="NOTIFICATION_CONFIG",
        user=current_user["username"],
        action="CONFIG_UPDATED",
        details={"channels": channels}
    )
    
    return {
        "success": True,
        "message": "Notification settings updated",
        "enabled_channels": channels
    }


@router.post("/test/telegram")
@limiter.limit("5/minute")
async def test_telegram_notification(
    request,
    test_data: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Send a test notification to Telegram"""
    message = test_data.get("message", "Test notification from AI Security Dashboard") if test_data else "Test notification from AI Security Dashboard"
    
    success = await notification_service.send_telegram(message)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send Telegram notification. Check configuration."
        )
    
    return {"success": True, "message": "Test notification sent to Telegram"}


@router.post("/test/discord")
@limiter.limit("5/minute")
async def test_discord_notification(
    request,
    test_data: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Send a test notification to Discord"""
    success = await notification_service.send_discord(
        title="🧪 Test Notification",
        description="This is a test notification from the AI Security Dashboard",
        color=0x0ea5e9
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send Discord notification. Check configuration."
        )
    
    return {"success": True, "message": "Test notification sent to Discord"}


@router.post("/test/slack")
@limiter.limit("5/minute")
async def test_slack_notification(
    request,
    test_data: Optional[dict] = None,
    current_user: dict = Depends(require_role("admin"))
):
    """Send a test notification to Slack"""
    success = await notification_service.send_slack(
        text="🧪 *Test Notification* - This is a test from the AI Security Dashboard"
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send Slack notification. Check configuration."
        )
    
    return {"success": True, "message": "Test notification sent to Slack"}


@router.post("/test/all")
@limiter.limit("3/minute")
async def test_all_notifications(
    request,
    current_user: dict = Depends(require_role("admin"))
):
    """Send test notifications to all configured channels"""
    results = {}
    
    config = notification_service.config
    
    if "telegram" in config.enabled_channels and config.telegram_bot_token:
        results["telegram"] = await notification_service.send_telegram(
            "🧪 Test notification from AI Security Dashboard"
        )
    
    if "discord" in config.enabled_channels and config.discord_webhook_url:
        results["discord"] = await notification_service.send_discord(
            title="🧪 Test Notification",
            description="Testing all channels from AI Security Dashboard",
            color=0x0ea5e9
        )
    
    if "slack" in config.enabled_channels and config.slack_webhook_url:
        results["slack"] = await notification_service.send_slack(
            "🧪 *Test Notification* - Testing all channels"
        )
    
    return {
        "success": True,
        "results": results,
        "summary": f"{sum(results.values())}/{len(results)} channels received test notification"
    }


@router.post("/alert/resource")
@limiter.limit("10/minute")
async def send_resource_alert(
    alert_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Send a resource usage alert"""
    resource_type = alert_data.get("resource_type", "CPU")
    value = alert_data.get("value", 0)
    threshold = alert_data.get("threshold", 90)
    
    success = await notification_service.send_resource_alert(
        resource_type, value, threshold
    )
    
    return {"success": success}


@router.post("/alert/threat")
@limiter.limit("10/minute")
async def send_threat_alert(
    alert_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Send a security threat alert"""
    title = alert_data.get("title", "Unknown Threat")
    severity = alert_data.get("severity", "MEDIUM")
    source = alert_data.get("source", "Manual")
    cve_id = alert_data.get("cve_id")
    affected = alert_data.get("affected_systems", "Unknown")
    
    success = await notification_service.send_threat_alert(
        title, severity, source, cve_id, affected
    )
    
    return {"success": success}
