"""
Notification Service
Multi-channel alerts for Telegram, Discord, and Slack
"""

import aiohttp
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Notification channel configuration"""
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    enabled_channels: List[str] = None
    
    def __post_init__(self):
        if self.enabled_channels is None:
            self.enabled_channels = []


class NotificationService:
    """
    Multi-channel notification service for security alerts
    """
    
    def __init__(self, config: Optional[NotificationConfig] = None):
        self.config = config or NotificationConfig()
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def send_telegram(self, message: str, parse_mode: str = "HTML") -> bool:
        """Send notification to Telegram"""
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            logger.warning("Telegram not configured")
            return False
        
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": message,
            "parse_mode": parse_mode
        }
        
        try:
            session = await self._get_session()
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    logger.info(f"Telegram notification sent")
                    return True
                else:
                    error = await response.text()
                    logger.error(f"Telegram error: {error}")
                    return False
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False
    
    async def send_discord(self, title: str, description: str, 
                           color: int = 0x0ea5e9, fields: Optional[List[Dict]] = None) -> bool:
        """Send notification to Discord webhook"""
        if not self.config.discord_webhook_url:
            logger.warning("Discord not configured")
            return False
        
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {
                "text": "AI Security Dashboard",
                "icon_url": "https://example.com/icon.png"
            }
        }
        
        if fields:
            embed["fields"] = fields
        
        payload = {"embeds": [embed]}
        
        try:
            session = await self._get_session()
            async with session.post(
                self.config.discord_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status in (200, 204):
                    logger.info(f"Discord notification sent")
                    return True
                else:
                    error = await response.text()
                    logger.error(f"Discord error: {error}")
                    return False
        except Exception as e:
            logger.error(f"Discord send failed: {e}")
            return False
    
    async def send_slack(self, text: str, blocks: Optional[List[Dict]] = None) -> bool:
        """Send notification to Slack webhook"""
        if not self.config.slack_webhook_url:
            logger.warning("Slack not configured")
            return False
        
        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        
        try:
            session = await self._get_session()
            async with session.post(
                self.config.slack_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    logger.info(f"Slack notification sent")
                    return True
                else:
                    error = await response.text()
                    logger.error(f"Slack error: {error}")
                    return False
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False
    
    async def send_alert(self, alert_type: str, severity: str, 
                         title: str, details: Dict[str, Any]) -> bool:
        """
        Send alert to all configured channels
        """
        results = []
        
        # Format message based on severity
        emoji = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "⚡", "LOW": "ℹ️"}.get(severity, "📢")
        color_map = {"CRITICAL": 0xdc2626, "HIGH": 0xea580c, "MEDIUM": 0xeab308, "LOW": 0x22c55e}
        color = color_map.get(severity, 0x0ea5e9)
        
        # Telegram message
        telegram_msg = f"{emoji} *{severity}* - {title}\n\n"
        for key, value in details.items():
            telegram_msg += f"• {key}: {value}\n"
        telegram_msg += f"\n_Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}_"
        
        # Discord fields
        discord_fields = [
            {"name": k, "value": str(v), "inline": True}
            for k, v in details.items()
        ]
        
        # Slack blocks
        slack_blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {severity}: {title}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{k}*:\n{v}"}
                    for k, v in details.items()
                ]
            }
        ]
        
        # Send to enabled channels
        if "telegram" in self.config.enabled_channels:
            results.append(await self.send_telegram(telegram_msg, parse_mode="Markdown"))
        
        if "discord" in self.config.enabled_channels:
            results.append(await self.send_discord(
                title=f"{emoji} {severity}: {title}",
                description="\n".join(f"**{k}**: {v}" for k, v in details.items()),
                color=color,
                fields=discord_fields
            ))
        
        if "slack" in self.config.enabled_channels:
            results.append(await self.send_slack(
                text=f"{emoji} *{severity}* - {title}",
                blocks=slack_blocks
            ))
        
        return any(results)
    
    async def send_resource_alert(self, resource_type: str, value: float, 
                                  threshold: float) -> bool:
        """Send high resource usage alert"""
        severity = "CRITICAL" if value > 95 else "HIGH"
        
        return await self.send_alert(
            alert_type="RESOURCE_WARNING",
            severity=severity,
            title=f"High {resource_type} Usage Detected",
            details={
                "Resource": resource_type,
                "Current Value": f"{value:.1f}%",
                "Threshold": f"{threshold:.1f}%",
                "Status": "Exceeded" if value > threshold else "Warning"
            }
        )
    
    async def send_threat_alert(self, threat_title: str, severity: str,
                                source: str, cve_id: Optional[str],
                                affected: str) -> bool:
        """Send security threat alert"""
        return await self.send_alert(
            alert_type="THREAT_DETECTED",
            severity=severity,
            title=threat_title,
            details={
                "Source": source,
                "CVE ID": cve_id or "N/A",
                "Affected Systems": affected[:100] + "..." if len(affected) > 100 else affected
            }
        )
    
    async def send_command_alert(self, user: str, command: str, 
                                 risk_level: str) -> bool:
        """Send high-risk command execution alert"""
        return await self.send_alert(
            alert_type="COMMAND_EXECUTION",
            severity=risk_level,
            title=f"High-Risk Command Executed",
            details={
                "User": user,
                "Command": command[:80] + "..." if len(command) > 80 else command,
                "Risk Level": risk_level
            }
        )


# Global notification service instance
notification_service = NotificationService()


def configure_notifications(telegram_token: Optional[str] = None,
                           telegram_chat: Optional[str] = None,
                           discord_url: Optional[str] = None,
                           slack_url: Optional[str] = None,
                           channels: Optional[List[str]] = None):
    """Configure notification service"""
    notification_service.config = NotificationConfig(
        telegram_bot_token=telegram_token,
        telegram_chat_id=telegram_chat,
        discord_webhook_url=discord_url,
        slack_webhook_url=slack_url,
        enabled_channels=channels or []
    )
