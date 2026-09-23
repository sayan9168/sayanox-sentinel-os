"""
Multi-Channel Notification Gateway
Integrates Telegram, Discord, and Slack webhooks for real-time alerting
"""

import os
import json
import logging
import aiohttp
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AlertMessage:
    """Standardized alert message structure."""
    title: str
    description: str
    severity: AlertSeverity
    source: str
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None


class NotificationChannel(Enum):
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SLACK = "slack"


class NotificationGateway:
    """Multi-channel notification gateway for security alerts."""
    
    def __init__(self):
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        
        # Enable/disable flags
        self.enabled_channels = []
        if self.telegram_bot_token and self.telegram_chat_id:
            self.enabled_channels.append(NotificationChannel.TELEGRAM)
        if self.discord_webhook_url:
            self.enabled_channels.append(NotificationChannel.DISCORD)
        if self.slack_webhook_url:
            self.enabled_channels.append(NotificationChannel.SLACK)
    
    async def send_alert(
        self, 
        alert: AlertMessage,
        channels: Optional[List[NotificationChannel]] = None
    ) -> Dict[str, bool]:
        """Send alert to specified channels."""
        if channels is None:
            channels = self.enabled_channels
        
        results = {}
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            if NotificationChannel.TELEGRAM in channels:
                tasks.append(self._send_telegram(session, alert))
            if NotificationChannel.DISCORD in channels:
                tasks.append(self._send_discord(session, alert))
            if NotificationChannel.SLACK in channels:
                tasks.append(self._send_slack(session, alert))
            
            if tasks:
                task_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for channel, result in zip(channels, task_results):
                    if isinstance(result, Exception):
                        logger.error(f"Failed to send to {channel.value}: {result}")
                        results[channel.value] = False
                    else:
                        results[channel.value] = True
            else:
                logger.warning("No notification channels configured")
                results["none_configured"] = False
        
        return results
    
    async def _send_telegram(self, session: aiohttp.ClientSession, alert: AlertMessage) -> bool:
        """Send alert to Telegram."""
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        
        # Format message with emoji based on severity
        emoji_map = {
            AlertSeverity.LOW: "ℹ️",
            AlertSeverity.MEDIUM: "⚠️",
            AlertSeverity.HIGH: "🚨",
            AlertSeverity.CRITICAL: "🔴 CRITICAL"
        }
        emoji = emoji_map.get(alert.severity, "📢")
        
        message = f"""
{emoji} *{alert.title}*

{alert.description}

*Source:* {alert.source}
*Severity:* {alert.severity.value.upper()}
*Time:* {alert.timestamp}
"""
        
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message.strip(),
            "parse_mode": "Markdown"
        }
        
        try:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    logger.info(f"Telegram alert sent: {alert.title}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Telegram API error: {error_text}")
                    return False
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")
            return False
    
    async def _send_discord(self, session: aiohttp.ClientSession, alert: AlertMessage) -> bool:
        """Send alert to Discord."""
        if not self.discord_webhook_url:
            return False
        
        # Color based on severity
        color_map = {
            AlertSeverity.LOW: 3447003,      # Blue
            AlertSeverity.MEDIUM: 15158332,  # Yellow
            AlertSeverity.HIGH: 15105570,    # Orange
            AlertSeverity.CRITICAL: 15548997 # Red
        }
        color = color_map.get(alert.severity, 3447003)
        
        embed = {
            "title": alert.title,
            "description": alert.description,
            "color": color,
            "fields": [
                {"name": "Source", "value": alert.source, "inline": True},
                {"name": "Severity", "value": alert.severity.value.upper(), "inline": True},
                {"name": "Timestamp", "value": alert.timestamp, "inline": False}
            ],
            "footer": {"text": "AI Security Intelligence Dashboard"},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {
            "embeds": [embed],
            "username": "Security Alert Bot"
        }
        
        try:
            async with session.post(
                self.discord_webhook_url, 
                json=payload, 
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status in [200, 204]:
                    logger.info(f"Discord alert sent: {alert.title}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Discord webhook error: {error_text}")
                    return False
        except Exception as e:
            logger.error(f"Discord send failed: {e}")
            return False
    
    async def _send_slack(self, session: aiohttp.ClientSession, alert: AlertMessage) -> bool:
        """Send alert to Slack."""
        if not self.slack_webhook_url:
            return False
        
        # Color based on severity
        color_map = {
            AlertSeverity.LOW: "#36a64f",
            AlertSeverity.MEDIUM: "#ffcc00",
            AlertSeverity.HIGH: "#ff9900",
            AlertSeverity.CRITICAL: "#ff0000"
        }
        color = color_map.get(alert.severity, "#36a64f")
        
        attachment = {
            "color": color,
            "title": alert.title,
            "text": alert.description,
            "fields": [
                {"title": "Source", "value": alert.source, "short": True},
                {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                {"title": "Timestamp", "value": alert.timestamp, "short": False}
            ],
            "footer": "AI Security Intelligence Dashboard",
            "ts": int(datetime.utcnow().timestamp())
        }
        
        payload = {
            "attachments": [attachment],
            "username": "Security Alert Bot",
            "icon_emoji": ":shield:"
        }
        
        try:
            async with session.post(
                self.slack_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    logger.info(f"Slack alert sent: {alert.title}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Slack webhook error: {error_text}")
                    return False
        except Exception as e:
            logger.error(f"Slack send failed: {e}")
            return False
    
    async def send_resource_alert(self, metric_name: str, current_value: float, threshold: float):
        """Send alert when resource usage exceeds threshold."""
        if current_value <= threshold:
            return
        
        severity = AlertSeverity.HIGH if current_value > 95 else AlertSeverity.MEDIUM
        
        alert = AlertMessage(
            title=f"High {metric_name} Usage Detected",
            description=f"{metric_name} usage has exceeded {threshold}%. Current value: {current_value:.1f}%",
            severity=severity,
            source="System Monitor",
            timestamp=datetime.utcnow().isoformat(),
            metadata={"metric": metric_name, "value": current_value, "threshold": threshold}
        )
        
        await self.send_alert(alert)
    
    async def send_threat_alert(self, threat_data: Dict[str, Any]):
        """Send alert for detected security threats."""
        severity_str = threat_data.get("severity", "low")
        severity = AlertSeverity(severity_str) if severity_str in [s.value for s in AlertSeverity] else AlertSeverity.LOW
        
        # Only send high/critical threats automatically
        if severity not in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            return
        
        alert = AlertMessage(
            title=f"Security Threat: {threat_data.get('title', 'Unknown')}",
            description=threat_data.get("description", "No description available"),
            severity=severity,
            source=threat_data.get("source", "Unknown"),
            timestamp=datetime.utcnow().isoformat(),
            metadata=threat_data
        )
        
        await self.send_alert(alert)
    
    async def send_command_alert(self, command: str, user: str, risk_level: str):
        """Send alert for high-risk terminal commands."""
        if risk_level.lower() not in ["high", "critical"]:
            return
        
        severity = AlertSeverity.CRITICAL if risk_level.lower() == "critical" else AlertSeverity.HIGH
        
        alert = AlertMessage(
            title=f"High-Risk Command Executed",
            description=f"User '{user}' executed command: `{command}`",
            severity=severity,
            source="Terminal Audit",
            timestamp=datetime.utcnow().isoformat(),
            metadata={"command": command, "user": user, "risk_level": risk_level}
        )
        
        await self.send_alert(alert)


# Singleton instance
notification_gateway = NotificationGateway()


# Import asyncio for the gather call
import asyncio
