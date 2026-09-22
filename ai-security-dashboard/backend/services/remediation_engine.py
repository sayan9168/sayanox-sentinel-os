"""
Autonomous Remediation Engine
Automatically responds to high-severity threats with pre-approved isolation rules
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json

logger = logging.getLogger(__name__)


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RemediationAction(str, Enum):
    KILL_PROCESS = "KILL_PROCESS"
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_CONNECTION = "ISOLATE_CONNECTION"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    DISABLE_SERVICE = "DISABLE_SERVICE"
    ALERT_ONLY = "ALERT_ONLY"


@dataclass
class RemediationRule:
    """Pre-approved remediation rule for automatic execution"""
    id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]  # Conditions that trigger this rule
    actions: List[Dict[str, Any]]  # Actions to execute
    severity_threshold: str  # Minimum severity to trigger
    enabled: bool = True
    cooldown_seconds: int = 300  # Prevent rapid re-execution
    max_executions: int = 5  # Max times this rule can execute
    execution_count: int = 0
    last_execution: Optional[datetime] = None
    
    def should_trigger(self, threat: Dict[str, Any]) -> bool:
        """Check if a threat matches this rule's conditions"""
        if not self.enabled:
            return False
        
        # Check severity threshold
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        threat_severity = severity_order.get(threat.get("severity", "LOW"), 0)
        threshold_severity = severity_order.get(self.severity_threshold, 0)
        
        if threat_severity < threshold_severity:
            return False
        
        # Check trigger conditions
        for key, expected_value in self.trigger_conditions.items():
            threat_value = threat.get(key)
            
            if isinstance(expected_value, list):
                if threat_value not in expected_value:
                    return False
            elif expected_value is not None and threat_value != expected_value:
                return False
        
        # Check cooldown
        if self.last_execution:
            cooldown_end = self.last_execution + timedelta(seconds=self.cooldown_seconds)
            if datetime.utcnow() < cooldown_end:
                return False
        
        # Check max executions
        if self.execution_count >= self.max_executions:
            return False
        
        return True
    
    def record_execution(self):
        """Record that this rule was executed"""
        self.execution_count += 1
        self.last_execution = datetime.utcnow()


@dataclass
class RemediationResult:
    """Result of a remediation action"""
    success: bool
    action: str
    target: str
    message: str
    timestamp: str
    error: Optional[str] = None


class AutonomousRemediationEngine:
    """
    Autonomous engine for automatic threat remediation
    Executes pre-approved rules without human intervention
    """
    
    def __init__(self, system_controller=None, notification_service=None, 
                 db_manager=None, approval_callback: Optional[Callable] = None):
        self.system_controller = system_controller
        self.notification_service = notification_service
        self.db_manager = db_manager
        self.approval_callback = approval_callback  # Optional human-in-loop
        
        self.rules: Dict[str, RemediationRule] = {}
        self.execution_log: List[RemediationResult] = []
        self._running = False
        self._lock = asyncio.Lock()
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default remediation rules"""
        
        # Rule 1: Kill suspicious processes with high CPU
        self.add_rule(RemediationRule(
            id="kill_high_cpu_process",
            name="Kill High CPU Process",
            description="Automatically kill processes consuming excessive CPU",
            trigger_conditions={
                "type": ["PROCESS_ANOMALY"],
                "cpu_percent": lambda x: x > 90 if isinstance(x, (int, float)) else False
            },
            actions=[
                {"type": RemediationAction.KILL_PROCESS.value, "force": True}
            ],
            severity_threshold=ThreatSeverity.HIGH.value,
            cooldown_seconds=60,
            max_executions=10
        ))
        
        # Rule 2: Block IPs from threat intelligence
        self.add_rule(RemediationRule(
            id="block_malicious_ip",
            name="Block Malicious IP",
            description="Block IPs identified as malicious by threat intelligence",
            trigger_conditions={
                "type": ["NETWORK_THREAT", "INTRUSION_ATTEMPT"],
                "source_ip": lambda x: x is not None
            },
            actions=[
                {"type": RemediationAction.BLOCK_IP.value, "reason": "Autonomous block - threat detected"}
            ],
            severity_threshold=ThreatSeverity.HIGH.value,
            cooldown_seconds=30,
            max_executions=50
        ))
        
        # Rule 3: Isolate suspicious network connections
        self.add_rule(RemediationRule(
            id="isolate_suspicious_connection",
            name="Isolate Suspicious Connection",
            description="Terminate suspicious outbound connections",
            trigger_conditions={
                "type": ["SUSPICIOUS_CONNECTION", "DATA_EXFILTRATION"],
                "destination_port": [4444, 5555, 6666, 31337, 12345]  # Common malware ports
            },
            actions=[
                {"type": RemediationAction.ISOLATE_CONNECTION.value},
                {"type": RemediationAction.BLOCK_IP.value, "reason": "Autonomous block - suspicious port"}
            ],
            severity_threshold=ThreatSeverity.CRITICAL.value,
            cooldown_seconds=10,
            max_executions=20
        ))
        
        # Rule 4: Critical CVE exploitation attempt
        self.add_rule(RemediationRule(
            id="cve_exploit_response",
            name="CVE Exploitation Response",
            description="Respond to active CVE exploitation attempts",
            trigger_conditions={
                "type": ["CVE_EXPLOIT", "EXPLOIT_ATTEMPT"],
                "cve_id": lambda x: x is not None
            },
            actions=[
                {"type": RemediationAction.BLOCK_IP.value, "reason": "CVE exploitation attempt"},
                {"type": RemediationAction.ALERT_ONLY.value}
            ],
            severity_threshold=ThreatSeverity.CRITICAL.value,
            cooldown_seconds=60,
            max_executions=30
        ))
    
    def add_rule(self, rule: RemediationRule):
        """Add a remediation rule"""
        self.rules[rule.id] = rule
        logger.info(f"Added remediation rule: {rule.name}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a remediation rule"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info(f"Removed remediation rule: {rule_id}")
            return True
        return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a specific rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a specific rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            return True
        return False
    
    async def evaluate_threat(self, threat: Dict[str, Any]) -> List[RemediationResult]:
        """Evaluate a threat against all rules and execute matching actions"""
        results = []
        
        async with self._lock:
            for rule in self.rules.values():
                if rule.should_trigger(threat):
                    logger.info(f"Rule '{rule.name}' triggered by threat: {threat.get('title', 'Unknown')}")
                    
                    # Execute actions
                    for action_config in rule.actions:
                        result = await self._execute_action(
                            action_type=action_config["type"],
                            target_data=threat,
                            action_params={k: v for k, v in action_config.items() if k != "type"},
                            rule_name=rule.name
                        )
                        results.append(result)
                        
                        # Log execution
                        self.execution_log.append(result)
                        if len(self.execution_log) > 1000:
                            self.execution_log = self.execution_log[-1000:]
                    
                    # Record rule execution
                    rule.record_execution()
                    
                    # Send notification
                    if self.notification_service:
                        try:
                            asyncio.create_task(
                                self.notification_service.send_alert(
                                    alert_type="AUTONOMOUS_REMEDIATION",
                                    severity=threat.get("severity", "HIGH"),
                                    title=f"Autonomous Remediation Executed: {rule.name}",
                                    details={
                                        "Threat": threat.get("title", "Unknown"),
                                        "Actions Taken": len(action_config),
                                        "Timestamp": datetime.utcnow().isoformat()
                                    }
                                )
                            )
                        except Exception as e:
                            logger.error(f"Failed to send remediation notification: {e}")
        
        return results
    
    async def _execute_action(self, action_type: str, target_data: Dict[str, Any],
                             action_params: Dict[str, Any], rule_name: str) -> RemediationResult:
        """Execute a single remediation action"""
        timestamp = datetime.utcnow().isoformat()
        
        try:
            if action_type == RemediationAction.KILL_PROCESS.value:
                pid = target_data.get("pid") or target_data.get("process_id")
                if not pid:
                    return RemediationResult(
                        success=False, action=action_type, target="unknown",
                        message="No PID found in threat data",
                        timestamp=timestamp
                    )
                
                force = action_params.get("force", False)
                success, message = await self.system_controller.kill_process(int(pid), force)
                
                return RemediationResult(
                    success=success, action=action_type, target=str(pid),
                    message=message, timestamp=timestamp
                )
            
            elif action_type == RemediationAction.BLOCK_IP.value:
                ip = target_data.get("source_ip") or target_data.get("ip") or target_data.get("remote_ip")
                if not ip:
                    return RemediationResult(
                        success=False, action=action_type, target="unknown",
                        message="No IP address found in threat data",
                        timestamp=timestamp
                    )
                
                reason = action_params.get("reason", "Autonomous security response")
                success, message = await self.system_controller.block_ip(ip, reason)
                
                return RemediationResult(
                    success=success, action=action_type, target=ip,
                    message=message, timestamp=timestamp
                )
            
            elif action_type == RemediationAction.ISOLATE_CONNECTION.value:
                # For now, this blocks the remote IP
                ip = target_data.get("remote_ip") or target_data.get("destination_ip")
                if not ip:
                    return RemediationResult(
                        success=False, action=action_type, target="unknown",
                        message="No connection IP found",
                        timestamp=timestamp
                    )
                
                success, message = await self.system_controller.block_ip(
                    ip, "Autonomous isolation - suspicious connection"
                )
                
                return RemediationResult(
                    success=success, action=action_type, target=ip,
                    message=message, timestamp=timestamp
                )
            
            elif action_type == RemediationAction.ALERT_ONLY.value:
                return RemediationResult(
                    success=True, action=action_type, target=target_data.get("title", "Unknown"),
                    message="Alert-only action executed",
                    timestamp=timestamp
                )
            
            else:
                return RemediationResult(
                    success=False, action=action_type, target="unknown",
                    message=f"Unknown action type: {action_type}",
                    timestamp=timestamp
                )
                
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return RemediationResult(
                success=False, action=action_type, target=str(target_data),
                message=f"Execution error: {str(e)}",
                timestamp=timestamp,
                error=str(e)
            )
    
    def get_execution_log(self, limit: int = 100) -> List[Dict]:
        """Get recent execution log entries"""
        results = []
        for entry in self.execution_log[-limit:][::-1]:
            results.append({
                "success": entry.success,
                "action": entry.action,
                "target": entry.target,
                "message": entry.message,
                "timestamp": entry.timestamp,
                "error": entry.error
            })
        return results
    
    def get_rules_status(self) -> List[Dict]:
        """Get status of all rules"""
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
                "severity_threshold": rule.severity_threshold,
                "execution_count": rule.execution_count,
                "max_executions": rule.max_executions,
                "last_execution": rule.last_execution.isoformat() if rule.last_execution else None,
                "cooldown_remaining": self._get_cooldown_remaining(rule)
            }
            for rule in self.rules.values()
        ]
    
    def _get_cooldown_remaining(self, rule: RemediationRule) -> Optional[int]:
        """Get remaining cooldown time in seconds"""
        if not rule.last_execution:
            return None
        
        elapsed = (datetime.utcnow() - rule.last_execution).total_seconds()
        remaining = rule.cooldown_seconds - elapsed
        
        return max(0, int(remaining)) if remaining > 0 else 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get remediation engine statistics"""
        total_executions = sum(r.execution_count for r in self.rules.values())
        successful = sum(1 for e in self.execution_log if e.success)
        failed = len(self.execution_log) - successful
        
        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "total_executions": total_executions,
            "successful_actions": successful,
            "failed_actions": failed,
            "recent_executions": self.get_execution_log(limit=10)
        }
    
    def is_enabled(self) -> bool:
        """Check if remediation engine is active"""
        return self._running or len(self.rules) > 0


# Global remediation engine instance
remediation_engine = AutonomousRemediationEngine()


def configure_remediation(system_controller=None, notification_service=None,
                         db_manager=None) -> AutonomousRemediationEngine:
    """Configure and return the remediation engine"""
    global remediation_engine
    
    remediation_engine.system_controller = system_controller
    remediation_engine.notification_service = notification_service
    remediation_engine.db_manager = db_manager
    
    return remediation_engine
