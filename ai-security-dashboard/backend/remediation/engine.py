"""
AI Autonomous Remediation Engine
Automated fallback loop for high-severity threat response
"""

import asyncio
import logging
import subprocess
import psutil
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RemediationRule:
    """Pre-approved isolation rule for automated remediation."""
    
    def __init__(self, rule_id: str, name: str, condition: callable, action: callable):
        self.rule_id = rule_id
        self.name = name
        self.condition = condition
        self.action = action
        self.enabled = True
        self.trigger_count = 0
        self.last_triggered = None
    
    def evaluate(self, threat: Dict[str, Any]) -> bool:
        """Evaluate if the rule should be triggered."""
        if not self.enabled:
            return False
        try:
            return self.condition(threat)
        except Exception as e:
            logger.error(f"Error evaluating rule {self.rule_id}: {e}")
            return False
    
    def execute(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the remediation action."""
        try:
            result = self.action(threat)
            self.trigger_count += 1
            self.last_triggered = datetime.utcnow().isoformat()
            logger.info(f"Remediation rule '{self.name}' executed for threat: {threat.get('title', 'Unknown')}")
            return {
                "success": True,
                "rule_id": self.rule_id,
                "rule_name": self.name,
                "threat_id": threat.get("id"),
                "executed_at": self.last_triggered,
                "result": result
            }
        except Exception as e:
            logger.error(f"Error executing rule {self.rule_id}: {e}")
            return {
                "success": False,
                "rule_id": self.rule_id,
                "error": str(e)
            }


class AutonomousRemediationEngine:
    """
    AI Autonomous Remediation Engine
    Automatically triggers pre-approved isolation rules for high-severity threats
    """
    
    def __init__(self):
        self.rules: List[RemediationRule] = []
        self.remediation_log: List[Dict[str, Any]] = []
        self.is_running = False
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default pre-approved remediation rules."""
        
        # Rule 1: Auto-kill suspicious processes for critical threats
        def critical_process_condition(threat: Dict[str, Any]) -> bool:
            return (
                threat.get("severity", "").lower() in ["critical", "high"] and
                "process" in threat.get("description", "").lower()
            )
        
        def kill_suspicious_process(threat: Dict[str, Any]) -> Dict[str, Any]:
            """Kill suspicious processes mentioned in threat."""
            description = threat.get("description", "")
            killed_processes = []
            
            # Extract potential process names from description
            suspicious_keywords = ["malware", "trojan", "backdoor", "keylogger", "miner"]
            for keyword in suspicious_keywords:
                if keyword in description.lower():
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            if keyword in proc.info['name'].lower():
                                p = psutil.Process(proc.info['pid'])
                                p.terminate()
                                p.wait(timeout=3)
                                killed_processes.append({
                                    "pid": proc.info['pid'],
                                    "name": proc.info['name']
                                })
                                logger.warning(f"Killed suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                            continue
            
            return {"killed_processes": killed_processes}
        
        self.rules.append(RemediationRule(
            rule_id="AUTO_KILL_001",
            name="Auto-Kill Suspicious Processes",
            condition=critical_process_condition,
            action=kill_suspicious_process
        ))
        
        # Rule 2: Terminate unauthorized network connections
        def unauthorized_connection_condition(threat: Dict[str, Any]) -> bool:
            return (
                threat.get("severity", "").lower() in ["critical", "high"] and
                ("connection" in threat.get("description", "").lower() or
                 "network" in threat.get("description", "").lower() or
                 "remote" in threat.get("description", "").lower())
            )
        
        def terminate_connections(threat: Dict[str, Any]) -> Dict[str, Any]:
            """Terminate suspicious network connections."""
            terminated = []
            
            # Get all network connections
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Check for suspicious remote addresses
                        raddr_ip = conn.raddr.ip
                        
                        # Block known malicious IP ranges (example)
                        suspicious_ranges = ["185.220.", "45.155.", "91.219."]
                        for prefix in suspicious_ranges:
                            if raddr_ip.startswith(prefix):
                                try:
                                    proc = psutil.Process(conn.pid)
                                    proc.terminate()
                                    terminated.append({
                                        "pid": conn.pid,
                                        "remote_ip": raddr_ip,
                                        "remote_port": conn.raddr.port,
                                        "process_name": proc.name() if proc else "unknown"
                                    })
                                    logger.warning(f"Terminated connection to suspicious IP: {raddr_ip}")
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                except (psutil.AccessDenied, AttributeError):
                    continue
            
            return {"terminated_connections": terminated}
        
        self.rules.append(RemediationRule(
            rule_id="AUTO_NET_001",
            name="Terminate Unauthorized Connections",
            condition=unauthorized_connection_condition,
            action=terminate_connections
        ))
        
        # Rule 3: Isolate compromised user sessions
        def session_isolation_condition(threat: Dict[str, Any]) -> bool:
            return (
                threat.get("severity", "").lower() == "critical" and
                ("session" in threat.get("description", "").lower() or
                 "authentication" in threat.get("description", "").lower() or
                 "credential" in threat.get("description", "").lower())
            )
        
        def isolate_session(threat: Dict[str, Any]) -> Dict[str, Any]:
            """Isolate compromised user sessions."""
            # This would integrate with PAM or session management
            # For now, log the action
            logger.warning(f"Session isolation triggered for threat: {threat.get('title')}")
            return {
                "action": "session_isolation",
                "status": "logged",
                "recommendation": "Manual review required for session termination"
            }
        
        self.rules.append(RemediationRule(
            rule_id="AUTO_SESS_001",
            name="Isolate Compromised Sessions",
            condition=session_isolation_condition,
            action=isolate_session
        ))
    
    def add_rule(self, rule: RemediationRule):
        """Add a custom remediation rule."""
        self.rules.append(rule)
        logger.info(f"Added remediation rule: {rule.name}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a remediation rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                self.rules.pop(i)
                logger.info(f"Removed remediation rule: {rule_id}")
                return True
        return False
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all registered rules with their status."""
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "enabled": rule.enabled,
                "trigger_count": rule.trigger_count,
                "last_triggered": rule.last_triggered
            }
            for rule in self.rules
        ]
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a specific rule."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a specific rule."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                return True
        return False
    
    async def evaluate_threat(self, threat: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a threat against all rules and execute matching actions.
        This is the main entry point for autonomous remediation.
        """
        results = []
        severity = threat.get("severity", "").lower()
        
        # Only auto-remediate high and critical severity threats
        if severity not in ["high", "critical"]:
            logger.debug(f"Skipping auto-remediation for {severity} severity threat")
            return results
        
        logger.info(f"Evaluating threat '{threat.get('title')}' (severity: {severity}) for auto-remediation")
        
        for rule in self.rules:
            if rule.evaluate(threat):
                result = rule.execute(threat)
                results.append(result)
                self.remediation_log.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "threat": threat,
                    "rule_result": result
                })
        
        return results
    
    def get_remediation_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent remediation actions."""
        return self.remediation_log[-limit:]
    
    def clear_log(self):
        """Clear the remediation log."""
        self.remediation_log = []


# Global instance
remediation_engine = AutonomousRemediationEngine()
