"""
Security Middleware
Rate limiting, command sanitization, and audit logging
"""

import re
import logging
import hashlib
from datetime import datetime
from typing import Optional, List, Set
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)

# Dangerous commands that require admin privileges
DANGEROUS_COMMANDS = {
    # File system destruction
    'rm -rf', 'rm -fr', 'rm -r', 'rm --no-preserve-root',
    'del /s', 'del /f', 'format', 'mkfs', 'diskpart',
    # Network attacks
    'nmap', 'masscan', 'hping', 'ddos',
    # Privilege escalation
    'sudo', 'su ', 'chmod 777', 'chown root',
    # Process killing
    'kill -9', 'killall', 'pkill', 'taskkill',
    # Firewall manipulation
    'iptables', 'firewall-cmd', 'netsh firewall', 'ufw',
    # Data exfiltration
    'curl -X POST', 'wget --post-data', 'nc -e', 'netcat',
    # Rootkit/malware
    'curl .* | bash', 'wget .* | sh', 'curl .* | sh'
}

# Command injection patterns
INJECTION_PATTERNS = [
    r';\s*\w+',           # Semicolon injection
    r'\|\s*\w+',          # Pipe injection
    r'`\w+`',             # Backtick execution
    r'\$\(\w+\)',         # Subshell execution
    r'&&\s*\w+',          # AND chain
    r'\|\|\s*\w+',        # OR chain
    r'>\s*/\w+',          # Redirect to root
    r'<\s*/\w+',          # Read from root
]

# Allowed commands for viewers
VIEWER_ALLOWED_COMMANDS = {
    'ls', 'dir', 'pwd', 'cd', 'cat', 'head', 'tail', 'less', 'more',
    'grep', 'find', 'which', 'whoami', 'uname', 'hostname', 'date',
    'uptime', 'top', 'htop', 'ps', 'df', 'du', 'free', 'netstat',
    'ss', 'ip addr', 'ifconfig', 'ping', 'traceroute', 'tracepath'
}


def sanitize_command(command: str) -> str:
    """Sanitize a shell command by removing dangerous characters"""
    # Remove null bytes
    command = command.replace('\x00', '')
    
    # Strip leading/trailing whitespace
    command = command.strip()
    
    # Remove backticks and $() for command substitution
    command = re.sub(r'`[^`]*`', '', command)
    command = re.sub(r'\$\([^)]*\)', '', command)
    
    return command


def validate_command(command: str, user_role: str) -> tuple[bool, str]:
    """
    Validate a command based on user role
    Returns (is_valid, error_message)
    """
    sanitized = sanitize_command(command)
    
    if not sanitized:
        return False, "Empty or invalid command"
    
    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            logger.warning(f"Command injection attempt detected: {command}")
            return False, "Potentially malicious command detected"
    
    # Check for dangerous commands
    for dangerous in DANGEROUS_COMMANDS:
        if dangerous.lower() in command.lower():
            if user_role != 'admin':
                logger.warning(f"Non-admin user attempted dangerous command: {command}")
                return False, f"Command '{dangerous}' requires admin privileges"
    
    # Viewers can only run safe commands
    if user_role == 'viewer':
        base_command = sanitized.split()[0] if sanitized.split() else ''
        if base_command not in VIEWER_ALLOWED_COMMANDS:
            # Check if it's a partial match of allowed commands
            allowed_partial = any(cmd.startswith(base_command) for cmd in VIEWER_ALLOWED_COMMANDS)
            if not allowed_partial:
                return False, f"Command '{base_command}' not allowed for viewer role"
    
    return True, ""


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for audit logging"""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


class AuditLogger:
    """Audit logger for security events"""
    
    def __init__(self):
        self.log_file = "audit_log.jsonl"
    
    def log_event(self, event_type: str, user: str, action: str, 
                  details: Optional[dict] = None, ip_address: Optional[str] = None):
        """Log a security event"""
        import json
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user": user,
            "action": action,
            "details": details or {},
            "ip_address": ip_address,
            "action_hash": hash_sensitive_data(action)
        }
        
        logger.info(f"AUDIT: {json.dumps(log_entry)}")
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def log_command_execution(self, user: str, command: str, 
                              success: bool, output_length: int = 0,
                              ip_address: Optional[str] = None):
        """Log a command execution event"""
        self.log_event(
            event_type="COMMAND_EXECUTION",
            user=user,
            action=f"EXECUTE: {'SUCCESS' if success else 'FAILED'}",
            details={
                "command_hash": hash_sensitive_data(command),
                "command_preview": command[:50] + "..." if len(command) > 50 else command,
                "output_length": output_length
            },
            ip_address=ip_address
        )
    
    def log_process_kill(self, user: str, pid: int, process_name: str,
                         ip_address: Optional[str] = None):
        """Log a process termination event"""
        self.log_event(
            event_type="PROCESS_TERMINATION",
            user=user,
            action=f"KILL_PID_{pid}",
            details={
                "pid": pid,
                "process_name": process_name
            },
            ip_address=ip_address
        )
    
    def log_ip_block(self, user: str, ip_address: str, 
                     reason: str, method: str = "iptables"):
        """Log an IP blocking event"""
        self.log_event(
            event_type="IP_BLOCK",
            user=user,
            action=f"BLOCK_IP_{ip_address}",
            details={
                "blocked_ip": ip_address,
                "reason": reason,
                "method": method
            }
        )
    
    def log_high_resource_alert(self, resource_type: str, value: float, 
                                threshold: float):
        """Log a high resource usage alert"""
        self.log_event(
            event_type="RESOURCE_ALERT",
            user="SYSTEM",
            action=f"HIGH_{resource_type}_USAGE",
            details={
                "resource_type": resource_type,
                "current_value": value,
                "threshold": threshold,
                "severity": "CRITICAL" if value > 95 else "HIGH"
            }
        )
    
    def log_threat_detected(self, threat_title: str, severity: str, 
                            source: str, cve_id: Optional[str] = None):
        """Log a detected threat"""
        self.log_event(
            event_type="THREAT_DETECTED",
            user="SCRAPER",
            action=f"THREAT_{severity}",
            details={
                "title": threat_title,
                "severity": severity,
                "source": source,
                "cve_id": cve_id
            }
        )


# Global audit logger instance
audit_logger = AuditLogger()


def rate_limit_exceeded_handler(request: Request, exc: Exception) -> JSONResponse:
    """Custom rate limit exceeded handler"""
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": str(exc),
            "retry_after": getattr(exc, 'retry_after', 60)
        }
    )
