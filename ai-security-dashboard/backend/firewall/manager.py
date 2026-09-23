"""
Dynamic Firewall Integration Module
Native OS firewall rule management for iptables (Linux) and netsh (Windows)
"""

import os
import subprocess
import logging
import sqlite3
import platform
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "database", "security_dashboard.db")


class FirewallManager:
    """
    Dynamic Firewall Manager
    Provides cross-platform firewall rule management
    """
    
    def __init__(self):
        self.system = platform.system()
        self._init_database()
    
    def _init_database(self):
        """Initialize firewall rules table in database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    action TEXT NOT NULL,
                    protocol TEXT DEFAULT 'tcp',
                    port INTEGER,
                    direction TEXT DEFAULT 'inbound',
                    description TEXT,
                    created_at TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info("Firewall rules table initialized")
        except Exception as e:
            logger.error(f"Error initializing firewall database: {e}")
    
    def _run_command(self, command: List[str], shell: bool = False) -> Dict[str, Any]:
        """Run a system command and return result."""
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def add_rule_iptables(self, ip_address: str, action: str = "DROP", 
                          protocol: str = "tcp", port: Optional[int] = None,
                          direction: str = "inbound", description: str = "") -> Dict[str, Any]:
        """Add an iptables rule on Linux."""
        if self.system != "Linux":
            return {"success": False, "error": "iptables only available on Linux"}
        
        # Build iptables command
        chain = "INPUT" if direction == "inbound" else "OUTPUT"
        cmd = ["sudo", "iptables", "-A", chain]
        
        if protocol:
            cmd.extend(["-p", protocol])
        
        if port:
            cmd.extend(["--dport" if direction == "inbound" else "--sport", str(port)])
        
        cmd.extend(["-s" if direction == "inbound" else "-d", ip_address])
        cmd.extend(["-j", action])
        
        result = self._run_command(cmd)
        
        if result["success"]:
            # Store in database
            self._store_rule(ip_address, action, protocol, port, direction, description)
            logger.info(f"Added iptables rule: {action} {ip_address}")
        
        return result
    
    def add_rule_netsh(self, ip_address: str, action: str = "block",
                       protocol: str = "tcp", port: Optional[int] = None,
                       direction: str = "inbound", description: str = "") -> Dict[str, Any]:
        """Add a Windows Firewall rule using netsh."""
        if self.system != "Windows":
            return {"success": False, "error": "netsh only available on Windows"}
        
        # Map action to netsh terminology
        netsh_action = "block" if action.lower() in ["drop", "block", "deny"] else "allow"
        netsh_direction = "in" if direction == "inbound" else "out"
        
        rule_name = f"SecurityDashboard_{netsh_action}_{ip_address.replace('.', '_')}"
        
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={netsh_direction}",
            f"action={netsh_action}",
            f"remoteip={ip_address}",
            f"protocol={protocol}"
        ]
        
        if port:
            cmd.append(f"localport={port}")
        
        if description:
            cmd.append(f"description={description}")
        
        result = self._run_command(cmd)
        
        if result["success"]:
            self._store_rule(ip_address, action, protocol, port, direction, description)
            logger.info(f"Added Windows Firewall rule: {action} {ip_address}")
        
        return result
    
    def add_rule(self, ip_address: str, action: str = "DROP",
                 protocol: str = "tcp", port: Optional[int] = None,
                 direction: str = "inbound", description: str = "") -> Dict[str, Any]:
        """Add a firewall rule (auto-detects OS)."""
        if self.system == "Linux":
            return self.add_rule_iptables(ip_address, action, protocol, port, direction, description)
        elif self.system == "Windows":
            return self.add_rule_netsh(ip_address, action, protocol, port, direction, description)
        else:
            return {"success": False, "error": f"Unsupported OS: {self.system}"}
    
    def remove_rule_iptables(self, ip_address: str, port: Optional[int] = None,
                             direction: str = "inbound") -> Dict[str, Any]:
        """Remove an iptables rule."""
        if self.system != "Linux":
            return {"success": False, "error": "iptables only available on Linux"}
        
        chain = "INPUT" if direction == "inbound" else "OUTPUT"
        
        # First, list rules to find the line number
        list_cmd = ["sudo", "iptables", "-L", chain, "-n", "--line-numbers"]
        list_result = self._run_command(list_cmd)
        
        if not list_result["success"]:
            return list_result
        
        # Find the rule line number
        lines = list_result["stdout"].split('\n')[2:]  # Skip headers
        rule_num = None
        
        for line in lines:
            if ip_address in line:
                if port is None or str(port) in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_num = parts[0]
                        break
        
        if rule_num is None:
            return {"success": False, "error": f"Rule for {ip_address} not found"}
        
        # Delete the rule
        del_cmd = ["sudo", "iptables", "-D", chain, rule_num]
        result = self._run_command(del_cmd)
        
        if result["success"]:
            self._disable_rule_in_db(ip_address)
            logger.info(f"Removed iptables rule for {ip_address}")
        
        return result
    
    def remove_rule_netsh(self, ip_address: str, description: str = "") -> Dict[str, Any]:
        """Remove a Windows Firewall rule."""
        if self.system != "Windows":
            return {"success": False, "error": "netsh only available on Windows"}
        
        rule_name = f"SecurityDashboard_{'block'}_{ip_address.replace('.', '_')}"
        
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        result = self._run_command(cmd)
        
        if result["success"]:
            self._disable_rule_in_db(ip_address)
            logger.info(f"Removed Windows Firewall rule for {ip_address}")
        
        return result
    
    def remove_rule(self, ip_address: str, port: Optional[int] = None,
                    direction: str = "inbound") -> Dict[str, Any]:
        """Remove a firewall rule (auto-detects OS)."""
        if self.system == "Linux":
            return self.remove_rule_iptables(ip_address, port, direction)
        elif self.system == "Windows":
            return self.remove_rule_netsh(ip_address)
        else:
            return {"success": False, "error": f"Unsupported OS: {self.system}"}
    
    def flush_rules_iptables(self, chain: str = "INPUT") -> Dict[str, Any]:
        """Flush all rules in a specific iptables chain."""
        if self.system != "Linux":
            return {"success": False, "error": "iptables only available on Linux"}
        
        cmd = ["sudo", "iptables", "-F", chain]
        result = self._run_command(cmd)
        
        if result["success"]:
            logger.info(f"Flushed all iptables rules in chain {chain}")
        
        return result
    
    def flush_rules_netsh(self) -> Dict[str, Any]:
        """Flush Windows Firewall rules created by this application."""
        if self.system != "Windows":
            return {"success": False, "error": "netsh only available on Windows"}
        
        # Get all rules with our prefix
        list_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        list_result = self._run_command(list_cmd)
        
        if not list_result["success"]:
            return list_result
        
        # Parse and delete our rules
        deleted_count = 0
        for line in list_result["stdout"].split('\n'):
            if "SecurityDashboard_" in line:
                rule_name = line.split(':')[1].strip()
                del_cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                del_result = self._run_command(del_cmd)
                if del_result["success"]:
                    deleted_count += 1
        
        logger.info(f"Flushed {deleted_count} Windows Firewall rules")
        return {"success": True, "deleted_count": deleted_count}
    
    def flush_rules(self) -> Dict[str, Any]:
        """Flush all application-created firewall rules."""
        if self.system == "Linux":
            return self.flush_rules_iptables()
        elif self.system == "Windows":
            return self.flush_rules_netsh()
        else:
            return {"success": False, "error": f"Unsupported OS: {self.system}"}
    
    def list_rules_iptables(self) -> List[Dict[str, Any]]:
        """List current iptables rules."""
        if self.system != "Linux":
            return []
        
        result = self._run_command(["sudo", "iptables", "-L", "-n", "-v"])
        
        if not result["success"]:
            return []
        
        rules = []
        current_chain = None
        
        for line in result["stdout"].split('\n'):
            if line.startswith('Chain'):
                current_chain = line.split()[1]
            elif line.strip() and not line.startswith('target'):
                parts = line.split()
                if len(parts) >= 8:
                    rules.append({
                        "chain": current_chain,
                        "target": parts[0],
                        "protocol": parts[1],
                        "options": " ".join(parts[2:-2]),
                        "source": parts[-2],
                        "destination": parts[-1]
                    })
        
        return rules
    
    def list_rules_netsh(self) -> List[Dict[str, Any]]:
        """List Windows Firewall rules created by this application."""
        if self.system != "Windows":
            return []
        
        result = self._run_command(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"])
        
        if not result["success"]:
            return []
        
        rules = []
        current_rule = {}
        
        for line in result["stdout"].split('\n'):
            if "SecurityDashboard_" in line:
                if current_rule:
                    rules.append(current_rule)
                current_rule = {"raw": line}
            elif current_rule and ':' in line:
                key, value = line.split(':', 1)
                current_rule[key.strip()] = value.strip()
        
        if current_rule:
            rules.append(current_rule)
        
        return rules
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List all firewall rules."""
        if self.system == "Linux":
            return self.list_rules_iptables()
        elif self.system == "Windows":
            return self.list_rules_netsh()
        return []
    
    def _store_rule(self, ip_address: str, action: str, protocol: str,
                    port: Optional[int], direction: str, description: str):
        """Store rule in database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO firewall_rules 
                (ip_address, action, protocol, port, direction, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip_address, action, protocol, port, direction, description, 
                  datetime.utcnow().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error storing firewall rule: {e}")
    
    def _disable_rule_in_db(self, ip_address: str):
        """Mark a rule as disabled in database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE firewall_rules 
                SET enabled = 0 
                WHERE ip_address = ?
            """, (ip_address,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error disabling firewall rule in DB: {e}")
    
    def get_stored_rules(self, enabled_only: bool = True) -> List[Dict[str, Any]]:
        """Get stored rules from database."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if enabled_only:
                cursor.execute("""
                    SELECT * FROM firewall_rules 
                    WHERE enabled = 1 
                    ORDER BY id DESC
                """)
            else:
                cursor.execute("SELECT * FROM firewall_rules ORDER BY id DESC")
            
            columns = ["id", "ip_address", "action", "protocol", "port", 
                      "direction", "description", "created_at", "enabled"]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving stored rules: {e}")
            return []
    
    def block_ip(self, ip_address: str, description: str = "Blocked by Security Dashboard") -> Dict[str, Any]:
        """Convenience method to block an IP address."""
        return self.add_rule(
            ip_address=ip_address,
            action="DROP",
            protocol="all",
            port=None,
            direction="inbound",
            description=description
        )
    
    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Convenience method to unblock an IP address."""
        return self.remove_rule(ip_address)


# Global instance
firewall_manager = FirewallManager()
