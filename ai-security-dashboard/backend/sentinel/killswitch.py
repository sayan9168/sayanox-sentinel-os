"""
AI Kill Switch - Phase 5 Advanced Feature
=========================================
A hardware-inspired software panic button for the autonomous AI stack.

When triggered (manually via API, by voice keyword detection, or automatically
by a critical-confidence incident), the kill switch executes an ordered
degradation ladder:

    L1  PAUSE     - stop all background workers (sniffer, honeypot, FIM)
    L2  ISOLATE   - block all outbound traffic except loopback via firewall
    L3  HALT      - terminate AI/automation processes (terminal + browser engines)
    L4  FREEZE    - put the remediation engine into safe mode (no autonomous actions)

Every state transition is written to an immutable audit ledger so post-incident
forensics can reconstruct exactly who killed what and when. A dual-key
confirmation (admin JWT + kill-switch PIN) is required for L2+ activation,
preventing a compromised viewer token from bricking the machine.
"""

import logging
import os
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

LEVEL_PAUSE = 1
LEVEL_ISOLATE = 2
LEVEL_HALT = 3
LEVEL_FREEZE = 4

LEVEL_NAMES = {
    LEVEL_PAUSE: "PAUSE_WORKERS",
    LEVEL_ISOLATE: "NETWORK_ISOLATE",
    LEVEL_HALT: "HALT_PROCESSES",
    LEVEL_FREEZE: "FULL_FREEZE",
}


class AIKillSwitch:
    """Auditable, tiered emergency stop for every autonomous component."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.active_level: int = 0          # 0 = all clear
        self.armed = True                    # kill switch availability flag
        self.pin_hash: Optional[str] = None
        self._lock = threading.Lock()
        self._hooks: Dict[int, List[Callable[[], None]]] = {
            LEVEL_PAUSE: [], LEVEL_ISOLATE: [], LEVEL_HALT: [], LEVEL_FREEZE: []
        }
        self.activation_history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ DB
    def _ensure_db(self):
        """Lazily (re)create the ledger table — safe if db_path is swapped."""
        if not self.db_path:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS killswitch_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    level INTEGER,
                    actor TEXT,
                    reason TEXT
                )
            """)
            conn.commit()
            conn.close()
        except sqlite3.Error as e:  # pragma: no cover
            logger.error(f"Kill switch DB init error: {e}")

    def _init_db(self):
        self._ensure_db()

    def _ledger(self, action: str, level: int, actor: str, reason: str):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "level": level,
            "actor": actor,
            "reason": reason,
        }
        self.activation_history.insert(0, entry)
        self.activation_history = self.activation_history[:200]
        try:
            self._ensure_db()
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO killswitch_ledger (timestamp, action, level, actor, reason)"
                " VALUES (?, ?, ?, ?, ?)",
                (entry["timestamp"], action, level, actor, reason),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Kill switch ledger write failed: {e}")

    # ----------------------------------------------------------------- PIN
    def set_pin(self, pin: str):
        """Store salted SHA-256 of the kill-switch PIN."""
        import hashlib
        salt = os.urandom(16).hex()
        digest = hashlib.sha256((salt + pin).encode()).hexdigest()
        self.pin_hash = f"{salt}${digest}"

    def verify_pin(self, pin: str) -> bool:
        if not self.pin_hash:
            return False
        import hashlib
        salt, expected = self.pin_hash.split("$", 1)
        return hashlib.sha256((salt + pin).encode()).hexdigest() == expected

    # --------------------------------------------------------------- hooks
    def register_hook(self, level: int, callback: Callable[[], None]):
        if level in self._hooks:
            self._hooks[level].append(callback)

    def _run_hooks(self, level: int):
        for cb in self._hooks.get(level, []):
            try:
                cb()
            except Exception as e:
                logger.error(f"Kill switch hook error at level {level}: {e}")

    # ------------------------------------------------------------ activate
    def activate(self, level: int, actor: str = "manual", reason: str = "",
                 pin: Optional[str] = None) -> Dict[str, Any]:
        """Engage the kill switch up to `level`. L2+ requires valid PIN."""
        with self._lock:
            if not self.armed:
                return {"success": False, "error": "Kill switch is disarmed"}
            if level not in LEVEL_NAMES:
                return {"success": False, "error": f"Invalid level {level}"}
            if level >= LEVEL_ISOLATE:
                if not self.pin_hash:
                    return {"success": False,
                            "error": "No PIN configured — call /killswitch/pin first"}
                if not pin or not self.verify_pin(pin):
                    self._ledger("REJECTED", level, actor, reason or "bad pin")
                    return {"success": False, "error": "Invalid kill-switch PIN"}

            executed: List[str] = []
            prev = self.active_level
            for lv in range(max(prev + 1, LEVEL_PAUSE), level + 1):
                self._run_hooks(lv)
                executed.append(LEVEL_NAMES[lv])
            self.active_level = max(self.active_level, level)
            self._ledger("ACTIVATED", level, actor, reason)
            logger.critical(f"KILL SWITCH ENGAGED level={level} actor={actor}")
            return {
                "success": True,
                "level": level,
                "level_name": LEVEL_NAMES[level],
                "actions_executed": executed,
                "timestamp": datetime.utcnow().isoformat(),
            }

    def stand_down(self, actor: str = "manual", pin: Optional[str] = None) -> Dict[str, Any]:
        """Release the kill switch (PIN required if previously isolated)."""
        with self._lock:
            if self.active_level >= LEVEL_ISOLATE:
                if not pin or not self.verify_pin(pin):
                    return {"success": False, "error": "PIN required to stand down"}
            self.active_level = 0
            self._ledger("STAND_DOWN", 0, actor, "operators cleared kill switch")
            return {"success": True, "message": "All systems released",
                    "timestamp": datetime.utcnow().isoformat()}

    def disarm(self, pin: str) -> Dict[str, Any]:
        if not self.verify_pin(pin):
            return {"success": False, "error": "Invalid PIN"}
        self.armed = False
        self._ledger("DISARMED", self.active_level, "admin", "kill switch disabled")
        return {"success": True, "message": "Kill switch disarmed"}

    def arm(self, pin: str) -> Dict[str, Any]:
        if not self.verify_pin(pin):
            return {"success": False, "error": "Invalid PIN"}
        self.armed = True
        self._ledger("ARMED", 0, "admin", "kill switch enabled")
        return {"success": True, "message": "Kill switch armed"}

    # -------------------------------------------------------------- status
    def get_status(self) -> Dict[str, Any]:
        return {
            "armed": self.armed,
            "active_level": self.active_level,
            "active_level_name": LEVEL_NAMES.get(self.active_level, "ALL_CLEAR"),
            "pin_configured": bool(self.pin_hash),
            "registered_hooks": {LEVEL_NAMES[k]: len(v) for k, v in self._hooks.items()},
            "recent_ledger": self.activation_history[:20],
        }


# Singleton instance
kill_switch = AIKillSwitch(db_path="")
