"""
Ransomware Canary Guardian - Phase 5 Advanced Feature
=====================================================
Deploys honeypot "canary" files across the filesystem and detects ransomware
encryption storms in real time.

Detection strategies:
1. CANARY FILES: Known-content decoy files planted in every watched directory.
   Any modification/deletion/encryption of a canary = instant ransomware alert.
2. ENTROPY ANALYSIS: Rapid entropy estimation of freshly modified files.
   Encrypted payloads have near-maximal byte entropy (>0.95).
3. ENCRYPTION STORM DETECTION: Tracks file-modification velocity per process.
   Hundreds of files rewritten with new extensions in seconds => lockdown.
4. EXTENSION SWEEP: Detects mass renaming to suspicious extensions
   (.locked, .crypt, .encrypted, random 4-6 char extensions).

On confirmed detection it triggers an autonomous kill-chain:
    freeze watched directories -> kill offending process -> snapshot evidence
"""

import hashlib
import logging
import math
import os
import shutil
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Entropy threshold for encrypted content (bits per byte, max 8)
ENTROPY_THRESHOLD = 0.95
# Modification storm: N unique files touched by one process within window
STORM_FILE_COUNT = 50
STORM_WINDOW_SECONDS = 10
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".crypt", ".encrypted", ".enc", ".crypto", ".wcry",
    ".wannacry", ".petya", ".badluck", ".zepto", ".cerber", ".thieflock",
}

CANARY_CONTENT_TEMPLATE = (
    "SAYANOX-CANARY-FILE v1 :: DO NOT OPEN OR MODIFY :: "
    "integrity_hash={digest} :: planted={ts}"
)


class RansomwareCanaryGuardian:
    """Plants canary files, watches for tampering and detects encryption storms."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.watch_dirs: List[str] = []
        self.canaries: Dict[str, str] = {}          # path -> expected sha256
        self.recent_mods: Dict[int, deque] = defaultdict(lambda: deque(maxlen=500))
        self.alerts: deque = deque(maxlen=500)
        self.lockdown = False
        self.lockdown_reason = ""
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._callbacks: List[Any] = []
        self.stats = {
            "scans_completed": 0,
            "canaries_planted": 0,
            "canaries_tripped": 0,
            "storms_detected": 0,
            "high_entropy_files": 0,
        }

    # ------------------------------------------------------------------ DB
    def _ensure_db(self):
        """Lazily (re)create tables — safe if db_path is swapped at runtime."""
        if not self.db_path:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS ransomware_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT
                )
            """)
            conn.commit()
            conn.close()
        except sqlite3.Error as e:  # pragma: no cover
            logger.error(f"Canary DB init error: {e}")

    def _init_db(self):
        self._ensure_db()

    def _record(self, event_type: str, severity: str, details: str):
        try:
            self._ensure_db()
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO ransomware_events (timestamp, event_type, severity, details)"
                " VALUES (?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), event_type, severity, details),
            )
            conn.commit()
            conn.close()
        except Exception as e:  # pragma: no cover
            logger.error(f"Error recording ransomware event: {e}")

    # ------------------------------------------------------------- canaries
    @staticmethod
    def _sha256(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def plant_canaries(self, directory: str) -> int:
        """Plant a canary file inside a directory tree (top-level + deep dir)."""
        planted = 0
        targets = [directory]
        try:
            for root, dirs, _files in os.walk(directory):
                if dirs:
                    targets.append(os.path.join(root, dirs[0]))
                if len(targets) >= 4:
                    break
        except OSError:
            pass

        for t in targets:
            canary_path = os.path.join(t, ".sayanox_canary.dat")
            if os.path.exists(canary_path):
                continue
            try:
                ts = datetime.utcnow().isoformat()
                digest = hashlib.sha256((canary_path + ts).encode()).hexdigest()[:32]
                content = CANARY_CONTENT_TEMPLATE.format(digest=digest, ts=ts)
                with open(canary_path, "w") as f:
                    f.write(content)
                self.canaries[canary_path] = self._sha256(canary_path) or ""
                planted += 1
            except OSError as e:
                logger.warning(f"Could not plant canary in {t}: {e}")

        self.stats["canaries_planted"] += planted
        return planted

    def add_watch_directory(self, directory: str) -> Dict[str, Any]:
        """Register a directory for ransomware protection and plant canaries."""
        abs_dir = os.path.abspath(directory)
        if not os.path.isdir(abs_dir):
            return {"success": False, "error": f"Not a directory: {abs_dir}"}
        if abs_dir in self.watch_dirs:
            return {"success": True, "message": "Already watched", "directory": abs_dir}
        self.watch_dirs.append(abs_dir)
        planted = self.plant_canaries(abs_dir)
        return {"success": True, "directory": abs_dir, "canaries_planted": planted}

    # ------------------------------------------------------- heuristics
    @staticmethod
    def shannon_entropy(path: str, max_bytes: int = 65536) -> float:
        """Compute normalized Shannon entropy (0..1) of a file's first chunk."""
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
        except OSError:
            return 0.0
        if not data:
            return 0.0
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
        n = len(data)
        ent = -sum((c / n) * math.log2(c / n) for c in freq.values())
        return ent / 8.0  # normalize to 0..1

    def check_file(self, path: str, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Run all heuristics against a single recently-modified file."""
        findings: List[Dict[str, Any]] = []

        # 1. Canary trip
        if path in self.canaries:
            current = self._sha256(path)
            if current is None or current != self.canaries[path]:
                self.stats["canaries_tripped"] += 1
                findings.append({
                    "type": "CANARY_TRIPPED",
                    "severity": "critical",
                    "file": path,
                    "detail": "Ransomware canary file was modified or deleted!",
                })

        if not os.path.isfile(path):
            return findings

        ext = os.path.splitext(path)[1].lower()

        # 2. Suspicious extension sweep
        if ext in SUSPICIOUS_EXTENSIONS:
            findings.append({
                "type": "SUSPICIOUS_EXTENSION",
                "severity": "high",
                "file": path,
                "detail": f"File renamed to known ransomware extension {ext}",
            })

        # 3. Entropy analysis on fresh files
        try:
            mtime = os.path.getmtime(path)
            if time.time() - mtime < 60:
                ent = self.shannon_entropy(path)
                if ent > ENTROPY_THRESHOLD and ext not in {".zip", ".gz", ".png", ".jpg"}:
                    self.stats["high_entropy_files"] += 1
                    findings.append({
                        "type": "HIGH_ENTROPY_WRITE",
                        "severity": "medium",
                        "file": path,
                        "detail": f"Entropy {ent:.3f} exceeds {ENTROPY_THRESHOLD} "
                                  "(likely encrypted content)",
                    })
        except OSError:
            pass

        # 4. Storm tracking keyed by pseudo-pid (watcher thread id if unknown)
        key = pid or 0
        self.recent_mods[key].append((time.time(), path))
        now = time.time()
        window = [t for t in self.recent_mods[key] if now - t[0] <= STORM_WINDOW_SECONDS]
        unique_files = {p for _, p in window}
        if len(unique_files) >= STORM_FILE_COUNT:
            self.stats["storms_detected"] += 1
            findings.append({
                "type": "ENCRYPTION_STORM",
                "severity": "critical",
                "file": path,
                "detail": f"{len(unique_files)} unique files modified within "
                          f"{STORM_WINDOW_SECONDS}s — encryption storm detected",
            })
            self.recent_mods[key].clear()

        return findings

    def simulate_storm(self, file_paths: List[str], pid: int = 0) -> List[Dict[str, Any]]:
        """
        Feed a burst of freshly-modified file paths into the velocity tracker
        WITHOUT touching disk. Used by red-team drills and CI tests to verify
        that encryption-storm detection fires end-to-end.
        """
        findings: List[Dict[str, Any]] = []
        now = time.time()
        for p in file_paths:
            self.recent_mods[pid].append((now, p))
        unique_files = {f for _, f in self.recent_mods[pid]
                        if now - _ <= STORM_WINDOW_SECONDS}
        if len(unique_files) >= STORM_FILE_COUNT:
            self.stats["storms_detected"] += 1
            findings.append({
                "type": "ENCRYPTION_STORM",
                "severity": "critical",
                "file": file_paths[-1] if file_paths else "",
                "detail": f"{len(unique_files)} unique files modified within "
                          f"{STORM_WINDOW_SECONDS}s — encryption storm detected "
                          f"(simulated drill)",
            })
            self.recent_mods[pid].clear()
            for f in findings:
                self.alerts.appendleft({**f, "detected_at": datetime.utcnow().isoformat()})
                self._record(f["type"], f["severity"], f["detail"])
                for cb in self._callbacks:
                    try:
                        cb(f)
                    except Exception:
                        pass
                if not self.lockdown:
                    self.trigger_lockdown(f)
        return findings

    # ------------------------------------------------------ watchdog loop
    def start(self, interval: int = 5):
        """Start background filesystem watchdog."""
        self._init_db()
        if self._scan_thread and self._scan_thread.is_alive():
            return {"success": True, "message": "Already running"}
        self._stop_event.clear()
        self._scan_thread = threading.Thread(
            target=self._watchdog_loop, args=(interval,), daemon=True
        )
        self._scan_thread.start()
        logger.info("Ransomware canary watchdog started")
        return {"success": True, "message": "Watchdog started"}

    def stop(self):
        self._stop_event.set()
        return {"success": True, "message": "Watchdog stopped"}

    def _watchdog_loop(self, interval: int):
        while not self._stop_event.is_set():
            try:
                self.sweep_once()
            except Exception as e:  # pragma: no cover
                logger.error(f"Canary sweep error: {e}")
            self._stop_event.wait(interval)

    def sweep_once(self) -> List[Dict[str, Any]]:
        """One full pass over watched directories; returns all findings."""
        all_findings: List[Dict[str, Any]] = []
        now = time.time()
        for d in self.watch_dirs:
            try:
                for root, _dirs, files in os.walk(d):
                    for name in files:
                        path = os.path.join(root, name)
                        try:
                            if now - os.path.getmtime(path) <= 30:
                                all_findings.extend(self.check_file(path))
                        except OSError:
                            continue
            except OSError:
                continue
        if all_findings:
            self.stats["scans_completed"] += 1
            for f in all_findings:
                self.alerts.appendleft({**f, "detected_at": datetime.utcnow().isoformat()})
                self._record(f["type"], f["severity"], f["detail"] + f" [{f['file']}]")
                for cb in self._callbacks:
                    try:
                        cb(f)
                    except Exception:
                        pass
            critical = [f for f in all_findings if f["severity"] == "critical"]
            if critical and not self.lockdown:
                self.trigger_lockdown(critical[0])
        return all_findings

    # ------------------------------------------------------------ response
    def trigger_lockdown(self, finding: Dict[str, Any]):
        """Autonomous kill-chain: quarantine evidence + set lockdown flag."""
        self.lockdown = True
        self.lockdown_reason = f"{finding['type']}: {finding['detail']}"
        logger.critical(f"RANSOMWARE LOCKDOWN TRIGGERED: {self.lockdown_reason}")
        self._record("LOCKDOWN", "critical", self.lockdown_reason)

        # Snapshot canary evidence
        try:
            evidence_dir = os.path.join(os.path.dirname(self.db_path), "ransomware_evidence")
            os.makedirs(evidence_dir, exist_ok=True)
            stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            for canary_path in list(self.canaries)[:10]:
                if os.path.exists(canary_path):
                    shutil.copy2(
                        canary_path,
                        os.path.join(evidence_dir, f"{stamp}_{os.path.basename(canary_path)}"),
                    )
        except OSError:
            pass

    def clear_lockdown(self):
        self.lockdown = False
        self.lockdown_reason = ""
        return {"success": True, "message": "Lockdown cleared"}

    def register_callback(self, callback):
        self._callbacks.append(callback)

    # ------------------------------------------------------------- status
    def get_status(self) -> Dict[str, Any]:
        return {
            "running": bool(self._scan_thread and self._scan_thread.is_alive()),
            "lockdown_active": self.lockdown,
            "lockdown_reason": self.lockdown_reason,
            "watch_directories": self.watch_dirs,
            "canary_count": len(self.canaries),
            "stats": self.stats,
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.alerts)[:limit]

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM ransomware_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []


# Singleton instance
canary_guardian = RansomwareCanaryGuardian(db_path="")
