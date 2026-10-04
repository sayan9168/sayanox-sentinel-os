"""
Incident Correlation Engine - Phase 5 Advanced Feature
======================================================
Fuses low-level security events (honeypot hits, FIM violations, anomalies,
firewall blocks, ransomware canary trips) into high-level *incidents* using a
sliding-window attack-chain analysis:

1. Events are grouped by correlated keys: source IP, file path, process name.
2. Kill-chain scoring: an incident's severity rises as it moves through
   RECON -> INITIAL ACCESS -> EXECUTION -> PERSISTENCE -> EXFIL/IMPACT stages.
3. Bayesian confidence: each event type contributes a log-odds weight; the
   summed score maps to an incident confidence probability.
4. Auto-generated narrative timeline for SOC reporting.
5. Incidents auto-close after a quiet period (configurable TTL).
"""

import logging
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Event type -> kill-chain stage + log-odds weight (Bayesian-ish scoring)
EVENT_MODEL: Dict[str, Dict[str, Any]] = {
    "honeypot_hit":        {"stage": "RECON",           "weight": 1.2},
    "port_scan":           {"stage": "RECON",           "weight": 1.0},
    "nmap_scan":           {"stage": "RECON",           "weight": 0.8},
    "failed_login":        {"stage": "INITIAL_ACCESS",  "weight": 1.5},
    "brute_force":         {"stage": "INITIAL_ACCESS",  "weight": 2.0},
    "exploit_attempt":     {"stage": "INITIAL_ACCESS",  "weight": 2.5},
    "anomaly_detected":    {"stage": "EXECUTION",       "weight": 1.8},
    "suspicious_process":  {"stage": "EXECUTION",       "weight": 2.2},
    "fim_violation":       {"stage": "PERSISTENCE",     "weight": 2.0},
    "canary_tripped":      {"stage": "IMPACT",          "weight": 3.5},
    "encryption_storm":    {"stage": "IMPACT",          "weight": 4.0},
    "high_entropy_write":  {"stage": "IMPACT",          "weight": 2.5},
    "outbound_anomaly":    {"stage": "EXFILTRATION",    "weight": 2.8},
    "dns_tunneling":       {"stage": "EXFILTRATION",    "weight": 3.0},
    "firewall_block":      {"stage": "RESPONSE",        "weight": 0.5},
}

STAGE_ORDER = ["RECON", "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE",
               "EXFILTRATION", "IMPACT"]

KILL_CHAIN_LABELS = {
    "RECON": "Discovery & Reconnaissance",
    "INITIAL_ACCESS": "Initial Access Attempted",
    "EXECUTION": "Adversary Execution Detected",
    "PERSISTENCE": "Persistence Mechanism Observed",
    "EXFILTRATION": "Data Exfiltration Indicators",
    "IMPACT": "Destructive Impact / Encryption",
    "RESPONSE": "Defensive Response Triggered",
}


class IncidentCorrelator:
    """Sliding-window multi-signal incident fusion."""

    def __init__(self, window_seconds: int = 900, close_ttl: int = 1800):
        self.window = window_seconds
        self.close_ttl = close_ttl
        self.events: deque = deque(maxlen=10000)
        self.incidents: Dict[int, Dict[str, Any]] = {}
        self._next_incident_id = 1000

    # ----------------------------------------------------------- ingest
    def ingest(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Add one raw event and return its correlation result."""
        model = EVENT_MODEL.get(event_type)
        if not model:
            return {"accepted": False, "error": f"Unknown event type '{event_type}'"}

        event = {
            "type": event_type,
            "stage": model["stage"],
            "weight": model["weight"],
            "timestamp": time.time(),
            "detected_at": datetime.utcnow().isoformat(),
            "source_ip": details.get("source_ip"),
            "file_path": details.get("file_path") or details.get("file"),
            "process": details.get("process"),
            "details": details,
        }
        self.events.append(event)
        incident = self._correlate(event)
        return {"accepted": True, "incident_id": incident["id"],
                "confidence": incident["confidence"], "severity": incident["severity"]}

    # -------------------------------------------------------- correlation
    @staticmethod
    def _match_key(event: Dict[str, Any], inc: Dict[str, Any]) -> bool:
        """Two signals belong together if they share IP, path prefix or process."""
        keys_new = {k for k in (event["source_ip"], event["file_path"], event["process"]) if k}
        keys_inc = inc["keys"]
        if keys_new & keys_inc:
            return True
        # Path-prefix correlation: /etc/passwd & /etc/shadow share '/etc'
        for p_new in [event["file_path"]] if event["file_path"] else []:
            for p_inc in [k for k in keys_inc if "/" in str(k)]:
                if str(p_new).split("/")[1:2] == str(p_inc).split("/")[1:2]:
                    return True
        return False

    def _recent_events(self) -> List[Dict[str, Any]]:
        now = time.time()
        return [e for e in self.events if now - e["timestamp"] <= self.window]

    def _score_to_confidence(self, log_odds: float) -> float:
        """sigmoid(log-odds) -> probability."""
        return round(1.0 / (1.0 + pow(2.718281828, -log_odds)), 3)

    def _severity_from(self, stages: List[str], score: float) -> str:
        if "IMPACT" in stages or score >= 8:
            return "critical"
        if "EXFILTRATION" in stages or score >= 6:
            return "high"
        if "PERSISTENCE" in stages or score >= 4:
            return "medium"
        return "low"

    def _correlate(self, new_event: Dict[str, Any]) -> Dict[str, Any]:
        recent = self._recent_events()

        # Try to attach to an existing open incident
        target: Optional[Dict[str, Any]] = None
        for inc in self.incidents.values():
            if inc["status"] != "OPEN":
                continue
            if any(self._match_key(e, inc) for e in recent
                   if e.get("type")) and self._match_key(new_event, inc):
                target = inc
                break

        if target is None:
            target = self._new_incident()

        target["events"].append(new_event)
        target["keys"].update(
            k for k in (new_event["source_ip"], new_event["file_path"],
                        new_event["process"]) if k)
        self._recompute(target)
        return target

    def _new_incident(self) -> Dict[str, Any]:
        inc = {
            "id": self._next_incident_id,
            "status": "OPEN",
            "created_at": datetime.utcnow().isoformat(),
            "last_event_at": time.time(),
            "events": [],
            "keys": set(),
            "stages_seen": [],
            "score": 0.0,
            "confidence": 0.0,
            "severity": "low",
            "narrative": [],
        }
        self._next_incident_id += 1
        self.incidents[inc["id"]] = inc
        logger.info(f"New incident opened: #{inc['id']}")
        return inc

    def _recompute(self, inc: Dict[str, Any]):
        events = inc["events"]
        stages = list(dict.fromkeys(e["stage"] for e in events))
        ordered = [s for s in STAGE_ORDER if s in stages] + \
                  [s for s in stages if s not in STAGE_ORDER]
        score = sum(e["weight"] for e in events)
        # Chain bonus: moving deeper along the kill chain multiplies risk
        chain_depth = len([s for s in ordered if s in STAGE_ORDER])
        score *= (1 + 0.15 * max(0, chain_depth - 1))

        inc["stages_seen"] = ordered
        inc["score"] = round(score, 2)
        inc["confidence"] = self._score_to_confidence(score - 4)
        inc["severity"] = self._severity_from(stages, score)
        inc["last_event_at"] = events[-1]["timestamp"]
        inc["event_count"] = len(events)
        inc["narrative"] = [
            {
                "time": e["detected_at"],
                "stage_label": KILL_CHAIN_LABELS.get(e["stage"], e["stage"]),
                "event": e["type"],
                "summary": self._summarize(e),
            }
            for e in events[-50:]
        ]

    @staticmethod
    def _summarize(event: Dict[str, Any]) -> str:
        parts = [f"[{event['stage']}] {event['type']}"]
        if event["source_ip"]:
            parts.append(f"src={event['source_ip']}")
        if event["file_path"]:
            parts.append(f"file={event['file_path']}")
        if event["process"]:
            parts.append(f"proc={event['process']}")
        return " ".join(parts)

    # ---------------------------------------------------------- lifecycle
    def tick(self):
        """Close incidents that have gone quiet beyond the TTL."""
        now = time.time()
        for inc in self.incidents.values():
            if inc["status"] == "OPEN" and now - inc["last_event_at"] > self.close_ttl:
                inc["status"] = "CLOSED_AUTO"
                inc["closed_at"] = datetime.utcnow().isoformat()

    def close(self, incident_id: int, resolution: str = "manual") -> Dict[str, Any]:
        inc = self.incidents.get(incident_id)
        if not inc:
            return {"success": False, "error": "Incident not found"}
        inc["status"] = "CLOSED"
        inc["resolution"] = resolution
        inc["closed_at"] = datetime.utcnow().isoformat()
        return {"success": True, "id": incident_id}

    def get_incidents(self, status: Optional[str] = None,
                      limit: int = 50) -> List[Dict[str, Any]]:
        self.tick()
        out = []
        for inc in sorted(self.incidents.values(),
                          key=lambda i: i["score"], reverse=True):
            if status and inc["status"] != status:
                continue
            view = {k: v for k, v in inc.items() if k != "events"}
            out.append(view)
            if len(out) >= limit:
                break
        return out

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        return self.incidents.get(incident_id)

    def get_stats(self) -> Dict[str, Any]:
        self.tick()
        by_sev: Dict[str, int] = defaultdict(int)
        for inc in self.incidents.values():
            if inc["status"] == "OPEN":
                by_sev[inc["severity"]] += 1
        return {
            "total_incidents": len(self.incidents),
            "open_incidents": sum(1 for i in self.incidents.values()
                                  if i["status"] == "OPEN"),
            "open_by_severity": dict(by_sev),
            "events_ingested": len(self.events),
            "window_seconds": self.window,
            "supported_event_types": sorted(EVENT_MODEL.keys()),
        }


# Singleton instance
incident_correlator = IncidentCorrelator()
