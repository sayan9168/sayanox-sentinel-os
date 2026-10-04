"""
Tests for Phase 5 Advanced Features:
- Ransomware Canary Guardian (canary trip, entropy, storm detection)
- AI Kill Switch (PIN gating, ladder, audit ledger)
- Threat Intel NLP (IOC extraction, CVSS estimate, MITRE mapping)
- Incident Correlator (kill-chain fusion, confidence scoring)
"""

import math
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    os.unlink(path)


@pytest.fixture
def canary(tmp_db):
    from ransomware.canary import RansomwareCanaryGuardian
    g = RansomwareCanaryGuardian(db_path=tmp_db)
    return g


@pytest.fixture
def kswitch(tmp_db):
    from sentinel.killswitch import AIKillSwitch
    ks = AIKillSwitch(db_path=tmp_db)
    ks.set_pin("1337")
    return ks


# ------------------------------------------------------- ransomware canary
class TestRansomwareCanary:
    def test_plant_and_verify(self, canary, tmp_path):
        d = tmp_path / "docs"
        d.mkdir()
        result = canary.add_watch_directory(str(d))
        assert result["success"]
        assert result["canaries_planted"] >= 1
        assert len(canary.canaries) >= 1

    def test_canary_trip_detected(self, canary, tmp_path):
        d = tmp_path / "docs"
        d.mkdir()
        canary.add_watch_directory(str(d))
        canary_path = list(canary.canaries)[0]
        # Simulate ransomware encrypting the canary
        with open(canary_path, "w") as f:
            f.write("ENCRYPTED BY RANSOMWARE")
        findings = canary.check_file(canary_path)
        types = [f["type"] for f in findings]
        assert "CANARY_TRIPPED" in types
        sev = [f for f in findings if f["type"] == "CANARY_TRIPPED"][0]["severity"]
        assert sev == "critical"

    def test_entropy_detection(self, canary, tmp_path):
        p = tmp_path / "victim.txt"
        p.write_bytes(os.urandom(4096))  # random bytes = high entropy
        ent = canary.shannon_entropy(str(p))
        assert ent > 0.9  # near-maximal entropy
        findings = canary.check_file(str(p))
        assert any(f["type"] == "HIGH_ENTROPY_WRITE" for f in findings)

    def test_low_entropy_clean(self, canary, tmp_path):
        p = tmp_path / "plain.txt"
        p.write_text("a" * 4096)
        ent = canary.shannon_entropy(str(p))
        assert ent < 0.1
        findings = [f for f in canary.check_file(str(p))
                    if f["type"] == "HIGH_ENTROPY_WRITE"]
        assert findings == []

    def test_suspicious_extension(self, canary, tmp_path):
        p = tmp_path / "report.locked"
        p.write_text("ransom note")
        findings = canary.check_file(str(p))
        assert any(f["type"] == "SUSPICIOUS_EXTENSION" for f in findings)

    def test_encryption_storm(self, canary, tmp_path):
        # Red-team drill: burst of 60 unique modified paths from one process
        paths = [f"/tmp/storm/file_{i}.docx" for i in range(60)]
        findings = canary.simulate_storm(paths, pid=4242)
        assert any(f["type"] == "ENCRYPTION_STORM" for f in findings)
        assert canary.stats["storms_detected"] >= 1
        assert canary.lockdown is True

    def test_lockdown_triggered_on_sweep(self, canary, tmp_path):
        d = tmp_path / "protected"
        d.mkdir()
        canary.add_watch_directory(str(d))
        canary_path = list(canary.canaries)[0]
        with open(canary_path, "w") as f:
            f.write("crypto locked")
        findings = canary.sweep_once()
        assert len(findings) >= 1
        assert canary.lockdown is True
        assert "CANARY_TRIPPED" in canary.lockdown_reason
        events = canary.get_events()
        assert any(e["event_type"] == "LOCKDOWN" for e in events)

    def test_clear_lockdown(self, canary):
        canary.lockdown = True
        canary.clear_lockdown()
        assert canary.lockdown is False


# ----------------------------------------------------------- kill switch
class TestKillSwitch:
    def test_l1_pause_no_pin_needed(self, kswitch):
        calls = []
        from sentinel.killswitch import LEVEL_PAUSE
        kswitch.register_hook(LEVEL_PAUSE, lambda: calls.append("paused"))
        result = kswitch.activate(LEVEL_PAUSE, actor="test")
        assert result["success"]
        assert "paused" in calls

    def test_l2_requires_pin(self, kswitch):
        from sentinel.killswitch import LEVEL_ISOLATE
        bad = kswitch.activate(LEVEL_ISOLATE, pin="wrong")
        assert not bad["success"]
        good = kswitch.activate(LEVEL_ISOLATE, pin="1337", reason="drill")
        assert good["success"]
        assert "NETWORK_ISOLATE" in good["actions_executed"]

    def test_ladder_runs_all_levels(self, kswitch):
        from sentinel.killswitch import LEVEL_FREEZE
        calls = []
        kswitch.register_hook(1, lambda: calls.append(1))
        kswitch.register_hook(2, lambda: calls.append(2))
        kswitch.register_hook(3, lambda: calls.append(3))
        kswitch.register_hook(4, lambda: calls.append(4))
        result = kswitch.activate(LEVEL_FREEZE, pin="1337")
        assert result["success"]
        assert sorted(calls) == [1, 2, 3, 4]

    def test_audit_ledger_persisted(self, kswitch, tmp_db):
        import sqlite3
        kswitch.activate(1, actor="tester", reason="unit test")
        conn = sqlite3.connect(tmp_db)
        rows = conn.execute("SELECT action, actor, reason FROM killswitch_ledger").fetchall()
        conn.close()
        assert ("ACTIVATED", "tester", "unit test") in rows

    def test_stand_down_needs_pin_after_isolate(self, kswitch):
        kswitch.activate(2, pin="1337")
        assert not kswitch.stand_down()["success"]
        assert kswitch.stand_down(pin="1337")["success"]
        assert kswitch.active_level == 0

    def test_disarmed_switch_refuses(self, kswitch):
        kswitch.disarm("1337")
        result = kswitch.activate(1)
        assert not result["success"]
        kswitch.arm("1337")
        assert kswitch.activate(1)["success"]

    def test_invalid_level(self, kswitch):
        assert not kswitch.activate(99)["success"]


# ------------------------------------------------------------------ NLP
class TestThreatNLP:
    @pytest.fixture
    def nlp(self):
        from sentinel.nlp import ThreatNLP
        return ThreatNLP()

    SAMPLE = (
        "CVE-2024-3400 exploited in the wild by PAN-OS devices. "
        "Attackers from APT38 used remote code execution via a web exploit; "
        "C2 callbacks to evil-corp.example.com from 198.51.100.23. "
        "Malware hash: " + "ab" * 32
    )

    def test_ioc_extraction(self, nlp):
        iocs = nlp.extract_iocs(self.SAMPLE)
        assert "CVE-2024-3400" in iocs["cve_ids"]
        assert "198.51.100.23" in iocs["ipv4"]
        assert "evil-corp.example.com" in iocs["domains"]
        assert "ab" * 32 in [h.lower() for h in iocs["sha256"]]
        assert any("APT38" in a.upper() for a in iocs["actors"])

    def test_cvss_estimate(self, nlp):
        est = nlp.estimate_cvss("A wormable zero-day allows remote code execution")
        assert est["score"] >= 9.0
        assert est["severity"] == "critical"

    def test_mitre_mapping(self, nlp):
        hits = nlp.map_mitre("attacker delivered phishing email with malicious attachment")
        assert any(h["technique"] == "T1566" for h in hits)

    def test_urgency_classification(self, nlp):
        assert nlp.classify_urgency("actively exploited zero-day, patch immediately") == "critical"
        assert nlp.classify_urgency("purely theoretical issue") == "low"

    def test_full_analyze_and_dedupe(self, nlp):
        a1 = nlp.analyze(self.SAMPLE)
        assert a1["ioc_total"] > 0
        assert 0 <= a1["confidence"] <= 1
        a2 = nlp.analyze(self.SAMPLE)  # exact duplicate
        assert len(a2["near_duplicate_of"]) >= 1

    def test_status(self, nlp):
        st = nlp.get_status()
        assert st["mitre_techniques_mapped"] > 0


# ------------------------------------------------------------ correlator
class TestIncidentCorrelator:
    @pytest.fixture
    def corr(self):
        from sentinel.correlator import IncidentCorrelator
        return IncidentCorrelator(window_seconds=60, close_ttl=120)

    def test_single_event_opens_incident(self, corr):
        res = corr.ingest("honeypot_hit", {"source_ip": "1.2.3.4"})
        assert res["accepted"]
        assert res["incident_id"] >= 1000

    def test_unknown_event_rejected(self, corr):
        assert not corr.ingest("not_a_real_event", {})["accepted"]

    def test_same_ip_chains_into_one_incident(self, corr):
        r1 = corr.ingest("port_scan", {"source_ip": "9.9.9.9"})
        r2 = corr.ingest("brute_force", {"source_ip": "9.9.9.9"})
        r3 = corr.ingest("exploit_attempt", {"source_ip": "9.9.9.9"})
        assert r1["incident_id"] == r2["incident_id"] == r3["incident_id"]
        inc = corr.get_incident(r1["incident_id"])
        assert "INITIAL_ACCESS" in inc["stages_seen"]
        assert inc["confidence"] > r1["confidence"]  # grows with chain depth

    def test_impact_stage_forces_critical(self, corr):
        corr.ingest("canary_tripped", {"file_path": "/home/u/docs/a.txt"})
        incidents = corr.get_incidents(status="OPEN")
        assert incidents[0]["severity"] == "critical"

    def test_narrative_generated(self, corr):
        corr.ingest("fim_violation", {"file_path": "/etc/passwd"})
        inc = corr.get_incidents()[0]
        assert len(inc["narrative"]) == 1
        assert "PERSISTENCE" in inc["narrative"][0]["stage_label"] or \
               "Persistence" in inc["narrative"][0]["stage_label"]

    def test_close_incident(self, corr):
        res = corr.ingest("dns_tunneling", {"source_ip": "5.5.5.5"})
        assert corr.close(res["incident_id"], "resolved")["success"]
        assert corr.get_incident(res["incident_id"])["status"] == "CLOSED"

    def test_stats(self, corr):
        corr.ingest("anomaly_detected", {"process": "svchost.exe"})
        st = corr.get_stats()
        assert st["events_ingested"] == 1
        assert st["open_incidents"] == 1
