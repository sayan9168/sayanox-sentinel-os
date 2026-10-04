"""
Threat Intelligence NLP Engine - Phase 5 Advanced Feature
=========================================================
Turns raw threat-intel text (RSS/CVE scrapes, honeypot banners, FIM audit
notes) into structured intelligence without any external LLM dependency:

1. CVE ID extraction & CVSS-style severity scoring heuristics
2. MITRE ATT&CK technique mapping via curated keyword taxonomy
3. IOC extraction: IPs, domains, URLs, SHA-256 hashes, email addresses
4. Threat-actor naming detection (APTxx / Lazarus / Fin7 style aliases)
5. Sentiment/urgency classification for triage prioritisation
6. Text similarity clustering (TF-IDF cosine) to deduplicate intel feeds

Everything is pure-Python + regex so it runs in CI with zero network access.
"""

import math
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- regex IOCs
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|"
    r"xyz|top|info|biz|tk|ml|ga|cf|gq|hu|su|onion)\b", re.IGNORECASE)
ACTOR_RE = re.compile(
    r"\b(?:APT\d{1,4}|Lazarus|Fin\s?7|Cozy\s?Bear|Fancy\s?Bear|Turla|"
    r"Equation Group|Kimsuky|Sandworm|Charming Kitten|DarkSide|Revil|"
    r"LockBit|Conti|BlackCat|ALPHV|Ryuk|Maze|Cl0p)\b", re.IGNORECASE)

CVSS_HINTS = {
    "remote code execution": 9.8, "rce": 9.8, "zero-day": 9.0, "zeroday": 9.0,
    "privilege escalation": 7.8, "buffer overflow": 7.5, "sql injection": 8.1,
    "xss": 6.1, "denial of service": 5.3, "dos": 5.3, "ddos": 7.5,
    "information disclosure": 5.3, "authentication bypass": 8.2,
    "deserialization": 7.2, "path traversal": 5.3, "ssrf": 6.8,
    "ransomware": 9.3, "supply chain": 8.5, "wormable": 9.5,
}

# MITRE ATT&CK keyword taxonomy (subset, curated for security ops)
MITRE_TAXONOMY: Dict[str, List[str]] = {
    "T1059": ["command", "shell", "powershell", "bash", "script execution"],
    "T1071": ["http beacon", "c2", "command and control", "callback"],
    "T1027": ["obfuscated", "packed", "encoded payload", "encrypted binary"],
    "T1566": ["phishing", "spear phishing", "malicious attachment", "email lure"],
    "T1078": ["stolen credentials", "valid accounts", "credential reuse"],
    "T1486": ["data encrypted for impact", "ransom note", "double extortion"],
    "T1490": ["shadow copy deletion", "vssadmin delete", "disable recovery"],
    "T1053": ["scheduled task", "cron persistence", "at job"],
    "T1005": ["data from local system", "database dump", "file collection"],
    "T1046": ["port scan", "network service discovery", "nmap"],
    "T1190": ["exploit public application", "web exploit", "cvss"],
    "T1048": ["exfiltration over alternative protocol", "dns tunneling"],
    "T1547": ["run key", "startup folder", "registry autorun"],
}

URGENCY_WORDS = {
    "critical": ["actively exploited", "in the wild", "mass exploitation",
                 "zero-day", "urgent", "immediate patch", "kev"],
    "high": ["exploit available", "proof of concept", "poof of concept",
             "public exploit", "attack campaign"],
    "low": ["theoretical", "proof-of-concept only", "lab environment"],
}


class ThreatNLP:
    """Pure-python threat-intelligence text analytics."""

    def __init__(self):
        self.corpus: List[Tuple[str, Dict[str, float]]] = []  # (text, tfidf vec)

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[a-z0-9_/-]{2,}", text.lower())

    def _tfidf(self, tokens: List[str]) -> Dict[str, float]:
        tf = Counter(tokens)
        n = len(tokens) or 1
        vec: Dict[str, float] = {}
        for tok, c in tf.items():
            df = sum(1 for _, v in self.corpus if tok in v) + 1
            idf = math.log((len(self.corpus) + 1) / df) + 1.0
            vec[tok] = (c / n) * idf
        return vec

    # -------------------------------------------------------- extraction
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        return {
            "cve_ids": sorted(set(m.group(0).upper() for m in CVE_RE.finditer(text))),
            "ipv4": sorted(set(IPV4_RE.findall(text))),
            "urls": sorted(set(URL_RE.findall(text))),
            "domains": sorted(set(d.lower() for d in DOMAIN_RE.findall(text))),
            "sha256": sorted(set(SHA256_RE.findall(text))),
            "emails": sorted(set(EMAIL_RE.findall(text))),
            "actors": sorted(set(m.group(0) for m in ACTOR_RE.finditer(text))),
        }

    def estimate_cvss(self, text: str) -> Dict[str, Any]:
        low = text.lower()
        best_score = 0.0
        matched: List[str] = []
        for hint, score in CVSS_HINTS.items():
            if hint in low:
                matched.append(hint)
                best_score = max(best_score, score)
        if not matched:
            best_score = 4.0  # unknown default
        severity = ("critical" if best_score >= 9.0 else
                    "high" if best_score >= 7.0 else
                    "medium" if best_score >= 4.0 else "low")
        return {"score": round(best_score, 1), "severity": severity,
                "matched_indicators": matched}

    def map_mitre(self, text: str) -> List[Dict[str, str]]:
        low = text.lower()
        hits = []
        for technique, keywords in MITRE_TAXONOMY.items():
            for kw in keywords:
                if kw in low:
                    hits.append({"technique": technique, "keyword": kw})
                    break
        return hits

    def classify_urgency(self, text: str) -> str:
        low = text.lower()
        for level in ("critical", "high", "low"):
            if any(w in low for w in URGENCY_WORDS[level]):
                return level
        return "medium"

    # ------------------------------------------------------- dedup/clustering
    def analyze(self, text: str) -> Dict[str, Any]:
        """Full analysis pipeline; also indexes text for near-duplicate checks."""
        iocs = self.extract_iocs(text)
        cvss = self.estimate_cvss(text)
        mitre = self.map_mitre(text)
        urgency = self.classify_urgency(text)

        tokens = self._tokenize(text)
        vec = self._tfidf(tokens)
        dupes = [i for i, (_, v) in enumerate(self.corpus)
                 if self._cosine(vec, v) > 0.85]
        self.corpus.append((text[:200], vec))
        if len(self.corpus) > 2000:
            self.corpus = self.corpus[-1500:]

        confidence = min(1.0, 0.25 * len(iocs["cve_ids"]) +
                         0.2 * len(mitre) + 0.15 * len(iocs["actors"]) + 0.1)
        return {
            "iocs": iocs,
            "cvss_estimate": cvss,
            "mitre_techniques": mitre,
            "urgency": urgency,
            "confidence": round(confidence, 2),
            "near_duplicate_of": dupes,
            "ioc_total": sum(len(v) for v in iocs.values()),
        }

    @staticmethod
    def _cosine(a: Dict[str, float], b: Dict[str, float]) -> float:
        common = set(a) & set(b)
        if not common:
            return 0.0
        dot = sum(a[k] * b[k] for k in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return dot / (na * nb) if na and nb else 0.0

    def get_status(self) -> Dict[str, Any]:
        return {
            "corpus_size": len(self.corpus),
            "supported_ioc_types": ["cve_ids", "ipv4", "urls", "domains",
                                    "sha256", "emails", "actors"],
            "mitre_techniques_mapped": len(MITRE_TAXONOMY),
        }


# Singleton instance
threat_nlp = ThreatNLP()
