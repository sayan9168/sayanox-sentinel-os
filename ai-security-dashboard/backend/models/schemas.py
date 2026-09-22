"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class SystemMetrics(BaseModel):
    """System resource metrics schema"""
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    cpu_percent: float = Field(..., description="CPU usage percentage")
    memory_percent: float = Field(..., description="Memory usage percentage")
    memory_used: int = Field(..., description="Memory used in bytes")
    memory_total: int = Field(..., description="Total memory in bytes")
    disk_percent: float = Field(..., description="Disk usage percentage")
    network_sent: int = Field(..., description="Network bytes sent")
    network_recv: int = Field(..., description="Network bytes received")
    process_count: int = Field(..., description="Number of running processes")
    
    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2024-01-15T10:30:00",
                "cpu_percent": 45.2,
                "memory_percent": 62.8,
                "memory_used": 8589934592,
                "memory_total": 17179869184,
                "disk_percent": 55.0,
                "network_sent": 1024000,
                "network_recv": 2048000,
                "process_count": 156
            }
        }


class ThreatAlert(BaseModel):
    """Security threat alert schema"""
    id: Optional[int] = None
    title: str = Field(..., description="Threat title")
    source: str = Field(..., description="Source of the threat information")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    description: str = Field(..., description="Detailed description")
    url: Optional[str] = Field(None, description="Reference URL")
    cve_id: Optional[str] = Field(None, description="CVE identifier if applicable")
    affected_systems: Optional[str] = Field(None, description="Affected systems or software")
    published_date: Optional[str] = Field(None, description="Publication date")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    class Config:
        json_schema_extra = {
            "example": {
                "title": "Critical Vulnerability in OpenSSL",
                "source": "CISA",
                "severity": "CRITICAL",
                "description": "A critical vulnerability allowing remote code execution...",
                "url": "https://www.cisa.gov/news-events/alerts/2024/01/15",
                "cve_id": "CVE-2024-0001",
                "affected_systems": "OpenSSL 1.1.1, 3.0.x",
                "published_date": "2024-01-15"
            }
        }


class SkillLog(BaseModel):
    """Skill/knowledge log entry schema"""
    id: Optional[int] = None
    skill_name: str = Field(..., description="Name of the skill")
    category: str = Field(..., description="Skill category")
    description: str = Field(..., description="Skill description")
    code_path: Optional[str] = Field(None, description="Path to skill code file")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    class Config:
        json_schema_extra = {
            "example": {
                "skill_name": "threat_scraper",
                "category": "security",
                "description": "Automated security advisory scraper for CISA and NVD",
                "code_path": ".skills/threat_scraper.py",
                "metadata": {"version": "1.0", "last_updated": "2024-01-15"}
            }
        }


class MetricsHistoryResponse(BaseModel):
    """Response for metrics history endpoint"""
    data: List[SystemMetrics]
    count: int
    time_range: Dict[str, str]


class ThreatsResponse(BaseModel):
    """Response for threats endpoint"""
    threats: List[ThreatAlert]
    count: int
    severity_breakdown: Dict[str, int]


class SkillsResponse(BaseModel):
    """Response for skills endpoint"""
    skills: List[SkillLog]
    count: int
    categories: List[str]
