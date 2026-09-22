"""
Pydantic schemas for request/response validation
Enterprise-grade with authentication and system control models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# ============== Authentication Schemas ==============

class Token(BaseModel):
    """JWT Token response schema"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLogin(BaseModel):
    """User login schema"""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)


class UserCreate(BaseModel):
    """User creation schema"""
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$')
    password: str = Field(..., min_length=6, max_length=100)
    role: str = Field(default="viewer", pattern="^(admin|viewer)$")


class User(BaseModel):
    """User schema"""
    id: int
    username: str
    email: str
    role: str
    disabled: bool = False


# ============== System Metrics Schemas ==============

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


class ProcessInfo(BaseModel):
    """Process information schema"""
    pid: int
    name: str
    status: str
    username: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None


class NetworkConnection(BaseModel):
    """Network connection schema"""
    family: str
    type: str
    local_address: Optional[str] = None
    remote_address: Optional[str] = None
    status: Optional[str] = None
    pid: Optional[int] = None


# ============== Threat Alert Schemas ==============

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


# ============== Skill Log Schemas ==============

class SkillLog(BaseModel):
    """Skill/knowledge log entry schema"""
    id: Optional[int] = None
    skill_name: str = Field(..., description="Name of the skill")
    category: str = Field(..., description="Skill category")
    description: str = Field(..., description="Skill description")
    code_path: Optional[str] = Field(None, description="Path to skill code file")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ============== System Control Schemas ==============

class CommandRequest(BaseModel):
    """Command execution request schema"""
    command: str = Field(..., min_length=1, max_length=1000)
    timeout: int = Field(default=30, ge=1, le=300)


class CommandResponse(BaseModel):
    """Command execution response schema"""
    success: bool
    stdout: str
    stderr: str
    command: str


class ProcessKillRequest(BaseModel):
    """Process kill request schema"""
    pid: int = Field(..., gt=0)
    force: bool = Field(default=False)


class IPBlockRequest(BaseModel):
    """IP block request schema"""
    ip: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    reason: str = Field(default="Security threat", max_length=200)


class TerminalSessionCreate(BaseModel):
    """Terminal session creation response"""
    session_id: str
    message: str


# ============== Browser Automation Schemas ==============

class BrowserNavigateRequest(BaseModel):
    """Browser navigation request schema"""
    url: str = Field(..., min_length=1)
    wait_until: str = Field(default="networkidle")
    timeout: int = Field(default=30000, ge=1000, le=120000)


class BrowserScreenshotRequest(BaseModel):
    """Browser screenshot request schema"""
    name: Optional[str] = None
    full_page: bool = Field(default=False)


class BrowserClickRequest(BaseModel):
    """Browser click request schema"""
    selector: str = Field(..., min_length=1)
    timeout: int = Field(default=5000, ge=100, le=30000)


class BrowserFillRequest(BaseModel):
    """Browser fill request schema"""
    selector: str = Field(..., min_length=1)
    value: str
    timeout: int = Field(default=5000, ge=100, le=30000)


class BrowserEvaluateRequest(BaseModel):
    """Browser JavaScript evaluation request schema"""
    javascript: str = Field(..., min_length=1)


# ============== Notification Schemas ==============

class NotificationConfig(BaseModel):
    """Notification configuration schema"""
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    enabled_channels: List[str] = Field(default=["discord"])


class TestNotificationRequest(BaseModel):
    """Test notification request schema"""
    message: Optional[str] = "Test notification from AI Security Dashboard"


class ResourceAlertRequest(BaseModel):
    """Resource alert request schema"""
    resource_type: str = Field(default="CPU")
    value: float = Field(..., ge=0, le=100)
    threshold: float = Field(default=90, ge=0, le=100)


class ThreatAlertRequest(BaseModel):
    """Threat alert request schema"""
    title: str
    severity: str = Field(pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    source: str
    cve_id: Optional[str] = None
    affected_systems: str


# ============== Response Wrapper Schemas ==============

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


class ProcessListResponse(BaseModel):
    """Response for process list endpoint"""
    processes: List[ProcessInfo]
    total: int


class NetworkStatusResponse(BaseModel):
    """Response for network status endpoint"""
    connections: List[NetworkConnection]
    listening_ports: List[Dict[str, Any]]
    total_connections: int


class APIResponse(BaseModel):
    """Generic API response wrapper"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None