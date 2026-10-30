from datetime import datetime
from enum import Enum as PyEnum
from typing import List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class Role(str, PyEnum):
    ANALYST = "analyst"
    ADMIN = "admin"


# --- Auth ----------------------------------------------------------------

class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    username: str
    role: Role


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: Role


# --- Chat ----------------------------------------------------------------

class ChatMessageIn(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatMessageOut(ChatMessageIn):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    created_at: datetime


class ChatSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    created_at: datetime
    updated_at: datetime


class ChatSessionListOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    updated_at: datetime
    archived: bool = False


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None  # if omitted, a new session is created


class ChatResponse(BaseModel):
    session_id: str = ""
    message: str  # assistant reply
    sources: List[dict] = []  # SOP citations


# --- Tickets -------------------------------------------------------------

class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    threat_type: str
    severity: str
    status: Optional[str]
    source_ip: Optional[str]
    target_host: Optional[str]
    description: str
    created_at: datetime


class TicketStatusUpdate(BaseModel):
    status: Optional[Literal["in_progress", "resolved"]]


class TicketCreate(BaseModel):
    title: str
    threat_type: str = "general"
    severity: str = "medium"
    status: Optional[str] = "open"
    source_ip: Optional[str] = None
    target_host: Optional[str] = None
    description: str = ""


class TicketSeverityUpdate(BaseModel):
    severity: str



# --- SOPs ----------------------------------------------------------------

class SOPDocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    filename: str
    category: str
    chunks_count: int


class SOPChunkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sop_id: str
    section: str
    content: str


# --- Log Analysis --------------------------------------------------------

class LogEventSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    timestamp: str
    level: str = "INFO"
    source: str = "System"
    event_id: Optional[str] = None
    message: str
    host: Optional[str] = None
    raw: Optional[str] = None
    severity: str = "low"
    severity_score: int = 20
    severity_reasons: List[str] = []

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):
        if hasattr(obj, "severity_reasons") and isinstance(obj.severity_reasons, str):
            try:
                import json
                reasons = json.loads(obj.severity_reasons)
                if isinstance(reasons, list):
                    # temporarily set attribute or build dict
                    d = {col.name: getattr(obj, col.name) for col in obj.__table__.columns}
                    d["severity_reasons"] = reasons
                    return super().model_validate(d, *args, **kwargs)
            except Exception:
                pass
        return super().model_validate(obj, *args, **kwargs)


class FindingSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    severity: str
    category: str
    title: str
    description: str
    evidence: List[str] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    mitre_technique: Optional[str] = None
    sop_recommendation: Optional[str] = None
    sop_citations: List[dict] = []
    ticket_id: Optional[str] = None
    created_at: Optional[datetime] = None


class LogUploadSummary(BaseModel):
    id: str
    filename: str
    file_size: int
    total_events: int
    levels_count: dict = {}
    severities_count: dict = {}
    top_sources: dict = {}
    time_range: dict = {}
    findings: List[FindingSchema] = []
    events_sample: List[LogEventSchema] = []



class LogEventsPageResponse(BaseModel):
    upload_id: str
    page: int
    page_size: int
    total: int
    events: List[LogEventSchema]


class AnalyzeResult(BaseModel):
    upload_id: Optional[str] = None
    total_findings: int
    findings: List[FindingSchema]
    tickets_created: List[str] = []
    summary: str


# --- Log Explainer Chat --------------------------------------------------

class LogChatContext(BaseModel):
    event_ids: List[str] = []
    finding_ids: List[str] = []
    upload_id: Optional[str] = None
    mode: Optional[str] = "live"  # "live" | "upload"
    raw_events: Optional[List[dict]] = []


class LogChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    context: Optional[LogChatContext] = None
    detail_level: Optional[Literal["simple", "technical"]] = "simple"


class SeveritySummary(BaseModel):
    severity: str = "low"
    score: int = 20
    reasons: List[str] = []


class LogChatResponse(BaseModel):
    session_id: str
    answer: str
    severity_summary: SeveritySummary
    citations: List[dict] = []
    suggested_questions: List[str] = []
    detail_level: str = "simple"


class LogChatMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    role: str
    content: str
    detail_level: str = "simple"
    severity_summary: Optional[dict] = None
    citations: List[dict] = []
    suggested_questions: List[str] = []
    created_at: datetime


# --- Threat Map & Geolocation --------------------------------------------

class IPGeo(BaseModel):
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    is_tor_or_vpn: bool = False
    source: str = "demo"  # mmdb | online | demo | internal
    classification: str = "public"  # public | internal | documentation | private | loopback


class AttackerIPOrigin(BaseModel):
    id: str
    ip: str
    upload_id: Optional[str] = None
    classification: str = "public"
    source: str = "demo"
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    is_tor_or_vpn: bool = False
    event_count: int = 1
    max_severity: str = "low"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    linked_finding_ids: List[str] = []
    is_active: bool = False


class AttackerIPDetail(AttackerIPOrigin):
    linked_events: List[LogEventSchema] = []


class HomeLocation(BaseModel):
    lat: float
    lon: float
    label: str = "Protected SOC Asset"


class HomeLocationUpdate(BaseModel):
    lat: float
    lon: float
    label: Optional[str] = None


class NotificationLogOut(BaseModel):
    id: str
    alert_id: str
    alert_type: str
    alert_title: str
    severity: str
    recipients: str
    status: str
    error_message: Optional[str] = None
    retry_count: int = 0
    grouped_count: int = 1
    created_at: datetime


class NotificationSettingsOut(BaseModel):
    enabled: bool
    min_severity: str
    recipients: List[str]
    cooldown_seconds: int
    smtp_configured: bool
    smtp_host: str
    smtp_port: int
    sender_email: str


class NotificationSettingsUpdate(BaseModel):
    enabled: Optional[bool] = None
    min_severity: Optional[str] = None
    recipients: Optional[List[str]] = None
    cooldown_seconds: Optional[int] = None
    smtp_password: Optional[str] = None
    sender_email: Optional[str] = None


class TestNotificationResponse(BaseModel):
    status: str
    message: str
    recipients: List[str]
    log_id: Optional[str] = None



