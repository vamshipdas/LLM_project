import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Text, DateTime, ForeignKey, Integer, Enum, Boolean, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    ANALYST = "analyst"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"USR-{uuid.uuid4().hex[:12]}"
    )
    username: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), default=Role.ANALYST, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    sessions = relationship(
        "ChatSession", back_populates="user", cascade="all, delete-orphan"
    )
    log_uploads = relationship(
        "LogUpload", back_populates="user", cascade="all, delete-orphan"
    )



class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"CHAT-{uuid.uuid4().hex[:12]}"
    )
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, default="New Chat", nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    user = relationship("User", back_populates="sessions")
    messages = relationship(
        "ChatMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessage.created_at",
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"MSG-{uuid.uuid4().hex[:12]}"
    )
    session_id: Mapped[str] = mapped_column(
        String, ForeignKey("chat_sessions.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(String, nullable=False)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    session = relationship("ChatSession", back_populates="messages")


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"TKT-{uuid.uuid4().hex[:10].upper()}"
    )
    title: Mapped[str] = mapped_column(String, nullable=False)
    threat_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[Optional[str]] = mapped_column(String, default=None, nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    target_host: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class SOPDocument(Base):
    __tablename__ = "sop_documents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, default="general", nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    chunks = relationship(
        "SOPChunk", back_populates="document", cascade="all, delete-orphan"
    )


class SOPChunk(Base):
    __tablename__ = "sop_chunks"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"CHK-{uuid.uuid4().hex[:12]}"
    )
    sop_id: Mapped[str] = mapped_column(
        String, ForeignKey("sop_documents.id"), nullable=False
    )
    section: Mapped[str] = mapped_column(String, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)

    document = relationship("SOPDocument", back_populates="chunks")


class LogUpload(Base):
    __tablename__ = "log_uploads"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"UPL-{uuid.uuid4().hex[:12]}"
    )
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    user = relationship("User", back_populates="log_uploads")
    events = relationship(
        "LogEvent",
        back_populates="upload",
        cascade="all, delete-orphan",
        order_by="LogEvent.created_at",
    )
    findings = relationship(
        "Finding",
        back_populates="upload",
        cascade="all, delete-orphan",
        order_by="Finding.created_at",
    )


class LogEvent(Base):
    __tablename__ = "log_events"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"EVT-{uuid.uuid4().hex[:12]}"
    )
    upload_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("log_uploads.id", ondelete="CASCADE"), nullable=True, index=True
    )
    timestamp: Mapped[str] = mapped_column(String, nullable=False, index=True)
    level: Mapped[str] = mapped_column(String, default="INFO", nullable=False, index=True)
    source: Mapped[str] = mapped_column(String, default="System", nullable=False, index=True)
    event_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="low", nullable=False, index=True)
    severity_score: Mapped[int] = mapped_column(Integer, default=20, nullable=False)
    severity_reasons: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


    upload = relationship("LogUpload", back_populates="events")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"FND-{uuid.uuid4().hex[:12]}"
    )
    upload_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("log_uploads.id", ondelete="CASCADE"), nullable=True, index=True
    )
    severity: Mapped[str] = mapped_column(String, nullable=False, index=True)  # "low"|"medium"|"high"|"critical"
    category: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON serialized list
    first_seen: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    sop_recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sop_citations: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON serialized citations
    ticket_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    upload = relationship("LogUpload", back_populates="findings")


class LogChatMessage(Base):
    __tablename__ = "log_chat_messages"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"LCM-{uuid.uuid4().hex[:12]}"
    )
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String, nullable=False)  # "user" | "assistant"
    content: Mapped[str] = mapped_column(Text, nullable=False)
    detail_level: Mapped[str] = mapped_column(String, default="simple", nullable=False)
    context_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    citations_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    severity_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    suggested_questions_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class IPGeoCache(Base):
    __tablename__ = "ip_geo_cache"

    ip: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    country: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    lat: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    lon: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    org: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_tor_or_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source: Mapped[str] = mapped_column(String, default="demo", nullable=False)  # mmdb, online, demo, internal
    classification: Mapped[str] = mapped_column(String, default="public", nullable=False)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


# Alias IPGeo to IPGeoCache to satisfy both model names
IPGeo = IPGeoCache


class AttackerIP(Base):
    __tablename__ = "attacker_ips"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"AIP-{uuid.uuid4().hex[:12]}"
    )
    ip: Mapped[str] = mapped_column(String, index=True, nullable=False)
    upload_id: Mapped[Optional[str]] = mapped_column(
        String, ForeignKey("log_uploads.id", ondelete="CASCADE"), nullable=True, index=True
    )
    classification: Mapped[str] = mapped_column(String, default="public", nullable=False)
    source: Mapped[str] = mapped_column(String, default="demo", nullable=False)
    country: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    lat: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    lon: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    org: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_tor_or_vpn: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    max_severity: Mapped[str] = mapped_column(String, default="low", nullable=False)
    first_seen: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    linked_finding_ids: Mapped[str] = mapped_column(Text, default="[]", nullable=False)  # JSON array
    linked_event_ids: Mapped[str] = mapped_column(Text, default="[]", nullable=False)    # JSON array
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class NotificationLog(Base):
    __tablename__ = "notification_logs"

    id: Mapped[str] = mapped_column(
        String, primary_key=True, default=lambda: f"NOTIF-{uuid.uuid4().hex[:12]}"
    )
    alert_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    alert_type: Mapped[str] = mapped_column(String, default="ticket", nullable=False)
    alert_title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, default="critical", nullable=False)
    recipients: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)  # "sent" | "failed" | "skipped"
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    grouped_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


