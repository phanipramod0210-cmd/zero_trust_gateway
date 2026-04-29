"""
SQLAlchemy ORM Models — Zero-Trust AI Gateway.

Two tables:
  - GatewayAuditLog  : immutable record of every proxied request
  - BlockedRequestLog: dedicated table for policy-blocked requests (critical PII detected)

Design: Original prompt text is NEVER stored. Only hashes and metadata.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean,
    DateTime, Text, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class GatewayAuditLog(Base):
    """
    Immutable audit record for every request processed by the gateway.
    Prompt content is never persisted — only its SHA-256 hash.
    """
    __tablename__ = "gateway_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(36), nullable=False, unique=True, index=True)
    session_id = Column(String(100), nullable=False, index=True)

    # Prompt fingerprint only — no raw content stored
    original_prompt_hash = Column(String(64), nullable=False)
    prompt_char_count = Column(Integer, default=0)

    # Masking results
    total_masked = Column(Integer, default=0)
    pii_types_detected = Column(JSONB, default=list)
    risk_level = Column(String(20), nullable=False, index=True)

    # Policy & routing
    policy_applied = Column(String(50), nullable=False)
    was_blocked = Column(Boolean, default=False, index=True)
    block_reason = Column(String(200))
    unmask_requested = Column(Boolean, default=False)

    # Performance
    masking_time_ms = Column(Float)
    llm_time_ms = Column(Float)
    total_processing_ms = Column(Float)

    # Audit metadata
    client_ip = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_audit_session_timestamp", "session_id", "timestamp"),
        Index("idx_audit_risk_blocked", "risk_level", "was_blocked"),
    )


class BlockedRequestLog(Base):
    """
    Dedicated high-visibility table for all policy-blocked requests.
    Separating blocked requests enables faster security alerting queries.
    """
    __tablename__ = "blocked_request_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(36), nullable=False, unique=True, index=True)
    session_id = Column(String(100), nullable=False, index=True)
    original_prompt_hash = Column(String(64), nullable=False)
    critical_pii_types = Column(JSONB, default=list)
    total_detections = Column(Integer, default=0)
    block_reason = Column(String(500), nullable=False)
    policy_applied = Column(String(50), nullable=False)
    client_ip = Column(String(50))
    blocked_at = Column(DateTime, default=datetime.utcnow, index=True)
    reviewed = Column(Boolean, default=False)
    reviewed_by = Column(String(200))
    review_notes = Column(Text)
