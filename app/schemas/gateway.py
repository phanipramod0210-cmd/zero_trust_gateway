"""Pydantic v2 schemas for Zero-Trust AI Gateway."""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum


class MaskingPolicy(str, Enum):
    MASK_AND_FORWARD = "mask_and_forward"      # Mask PII, always forward
    BLOCK_ON_CRITICAL = "block_on_critical"    # Block if critical secrets found
    INSPECT_ONLY = "inspect_only"              # Report PII but don't mask (audit mode)


class GatewayRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=50_000)
    session_id: Optional[str] = Field(None, max_length=100)
    policy: MaskingPolicy = MaskingPolicy.MASK_AND_FORWARD
    unmask_response: bool = False
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt cannot be blank or whitespace-only")
        return v

    @field_validator("session_id")
    @classmethod
    def sanitize_session_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import re
        if not re.match(r'^[a-zA-Z0-9\-_\.]{1,100}$', v):
            raise ValueError("session_id must be alphanumeric with hyphens/underscores only")
        return v


class DetectionDetail(BaseModel):
    pii_type: str
    method: Literal["regex", "spacy_ner"]
    position: int
    mask_token: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class MaskingSummary(BaseModel):
    total_items_masked: int
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "NONE"]
    pii_types_detected: List[str]
    detections: List[Dict[str, Any]]
    processing_ms: float


class GatewayResponse(BaseModel):
    request_id: str
    session_id: str
    masked_prompt: Optional[str] = None  # Only returned if include_masked_prompt=True
    llm_response: str
    masking_summary: MaskingSummary
    policy_applied: MaskingPolicy
    was_blocked: bool = False
    total_processing_ms: float
    timestamp: datetime


class InspectRequest(BaseModel):
    """Inspect-only mode — detect PII without forwarding to LLM."""
    text: str = Field(..., min_length=1, max_length=50_000)
    session_id: Optional[str] = None


class InspectResponse(BaseModel):
    original_hash: str
    masking_summary: MaskingSummary
    masked_preview: str  # First 500 chars of masked text
    session_id: str
    timestamp: datetime


class AuditLogEntry(BaseModel):
    request_id: str
    session_id: str
    risk_level: str
    total_masked: int
    pii_types: List[str]
    policy_applied: str
    was_blocked: bool
    processing_ms: float
    timestamp: str
