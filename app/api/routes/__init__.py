"""
Zero-Trust AI Gateway — API Routes.

Endpoints:
  POST /proxy         — Mask + forward prompt to LLM
  POST /inspect       — Detect PII without forwarding (audit mode)
  GET  /audit/{sid}   — Session audit trail
  GET  /dashboard     — Aggregate risk metrics
  GET  /blocked       — Recent blocked requests (security ops)
  GET  /pii-frequency — PII type frequency report (compliance)
  DELETE /session/{sid} — Purge session token map from Redis
"""
from datetime import datetime
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Query, Path, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import ValidationException, SessionNotFoundException
from app.schemas.gateway import (
    GatewayRequest, InspectRequest, InspectResponse,
    MaskingSummary, MaskingPolicy,
)
from app.services.masking_service import PIIMaskingService
from app.services.proxy_service import ZeroTrustProxyService
from app.repositories.gateway_repository import GatewayRepository

limiter = Limiter(key_func=get_remote_address)
gateway_router = APIRouter()


# ─── Dependency Injection ─────────────────────────────────────────────────────

def get_masking_service() -> PIIMaskingService:
    return PIIMaskingService()


def get_proxy_service(
    db: AsyncSession = Depends(get_db),
    masking_service: PIIMaskingService = Depends(get_masking_service),
) -> ZeroTrustProxyService:
    repo = GatewayRepository(db)
    return ZeroTrustProxyService(masking_service, repo)


def get_repository(db: AsyncSession = Depends(get_db)) -> GatewayRepository:
    return GatewayRepository(db)


# ─── Routes ───────────────────────────────────────────────────────────────────

@gateway_router.post("/proxy", summary="Proxy Prompt Through Zero-Trust Masking Layer")
@limiter.limit("30/minute")
async def proxy_prompt(
    request_body: GatewayRequest,
    request: Request,
    service: ZeroTrustProxyService = Depends(get_proxy_service),
):
    """
    Submit a prompt to be masked and proxied to the external LLM.

    **Masking Policies:**
    - `mask_and_forward` — Mask all PII/secrets, always forward to LLM
    - `block_on_critical` — Block if API keys, private keys, SSNs, or credit cards detected
    - `inspect_only` — Audit mode: detect and report PII, do NOT forward to LLM

    **What gets masked (Regex Phase):**
    API keys (OpenAI, Anthropic, AWS, GitHub), JWTs, private key blocks,
    SSNs, emails, phone numbers, credit cards, IBANs, IPs, connection strings,
    bearer tokens, generic passwords in config format.

    **What gets masked (NER Phase, if spaCy available):**
    Person names, organization names, geopolitical entities, locations.

    **Rate limit:** 30 requests/minute per IP
    """
    session_id = request_body.session_id or str(uuid.uuid4())
    client_ip = request.client.host if request.client else None

    if request_body.policy == MaskingPolicy.INSPECT_ONLY:
        masking_svc = PIIMaskingService()
        result = masking_svc.mask(request_body.prompt, session_id)
        risk = masking_svc.get_risk_summary(result)
        return {
            "mode": "inspect_only",
            "session_id": session_id,
            "masking_summary": {
                "total_items_masked": result.total_masked,
                "risk_level": risk["risk_level"],
                "pii_types_detected": risk["pii_types_detected"],
                "detections": result.detections,
                "processing_ms": result.processing_ms,
            },
            "masked_preview": result.masked_text[:500] + ("..." if len(result.masked_text) > 500 else ""),
            "note": "inspect_only mode — prompt was NOT forwarded to any external LLM",
        }

    return await service.proxy_request(
        prompt=request_body.prompt,
        session_id=session_id,
        policy=request_body.policy.value,
        unmask_response=request_body.unmask_response,
        metadata=request_body.metadata,
        client_ip=client_ip,
    )


@gateway_router.post("/inspect", response_model=InspectResponse, summary="Inspect Text for PII (No LLM Forward)")
@limiter.limit("60/minute")
async def inspect_text(
    request_body: InspectRequest,
    request: Request,
    masking_service: PIIMaskingService = Depends(get_masking_service),
):
    """
    Analyze text for PII and secrets WITHOUT forwarding to any LLM.
    Use for pre-flight checks, CI/CD pipeline scans, and compliance audits.

    Returns full detection report with masked preview. Never calls external APIs.

    **Rate limit:** 60 requests/minute per IP
    """
    session_id = request_body.session_id or str(uuid.uuid4())
    result = masking_service.mask(request_body.text, session_id)
    risk = masking_service.get_risk_summary(result)

    return InspectResponse(
        original_hash=result.original_hash,
        masking_summary=MaskingSummary(
            total_items_masked=result.total_masked,
            risk_level=risk["risk_level"],
            pii_types_detected=risk["pii_types_detected"],
            detections=result.detections,
            processing_ms=result.processing_ms,
        ),
        masked_preview=result.masked_text[:500] + ("..." if len(result.masked_text) > 500 else ""),
        session_id=session_id,
        timestamp=datetime.utcnow(),
    )


@gateway_router.get("/audit/{session_id}", summary="Get Audit Trail for a Session")
@limiter.limit("20/minute")
async def get_session_audit(
    session_id: str = Path(..., min_length=1, max_length=100),
    request: Request = None,
    limit: int = Query(50, ge=1, le=200),
    repo: GatewayRepository = Depends(get_repository),
):
    """Retrieve the full audit trail for a session. Ordered newest-first."""
    import re
    if not re.match(r'^[a-zA-Z0-9\-_\.]{1,100}$', session_id):
        raise ValidationException("Invalid session_id format", fields=["session_id"])

    logs = await repo.get_session_history(session_id, limit)
    return {
        "session_id": session_id,
        "total_records": len(logs),
        "audit_log": [
            {
                "request_id": log.request_id,
                "risk_level": log.risk_level,
                "total_masked": log.total_masked,
                "pii_types_detected": log.pii_types_detected,
                "policy_applied": log.policy_applied,
                "was_blocked": log.was_blocked,
                "total_processing_ms": log.total_processing_ms,
                "timestamp": log.timestamp.isoformat(),
            }
            for log in logs
        ],
    }


@gateway_router.get("/dashboard", summary="Risk Dashboard — Aggregate Metrics")
@limiter.limit("20/minute")
async def risk_dashboard(
    request: Request,
    repo: GatewayRepository = Depends(get_repository),
):
    """Security operations dashboard. Returns aggregate masking and blocking statistics."""
    return await repo.get_risk_dashboard()


@gateway_router.get("/blocked", summary="Recent Blocked Requests (Security Ops)")
@limiter.limit("20/minute")
async def get_blocked_requests(
    request: Request,
    hours_back: int = Query(24, ge=1, le=168),
    limit: int = Query(50, ge=1, le=500),
    repo: GatewayRepository = Depends(get_repository),
):
    """
    Fetch recent policy-blocked requests.
    Use for security incident triage and analyst review workflows.
    """
    blocked = await repo.get_blocked_requests(hours_back=hours_back, limit=limit)
    return {
        "hours_back": hours_back,
        "total_blocked": len(blocked),
        "blocked_requests": [
            {
                "request_id": b.request_id,
                "session_id": b.session_id,
                "critical_pii_types": b.critical_pii_types,
                "total_detections": b.total_detections,
                "block_reason": b.block_reason,
                "client_ip": b.client_ip,
                "blocked_at": b.blocked_at.isoformat(),
                "reviewed": b.reviewed,
            }
            for b in blocked
        ],
    }


@gateway_router.get("/pii-frequency", summary="PII Type Frequency Report (Compliance)")
@limiter.limit("10/minute")
async def pii_frequency_report(
    request: Request,
    days_back: int = Query(7, ge=1, le=90),
    repo: GatewayRepository = Depends(get_repository),
):
    """
    Aggregate frequency of each PII type detected over the past N days.
    Answers: 'Which types of sensitive data are employees most often
    accidentally including in LLM prompts?'

    Essential for CISO-level reporting and DLP policy tuning.
    """
    frequency = await repo.get_pii_type_frequency(days_back=days_back)
    return {
        "days_back": days_back,
        "total_pii_types_seen": len(frequency),
        "frequency_by_type": frequency,
        "top_5": dict(list(frequency.items())[:5]),
    }


__all__ = ["gateway_router"]
