"""
Gateway Audit Repository — Zero-Trust AI Gateway.

Strict Service-Repository pattern: all DB operations isolated here.
The GatewayAuditRepository in database.py is the embedded version;
this standalone file is the canonical implementation following the
project's architectural standard.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_
from loguru import logger

from app.models.gateway import GatewayAuditLog, BlockedRequestLog
from app.core.exceptions import AuditRepositoryException


class GatewayRepository:
    """
    All PostgreSQL interactions for the Zero-Trust Gateway.
    Never raises generic exceptions — wraps all errors in AuditRepositoryException.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # ─── Write Operations ─────────────────────────────────────────────────────

    async def log_request(self, record: Dict[str, Any]) -> None:
        """Persist an audit record for every proxied request."""
        try:
            entry = GatewayAuditLog(
                request_id=record["request_id"],
                session_id=record["session_id"],
                original_prompt_hash=record["original_prompt_hash"],
                prompt_char_count=record.get("prompt_char_count", 0),
                total_masked=record.get("total_masked", 0),
                pii_types_detected=record.get("pii_types", []),
                risk_level=record["risk_level"],
                policy_applied=record["policy_applied"],
                was_blocked=record.get("was_blocked", False),
                block_reason=record.get("block_reason"),
                unmask_requested=record.get("unmask_requested", False),
                masking_time_ms=record.get("masking_time_ms"),
                llm_time_ms=record.get("llm_time_ms"),
                total_processing_ms=record.get("processing_ms"),
                client_ip=record.get("client_ip"),
            )
            self.session.add(entry)
            await self.session.commit()
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to log audit record: {e}")
            raise AuditRepositoryException(str(e), "log_request")

    async def log_blocked_request(
        self,
        request_id: str,
        session_id: str,
        reason: str,
        risk_summary: Dict[str, Any],
        client_ip: Optional[str] = None,
    ) -> None:
        """Write to the dedicated blocked-requests table and the main audit log."""
        try:
            blocked = BlockedRequestLog(
                request_id=request_id,
                session_id=session_id,
                original_prompt_hash=risk_summary.get("hash", "unknown"),
                critical_pii_types=risk_summary.get("critical_findings", []),
                total_detections=risk_summary.get("total_detections", 0),
                block_reason=reason,
                policy_applied="block_on_critical",
                client_ip=client_ip,
            )
            self.session.add(blocked)

            # Also write to main audit log for unified querying
            audit = GatewayAuditLog(
                request_id=f"blocked-{request_id}",
                session_id=session_id,
                original_prompt_hash=risk_summary.get("hash", "unknown"),
                total_masked=risk_summary.get("total_detections", 0),
                pii_types_detected=risk_summary.get("pii_types_detected", []),
                risk_level="CRITICAL",
                policy_applied="block_on_critical",
                was_blocked=True,
                block_reason=reason,
                client_ip=client_ip,
            )
            self.session.add(audit)
            await self.session.commit()
            logger.critical(
                f"[SECURITY] Request BLOCKED and logged | "
                f"id={request_id} reason={reason} "
                f"types={risk_summary.get('critical_findings', [])}"
            )
        except Exception as e:
            await self.session.rollback()
            raise AuditRepositoryException(str(e), "log_blocked_request")

    # ─── Read Operations ──────────────────────────────────────────────────────

    async def get_session_history(
        self, session_id: str, limit: int = 50
    ) -> List[GatewayAuditLog]:
        """Full audit trail for a session, newest first."""
        try:
            result = await self.session.execute(
                select(GatewayAuditLog)
                .where(GatewayAuditLog.session_id == session_id)
                .order_by(desc(GatewayAuditLog.timestamp))
                .limit(min(limit, 200))
            )
            return result.scalars().all()
        except Exception as e:
            raise AuditRepositoryException(str(e), "get_session_history")

    async def get_blocked_requests(
        self, hours_back: int = 24, limit: int = 100
    ) -> List[BlockedRequestLog]:
        """Fetch recent blocked requests for security alerting."""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours_back)
            result = await self.session.execute(
                select(BlockedRequestLog)
                .where(BlockedRequestLog.blocked_at >= cutoff)
                .order_by(desc(BlockedRequestLog.blocked_at))
                .limit(min(limit, 500))
            )
            return result.scalars().all()
        except Exception as e:
            raise AuditRepositoryException(str(e), "get_blocked_requests")

    async def get_risk_dashboard(self) -> Dict[str, Any]:
        """Aggregate metrics for the security dashboard endpoint."""
        try:
            result = await self.session.execute(
                select(
                    func.count(GatewayAuditLog.id).label("total_requests"),
                    func.coalesce(func.sum(GatewayAuditLog.total_masked), 0).label("total_pii_masked"),
                    func.count(GatewayAuditLog.id).filter(
                        GatewayAuditLog.was_blocked == True
                    ).label("blocked_count"),
                    func.count(GatewayAuditLog.id).filter(
                        GatewayAuditLog.risk_level == "CRITICAL"
                    ).label("critical_count"),
                    func.count(GatewayAuditLog.id).filter(
                        GatewayAuditLog.risk_level == "HIGH"
                    ).label("high_count"),
                    func.coalesce(func.avg(GatewayAuditLog.total_processing_ms), 0).label("avg_processing_ms"),
                )
            )
            row = result.one()
            total = int(row.total_requests or 0)
            blocked = int(row.blocked_count or 0)
            return {
                "total_requests": total,
                "total_pii_items_masked": int(row.total_pii_masked or 0),
                "blocked_count": blocked,
                "block_rate_pct": round(blocked / max(total, 1) * 100, 2),
                "critical_risk_count": int(row.critical_count or 0),
                "high_risk_count": int(row.high_count or 0),
                "avg_processing_ms": round(float(row.avg_processing_ms or 0), 2),
            }
        except Exception as e:
            raise AuditRepositoryException(str(e), "get_risk_dashboard")

    async def get_pii_type_frequency(self, days_back: int = 7) -> Dict[str, int]:
        """
        Aggregate frequency of each PII type detected over the past N days.
        Used for compliance reporting — 'what types of data are leaking most?'
        """
        try:
            cutoff = datetime.utcnow() - timedelta(days=days_back)
            result = await self.session.execute(
                select(GatewayAuditLog.pii_types_detected)
                .where(GatewayAuditLog.timestamp >= cutoff)
                .where(GatewayAuditLog.total_masked > 0)
            )
            rows = result.scalars().all()
            frequency: Dict[str, int] = {}
            for pii_list in rows:
                if isinstance(pii_list, list):
                    for pii_type in pii_list:
                        frequency[pii_type] = frequency.get(pii_type, 0) + 1
            return dict(sorted(frequency.items(), key=lambda x: x[1], reverse=True))
        except Exception as e:
            raise AuditRepositoryException(str(e), "get_pii_type_frequency")
