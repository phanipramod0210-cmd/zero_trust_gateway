"""Database init, Audit Repository, and Redis session store for Zero-Trust Gateway."""
import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional, List

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, Integer, text, select, desc
from sqlalchemy.dialects.postgresql import UUID, JSONB
from loguru import logger

from app.core.config import settings
from app.core.exceptions import AuditRepositoryException


# ─── Database Setup ───────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("SELECT 1"))
        logger.info("Zero-Trust Gateway database initialized")
    except Exception as e:
        logger.critical(f"Database init failed: {e}")
        raise


# ─── ORM Models ───────────────────────────────────────────────────────────────

class GatewayAuditLog(Base):
    __tablename__ = "gateway_audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(36), nullable=False, unique=True, index=True)
    session_id = Column(String(100), nullable=False, index=True)
    original_prompt_hash = Column(String(64), nullable=False)
    total_masked = Column(Integer, default=0)
    pii_types_detected = Column(JSONB, default=list)
    risk_level = Column(String(20), nullable=False)
    policy_applied = Column(String(50), nullable=False)
    was_blocked = Column(Boolean, default=False)
    block_reason = Column(String(200))
    processing_ms = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


# ─── Audit Repository ─────────────────────────────────────────────────────────

class GatewayAuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def log_request(self, record: Dict[str, Any]) -> None:
        try:
            log_entry = GatewayAuditLog(
                request_id=record["request_id"],
                session_id=record["session_id"],
                original_prompt_hash=record["original_prompt_hash"],
                total_masked=record["total_masked"],
                pii_types_detected=record["pii_types"],
                risk_level=record["risk_level"],
                policy_applied=record["policy_applied"],
                was_blocked=record.get("was_blocked", False),
            )
            self.session.add(log_entry)
            await self.session.commit()
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Failed to log audit record: {e}")
            raise AuditRepositoryException(str(e), "log_request")

    async def log_blocked_request(
        self, request_id: str, session_id: str, reason: str, risk_summary: Dict
    ) -> None:
        try:
            log_entry = GatewayAuditLog(
                request_id=request_id,
                session_id=session_id,
                original_prompt_hash=risk_summary.get("hash", "unknown"),
                total_masked=risk_summary.get("total_detections", 0),
                pii_types_detected=risk_summary.get("pii_types_detected", []),
                risk_level=risk_summary.get("risk_level", "CRITICAL"),
                policy_applied="block_on_critical",
                was_blocked=True,
                block_reason=reason,
            )
            self.session.add(log_entry)
            await self.session.commit()
            logger.critical(f"[SECURITY] Request BLOCKED | id={request_id} reason={reason}")
        except Exception as e:
            await self.session.rollback()
            raise AuditRepositoryException(str(e), "log_blocked_request")

    async def get_session_history(
        self, session_id: str, limit: int = 50
    ) -> List[GatewayAuditLog]:
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

    async def get_risk_dashboard(self) -> Dict[str, Any]:
        """Aggregate risk metrics across all sessions for security dashboard."""
        try:
            from sqlalchemy import func
            result = await self.session.execute(
                select(
                    func.count(GatewayAuditLog.id).label("total_requests"),
                    func.sum(GatewayAuditLog.total_masked).label("total_pii_masked"),
                    func.count(GatewayAuditLog.id).filter(GatewayAuditLog.was_blocked).label("blocked_count"),
                    func.count(GatewayAuditLog.id).filter(GatewayAuditLog.risk_level == "CRITICAL").label("critical_count"),
                )
            )
            row = result.one()
            return {
                "total_requests": row.total_requests or 0,
                "total_pii_masked": int(row.total_pii_masked or 0),
                "blocked_count": row.blocked_count or 0,
                "critical_risk_count": row.critical_count or 0,
                "block_rate_pct": round((row.blocked_count or 0) / max(row.total_requests or 1, 1) * 100, 2),
            }
        except Exception as e:
            raise AuditRepositoryException(str(e), "get_risk_dashboard")


# ─── Redis Session Token Store ────────────────────────────────────────────────

class RedisSessionStore:
    """
    Stores mask_token → original_value maps in Redis with TTL.
    Enables response unmasking across async request/response cycles.
    """

    def __init__(self, redis_client):
        self.redis = redis_client
        self.ttl = settings.SESSION_TOKEN_TTL_SECONDS

    async def store_token_map(self, session_id: str, token_map: Dict[str, str]) -> None:
        if not token_map:
            return
        key = f"zt_gateway:token_map:{session_id}"
        try:
            await self.redis.setex(key, self.ttl, json.dumps(token_map))
            logger.debug(f"Token map stored | session={session_id[:8]} tokens={len(token_map)}")
        except Exception as e:
            logger.error(f"Failed to store token map in Redis: {e}")

    async def get_token_map(self, session_id: str) -> Optional[Dict[str, str]]:
        key = f"zt_gateway:token_map:{session_id}"
        try:
            raw = await self.redis.get(key)
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error(f"Failed to retrieve token map: {e}")
            return None

    async def delete_session(self, session_id: str) -> None:
        key = f"zt_gateway:token_map:{session_id}"
        await self.redis.delete(key)
        logger.info(f"Session token map deleted | session={session_id[:8]}")
