"""
Zero-Trust Proxy Service.
Intercepts prompts, masks PII/secrets, forwards to LLM, optionally unmasks response.
"""
import time
import uuid
from typing import Optional, Dict, Any

import httpx
from loguru import logger

from app.services.masking_service import PIIMaskingService, MaskingResult
from app.core.config import settings
from app.core.exceptions import UpstreamLLMException, MaskingPolicyViolation


class ZeroTrustProxyService:
    def __init__(self, masking_service: PIIMaskingService, audit_repository):
        self.masking_service = masking_service
        self.audit_repository = audit_repository
        self.http_client = httpx.AsyncClient(timeout=settings.LLM_PROXY_TIMEOUT)
        logger.info("ZeroTrustProxyService initialized")

    async def proxy_request(
        self,
        prompt: str,
        session_id: str,
        policy: str = "mask_and_forward",
        unmask_response: bool = False,
        metadata: Optional[Dict] = None,
        client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        request_id = str(uuid.uuid4())
        start_time = time.time()
        logger.info(f"[GATEWAY] Request | id={request_id} session={session_id[:8]} policy={policy}")

        mask_start = time.time()
        masking_result: MaskingResult = self.masking_service.mask(prompt, session_id)
        risk_summary = self.masking_service.get_risk_summary(masking_result)
        masking_ms = round((time.time() - mask_start) * 1000, 2)
        logger.info(f"[GATEWAY] Masked {masking_result.total_masked} items | risk={risk_summary['risk_level']} | id={request_id}")

        if policy == "block_on_critical" and risk_summary["risk_level"] == "CRITICAL":
            await self.audit_repository.log_blocked_request(
                request_id=request_id,
                session_id=session_id,
                reason="CRITICAL_PII_DETECTED",
                risk_summary={**risk_summary, "hash": masking_result.original_hash},
                client_ip=client_ip,
            )
            raise MaskingPolicyViolation(
                f"Request blocked: critical PII/secrets detected ({risk_summary['critical_findings']}). Remove sensitive data before submitting to an external LLM.",
                critical_types=risk_summary["critical_findings"],
            )

        llm_start = time.time()
        llm_response_text = await self._forward_to_llm(masking_result.masked_text, request_id)
        llm_ms = round((time.time() - llm_start) * 1000, 2)

        final_response = llm_response_text
        if unmask_response and masking_result.mask_token_map:
            final_response = self.masking_service.unmask(llm_response_text, masking_result.mask_token_map)

        total_ms = round((time.time() - start_time) * 1000, 2)

        await self.audit_repository.log_request({
            "request_id": request_id,
            "session_id": session_id,
            "original_prompt_hash": masking_result.original_hash,
            "prompt_char_count": len(prompt),
            "total_masked": masking_result.total_masked,
            "pii_types": risk_summary["pii_types_detected"],
            "risk_level": risk_summary["risk_level"],
            "policy_applied": policy,
            "was_blocked": False,
            "unmask_requested": unmask_response,
            "masking_time_ms": masking_ms,
            "llm_time_ms": llm_ms,
            "processing_ms": total_ms,
            "client_ip": client_ip,
        })

        return {
            "request_id": request_id,
            "session_id": session_id,
            "masked_prompt": masking_result.masked_text,
            "llm_response": final_response,
            "masking_summary": {
                "total_items_masked": masking_result.total_masked,
                "detections": masking_result.detections,
                "risk_level": risk_summary["risk_level"],
                "pii_types_detected": risk_summary["pii_types_detected"],
                "masking_time_ms": masking_ms,
            },
            "llm_time_ms": llm_ms,
            "total_processing_ms": total_ms,
        }

    async def _forward_to_llm(self, masked_prompt: str, request_id: str) -> str:
        try:
            response = await self.http_client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={"model": settings.LLM_MODEL, "max_tokens": 1024,
                      "messages": [{"role": "user", "content": masked_prompt}]},
            )
            if response.status_code != 200:
                raise UpstreamLLMException(f"LLM returned HTTP {response.status_code}: {response.text[:200]}")
            return response.json()["content"][0]["text"]
        except httpx.TimeoutException:
            raise UpstreamLLMException(f"LLM API timeout after {settings.LLM_PROXY_TIMEOUT}s")
        except httpx.ConnectError as e:
            raise UpstreamLLMException(f"Cannot connect to LLM API: {str(e)}")
        except (KeyError, IndexError) as e:
            raise UpstreamLLMException(f"Unexpected LLM response structure: {str(e)}")
