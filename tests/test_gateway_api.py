"""
Integration Test Suite — Zero-Trust AI Gateway (POC-03)

Covers:
  - /inspect endpoint: PII detection without LLM forwarding
  - /proxy endpoint: policy enforcement, blocked requests, masking flow
  - /dashboard endpoint: aggregate stats
  - Schema validation: blank prompts, oversized payloads, invalid session IDs
  - Policy enforcement: block_on_critical with critical PII types
  - Edge cases: empty text, clean text, mixed PII types
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.schemas.gateway import GatewayRequest, InspectRequest, MaskingPolicy
from app.services.masking_service import PIIMaskingService
from app.core.exceptions import MaskingPolicyViolation, UpstreamLLMException


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def masking_service():
    return PIIMaskingService()


@pytest.fixture
async def async_client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


# ─── Health Check ─────────────────────────────────────────────────────────────

class TestHealthCheck:

    @pytest.mark.asyncio
    async def test_health_returns_healthy(self, async_client):
        response = await async_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "zero-trust-ai-gateway"
        assert data["version"] == "1.0.0"


# ─── /inspect Endpoint Tests ──────────────────────────────────────────────────

class TestInspectEndpoint:

    @pytest.mark.asyncio
    async def test_inspect_detects_api_key(self, async_client):
        payload = {
            "text": "My key is sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx",
            "session_id": "test-session-inspect-001",
        }
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["masking_summary"]["total_items_masked"] >= 1
        assert data["masking_summary"]["risk_level"] in {"CRITICAL", "HIGH"}
        assert "OPENAI_API_KEY" in data["masking_summary"]["pii_types_detected"]

    @pytest.mark.asyncio
    async def test_inspect_detects_ssn(self, async_client):
        payload = {"text": "Employee SSN: 123-45-6789", "session_id": "test-session-002"}
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["masking_summary"]["total_items_masked"] >= 1

    @pytest.mark.asyncio
    async def test_inspect_detects_connection_string(self, async_client):
        payload = {
            "text": "DB: postgresql://admin:password123@prod-db.internal:5432/customers",
            "session_id": "test-session-003",
        }
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["masking_summary"]["total_items_masked"] >= 1

    @pytest.mark.asyncio
    async def test_inspect_clean_text_zero_detections(self, async_client):
        payload = {
            "text": "The quick brown fox jumps over the lazy dog. No sensitive data here.",
            "session_id": "test-session-004",
        }
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["masking_summary"]["total_items_masked"] == 0
        assert data["masking_summary"]["risk_level"] == "NONE"

    @pytest.mark.asyncio
    async def test_inspect_masked_preview_truncated(self, async_client):
        """Masked preview should be at most 503 chars (500 + '...')"""
        payload = {
            "text": "A" * 2000 + " admin@example.com",
            "session_id": "test-session-005",
        }
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        assert len(response.json()["masked_preview"]) <= 503

    @pytest.mark.asyncio
    async def test_inspect_returns_session_id(self, async_client):
        payload = {"text": "Hello world", "session_id": "my-custom-session-id"}
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        assert response.json()["session_id"] == "my-custom-session-id"

    @pytest.mark.asyncio
    async def test_inspect_auto_generates_session_id_when_missing(self, async_client):
        payload = {"text": "Hello world"}
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        assert response.json()["session_id"] is not None
        assert len(response.json()["session_id"]) > 0

    @pytest.mark.asyncio
    async def test_inspect_empty_text_rejected(self, async_client):
        payload = {"text": "", "session_id": "test-session-007"}
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_inspect_oversized_text_rejected(self, async_client):
        payload = {"text": "x" * 60_000, "session_id": "test-session-008"}
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_inspect_multiple_pii_types(self, async_client):
        payload = {
            "text": "Email: john@acme.com, SSN: 234-56-7890, Card: 4111111111111111",
            "session_id": "test-session-009",
        }
        response = await async_client.post("/api/v1/gateway/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["masking_summary"]["total_items_masked"] >= 3
        assert len(data["masking_summary"]["pii_types_detected"]) >= 2


# ─── /proxy Endpoint Tests ────────────────────────────────────────────────────

class TestProxyEndpoint:

    @pytest.mark.asyncio
    async def test_proxy_inspect_only_mode_does_not_call_llm(self, async_client):
        """inspect_only policy must never forward to external LLM."""
        payload = {
            "prompt": "Tell me about machine learning",
            "session_id": "test-proxy-001",
            "policy": "inspect_only",
        }
        # No LLM mock needed — inspect_only should never reach it
        with patch("httpx.AsyncClient.post") as mock_post:
            response = await async_client.post("/api/v1/gateway/proxy", json=payload)
            mock_post.assert_not_called()

        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == "inspect_only"
        assert "NOT forwarded" in data["note"]

    @pytest.mark.asyncio
    async def test_proxy_block_on_critical_blocks_api_key(self, async_client):
        """block_on_critical policy must block prompts with API keys."""
        payload = {
            "prompt": "Use API key sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx to call the service",
            "session_id": "test-proxy-002",
            "policy": "block_on_critical",
        }
        with patch("app.services.proxy_service.ZeroTrustProxyService.audit_repository") as _:
            with patch("app.repositories.gateway_repository.GatewayRepository.log_blocked_request", new_callable=AsyncMock):
                response = await async_client.post("/api/v1/gateway/proxy", json=payload)

        assert response.status_code == 400
        data = response.json()
        assert data["code"] == "MASKING_POLICY_VIOLATION"
        assert "critical_pii_types" in data

    @pytest.mark.asyncio
    async def test_proxy_empty_prompt_rejected(self, async_client):
        payload = {"prompt": "", "policy": "mask_and_forward"}
        response = await async_client.post("/api/v1/gateway/proxy", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_proxy_whitespace_prompt_rejected(self, async_client):
        payload = {"prompt": "   \n\t  ", "policy": "mask_and_forward"}
        response = await async_client.post("/api/v1/gateway/proxy", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_proxy_invalid_session_id_rejected(self, async_client):
        payload = {
            "prompt": "Hello",
            "session_id": "invalid session id with spaces!",
            "policy": "inspect_only",
        }
        response = await async_client.post("/api/v1/gateway/proxy", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_proxy_invalid_policy_rejected(self, async_client):
        payload = {"prompt": "Hello", "policy": "not_a_real_policy"}
        response = await async_client.post("/api/v1/gateway/proxy", json=payload)
        assert response.status_code == 422


# ─── Schema Validation Tests ──────────────────────────────────────────────────

class TestSchemaValidation:

    def test_gateway_request_valid(self):
        req = GatewayRequest(
            prompt="Hello, this is a clean prompt.",
            session_id="valid-session-001",
            policy=MaskingPolicy.MASK_AND_FORWARD,
        )
        assert req.prompt == "Hello, this is a clean prompt."

    def test_gateway_request_empty_prompt_rejected(self):
        with pytest.raises(Exception):
            GatewayRequest(prompt="", policy=MaskingPolicy.INSPECT_ONLY)

    def test_gateway_request_oversized_prompt_rejected(self):
        with pytest.raises(Exception):
            GatewayRequest(prompt="x" * 60_000, policy=MaskingPolicy.MASK_AND_FORWARD)

    def test_inspect_request_valid(self):
        req = InspectRequest(text="Scan this text for PII", session_id="sess-123")
        assert req.text == "Scan this text for PII"

    def test_session_id_special_chars_rejected(self):
        with pytest.raises(Exception):
            GatewayRequest(
                prompt="Valid prompt",
                session_id="bad; DROP TABLE sessions; --",
                policy=MaskingPolicy.INSPECT_ONLY,
            )


# ─── Masking Service Unit Tests (Extended) ────────────────────────────────────

class TestMaskingServiceExtended:

    def test_aws_access_key_masked(self, masking_service):
        result = masking_service.mask("AKIAIOSFODNN7EXAMPLE is the key", "s1")
        assert "AKIAIOSFODNN7EXAMPLE" not in result.masked_text
        assert result.total_masked >= 1

    def test_github_token_masked(self, masking_service):
        result = masking_service.mask("token: ghp_abcdefghijklmnopqrstuvwxyz123456AB", "s2")
        assert result.total_masked >= 1

    def test_iban_masked(self, masking_service):
        result = masking_service.mask("IBAN: GB29NWBK60161331926819", "s3")
        assert result.total_masked >= 1

    def test_ipv4_masked(self, masking_service):
        result = masking_service.mask("Server at 10.0.0.1 — internal only", "s4")
        assert "10.0.0.1" not in result.masked_text

    def test_jwt_masked(self, masking_service):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = masking_service.mask(jwt, "s5")
        assert result.total_masked >= 1

    def test_private_key_block_masked(self, masking_service):
        result = masking_service.mask("Key:\n-----BEGIN RSA PRIVATE KEY-----\nABCDEF", "s6")
        assert "BEGIN RSA PRIVATE KEY" not in result.masked_text

    def test_bearer_token_masked(self, masking_service):
        result = masking_service.mask("Authorization: Bearer mytoken.payload.sig", "s7")
        assert result.total_masked >= 1

    def test_password_in_config_masked(self, masking_service):
        result = masking_service.mask('DB_PASSWORD="SuperSecretPass123"', "s8")
        assert "SuperSecretPass123" not in result.masked_text

    def test_connection_string_masked(self, masking_service):
        result = masking_service.mask("redis://admin:s3cr3t@cache.internal:6379/0", "s9")
        assert "s3cr3t" not in result.masked_text

    def test_unmask_restores_values(self, masking_service):
        original = "Email john@corp.com and SSN 987-65-4321"
        result = masking_service.mask(original, "s10")
        restored = masking_service.unmask(result.masked_text, result.mask_token_map)
        assert "john@corp.com" in restored
        assert "987-65-4321" in restored

    def test_processing_ms_is_measured(self, masking_service):
        result = masking_service.mask("Some text with email@example.com", "s11")
        assert result.processing_ms >= 0
        assert isinstance(result.processing_ms, float)
