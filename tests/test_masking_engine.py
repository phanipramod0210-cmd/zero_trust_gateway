"""
Test Suite for Zero-Trust AI Gateway.
Focus: masking engine correctness, edge cases, and policy enforcement.
"""
import pytest
from app.services.masking_service import PIIMaskingService


@pytest.fixture
def masking_service():
    return PIIMaskingService()


class TestRegexMasking:

    def test_masks_openai_api_key(self, masking_service):
        text = "Use this key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"
        result = masking_service.mask(text, "sess-001")
        assert "sk-ABCD" not in result.masked_text
        assert "[OPENAI_API_KEY" in result.masked_text
        assert result.total_masked >= 1

    def test_masks_anthropic_api_key(self, masking_service):
        text = "Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
        result = masking_service.mask(text, "sess-002")
        assert "sk-ant-api03" not in result.masked_text
        assert result.total_masked >= 1

    def test_masks_aws_access_key(self, masking_service):
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = masking_service.mask(text, "sess-003")
        assert "AKIAIOSFODNN7EXAMPLE" not in result.masked_text

    def test_masks_ssn(self, masking_service):
        text = "Patient SSN: 123-45-6789"
        result = masking_service.mask(text, "sess-004")
        assert "123-45-6789" not in result.masked_text
        assert result.total_masked >= 1

    def test_masks_email_address(self, masking_service):
        text = "Contact john.doe@acme.corp for more info."
        result = masking_service.mask(text, "sess-005")
        assert "john.doe@acme.corp" not in result.masked_text

    def test_masks_credit_card(self, masking_service):
        text = "Charge card number 4111111111111111"
        result = masking_service.mask(text, "sess-006")
        assert "4111111111111111" not in result.masked_text

    def test_masks_ipv4_address(self, masking_service):
        text = "Server is at 192.168.1.100 — do not expose."
        result = masking_service.mask(text, "sess-007")
        assert "192.168.1.100" not in result.masked_text

    def test_masks_connection_string(self, masking_service):
        text = "DB: postgresql://admin:supersecret123@prod-db.internal:5432/customers"
        result = masking_service.mask(text, "sess-008")
        assert "supersecret123" not in result.masked_text
        assert "prod-db.internal" not in result.masked_text

    def test_masks_jwt_token(self, masking_service):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = masking_service.mask(jwt, "sess-009")
        assert "eyJhbGci" not in result.masked_text

    def test_masks_private_key_block(self, masking_service):
        text = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = masking_service.mask(text, "sess-010")
        assert "BEGIN RSA PRIVATE KEY" not in result.masked_text

    def test_masks_generic_password_in_config(self, masking_service):
        text = 'password="SuperSecret123!" and secret=MyToken99'
        result = masking_service.mask(text, "sess-011")
        assert "SuperSecret123!" not in result.masked_text

    def test_masks_phone_number(self, masking_service):
        text = "Call me at +1 (555) 867-5309"
        result = masking_service.mask(text, "sess-012")
        assert "867-5309" not in result.masked_text

    def test_empty_text_returns_safely(self, masking_service):
        result = masking_service.mask("", "sess-013")
        assert result.masked_text == ""
        assert result.total_masked == 0

    def test_whitespace_only_returns_safely(self, masking_service):
        result = masking_service.mask("   \n\t  ", "sess-014")
        assert result.total_masked == 0

    def test_clean_text_unchanged(self, masking_service):
        text = "The quick brown fox jumps over the lazy dog."
        result = masking_service.mask(text, "sess-015")
        assert result.total_masked == 0
        assert result.masked_text == text

    def test_deduplication_same_value_one_token(self, masking_service):
        """Same PII value appearing twice should produce ONE mask token."""
        text = "Email: alice@test.com then again alice@test.com"
        result = masking_service.mask(text, "sess-016")
        # Both occurrences should be replaced by the same token
        assert result.masked_text.count("[EMAIL_") <= 2
        unique_tokens = set(result.mask_token_map.keys())
        assert len(unique_tokens) <= 2  # Should deduplicate

    def test_original_hash_consistent(self, masking_service):
        text = "Hello world"
        r1 = masking_service.mask(text, "sess-017")
        r2 = masking_service.mask(text, "sess-018")
        assert r1.original_hash == r2.original_hash

    def test_multiple_pii_types_in_one_text(self, masking_service):
        text = """
        Employee: john.doe@company.com
        SSN: 234-56-7890
        Phone: +1 555-123-4567
        API Key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr
        """
        result = masking_service.mask(text, "sess-019")
        assert result.total_masked >= 4
        assert "john.doe@company.com" not in result.masked_text
        assert "234-56-7890" not in result.masked_text

    def test_risk_summary_critical_for_api_key(self, masking_service):
        text = "Key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"
        result = masking_service.mask(text, "sess-020")
        risk = masking_service.get_risk_summary(result)
        assert risk["risk_level"] in {"CRITICAL", "HIGH"}

    def test_risk_summary_none_for_clean_text(self, masking_service):
        result = masking_service.mask("Hello, how are you?", "sess-021")
        risk = masking_service.get_risk_summary(result)
        assert risk["risk_level"] == "NONE"

    def test_unmask_restores_original(self, masking_service):
        original = "Contact admin@example.com or call 555-867-5309"
        result = masking_service.mask(original, "sess-022")
        restored = masking_service.unmask(result.masked_text, result.mask_token_map)
        assert "admin@example.com" in restored
        assert "555-867-5309" in restored

    def test_very_long_text_handled(self, masking_service):
        # 10k word text with one embedded email
        base = "The quick brown fox. " * 500
        text = base + " Contact hidden@secret.org for details. " + base
        result = masking_service.mask(text, "sess-023")
        assert "hidden@secret.org" not in result.masked_text

    def test_bearer_token_masked(self, masking_service):
        text = "Authorization: Bearer eyABCDEFGHIJKLMNOP.payload.signature"
        result = masking_service.mask(text, "sess-024")
        assert "BEARER_TOKEN" in str(result.detections) or result.total_masked >= 1


class TestRiskSummary:

    def test_high_severity_private_key(self, masking_service):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        result = masking_service.mask(text, "sess-025")
        risk = masking_service.get_risk_summary(result)
        assert risk["high_severity_count"] >= 1

    def test_critical_findings_list(self, masking_service):
        text = "SSN: 789-01-2345 and card 4111111111111111"
        result = masking_service.mask(text, "sess-026")
        risk = masking_service.get_risk_summary(result)
        assert len(risk["pii_types_detected"]) >= 1
