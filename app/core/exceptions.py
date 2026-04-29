"""Custom exceptions for Zero-Trust AI Gateway."""
from typing import List, Optional


class GatewayException(Exception):
    def __init__(self, detail: str, error_code: str = "GATEWAY_ERROR", status_code: int = 500):
        self.detail = detail
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(detail)


class ValidationException(GatewayException):
    def __init__(self, detail: str, fields: Optional[List[str]] = None):
        self.fields = fields or []
        super().__init__(detail, "VALIDATION_ERROR", 422)


class MaskingPolicyViolation(GatewayException):
    """Raised when policy is 'block_on_critical' and critical PII/secrets are found."""
    def __init__(self, detail: str, critical_types: Optional[List[str]] = None):
        self.critical_types = critical_types or []
        super().__init__(detail, "MASKING_POLICY_VIOLATION", 400)


class UpstreamLLMException(GatewayException):
    """Raised when the upstream LLM API fails or times out."""
    def __init__(self, detail: str):
        super().__init__(detail, "UPSTREAM_LLM_ERROR", 503)


class AuditRepositoryException(GatewayException):
    def __init__(self, detail: str, operation: str = "unknown"):
        super().__init__(f"Audit repo error during '{operation}': {detail}", "REPOSITORY_ERROR", 500)


class SessionNotFoundException(GatewayException):
    def __init__(self, session_id: str):
        super().__init__(f"Session '{session_id}' not found or expired", "SESSION_NOT_FOUND", 404)
