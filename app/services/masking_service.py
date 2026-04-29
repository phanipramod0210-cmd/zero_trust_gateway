"""
POC-03: Zero-Trust AI Gateway — PII & Secrets Masking Middleware

Architecture:
  Client → FastAPI Gateway → PIIMaskingService (Regex + NER) → External LLM API
                                     ↓
                          MaskingAuditRepository (PostgreSQL)

Design decisions:
  - Two-phase detection: Fast Regex catches structured PII (SSNs, API keys, emails)
    then spaCy NER catches unstructured PII (person names, orgs, locations)
  - Masking uses reversible token map stored in Redis (TTL = session lifetime)
  - Proxy mode: strips secrets BEFORE forwarding to any external LLM
  - Full audit log: every masking operation is logged with hash of original (not raw)
"""
import re
import uuid
import hashlib
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field

from loguru import logger

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    NER_AVAILABLE = True
    logger.info("spaCy NER model loaded: en_core_web_sm")
except (ImportError, OSError):
    NER_AVAILABLE = False
    logger.warning("spaCy not available — using regex-only mode")


# ─── PII Detection Patterns ───────────────────────────────────────────────────

PII_PATTERNS: Dict[str, re.Pattern] = {
    # Credentials & Secrets
    "OPENAI_API_KEY":     re.compile(r'\bsk-[A-Za-z0-9]{20,60}\b'),
    "ANTHROPIC_API_KEY":  re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{20,80}\b'),
    "AWS_ACCESS_KEY":     re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "AWS_SECRET_KEY":     re.compile(r'\b[A-Za-z0-9+/]{40}\b'),
    "GITHUB_TOKEN":       re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,76}\b'),
    "JWT_TOKEN":          re.compile(r'\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),
    "PRIVATE_KEY_BLOCK":  re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    "BEARER_TOKEN":       re.compile(r'\bBearer\s+[A-Za-z0-9\-_\.]+', re.IGNORECASE),

    # Identity PII
    "SSN":                re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
    "EMAIL":              re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    "PHONE_US":           re.compile(r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "PHONE_INTL":         re.compile(r'\+(?:[0-9] ?){6,14}[0-9]\b'),
    "CREDIT_CARD":        re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b'),
    "IBAN":               re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b'),

    # Network & Infrastructure
    "IPV4":               re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "IPV6":               re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "CONNECTION_STRING":  re.compile(r'(?:postgresql|mysql|mongodb|redis):\/\/[^\s"\'<>]+', re.IGNORECASE),
    "GENERIC_PASSWORD":   re.compile(r'(?:password|passwd|pwd|secret|token|key)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]]{8,})["\']?', re.IGNORECASE),

    # Documents
    "PASSPORT":           re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'),
    "NHS_NUMBER":         re.compile(r'\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b'),
}

NER_ENTITY_TYPES = {"PERSON", "ORG", "GPE", "LOC", "MONEY"}


@dataclass
class MaskingResult:
    original_hash: str
    masked_text: str
    detections: List[Dict[str, Any]] = field(default_factory=list)
    total_masked: int = 0
    mask_token_map: Dict[str, str] = field(default_factory=dict)  # mask_token → original
    processing_ms: float = 0.0


class PIIMaskingService:
    """
    Two-phase PII and secrets masking engine.
    Phase 1: Regex patterns for structured PII
    Phase 2: spaCy NER for unstructured PII (names, orgs, locations)
    """

    def __init__(self, masking_repository=None):
        self.masking_repository = masking_repository
        logger.info(f"PIIMaskingService initialized | ner_available={NER_AVAILABLE}")

    def _generate_mask_token(self, pii_type: str, session_id: str, index: int) -> str:
        """
        Generate a consistent, reversible mask token.
        Format: [PII_TYPE_XXXXXXXX] where X is a session-scoped index.
        """
        return f"[{pii_type}_{session_id[:8].upper()}_{index:04d}]"

    def _apply_regex_masking(
        self, text: str, session_id: str, token_map: Dict[str, str], detection_log: List[Dict]
    ) -> Tuple[str, int]:
        """Apply all regex patterns. Returns (masked_text, count_masked)."""
        masked = text
        count = 0
        existing_token_count = len(token_map)

        for pii_type, pattern in PII_PATTERNS.items():
            matches = list(pattern.finditer(masked))
            for match in reversed(matches):  # Reverse to preserve positions
                original_value = match.group(0)

                # Check if this exact value already has a mask token (deduplication)
                existing_token = next(
                    (tok for tok, orig in token_map.items() if orig == original_value), None
                )
                if existing_token:
                    mask_token = existing_token
                else:
                    mask_token = self._generate_mask_token(pii_type, session_id, existing_token_count + count)
                    token_map[mask_token] = original_value

                masked = masked[:match.start()] + mask_token + masked[match.end():]
                detection_log.append({
                    "type": pii_type,
                    "method": "regex",
                    "position": match.start(),
                    "mask_token": mask_token,
                    "severity": "HIGH" if pii_type in {"CREDIT_CARD", "SSN", "PRIVATE_KEY_BLOCK", "OPENAI_API_KEY", "AWS_SECRET_KEY"} else "MEDIUM",
                })
                count += 1

        return masked, count

    def _apply_ner_masking(
        self, text: str, session_id: str, token_map: Dict[str, str], detection_log: List[Dict]
    ) -> Tuple[str, int]:
        """Apply spaCy NER masking for unstructured PII. Only runs if NER is available."""
        if not NER_AVAILABLE:
            return text, 0

        # Skip NER on very long texts to avoid latency (chunk if needed)
        if len(text) > 100_000:
            logger.warning("Text too long for NER — skipping NER phase")
            return text, 0

        doc = nlp(text)
        count = 0
        masked = text
        offset = 0

        for ent in doc.ents:
            if ent.label_ not in NER_ENTITY_TYPES:
                continue

            original_value = ent.text
            existing_token = next(
                (tok for tok, orig in token_map.items() if orig == original_value), None
            )
            if existing_token:
                mask_token = existing_token
            else:
                mask_token = self._generate_mask_token(f"NER_{ent.label_}", session_id, len(token_map))
                token_map[mask_token] = original_value

            start = ent.start_char + offset
            end = ent.end_char + offset
            masked = masked[:start] + mask_token + masked[end:]
            offset += len(mask_token) - (ent.end_char - ent.start_char)

            detection_log.append({
                "type": f"NER_{ent.label_}",
                "method": "spacy_ner",
                "position": ent.start_char,
                "mask_token": mask_token,
                "severity": "MEDIUM" if ent.label_ == "PERSON" else "LOW",
            })
            count += 1

        return masked, count

    def mask(self, text: str, session_id: Optional[str] = None) -> MaskingResult:
        """
        Main masking entry point. Applies regex then NER in sequence.
        Returns a MaskingResult with masked text and metadata.
        """
        if not text or not text.strip():
            return MaskingResult(
                original_hash=hashlib.sha256(b"").hexdigest(),
                masked_text=text or "",
            )

        start_time = time.time()
        session_id = session_id or str(uuid.uuid4())
        original_hash = hashlib.sha256(text.encode()).hexdigest()

        token_map: Dict[str, str] = {}
        detection_log: List[Dict] = []

        # Phase 1: Regex
        masked_text, regex_count = self._apply_regex_masking(text, session_id, token_map, detection_log)
        logger.debug(f"Regex phase: {regex_count} items masked | session={session_id[:8]}")

        # Phase 2: NER (on already-regex-masked text to avoid re-detecting)
        masked_text, ner_count = self._apply_ner_masking(masked_text, session_id, token_map, detection_log)
        logger.debug(f"NER phase: {ner_count} items masked | session={session_id[:8]}")

        total = regex_count + ner_count
        processing_ms = round((time.time() - start_time) * 1000, 4)

        if total > 0:
            types_found = list({d["type"] for d in detection_log})
            logger.warning(f"PII/Secrets detected and masked | count={total} types={types_found} session={session_id[:8]}")

        return MaskingResult(
            original_hash=original_hash,
            masked_text=masked_text,
            detections=detection_log,
            total_masked=total,
            mask_token_map=token_map,
            processing_ms=processing_ms,
        )

    def unmask(self, masked_text: str, token_map: Dict[str, str]) -> str:
        """
        Restore masked tokens to original values.
        Used for post-LLM response processing if needed.
        """
        result = masked_text
        for token, original in token_map.items():
            result = result.replace(token, original)
        return result

    def get_risk_summary(self, result: MaskingResult) -> Dict[str, Any]:
        """Produce a risk assessment from masking detections."""
        high_severity = [d for d in result.detections if d["severity"] == "HIGH"]
        critical_types = {"PRIVATE_KEY_BLOCK", "AWS_SECRET_KEY", "OPENAI_API_KEY", "CREDIT_CARD", "SSN"}
        critical_found = [d for d in result.detections if d["type"] in critical_types]

        return {
            "total_detections": result.total_masked,
            "high_severity_count": len(high_severity),
            "critical_findings": [d["type"] for d in critical_found],
            "risk_level": "CRITICAL" if critical_found else ("HIGH" if high_severity else ("MEDIUM" if result.total_masked > 0 else "NONE")),
            "pii_types_detected": list({d["type"] for d in result.detections}),
            "processing_ms": result.processing_ms,
        }
