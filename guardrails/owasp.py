"""OWASP LLM Top-10 guardrails for HoneyGuard agent input/output.

Implements defenses against:
- LLM01: Prompt Injection — detect and reject malicious instruction injection
- LLM02: Insecure Output Handling — sanitise LLM outputs before use
- LLM06: Sensitive Information Disclosure — scrub PII / internal paths
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# LLM01: Prompt Injection detection patterns
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"disregard\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"<\s*/?system\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]"),
    re.compile(r"###\s*instruction", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# LLM06: PII / sensitive data patterns to scrub from outputs
# ---------------------------------------------------------------------------
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Email addresses
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b"), "[REDACTED_EMAIL]"),
    # Private RFC-1918 IPs (not threat IPs — those are intentional)
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[INTERNAL_IP]"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "[INTERNAL_IP]"),
    # API keys / tokens (generic pattern)
    (re.compile(r"\b(sk|pk|Bearer)\-[A-Za-z0-9\-_]{16,}\b"), "[REDACTED_KEY]"),
]


def validate_input(text: str) -> str:
    """Validate agent input against prompt-injection patterns (OWASP LLM01).

    Args:
        text: Raw input string from the user or external honeypot sensor.

    Returns:
        The original text if it passes all checks.

    Raises:
        ValueError: If a prompt-injection pattern is detected.
    """
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            raise ValueError(
                f"Prompt injection attempt detected. Blocked pattern: {pattern.pattern!r}"
            )
    return text


def sanitize_output(text: str) -> str:
    """Sanitise LLM output by scrubbing PII and sensitive data (OWASP LLM02/LLM06).

    Args:
        text: Raw LLM output string.

    Returns:
        Sanitised string with PII and sensitive tokens redacted.
    """
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
