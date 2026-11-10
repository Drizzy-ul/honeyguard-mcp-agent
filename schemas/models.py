"""Pydantic v2 models for the HoneyGuard MCP agent."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator
import re


class IPReputationResult(BaseModel):
    """Result of an IP reputation lookup from threat-intel feeds.

    Attributes:
        ip: The queried IPv4 address.
        abuse_confidence_score: Score 0-100 (100 = highest abuse confidence).
        is_malicious: True if score >= 70.
        tags: List of abuse category tags (e.g. 'ssh-brute-force').
        country_code: ISO-3166 two-letter country code.
    """

    ip: str = Field(..., description="IPv4 address queried")
    abuse_confidence_score: int = Field(..., ge=0, le=100)
    is_malicious: bool
    tags: list[str] = Field(default_factory=list)
    country_code: str = Field(..., min_length=2, max_length=2)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 format."""
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
            raise ValueError(f"Invalid IPv4: {v!r}")
        return v


class FirewallRule(BaseModel):
    """Generated iptables firewall rule for blocking a malicious IP.

    Attributes:
        ip: IPv4 address to block.
        command: Full iptables DROP command string.
        reason: Human-readable block reason (sanitised).
        requires_review: Always True — HITL enforcement before execution.
    """

    ip: str
    command: str
    reason: str
    requires_review: bool = Field(default=True)


class ThreatAssessment(BaseModel):
    """Structured output of a full agent threat-triage run.

    Attributes:
        raw_alert: Original honeypot alert text.
        agent_response: Final LLM-generated assessment (sanitised).
        intermediate_steps: Tool call chain from AgentExecutor.
        severity: Computed severity level (LOW/MEDIUM/HIGH/CRITICAL).
    """

    raw_alert: str
    agent_response: str
    intermediate_steps: list = Field(default_factory=list)
    severity: str = Field(default="UNKNOWN")
