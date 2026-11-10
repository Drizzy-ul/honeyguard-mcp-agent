"""Tests for Pydantic v2 schema models."""
import pytest
from pydantic import ValidationError

from schemas.models import IPReputationResult, FirewallRule, ThreatAssessment


class TestIPReputationResult:
    def test_valid_malicious_ip(self):
        result = IPReputationResult(
            ip="1.2.3.4",
            abuse_confidence_score=95,
            is_malicious=True,
            tags=["ssh-brute-force"],
            country_code="CN",
        )
        assert result.is_malicious is True
        assert result.abuse_confidence_score == 95

    def test_score_out_of_range(self):
        with pytest.raises(ValidationError):
            IPReputationResult(
                ip="1.2.3.4",
                abuse_confidence_score=150,
                is_malicious=True,
                tags=[],
                country_code="US",
            )

    def test_invalid_ip_format(self):
        with pytest.raises(ValidationError):
            IPReputationResult(
                ip="not-an-ip",
                abuse_confidence_score=50,
                is_malicious=False,
                tags=[],
                country_code="US",
            )

    def test_country_code_too_long(self):
        with pytest.raises(ValidationError):
            IPReputationResult(
                ip="1.2.3.4",
                abuse_confidence_score=50,
                is_malicious=False,
                tags=[],
                country_code="USA",
            )


class TestFirewallRule:
    def test_requires_review_default(self):
        rule = FirewallRule(
            ip="5.6.7.8",
            command="iptables -I INPUT -s 5.6.7.8 -j DROP",
            reason="ssh-brute-force",
        )
        assert rule.requires_review is True

    def test_explicit_fields(self):
        rule = FirewallRule(
            ip="9.10.11.12",
            command="iptables -I INPUT -s 9.10.11.12 -j DROP",
            reason="scanner",
            requires_review=True,
        )
        assert rule.ip == "9.10.11.12"


class TestThreatAssessment:
    def test_default_severity(self):
        ta = ThreatAssessment(
            raw_alert="SSH login attempt from 1.2.3.4",
            agent_response="High-severity brute force attack detected.",
        )
        assert ta.severity == "UNKNOWN"
        assert ta.intermediate_steps == []
