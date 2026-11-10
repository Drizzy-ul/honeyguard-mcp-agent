"""Tests for FastMCP server tools (no real network calls)."""
import pytest

from mcp_server.server import lookup_ip_reputation, generate_firewall_rule
from schemas.models import IPReputationResult, FirewallRule


class TestLookupIPReputation:
    def test_valid_ip_returns_result(self):
        result = lookup_ip_reputation("203.0.113.42")
        assert isinstance(result, IPReputationResult)
        assert result.ip == "203.0.113.42"
        assert 0 <= result.abuse_confidence_score <= 100

    def test_score_range(self):
        result = lookup_ip_reputation("1.2.3.4")
        assert 0 <= result.abuse_confidence_score <= 100

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="Invalid IPv4"):
            lookup_ip_reputation("not-an-ip")

    def test_non_malicious_ip(self):
        # 8.8.8.8: (8+8) % 101 = 16 → not malicious
        result = lookup_ip_reputation("8.8.8.8")
        assert result.is_malicious is False
        assert result.tags == []


class TestGenerateFirewallRule:
    def test_valid_rule_generated(self):
        rule = generate_firewall_rule("203.0.113.42", "ssh-brute-force")
        assert isinstance(rule, FirewallRule)
        assert "203.0.113.42" in rule.command
        assert "DROP" in rule.command
        assert rule.requires_review is True

    def test_reason_sanitised(self):
        rule = generate_firewall_rule("1.2.3.4", "scanner; rm -rf /")
        assert "rm" not in rule.reason
        assert ";" not in rule.reason

    def test_invalid_ip_raises(self):
        with pytest.raises(ValueError, match="Invalid IPv4"):
            generate_firewall_rule("bad-ip", "test")
