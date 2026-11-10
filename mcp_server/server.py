"""FastMCP server exposing threat-intel tools for the HoneyGuard agent."""
from __future__ import annotations

import re

import fastmcp
from pydantic import BaseModel, Field

from rag.retriever import TechniqueRetriever
from schemas.models import IPReputationResult, FirewallRule

mcp = fastmcp.FastMCP("honeyguard-threat-intel")

# Module-level retriever (lazy-initialised on first query)
_retriever: TechniqueRetriever | None = None


def _get_retriever() -> TechniqueRetriever:
    global _retriever
    if _retriever is None:
        _retriever = TechniqueRetriever()
    return _retriever


@mcp.tool()
def lookup_ip_reputation(ip: str) -> IPReputationResult:
    """Look up an IP address in threat-intel feeds and return a reputation score.

    Args:
        ip: IPv4 address to look up (e.g. '192.168.1.100').

    Returns:
        IPReputationResult with score, tags, and abuse confidence.
    """
    # Validate IPv4 format
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")

    # Deterministic stub — in production, call AbuseIPDB / VirusTotal APIs
    octets = list(map(int, ip.split(".")))
    score = min(100, (octets[0] + octets[3]) % 101)
    is_malicious = score >= 70

    return IPReputationResult(
        ip=ip,
        abuse_confidence_score=score,
        is_malicious=is_malicious,
        tags=["ssh-brute-force", "scanner"] if is_malicious else [],
        country_code="CN" if is_malicious else "US",
    )


@mcp.tool()
def query_mitre_technique(query: str) -> dict:
    """Retrieve MITRE ATT&CK technique details via RAG similarity search.

    Args:
        query: Natural-language description of observed attack behaviour.

    Returns:
        Dict with top matching technique ID, name, tactic, and description.
    """
    retriever = _get_retriever()
    results = retriever.retrieve(query, top_k=1)
    if not results:
        return {"error": "No matching technique found"}
    return results[0]


@mcp.tool()
def generate_firewall_rule(ip: str, reason: str) -> FirewallRule:
    """Generate an iptables DROP rule to block a malicious IP.

    Args:
        ip: IPv4 address to block.
        reason: Human-readable reason for the block (logged as a comment).

    Returns:
        FirewallRule with the iptables command and metadata.
    """
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")

    # Sanitise reason to prevent shell injection in comments
    safe_reason = re.sub(r"[^a-zA-Z0-9 \-_\.]", "", reason)[:80]
    rule = f'iptables -I INPUT -s {ip} -j DROP -m comment --comment "{safe_reason}"'

    return FirewallRule(
        ip=ip,
        command=rule,
        reason=safe_reason,
        requires_review=True,
    )
