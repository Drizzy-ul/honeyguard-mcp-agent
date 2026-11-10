# HoneyGuard MCP Agent 🛡️🤖

> AI-powered threat-triage agent combining **MCP tool-calling**, **RAG over MITRE ATT&CK**, and **LLM reasoning** to automatically classify honeypot alerts, enrich IPs, and generate firewall rules.

![Python](https://img.shields.io/badge/python-3.11+-blue)
![FastMCP](https://img.shields.io/badge/FastMCP-2.0-green)
![LangChain](https://img.shields.io/badge/LangChain-0.3-orange)
![ChromaDB](https://img.shields.io/badge/ChromaDB-0.5-purple)
![CI](https://github.com/Drizzy-ul/honeyguard-mcp-agent/actions/workflows/ci.yml/badge.svg)

## Architecture

```
Honeypot Alert
     │
     ▼
┌─────────────────────────────────────────────┐
│          OWASP Guardrails (LLM01/02/06)     │  ← Input validation & output sanitisation
└───────────────────┬─────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│        LangChain Tool-Calling Agent          │  ← GPT-4o-mini orchestrator
│   (ConversationBufferMemory, max_iter=6)    │
└───┬────────────────┬───────────────┬────────┘
    │                │               │
    ▼                ▼               ▼
[MCP Tool]      [MCP Tool]      [MCP Tool]
lookup_ip_   query_mitre_    generate_firewall_
reputation    technique         rule
(AbuseIPDB)  (ChromaDB RAG)   (iptables DROP)
                    │
                    ▼
         ┌──────────────────┐
         │   ChromaDB       │  ← MITRE ATT&CK embedded with
         │  (EphemeralDB)   │    sentence-transformers (MiniLM)
         └──────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| MCP Server | FastMCP 2.0 |
| LLM Orchestration | LangChain 0.3 + `create_tool_calling_agent` |
| LLM Model | OpenAI GPT-4o-mini (configurable) |
| RAG Vector Store | ChromaDB (EphemeralClient) |
| Embeddings | sentence-transformers `all-MiniLM-L6-v2` (local, offline) |
| Memory | `ConversationBufferMemory` (session-scoped) |
| Data Validation | Pydantic v2 |
| Guardrails | OWASP LLM Top-10 (LLM01, LLM02, LLM06) |
| Testing | pytest 8.2 |
| CI/CD | GitHub Actions |

## MCP Tools

### `lookup_ip_reputation(ip: str) → IPReputationResult`
Checks an IPv4 address against threat-intel feeds (AbuseIPDB/VirusTotal in production).
Returns abuse confidence score (0–100), tags, and country code.

### `query_mitre_technique(query: str) → dict`
Performs RAG similarity search over 10 MITRE ATT&CK Enterprise techniques embedded
in ChromaDB using sentence-transformers. Returns top matching technique with ID, name,
tactic, and description.

### `generate_firewall_rule(ip: str, reason: str) → FirewallRule`
Generates a sanitised `iptables DROP` rule for the given IP. The `requires_review`
flag is always `True` — enforcing human-in-the-loop (HITL) before execution.

## RAG Pipeline

1. MITRE ATT&CK technique catalog loaded from `rag/mitre_data.py` (10 techniques, expandable)
2. Each technique embedded with `sentence-transformers/all-MiniLM-L6-v2` (runs locally, no API key)
3. Embeddings stored in ChromaDB `EphemeralClient`
4. Cosine similarity search retrieves top-k techniques for any natural-language attack description
5. Retrieved technique context injected into the agent's tool response

## OWASP LLM Guardrails

| OWASP ID | Risk | Implementation |
|----------|------|----------------|
| LLM01 | Prompt Injection | Regex pattern detection on all inputs; raises `ValueError` |
| LLM02 | Insecure Output Handling | Output sanitisation before returning to caller |
| LLM06 | Sensitive Info Disclosure | PII scrubbing (emails, internal IPs, API keys) |

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Drizzy-ul/honeyguard-mcp-agent.git
cd honeyguard-mcp-agent

# 2. Install
pip install -r requirements.txt

# 3. Set API key
export OPENAI_API_KEY="your-key-here"

# 4. Run tests (no API key required — all LLM calls mocked)
python -m pytest tests/ -v

# 5. Start MCP server
python -m mcp_server.server
```

## My Contribution

I designed and implemented this project end-to-end as a demonstration of secure LLM application architecture:

- **MCP tool schema design** — defined the three tool interfaces with Pydantic v2 validation and input sanitisation
- **RAG pipeline** — selected sentence-transformers for offline embedding and ChromaDB for the vector store; designed the MITRE ATT&CK catalog ingestion and cosine-similarity retrieval flow
- **LangChain agent** — wired `create_tool_calling_agent` with `ConversationBufferMemory` for multi-turn session support; tuned `max_iterations=6` and `temperature=0.0` for deterministic triage
- **OWASP guardrails** — implemented LLM01 prompt-injection detection (regex patterns), LLM02 output sanitisation, and LLM06 PII scrubbing based on OWASP LLM Top-10 (2025)
- **HITL enforcement** — `FirewallRule.requires_review = True` by design; no firewall command executes automatically

## License

MIT
