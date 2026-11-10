"""LangChain tool-calling agent for honeypot threat triage."""
from __future__ import annotations

import os
from typing import Any

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from agent.memory import create_session_memory
from agent.prompts import THREAT_TRIAGE_SYSTEM_PROMPT
from guardrails.owasp import validate_input, sanitize_output
from schemas.models import ThreatAssessment


def _build_tools(mcp_client: Any) -> list[StructuredTool]:
    """Build LangChain StructuredTools wrapping MCP server functions.

    Args:
        mcp_client: An object with methods: lookup_ip_reputation,
                    query_mitre_technique, generate_firewall_rule.

    Returns:
        List of StructuredTool instances ready for the agent executor.
    """
    return [
        StructuredTool.from_function(
            func=mcp_client.lookup_ip_reputation,
            name="lookup_ip_reputation",
            description="Check an IP address against threat-intel feeds. Input: ip (str).",
        ),
        StructuredTool.from_function(
            func=mcp_client.query_mitre_technique,
            name="query_mitre_technique",
            description=(
                "Retrieve MITRE ATT&CK technique details via RAG similarity search. "
                "Input: query (str) describing the observed attack behaviour."
            ),
        ),
        StructuredTool.from_function(
            func=mcp_client.generate_firewall_rule,
            name="generate_firewall_rule",
            description="Generate an iptables firewall rule to block an IP. Input: ip (str), reason (str).",
        ),
    ]


def build_agent_executor(
    mcp_client: Any,
    session_id: str = "default",
    model: str = "gpt-4o-mini",
    temperature: float = 0.0,
) -> AgentExecutor:
    """Construct and return a LangChain AgentExecutor for threat triage.

    Args:
        mcp_client: Client exposing MCP tool functions.
        session_id: Unique session identifier for memory isolation.
        model: OpenAI model name.
        temperature: Sampling temperature (0 = deterministic).

    Returns:
        A configured AgentExecutor with memory and tool-calling enabled.
    """
    llm = ChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=os.getenv("OPENAI_API_KEY", ""),
    )
    tools = _build_tools(mcp_client)
    memory = create_session_memory(session_id)

    prompt = ChatPromptTemplate.from_messages([
        ("system", THREAT_TRIAGE_SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name=f"chat_history_{session_id}", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=True,
        return_intermediate_steps=True,
        max_iterations=6,
    )


def triage_alert(executor: AgentExecutor, alert_text: str) -> ThreatAssessment:
    """Run the agent on a honeypot alert and return a ThreatAssessment.

    Args:
        executor: Configured AgentExecutor.
        alert_text: Raw alert text from the honeypot sensor.

    Returns:
        Structured ThreatAssessment with enriched threat data.

    Raises:
        ValueError: If the input fails OWASP guardrail validation.
    """
    validated = validate_input(alert_text)
    raw_output = executor.invoke({"input": validated})
    safe_output = sanitize_output(raw_output.get("output", ""))
    return ThreatAssessment(
        raw_alert=alert_text,
        agent_response=safe_output,
        intermediate_steps=raw_output.get("intermediate_steps", []),
    )
