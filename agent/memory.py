"""Conversation memory management for multi-turn threat sessions."""
from __future__ import annotations

from langchain.memory import ConversationBufferMemory


def create_session_memory(session_id: str) -> ConversationBufferMemory:
    """Create a fresh ConversationBufferMemory for a threat-triage session.

    Args:
        session_id: Unique identifier for the honeypot session.

    Returns:
        A ConversationBufferMemory instance with the session ID stored
        in the memory key so multiple sessions remain isolated.
    """
    return ConversationBufferMemory(
        memory_key=f"chat_history_{session_id}",
        return_messages=True,
        output_key="output",
    )
