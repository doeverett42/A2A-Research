# Agent Card construction for the remote agent.

from __future__ import annotations

from a2a.types import AgentCapabilities, AgentCard, AgentInterface

from common.config import config
from remote.skills import build_skills


def build_agent_card(base_url: str | None = None) -> AgentCard:
    service_url = base_url or config.remote_base_url
    return AgentCard(
        name=config.REMOTE_AGENT_NAME,
        description="Remote reasoning agent backed by Ollama DeepSeek.",
        version=config.REMOTE_AGENT_VERSION,
        capabilities=AgentCapabilities(
            streaming=False,
            push_notifications=False,
            extended_agent_card=False,
        ),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=service_url,
                protocol_version="1.0",
            )
        ],
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=build_skills(),
    )
