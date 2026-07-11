# Agent Card construction for the remote agent.

from __future__ import annotations

from a2a.types import AgentCapabilities, AgentCard, AgentInterface

from remote.skills import build_skills


def build_agent_card(name: str, model: str, version: str, base_url: str) -> AgentCard:
    return AgentCard(
        name=name,
        description=f"Remote reasoning agent backed by Ollama model {model}.",
        version=version,
        capabilities=AgentCapabilities(
            streaming=False,
            push_notifications=False,
            extended_agent_card=False,
        ),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=base_url,
                protocol_version="1.0",
            )
        ],
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=build_skills(model),
    )
