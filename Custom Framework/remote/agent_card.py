#Agent Card construction for the remote agent

from __future__ import annotations

from typing import Any

from a2a.types import AgentCapabilities, AgentCard, AgentInterface

from remote.skills import build_skills


def build_agent_card(agent_spec: dict[str, Any], version: str, base_url: str) -> AgentCard:
    return AgentCard(
        name = agent_spec["name"],
        description = agent_spec["card_description"],
        version = version,
        capabilities = AgentCapabilities(
            streaming = False,
            push_notifications = False,
            extended_agent_card = False
        ),
        supported_interfaces = [
            AgentInterface(
                protocol_binding = "JSONRPC",
                url = base_url,
                protocol_version = "1.0"
            )
        ],
        default_input_modes = ["text/plain"],
        default_output_modes = ["text/plain"],
        skills = build_skills(agent_spec["skill"])
    )
