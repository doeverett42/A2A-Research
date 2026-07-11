#Host AI agent
#contains host-side routing and delegation behavior

from __future__ import annotations

import json
import re

from google.protobuf.json_format import MessageToDict

from common.logging import logger
from common.ollama_client import OllamaClient
from common.prompts import HOST_ROUTER_SYSTEM_PROMPT, build_host_router_prompt
from host.discovery import RemoteAgentInfo


class HostAgent:
    def __init__(self, client: OllamaClient, model: str) -> None:
        self.client = client
        self.model = model

    async def select_agent(self, user_message: str, agents: list[RemoteAgentInfo]) -> int:
        logger.info("Asking host LLM to select a remote agent from discovered Agent Cards...")

        response = await self.client.chat(
            model = self.model,
            system = HOST_ROUTER_SYSTEM_PROMPT,
            prompt = build_host_router_prompt(user_message, _agent_cards_text(agents)),
            temperature = 0.0
        )
        selected_index = _selected_index(response, len(agents))

        logger.info("Host LLM selected %s with response: %s", agents[selected_index].name, response.strip())

        return selected_index

    async def prepare_delegation(self, user_message: str, agent_name: str) -> str:
        delegated_request = user_message.strip()

        logger.info("Forwarding user request to %s without host rewrite.", agent_name)
        logger.info("Delegated request text: %s", delegated_request)

        return delegated_request


def _agent_cards_text(agents: list[RemoteAgentInfo]) -> str:
    card_text = []
    for index, agent in enumerate(agents):
        card = MessageToDict(agent.card)
        card_text.append(
            json.dumps(
                {
                    "index": index,
                    "service_url": agent.url,
                    "agent_card": card
                },
                indent = 2
            )
        )
    return "\n\n".join(card_text)


def _selected_index(response: str, agent_count: int) -> int:
    match = re.search(r"\d+", response)
    if match is None:
        raise ValueError(f"Host LLM did not return an agent index: {response!r}")

    selected_index = int(match.group(0))
    if selected_index < 0 or selected_index >= agent_count:
        raise ValueError(f"Host LLM selected invalid agent index {selected_index}.")

    return selected_index
