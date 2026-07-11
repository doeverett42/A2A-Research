#Host agent discovery
#fetches agent cards and reads remote URLs from them

from __future__ import annotations

import httpx

from a2a.client import A2ACardResolver
from a2a.types import AgentCard

from common.logging import logger


class RemoteAgentInfo:
    def __init__(self, card_url: str, card: AgentCard) -> None:
        self.card_url = card_url
        self.card = card
        self.url = _jsonrpc_url_from_card(card)

    @property
    def name(self) -> str:
        return self.card.name

    @property
    def summary(self) -> str:
        skill_summaries = []
        for skill in self.card.skills:
            skill_summaries.append(
                " ".join(
                    [
                        skill.id,
                        skill.name,
                        skill.description,
                        " ".join(skill.tags),
                        " ".join(skill.examples)
                    ]
                )
            )

        return " ".join(
            [
                self.card.name,
                self.card.description,
                " ".join(self.card.default_input_modes),
                " ".join(self.card.default_output_modes),
                " ".join(skill_summaries)
            ]
        )


class AgentDiscovery:
    def __init__(self, agent_card_urls: list[str], timeout_seconds: int) -> None:
        self.agent_card_urls = agent_card_urls
        self.timeout_seconds = timeout_seconds

    async def discover(self) -> list[RemoteAgentInfo]:
        agents = []
        httpx_client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout_seconds))

        try:
            for agent_card_url in self.agent_card_urls:
                try:
                    resolver = A2ACardResolver(httpx_client, agent_card_url)
                    card = await resolver.get_agent_card()
                    agent = RemoteAgentInfo(agent_card_url, card)
                    agents.append(agent)
                    logger.info("Discovered remote agent %s at %s from card %s", card.name, agent.url, agent_card_url)
                except Exception as e:
                    logger.warning("Could not discover remote agent card at %s: %s", agent_card_url, e)
        finally:
            await httpx_client.aclose()

        return agents


def _jsonrpc_url_from_card(card: AgentCard) -> str:
    for interface in card.supported_interfaces:
        if interface.protocol_binding == "JSONRPC":
            return interface.url

    raise ValueError(f"Agent Card for {card.name} does not include a supported interface URL.")
