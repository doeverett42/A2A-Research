#Host routing logic
#Routes user requests across discovered Agent Cards

from __future__ import annotations

from typing import TYPE_CHECKING

from host.discovery import RemoteAgentInfo

if TYPE_CHECKING:
    from host.agent import HostAgent


class RouteDecision:
    def __init__(self, remote_url: str, reason: str, agent_name: str) -> None:
        self.remote_url = remote_url
        self.reason = reason
        self.agent_name = agent_name


class MultiRemoteRouter:
    async def route(self, user_message: str, agents: list[RemoteAgentInfo], host_agent: "HostAgent") -> RouteDecision:
        if not user_message.strip():
            raise ValueError("Cannot route an empty user message.")
        if not agents:
            raise RuntimeError("No remote agents are currently discoverable.")

        selected_index = await host_agent.select_agent(user_message, agents)
        agent = agents[selected_index]
        
        return RouteDecision(
            remote_url = agent.url,
            reason = "host_llm_agent_card_match",
            agent_name = agent.name,
        )
