# Host orchestrator
# Coordinates host routing and remote A2A delegation

from __future__ import annotations

from common.logging import logger
from host.agent import HostAgent
from host.client import RemoteAgentClient
from host.discovery import AgentDiscovery
from host.router import MultiRemoteRouter


class HostOrchestrator:
    def __init__(self, agent: HostAgent, discovery: AgentDiscovery, router: MultiRemoteRouter, timeout_seconds: int) -> None:
        self.agent = agent
        self.discovery = discovery
        self.router = router
        self.timeout_seconds = timeout_seconds
        self.remote_clients = {}

    async def run(self, user_message: str) -> str:
        agents = await self.discovery.discover()
        decision = await self.router.route(user_message, agents, self.agent)
        delegated_request = await self.agent.prepare_delegation(
            user_message,
            agent_name = decision.agent_name
        )

        logger.info(
            "Delegating request to %s at %s: %s",
            decision.agent_name,
            decision.remote_url,
            decision.reason
        )

        client = self._client_for(decision.remote_url)
        response = await client.send_text(delegated_request)

        return response

    async def close(self) -> None:
        for client in self.remote_clients.values():
            await client.close()
        self.remote_clients = {}

    def _client_for(self, remote_url: str) -> RemoteAgentClient:
        if remote_url not in self.remote_clients:
            self.remote_clients[remote_url] = RemoteAgentClient(remote_url, self.timeout_seconds)
        return self.remote_clients[remote_url]
