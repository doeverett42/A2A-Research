# Host orchestrator
# Coordinates host model preparation and remote A2A delegation

from __future__ import annotations

from common.logging import logger
from host.agent import HostAgent
from host.client import RemoteAgentClient
from host.router import SingleRemoteRouter


class HostOrchestrator:
    def __init__(self, agent: HostAgent | None = None, router: SingleRemoteRouter | None = None, remote_client: RemoteAgentClient | None = None) -> None:
        self.agent = agent or HostAgent()
        self.router = router or SingleRemoteRouter()
        self.remote_client = remote_client

    async def run(self, user_message: str) -> str:
        decision = self.router.route(user_message)
        delegated_request = await self.agent.prepare_delegation(user_message)

        logger.info("Delegating request to remote agent: %s", decision.reason)

        client = self.remote_client or RemoteAgentClient(decision.remote_url)
        response = await client.send_text(delegated_request)

        if self.remote_client is None:
            await client.close()

        return response

    async def close(self) -> None:
        if self.remote_client is not None:
            await self.remote_client.close()
