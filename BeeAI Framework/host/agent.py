from beeai_framework.adapters.a2a.agents.agent import A2AAgent, A2AAgentParameters, HttpxAsyncClientParameters
from beeai_framework.memory.unconstrained_memory import UnconstrainedMemory


class SecureRemoteAgent:
    def __init__(self, server_url: str, api_key: str) -> None:
        #store the remote endpoint and authenticated token so cloned copies keep them
        self._server_url = server_url
        self._api_key = api_key
        self._agent = self._create_agent()

    def _create_agent(self) -> A2AAgent:
        #attach the API key  once at the HTTP client layer
        custom_headers = {"X-API-Key": self._api_key}

        return A2AAgent(
            url=self._server_url,
            memory=UnconstrainedMemory(),
            parameters=A2AAgentParameters(
                httpx_async_client=HttpxAsyncClientParameters(headers=custom_headers)
            )
        )

    @property
    def name(self) -> str:
        #forward the wrapped agent's public metadata
        return self._agent.name

    @property
    def agent_card(self):
        return self._agent.agent_card

    @property
    def memory(self):
        return self._agent.memory

    async def check_agent_exists(self) -> None:
        #give discovery to the wrapped A2A client
        await self._agent.check_agent_exists()

    async def run(self, *args, **kwargs):
        #give the actual A2A request to the wrapped client
        return await self._agent.run(*args, **kwargs)

    async def clone(self) -> "SecureRemoteAgent":
        #rebuild the wrapped client so the auth header survives cloning
        cloned = SecureRemoteAgent(self._server_url, self._api_key)
        cloned._agent = A2AAgent(
            url=self._server_url,
            agent_card_path=self._agent._agent_card_path,
            agent_card=self._agent.agent_card,
            memory=await self._agent.memory.clone(),
            grpc_client_credentials=self._agent._grpc_client_credentials,
            parameters=A2AAgentParameters(
                httpx_async_client=HttpxAsyncClientParameters(headers={"X-API-Key": self._api_key})
            )
        )
        return cloned


def create_host_client(server_url: str, api_key: str) -> SecureRemoteAgent:
    return SecureRemoteAgent(server_url, api_key)
