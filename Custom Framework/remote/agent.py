#Remote AI agent
#Contains the intelligence of the remote agents

from __future__ import annotations

from typing import Protocol

from common.logging import logger
from common.ollama_client import OllamaClient
from common.prompts import SYSTEM_PROMPT, build_prompt

#ensure that every remote agent includes the method run()
class RemoteAgentProtocl(Protocol):
    async def run(self, query: str) -> str:
        pass


#simple ollama-backed chat agent
class OllamaRemoteAgent:

    def __init__(self, client: OllamaClient, model: str) -> None:
        self.client = client
        self.model = model

    async def run(self, query: str) -> str:
        logger.info("Sending request to Ollama model %s...", self.model)

        response = await self.client.chat(
            model = self.model,
            system = SYSTEM_PROMPT,
            prompt = build_prompt(query),
            temperature = 0.2
        )

        logger.info("Received response from Ollama.")

        return response
