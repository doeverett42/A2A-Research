# Remote AI agent.
# Contains the intelligence of the remote agents.

from __future__ import annotations

from typing import Protocol

from common.config import config
from common.logging import logger
from common.ollama_client import OllamaClient
from common.prompts import SYSTEM_PROMPT, build_prompt


class TextAgent(Protocol):
    async def run(self, query: str) -> str:
        ...


# Simple DeepSeek-backed chat agent.
class DeepSeekAgent:

    def __init__(
        self,
        client: OllamaClient | None = None,
        model: str | None = None,
    ) -> None:
        self.client = client or OllamaClient()
        self.model = model or config.REMOTE_MODEL

    async def run(self, query: str) -> str:
        logger.info("Sending request to Ollama...")

        response = await self.client.chat(
            model=self.model,
            system=SYSTEM_PROMPT,
            prompt=build_prompt(query),
        )

        logger.info("Received response from Ollama.")

        return response
