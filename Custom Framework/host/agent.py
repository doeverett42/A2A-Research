#Host AI agent
#Contains the host-side orchestration intelligence

from __future__ import annotations

from common.config import config
from common.logging import logger
from common.ollama_client import OllamaClient
from common.prompts import HOST_SYSTEM_PROMPT, build_host_prompt


class HostAgent:
    def __init__(self, client: OllamaClient | None = None, model: str | None = None) -> None:
        self.client = client or OllamaClient()
        self.model = config.ollama_model(model or config.HOST_MODEL)

    async def prepare_delegation(self, user_message: str) -> str:
        logger.info("Preparing host delegation request...")

        delegated_request = await self.client.chat(
            model = self.model,
            system = HOST_SYSTEM_PROMPT,
            prompt = build_host_prompt(user_message)
        )

        logger.info("Prepared host delegation request.")

        return delegated_request.strip() or user_message.strip()
