#wrapper around Ollama Python client

from __future__ import annotations

from typing import Any

from ollama import AsyncClient

class OllamaClient:
    def __init__(self, host: str) -> None:
        self.client = AsyncClient(host=host)

    async def chat(self, model: str, system: str, prompt: str, temperature: float) -> str:
        response = await self.client.chat(
            model = model,
            options = {"temperature": temperature},
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        )
        return _message_content(response)

    async def chat_json(
        self,
        model: str,
        system: str,
        prompt: str,
        temperature: float,
        schema: dict[str, Any]
    ) -> str:
        response = await self.client.chat(
            model = model,
            format = schema,
            options = {"temperature": temperature},
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        )
        return _message_content(response)

    async def health_check(self) -> bool:
        try:
            await self.client.list()
            return True
        except Exception:
            return False


def _message_content(response: Any) -> str:
    message = response.get("message") if isinstance(response, dict) else getattr(response, "message", None)
    if isinstance(message, dict):
        return str(message.get("content", ""))
    return str(getattr(message, "content", ""))
