# Official A2A SDK client wrapper
# Keeps protocol calls out of the host orchestrator

from __future__ import annotations

import httpx

from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageConfiguration, SendMessageRequest, StreamResponse

from common.config import config
from common.logging import logger


class RemoteAgentClient:
    def __init__(self, remote_url: str | None = None, timeout_seconds: int | None = None) -> None:
        self.remote_url = remote_url or config.host_remote_url
        self.timeout_seconds = timeout_seconds or config.A2A_CLIENT_TIMEOUT_SECONDS
        self._client = None

    async def send_text(self, text: str) -> str:
        client = await self._get_client()
        request = SendMessageRequest(
            message = new_text_message(
                text,
                media_type = "text/plain",
                role = Role.ROLE_USER,
            ),
            configuration = SendMessageConfiguration(
                accepted_output_modes = ["text/plain"],
            ),
        )

        chunks = []
        async for event in client.send_message(request):
            chunks.extend(_extract_text(event))

        response = "\n".join(chunk for chunk in chunks if chunk).strip()
        if not response:
            raise RuntimeError("Remote agent returned no text response.")

        return response

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def _get_client(self):
        if self._client is None:
            logger.info("Resolving remote agent card from %s", self.remote_url)
            httpx_client = httpx.AsyncClient(
                timeout = httpx.Timeout(self.timeout_seconds),
            )
            try:
                self._client = await create_client(
                    self.remote_url,
                    client_config = ClientConfig(
                        streaming = False,
                        polling = False,
                        httpx_client = httpx_client,
                        accepted_output_modes = ["text/plain"],
                    ),
                )
            except Exception:
                await httpx_client.aclose()
                raise
            logger.info("Remote A2A client ready.")

        return self._client


def _extract_text(event: StreamResponse) -> list[str]:
    if event.HasField("message"):
        return _parts_text(event.message.parts)

    if event.HasField("task"):
        artifact_text = []
        for artifact in event.task.artifacts:
            artifact_text.extend(_parts_text(artifact.parts))
        if artifact_text:
            return artifact_text
        if event.task.status.HasField("message"):
            return _parts_text(event.task.status.message.parts)

    if event.HasField("artifact_update"):
        return _parts_text(event.artifact_update.artifact.parts)

    if event.HasField("status_update") and event.status_update.status.HasField("message"):
        return _parts_text(event.status_update.status.message.parts)

    return []


def _parts_text(parts) -> list[str]:
    text_parts = []
    for part in parts:
        if part.WhichOneof("content") == "text":
            text_parts.append(part.text)
    return text_parts
