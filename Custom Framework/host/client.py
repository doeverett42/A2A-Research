#Official A2A SDK client wrapper
#keeps protocol calls out of host orchestrator

from __future__ import annotations

import httpx

from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageConfiguration, SendMessageRequest, StreamResponse, TaskState

from common.logging import logger


class RemoteTaskResponse:
    def __init__(self, text: str, task_id: str, context_id: str, state: int) -> None:
        self.text = text
        self.task_id = task_id
        self.context_id = context_id
        self.state = state

    @property
    def requires_input(self) -> bool:
        return self.state == TaskState.TASK_STATE_INPUT_REQUIRED


class RemoteAgentClient:
    def __init__(self, remote_url: str, timeout_seconds: int) -> None:
        self.remote_url = remote_url
        self.timeout_seconds = timeout_seconds
        self._client = None

    async def send_text(self, text: str) -> RemoteTaskResponse:
        return await self._send_text(text, None, None)

    async def continue_task(self, text: str, task_id: str, context_id: str) -> RemoteTaskResponse:
        return await self._send_text(text, task_id, context_id)

    async def _send_text(
        self,
        text: str,
        task_id: str | None,
        context_id: str | None
    ) -> RemoteTaskResponse:
        client = await self._get_client()
        request = SendMessageRequest(
            message = new_text_message(
                text,
                media_type = "text/plain",
                context_id = context_id,
                task_id = task_id,
                role = Role.ROLE_USER
            ),
            configuration = SendMessageConfiguration(
                accepted_output_modes = ["text/plain"]
            )
        )

        chunks = []
        response_task_id = ""
        response_context_id = ""
        response_state = TaskState.TASK_STATE_UNSPECIFIED
        async for event in client.send_message(request):
            chunks.extend(_extract_text(event))
            if event.HasField("task"):
                response_task_id = event.task.id
                response_context_id = event.task.context_id
                response_state = event.task.status.state
            elif event.HasField("status_update"):
                response_task_id = event.status_update.task_id
                response_context_id = event.status_update.context_id
                response_state = event.status_update.status.state
            elif event.HasField("artifact_update"):
                response_task_id = event.artifact_update.task_id
                response_context_id = event.artifact_update.context_id
            elif event.HasField("message"):
                response_task_id = event.message.task_id
                response_context_id = event.message.context_id

        response = "\n".join(chunk for chunk in chunks if chunk).strip()
        if not response:
            raise RuntimeError("Remote agent returned no text response.")
        if response_state == TaskState.TASK_STATE_INPUT_REQUIRED:
            if not response_task_id or not response_context_id:
                raise RuntimeError("Remote agent requested input without task/context IDs.")

        return RemoteTaskResponse(
            text = response,
            task_id = response_task_id,
            context_id = response_context_id,
            state = response_state
        )

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
                        accepted_output_modes = ["text/plain"]
                    )
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
