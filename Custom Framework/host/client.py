#official a2a sdk client wrapper
#keeps protocol calls out of host orchestrator
#
#this is the wrapper mentioned in the experiment notes. the orchestrator deals
#with one simple remotetaskresponse, while this class deals with sdk messages,
#tasks, status updates, artifact updates, and streaming order.
#
#for a streaming call it keeps reading until the server stops. after every event
#it appends text and updates the currently selected task id, context id, and
#state. the final selected values are what the orchestrator receives. observers
#only copy these views into reports and do not change the response.

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
from google.protobuf.json_format import MessageToDict

from a2a.client import (
    A2ACardResolver,
    ClientCallContext,
    ClientConfig,
    create_client
)
from a2a.helpers import new_text_message
from a2a.types import (
    AgentCard,
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    StreamResponse,
    TaskState
)

from common.logging import logger
from common.services import validate_loopback_url


ClientEventObserver = Callable[[dict[str, Any]], None]


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
    def __init__(
        self,
        remote_url: str,
        timeout_seconds: int,
        streaming: bool = False,
        call_headers: dict[str, str] | None = None,
        event_observer: ClientEventObserver | None = None
    ) -> None:
        self.remote_url = remote_url
        self.timeout_seconds = timeout_seconds
        self.streaming = streaming
        self.call_headers = dict(call_headers or {})
        self.event_observer = event_observer
        self._client = None
        self._request_index = 0

    async def send_text(self, text: str) -> RemoteTaskResponse:
        #a new task starts without a task or context handle supplied by the host.
        return await self._send_text(text, None, None)

    async def continue_task(self, text: str, task_id: str, context_id: str) -> RemoteTaskResponse:
        #a continuation carries the tuple stored on the waiting orchestrator step.
        return await self._send_text(text, task_id, context_id)

    async def _send_text(
        self,
        text: str,
        task_id: str | None,
        context_id: str | None
    ) -> RemoteTaskResponse:
        self._request_index += 1
        request_index = self._request_index
        client = await self._get_client()
        #both new and continued tasks use the same sdk request shape. the only
        #difference is whether task_id and context_id are filled in above.
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
        call_context = None
        if self.call_headers:
            call_context = ClientCallContext(
                service_parameters = self.call_headers
            )

        self._observe(
            {
                "layer": "wrapper",
                "observation": "request_prepared",
                "request_index": request_index,
                "text": text,
                "task_id": task_id or "",
                "context_id": context_id or "",
                "streaming": self.streaming
            }
        )

        event_index = 0
        #the sdk yields once for a normal response or several times for a stream.
        #ea-a3 matters because later events replace the handles selected here.
        async for event in client.send_message(request, context = call_context):
            event_index += 1
            event_type = _event_type(event)
            self._observe(
                {
                    "layer": "sdk",
                    "observation": "event_yielded",
                    "request_index": request_index,
                    "event_index": event_index,
                    "event_type": event_type,
                    "payload": MessageToDict(event)
                }
            )

            event_chunks = _extract_text(event)
            chunks.extend(event_chunks)
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

            #records wrapper output after this event changes text and handles
            #this is how the report shows the exact event where a/a became b/b
            self._observe(
                {
                    "layer": "wrapper",
                    "observation": "event_processed",
                    "request_index": request_index,
                    "event_index": event_index,
                    "event_type": event_type,
                    "extracted_text": event_chunks,
                    "accumulated_text": "\n".join(
                        chunk for chunk in chunks if chunk
                    ).strip(),
                    "selected_task_id": response_task_id,
                    "selected_context_id": response_context_id,
                    "selected_state": int(response_state)
                }
            )

        response = "\n".join(chunk for chunk in chunks if chunk).strip()
        if not response:
            raise RuntimeError("Remote agent returned no text response.")
        if response_state == TaskState.TASK_STATE_INPUT_REQUIRED:
            if not response_task_id or not response_context_id:
                raise RuntimeError("Remote agent requested input without task/context IDs.")

        self._observe(
            {
                "layer": "wrapper",
                "observation": "response_returned",
                "request_index": request_index,
                "text": response,
                "task_id": response_task_id,
                "context_id": response_context_id,
                "state": int(response_state),
                "requires_input": response_state == TaskState.TASK_STATE_INPUT_REQUIRED
            }
        )
        #from here on the orchestrator sees only this flattened response. it does
        #not reread the original sdk event sequence itself.
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
            validate_loopback_url(self.remote_url)
            httpx_client = httpx.AsyncClient(
                timeout = httpx.Timeout(self.timeout_seconds),
            )
            try:
                #discovery already reads this card for planning, but the sdk
                #client reads it again when the step runs. validate this fresh
                #copy too so a changed card cannot redirect the local test.
                resolver = A2ACardResolver(httpx_client, self.remote_url)
                card = await resolver.get_agent_card()
                _validate_agent_card_urls(card)
                self._client = await create_client(
                    card,
                    client_config = ClientConfig(
                        streaming = self.streaming,
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

    def _observe(self, observation: dict[str, Any]) -> None:
        if self.event_observer is not None:
            self.event_observer(observation)


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


def _event_type(event: StreamResponse) -> str:
    for event_type in ("task", "status_update", "artifact_update", "message"):
        if event.HasField(event_type):
            return event_type
    return "unknown"


def _validate_agent_card_urls(card: AgentCard) -> None:
    jsonrpc_urls = [
        interface.url
        for interface in card.supported_interfaces
        if interface.protocol_binding == "JSONRPC"
    ]
    if not jsonrpc_urls:
        raise ValueError(
            f"Agent Card for {card.name} does not include a JSON-RPC URL."
        )
    for url in jsonrpc_urls:
        validate_loopback_url(url)
