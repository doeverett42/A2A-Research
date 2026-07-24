#Remote AI agent
#Contains the intelligence of the remote agents

from __future__ import annotations

import json

from typing import Protocol

from common.logging import logger
from common.ollama_client import OllamaClient
from common.prompts import REMOTE_AGENT_RESPONSE_SYSTEM_PROMPT, build_prompt


REMOTE_AGENT_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["completed", "input_required"]
        },
        "message": {
            "type": "string",
            "minLength": 1
        }
    },
    "required": ["status", "message"],
    "additionalProperties": False
}


class RemoteAgentResponse:
    def __init__(self, status: str, message: str) -> None:
        self.status = status
        self.message = message

    @property
    def requires_input(self) -> bool:
        return self.status == "input_required"

#ensure that every remote agent includes the method run()
class RemoteAgentProtocol(Protocol):
    async def run(self, query: str) -> RemoteAgentResponse:
        pass


#simple ollama-backed chat agent
class OllamaRemoteAgent:

    def __init__(self, client: OllamaClient, model: str, system_prompt: str) -> None:
        self.client = client
        self.model = model
        self.system_prompt = system_prompt

    async def run(self, query: str) -> RemoteAgentResponse:
        logger.info("Sending request to Ollama model %s...", self.model)

        response = await self.client.chat_json(
            model = self.model,
            system = "\n\n".join(
                [self.system_prompt, REMOTE_AGENT_RESPONSE_SYSTEM_PROMPT]
            ),
            prompt = build_prompt(query),
            temperature = 0.2,
            schema = REMOTE_AGENT_RESPONSE_SCHEMA
        )
        result = _response_data(response)

        logger.info("Received response from Ollama.")

        return RemoteAgentResponse(
            status = str(result["status"]),
            message = str(result["message"]).strip()
        )


def _response_data(response: str) -> dict[str, object]:
    try:
        data = json.loads(response)
    except json.JSONDecodeError as e:
        raise ValueError(f"Remote agent returned invalid response JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Remote agent response must be a JSON object.")
    if data.get("status") not in {"completed", "input_required"}:
        raise ValueError("Remote agent response contains an invalid status.")
    if not isinstance(data.get("message"), str) or not data["message"].strip():
        raise ValueError("Remote agent response must contain a message.")

    return data
