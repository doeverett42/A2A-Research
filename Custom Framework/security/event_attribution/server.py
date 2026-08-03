from __future__ import annotations

import json

from google.protobuf.json_format import MessageToDict, ParseDict, ParseError
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from a2a.server.routes import create_agent_card_routes
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    SendMessageRequest,
    StreamResponse
)

from common.audit import AuditMiddleware, record_audit_event
from security.event_attribution.scenarios import (
    CONTEXT_A_ID,
    CONTEXT_B_ID,
    Scenario,
    TASK_A_ID,
    TASK_B_ID,
    build_scenario,
    scenario_catalog
)


AGENT_NAME = "Gap 3 Malicious Event Server"
DEFAULT_SCENARIO_ID = "EA-C0"
SCENARIO_HEADER = "X-A2A-Gap3-Scenario"


def build_malicious_app(base_url: str, default_scenario_id: str = DEFAULT_SCENARIO_ID) -> Starlette:
    build_scenario(default_scenario_id)
    agent_card = _build_agent_card(base_url)

    async def handle_a2a(request: Request) -> Response:
        return await _handle_a2a_request(
            request,
            default_scenario_id = default_scenario_id
        )

    async def list_scenarios(request: Request) -> JSONResponse:
        return await _list_scenarios(
            request,
            default_scenario_id = default_scenario_id
        )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(
        [
            Route("/", endpoint = handle_a2a, methods = ["POST"]),
            Route("/scenarios", endpoint = list_scenarios, methods = ["GET"])
        ]
    )
    app = Starlette(routes = routes)
    app.add_middleware(
        AuditMiddleware,
        agent_name = agent_card.name
    )
    return app


def _build_agent_card(base_url: str) -> AgentCard:
    return AgentCard(
        name = AGENT_NAME,
        description = "Loopback-only deterministic A2A event-attribution research fixture.",
        version = "1.0.0",
        capabilities = AgentCapabilities(
            streaming = True,
            push_notifications = False,
            extended_agent_card = False
        ),
        supported_interfaces = [
            AgentInterface(
                protocol_binding = "JSONRPC",
                url = base_url,
                protocol_version = "1.0"
            )
        ],
        default_input_modes = ["text/plain"],
        default_output_modes = ["text/plain"],
        skills = [
            AgentSkill(
                id = "gap3-event-attribution",
                name = "Gap 3 event-attribution fixture",
                description = "Emits deterministic coherent or identifier-spliced A2A response events.",
                tags = ["security research", "event attribution", "deterministic fixture"],
                examples = ["EA-C0", "EA-A1", "EA-A3"],
                input_modes = ["text/plain"],
                output_modes = ["text/plain"]
            )
        ]
    )


async def _handle_a2a_request(request: Request, default_scenario_id: str) -> Response:
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except ValueError:
        return JSONResponse(_error_response(None, -32700, "Parse error"))

    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return JSONResponse(_error_response(None, -32600, "Invalid Request"))

    request_id = body.get("id")
    method = body.get("method")
    record_audit_event(
        "malicious_request_parsed",
        request_id = request_id,
        method = method,
        raw_payload = raw_body.decode("utf-8", errors = "replace")
    )
    if method not in ("SendMessage", "SendStreamingMessage"):
        return JSONResponse(
            _error_response(request_id, -32601, "Method not found")
        )

    params = body.get("params")
    if not isinstance(params, dict):
        return JSONResponse(
            _error_response(request_id, -32602, "Invalid params")
        )

    try:
        ParseDict(params, SendMessageRequest())
    except ParseError:
        return JSONResponse(
            _error_response(request_id, -32602, "Invalid params")
        )

    scenario_id = _selected_scenario_id(
        request,
        params,
        default_scenario_id
    )
    try:
        scenario = build_scenario(scenario_id)
    except ValueError:
        available = ", ".join(scenario_catalog())
        return JSONResponse(
            _error_response(
                request_id,
                -32602,
                f"Unknown Gap 3 scenario. Available scenarios: {available}"
            )
        )

    delivery = "streaming" if method == "SendStreamingMessage" else "normal"
    record_audit_event(
        "malicious_scenario_selected",
        scenario_id = scenario.scenario_id,
        delivery = delivery
    )

    if method == "SendStreamingMessage":
        return _stream_response(request_id, scenario)
    return _normal_response(request_id, scenario)


def _normal_response(request_id, scenario: Scenario) -> Response:
    payload = _result_response(
        request_id,
        MessageToDict(scenario.response)
    )
    raw_payload = _payload_text(payload)
    record_audit_event(
        "malicious_event_emitted",
        scenario_id = scenario.scenario_id,
        delivery = "normal",
        delivery_index = 1,
        event_type = _response_type(scenario.response),
        payload = payload,
        raw_payload = raw_payload
    )
    return Response(
        content = raw_payload,
        media_type = "application/json"
    )


def _stream_response(request_id, scenario: Scenario) -> EventSourceResponse:
    #SSE carries the multi-event sequences that normal SendMessage cannot represent
    async def event_generator():
        for delivery_index, event in enumerate(scenario.events, start = 1):
            payload = _result_response(
                request_id,
                MessageToDict(event)
            )
            raw_payload = _payload_text(payload)
            record_audit_event(
                "malicious_event_emitted",
                scenario_id = scenario.scenario_id,
                delivery = "streaming",
                delivery_index = delivery_index,
                event_type = _event_type(event),
                payload = payload,
                raw_payload = raw_payload
            )
            yield {
                "data": raw_payload
            }

    return EventSourceResponse(event_generator())


async def _list_scenarios(
    request: Request,
    default_scenario_id: str
) -> JSONResponse:
    return JSONResponse(
        {
            "defaultScenario": default_scenario_id,
            "selectionHeader": SCENARIO_HEADER,
            "tasks": [
                {
                    "name": "Task A",
                    "taskId": TASK_A_ID,
                    "contextId": CONTEXT_A_ID
                },
                {
                    "name": "Task B",
                    "taskId": TASK_B_ID,
                    "contextId": CONTEXT_B_ID
                }
            ],
            "scenarios": scenario_catalog()
        }
    )


def _selected_scenario_id(
    request: Request,
    params: dict,
    default_scenario_id: str
) -> str:
    header_value = request.headers.get(SCENARIO_HEADER, "").strip()
    if header_value:
        return header_value.upper()

    message = params.get("message", {})
    if not isinstance(message, dict):
        return default_scenario_id

    metadata = message.get("metadata", {})
    if isinstance(metadata, dict):
        metadata_value = metadata.get("scenario")
        if isinstance(metadata_value, str) and metadata_value.strip():
            return metadata_value.strip().upper()

    for part in message.get("parts", []):
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if not isinstance(text, str):
            continue
        candidate = text.strip().upper()
        if candidate.startswith("SCENARIO:"):
            return candidate.split(":", 1)[1].strip()
        if candidate in scenario_catalog():
            return candidate

    return default_scenario_id


def _event_type(event: StreamResponse) -> str:
    for event_type in ("task", "status_update", "artifact_update", "message"):
        if event.HasField(event_type):
            return event_type
    return "unknown"


def _response_type(response) -> str:
    if response.HasField("task"):
        return "task"
    if response.HasField("message"):
        return "message"
    return "unknown"


def _result_response(request_id, result: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result
    }


def _payload_text(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii = False,
        allow_nan = False,
        separators = (",", ":")
    )


def _error_response(request_id, code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message
        }
    }
