from __future__ import annotations

#local deterministic a2a test server
#this server is the controlled response source used by both experiment runners.
#it advertises a real agent card and accepts real sdk requests, but it never
#calls an llm. instead, it selects one fixture from scenarios.py and emits the
#same harmless events every time.
#the five fixtures cover ea-a3, tm-1/tm-2, and their coherent controls. the do
#experiments reuse ea-a3 while the runner changes the surrounding agent order.
#
#request flow:
#1. parse and validate the json-rpc request
#2. choose the scenario from the experiment header or message
#3. attach the run-specific canary used for attribution
#4. decide whether this is an initial request or the expected continuation
#5. return one normal response or the fixture's ordered streaming events
#6. audit the raw request and every emitted event for the final report

import json
import re

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
    HOST_CONTINUATION_CANARY,
    Scenario,
    TASK_A_ID,
    TASK_B_ID,
    build_continuation_scenario,
    build_scenario,
    continuation_handles,
    scenario_catalog
)


AGENT_NAME = "External Security Reviewer Test Agent"
DEFAULT_SCENARIO_ID = "EA-C0"
SCENARIO_HEADER = "X-A2A-Gap3-Scenario"
RUN_CANARY_HEADER = "X-A2A-Gap3-Canary"


def build_malicious_app(base_url: str, default_scenario_id: str = DEFAULT_SCENARIO_ID) -> Starlette:
    #building the default once here catches a bad scenario before uvicorn starts.
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
        description = "Loopback-only deterministic A2A external-review research fixture.",
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
                id = "gap3-external-review",
                name = "Gap 3 external-review fixture",
                description = "Emits deterministic coherent or identifier-spliced A2A response events.",
                tags = ["security research", "event attribution", "deterministic fixture"],
                examples = ["EA-C0", "EA-C2", "EA-TM1", "EA-TM2", "EA-A3"],
                input_modes = ["text/plain"],
                output_modes = ["text/plain"]
            )
        ]
    )


async def _handle_a2a_request(request: Request, default_scenario_id: str) -> Response:
    #keep the raw bytes for the audit trail before protobuf parsing changes the
    #shape or naming of any fields.
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

    #the runners normally select the case with a header. message selection is
    #also supported so the fixture can be inspected by hand during development.
    scenario_id = _selected_scenario_id(
        request,
        params,
        default_scenario_id
    )
    try:
        run_canary = validate_run_canary(
            request.headers.get(RUN_CANARY_HEADER, "")
        )
    except ValueError as e:
        return JSONResponse(
            _error_response(request_id, -32602, str(e))
        )

    try:
        #a continuation must carry the exact expected tuple and harmless text.
        #otherwise it is treated as a fresh initial request for that scenario.
        if _is_scenario_continuation(scenario_id, params):
            scenario = build_continuation_scenario(
                scenario_id,
                run_canary
            )
            scenario_phase = "continuation_completion"
        else:
            scenario = build_scenario(scenario_id, run_canary)
            scenario_phase = "initial"
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
        delivery = delivery,
        phase = scenario_phase,
        run_canary = run_canary
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
        event_type = "task",
        payload = payload,
        raw_payload = raw_payload
    )
    return Response(
        content = raw_payload,
        media_type = "application/json"
    )


def _stream_response(request_id, scenario: Scenario) -> EventSourceResponse:
    #sse carries the multi-event sequences that normal sendmessage cannot represent
    async def event_generator():
        #events are yielded in list order so the wrapper can record its selected
        #text, tuple, and state after each separate change.
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
            "runCanaryHeader": RUN_CANARY_HEADER,
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


def _is_scenario_continuation(scenario_id: str, params: dict) -> bool:
    #this check belongs to the deterministic fixture, not the host. the host has
    #already chosen which tuple to send by the time the request reaches here.
    handles = continuation_handles(scenario_id)
    if handles is None:
        return False
    task_id, context_id = handles

    message = params.get("message", {})
    if not isinstance(message, dict):
        return False
    if message.get("taskId") != task_id:
        return False
    if message.get("contextId") != context_id:
        return False

    return HOST_CONTINUATION_CANARY in _message_text(message)


def validate_run_canary(value: str) -> str:
    run_canary = value.strip().upper()
    if not run_canary:
        return ""
    if not re.fullmatch(r"CANARY-G3-[A-Z0-9-]{1,64}", run_canary):
        raise ValueError(
            "Gap 3 run canary must use CANARY-G3- followed by letters, "
            "numbers, or hyphens."
        )
    return run_canary


def _message_text(message: dict) -> str:
    text_parts = []
    for part in message.get("parts", []):
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str):
            text_parts.append(text)
    return "\n".join(text_parts)


def _event_type(event: StreamResponse) -> str:
    for event_type in ("task", "status_update", "artifact_update"):
        if event.HasField(event_type):
            return event_type
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
