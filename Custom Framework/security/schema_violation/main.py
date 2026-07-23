from __future__ import annotations

import asyncio
from uuid import uuid4

import httpx

from common.audit import AUDIT_HEADER, audit_log_path, read_audit_events
from common.config import config
from host.discovery import AgentDiscovery, RemoteAgentInfo
from security.schema_violation.attacks.malformed_json import build_payload


def build_control_message(request_id: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": f"{request_id}-message",
                "role": "ROLE_USER",
                "parts": [
                    {
                        "text": "Confirm that you received this live A2A security control message.",
                        "mediaType": "text/plain"
                    }
                ]
            },
            "configuration": {
                "acceptedOutputModes": ["text/plain"]
            }
        }
    }


async def run_test() -> bool:
    discovery = AgentDiscovery(
        agent_card_urls = config.remote_agent_card_urls,
        timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS
    )
    agents = await discovery.discover()

    if not agents:
        print("No live remote agents were discovered.")
        print("Start the configured remote servers and run this test again.")
        return False

    all_passed = len(agents) == len(config.remote_agent_card_urls)
    async with httpx.AsyncClient(
        timeout = httpx.Timeout(config.A2A_CLIENT_TIMEOUT_SECONDS)
    ) as client:
        for agent in agents:
            passed = await test_agent(client, agent)
            all_passed = all_passed and passed

    return all_passed


async def test_agent(client: httpx.AsyncClient, agent: RemoteAgentInfo) -> bool:
    run_id = uuid4().hex
    control_audit_id = f"control-{run_id}"
    attack_audit_id = f"attack-{run_id}"

    control_response = await client.post(
        agent.url,
        json = build_control_message(control_audit_id),
        headers = {
            "A2A-Version": "1.0",
            AUDIT_HEADER: control_audit_id
        }
    )
    attack_response = await client.post(
        agent.url,
        content = build_payload(attack_audit_id),
        headers = {
            "A2A-Version": "1.0",
            "Content-Type": "application/json",
            AUDIT_HEADER: attack_audit_id
        }
    )

    control_events = read_audit_events(agent.name, control_audit_id)
    attack_events = read_audit_events(agent.name, attack_audit_id)
    control_event_names = _event_names(control_events)
    attack_event_names = _event_names(attack_events)

    control_reached_ollama = "agent_call_completed" in control_event_names
    attack_reached_executor = "executor_started" in attack_event_names
    attack_error_code = _jsonrpc_error_code(attack_response)
    auditing_active = bool(control_events) and bool(attack_events)
    passed = (
        control_reached_ollama
        and not attack_reached_executor
        and attack_error_code == -32700
    )

    print()
    print(f"agent: {agent.name}")
    print(f"endpoint: {agent.url}")
    print(f"audit log: {audit_log_path(agent.name)}")
    print(f"control status: {control_response.status_code}")
    print(f"control events: {', '.join(control_event_names) or 'none'}")
    print(f"control reached ollama: {control_reached_ollama}")
    print(f"attack status: {attack_response.status_code}")
    print(f"attack json-rpc error: {attack_error_code}")
    print(f"attack events: {', '.join(attack_event_names) or 'none'}")
    print(f"attack reached executor: {attack_reached_executor}")
    print(f"result: {'passed' if passed else 'failed'}")

    if not auditing_active:
        print("audit warning: restart this remote server so it loads the audit middleware")

    return passed


def _event_names(events: list[dict]) -> list[str]:
    return [event["event"] for event in events]


def _jsonrpc_error_code(response: httpx.Response):
    try:
        response_body = response.json()
    except ValueError:
        return None
    return response_body.get("error", {}).get("code")


if __name__ == "__main__":
    if not asyncio.run(run_test()):
        raise SystemExit(1)
