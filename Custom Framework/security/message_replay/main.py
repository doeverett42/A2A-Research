from __future__ import annotations

import argparse
import asyncio
from uuid import uuid4

import httpx

from common.audit import AUDIT_HEADER, audit_log_path, read_audit_events
from common.config import config
from host.discovery import AgentDiscovery, RemoteAgentInfo
from security.message_replay.attack import build_replay_message


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Run the sequential A2A message-ID replay test."
    )
    parser.add_argument(
        "--agent-index",
        type = int,
        required = True,
        choices = range(len(config.remote_agent_specs)),
        help = "Configured remote agent index to test."
    )
    return parser.parse_args()


async def run_test(agent_index: int) -> bool:
    discovery = AgentDiscovery(
        agent_card_urls = [config.remote_agent_card_urls[agent_index]],
        timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS
    )
    agents = await discovery.discover()

    if not agents:
        print("The selected remote agent could not be discovered.")
        print("Start that remote server and run this test again.")
        return False

    async with httpx.AsyncClient(timeout=httpx.Timeout(config.A2A_CLIENT_TIMEOUT_SECONDS)) as client:
        return await test_agent(client, agents[0])


async def test_agent(client: httpx.AsyncClient, agent: RemoteAgentInfo) -> bool:
    run_id = uuid4().hex
    message_id = f"replay-message-{run_id}"
    context_id = f"replay-context-{run_id}"
    first_audit_id = f"replay-first-{run_id}"
    second_audit_id = f"replay-second-{run_id}"
    text = "Confirm that you received this A2A replay research message."

    first_response = await _send_message(
        client,
        agent,
        first_audit_id,
        message_id,
        context_id,
        text
    )
    second_response = await _send_message(
        client,
        agent,
        second_audit_id,
        message_id,
        context_id,
        text
    )

    first_events = read_audit_events(agent.name, first_audit_id)
    second_events = read_audit_events(agent.name, second_audit_id)
    first_event_names = _event_names(first_events)
    second_event_names = _event_names(second_events)
    first_completed = "agent_call_completed" in first_event_names
    second_completed = "agent_call_completed" in second_event_names
    first_task_id = _task_id(first_events)
    second_task_id = _task_id(second_events)

    if not first_completed:
        outcome = "inconclusive"
        explanation = "The first delivery did not complete an Ollama call."
        completed = False
    elif second_completed:
        outcome = "replay accepted"
        explanation = "The repeated message ID caused a second Ollama call."
        completed = True
    elif "executor_started" not in second_event_names:
        outcome = "replay rejected"
        explanation = "The repeated message ID did not enter the executor."
        completed = True
    else:
        outcome = "inconclusive"
        explanation = "The replay entered the executor but did not complete an Ollama call."
        completed = False

    print()
    print(f"agent: {agent.name}")
    print(f"endpoint: {agent.url}")
    print(f"audit log: {audit_log_path(agent.name)}")
    print(f"shared message ID: {message_id}")
    print(f"shared context ID: {context_id}")
    print(f"first audit ID: {first_audit_id}")
    print(f"first status: {first_response.status_code}")
    print(f"first events: {', '.join(first_event_names) or 'none'}")
    print(f"first task ID: {first_task_id or 'none'}")
    print(f"second audit ID: {second_audit_id}")
    print(f"second status: {second_response.status_code}")
    print(f"second events: {', '.join(second_event_names) or 'none'}")
    print(f"second task ID: {second_task_id or 'none'}")
    print(f"outcome: {outcome}")
    print(f"finding: {explanation}")

    if not first_events or not second_events:
        print("audit warning: restart this remote server so it loads the current audit code")

    return completed


async def _send_message(client: httpx.AsyncClient, agent: RemoteAgentInfo, audit_id: str, message_id: str, context_id: str, text: str) -> httpx.Response:
    response = await client.post(
        agent.url,
        json = build_replay_message(
            request_id = audit_id,
            message_id = message_id,
            context_id = context_id,
            text = text
        ),
        headers = {
            "A2A-Version": "1.0",
            AUDIT_HEADER: audit_id
        }
    )
    return response


def _event_names(events: list[dict]) -> list[str]:
    return [event["event"] for event in events]


def _task_id(events: list[dict]) -> str:
    for event in events:
        if event["event"] == "task_ready":
            return event["task_id"]
    return ""


if __name__ == "__main__":
    args = parse_args()
    if not asyncio.run(run_test(args.agent_index)):
        raise SystemExit(1)