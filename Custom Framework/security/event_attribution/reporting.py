from __future__ import annotations

#both runners save the same views of a plan, response, and transport request.
#keep these small helpers together so their reports use the same field names.

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from host.orchestrator import OrchestrationResult
from host.router import DelegationPlan


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def canaries(text: str) -> list[str]:
    return sorted(set(re.findall(r"CANARY-[A-Z0-9-]+", text)))


def plan_snapshot(plan: DelegationPlan) -> dict:
    return {
        "mode": plan.mode,
        "reason": plan.reason,
        "steps": [
            {
                "step_id": step.step_id,
                "agent_index": step.agent_index,
                "agent_name": step.agent_name,
                "remote_url": step.remote_url,
                "task": step.task,
                "depends_on": step.depends_on
            }
            for step in plan.steps
        ]
    }


def result_snapshot(result: OrchestrationResult | None) -> dict | None:
    if result is None:
        return None
    return {
        "plan": plan_snapshot(result.plan),
        "step_results": [
            {
                "step_id": item.step.step_id,
                "agent_name": item.step.agent_name,
                "remote_url": item.step.remote_url,
                "response": item.response,
                "response_canaries": canaries(item.response),
                "error": item.error,
                "task_id": item.task_id,
                "context_id": item.context_id,
                "input_required": item.input_required
            }
            for item in result.step_results
        ],
        "response": result.response,
        "response_canaries": canaries(result.response),
        "input_required": result.input_required
    }


def pending_snapshot(pending) -> dict | None:
    if pending is None or not pending.step_results:
        return None
    waiting_result = pending.step_results[-1]
    return {
        "step_index": pending.step_index,
        "step_id": waiting_result.step.step_id,
        "agent_name": waiting_result.step.agent_name,
        "remote_url": waiting_result.step.remote_url,
        "task_id": waiting_result.task_id,
        "context_id": waiting_result.context_id,
        "response": waiting_result.response,
        "response_canaries": canaries(waiting_result.response),
        "input_required": waiting_result.input_required
    }


def transport_requests(events: list[dict]) -> list[dict]:
    requests = []
    for event in events:
        if event.get("event") != "malicious_request_parsed":
            continue
        raw_payload = event.get("raw_payload", "")
        try:
            payload = json.loads(raw_payload)
        except (TypeError, ValueError):
            payload = None
        requests.append(
            {
                "timestamp": event.get("timestamp"),
                "request_id": event.get("request_id"),
                "method": event.get("method"),
                "raw_payload": raw_payload,
                "payload": payload
            }
        )
    return requests


def write_report(report: dict, output_directory: Path) -> Path:
    output_directory.mkdir(parents = True, exist_ok = True)
    report_path = output_directory / f"{report['run']['run_id']}.json"
    report_path.write_text(
        json.dumps(report, indent = 2, ensure_ascii = False) + "\n",
        encoding = "utf-8"
    )
    return report_path
