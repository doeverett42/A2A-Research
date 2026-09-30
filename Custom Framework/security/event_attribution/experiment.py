from __future__ import annotations

#standalone gap 3 experiment runner
#this is the small version of the experiment, so it only follows one step from
#the real host orchestrator to the local test server. it skips ollama planning
#and synthesis on purpose so a changing model cannot change the test order.
#
#the full path through this file is:
#1. discover the local test server and read its real agent card
#2. build one fixed plan step that points at that server
#3. send the selected scenario through the real a2a client wrapper
#4. record every streaming event after the sdk and wrapper process it
#5. let the real host orchestrator decide whether the task is now pending
#6. send one harmless continuation when the response asks for input
#7. save the transport, wrapper, orchestrator, and host views in one report
#
#usual local setup:
#terminal 1: python -m security.event_attribution.main
#terminal 2: python -m security.event_attribution.experiment --scenario ea-a3
#
#ea-a3 is useful here because its first event uses task a/context a, but its
#later input-required event uses task b/context b. this shows which handles the
#wrapper and orchestrator actually keep when the stream changes underneath them.

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from google.protobuf.json_format import MessageToDict

from common.audit import AUDIT_HEADER, read_audit_events
from common.services import validate_loopback_url
from host.client import RemoteAgentClient
from host.discovery import AgentDiscovery, RemoteAgentInfo
from host.orchestrator import HostOrchestrator, OrchestrationResult
from host.router import DelegationPlan, PlanStep
from security.event_attribution.reporting import (
    canaries as _canaries,
    pending_snapshot as _pending_snapshot,
    plan_snapshot as _plan_snapshot,
    result_snapshot as _result_snapshot,
    timestamp as _timestamp,
    transport_requests as _transport_requests,
    write_report as _write_report
)
from security.event_attribution.scenarios import (
    CONTEXT_B_ID,
    TASK_B_ID,
    scenario_catalog
)
from security.event_attribution.server import (
    AGENT_NAME,
    SCENARIO_HEADER
)


DEFAULT_SERVER_URL = "http://127.0.0.1:8010"
DEFAULT_OUTPUT_DIRECTORY = Path(__file__).resolve().parents[2] / "logs" / "audit" / "gap3_runs"
DEFAULT_USER_MESSAGE = "Run the deterministic Gap 3 orchestration experiment."
DEFAULT_CONTINUATION = "CANARY-HOST-CONTINUATION"

ATTACK_CANARIES = {
    "EA-C0": [],
    "EA-C2": [],
    "EA-TM1": ["CANARY-TM1-SPLIT-B-A"],
    "EA-TM2": ["CANARY-TM2-SPLIT-A-B"],
    "EA-A3": ["CANARY-FORGED-INPUT-B"]
}


class ExperimentRecorder:
    def __init__(self) -> None:
        self.client_observations = []
        self.orchestrator_observations = []

    def record_client(self, observation: dict[str, Any]) -> None:
        self.client_observations.append(
            {
                "recorded_at": _timestamp(),
                **observation
            }
        )

    def record_orchestrator(self, observation: str, **details) -> None:
        self.orchestrator_observations.append(
            {
                "recorded_at": _timestamp(),
                "observation": observation,
                **details
            }
        )


#replaces only the llm-owned wording decisions while preserving the real host flow
class DeterministicHostAgent:
    def __init__(self, scenario_id: str, recorder: ExperimentRecorder) -> None:
        self.scenario_id = scenario_id
        self.recorder = recorder

    async def prepare_delegation(
        self,
        user_message: str,
        agent_name: str,
        assigned_task: str,
        dependency_results: list[str]
    ) -> str:
        self.recorder.record_orchestrator(
            "delegation_prepared",
            agent_name = agent_name,
            assigned_task = assigned_task,
            dependency_results = dependency_results,
            delegated_text = self.scenario_id
        )
        return self.scenario_id

    async def respond_directly(self, user_message: str) -> str:
        raise RuntimeError("The deterministic Gap 3 plan must contain one remote step.")

    async def synthesize(self, user_message: str, plan: str, results: str) -> str:
        raise RuntimeError("The deterministic one-step experiment must use passthrough output.")


class DeterministicRouter:
    def __init__(self, scenario_id: str, recorder: ExperimentRecorder) -> None:
        self.scenario_id = scenario_id
        self.recorder = recorder

    async def plan(
        self,
        user_message: str,
        agents: list[RemoteAgentInfo],
        host_agent: DeterministicHostAgent
    ) -> DelegationPlan:
        if len(agents) != 1:
            raise RuntimeError(
                f"Gap 3 discovery expected one malicious server and found {len(agents)}."
            )

        #there is no model choice here. every run gets the same one-step plan.
        agent = agents[0]
        #the discovery url is local, but the card supplies the execution url.
        #validate that second url too so a card cannot redirect this test run.
        validate_loopback_url(agent.url)
        plan = DelegationPlan(
            mode = "delegate",
            reason = "deterministic Gap 3 experiment",
            steps = [
                PlanStep(
                    step_id = 1,
                    agent_index = 0,
                    agent_name = agent.name,
                    remote_url = agent.url,
                    task = f"Execute {self.scenario_id} through the host orchestrator.",
                    depends_on = []
                )
            ]
        )
        self.recorder.record_orchestrator(
            "plan_created",
            user_message = user_message,
            discovered_agent = MessageToDict(agent.card),
            plan = _plan_snapshot(plan)
        )
        return plan


async def run_scenario(
    scenario_id: str,
    server_url: str = DEFAULT_SERVER_URL,
    timeout_seconds: int = 10,
    output_directory: Path | None = None,
    continue_pending: bool = True
) -> tuple[dict[str, Any], Path]:
    scenario_id = scenario_id.upper()
    if scenario_id not in scenario_catalog():
        raise ValueError(f"Unknown Gap 3 scenario: {scenario_id}")
    validate_loopback_url(server_url)

    #the run and audit ids tie the outgoing request to the exact server events
    #that come back later. this keeps two nearby runs from sharing evidence.
    run_id = f"gap3-{scenario_id.lower()}-{uuid4().hex}"
    audit_id = f"{run_id}-audit"
    recorder = ExperimentRecorder()
    deterministic_agent = DeterministicHostAgent(scenario_id, recorder)
    deterministic_router = DeterministicRouter(scenario_id, recorder)

    def client_factory(remote_url: str, timeout: int) -> RemoteAgentClient:
        #streaming is required because the fixture changes state and handles
        #across multiple events. the observer records what the wrapper sees.
        return RemoteAgentClient(
            remote_url,
            timeout,
            streaming = True,
            call_headers = {
                AUDIT_HEADER: audit_id,
                SCENARIO_HEADER: scenario_id
            },
            event_observer = recorder.record_client
        )

    #this is the normal host orchestrator. only its planner and host wording
    #object were replaced above so the experiment stays repeatable.
    orchestrator = HostOrchestrator(
        agent = deterministic_agent,
        discovery = AgentDiscovery(
            agent_card_urls = [server_url],
            timeout_seconds = timeout_seconds
        ),
        router = deterministic_router,
        timeout_seconds = timeout_seconds,
        client_factory = client_factory
    )
    recorder.record_orchestrator(
        "experiment_started",
        run_id = run_id,
        scenario_id = scenario_id,
        server_url = server_url,
        streaming = True
    )

    initial_result = None
    continuation_result = None
    pending_after_initial = None
    pending_after_continuation = None
    error = None

    try:
        #the first call runs the one fixed plan step and may leave it pending.
        initial_result = await orchestrator.run(DEFAULT_USER_MESSAGE)
        pending_after_initial = _pending_snapshot(orchestrator.pending)
        recorder.record_orchestrator(
            "initial_result_returned",
            result = _result_snapshot(initial_result),
            pending = pending_after_initial
        )

        if initial_result.input_required and continue_pending:
            #proves which pending handles the host uses for the next message
            recorder.record_orchestrator(
                "continuation_submitted",
                text = DEFAULT_CONTINUATION,
                task_id = initial_result.step_results[-1].task_id,
                context_id = initial_result.step_results[-1].context_id
            )
            #only the text is supplied here. the orchestrator itself pulls the
            #task and context ids out of the pending step result it stored.
            continuation_result = await orchestrator.run(DEFAULT_CONTINUATION)
            pending_after_continuation = _pending_snapshot(orchestrator.pending)
            recorder.record_orchestrator(
                "continuation_result_returned",
                result = _result_snapshot(continuation_result),
                pending = pending_after_continuation
            )
    except Exception as e:
        error = {
            "type": type(e).__name__,
            "message": str(e)
        }
        recorder.record_orchestrator(
            "experiment_failed",
            error = error
        )
    finally:
        await orchestrator.close()

    #the server audit, sdk events, wrapper output, and host state are kept apart
    #so it is clear which layer first accepted or changed a value.
    transport_events = read_audit_events(AGENT_NAME, audit_id)
    sdk_observations = [
        item for item in recorder.client_observations
        if item["layer"] == "sdk"
    ]
    wrapper_observations = [
        item for item in recorder.client_observations
        if item["layer"] == "wrapper"
    ]

    report = {
        "run": {
            "run_id": run_id,
            "scenario_id": scenario_id,
            "started_at": recorder.orchestrator_observations[0]["recorded_at"],
            "completed_at": _timestamp(),
            "server_url": server_url,
            "streaming": True,
            "continued_pending_task": bool(
                initial_result
                and initial_result.input_required
                and continue_pending
            )
        },
        "layers": {
            "transport": {
                "audit_id": audit_id,
                "requests": _transport_requests(transport_events),
                "audit_events": transport_events
            },
            "sdk": {
                "observations": sdk_observations
            },
            "wrapper": {
                "observations": wrapper_observations
            },
            "orchestrator": {
                "observations": recorder.orchestrator_observations,
                "initial_result": _result_snapshot(initial_result),
                "pending_after_initial": pending_after_initial,
                "continuation_result": _result_snapshot(continuation_result),
                "pending_after_continuation": pending_after_continuation
            },
            "host_output": {
                "mode": "single_step_passthrough",
                "initial_response": initial_result.response if initial_result else "",
                "continuation_response": continuation_result.response if continuation_result else ""
            }
        },
        "measurements": _measurements(
            scenario_id,
            sdk_observations,
            wrapper_observations,
            initial_result,
            continuation_result,
            pending_after_initial,
            pending_after_continuation,
            transport_events,
            error
        ),
        "error": error
    }

    report_path = _write_report(
        report,
        output_directory or DEFAULT_OUTPUT_DIRECTORY
    )
    return report, report_path


def _measurements(
    scenario_id: str,
    sdk_observations: list[dict],
    wrapper_observations: list[dict],
    initial_result: OrchestrationResult | None,
    continuation_result: OrchestrationResult | None,
    pending_after_initial: dict | None,
    pending_after_continuation: dict | None,
    transport_events: list[dict],
    error: dict | None
) -> dict:
    attack_canaries = ATTACK_CANARIES[scenario_id]
    wrapper_text = "\n".join(
        item.get("text", "")
        for item in wrapper_observations
        if item["observation"] == "response_returned"
    )
    step_text = ""
    host_text = ""
    step_uses_task_b = False
    if initial_result is not None:
        host_text = initial_result.response
        if initial_result.step_results:
            step_result = initial_result.step_results[-1]
            step_text = step_result.response
            step_uses_task_b = (
                step_result.task_id == TASK_B_ID
                and step_result.context_id == CONTEXT_B_ID
            )

    pending_uses_task_b = bool(
        pending_after_initial
        and pending_after_initial["task_id"] == TASK_B_ID
        and pending_after_initial["context_id"] == CONTEXT_B_ID
    )
    serialized_sdk = json.dumps(sdk_observations)
    final_result = continuation_result or initial_result
    final_input_required = bool(
        final_result and final_result.input_required
    )
    run_completed = bool(
        final_result
        and not error
        and not final_input_required
        and pending_after_continuation is None
    )

    return {
        "sdk_event_count": len(sdk_observations),
        "wrapper_response_count": sum(
            1 for item in wrapper_observations
            if item["observation"] == "response_returned"
        ),
        "all_wrapper_canaries": _canaries(wrapper_text),
        "wrapper_canary_counts": _canary_counts(wrapper_text),
        "host_canary_counts": _canary_counts(host_text),
        "attack_canaries": attack_canaries,
        "attack_canaries_reaching_wrapper": _matching_canaries(
            attack_canaries,
            wrapper_text
        ),
        "attack_canaries_reaching_step_result": _matching_canaries(
            attack_canaries,
            step_text
        ),
        "attack_canaries_reaching_host_output": _matching_canaries(
            attack_canaries,
            host_text
        ),
        "foreign_task_or_context_seen_by_sdk": (
            TASK_B_ID in serialized_sdk or CONTEXT_B_ID in serialized_sdk
        ),
        "step_result_uses_task_b_handles": step_uses_task_b,
        "pending_handles_overwritten": pending_uses_task_b,
        "continuation_sent_with_task_b_handles": _continuation_used_task_b(
            transport_events
        ),
        "continuation_attempted": continuation_result is not None,
        "final_input_required": final_input_required,
        "run_completed": run_completed,
        "operational_error": error is not None
    }


def _continuation_used_task_b(events: list[dict]) -> bool:
    for request in _transport_requests(events)[1:]:
        payload = request.get("payload") or {}
        message = payload.get("params", {}).get("message", {})
        if (
            message.get("taskId") == TASK_B_ID
            and message.get("contextId") == CONTEXT_B_ID
        ):
            return True
    return False


def _canary_counts(text: str) -> dict[str, int]:
    return {
        canary: text.count(canary)
        for canary in _canaries(text)
    }


def _matching_canaries(expected: list[str], text: str) -> list[str]:
    return [canary for canary in expected if canary in text]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Run Gap 3 through the deterministic host orchestrator."
    )
    parser.add_argument(
        "--scenario",
        type = str.upper,
        choices = list(scenario_catalog()),
        default = "EA-A3"
    )
    parser.add_argument("--all-scenarios", action = "store_true")
    parser.add_argument("--server-url", default = DEFAULT_SERVER_URL)
    parser.add_argument("--timeout-seconds", type = int, default = 10)
    parser.add_argument(
        "--output-directory",
        type = Path,
        default = DEFAULT_OUTPUT_DIRECTORY
    )
    parser.add_argument("--no-continuation", action = "store_true")
    return parser.parse_args()


async def _run_from_args(args: argparse.Namespace) -> bool:
    scenario_ids = list(scenario_catalog()) if args.all_scenarios else [args.scenario]
    completed = True

    for scenario_id in scenario_ids:
        report, report_path = await run_scenario(
            scenario_id,
            server_url = args.server_url,
            timeout_seconds = args.timeout_seconds,
            output_directory = args.output_directory,
            continue_pending = not args.no_continuation
        )
        measurements = report["measurements"]
        print()
        print(f"scenario: {scenario_id}")
        print(f"report: {report_path}")
        print(f"sdk events: {measurements['sdk_event_count']}")
        print(
            "attack canaries in host output: "
            + ", ".join(measurements["attack_canaries_reaching_host_output"])
            if measurements["attack_canaries_reaching_host_output"]
            else "attack canaries in host output: none"
        )
        print(f"pending handles overwritten: {measurements['pending_handles_overwritten']}")
        print(
            "continuation used Task B handles: "
            f"{measurements['continuation_sent_with_task_b_handles']}"
        )
        print(f"operational error: {measurements['operational_error']}")
        print(f"run completed: {measurements['run_completed']}")
        completed = completed and measurements["run_completed"]

    return completed


def main() -> None:
    args = _parse_args()
    if not asyncio.run(_run_from_args(args)):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
