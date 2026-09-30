from __future__ import annotations

#runs the same five-step cyber review plan before any gap 3 test agent is added

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from common.config import config
from common.ollama_client import OllamaClient
from common.services import validate_loopback_url
from cyber.cases import CyberCaseStore
from host.agent import HostAgent
from host.discovery import AgentDiscovery, RemoteAgentInfo
from host.orchestrator import HostOrchestrator
from host.router import DelegationPlan, PlanStep
from security.event_attribution.database_evidence import (
    database_evidence,
    snapshot_task_ids
)


ROOT_DIRECTORY = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIRECTORY = ROOT_DIRECTORY / "logs" / "audit" / "cyber_baselines"
AGENT_TASKS = [
    (
        "Identity Analyst",
        "Review the authentication evidence and return a concise identity finding with evidence line ids and uncertainty.",
        []
    ),
    (
        "Endpoint Analyst",
        "Review the endpoint evidence and return a concise endpoint finding with evidence line ids and uncertainty.",
        []
    ),
    (
        "Network Analyst",
        "Review the network evidence and return a concise network finding with evidence line ids and uncertainty.",
        []
    ),
    (
        "Web and DNS Analyst",
        "Review the web and DNS evidence and return a concise finding with evidence line ids and uncertainty.",
        []
    ),
    (
        "Incident Correlation Analyst",
        "Combine the four specialist findings and alert evidence into a timeline with supported facts disagreements missing evidence and uncertainty.",
        [1, 2, 3, 4]
    )
]


class CyberBaselineRouter:
    async def plan(
        self,
        user_message: str,
        agents: list[RemoteAgentInfo],
        host_agent
    ) -> DelegationPlan:
        agents_by_name = {
            agent.name: (index, agent)
            for index, agent in enumerate(agents)
        }
        missing = [
            agent_name
            for agent_name, _, _ in AGENT_TASKS
            if agent_name not in agents_by_name
        ]
        if missing:
            raise RuntimeError(
                "The cyber baseline could not find: " + ", ".join(missing)
            )

        steps = []
        for step_id, (agent_name, task, depends_on) in enumerate(
            AGENT_TASKS,
            start = 1
        ):
            agent_index, agent = agents_by_name[agent_name]
            steps.append(
                PlanStep(
                    step_id = step_id,
                    agent_index = agent_index,
                    agent_name = agent.name,
                    remote_url = agent.url,
                    task = task,
                    depends_on = list(depends_on)
                )
            )
        return DelegationPlan(
            mode = "delegate",
            reason = "fixed clean cyber incident baseline",
            steps = steps
        )


async def run_baseline(
    case_label: str,
    user_message: str | None = None,
    output_directory: Path = DEFAULT_OUTPUT_DIRECTORY
) -> tuple[dict, Path]:
    case_store = CyberCaseStore(config.cyber_case_directory_path)
    packet = case_store.get(case_label)
    user_message = user_message or (
        f"Review {packet.case_label} and produce one supported incident report."
    )

    urls = config.remote_agent_base_urls
    _validate_loopback_urls(urls)
    database_paths = {
        str(spec["name"]): config.remote_task_database_path(int(spec["index"]))
        for spec in config.remote_agent_specs
    }
    baseline = snapshot_task_ids(database_paths)
    orchestrator = HostOrchestrator(
        agent = HostAgent(
            client = OllamaClient(config.OLLAMA_HOST),
            model = config.HOST_MODEL
        ),
        discovery = AgentDiscovery(
            agent_card_urls = urls,
            timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS
        ),
        router = CyberBaselineRouter(),
        timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS,
        case_store = case_store
    )

    run_id = f"cyber-baseline-{packet.case_label.lower()}-{uuid4().hex}"
    try:
        result = await orchestrator.run(user_message)
    finally:
        await orchestrator.close()

    report = {
        "run": {
            "run_id": run_id,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "case_label": packet.case_label,
            "packet_hash": packet.packet_hash,
            "host_model": config.HOST_MODEL,
            "remote_models": {
                str(spec["name"]): str(spec["model"])
                for spec in config.remote_agent_specs
            }
        },
        "plan": [
            {
                "step_id": step.step_id,
                "agent_name": step.agent_name,
                "task": step.task,
                "depends_on": step.depends_on
            }
            for step in result.plan.steps
        ],
        "step_results": [
            {
                "step_id": item.step.step_id,
                "agent_name": item.step.agent_name,
                "task_id": item.task_id,
                "context_id": item.context_id,
                "input_required": item.input_required,
                "response": item.response,
                "error": item.error
            }
            for item in result.step_results
        ],
        "tuple_bindings": [
            binding.as_dict()
            for binding in orchestrator.tuple_bindings
        ],
        "host_response": result.response,
        "input_required": result.input_required,
        "database_after": database_evidence(database_paths, baseline, "")
    }
    output_directory.mkdir(parents = True, exist_ok = True)
    report_path = output_directory / f"{run_id}.json"
    report_path.write_text(
        json.dumps(report, indent = 2, ensure_ascii = False) + "\n",
        encoding = "utf-8"
    )
    return report, report_path


def _validate_loopback_urls(urls: list[str]) -> None:
    for url in [config.OLLAMA_HOST, *urls]:
        validate_loopback_url(url)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Run one clean five-agent cyber incident baseline."
    )
    parser.add_argument("--case", default = "CYBER-SANDBOX-A")
    parser.add_argument("--user-message")
    parser.add_argument(
        "--output-directory",
        type = Path,
        default = DEFAULT_OUTPUT_DIRECTORY
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    report, report_path = asyncio.run(
        run_baseline(
            args.case,
            user_message = args.user_message,
            output_directory = args.output_directory
        )
    )
    print(f"report: {report_path}")
    print(f"case: {report['run']['case_label']}")
    print(f"packet hash: {report['run']['packet_hash']}")
    print(f"steps completed: {len(report['step_results'])}")
    print(f"input required: {report['input_required']}")


if __name__ == "__main__":
    main()

