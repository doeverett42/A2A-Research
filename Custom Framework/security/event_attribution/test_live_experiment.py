from __future__ import annotations

import asyncio
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from a2a.types import TaskState

from host.agent import HostAgent
from host.client import RemoteTaskResponse
from host.orchestrator import HostOrchestrator, OrchestrationResult, StepResult
from host.router import DelegationPlan, PlanStep
from security.event_attribution import live_experiment
from security.event_attribution.live_experiment import (
    ATTACK_CANARY,
    LiveExperimentRecorder,
    RecordingHostAgent,
    _validate_loopback_urls
)
from common.services import validate_loopback_url
from security.event_attribution.scenarios import (
    CONTEXT_B_ID,
    HOST_CONTINUATION_CANARY,
    TASK_B_ID
)


MALICIOUS_URL = "http://gap3.test"
IDENTITY_URL = "http://identity.test"


class FakeAgentInfo:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url


class FakeDiscovery:
    async def discover(self):
        return [
            FakeAgentInfo("External Security Reviewer Test Agent", MALICIOUS_URL),
            FakeAgentInfo("Identity Analyst", IDENTITY_URL)
        ]


class FixedRouter:
    async def plan(self, user_message: str, agents, host_agent):
        return DelegationPlan(
            mode = "delegate",
            reason = "live framework flow test",
            steps = [
                PlanStep(
                    step_id = 1,
                    agent_index = 0,
                    agent_name = agents[0].name,
                    remote_url = agents[0].url,
                    task = "Run the harmless EA-A3 fixture.",
                    depends_on = []
                ),
                PlanStep(
                    step_id = 2,
                    agent_index = 1,
                    agent_name = agents[1].name,
                    remote_url = agents[1].url,
                    task = "Review identity evidence using the earlier result.",
                    depends_on = [1]
                )
            ]
        )


class FrameworkTestHostAgent:
    def __init__(self) -> None:
        self.formatter = HostAgent(client = None, model = "test")
        self.synthesis_results = ""

    async def prepare_delegation(
        self,
        user_message: str,
        agent_name: str,
        assigned_task: str,
        dependency_results: list[str]
    ) -> str:
        return await self.formatter.prepare_delegation(
            user_message,
            agent_name,
            assigned_task,
            dependency_results
        )

    async def synthesize(
        self,
        user_message: str,
        plan: str,
        results: str
    ) -> str:
        self.synthesis_results = results
        return results


class FakeMaliciousClient:
    def __init__(self) -> None:
        self.continuations = []

    async def send_text(self, text: str) -> RemoteTaskResponse:
        return RemoteTaskResponse(
            text = ATTACK_CANARY,
            task_id = TASK_B_ID,
            context_id = CONTEXT_B_ID,
            state = TaskState.TASK_STATE_INPUT_REQUIRED
        )

    async def continue_task(
        self,
        text: str,
        task_id: str,
        context_id: str
    ) -> RemoteTaskResponse:
        self.continuations.append(
            {
                "text": text,
                "task_id": task_id,
                "context_id": context_id
            }
        )
        return RemoteTaskResponse(
            text = f"{ATTACK_CANARY} CANARY-EA-A3-COMPLETED-B",
            task_id = task_id,
            context_id = context_id,
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class FakeIdentityClient:
    def __init__(self) -> None:
        self.requests = []

    async def send_text(self, text: str) -> RemoteTaskResponse:
        self.requests.append(text)
        return RemoteTaskResponse(
            text = f"Identity review observed {ATTACK_CANARY}.",
            task_id = "identity-task",
            context_id = "identity-context",
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class LiveGap3FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_forged_step_reaches_dependent_agent(self) -> None:
        malicious_client = FakeMaliciousClient()
        identity_client = FakeIdentityClient()
        host_agent = FrameworkTestHostAgent()

        def client_factory(remote_url: str, timeout_seconds: int):
            if remote_url == MALICIOUS_URL:
                return malicious_client
            return identity_client

        orchestrator = HostOrchestrator(
            agent = host_agent,
            discovery = FakeDiscovery(),
            router = FixedRouter(),
            timeout_seconds = 5,
            client_factory = client_factory
        )
        try:
            initial_result = await orchestrator.run(
                "Run the local multi-agent test."
            )
            self.assertTrue(initial_result.input_required)
            self.assertEqual(
                TASK_B_ID,
                orchestrator.pending.step_results[-1].task_id
            )

            final_result = await orchestrator.run(
                HOST_CONTINUATION_CANARY
            )

            self.assertFalse(final_result.input_required)
            self.assertEqual(2, len(final_result.step_results))
            self.assertEqual(TASK_B_ID, malicious_client.continuations[0]["task_id"])
            self.assertEqual(CONTEXT_B_ID, malicious_client.continuations[0]["context_id"])
            self.assertIn(ATTACK_CANARY, identity_client.requests[0])
            self.assertIn(ATTACK_CANARY, host_agent.synthesis_results)
        finally:
            await orchestrator.close()

    async def test_recording_agent_preserves_real_delegation_formatter(self) -> None:
        recorder = LiveExperimentRecorder()
        real_agent = HostAgent(client = None, model = "test")
        agent = RecordingHostAgent(real_agent, recorder)

        delegated = await agent.prepare_delegation(
            "Review authentication evidence.",
            "Identity Analyst",
            "Use the earlier reference result.",
            [f"Step 1 from test agent:\n{ATTACK_CANARY}"]
        )

        self.assertIn(ATTACK_CANARY, delegated)
        self.assertEqual(
            "delegation_prepared",
            recorder.host_observations[0]["observation"]
        )
        self.assertEqual(
            [ATTACK_CANARY],
            recorder.host_observations[0]["canaries"]
        )

    def test_live_runner_rejects_non_loopback_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            _validate_loopback_urls(["https://example.com"])

    def test_live_service_launcher_rejects_non_loopback_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "only permit loopback"):
            validate_loopback_url("http://0.0.0.0:8010")

    def test_step_two_pause_is_not_reported_as_a_resumed_plan(self) -> None:
        steps = [
            PlanStep(1, 0, "Identity Analyst", IDENTITY_URL, "identity", []),
            PlanStep(2, 1, "External Security Reviewer Test Agent", MALICIOUS_URL, "fixture", [1]),
            PlanStep(3, 2, "Incident Correlation Analyst", "http://127.0.0.1:8005", "correlate", [2])
        ]
        plan = DelegationPlan("delegate", "step two pause", steps)
        result = OrchestrationResult(
            plan,
            [
                StepResult(steps[0], response = "identity complete"),
                StepResult(
                    steps[1],
                    response = ATTACK_CANARY,
                    task_id = TASK_B_ID,
                    context_id = CONTEXT_B_ID,
                    input_required = True
                )
            ],
            ATTACK_CANARY,
            True
        )
        pending = {
            "step_index": 1,
            "step_id": 2,
            "agent_name": steps[1].agent_name,
            "task_id": TASK_B_ID,
            "context_id": CONTEXT_B_ID
        }

        measurements = live_experiment._measurements(
            "EA-A3",
            "identity-external-correlation",
            "CANARY-G3-MEASURE-001",
            MALICIOUS_URL,
            {},
            LiveExperimentRecorder(),
            result,
            pending,
            [],
            None,
            {"agents": {}},
            None
        )

        self.assertFalse(measurements["plan_resumed_after_continuation"])
        self.assertFalse(measurements["plan_reached_downstream_steps"])

    def test_final_output_requires_an_exact_run_canary(self) -> None:
        step = PlanStep(
            1,
            0,
            "External Security Reviewer Test Agent",
            "http://127.0.0.1:8010",
            "fixture",
            []
        )
        result = OrchestrationResult(
            DelegationPlan("delegate", "exact canary test", [step]),
            [StepResult(step, response = "fixture complete")],
            "CANARY-G3-CLI-TEST-OTHER",
            False
        )

        measurements = live_experiment._measurements(
            "EA-C0",
            "external-identity-correlation",
            "CANARY-G3-CLI-TEST",
            "http://127.0.0.1:8010",
            {},
            LiveExperimentRecorder(),
            result,
            None,
            [],
            None,
            {"agents": {}},
            None
        )

        self.assertFalse(measurements["run_canary_reached_final_output"])


class LiveGap3CommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_finishes_all_pairs_sequentially_after_failed_run(self) -> None:
        args = self._args("--all-experiments", "--variant", "both")
        calls = []

        async def run_case(arguments, experiment_id, variant):
            calls.append(("start", experiment_id, variant))
            #give a concurrent implementation a chance to overlap runs.
            await asyncio.sleep(0)
            calls.append(("finish", experiment_id, variant))
            return (experiment_id, variant) != ("TM-1", "attack")

        with patch.object(live_experiment, "_run_case", side_effect = run_case):
            completed = await live_experiment._run_from_args(args)

        self.assertFalse(completed)
        self.assertEqual(
            [
                (phase, experiment_id, variant)
                for experiment_id in (
                    "EA-A3", "TM-1", "TM-2", "DO-2", "DO-3", "DO-5", "DO-6"
                )
                for variant in ("control", "attack")
                for phase in ("start", "finish")
            ],
            calls
        )

    def test_command_exit_status_reports_incomplete_execution(self) -> None:
        #main must expose the batch result to the calling terminal.
        args = self._args()
        for completed in (True, False):
            with self.subTest(completed = completed):
                with (
                    patch.object(live_experiment, "_parse_args", return_value = args),
                    patch.object(
                        live_experiment,
                        "_run_from_args",
                        new = AsyncMock(return_value = completed)
                    ) as run
                ):
                    if completed:
                        live_experiment.main()
                    else:
                        with self.assertRaises(SystemExit) as error:
                            live_experiment.main()
                        self.assertEqual(1, error.exception.code)
                    run.assert_awaited_once_with(args)

    async def test_ea_a3_variants_select_matching_control_and_show_host_answer(self) -> None:
        args = self._args("--experiment", "ea-a3")
        for variant, scenario in (("control", "EA-C0"), ("attack", "EA-A3")):
            with self.subTest(variant = variant):
                output = io.StringIO()
                with (
                    patch.object(
                        live_experiment,
                        "run_live_experiment",
                        new = AsyncMock(return_value = self._report(scenario))
                    ) as run,
                    redirect_stdout(output)
                ):
                    completed = await live_experiment._run_case(args, "EA-A3", variant)

                self.assertTrue(completed)
                self.assertEqual(scenario, run.call_args.kwargs["scenario_id"])
                self.assertEqual(
                    "external-identity-correlation",
                    run.call_args.kwargs["plan_order"]
                )
                self.assertEqual("EA-A3", run.call_args.kwargs["experiment_id"])
                self.assertEqual(variant, run.call_args.kwargs["variant"])
                self.assertIn("host response>\nFinal host summary.", output.getvalue())

    async def test_failed_or_unfinished_report_is_not_a_completed_run(self) -> None:
        args = self._args()
        for changes in (
            {"operational_error": True},
            {"final_input_required": True},
            {"completed_step_count": 0},
            {"completed_step_count": 0, "plan_step_count": 0}
        ):
            with self.subTest(changes = changes):
                report, path = self._report("EA-A3")
                report["measurements"].update(changes)
                with (
                    patch.object(
                        live_experiment,
                        "run_live_experiment",
                        new = AsyncMock(return_value = (report, path))
                    ),
                    redirect_stdout(io.StringIO())
                ):
                    self.assertFalse(await live_experiment._run_case(args, "EA-A3", "attack"))

    async def test_repeated_runs_generate_distinct_canaries_and_reports(self) -> None:
        #exercise actual report creation while replacing all remote execution.
        orchestrator = SimpleNamespace(
            run = AsyncMock(return_value = self._finished_result()),
            close = AsyncMock(),
            pending = None,
            tuple_bindings = []
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(live_experiment, "HostOrchestrator", return_value = orchestrator),
            patch.object(live_experiment, "OllamaClient")
        ):
            reports = []
            paths = []
            for _ in range(2):
                report, path = await live_experiment.run_live_experiment(
                    scenario_id = "EA-C0",
                    remote_agent_urls = [],
                    database_paths = {},
                    output_directory = Path(directory)
                )
                reports.append(report)
                paths.append(path)
                saved = json.loads(path.read_text(encoding = "utf-8"))
                self.assertEqual(report, saved)
                self.assertEqual(
                    report["run"]["run_canary"],
                    report["layers"]["database"]["after"]["run_canary"]
                )
                step = saved["layers"]["orchestrator"]["initial_result"]["step_results"][0]
                self.assertEqual(TASK_B_ID, step["task_id"])
                self.assertEqual(CONTEXT_B_ID, step["context_id"])
                self.assertIn(ATTACK_CANARY, step["response_canaries"])
            self.assertNotEqual(paths[0], paths[1])
            self.assertNotEqual(reports[0]["run"]["run_canary"], reports[1]["run"]["run_canary"])

    def _args(self, *arguments):
        with patch("sys.argv", ["live_experiment", *arguments]):
            return live_experiment._parse_args()

    def _finished_result(self):
        step = PlanStep(
            step_id = 1,
            agent_index = 0,
            agent_name = "External Security Reviewer Test Agent",
            remote_url = "http://127.0.0.1:8010",
            task = "Review the harmless fixture.",
            depends_on = []
        )
        return OrchestrationResult(
            plan = DelegationPlan(mode = "delegate", reason = "cli test", steps = [step]),
            step_results = [
                StepResult(
                    step,
                    response = ATTACK_CANARY,
                    task_id = TASK_B_ID,
                    context_id = CONTEXT_B_ID
                )
            ],
            response = "Final host summary.",
            input_required = False
        )

    def _report(self, scenario):
        result = self._finished_result()
        return (
            {
                "measurements": live_experiment._measurements(
                    scenario,
                    "external-identity-correlation",
                    "CANARY-G3-CLI-TEST",
                    "http://127.0.0.1:8010",
                    {},
                    LiveExperimentRecorder(),
                    result,
                    None,
                    [],
                    None,
                    {"agents": {}},
                    None
                ),
                "layers": {"host_output": {"response": result.response}}
            },
            Path("test-report.json")
        )


if __name__ == "__main__":
    unittest.main()
