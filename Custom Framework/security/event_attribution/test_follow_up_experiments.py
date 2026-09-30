from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from a2a.types import TaskState

from host.agent import HostAgent
from host.client import RemoteTaskResponse
from host.orchestrator import HostOrchestrator
from security.event_attribution.database_evidence import (
    database_evidence,
    snapshot_task_ids
)
from security.event_attribution.fixed_plans import (
    CORRELATION_AGENT_NAME,
    IDENTITY_AGENT_NAME,
    FixedPlanRouter,
    follow_up_case,
    follow_up_catalog,
    plan_order_catalog
)
from security.event_attribution.live_experiment import (
    _database_canary_matches,
    _run_canary
)
from security.event_attribution.scenarios import (
    CONTEXT_B_ID,
    TASK_B_ID
)
from security.event_attribution.server import AGENT_NAME


MALICIOUS_URL = "http://127.0.0.1:8010"
IDENTITY_URL = "http://127.0.0.1:8001"
CORRELATION_URL = "http://127.0.0.1:8005"
RUN_CANARY = "CANARY-G3-ORDER-TEST-001"


class FakeAgentInfo:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url


class FakeDiscovery:
    async def discover(self):
        return [
            FakeAgentInfo(AGENT_NAME, MALICIOUS_URL),
            FakeAgentInfo(IDENTITY_AGENT_NAME, IDENTITY_URL),
            FakeAgentInfo(CORRELATION_AGENT_NAME, CORRELATION_URL)
        ]


class FormatterHostAgent:
    def __init__(self) -> None:
        self.formatter = HostAgent(client = None, model = "test")

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
        return results


class FakeMaliciousClient:
    def __init__(self) -> None:
        self.continuations = []

    async def send_text(self, text: str) -> RemoteTaskResponse:
        return RemoteTaskResponse(
            text = f"Harmless fixture waiting. {RUN_CANARY}",
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
        self.continuations.append((task_id, context_id))
        return RemoteTaskResponse(
            text = f"Harmless fixture completed. {RUN_CANARY}",
            task_id = task_id,
            context_id = context_id,
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class FakeRemoteAgentClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.requests = []

    async def send_text(self, text: str) -> RemoteTaskResponse:
        self.requests.append(text)
        request_number = len(self.requests)
        return RemoteTaskResponse(
            text = f"{self.name} harmless result {request_number}.",
            task_id = f"{self.name.lower()}-task-{request_number}",
            context_id = f"{self.name.lower()}-context-{request_number}",
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class FixedPlanTests(unittest.IsolatedAsyncioTestCase):
    async def test_plan_orders_have_expected_agents_and_dependencies(self) -> None:
        expected = {
            "external-identity-correlation": (
                [AGENT_NAME, IDENTITY_AGENT_NAME, CORRELATION_AGENT_NAME],
                [[], [1], [2]]
            ),
            "identity-external-correlation": (
                [IDENTITY_AGENT_NAME, AGENT_NAME, CORRELATION_AGENT_NAME],
                [[], [1], [2]]
            ),
            "identity-external-correlation-independent": (
                [IDENTITY_AGENT_NAME, AGENT_NAME, CORRELATION_AGENT_NAME],
                [[], [], [1]]
            ),
            "external-fanout": (
                [AGENT_NAME, IDENTITY_AGENT_NAME, CORRELATION_AGENT_NAME],
                [[], [1], [1]]
            ),
            "identity-external-identity": (
                [IDENTITY_AGENT_NAME, AGENT_NAME, IDENTITY_AGENT_NAME],
                [[], [1], [2]]
            )
        }
        agents = await FakeDiscovery().discover()

        self.assertEqual(set(expected), set(plan_order_catalog()))
        for plan_order, (agent_names, dependencies) in expected.items():
            with self.subTest(plan_order = plan_order):
                plan = await FixedPlanRouter(
                    plan_order,
                    "EA-A3"
                ).plan("test", agents, None)
                self.assertEqual(
                    agent_names,
                    [step.agent_name for step in plan.steps]
                )
                self.assertEqual(
                    dependencies,
                    [step.depends_on for step in plan.steps]
                )

    async def test_fixed_plan_rejects_non_loopback_card_url(self) -> None:
        agents = await FakeDiscovery().discover()
        agents[0].url = "https://example.com"

        with self.assertRaisesRegex(ValueError, "loopback"):
            await FixedPlanRouter(
                "external-identity-correlation",
                "EA-A3"
            ).plan("test", agents, None)

    def test_six_follow_up_codes_select_expected_cases(self) -> None:
        expected = {
            "TM-1": ("EA-C2", "EA-TM1", "external-identity-correlation"),
            "TM-2": ("EA-C2", "EA-TM2", "external-identity-correlation"),
            "DO-2": ("EA-C0", "EA-A3", "identity-external-correlation"),
            "DO-3": (
                "EA-C0",
                "EA-A3",
                "identity-external-correlation-independent"
            ),
            "DO-5": ("EA-C0", "EA-A3", "external-fanout"),
            "DO-6": ("EA-C0", "EA-A3", "identity-external-identity")
        }

        self.assertEqual(set(expected), set(follow_up_catalog()))
        for experiment_id, values in expected.items():
            control_scenario, attack_scenario, plan_order = values
            with self.subTest(experiment = experiment_id):
                self.assertEqual(
                    (control_scenario, plan_order),
                    follow_up_case(experiment_id, "control")
                )
                self.assertEqual(
                    (attack_scenario, plan_order),
                    follow_up_case(experiment_id, "attack")
                )
                self.assertTrue(
                    _run_canary(
                        experiment_id,
                        None,
                        "gap3-live-test-ABCDEF12"
                    ).startswith(
                        f"CANARY-G3-{experiment_id.replace('-', '')}-"
                    )
                )

    async def test_do_2_passes_external_result_to_correlation(self) -> None:
        clients, result_before, result_after, calls_before = await self._run_order(
            "identity-external-correlation"
        )

        self.assertTrue(result_before.input_required)
        self.assertEqual(0, calls_before[CORRELATION_URL])
        self.assertFalse(result_after.input_required)
        self.assertIn(RUN_CANARY, clients[CORRELATION_URL].requests[0])

    async def test_do_3_blocks_correlation_but_keeps_its_input_clean(self) -> None:
        clients, result_before, result_after, calls_before = await self._run_order(
            "identity-external-correlation-independent"
        )

        self.assertTrue(result_before.input_required)
        self.assertEqual(0, calls_before[CORRELATION_URL])
        self.assertFalse(result_after.input_required)
        self.assertNotIn(RUN_CANARY, clients[CORRELATION_URL].requests[0])

    async def test_do_5_passes_one_result_to_both_remote_agents(self) -> None:
        clients, _, _, _ = await self._run_order("external-fanout")

        self.assertIn(RUN_CANARY, clients[IDENTITY_URL].requests[0])
        self.assertIn(RUN_CANARY, clients[CORRELATION_URL].requests[0])

    async def test_do_6_separates_identity_before_and_after_requests(self) -> None:
        clients, _, _, _ = await self._run_order("identity-external-identity")
        identity_requests = clients[IDENTITY_URL].requests

        self.assertEqual(2, len(identity_requests))
        self.assertNotIn(RUN_CANARY, identity_requests[0])
        self.assertIn(RUN_CANARY, identity_requests[1])

    async def _run_order(self, plan_order: str):
        clients = {
            MALICIOUS_URL: FakeMaliciousClient(),
            IDENTITY_URL: FakeRemoteAgentClient("Identity"),
            CORRELATION_URL: FakeRemoteAgentClient("Correlation")
        }
        orchestrator = HostOrchestrator(
            agent = FormatterHostAgent(),
            discovery = FakeDiscovery(),
            router = FixedPlanRouter(plan_order, "EA-A3"),
            timeout_seconds = 5,
            client_factory = lambda remote_url, timeout: clients[remote_url]
        )
        try:
            result_before = await orchestrator.run("Harmless local test.")
            calls_before = {
                remote_url: len(getattr(client, "requests", []))
                for remote_url, client in clients.items()
            }
            result_after = await orchestrator.run("Harmless continuation.")
            return clients, result_before, result_after, calls_before
        finally:
            await orchestrator.close()


class DatabaseEvidenceTests(unittest.TestCase):
    def test_only_new_rows_are_searched_for_the_run_canary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote_agent_0.db"
            self._create_database(database_path)
            self._insert_task(database_path, "clean-task", "[]")
            paths = {IDENTITY_AGENT_NAME: database_path}
            baseline = snapshot_task_ids(paths)
            self._insert_task(
                database_path,
                "test-task",
                json.dumps([{"parts": [{"text": RUN_CANARY}]}])
            )

            evidence = database_evidence(paths, baseline, RUN_CANARY)
            identity_evidence = evidence["agents"][IDENTITY_AGENT_NAME]

            self.assertEqual(1, identity_evidence["new_task_count"])
            self.assertEqual("test-task", identity_evidence["new_rows"][0]["task_id"])
            self.assertEqual(
                ["history"],
                identity_evidence["new_rows"][0]["run_canary_columns"]
            )
            self.assertNotIn(
                "clean-task",
                [row["task_id"] for row in identity_evidence["new_rows"]]
            )

    def test_run_canary_matching_requires_the_exact_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote_agent_0.db"
            self._create_database(database_path)
            paths = {IDENTITY_AGENT_NAME: database_path}
            baseline = snapshot_task_ids(paths)
            self._insert_task(
                database_path,
                "longer-canary-task",
                json.dumps(
                    [{"parts": [{"text": f"{RUN_CANARY}-OTHER"}]}]
                )
            )

            evidence = database_evidence(paths, baseline, RUN_CANARY)
            row = evidence["agents"][IDENTITY_AGENT_NAME]["new_rows"][0]

            self.assertFalse(row["contains_run_canary"])
            self.assertEqual([], row["run_canary_columns"])

    def test_case_evidence_canary_is_included_in_database_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "remote_agent_0.db"
            self._create_database(database_path)
            paths = {IDENTITY_AGENT_NAME: database_path}
            baseline = snapshot_task_ids(paths)
            self._insert_task(database_path, "case-task", "[]")
            self._insert_case_evidence(
                database_path,
                "case-task",
                json.dumps([RUN_CANARY])
            )

            evidence = database_evidence(paths, baseline, RUN_CANARY)
            matches = _database_canary_matches(evidence)

            self.assertEqual(1, len(matches))
            self.assertEqual("case_evidence", matches[0]["source"])
            self.assertEqual("case-task", matches[0]["task_id"])
            self.assertEqual(
                ["request_canaries"],
                matches[0]["columns"]
            )

    def _create_database(self, path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                CREATE TABLE tasks (
                    id TEXT PRIMARY KEY,
                    context_id TEXT,
                    last_updated TEXT,
                    status TEXT,
                    history TEXT,
                    artifacts TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE case_evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT,
                    stage TEXT,
                    agent_name TEXT,
                    message_id TEXT,
                    task_id TEXT,
                    context_id TEXT,
                    case_label TEXT,
                    packet_hash TEXT,
                    evidence_group TEXT,
                    request_canaries TEXT,
                    response_canaries TEXT
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _insert_case_evidence(
        self,
        path: Path,
        task_id: str,
        request_canaries: str
    ) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                INSERT INTO case_evidence (
                    recorded_at, stage, agent_name, message_id, task_id,
                    context_id, case_label, packet_hash, evidence_group,
                    request_canaries, response_canaries
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "2026-08-10T00:00:00Z",
                    "completed",
                    IDENTITY_AGENT_NAME,
                    "message-1",
                    task_id,
                    f"{task_id}-context",
                    "CYBER-SANDBOX-A",
                    "a" * 64,
                    "identity",
                    request_canaries,
                    "[]"
                )
            )
            connection.commit()
        finally:
            connection.close()

    def _insert_task(
        self,
        path: Path,
        task_id: str,
        history: str
    ) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                """
                INSERT INTO tasks (
                    id, context_id, last_updated, status, history, artifacts
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    f"{task_id}-context",
                    "2026-08-10T00:00:00Z",
                    "{}",
                    history,
                    "[]"
                )
            )
            connection.commit()
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
