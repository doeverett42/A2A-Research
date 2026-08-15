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
    BUDGET_AGENT_NAME,
    FOOD_AGENT_NAME,
    FixedPlanRouter,
    follow_up_case,
    follow_up_catalog,
    plan_order_catalog
)
from security.event_attribution.live_experiment import _run_canary
from security.event_attribution.scenarios import (
    CONTEXT_B_ID,
    TASK_B_ID
)
from security.event_attribution.server import AGENT_NAME


MALICIOUS_URL = "http://gap3.test"
FOOD_URL = "http://food.test"
BUDGET_URL = "http://budget.test"
RUN_CANARY = "CANARY-G3-ORDER-TEST-001"


class FakeAgentInfo:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url


class FakeDiscovery:
    async def discover(self):
        return [
            FakeAgentInfo(AGENT_NAME, MALICIOUS_URL),
            FakeAgentInfo(FOOD_AGENT_NAME, FOOD_URL),
            FakeAgentInfo(BUDGET_AGENT_NAME, BUDGET_URL)
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
            "malicious-first": (
                [AGENT_NAME, FOOD_AGENT_NAME, BUDGET_AGENT_NAME],
                [[], [1], [2]]
            ),
            "food-malicious-budget": (
                [FOOD_AGENT_NAME, AGENT_NAME, BUDGET_AGENT_NAME],
                [[], [1], [2]]
            ),
            "food-malicious-budget-independent": (
                [FOOD_AGENT_NAME, AGENT_NAME, BUDGET_AGENT_NAME],
                [[], [], [1]]
            ),
            "malicious-fanout": (
                [AGENT_NAME, FOOD_AGENT_NAME, BUDGET_AGENT_NAME],
                [[], [1], [1]]
            ),
            "food-malicious-food": (
                [FOOD_AGENT_NAME, AGENT_NAME, FOOD_AGENT_NAME],
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

    def test_six_follow_up_codes_select_expected_cases(self) -> None:
        expected = {
            "TM-1": ("EA-C2", "EA-TM1", "malicious-first"),
            "TM-2": ("EA-C2", "EA-TM2", "malicious-first"),
            "DO-2": ("EA-C0", "EA-A3", "food-malicious-budget"),
            "DO-3": (
                "EA-C0",
                "EA-A3",
                "food-malicious-budget-independent"
            ),
            "DO-5": ("EA-C0", "EA-A3", "malicious-fanout"),
            "DO-6": ("EA-C0", "EA-A3", "food-malicious-food")
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

    async def test_do_2_passes_malicious_result_to_budget(self) -> None:
        clients, result_before, result_after, calls_before = await self._run_order(
            "food-malicious-budget"
        )

        self.assertTrue(result_before.input_required)
        self.assertEqual(0, calls_before[BUDGET_URL])
        self.assertFalse(result_after.input_required)
        self.assertIn(RUN_CANARY, clients[BUDGET_URL].requests[0])

    async def test_do_3_blocks_budget_but_keeps_its_input_clean(self) -> None:
        clients, result_before, result_after, calls_before = await self._run_order(
            "food-malicious-budget-independent"
        )

        self.assertTrue(result_before.input_required)
        self.assertEqual(0, calls_before[BUDGET_URL])
        self.assertFalse(result_after.input_required)
        self.assertNotIn(RUN_CANARY, clients[BUDGET_URL].requests[0])

    async def test_do_5_passes_one_result_to_both_remote_agents(self) -> None:
        clients, _, _, _ = await self._run_order("malicious-fanout")

        self.assertIn(RUN_CANARY, clients[FOOD_URL].requests[0])
        self.assertIn(RUN_CANARY, clients[BUDGET_URL].requests[0])

    async def test_do_6_separates_food_before_and_after_requests(self) -> None:
        clients, _, _, _ = await self._run_order("food-malicious-food")
        food_requests = clients[FOOD_URL].requests

        self.assertEqual(2, len(food_requests))
        self.assertNotIn(RUN_CANARY, food_requests[0])
        self.assertIn(RUN_CANARY, food_requests[1])

    async def _run_order(self, plan_order: str):
        clients = {
            MALICIOUS_URL: FakeMaliciousClient(),
            FOOD_URL: FakeRemoteAgentClient("Food"),
            BUDGET_URL: FakeRemoteAgentClient("Budget")
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
            paths = {FOOD_AGENT_NAME: database_path}
            baseline = snapshot_task_ids(paths)
            self._insert_task(
                database_path,
                "test-task",
                json.dumps([{"parts": [{"text": RUN_CANARY}]}])
            )

            evidence = database_evidence(paths, baseline, RUN_CANARY)
            food_evidence = evidence["agents"][FOOD_AGENT_NAME]

            self.assertEqual(1, food_evidence["new_task_count"])
            self.assertEqual("test-task", food_evidence["new_rows"][0]["task_id"])
            self.assertEqual(
                ["history"],
                food_evidence["new_rows"][0]["run_canary_columns"]
            )
            self.assertNotIn(
                "clean-task",
                [row["task_id"] for row in food_evidence["new_rows"]]
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
