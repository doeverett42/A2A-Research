from __future__ import annotations

import unittest

from a2a.types import TaskState

from host.agent import HostAgent
from host.client import RemoteTaskResponse
from host.orchestrator import HostOrchestrator
from host.router import DelegationPlan, PlanStep
from security.event_attribution.live_experiment import (
    ATTACK_CANARY,
    LiveExperimentRecorder,
    RecordingHostAgent,
    _validate_loopback_urls
)
from security.event_attribution.live_services import _validate_loopback_url
from security.event_attribution.scenarios import (
    CONTEXT_B_ID,
    HOST_CONTINUATION_CANARY,
    TASK_B_ID
)


MALICIOUS_URL = "http://gap3.test"
FOOD_URL = "http://food.test"


class FakeAgentInfo:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url


class FakeDiscovery:
    async def discover(self):
        return [
            FakeAgentInfo("Gap 3 Malicious Event Server", MALICIOUS_URL),
            FakeAgentInfo("Food Agent", FOOD_URL)
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
                    task = "Create a sample menu from the earlier result.",
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


class FakeFoodClient:
    def __init__(self) -> None:
        self.requests = []

    async def send_text(self, text: str) -> RemoteTaskResponse:
        self.requests.append(text)
        return RemoteTaskResponse(
            text = f"Sample menu observed {ATTACK_CANARY}.",
            task_id = "food-task",
            context_id = "food-context",
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class LiveGap3FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_forged_step_reaches_dependent_agent(self) -> None:
        malicious_client = FakeMaliciousClient()
        food_client = FakeFoodClient()
        host_agent = FrameworkTestHostAgent()

        def client_factory(remote_url: str, timeout_seconds: int):
            if remote_url == MALICIOUS_URL:
                return malicious_client
            return food_client

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
            self.assertIn(ATTACK_CANARY, food_client.requests[0])
            self.assertIn(ATTACK_CANARY, host_agent.synthesis_results)
        finally:
            await orchestrator.close()

    async def test_recording_agent_preserves_real_delegation_formatter(self) -> None:
        recorder = LiveExperimentRecorder()
        real_agent = HostAgent(client = None, model = "test")
        agent = RecordingHostAgent(real_agent, recorder)

        delegated = await agent.prepare_delegation(
            "Create a sample menu.",
            "Food Agent",
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
        with self.assertRaisesRegex(ValueError, "only permits loopback"):
            _validate_loopback_urls(["https://example.com"])

    def test_live_service_launcher_rejects_non_loopback_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "only permit loopback"):
            _validate_loopback_url("http://0.0.0.0:8010")


if __name__ == "__main__":
    unittest.main()
