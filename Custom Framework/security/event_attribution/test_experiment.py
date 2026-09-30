from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, patch

from a2a.types import AgentCapabilities, AgentCard, AgentInterface, TaskState

from host.client import RemoteAgentClient, RemoteTaskResponse
from host.orchestrator import HostOrchestrator
from security.event_attribution.experiment import (
    DEFAULT_USER_MESSAGE,
    DeterministicHostAgent,
    DeterministicRouter,
    ExperimentRecorder,
    _measurements,
    run_scenario
)
from security.event_attribution.reporting import (
    pending_snapshot,
    result_snapshot,
    transport_requests
)
from security.event_attribution.scenarios import (
    CONTEXT_A_ID,
    CONTEXT_B_ID,
    TASK_A_ID,
    TASK_B_ID,
    build_scenario
)


class FakeSdkClient:
    def __init__(self, events) -> None:
        self.events = events
        self.contexts = []
        self.closed = False

    async def send_message(self, request, context = None):
        self.contexts.append(context)
        for event in self.events:
            yield event

    async def close(self) -> None:
        self.closed = True


class FakeAgentInfo:
    def __init__(self, url: str) -> None:
        self.name = "External Security Reviewer Test Agent"
        self.url = url
        self.card = AgentCard(
            name = self.name,
            description = "deterministic test card",
            version = "1.0.0",
            capabilities = AgentCapabilities(streaming = True),
            supported_interfaces = [
                AgentInterface(
                    protocol_binding = "JSONRPC",
                    url = url,
                    protocol_version = "1.0"
                )
            ],
            default_input_modes = ["text/plain"],
            default_output_modes = ["text/plain"]
        )


class FakeDiscovery:
    def __init__(self, agent: FakeAgentInfo) -> None:
        self.agent = agent

    async def discover(self):
        return [self.agent]


class FakeRemoteClient:
    def __init__(self) -> None:
        self.continuations = []
        self.closed = False

    async def send_text(self, text: str) -> RemoteTaskResponse:
        return RemoteTaskResponse(
            text = "002 CANARY-FORGED-INPUT-B",
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
        return await self.send_text(text)

    async def close(self) -> None:
        self.closed = True


class Gap3ExperimentTests(unittest.IsolatedAsyncioTestCase):
    async def test_wrapper_rechecks_fresh_agent_card_url(self) -> None:
        external_card = FakeAgentInfo("https://example.com/a2a").card
        resolver = AsyncMock()
        resolver.get_agent_card.return_value = external_card
        client = RemoteAgentClient("http://127.0.0.1:8010", 5)

        with patch(
            "host.client.A2ACardResolver",
            return_value = resolver
        ):
            with self.assertRaisesRegex(ValueError, "loopback"):
                await client._get_client()

    async def test_streaming_wrapper_records_handle_overwrite(self) -> None:
        observations = []
        sdk_client = FakeSdkClient(build_scenario("EA-A3").events)
        client = RemoteAgentClient(
            "http://gap3.test",
            5,
            streaming = True,
            call_headers = {
                "X-A2A-Audit-ID": "gap3-test-audit"
            },
            event_observer = observations.append
        )
        client._client = sdk_client

        response = await client.send_text("EA-A3")

        self.assertEqual(TASK_B_ID, response.task_id)
        self.assertEqual(CONTEXT_B_ID, response.context_id)
        self.assertTrue(response.requires_input)

        wrapper_events = [
            item for item in observations
            if item["observation"] == "event_processed"
        ]
        self.assertEqual(TASK_A_ID, wrapper_events[0]["selected_task_id"])
        self.assertEqual(CONTEXT_A_ID, wrapper_events[0]["selected_context_id"])
        self.assertEqual(TASK_B_ID, wrapper_events[1]["selected_task_id"])
        self.assertEqual(CONTEXT_B_ID, wrapper_events[1]["selected_context_id"])
        self.assertEqual(
            "gap3-test-audit",
            sdk_client.contexts[0].service_parameters["X-A2A-Audit-ID"]
        )

    async def test_orchestrator_continues_with_forged_handles(self) -> None:
        recorder = ExperimentRecorder()
        agent = DeterministicHostAgent("EA-A3", recorder)
        router = DeterministicRouter("EA-A3", recorder)
        remote_client = FakeRemoteClient()

        def client_factory(remote_url: str, timeout_seconds: int):
            return remote_client

        orchestrator = HostOrchestrator(
            agent = agent,
            discovery = FakeDiscovery(FakeAgentInfo("http://127.0.0.1:8010")),
            router = router,
            timeout_seconds = 5,
            client_factory = client_factory
        )
        try:
            initial_result = await orchestrator.run(DEFAULT_USER_MESSAGE)

            self.assertTrue(initial_result.input_required)
            self.assertEqual(TASK_B_ID, orchestrator.pending.step_results[-1].task_id)
            self.assertEqual(CONTEXT_B_ID, orchestrator.pending.step_results[-1].context_id)

            #the shared report helpers must preserve the tuple the host used.
            pending = pending_snapshot(orchestrator.pending)
            result = result_snapshot(initial_result)
            for snapshot in (pending, result["step_results"][0]):
                self.assertEqual(TASK_B_ID, snapshot["task_id"])
                self.assertEqual(CONTEXT_B_ID, snapshot["context_id"])
                self.assertEqual("http://127.0.0.1:8010", snapshot["remote_url"])
                self.assertTrue(snapshot["input_required"])
                self.assertIn("CANARY-FORGED-INPUT-B", snapshot["response"])
                self.assertEqual(["CANARY-FORGED-INPUT-B"], snapshot["response_canaries"])
            self.assertEqual(initial_result.response, result["response"])

            continuation_result = await orchestrator.run(
                "CANARY-HOST-CONTINUATION"
            )
            pending_after_continuation = pending_snapshot(
                orchestrator.pending
            )

            self.assertEqual(TASK_B_ID, remote_client.continuations[0]["task_id"])
            self.assertEqual(CONTEXT_B_ID, remote_client.continuations[0]["context_id"])
            measurements = _measurements(
                "EA-A3",
                [],
                [],
                initial_result,
                continuation_result,
                pending,
                pending_after_continuation,
                [],
                None
            )
            self.assertTrue(measurements["continuation_attempted"])
            self.assertTrue(measurements["final_input_required"])
            self.assertFalse(measurements["run_completed"])
        finally:
            await orchestrator.close()

    async def test_router_rejects_non_loopback_agent_card_url(self) -> None:
        router = DeterministicRouter("EA-A3", ExperimentRecorder())

        with self.assertRaisesRegex(ValueError, "loopback"):
            await router.plan(
                DEFAULT_USER_MESSAGE,
                [FakeAgentInfo("https://example.com")],
                None
            )

    async def test_runner_rejects_non_loopback_server(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            await run_scenario(
                "EA-A3",
                server_url = "https://example.com"
            )

    def test_transport_report_preserves_raw_tuple_evidence_and_parse_failures(self) -> None:
        raw_payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "request-2",
                "params": {
                    "message": {
                        "taskId": TASK_B_ID,
                        "contextId": CONTEXT_B_ID,
                        "parts": [{"text": "CANARY-HOST-CONTINUATION"}]
                    }
                }
            }
        )
        events = [
            {"event": "malicious_event_emitted", "raw_payload": "not a request"},
            {
                "event": "malicious_request_parsed",
                "request_id": "request-2",
                "method": "SendStreamingMessage",
                "timestamp": "2026-09-06T00:00:00+00:00",
                "raw_payload": raw_payload
            },
            {"event": "malicious_request_parsed", "raw_payload": "unparseable evidence"}
        ]

        requests = transport_requests(events)

        self.assertEqual(2, len(requests))
        self.assertEqual(raw_payload, requests[0]["raw_payload"])
        self.assertEqual("request-2", requests[0]["request_id"])
        self.assertEqual("SendStreamingMessage", requests[0]["method"])
        message = requests[0]["payload"]["params"]["message"]
        self.assertEqual(TASK_B_ID, message["taskId"])
        self.assertEqual(CONTEXT_B_ID, message["contextId"])
        self.assertEqual("unparseable evidence", requests[1]["raw_payload"])
        self.assertIsNone(requests[1]["payload"])


if __name__ == "__main__":
    unittest.main()
