from __future__ import annotations

import unittest

import httpx

from a2a.client import ClientCallContext, ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import (
    Role,
    SendMessageConfiguration,
    SendMessageRequest,
    TaskState
)

from security.event_attribution.scenarios import (
    CONTEXT_A_ID,
    CONTEXT_B_ID,
    EA_A3_COMPLETION_CANARY,
    EA_C2_COMPLETION_CANARY,
    EA_TM1_COMPLETION_CANARY,
    EA_TM2_COMPLETION_CANARY,
    HOST_CONTINUATION_CANARY,
    TASK_A_ID,
    TASK_B_ID,
    scenario_catalog
)
from security.event_attribution.server import (
    RUN_CANARY_HEADER,
    build_malicious_app
)


class MaliciousEventServerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.base_url = "http://gap3.test"
        self.app = build_malicious_app(self.base_url)

    async def test_coherent_stream_uses_one_task_context_pair(self) -> None:
        events = await self._stream_events("EA-C0")

        self.assertEqual(
            ["task", "artifact_update", "status_update"],
            [_event_type(event) for event in events]
        )
        self.assertEqual(TASK_A_ID, events[0].task.id)
        self.assertEqual(CONTEXT_A_ID, events[0].task.context_id)
        self.assertEqual(TASK_A_ID, events[1].artifact_update.task_id)
        self.assertEqual(CONTEXT_A_ID, events[1].artifact_update.context_id)
        self.assertEqual(TASK_A_ID, events[2].status_update.task_id)
        self.assertEqual(CONTEXT_A_ID, events[2].status_update.context_id)

    async def test_every_scenario_parses_on_both_delivery_paths(self) -> None:
        for scenario_id in scenario_catalog():
            with self.subTest(scenario = scenario_id, delivery = "normal"):
                normal_events = await self._normal_events(scenario_id)
                self.assertEqual(1, len(normal_events))

            with self.subTest(scenario = scenario_id, delivery = "streaming"):
                stream_events = await self._stream_events(scenario_id)
                self.assertGreaterEqual(len(stream_events), 2)
                for event in stream_events:
                    self.assertIn("sequenceNumber", _event_metadata(event))
                    self.assertIn("CANARY-", _event_text(event))

    async def test_ea_a3_continuation_completes_forged_task(self) -> None:
        #the initial stream changes a/a to b/b before the follow-up uses b/b.
        initial_events = await self._stream_events("EA-A3")
        self.assertEqual(TASK_A_ID, initial_events[0].task.id)
        self.assertEqual(CONTEXT_A_ID, initial_events[0].task.context_id)
        initial_update = initial_events[-1].status_update
        self.assertEqual(TASK_B_ID, initial_update.task_id)
        self.assertEqual(CONTEXT_B_ID, initial_update.context_id)
        self.assertEqual(
            TaskState.TASK_STATE_INPUT_REQUIRED,
            initial_update.status.state
        )

        events = await self._official_client_events(
            "EA-A3",
            streaming = True,
            text = HOST_CONTINUATION_CANARY,
            task_id = TASK_B_ID,
            context_id = CONTEXT_B_ID
        )

        self.assertEqual(1, len(events))
        update = events[0].status_update
        self.assertEqual(TASK_B_ID, update.task_id)
        self.assertEqual(CONTEXT_B_ID, update.context_id)
        self.assertEqual(
            TaskState.TASK_STATE_COMPLETED,
            update.status.state
        )
        self.assertIn(
            "CANARY-FORGED-INPUT-B",
            update.status.message.parts[0].text
        )
        self.assertIn(
            EA_A3_COMPLETION_CANARY,
            update.status.message.parts[0].text
        )

    async def test_follow_up_continuations_keep_selected_tuple(self) -> None:
        cases = (
            (
                "EA-C2",
                TASK_A_ID,
                CONTEXT_A_ID,
                EA_C2_COMPLETION_CANARY
            ),
            (
                "EA-TM1",
                TASK_B_ID,
                CONTEXT_A_ID,
                EA_TM1_COMPLETION_CANARY
            ),
            (
                "EA-TM2",
                TASK_A_ID,
                CONTEXT_B_ID,
                EA_TM2_COMPLETION_CANARY
            )
        )

        for scenario_id, task_id, context_id, completion_canary in cases:
            with self.subTest(scenario = scenario_id, phase = "initial"):
                initial_events = await self._stream_events(scenario_id)
                self.assertEqual(TASK_A_ID, initial_events[0].task.id)
                self.assertEqual(CONTEXT_A_ID, initial_events[0].task.context_id)
                update = initial_events[-1].status_update
                self.assertEqual(task_id, update.task_id)
                self.assertEqual(context_id, update.context_id)
                self.assertEqual(
                    TaskState.TASK_STATE_INPUT_REQUIRED,
                    update.status.state
                )

            with self.subTest(scenario = scenario_id, phase = "continuation"):
                continuation_events = await self._official_client_events(
                    scenario_id,
                    streaming = True,
                    text = HOST_CONTINUATION_CANARY,
                    task_id = task_id,
                    context_id = context_id
                )
                update = continuation_events[-1].status_update
                self.assertEqual(task_id, update.task_id)
                self.assertEqual(context_id, update.context_id)
                self.assertEqual(
                    TaskState.TASK_STATE_COMPLETED,
                    update.status.state
                )
                self.assertIn(
                    completion_canary,
                    update.status.message.parts[0].text
                )

    async def test_unique_run_canary_is_returned_as_plain_data(self) -> None:
        run_canary = "CANARY-G3-TM1-TEST-001"
        events = await self._official_client_events(
            "EA-TM1",
            streaming = True,
            run_canary = run_canary
        )

        self.assertIn(run_canary, _event_text(events[-1]))

        #a new request must not inherit the previous run's unique marker.
        next_events = await self._stream_events("EA-TM1")
        for event in next_events:
            self.assertNotIn(run_canary, _event_text(event))

    async def test_continuation_requires_the_selected_tuple(self) -> None:
        #the fixture should only complete the exact tuple it advertised.
        events = await self._official_client_events(
            "EA-A3",
            streaming = True,
            text = HOST_CONTINUATION_CANARY,
            task_id = TASK_B_ID,
            context_id = CONTEXT_A_ID
        )

        self.assertEqual(2, len(events))
        self.assertEqual(TASK_A_ID, events[0].task.id)
        self.assertEqual(
            TaskState.TASK_STATE_INPUT_REQUIRED,
            events[-1].status_update.status.state
        )
        self.assertNotIn(EA_A3_COMPLETION_CANARY, _event_text(events[-1]))

    async def test_scenario_catalog_reports_configured_default_and_tasks(self) -> None:
        app = build_malicious_app(
            self.base_url,
            default_scenario_id = "EA-A3"
        )
        transport = httpx.ASGITransport(app = app)
        async with httpx.AsyncClient(
            transport = transport,
            base_url = self.base_url
        ) as httpx_client:
            response = await httpx_client.get("/scenarios")

        body = response.json()
        self.assertEqual("EA-A3", body["defaultScenario"])
        self.assertEqual(
            {"EA-C0", "EA-C2", "EA-TM1", "EA-TM2", "EA-A3"},
            set(body["scenarios"])
        )
        self.assertEqual(TASK_A_ID, body["tasks"][0]["taskId"])
        self.assertEqual(CONTEXT_A_ID, body["tasks"][0]["contextId"])
        self.assertEqual(TASK_B_ID, body["tasks"][1]["taskId"])
        self.assertEqual(CONTEXT_B_ID, body["tasks"][1]["contextId"])

    async def test_unknown_scenario_returns_invalid_params(self) -> None:
        transport = httpx.ASGITransport(app = self.app)
        async with httpx.AsyncClient(
            transport = transport,
            base_url = self.base_url
        ) as httpx_client:
            response = await httpx_client.post(
                "/",
                json = {
                    "jsonrpc": "2.0",
                    "id": "unknown-scenario",
                    "method": "SendMessage",
                    "params": {
                        "message": {
                            "messageId": "unknown-scenario-message",
                            "role": "ROLE_USER",
                            "parts": [
                                {
                                    "text": "test",
                                    "mediaType": "text/plain"
                                }
                            ],
                            "metadata": {
                                "scenario": "EA-NOT-REAL"
                            }
                        }
                    }
                }
            )

        self.assertEqual(-32602, response.json()["error"]["code"])

    async def _stream_events(self, scenario_id: str):
        return await self._official_client_events(
            scenario_id,
            streaming = True
        )

    async def _normal_events(self, scenario_id: str):
        return await self._official_client_events(
            scenario_id,
            streaming = False
        )

    async def _official_client_events(
        self,
        scenario_id: str,
        streaming: bool,
        text: str = "Run the selected deterministic Gap 3 scenario.",
        task_id: str | None = None,
        context_id: str | None = None,
        run_canary: str | None = None
    ):
        transport = httpx.ASGITransport(app = self.app)
        httpx_client = httpx.AsyncClient(
            transport = transport,
            base_url = self.base_url
        )
        client = await create_client(
            self.base_url,
            client_config = ClientConfig(
                streaming = streaming,
                polling = False,
                httpx_client = httpx_client,
                accepted_output_modes = ["text/plain"]
            )
        )
        try:
            message = new_text_message(
                text,
                media_type = "text/plain",
                role = Role.ROLE_USER,
                task_id = task_id,
                context_id = context_id
            )
            message.metadata.update(
                {
                    "scenario": scenario_id
                }
            )
            request = SendMessageRequest(
                message = message,
                configuration = SendMessageConfiguration(
                    accepted_output_modes = ["text/plain"]
                )
            )
            context = None
            if run_canary:
                context = ClientCallContext(
                    service_parameters = {
                        RUN_CANARY_HEADER: run_canary
                    }
                )
            return [
                event async for event in client.send_message(
                    request,
                    context = context
                )
            ]
        finally:
            await client.close()


def _event_type(event) -> str:
    for event_type in ("task", "status_update", "artifact_update"):
        if event.HasField(event_type):
            return event_type
    return "unknown"


def _event_metadata(event):
    if event.HasField("task"):
        return event.task.metadata
    if event.HasField("status_update"):
        return event.status_update.metadata
    return event.artifact_update.metadata


def _event_text(event) -> str:
    if event.HasField("task"):
        return event.task.status.message.parts[0].text
    if event.HasField("status_update"):
        return event.status_update.status.message.parts[0].text
    return event.artifact_update.artifact.parts[0].text


if __name__ == "__main__":
    unittest.main()
