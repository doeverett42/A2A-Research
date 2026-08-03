from __future__ import annotations

import unittest

import httpx
from google.protobuf.json_format import MessageToDict

from a2a.client import ClientConfig, create_client
from a2a.helpers import new_text_message
from a2a.types import Role, SendMessageConfiguration, SendMessageRequest

from security.event_attribution.scenarios import (
    CONTEXT_A_ID,
    CONTEXT_B_ID,
    TASK_A_ID,
    TASK_B_ID,
    scenario_catalog
)
from security.event_attribution.server import build_malicious_app


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

    async def test_foreign_artifact_is_schema_valid(self) -> None:
        events = await self._stream_events("EA-A1")
        update = events[1].artifact_update

        self.assertEqual(TASK_B_ID, update.task_id)
        self.assertEqual(CONTEXT_B_ID, update.context_id)
        self.assertIn(
            "CANARY-FOREIGN-ARTIFACT-B",
            update.artifact.parts[0].text
        )

    async def test_context_splice_survives_normal_sdk_parsing(self) -> None:
        events = await self._normal_events("EA-A2")
        task = events[0].task

        self.assertEqual(TASK_A_ID, task.id)
        self.assertEqual(CONTEXT_A_ID, task.context_id)
        self.assertEqual(TASK_A_ID, task.status.message.task_id)
        self.assertEqual(CONTEXT_B_ID, task.status.message.context_id)

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

    async def test_duplicate_status_is_byte_identical(self) -> None:
        events = await self._stream_events("EA-C1")

        self.assertEqual(
            MessageToDict(events[1]),
            MessageToDict(events[2])
        )

    async def test_scenario_catalog_reports_configured_default_and_tasks(self) -> None:
        app = build_malicious_app(
            self.base_url,
            default_scenario_id = "EA-A1"
        )
        transport = httpx.ASGITransport(app = app)
        async with httpx.AsyncClient(
            transport = transport,
            base_url = self.base_url
        ) as httpx_client:
            response = await httpx_client.get("/scenarios")

        body = response.json()
        self.assertEqual("EA-A1", body["defaultScenario"])
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
        streaming: bool
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
                "Run the selected deterministic Gap 3 scenario.",
                media_type = "text/plain",
                role = Role.ROLE_USER
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
            return [event async for event in client.send_message(request)]
        finally:
            await client.close()


def _event_type(event) -> str:
    for event_type in ("task", "status_update", "artifact_update", "message"):
        if event.HasField(event_type):
            return event_type
    return "unknown"


def _event_metadata(event):
    if event.HasField("task"):
        return event.task.metadata
    if event.HasField("status_update"):
        return event.status_update.metadata
    if event.HasField("artifact_update"):
        return event.artifact_update.metadata
    return event.message.metadata


def _event_text(event) -> str:
    if event.HasField("task"):
        return event.task.status.message.parts[0].text
    if event.HasField("status_update"):
        return event.status_update.status.message.parts[0].text
    if event.HasField("artifact_update"):
        return event.artifact_update.artifact.parts[0].text
    return event.message.parts[0].text


if __name__ == "__main__":
    unittest.main()
