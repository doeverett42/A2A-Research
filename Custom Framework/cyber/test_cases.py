from __future__ import annotations

import json
import tempfile
import sqlite3
import unittest
from pathlib import Path

from a2a.types import TaskState
from sqlalchemy import URL
from sqlalchemy.ext.asyncio import create_async_engine

from cyber.case_builder import (
    SANDBOX_DEFINITIONS,
    SANDBOX_RAW_DIRECTORY,
    build_case,
    build_cases
)
from cyber.cases import CaseMetadata, CyberCaseStore, extract_case_metadata
from host.agent import HostAgent
from host.client import RemoteTaskResponse
from host.orchestrator import HostOrchestrator
from host.router import DelegationPlan, PlanStep
from remote.case_evidence import CaseEvidenceStore


class FakeDiscovery:
    async def discover(self):
        return []


class IdentityRouter:
    async def plan(self, user_message: str, agents, host_agent):
        return DelegationPlan(
            mode = "delegate",
            reason = "case attachment test",
            steps = [
                PlanStep(
                    step_id = 1,
                    agent_index = 0,
                    agent_name = "Identity Analyst",
                    remote_url = "http://identity.test",
                    task = "Review the identity evidence.",
                    depends_on = []
                )
            ]
        )


class FormattingHostAgent:
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


class RecordingClient:
    def __init__(self) -> None:
        self.request = ""

    async def send_text(self, text: str) -> RemoteTaskResponse:
        self.request = text
        return RemoteTaskResponse(
            text = "identity baseline complete",
            task_id = "identity-task",
            context_id = "identity-context",
            state = TaskState.TASK_STATE_COMPLETED
        )

    async def close(self) -> None:
        pass


class CyberCaseTests(unittest.TestCase):
    def test_sandbox_packets_are_deterministic_and_hidden_keys_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = build_cases(
                SANDBOX_DEFINITIONS,
                SANDBOX_RAW_DIRECTORY,
                root / "packets",
                root / "keys"
            )
            first_hashes = [CyberCaseStore(root / "packets").get(path.stem).packet_hash for path in first]
            build_cases(
                SANDBOX_DEFINITIONS,
                SANDBOX_RAW_DIRECTORY,
                root / "packets",
                root / "keys"
            )
            second_hashes = [CyberCaseStore(root / "packets").get(path.stem).packet_hash for path in first]

            self.assertEqual(first_hashes, second_hashes)
            self.assertTrue((root / "keys" / "cyber-sandbox-a.answer.json").exists())
            self.assertNotIn(
                "answer_key",
                (root / "packets" / "cyber-sandbox-a.json").read_text(encoding = "utf-8")
            )

    def test_one_request_cannot_select_two_cases(self) -> None:
        store = CyberCaseStore(
            Path(__file__).resolve().parents[1]
            / "data"
            / "cyber_cases"
            / "packets"
        )

        with self.assertRaisesRegex(ValueError, "one local cyber case"):
            store.resolve("Compare CYBER-SANDBOX-A and CYBER-SANDBOX-B.")

    def test_conflicting_case_blocks_are_rejected(self) -> None:
        first = """
        [local-case]
        case_label: CYBER-SANDBOX-A
        packet_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        evidence_group: identity
        [/local-case]
        """
        second = """
        [local-case]
        case_label: CYBER-SANDBOX-B
        packet_hash: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        evidence_group: identity
        [/local-case]
        """

        with self.assertRaisesRegex(ValueError, "conflicting local-case"):
            extract_case_metadata(first + second)

    def test_case_builder_sorts_before_applying_the_group_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_directory = root / "raw"
            raw_directory.mkdir()
            (raw_directory / "identity.csv").write_text(
                "_time,_raw\n"
                "2026-01-10T10:05:00Z,later event\n"
                "2026-01-10T10:01:00Z,earlier event\n",
                encoding = "utf-8"
            )
            definition = {
                "case_label": "CYBER-ORDER-TEST",
                "title": "ordering test",
                "dataset": "local fixture",
                "time_window": {
                    "start": "2026-01-10T10:00:00Z",
                    "end": "2026-01-10T10:10:00Z"
                },
                "selection_rule": "sort then keep one",
                "limit_per_group": 1,
                "groups": {
                    "identity": [
                        {
                            "file": "identity.csv",
                            "prefix": "AUTH",
                            "sourcetype": "test"
                        }
                    ]
                }
            }
            packet_path = build_case(
                definition,
                raw_directory,
                root / "packets",
                root / "keys"
            )
            packet = json.loads(packet_path.read_text(encoding = "utf-8"))

            self.assertEqual(
                "earlier event",
                packet["evidence_groups"]["identity"][0]["event"]
            )


class CyberOrchestratorTests(unittest.IsolatedAsyncioTestCase):
    async def test_identity_receives_only_identity_lines_and_tuple_is_bound_to_case(self) -> None:
        case_store = CyberCaseStore(
            Path(__file__).resolve().parents[1] / "data" / "cyber_cases" / "packets"
        )
        client = RecordingClient()
        orchestrator = HostOrchestrator(
            agent = FormattingHostAgent(),
            discovery = FakeDiscovery(),
            router = IdentityRouter(),
            timeout_seconds = 5,
            client_factory = lambda remote_url, timeout: client,
            case_store = case_store
        )
        try:
            result = await orchestrator.run("Review CYBER-SANDBOX-A.")
        finally:
            await orchestrator.close()

        metadata = extract_case_metadata(client.request)
        self.assertIsNotNone(metadata)
        self.assertEqual("identity", metadata.evidence_group)
        self.assertIn("AUTH-001", client.request)
        self.assertNotIn("ENDPOINT-001", client.request)
        self.assertEqual("CYBER-SANDBOX-A", orchestrator.tuple_bindings[0].case_label)
        self.assertEqual(metadata.packet_hash, orchestrator.tuple_bindings[0].packet_hash)
        self.assertFalse(result.input_required)

    async def test_case_evidence_table_records_case_tuple_and_canaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.db"
            engine = create_async_engine(
                URL.create(
                    drivername = "sqlite+aiosqlite",
                    database = str(path)
                )
            )
            store = CaseEvidenceStore(engine, "Identity Analyst")
            await store.initialize()
            await store.record(
                "completed",
                CaseMetadata(
                    case_label = "CYBER-SANDBOX-A",
                    packet_hash = "a" * 64,
                    evidence_group = "identity"
                ),
                "message-1",
                "task-1",
                "context-1",
                "request CANARY-G3-TEST-001",
                "response CANARY-G3-TEST-001"
            )
            await engine.dispose()

            connection = sqlite3.connect(path)
            try:
                row = connection.execute(
                    "SELECT agent_name, task_id, context_id, case_label, "
                    "packet_hash, evidence_group, request_canaries, response_canaries "
                    "FROM case_evidence"
                ).fetchone()
            finally:
                connection.close()

            self.assertEqual("Identity Analyst", row[0])
            self.assertEqual("task-1", row[1])
            self.assertEqual("context-1", row[2])
            self.assertEqual("CYBER-SANDBOX-A", row[3])
            self.assertEqual("a" * 64, row[4])
            self.assertEqual("identity", row[5])
            self.assertIn("CANARY-G3-TEST-001", row[6])
            self.assertIn("CANARY-G3-TEST-001", row[7])

    async def test_case_evidence_rejects_unknown_packet_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.db"
            engine = create_async_engine(
                URL.create(
                    drivername = "sqlite+aiosqlite",
                    database = str(path)
                )
            )
            case_store = CyberCaseStore(
                Path(__file__).resolve().parents[1]
                / "data"
                / "cyber_cases"
                / "packets"
            )
            store = CaseEvidenceStore(
                engine,
                "Identity Analyst",
                case_store
            )
            await store.initialize()

            with self.assertRaisesRegex(ValueError, "hash does not match"):
                await store.record(
                    "completed",
                    CaseMetadata(
                        case_label = "CYBER-SANDBOX-A",
                        packet_hash = "a" * 64,
                        evidence_group = "identity"
                    ),
                    "message-1",
                    "task-1",
                    "context-1",
                    "request"
                )
            await engine.dispose()

            connection = sqlite3.connect(path)
            try:
                count = connection.execute(
                    "SELECT COUNT(*) FROM case_evidence"
                ).fetchone()[0]
            finally:
                connection.close()

            self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()
