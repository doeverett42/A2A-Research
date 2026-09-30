from __future__ import annotations

#stores case identity beside the sdk task table without changing a2a messages

import json
import re
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, MetaData, String, Table, Text, insert
from sqlalchemy.ext.asyncio import AsyncEngine

from cyber.cases import (
    AGENT_EVIDENCE_GROUPS,
    CaseMetadata,
    CyberCaseStore
)


metadata = MetaData()
case_evidence_table = Table(
    "case_evidence",
    metadata,
    Column("id", Integer, primary_key = True, autoincrement = True),
    Column("recorded_at", String, nullable = False),
    Column("stage", String, nullable = False),
    Column("agent_name", String, nullable = False),
    Column("message_id", String, nullable = False),
    Column("task_id", String, nullable = False),
    Column("context_id", String, nullable = False),
    Column("case_label", String, nullable = False),
    Column("packet_hash", String, nullable = False),
    Column("evidence_group", String, nullable = False),
    Column("request_canaries", Text, nullable = False),
    Column("response_canaries", Text, nullable = False)
)


class CaseEvidenceStore:
    def __init__(
        self,
        engine: AsyncEngine,
        agent_name: str,
        case_store: CyberCaseStore | None = None
    ) -> None:
        self.engine = engine
        self.agent_name = agent_name
        self.case_store = case_store

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(metadata.create_all)

    async def record(
        self,
        stage: str,
        case: CaseMetadata,
        message_id: str,
        task_id: str,
        context_id: str,
        request_text: str,
        response_text: str = ""
    ) -> None:
        self._validate_case(case)
        values = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "agent_name": self.agent_name,
            "message_id": message_id,
            "task_id": task_id,
            "context_id": context_id,
            "case_label": case.case_label,
            "packet_hash": case.packet_hash,
            "evidence_group": case.evidence_group,
            "request_canaries": json.dumps(_canaries(request_text)),
            "response_canaries": json.dumps(_canaries(response_text))
        }
        async with self.engine.begin() as connection:
            await connection.execute(insert(case_evidence_table).values(**values))

    def _validate_case(self, case: CaseMetadata) -> None:
        if self.case_store is None:
            return

        packet = self.case_store.get(case.case_label)
        if case.packet_hash != packet.packet_hash:
            raise ValueError(
                f"Case metadata hash does not match {case.case_label}."
            )
        expected_group = AGENT_EVIDENCE_GROUPS.get(self.agent_name)
        if expected_group and case.evidence_group != expected_group:
            raise ValueError(
                f"{self.agent_name} received case group "
                f"{case.evidence_group}, expected {expected_group}."
            )


def _canaries(text: str) -> list[str]:
    return sorted(set(re.findall(r"CANARY-[A-Z0-9-]+", text)))

