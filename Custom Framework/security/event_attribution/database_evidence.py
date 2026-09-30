from __future__ import annotations

#read-only sqlite evidence helper for the six live tests
#the normal remote-agent task stores write their own rows during a run. this
#file never creates, updates, or deletes those rows. it only compares the task
#ids seen before the run with the ids seen at a later checkpoint.
#
#for each new row it checks status, history, and artifacts separately. this
#makes it possible to say where a harmless run canary was persisted instead of
#treating one text match somewhere in the database as enough evidence.

import json
import re
import sqlite3
from pathlib import Path


SEARCH_COLUMNS = ("status", "history", "artifacts")
ROOT_DIRECTORY = Path(__file__).resolve().parents[2]


def database_path_text(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT_DIRECTORY))
    except ValueError:
        return str(resolved)


def snapshot_task_ids(
    database_paths: dict[str, Path]
) -> dict[str, set[str]]:
    #the baseline is intentionally small so old research rows stay untouched.
    return {
        agent_name: _task_ids(path)
        for agent_name, path in database_paths.items()
    }


def database_evidence(
    database_paths: dict[str, Path],
    baseline: dict[str, set[str]],
    run_canary: str
) -> dict:
    agents = {}
    for agent_name, path in database_paths.items():
        #subtracting the baseline limits the report to tasks created in this run.
        current_ids = _task_ids(path)
        new_ids = sorted(current_ids - baseline.get(agent_name, set()))
        rows = _task_rows(path, new_ids)
        agents[agent_name] = {
            "database_path": database_path_text(path),
            "database_exists": path.exists(),
            "baseline_task_count": len(baseline.get(agent_name, set())),
            "current_task_count": len(current_ids),
            "new_task_count": len(rows),
            "new_rows": [
                _row_evidence(row, run_canary)
                for row in rows
            ],
            "case_evidence_rows": _case_evidence_rows(
                path,
                new_ids,
                run_canary
            )
        }

    return {
        "run_canary": run_canary,
        "agents": agents
    }


def snapshot_report(
    database_paths: dict[str, Path],
    snapshot: dict[str, set[str]]
) -> dict:
    return {
        agent_name: {
            "database_path": database_path_text(path),
            "database_exists": path.exists(),
            "task_ids": sorted(snapshot.get(agent_name, set()))
        }
        for agent_name, path in database_paths.items()
    }


def _task_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()

    connection = _read_only_connection(path)
    try:
        return {
            row[0]
            for row in connection.execute("SELECT id FROM tasks")
        }
    finally:
        connection.close()


def _task_rows(path: Path, task_ids: list[str]) -> list[sqlite3.Row]:
    if not path.exists() or not task_ids:
        return []

    placeholders = ", ".join("?" for _ in task_ids)
    connection = _read_only_connection(path)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(
            "SELECT id, context_id, last_updated, status, history, artifacts "
            f"FROM tasks WHERE id IN ({placeholders}) ORDER BY last_updated, id",
            task_ids
        ).fetchall()
    finally:
        connection.close()


def _row_evidence(row: sqlite3.Row, run_canary: str) -> dict:
    raw_columns = {
        column: row[column] or ""
        for column in SEARCH_COLUMNS
    }
    canaries_by_column = {
        column: _canaries(text)
        for column, text in raw_columns.items()
    }
    #report the exact columns rather than only returning one yes/no value.
    run_canary_columns = [
        column
        for column, column_canaries in canaries_by_column.items()
        if run_canary and run_canary in column_canaries
    ]
    return {
        "task_id": row["id"],
        "context_id": row["context_id"],
        "last_updated": row["last_updated"],
        "contains_run_canary": bool(run_canary_columns),
        "run_canary_columns": run_canary_columns,
        "canaries_by_column": canaries_by_column,
        "status": _json_value(raw_columns["status"]),
        "history": _json_value(raw_columns["history"]),
        "artifacts": _json_value(raw_columns["artifacts"])
    }


def _read_only_connection(path: Path) -> sqlite3.Connection:
    #mode=ro makes an accidental write fail instead of changing experiment data.
    return sqlite3.connect(
        f"file:{path.resolve()}?mode=ro",
        uri = True
    )


def _case_evidence_rows(
    path: Path,
    task_ids: list[str],
    run_canary: str
) -> list[dict]:
    if not path.exists() or not task_ids:
        return []

    placeholders = ", ".join("?" for _ in task_ids)
    connection = _read_only_connection(path)
    connection.row_factory = sqlite3.Row
    try:
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'case_evidence'"
        ).fetchone()
        if not table_exists:
            return []
        rows = connection.execute(
            "SELECT recorded_at, stage, agent_name, message_id, task_id, "
            "context_id, case_label, packet_hash, evidence_group, "
            "request_canaries, response_canaries FROM case_evidence "
            f"WHERE task_id IN ({placeholders}) ORDER BY id",
            task_ids
        ).fetchall()
    finally:
        connection.close()

    evidence = []
    for row in rows:
        request_canaries = _json_value(row["request_canaries"])
        response_canaries = _json_value(row["response_canaries"])
        columns = []
        if _contains_canary(request_canaries, run_canary):
            columns.append("request_canaries")
        if _contains_canary(response_canaries, run_canary):
            columns.append("response_canaries")
        evidence.append(
            {
                "recorded_at": row["recorded_at"],
                "stage": row["stage"],
                "agent_name": row["agent_name"],
                "message_id": row["message_id"],
                "task_id": row["task_id"],
                "context_id": row["context_id"],
                "case_label": row["case_label"],
                "packet_hash": row["packet_hash"],
                "evidence_group": row["evidence_group"],
                "contains_run_canary": bool(columns),
                "run_canary_columns": columns,
                "request_canaries": request_canaries,
                "response_canaries": response_canaries
            }
        )
    return evidence


def _json_value(value: str):
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _canaries(text: str) -> list[str]:
    return sorted(set(re.findall(r"CANARY-[A-Z0-9-]+", text)))


def _contains_canary(value, run_canary: str) -> bool:
    if not run_canary:
        return False
    if isinstance(value, list):
        return run_canary in value
    return run_canary in _canaries(str(value))
