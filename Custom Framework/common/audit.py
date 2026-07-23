from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path


AUDIT_HEADER = "X-A2A-Audit-ID"
AUDIT_LOG_DIRECTORY = Path(__file__).resolve().parents[1] / "logs" / "audit"

_current_audit_id = ContextVar("current_a2a_audit_id", default="")
_current_agent_name = ContextVar("current_a2a_agent_name", default="")
_logger = logging.getLogger("a2a.audit")


class AuditMiddleware:

    def __init__(self, app, agent_name: str) -> None:
        self.app = app
        self.agent_name = agent_name

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        audit_id = _header_value(scope, AUDIT_HEADER)
        if not audit_id:
            await self.app(scope, receive, send)
            return

        audit_token = _current_audit_id.set(audit_id)
        agent_token = _current_agent_name.set(self.agent_name)
        status_code = 0

        async def audited_send(message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            record_audit_event(
                "http_request_received",
                method = scope["method"],
                path = scope["path"]
            )
            await self.app(scope, receive, audited_send)
        except Exception as e:
            record_audit_event(
                "http_request_failed",
                error_type = type(e).__name__
            )
            raise
        finally:
            if status_code:
                record_audit_event(
                    "http_response_sent",
                    status_code = status_code
                )
            _current_agent_name.reset(agent_token)
            _current_audit_id.reset(audit_token)


def record_audit_event(event: str, **details) -> None:
    audit_id = _current_audit_id.get()
    agent_name = _current_agent_name.get()
    if not audit_id or not agent_name:
        return

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "audit_id": audit_id,
        "agent_name": agent_name,
        "event": event,
        **details
    }

    try:
        path = audit_log_path(agent_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(entry) + "\n")
    except OSError:
        _logger.exception("Could not write A2A audit event.")


def read_audit_events(agent_name: str, audit_id: str) -> list[dict]:
    path = audit_log_path(agent_name)
    if not path.exists():
        return []

    events = []
    with path.open("r", encoding="utf-8") as audit_file:
        for line in audit_file:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("audit_id") == audit_id:
                events.append(entry)
    return events


def audit_log_path(agent_name: str) -> Path:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]+", "_", agent_name).strip("_").lower()
    return AUDIT_LOG_DIRECTORY / f"{safe_name}.jsonl"


def _header_value(scope, header_name: str) -> str:
    expected_name = header_name.lower().encode("ascii")
    for name, value in scope["headers"]:
        if name == expected_name:
            return value.decode("utf-8")[:128]
    return ""
