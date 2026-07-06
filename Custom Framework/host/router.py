# Host routing logic
# Stage two supports one configured remote agent

from __future__ import annotations

from common.config import config


class RouteDecision:
    def __init__(self, remote_url: str, reason: str) -> None:
        self.remote_url = remote_url
        self.reason = reason


class SingleRemoteRouter:
    def __init__(self, remote_url: str | None = None) -> None:
        self.remote_url = remote_url or config.host_remote_url

    def route(self, user_message: str) -> RouteDecision:
        if not user_message.strip():
            raise ValueError("Cannot route an empty user message.")

        return RouteDecision(
            remote_url = self.remote_url,
            reason = "stage_two_single_remote",
        )
