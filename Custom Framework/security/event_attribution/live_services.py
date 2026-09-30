from __future__ import annotations

#starts every local service needed by the six live experiments
#run this after ollama is available and leave it open while live_experiment.py
#runs in another terminal. one uvicorn process serves the deterministic fixture,
#and the selected configured agent indexes serve the real identity and correlation agents.
#
#each normal agent keeps its usual agent card, ollama model, executor, and sqlite
#task store. only loopback urls are allowed so this helper cannot point the
#experiment at an outside a2a service by accident.

import asyncio

from common.config import config
from common.services import serve_apps
from remote.configured_app import build_configured_remote_app
from security.event_attribution.fixed_plans import (
    FOLLOW_UP_REMOTE_AGENT_INDEXES
)
from security.event_attribution.server import build_malicious_app


DEFAULT_MALICIOUS_PORT = 8010
DEFAULT_REMOTE_AGENT_INDEXES = list(FOLLOW_UP_REMOTE_AGENT_INDEXES)


async def run_services(
    malicious_port: int = DEFAULT_MALICIOUS_PORT,
    remote_agent_indexes: list[int] | None = None
) -> None:
    remote_agent_indexes = list(
        remote_agent_indexes
        if remote_agent_indexes is not None
        else DEFAULT_REMOTE_AGENT_INDEXES
    )
    #the malicious fixture defaults to ea-a3, but each runner request also sends
    #an explicit scenario header so control and tm cases select their own fixture.
    apps = [
        (
            build_malicious_app(
                config.remote_base_url(malicious_port),
                default_scenario_id = "EA-A3"
            ),
            malicious_port
        )
    ]

    for agent_index in remote_agent_indexes:
        #build normal remote services from the same configuration used by the
        #rest of the framework instead of making simplified experiment agents.
        app, spec = build_configured_remote_app(agent_index)
        port = int(spec["port"])
        apps.append((app, port))
    await serve_apps(apps, "Live Gap 3")


def main() -> None:
    asyncio.run(run_services())


if __name__ == "__main__":
    main()
