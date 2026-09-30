from __future__ import annotations

#starts all five normal cyber agents together for a clean baseline or host chat

import asyncio

from common.config import config
from common.services import serve_apps
from remote.configured_app import build_configured_remote_app


async def run_services() -> None:
    apps = []
    for agent_index in range(len(config.remote_agent_specs)):
        app, spec = build_configured_remote_app(agent_index)
        apps.append((app, int(spec["port"])))
    await serve_apps(apps, "Cyber agent")


def main() -> None:
    asyncio.run(run_services())


if __name__ == "__main__":
    main()
