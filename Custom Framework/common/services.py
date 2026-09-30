from __future__ import annotations

#shared startup and shutdown for the two local agent service commands

import asyncio
from urllib.parse import urlparse

import uvicorn

from common.config import config


def validate_loopback_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in (
        "127.0.0.1",
        "localhost",
        "::1"
    ):
        raise ValueError("Local agent services only permit loopback URLs.")


async def serve_apps(apps: list[tuple], service_name: str) -> None:
    validate_loopback_url(config.OLLAMA_HOST)
    servers = []
    for app, port in apps:
        validate_loopback_url(config.remote_base_url(port))
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host = config.REMOTE_HOST,
                port = port,
                reload = False,
                log_level = "info"
            )
        )
        server.install_signal_handlers = lambda: None
        servers.append(server)

    #a startup failure stops the whole set so a partial run is not mistaken
    #for a complete experiment. both launchers use this same lifecycle.
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    try:
        while not all(server.started for server in servers):
            for task in tasks:
                if task.done():
                    task.result()
                    raise RuntimeError(
                        f"A {service_name} service stopped during startup."
                    )
            await asyncio.sleep(0.1)

        print(
            f"{service_name} services ready on ports: "
            + ", ".join(str(server.config.port) for server in servers),
            flush = True
        )
        await asyncio.gather(*tasks)
    finally:
        for server in servers:
            server.should_exit = True
        await asyncio.gather(*tasks, return_exceptions = True)
