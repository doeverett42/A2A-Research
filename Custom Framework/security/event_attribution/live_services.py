from __future__ import annotations

#starts every local service needed by the six live experiments
#run this after ollama is available and leave it open while live_experiment.py
#runs in another terminal. one uvicorn process serves the deterministic fixture,
#and the selected configured agent indexes serve the real food and budget agents.
#
#each normal agent keeps its usual agent card, ollama model, executor, and sqlite
#task store. only loopback urls are allowed so this helper cannot point the
#experiment at an outside a2a service by accident.

import argparse
import asyncio
from urllib.parse import urlparse

import uvicorn

from common.config import config
from common.ollama_client import OllamaClient
from remote.agent import OllamaRemoteAgent
from remote.agent_card import build_agent_card
from remote.executor import RemoteAgentExecutor
from remote.server import build_remote_app
from remote.task_store import build_task_store
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
    _validate_loopback_url(
        f"http://{config.REMOTE_HOST}:{malicious_port}"
    )
    _validate_loopback_url(config.OLLAMA_HOST)
    remote_agent_indexes = list(
        remote_agent_indexes
        if remote_agent_indexes is not None
        else DEFAULT_REMOTE_AGENT_INDEXES
    )
    #the malicious fixture defaults to ea-a3, but each runner request also sends
    #an explicit scenario header so control and tm cases select their own fixture.
    servers = [
        _server(
            build_malicious_app(
                f"http://{config.REMOTE_HOST}:{malicious_port}",
                default_scenario_id = "EA-A3"
            ),
            malicious_port
        )
    ]

    for agent_index in remote_agent_indexes:
        #build normal remote services from the same configuration used by the
        #rest of the framework instead of making simplified experiment agents.
        spec = config.remote_agent_spec(agent_index)
        port = int(spec["port"])
        model = str(spec["model"])
        task_store, database_engine = build_task_store(agent_index)
        app = build_remote_app(
            agent_card = build_agent_card(
                agent_spec = spec,
                version = config.REMOTE_AGENT_VERSION,
                base_url = config.remote_base_url(port)
            ),
            executor = RemoteAgentExecutor(
                OllamaRemoteAgent(
                    client = OllamaClient(config.OLLAMA_HOST),
                    model = model,
                    system_prompt = str(spec["system_prompt"])
                )
            ),
            task_store = task_store,
            database_engine = database_engine
        )
        servers.append(_server(app, port))

    #all servers share this terminal. if one fails during startup, the helper
    #stops the set so a partial experiment is not mistaken for a complete run.
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    try:
        while not all(server.started for server in servers):
            for task in tasks:
                if task.done():
                    task.result()
                    raise RuntimeError(
                        "A live Gap 3 service stopped during startup."
                    )
            await asyncio.sleep(0.1)

        print(
            "Live Gap 3 services ready on ports: "
            + ", ".join(str(server.config.port) for server in servers),
            flush = True
        )
        await asyncio.gather(*tasks)
    finally:
        for server in servers:
            server.should_exit = True
        await asyncio.gather(*tasks, return_exceptions = True)


def _validate_loopback_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in (
        "127.0.0.1",
        "localhost",
        "::1"
    ):
        raise ValueError("Live Gap 3 services only permit loopback URLs.")


def _server(app, port: int) -> uvicorn.Server:
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
    return server


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description = "Start the local services used by the live Gap 3 test."
    )
    parser.add_argument(
        "--malicious-port",
        type = int,
        default = DEFAULT_MALICIOUS_PORT
    )
    parser.add_argument(
        "--remote-agent-index",
        action = "append",
        type = int,
        dest = "remote_agent_indexes"
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    asyncio.run(
        run_services(
            malicious_port = args.malicious_port,
            remote_agent_indexes = args.remote_agent_indexes
        )
    )


if __name__ == "__main__":
    main()
