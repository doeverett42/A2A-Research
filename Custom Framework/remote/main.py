from __future__ import annotations
import argparse
import uvicorn


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start one configured remote A2A agent.")
    parser.add_argument("--agent-index", "--agent", type=int, default=None)
    parser.add_argument("--list-agents", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    from common.config import config

    if args.list_agents:
        for spec in config.remote_agent_specs:
            print(f"{spec['index']}: {spec['name']} | {spec['skill']['name']} | {spec['model']} | port {spec['port']}")
        return

    if args.agent_index is None:
        raise SystemExit("remote.main requires --agent-index.")

    from common.ollama_client import OllamaClient
    from remote.agent import OllamaRemoteAgent
    from remote.agent_card import build_agent_card
    from remote.executor import RemoteAgentExecutor
    from remote.server import build_remote_app
    from remote.task_store import build_task_store

    spec = config.remote_agent_spec(args.agent_index)
    port = int(spec["port"])
    model = str(spec["model"])
    task_store, database_engine = build_task_store(args.agent_index)

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

    uvicorn.run(
        app,
        host = config.REMOTE_HOST,
        port = port,
        reload= False
    )


if __name__ == "__main__":
    main()
