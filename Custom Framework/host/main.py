#Host CLI framework

from __future__ import annotations

import asyncio

from common.config import config
from common.logging import logger
from common.ollama_client import OllamaClient
from host.agent import HostAgent
from host.discovery import AgentDiscovery
from host.orchestrator import HostOrchestrator
from host.router import MultiRemoteRouter


EXIT_COMMANDS = {"exit", "quit", ":q"}


async def chat_loop() -> None:
    host_agent = HostAgent(
        client = OllamaClient(config.OLLAMA_HOST),
        model = config.HOST_MODEL
    )

    orchestrator = HostOrchestrator(
        agent = host_agent,
        discovery = AgentDiscovery(
            agent_card_urls = config.remote_agent_card_urls,
            timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS
        ),
        router = MultiRemoteRouter(),
        timeout_seconds = config.A2A_CLIENT_TIMEOUT_SECONDS
    )

    print("A2A host orchestrator. Type exit to quit.")

    try:
        while True:
            user_message = input("user> ").strip()
            if not user_message:
                continue
            if user_message.lower() in EXIT_COMMANDS:
                break

            try:
                response = await orchestrator.run(user_message)
                print(f"remote> {response}")
            except Exception as e:
                logger.exception("Host orchestration failed.")
                print(f"error> {e}")
    finally:
        await orchestrator.close()


def main() -> None:
    asyncio.run(chat_loop())


if __name__ == "__main__":
    main()
