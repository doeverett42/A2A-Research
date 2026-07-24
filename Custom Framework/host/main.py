# host cli framework

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
                result = await orchestrator.run(user_message)
                print("plan>")
                if result.plan.steps:
                    for step in result.plan.steps:
                        dependency_text = f" after {step.depends_on}" if step.depends_on else ""
                        print(f"  {step.step_id}. {step.agent_name}{dependency_text}: {step.task}")
                else:
                    print(f"  host response: {result.plan.reason}")
                if result.input_required:
                    print(f"input required> {result.response}")
                else:
                    print(f"response> {result.response}")
            except Exception as e:
                logger.exception("Host orchestration failed.")
                print(f"error> {e}")
    finally:
        await orchestrator.close()


def main() -> None:
    asyncio.run(chat_loop())


if __name__ == "__main__":
    main()
