# Host CLI entrypoint

from __future__ import annotations

import asyncio

from common.logging import logger
from host.orchestrator import HostOrchestrator


EXIT_COMMANDS = {"exit", "quit", ":q"}


async def chat_loop() -> None:
    orchestrator = HostOrchestrator()

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
