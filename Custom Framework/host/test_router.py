from __future__ import annotations

import unittest

from host.router import MultiRemoteRouter


class FakeAgent:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url


class IncompletePlanningAgent:
    async def analyze_request(self, user_message: str) -> dict:
        return {
            "delegate_candidate": True,
            "reason": "two specialists are required"
        }

    async def assess_delegation(self, user_message: str, agents: list) -> dict:
        return {
            "agent_indexes": [0, 1],
            "reason": "both cards directly match the request"
        }

    async def create_plan(
        self,
        user_message: str,
        agents: list,
        agent_indexes: list[int]
    ) -> list[dict]:
        #the malformed plan silently drops the second required specialist.
        return [
            {
                "id": 1,
                "agent_index": 0,
                "task": "complete the first part",
                "depends_on": []
            }
        ]


class MultiRemoteRouterTests(unittest.IsolatedAsyncioTestCase):
    async def test_plan_cannot_drop_a_required_agent(self) -> None:
        agents = [
            FakeAgent("First Agent", "http://127.0.0.1:8001"),
            FakeAgent("Second Agent", "http://127.0.0.1:8002")
        ]

        with self.assertRaisesRegex(ValueError, "omitted required agent"):
            await MultiRemoteRouter().plan(
                "Use both specialists.",
                agents,
                IncompletePlanningAgent()
            )


if __name__ == "__main__":
    unittest.main()
