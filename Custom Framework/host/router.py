#host planning and routing logic
#binds host plan steps to discovered agent card endpoints

from __future__ import annotations

from typing import TYPE_CHECKING

from host.discovery import RemoteAgentInfo

if TYPE_CHECKING:
    from host.agent import HostAgent


class PlanStep:
    def __init__(self, step_id: int, agent_index: int, agent_name: str, remote_url: str, task: str, depends_on: list[int]) -> None:
        self.step_id = step_id
        self.agent_index = agent_index
        self.agent_name = agent_name
        self.remote_url = remote_url
        self.task = task
        self.depends_on = depends_on


class DelegationPlan:
    def __init__(self, mode: str, reason: str, steps: list[PlanStep]) -> None:
        self.mode = mode
        self.reason = reason
        self.steps = steps


class MultiRemoteRouter:
    async def plan(self, user_message: str, agents: list[RemoteAgentInfo], host_agent: "HostAgent") -> DelegationPlan:
        if not user_message.strip():
            raise ValueError("Cannot plan an empty user message.")
        if not agents:
            return DelegationPlan(
                mode = "host",
                reason = "no remote agents are currently discoverable",
                steps = []
            )

        request_analysis = await host_agent.analyze_request(user_message)
        delegate_candidate = request_analysis.get("delegate_candidate")
        analysis_reason = request_analysis.get("reason")

        if not isinstance(delegate_candidate, bool):
            raise ValueError("Host LLM request analysis must contain a delegate_candidate boolean.")
        if not isinstance(analysis_reason, str) or not analysis_reason.strip():
            raise ValueError("Host LLM request analysis must contain a reason.")
        if not delegate_candidate:
            return DelegationPlan(
                mode = "host",
                reason = analysis_reason.strip(),
                steps = []
            )

        decision = await host_agent.assess_delegation(user_message, agents)
        agent_indexes = decision.get("agent_indexes")
        reason = decision.get("reason")

        if not isinstance(agent_indexes, list) or not all(_is_integer(value) for value in agent_indexes):
            raise ValueError("Host LLM delegation decision must contain a list of agent indexes.")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Host LLM delegation decision must contain a reason.")
        if len(agent_indexes) != len(set(agent_indexes)):
            raise ValueError("Host LLM delegation decision contains duplicate agent indexes.")
        if any(value < 0 or value >= len(agents) for value in agent_indexes):
            raise ValueError("Host LLM delegation decision contains an invalid agent index.")

        if not agent_indexes:
            return DelegationPlan(
                mode = "host",
                reason = reason.strip(),
                steps = []
            )

        plan_data = await host_agent.create_plan(user_message, agents, agent_indexes)
        steps = _validated_steps(plan_data, agents)
        if not steps:
            raise ValueError("Host LLM plan must contain at least one remote plan step.")
        if any(step.agent_index not in agent_indexes for step in steps):
            raise ValueError("Host LLM plan selected an agent outside the delegation decision.")

        return DelegationPlan(
            mode = "delegate",
            reason = reason.strip(),
            steps = steps
        )


def _validated_steps(plan_data: list[dict[str, object]], agents: list[RemoteAgentInfo]) -> list[PlanStep]:
    steps = []
    earlier_step_ids = set()

    for step_data in plan_data:
        step_id = step_data.get("id")
        agent_index = step_data.get("agent_index")
        task = step_data.get("task")
        depends_on = step_data.get("depends_on")

        if not _is_integer(step_id) or step_id < 1:
            raise ValueError("Every plan step id must be a positive integer.")
        if step_id in earlier_step_ids:
            raise ValueError(f"Plan step id {step_id} is duplicated.")
        if not _is_integer(agent_index) or agent_index < 0 or agent_index >= len(agents):
            raise ValueError(f"Plan step {step_id} contains an invalid agent index.")
        if not isinstance(task, str) or not task.strip():
            raise ValueError(f"Plan step {step_id} must contain a task.")
        if not isinstance(depends_on, list) or not all(_is_integer(value) for value in depends_on):
            raise ValueError(f"Plan step {step_id} must contain a list of dependency step ids.")
        if len(depends_on) != len(set(depends_on)):
            raise ValueError(f"Plan step {step_id} contains duplicate dependencies.")

        missing_dependencies = [value for value in depends_on if value not in earlier_step_ids]
        if missing_dependencies:
            raise ValueError(
                f"Plan step {step_id} depends on steps that do not appear earlier: {missing_dependencies}."
            )

        agent = agents[agent_index]
        steps.append(
            PlanStep(
                step_id = step_id,
                agent_index = agent_index,
                agent_name = agent.name,
                remote_url = agent.url,
                task = task.strip(),
                depends_on = depends_on
            )
        )
        earlier_step_ids.add(step_id)

    return steps


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
