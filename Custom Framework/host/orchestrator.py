# host orchestrator
# coordinates discovery, planning, remote execution, and result synthesis

from __future__ import annotations

from common.logging import logger
from host.agent import HostAgent
from host.client import RemoteAgentClient
from host.discovery import AgentDiscovery
from host.router import DelegationPlan, MultiRemoteRouter, PlanStep


class StepResult:
    def __init__(self, step: PlanStep, response: str = "", error: str = "") -> None:
        self.step = step
        self.response = response
        self.error = error


class OrchestrationResult:
    def __init__(self, plan: DelegationPlan, step_results: list[StepResult], response: str) -> None:
        self.plan = plan
        self.step_results = step_results
        self.response = response


class HostOrchestrator:
    def __init__(self, agent: HostAgent, discovery: AgentDiscovery, router: MultiRemoteRouter, timeout_seconds: int) -> None:
        self.agent = agent
        self.discovery = discovery
        self.router = router
        self.timeout_seconds = timeout_seconds
        self.remote_clients = {}

    async def run(self, user_message: str) -> OrchestrationResult:
        agents = await self.discovery.discover()
        plan = await self.router.plan(user_message, agents, self.agent)
        _log_plan(plan)

        if not plan.steps:
            response = await self.agent.respond_directly(user_message)
            return OrchestrationResult(plan, [], response)

        step_results = []
        results_by_id = {}

        for step in plan.steps:
            dependencies = [results_by_id[step_id] for step_id in step.depends_on]
            failed_dependencies = [result for result in dependencies if result.error]

            if failed_dependencies:
                failed_ids = ", ".join(str(result.step.step_id) for result in failed_dependencies)
                error = f"Required plan steps failed: {failed_ids}."
                result = StepResult(step, error = error)
                logger.warning("Skipping plan step %s for %s. %s", step.step_id, step.agent_name, error)
            else:
                result = await self._execute_step(user_message, step, dependencies)

            step_results.append(result)
            results_by_id[step.step_id] = result

        successful_results = [result for result in step_results if result.response]
        if not successful_results:
            errors = "; ".join(result.error for result in step_results if result.error)
            raise RuntimeError(f"No plan step completed successfully. {errors}".strip())

        if len(plan.steps) == 1 and not step_results[0].error:
            final_response = step_results[0].response
        else:
            final_response = await self.agent.synthesize(
                user_message,
                plan = _plan_text(plan),
                results = _results_text(step_results)
            )

        return OrchestrationResult(plan, step_results, final_response)

    async def close(self) -> None:
        for client in self.remote_clients.values():
            await client.close()
        self.remote_clients = {}

    async def _execute_step(
        self,
        user_message: str,
        step: PlanStep,
        dependencies: list[StepResult]
    ) -> StepResult:
        dependency_results = [
            f"Step {result.step.step_id} from {result.step.agent_name}:\n{result.response}"
            for result in dependencies
        ]
        delegated_request = await self.agent.prepare_delegation(
            user_message,
            agent_name = step.agent_name,
            assigned_task = step.task,
            dependency_results = dependency_results
        )

        logger.info(
            "Executing plan step %s with %s at %s.",
            step.step_id,
            step.agent_name,
            step.remote_url
        )

        try:
            client = self._client_for(step.remote_url)
            response = await client.send_text(delegated_request)
            logger.info("Completed plan step %s with %s.", step.step_id, step.agent_name)
            return StepResult(step, response = response)
        except Exception as e:
            logger.exception("Plan step %s failed with %s.", step.step_id, step.agent_name)
            return StepResult(step, error = f"{type(e).__name__}: {e}")

    def _client_for(self, remote_url: str) -> RemoteAgentClient:
        if remote_url not in self.remote_clients:
            self.remote_clients[remote_url] = RemoteAgentClient(remote_url, self.timeout_seconds)
        return self.remote_clients[remote_url]


def _log_plan(plan: DelegationPlan) -> None:
    logger.info(
        "Validated host plan: mode=%s reason=%s steps=%s",
        plan.mode,
        plan.reason,
        len(plan.steps)
    )
    for step in plan.steps:
        logger.info(
            "Plan step %s: agent=%s dependencies=%s task=%s",
            step.step_id,
            step.agent_name,
            step.depends_on,
            step.task
        )


def _plan_text(plan: DelegationPlan) -> str:
    return "\n".join(
        f"Step {step.step_id}: {step.agent_name}; task: {step.task}; depends on: {step.depends_on}"
        for step in plan.steps
    )


def _results_text(step_results: list[StepResult]) -> str:
    sections = []
    for result in step_results:
        outcome = result.response if result.response else f"failed or skipped: {result.error}"
        sections.append(f"Step {result.step.step_id} from {result.step.agent_name}:\n{outcome}")
    return "\n\n".join(sections)
