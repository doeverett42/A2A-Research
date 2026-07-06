from __future__ import annotations

from a2a.helpers import new_task_from_user_message, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import TaskState

from common.logging import logger
from remote.agent import DeepSeekAgent, TextAgent

#A thin A2A protocol bridge around a text agent
class DeepSeekAgentExecutor(AgentExecutor):
    def __init__(self, agent: TextAgent | None = None) -> None:
        self.agent = agent or DeepSeekAgent()

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        if context.current_task:
            task = context.current_task
        else:
            if context.message is None:
                raise ValueError("A2A request did not include a message.")
            task = new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)

        updater = TaskUpdater(
            event_queue=event_queue,
            task_id=task.id,
            context_id=task.context_id,
        )

        await updater.update_status(
            state=TaskState.TASK_STATE_WORKING,
            message=new_text_message(
                "Remote DeepSeek agent is processing the request.",
                media_type="text/plain",
                context_id=task.context_id,
                task_id=task.id,
            ),
        )

        try:
            query = context.get_user_input().strip()
            if not query:
                result = "No text input was provided."
            else:
                result = await self.agent.run(query)

            await updater.add_artifact(
                parts=[new_text_part(result, media_type="text/plain")],
                name="response",
                last_chunk=True,
            )
            await updater.update_status(
                state=TaskState.TASK_STATE_COMPLETED,
                message=new_text_message(
                    "Request completed.",
                    media_type="text/plain",
                    context_id=task.context_id,
                    task_id=task.id,
                ),
            )
        except Exception:
            logger.exception("Remote agent execution failed.")
            await updater.failed(
                message=new_text_message(
                    "Remote agent execution failed.",
                    media_type="text/plain",
                    context_id=task.context_id,
                    task_id=task.id,
                )
            )

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        if context.task_id is None or context.context_id is None:
            raise ValueError("Cannot cancel a request without task/context IDs.")

        updater = TaskUpdater(
            event_queue=event_queue,
            task_id=context.task_id,
            context_id=context.context_id,
        )
        await updater.cancel(
            message=new_text_message(
                "Request canceled.",
                media_type="text/plain",
                context_id=context.context_id,
                task_id=context.task_id,
            )
        )
