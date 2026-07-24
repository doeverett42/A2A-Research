from __future__ import annotations

from a2a.helpers import get_message_text, new_task_from_user_message, new_text_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import Role, TaskState

from common.audit import record_audit_event
from common.logging import logger
from remote.agent import RemoteAgentProtocol

#thin a2a protocol bridge around a remote agent
class RemoteAgentExecutor(AgentExecutor):
    def __init__(self, agent: RemoteAgentProtocol) -> None:
        self.agent = agent

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message_id = context.message.message_id if context.message else ""
        record_audit_event(
            "executor_started",
            message_id = message_id
        )

        if context.current_task:
            task = context.current_task
        else:
            if context.message is None:
                raise ValueError("A2A request did not include a message.")
            task = new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)

        record_audit_event(
            "task_ready",
            message_id = message_id,
            task_id = task.id,
            context_id = task.context_id
        )

        updater = TaskUpdater(
            event_queue = event_queue,
            task_id = task.id,
            context_id  = task.context_id
        )
        query = _task_input(context)

        await updater.update_status(
            state = TaskState.TASK_STATE_WORKING,
            message = new_text_message(
                "Remote agent is processing the request.",
                media_type = "text/plain",
                context_id = task.context_id,
                task_id = task.id
            )
        )

        try:
            record_audit_event(
                "agent_call_started",
                query_length = len(query)
            )
            result = await self.agent.run(query)
            record_audit_event(
                "agent_call_completed",
                response_length = len(result.message)
            )

            if result.requires_input:
                await updater.requires_input(
                    message = new_text_message(
                        result.message,
                        media_type = "text/plain",
                        context_id = task.context_id,
                        task_id = task.id
                    )
                )
                record_audit_event("executor_input_required")
                return

            await updater.add_artifact(
                parts = [new_text_part(result.message, media_type="text/plain")],
                name = "response",
                last_chunk = True
            )
            await updater.update_status(
                state = TaskState.TASK_STATE_COMPLETED,
                message = new_text_message(
                    "Request completed.",
                    media_type = "text/plain",
                    context_id = task.context_id,
                    task_id = task.id
                )
            )
            record_audit_event("executor_completed")
        except Exception as e:
            record_audit_event(
                "executor_failed",
                error_type = type(e).__name__
            )
            logger.exception("Remote agent execution failed.")
            await updater.failed(
                message = new_text_message(
                    f"Remote agent execution failed: {type(e).__name__}: {e}",
                    media_type = "text/plain",
                    context_id = task.context_id,
                    task_id = task.id
                )
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue, ) -> None:
        if context.task_id is None or context.context_id is None:
            raise ValueError("Cannot cancel a request without task/context IDs.")

        updater = TaskUpdater(
            event_queue = event_queue,
            task_id = context.task_id,
            context_id = context.context_id
        )
        await updater.cancel(
            message = new_text_message(
                "Request canceled.",
                media_type = "text/plain",
                context_id = context.context_id,
                task_id = context.task_id
            ) 
        )


#rebuild the task conversation when the user is answering a remote question
def _task_input(context: RequestContext) -> str:
    if context.current_task is None:
        return context.get_user_input().strip()

    messages = []
    for message in context.current_task.history:
        role = "user" if message.role == Role.ROLE_USER else "agent"
        _append_message(messages, role, get_message_text(message))

    if context.current_task.status.HasField("message"):
        _append_message(
            messages,
            "agent",
            get_message_text(context.current_task.status.message)
        )

    _append_message(messages, "user", context.get_user_input())

    return "\n\n".join(messages)


def _append_message(messages: list[str], role: str, text: str) -> None:
    clean_text = text.strip()
    if not clean_text or clean_text == "Remote agent is processing the request.":
        return

    message = f"{role}: {clean_text}"
    if message not in messages:
        messages.append(message)
