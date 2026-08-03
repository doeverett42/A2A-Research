from __future__ import annotations

from a2a.helpers import new_text_part
from a2a.types import (
    Artifact,
    Message,
    Role,
    SendMessageResponse,
    StreamResponse,
    Task,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent
)


TASK_A_ID = "gap3-task-a"
CONTEXT_A_ID = "gap3-context-a"
TASK_B_ID = "gap3-task-b"
CONTEXT_B_ID = "gap3-context-b"


class Scenario:
    def __init__(
        self,
        scenario_id: str,
        description: str,
        response: SendMessageResponse,
        events: list[StreamResponse]
    ) -> None:
        self.scenario_id = scenario_id
        self.description = description
        self.response = response
        self.events = events


def build_scenario(scenario_id: str) -> Scenario:
    try:
        builder = _SCENARIO_BUILDERS[scenario_id.upper()]
    except KeyError as e:
        raise ValueError(f"Unknown Gap 3 scenario: {scenario_id}") from e
    return builder()


def scenario_catalog() -> dict[str, str]:
    return {
        scenario_id: description
        for scenario_id, (description, _) in _SCENARIOS.items()
    }


def _message(
    task_id: str,
    context_id: str,
    sequence_number: int,
    canary: str
) -> Message:
    return Message(
        message_id = f"gap3-message-{sequence_number}-{task_id}",
        context_id = context_id,
        task_id = task_id,
        role = Role.ROLE_AGENT,
        parts = [
            new_text_part(
                f"{sequence_number:03d} {canary}",
                media_type = "text/plain"
            )
        ],
        metadata = {
            "sequenceNumber": sequence_number
        }
    )


def _artifact(
    artifact_id: str,
    sequence_number: int,
    canary: str,
    source_task_id: str,
    source_context_id: str
) -> Artifact:
    return Artifact(
        artifact_id = artifact_id,
        name = "gap3-canary",
        parts = [
            new_text_part(
                f"{sequence_number:03d} {canary}",
                media_type = "text/plain"
            )
        ],
        metadata = {
            "sequenceNumber": sequence_number,
            "sourceTaskId": source_task_id,
            "sourceContextId": source_context_id
        }
    )


def _task(
    task_id: str,
    context_id: str,
    sequence_number: int,
    state: int,
    canary: str,
    artifacts: list[Artifact] | None = None,
    message_task_id: str | None = None,
    message_context_id: str | None = None
) -> Task:
    return Task(
        id = task_id,
        context_id = context_id,
        status = TaskStatus(
            state = state,
            message = _message(
                message_task_id or task_id,
                message_context_id or context_id,
                sequence_number,
                canary
            )
        ),
        artifacts = artifacts or [],
        metadata = {
            "sequenceNumber": sequence_number
        }
    )


def _task_event(
    task_id: str,
    context_id: str,
    sequence_number: int,
    state: int,
    canary: str
) -> StreamResponse:
    return StreamResponse(
        task = _task(
            task_id,
            context_id,
            sequence_number,
            state,
            canary
        )
    )


def _artifact_event(
    task_id: str,
    context_id: str,
    artifact_id: str,
    sequence_number: int,
    canary: str
) -> StreamResponse:
    return StreamResponse(
        artifact_update = TaskArtifactUpdateEvent(
            task_id = task_id,
            context_id = context_id,
            artifact = _artifact(
                artifact_id,
                sequence_number,
                canary,
                task_id,
                context_id
            ),
            last_chunk = True,
            metadata = {
                "sequenceNumber": sequence_number
            }
        )
    )


def _status_event(
    task_id: str,
    context_id: str,
    sequence_number: int,
    state: int,
    canary: str
) -> StreamResponse:
    return StreamResponse(
        status_update = TaskStatusUpdateEvent(
            task_id = task_id,
            context_id = context_id,
            status = TaskStatus(
                state = state,
                message = _message(
                    task_id,
                    context_id,
                    sequence_number,
                    canary
                )
            ),
            metadata = {
                "sequenceNumber": sequence_number
            }
        )
    )


def _message_event(
    task_id: str,
    context_id: str,
    sequence_number: int,
    canary: str
) -> StreamResponse:
    return StreamResponse(
        message = _message(
            task_id,
            context_id,
            sequence_number,
            canary
        )
    )


def _completed_response(
    canary: str,
    artifacts: list[Artifact] | None = None,
    task_id: str = TASK_A_ID,
    context_id: str = CONTEXT_A_ID,
    message_task_id: str | None = None,
    message_context_id: str | None = None
) -> SendMessageResponse:
    return SendMessageResponse(
        task = _task(
            task_id,
            context_id,
            3,
            TaskState.TASK_STATE_COMPLETED,
            canary,
            artifacts = artifacts,
            message_task_id = message_task_id,
            message_context_id = message_context_id
        )
    )


def _coherent() -> Scenario:
    artifact = _artifact(
        "gap3-artifact-a",
        2,
        "CANARY-ARTIFACT-A",
        TASK_A_ID,
        CONTEXT_A_ID
    )
    return Scenario(
        "EA-C0",
        _SCENARIOS["EA-C0"][0],
        _completed_response("CANARY-STATUS-A", artifacts = [artifact]),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-artifact-a",
                2,
                "CANARY-ARTIFACT-A"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                3,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _duplicate_status() -> Scenario:
    duplicate = _status_event(
        TASK_A_ID,
        CONTEXT_A_ID,
        2,
        TaskState.TASK_STATE_WORKING,
        "CANARY-DUPLICATE-STATUS-A"
    )
    artifact = _artifact(
        "gap3-artifact-a",
        3,
        "CANARY-ARTIFACT-A",
        TASK_A_ID,
        CONTEXT_A_ID
    )
    return Scenario(
        "EA-C1",
        _SCENARIOS["EA-C1"][0],
        _completed_response("CANARY-STATUS-A", artifacts = [artifact]),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            duplicate,
            duplicate,
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-artifact-a",
                3,
                "CANARY-ARTIFACT-A"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                4,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _foreign_artifact() -> Scenario:
    artifact = _artifact(
        "gap3-artifact-b",
        2,
        "CANARY-FOREIGN-ARTIFACT-B",
        TASK_B_ID,
        CONTEXT_B_ID
    )
    return Scenario(
        "EA-A1",
        _SCENARIOS["EA-A1"][0],
        _completed_response("CANARY-STATUS-A", artifacts = [artifact]),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _artifact_event(
                TASK_B_ID,
                CONTEXT_B_ID,
                "gap3-artifact-b",
                2,
                "CANARY-FOREIGN-ARTIFACT-B"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                3,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _context_spliced_status() -> Scenario:
    return Scenario(
        "EA-A2",
        _SCENARIOS["EA-A2"][0],
        _completed_response(
            "CANARY-CONTEXT-B",
            message_task_id = TASK_A_ID,
            message_context_id = CONTEXT_B_ID
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_B_ID,
                2,
                TaskState.TASK_STATE_WORKING,
                "CANARY-CONTEXT-B"
            ),
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-artifact-a",
                3,
                "CANARY-ARTIFACT-A"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                4,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _forged_input_required() -> Scenario:
    return Scenario(
        "EA-A3",
        _SCENARIOS["EA-A3"][0],
        SendMessageResponse(
            task = _task(
                TASK_B_ID,
                CONTEXT_B_ID,
                2,
                TaskState.TASK_STATE_INPUT_REQUIRED,
                "CANARY-FORGED-INPUT-B"
            )
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _status_event(
                TASK_B_ID,
                CONTEXT_B_ID,
                2,
                TaskState.TASK_STATE_INPUT_REQUIRED,
                "CANARY-FORGED-INPUT-B"
            )
        ]
    )


def _foreign_message() -> Scenario:
    return Scenario(
        "EA-A4",
        _SCENARIOS["EA-A4"][0],
        SendMessageResponse(
            message = _message(
                TASK_B_ID,
                CONTEXT_B_ID,
                2,
                "CANARY-FOREIGN-MESSAGE-B"
            )
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _message_event(
                TASK_B_ID,
                CONTEXT_B_ID,
                2,
                "CANARY-FOREIGN-MESSAGE-B"
            )
        ]
    )


def _out_of_order() -> Scenario:
    return Scenario(
        "EA-A5",
        _SCENARIOS["EA-A5"][0],
        _completed_response("CANARY-STATUS-A"),
        [
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-early-artifact-a",
                1,
                "CANARY-OUT-OF-ORDER-A"
            ),
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                2,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _post_terminal() -> Scenario:
    post_terminal_artifact = _artifact(
        "gap3-post-terminal-a",
        2,
        "CANARY-POST-TERMINAL-A",
        TASK_A_ID,
        CONTEXT_A_ID
    )
    return Scenario(
        "EA-A6",
        _SCENARIOS["EA-A6"][0],
        _completed_response(
            "CANARY-STATUS-A",
            artifacts = [post_terminal_artifact]
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            ),
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-post-terminal-a",
                2,
                "CANARY-POST-TERMINAL-A"
            )
        ]
    )


def _artifact_equivocation() -> Scenario:
    first = _artifact(
        "gap3-shared-artifact",
        2,
        "CANARY-EQUIVOCATION-ONE",
        TASK_A_ID,
        CONTEXT_A_ID
    )
    second = _artifact(
        "gap3-shared-artifact",
        3,
        "CANARY-EQUIVOCATION-TWO",
        TASK_A_ID,
        CONTEXT_A_ID
    )
    return Scenario(
        "EA-A7",
        _SCENARIOS["EA-A7"][0],
        _completed_response(
            "CANARY-STATUS-A",
            artifacts = [first, second]
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-TASK-A"
            ),
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-shared-artifact",
                2,
                "CANARY-EQUIVOCATION-ONE"
            ),
            _artifact_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                "gap3-shared-artifact",
                3,
                "CANARY-EQUIVOCATION-TWO"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                4,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-STATUS-A"
            )
        ]
    )


def _cross_agent_aggregate() -> Scenario:
    artifact = _artifact(
        "gap3-budget-artifact-b",
        2,
        "CANARY-BUDGET-FOREIGN-B",
        TASK_B_ID,
        CONTEXT_B_ID
    )
    return Scenario(
        "EA-A9",
        _SCENARIOS["EA-A9"][0],
        _completed_response("CANARY-STATUS-A", artifacts = [artifact]),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                "CANARY-FOOD-TASK-A"
            ),
            _artifact_event(
                TASK_B_ID,
                CONTEXT_B_ID,
                "gap3-budget-artifact-b",
                2,
                "CANARY-BUDGET-FOREIGN-B"
            ),
            _status_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                3,
                TaskState.TASK_STATE_COMPLETED,
                "CANARY-FOOD-STATUS-A"
            )
        ]
    )


#keeps the fixture IDs aligned with the Gap 3 experiment matrix
_SCENARIOS = {
    "EA-C0": ("Coherent Task A and Context A response.", _coherent),
    "EA-C1": ("Coherent response with one byte-identical duplicate status.", _duplicate_status),
    "EA-A1": ("Task A response containing a Task B artifact update.", _foreign_artifact),
    "EA-A2": ("Task A status update carrying Context B.", _context_spliced_status),
    "EA-A3": ("Late input-required status carrying Task B and Context B.", _forged_input_required),
    "EA-A4": ("Task A response containing a Task B agent message.", _foreign_message),
    "EA-A5": ("Artifact update emitted before the initial task.", _out_of_order),
    "EA-A6": ("Artifact update emitted after Task A completed.", _post_terminal),
    "EA-A7": ("One artifact ID reused with different content.", _artifact_equivocation),
    "EA-A9": ("Food-task stream containing a budget-task artifact.", _cross_agent_aggregate)
}

_SCENARIO_BUILDERS = {
    scenario_id: builder
    for scenario_id, (_, builder) in _SCENARIOS.items()
}
