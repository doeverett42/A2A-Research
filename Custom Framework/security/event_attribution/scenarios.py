from __future__ import annotations

#deterministic response fixtures for the local gap 3 server
#nothing in this file calls an llm or performs an outside action. each builder
#just creates valid a2a protobuf objects with known ids, states, and harmless
#canary text so the same response can be replayed during every control or attack.
#
#task a/context a are the starting pair. task b/context b are the alternate pair
#used to see whether another tuple, or half of another tuple, is accepted later.
#the sequence numbers make the intended event order easy to verify in the logs.
#ea-a3 and the six follow-ups share five fixtures: two coherent controls and
#three tuple changes. the do cases reuse ea-a3 at different places in the plan.
#normal responses check sdk parsing; streaming shows the actual tuple change.

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
HOST_CONTINUATION_CANARY = "CANARY-HOST-CONTINUATION"
EA_A3_COMPLETION_CANARY = "CANARY-EA-A3-COMPLETED-B"
EA_C2_COMPLETION_CANARY = "CANARY-EA-C2-COMPLETED-A-A"
EA_TM1_COMPLETION_CANARY = "CANARY-EA-TM1-COMPLETED-B-A"
EA_TM2_COMPLETION_CANARY = "CANARY-EA-TM2-COMPLETED-A-B"


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


def build_scenario(
    scenario_id: str,
    run_canary: str = ""
) -> Scenario:
    try:
        _, builder = _SCENARIOS[scenario_id.upper()]
    except KeyError as e:
        raise ValueError(f"Unknown Gap 3 scenario: {scenario_id}") from e
    #build a fresh object every time so one run's added canary cannot leak into
    #the next run through a reused protobuf instance.
    scenario = builder()
    _add_run_canary(scenario, run_canary)
    return scenario


def scenario_catalog() -> dict[str, str]:
    return {
        scenario_id: description
        for scenario_id, (description, _) in _SCENARIOS.items()
    }


def continuation_handles(
    scenario_id: str
) -> tuple[str, str] | None:
    specification = _CONTINUATION_SPECS.get(scenario_id.upper())
    if specification is None:
        return None
    return specification[0], specification[1]


def build_continuation_scenario(
    scenario_id: str,
    run_canary: str = ""
) -> Scenario:
    scenario_id = scenario_id.upper()
    try:
        task_id, context_id, input_canary, completion_canary = (
            _CONTINUATION_SPECS[scenario_id]
        )
    except KeyError as e:
        raise ValueError(
            f"Scenario does not support continuation: {scenario_id}"
        ) from e

    #a continuation stays on the tuple returned by the initial fixture and
    #moves that same task from input-required to completed.
    completion_canaries = f"{input_canary} {completion_canary}"
    scenario = Scenario(
        scenario_id,
        f"{task_id} and {context_id} continuation completes.",
        _completed_response(
            completion_canaries,
            task_id = task_id,
            context_id = context_id
        ),
        [
            _status_event(
                task_id,
                context_id,
                3,
                TaskState.TASK_STATE_COMPLETED,
                completion_canaries
            )
        ]
    )
    _add_run_canary(scenario, run_canary)
    return scenario


def _add_run_canary(scenario: Scenario, run_canary: str) -> None:
    if not run_canary:
        return
    _append_response_canary(scenario.response, run_canary)
    _append_event_canary(scenario.events[-1], run_canary)


def _append_response_canary(response, run_canary: str) -> None:
    if response.HasField("task"):
        if response.task.artifacts:
            _append_part_canary(
                response.task.artifacts[-1].parts,
                run_canary
            )
        elif response.task.status.HasField("message"):
            _append_part_canary(
                response.task.status.message.parts,
                run_canary
            )


def _append_event_canary(event: StreamResponse, run_canary: str) -> None:
    if event.HasField("task"):
        if event.task.artifacts:
            _append_part_canary(event.task.artifacts[-1].parts, run_canary)
        elif event.task.status.HasField("message"):
            _append_part_canary(event.task.status.message.parts, run_canary)
    elif event.HasField("status_update"):
        if event.status_update.status.HasField("message"):
            _append_part_canary(
                event.status_update.status.message.parts,
                run_canary
            )
    elif event.HasField("artifact_update"):
        _append_part_canary(
            event.artifact_update.artifact.parts,
            run_canary
        )


def _append_part_canary(parts, run_canary: str) -> None:
    for part in reversed(parts):
        if part.WhichOneof("content") != "text":
            continue
        if run_canary not in part.text:
            part.text = f"{part.text} {run_canary}".strip()
        return


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
    artifacts: list[Artifact] | None = None
) -> Task:
    return Task(
        id = task_id,
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


def _completed_response(
    canary: str,
    artifacts: list[Artifact] | None = None,
    task_id: str = TASK_A_ID,
    context_id: str = CONTEXT_A_ID
) -> SendMessageResponse:
    return SendMessageResponse(
        task = _task(
            task_id,
            context_id,
            3,
            TaskState.TASK_STATE_COMPLETED,
            canary,
            artifacts = artifacts
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


def _input_required(
    scenario_id: str,
    task_id: str,
    context_id: str,
    start_canary: str,
    input_canary: str
) -> Scenario:
    #all four continuation cases share this two-event shape. the first event is
    #a coherent a/a working task; the second chooses the tuple being tested.
    return Scenario(
        scenario_id,
        _SCENARIOS[scenario_id][0],
        SendMessageResponse(
            task = _task(
                task_id,
                context_id,
                2,
                TaskState.TASK_STATE_INPUT_REQUIRED,
                input_canary
            )
        ),
        [
            _task_event(
                TASK_A_ID,
                CONTEXT_A_ID,
                1,
                TaskState.TASK_STATE_WORKING,
                start_canary
            ),
            _status_event(
                task_id,
                context_id,
                2,
                TaskState.TASK_STATE_INPUT_REQUIRED,
                input_canary
            )
        ]
    )


def _coherent_input_required() -> Scenario:
    #control for tm-1 and tm-2: neither half of the tuple changes.
    return _input_required(
        "EA-C2",
        TASK_A_ID,
        CONTEXT_A_ID,
        "CANARY-CONTROL-START-A-A",
        "CANARY-CONTROL-INPUT-A-A"
    )


def _task_b_context_a_input_required() -> Scenario:
    #tm-1: only the task id changes, leaving the original context id in place.
    return _input_required(
        "EA-TM1",
        TASK_B_ID,
        CONTEXT_A_ID,
        "CANARY-TM1-START-A-A",
        "CANARY-TM1-SPLIT-B-A"
    )


def _task_a_context_b_input_required() -> Scenario:
    #tm-2: only the context id changes, leaving the original task id in place.
    return _input_required(
        "EA-TM2",
        TASK_A_ID,
        CONTEXT_B_ID,
        "CANARY-TM2-START-A-A",
        "CANARY-TM2-SPLIT-A-B"
    )


def _forged_input_required() -> Scenario:
    #ea-a3: the later input-required event replaces both handles with b/b.
    #the wrapper and host then reveal whether those later handles are trusted.
    return _input_required(
        "EA-A3",
        TASK_B_ID,
        CONTEXT_B_ID,
        "CANARY-TASK-A",
        "CANARY-FORGED-INPUT-B"
    )


#these are the only fixtures needed by ea-a3 and the six follow-up experiments
_SCENARIOS = {
    "EA-C0": ("Coherent Task A and Context A response.", _coherent),
    "EA-C2": ("Coherent input-required control retaining Task A and Context A.", _coherent_input_required),
    "EA-TM1": ("Input-required transition splicing Task B into Context A.", _task_b_context_a_input_required),
    "EA-TM2": ("Input-required transition splicing Context B into Task A.", _task_a_context_b_input_required),
    "EA-A3": ("Late input-required status carrying Task B and Context B.", _forged_input_required)
}


_CONTINUATION_SPECS = {
    #the server uses these exact tuples to recognize the runner's harmless
    #follow-up message and return the matching completed response.
    "EA-C2": (
        TASK_A_ID,
        CONTEXT_A_ID,
        "CANARY-CONTROL-INPUT-A-A",
        EA_C2_COMPLETION_CANARY
    ),
    "EA-TM1": (
        TASK_B_ID,
        CONTEXT_A_ID,
        "CANARY-TM1-SPLIT-B-A",
        EA_TM1_COMPLETION_CANARY
    ),
    "EA-TM2": (
        TASK_A_ID,
        CONTEXT_B_ID,
        "CANARY-TM2-SPLIT-A-B",
        EA_TM2_COMPLETION_CANARY
    ),
    "EA-A3": (
        TASK_B_ID,
        CONTEXT_B_ID,
        "CANARY-FORGED-INPUT-B",
        EA_A3_COMPLETION_CANARY
    )
}
