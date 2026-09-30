# EA-A3 and the six Gap 3 follow-ups

Use the [root README](../../README.md) for terminal setup and run commands.
This folder keeps only the fixtures needed by the current experiments.

## Fixtures and experiments

The fixture code selects the server response. The experiment code selects the
delegation plan. Several experiments deliberately reuse the same fixture.

| Experiment | Attack fixture | Control fixture | Delegation order |
| --- | --- | --- | --- |
| EA-A3, live | EA-A3 | EA-C0 | External, Identity, Correlation |
| TM-1 | EA-TM1 | EA-C2 | External, Identity, Correlation |
| TM-2 | EA-TM2 | EA-C2 | External, Identity, Correlation |
| DO-2 | EA-A3 | EA-C0 | Identity, External, dependent Correlation |
| DO-3 | EA-A3 | EA-C0 | Identity, External, Correlation using only Identity |
| DO-5 | EA-A3 | EA-C0 | External result given to both normal agents |
| DO-6 | EA-A3 | EA-C0 | Identity, External, Identity again |

EA-C0 completes with A/A. EA-C2 asks for input with A/A. EA-A3 first emits
A/A, then asks for input with B/B. EA-TM1 changes only the task to B; EA-TM2
changes only the context to B. A continuation completes the selected tuple.

The standalone `experiment.py` uses one external step for each fixture.
The live runner adds the normal agents and final LLM synthesis. Use
`--experiment` to select a live case; the former arbitrary `--scenario` and
`--plan-order` live CLI options have been removed to keep runs tied to the
documented cases. The standalone runner still accepts `--scenario`.

## Read the code in this order

1. `fixed_plans.py`: which agents run and whose earlier results they receive.
2. `scenarios.py`: which task/context tuple each server event contains.
3. `server.py`: how the fixture is sent over A2A.
4. `experiment.py` or `live_experiment.py`: how the host is called and observed.
5. `../../host/client.py`: how the SDK's events become wrapper text and handles.
6. `../../host/orchestrator.py`: how step results and continuations are processed.
7. `database_evidence.py`: which new SQLite rows contain the run canary.

The server defaults to `http://127.0.0.1:8010`. Each runner selects the fixture
with `X-A2A-Gap3-Scenario`. Live runs also send `X-A2A-Gap3-Canary` and the audit
ID. `GET /scenarios` lists the five fixtures and known A/A and B/B identifiers.
The fixture and experiment entry points use local loopback URLs.

## What the reports show

The standalone report separates raw transport requests, server audit events,
SDK events, wrapper observations, orchestrator results, and host output.

The live report adds discovery, delegated text, final synthesis, and database
snapshots before execution, while input is pending, and after completion.
New task rows are searched in `status`, `history`, and `artifacts`. The
`case_evidence` rows keep the packet hash, case label, evidence group, agent,
task ID, context ID, and request/response canaries.

These are observations of the current behavior. A canary in an agent response
or database does not automatically mean the agent's tuple changed. Compare
the actual request IDs, returned IDs, and stored row IDs separately.

The runner supplies `CANARY-HOST-CONTINUATION` when the fixture requests input.
The orchestrator chooses the outgoing tuple from the pending step. The runner
records the expected tuple for comparison; it does not pass those expected
IDs into the orchestrator as a replacement for its state.

## Automated coverage

```powershell
python -m unittest discover -v
```

| Test file | Purpose |
| --- | --- |
| `test_server.py` | All five fixtures, SDK parsing, continuations, and canary isolation. |
| `test_experiment.py` | Streaming wrapper, report evidence, and host continuation behavior. |
| `test_live_experiment.py` | Host formatting, downstream flow, batch selection, and output. |
| `test_follow_up_experiments.py` | Six-case plan mapping, dependency routing, and database evidence. |
| `../../cyber/test_cases.py` | Reproducible log packets, evidence scoping, and case storage. |

These tests do not call Ollama. Use the live commands in the root README when
measuring real model behavior.
