# A2A Gap 3 test framework

This repo runs EA-A3 and its six follow-up experiments against the local log
review framework. The external reviewer is a deterministic test server. The
normal agents use Ollama and keep their tasks in SQLite.

The current defensive analysis is in [THREAT_MODEL.md](THREAT_MODEL.md). It
separates confirmed experiment findings from threats that still need testing.
The single-page [editable threat-model visual](A2A_Gap3_Threat_Model.drawio)
shows the normal and contaminated data paths in separate lanes and can be
imported into Lucidchart or opened in Draw.io.

## Start here

Use Python 3.10 or newer. For a fresh clone, open PowerShell in this folder and
create the local environment once:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

The final audit used Python 3.12.14, `a2a-sdk` 1.1.0, `ollama` 0.6.2,
`python-dotenv` 1.2.2, and `uvicorn` 0.50.0. `requirements.txt` keeps compatible
version ranges, while these versions record the tested setup.

The example configuration uses the local `granite3.3:8b` and `llama3.1:8b`
Ollama models. Pull those models before a live run if they are not installed.
The deterministic tests below do not need Ollama.

```powershell
ollama pull granite3.3:8b
ollama pull llama3.1:8b
```

For later terminals, open this folder and activate the existing environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

The local `.env` supplies URLs, model names, five agent definitions, and database
paths. It is ignored by Git; `.env.example` is the checked-in reproducible
starting point. The checked-in sandbox packets are ready to use.

Run the automated tests first. These use test doubles for model output and do
not require Ollama or running servers:

```powershell
python -m unittest discover -v
```

## EA-A3 without an LLM

In terminal 1:

```powershell
python -m security.event_attribution.main
```

In terminal 2:

```powershell
python -m security.event_attribution.experiment --scenario EA-C0
python -m security.event_attribution.experiment --scenario EA-A3
```

This uses real HTTP, Agent Card discovery, the A2A SDK, the client wrapper, and
the host orchestrator. A fixed one-step plan replaces LLM planning. The host
returns that step's answer directly. `--all-scenarios` checks the five retained
response fixtures; it does not run the six delegation-order experiments.

Stop this server with Ctrl+C before starting the live services below, since
both use port 8010.

## EA-A3 and the six follow-ups with Ollama

In terminal 1, start Ollama if it is not already running:

```powershell
ollama serve
```

In terminal 2, start the external reviewer, Identity Analyst, and Incident
Correlation Analyst together:

```powershell
python -m security.event_attribution.live_services
```

In terminal 3, run a matched pair or the complete set:

```powershell
python -m security.event_attribution.live_experiment --experiment EA-A3 --variant both
python -m security.event_attribution.live_experiment --experiment TM-1 --variant both
python -m security.event_attribution.live_experiment --all-experiments --variant both
```

The last command runs 14 runs: a control followed by an attack for EA-A3 and
each of the six follow-ups. They run one at a time. Each gets its own canary
and audit ID. The runner supplies the case request and one continuation, so
there is no interactive user prompt during an experiment.

Live plans are fixed. The host formats the delegated text without an LLM call;
the normal remote agents and final host synthesis use the configured Ollama
models. The final host answer and report path appear in terminal 3.

| Experiment | What stays under test |
| --- | --- |
| EA-A3 | A/A changes to B/B; the host continues that tuple and passes the result onward. |
| TM-1 | Task B is paired with Context A. |
| TM-2 | Task A is paired with Context B. |
| DO-2 | Identity runs first; Correlation receives the external reviewer's result. |
| DO-3 | The external reviewer pauses the sequential plan; Correlation depends only on Identity. |
| DO-5 | Identity and Correlation both receive the external reviewer's result. |
| DO-6 | Identity runs before and after the external reviewer; compare its requests and stored tasks. |

An experiment completing successfully means the intended run finished. The
report separately shows whether the tuple was accepted and where the canary
appeared. Canary propagation in a declared dependency is not, by itself,
proof that another agent's task ID or stored context was overwritten.

## Normal five-agent chat

To use the framework outside a fixed experiment, start Ollama and then run the
normal services in terminal 2:

```powershell
python -m cyber.services
```

Start the interactive host in terminal 3:

```powershell
python -m host.main
```

Type `cases` to list the local fake cases. A normal request can be as simple as
`Review CYBER-SANDBOX-A and produce one supported incident report.` The host
prints its plan and final response. If an agent asks for required information,
the next user message continues that waiting task. Type `exit`, `quit`, or `:q`
to stop the host.

## Where the code is

| Location | Purpose |
| --- | --- |
| `security/event_attribution/scenarios.py` | The five response fixtures and their continuation tuples. |
| `security/event_attribution/server.py` | Sends those fixtures through A2A. |
| `security/event_attribution/experiment.py` | One-step experiment without Ollama. |
| `security/event_attribution/fixed_plans.py` | The six follow-up definitions, ordering, and dependencies. |
| `security/event_attribution/live_experiment.py` | Runs live cases and records each layer. |
| `security/event_attribution/reporting.py` | Shared plan, tuple, response, and transport report helpers. |
| `security/event_attribution/database_evidence.py` | Reads before/after database evidence. |
| `host/` | Discovery, client wrapper, orchestration, terminal interaction, and synthesis. |
| `remote/` | Normal Ollama agents, A2A execution, and SQLite storage. |
| `cyber/` | Local log packets, packet rebuilding, and a clean five-agent baseline. |
| `common/` | Configuration, prompts, Ollama access, auditing, and shared service startup. |

## Results and storage

Deterministic reports go to `logs/audit/gap3_runs`. Live reports go to
`logs/audit/gap3_live_runs`. They include transport and wrapper observations,
host results, and, for live runs, database checkpoints. The retained historical
reports are indexed in [logs/README.md](logs/README.md).

Keep the local `data/task_stores` folder when comparing historical results.
Fresh live runs snapshot existing task IDs and examine newly created rows, so
old rows do not need to be deleted. The databases are intentionally ignored by
Git. Avoid running another experiment or host chat at the same time as a live
run, since they would share those databases.

For normal five-agent chat or a clean baseline, see [cyber/README.md](cyber/README.md).
For individual test files and report layers, see
[security/event_attribution/README.md](security/event_attribution/README.md).

## Before committing

Run the local quality checks:

```powershell
python -m unittest discover -v
python -m compileall -q common cyber host remote security
python -m pip check
git diff --check -- .
```

The Git repository root is the parent `A2A-Research` folder. Run `git add .`
from this `Custom Framework` folder so sibling paper downloads are not staged by
accident. Keep `.env`, `data/task_stores`, new run logs, and `tmp` local. The 15
selected JSON reports linked by [logs/README.md](logs/README.md) are the only run
outputs intentionally kept for the repository.

After staging, review the exact set before committing:

```powershell
git status --short
git diff --cached --stat
```
