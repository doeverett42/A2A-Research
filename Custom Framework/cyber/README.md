# Cyber incident review framework

This folder changes the five normal remote agents into Identity, Endpoint,
Network, Web and DNS, and Incident Correlation analysts. The transport and A2A
task store stay the same.

The checked-in `CYBER-SANDBOX-A` and `CYBER-SANDBOX-B` packets use only
fictional local logs, reserved test IP addresses, `.invalid` domains, and
harmless text. These are the fixed inputs for the current EA-A3 and six
follow-up Gap 3 experiments. No dataset download is needed.

## Rebuild the sandbox packets

```powershell
python -m cyber.case_builder build-sandbox
```

The packet hash must stay the same when the source CSV files and selection rule
do not change. Hidden answer keys are written to `data/cyber_cases/answer_keys`
and are never loaded into agent prompts.

## Run one clean five-agent baseline

Start Ollama if it is not already running:

```powershell
ollama serve
```

Start all five configured agents in a separate terminal:

```powershell
python -m cyber.services
```

Run the clean fixed plan in another terminal:

```powershell
python -m cyber.baseline --case CYBER-SANDBOX-A
```

The report is saved under `logs/audit/cyber_baselines`. It includes the packet
hash, fixed plan, remote responses, host output, endpoint/task/context bindings,
new task rows, and matching `case_evidence` rows.

## Run the translated Gap 3 tests

The same commands in `security/event_attribution/README.md` run EA-A3 and the
six follow-up cases. Their fixed plans now use the External Security Reviewer
Test Agent, Identity Analyst, and Incident Correlation Analyst. The default live
message uses `CYBER-SANDBOX-A`, so the database rows can be joined to one known
packet hash while canary propagation is measured.

`cyber.services` starts all five normal agents for baseline runs and host chat.
`security.event_attribution.live_services` starts the test server and the two
normal agents used by the fixed experiments. Both commands use the same local
service startup and shutdown helper in `common/services.py`. Run one service
command at a time because their agent ports overlap.
