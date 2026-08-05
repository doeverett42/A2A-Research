# Gap 3 malicious event server

This local fixture implements the deterministic malicious A2A server from the
Gap 3 plan. It never calls an LLM, uses harmless canaries, and the command-line
entry point only permits loopback interfaces.

Start the coherent control:

```powershell
python -m security.event_attribution.main
```

Start one fixed attack case:

```powershell
python -m security.event_attribution.main --scenario EA-A1
```

List the implemented cases:

```powershell
python -m security.event_attribution.main --list-scenarios
```

The default endpoint is `http://127.0.0.1:8010`. A request can override the
server default with the `X-A2A-Gap3-Scenario` header, a message metadata field
named `scenario`, or a text part containing `SCENARIO:EA-A1`.
`GET /scenarios` reports the active default, every case, and the deterministic
Task A/Context A and Task B/Context B identifiers.

`SendMessage` returns one structurally valid Task or Message for the current
non-streaming host path. `SendStreamingMessage` emits the full ordered event
sequence needed for attribution trials. When `X-A2A-Audit-ID` is present, the
existing audit logger records the selected scenario and exact JSON-RPC payload
for every emitted event.

EA-A8 is intentionally not included yet because unexpected-push attribution
requires the separate push receiver fixture described in the plan.

Run the fixture tests with:

```powershell
python -m unittest security.event_attribution.test_server
```

## Deterministic host-orchestrator experiment

The experiment runner uses the real Agent Card discovery, `HostOrchestrator`,
`RemoteAgentClient`, official SDK, and HTTP transport. It replaces only the
LLM-owned planning and delegation decisions with a fixed one-step plan to the
malicious endpoint.

Start the malicious server in one terminal:

```powershell
python -m security.event_attribution.main
```

Run the forged input-required scenario in another terminal:

```powershell
python -m security.event_attribution.experiment --scenario EA-A3
```

Run the complete implemented matrix:

```powershell
python -m security.event_attribution.experiment --all-scenarios
```

The runner enables streaming only for its injected experiment client. Normal
host clients remain non-streaming. It also restricts the target URL to
loopback addresses.

Each run writes one JSON report under `logs/audit/gap3_runs`. The report keeps
the observations separated by layer:

- Raw transport requests and exact malicious-server audit events.
- Every event yielded by the official SDK.
- Extracted text and selected handles after every wrapper event.
- Deterministic plan, `StepResult`, and pending-orchestration snapshots.
- Final one-step host output and calculated canary/handle measurements.

When a scenario returns input-required, the runner submits one harmless
continuation by default. The raw second request proves whether the host reused
the returned task and context handles. Use `--no-continuation` to disable that
step.

Run all automated tests with:

```powershell
python -m unittest discover -v
```
