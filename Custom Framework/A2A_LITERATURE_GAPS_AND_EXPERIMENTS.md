# A2A Literature Gaps and Experiment Plan

**Research environment:** custom event-planning A2A framework  
**Literature cutoff:** July 26, 2026  
**Scope:** general A2A security vulnerabilities; audit-evasion and product-specific exploit details are out of scope

## Executive recommendation

The strongest contribution available in this framework is a focused study of **stateful continuation integrity**:

> Does an A2A system keep the authenticated principal, remote endpoint, `taskId`, `contextId`, and task lifecycle state correctly bound across multi-turn work?

A suitable paper/benchmark title would be:

> **StateBinder-A2A: Measuring Identity and Lifecycle Binding in Stateful Agent-to-Agent Workflows**

The proposed context-switching attack is the best starting point, with one important qualification. The current A2A specification says that:

- a follow-up to an `input-required` task uses the same `taskId` and `contextId`;
- a server must infer the context when only a valid `taskId` is supplied; and
- a server **must reject** a request containing a `taskId` paired with a different context's `contextId`.

Therefore, an accepted mismatched pair is an **implementation conformance failure**, not proof that the A2A specification itself permits context switching. The larger and more original question is whether implementations bind the complete tuple:

`(caller identity, remote agent, taskId, contextId, lifecycle state)`

The supplied papers do not empirically study that tuple. The closest later work identifies session lifecycle and identity as broad gaps, but it does not report a dedicated context/task/caller continuation benchmark.

This topic is also clearly distinct from Unit 42's **agent session smuggling**. Session smuggling uses a malicious remote agent to insert semantic instructions during an established multi-turn conversation. The proposed work instead manipulates protocol identifiers, caller ownership, event attribution, ordering, and state transitions.

## What the current framework makes testable

The repository is unusually well suited to this study:

- Five event-planning specialists are exposed as separate A2A servers.
- The host performs discovery, LLM-based routing, delegation, and dependent-step synthesis.
- Remote tasks are persistent SQLite records.
- Remote agents can enter `input-required`, after which the host stores `taskId` and `contextId` and sends a continuation.
- The remote reconstructs the LLM prompt from stored task history before appending the new input.
- An audit header and JSONL events already distinguish HTTP arrival, executor entry, task creation, LLM calls, and terminal outcomes.
- Existing tests provide malformed-JSON and simple sequential message-replay baselines.

### Security-relevant code observations

| Observation | Location | Research significance |
|---|---|---|
| The host keeps one `self.pending` continuation and treats the next input as its answer. | `host/orchestrator.py:46-50`, `82-87`, `107-121` | A future multi-user host needs caller/session ownership on pending work. The current single-user CLI does not provide that boundary. |
| Continuations send both stored identifiers. | `host/client.py:36-52` | Directly supports controlled identifier-swapping trials. |
| The client overwrites its returned task/context handles as it consumes task, status, artifact, or message events. | `host/client.py:60-90` | Motivates malicious-event correlation and event-splicing tests. |
| The remote rebuilds model context from the stored task history. | `remote/executor.py:130-151` | Any incorrect task/context lookup can become semantic context contamination. |
| The server uses the SDK's default `DatabaseTaskStore`. | `remote/task_store.py:13-21` | The SDK scopes tasks by a resolved owner, so authentication context is security-critical. |
| The custom server installs audit middleware but no authentication middleware, and its public Agent Card declares no security scheme. | `remote/server.py:30-46`, `remote/agent_card.py:13-32` | In the present local configuration, all requests reach the SDK as unauthenticated unless another layer supplies identity. This is acceptable for a local prototype but is the correct baseline for an ownership-isolation experiment. |
| Discovery fetches an Agent Card, while client creation later resolves the remote endpoint again. | `host/discovery.py:56-72`, `host/client.py:100-114` | Creates a clean test point for Agent Card time-of-check/time-of-use drift. |

The installed A2A Python SDK is version **1.1.0**. Static inspection shows that it compares the stored task's context with a supplied context and raises an invalid-parameters error on a mismatch. That makes the likely result of a simple `(taskA, contextB)` swap a safe rejection. This should be measured, not assumed. More importantly, the framework currently has no application-level authenticated-principal distinction, so caller ownership is a separate question from pair matching.

## Audit of the supplied paper set

| Supplied file | Main contribution | What it covers | Remaining opening relevant here |
|---|---|---|---|
| `19822_A2ASecBench_A_Protocol_A.pdf` | A2ASecBench, ICLR 2026 | AgentCard spoofing, capability cloaking, cycle overflow, half-open flooding, agent-side request forgery, artifact-triggered script injection; safety-utility evaluation | No reported `taskId`/`contextId` binding, cross-principal task access, continuation race, or mixed-event correlation study |
| `2504.16902v2.pdf` | MAESTRO-based A2A threat analysis | Agent Card spoofing, task replay, schema violations, redirection, escalation, artifact tampering, authentication and session guidance | Mostly qualitative; mentions `input-required` but does not experimentally test multi-turn identifier binding |
| `2505.12490v3.pdf` | Sensitive-data and consent enhancements | Token lifetime, strong authentication, scopes, consent, direct user-to-service channels, prompt-injection evaluation | Does not measure task/context ownership or concurrent continuation behavior |
| `2507.19550v1.pdf` | Ledger identities and x402 micropayments | Verifiable Agent Cards, decentralized discovery, replay-resistant payment nonces | Focus is identity and settlement rather than task-state correlation |
| `2508.02188v3.pdf` | Covert event channel | Storage, timing, and behavioral covert channels | Audit/covert communication is intentionally outside this project's priority |
| `2602.05877v1.pdf` | AgentHeLLM human-centric threat modeling | Poison paths, trigger paths, safety-critical harms | Explicitly leaves production empirical validation for future work and does not model dynamic discovery |
| `2602.13795v2.pdf` | Agent-OSI | Communication, identity boundaries, settlement, replay-resistant receipts | Does not evaluate A2A multi-turn task identifiers |
| `2604.12213v1.pdf` | MMA2A multimodal routing | Native modality preservation, task-completion accuracy, latency | Performance/routing study, not stateful security |
| `2605.09889v1.pdf` | Skill Description Deception | Manipulating self-declared skills to capture routing | Discovery/routing is now a crowded contribution area |

### Implication

A new paper should not lead with Agent Card spoofing, generic skill deception, malformed JSON, simple replay, half-open flooding, cyclic routing, generic prompt injection, SSRF, script-bearing artifacts, or covert channels. Those are already represented in the supplied corpus.

## Important sources not in the ZIP

The following sources materially change the novelty assessment:

1. The [current A2A specification](https://github.com/a2aproject/A2A/blob/main/docs/specification.md) gives normative task/context mismatch, continuation, terminal-state, authorization-scoping, and push-notification requirements.
2. [AgentRFC](https://arxiv.org/abs/2603.23801) formalizes agent-protocol security and reports 42 implementation tests. It classifies A2A session/lifecycle, identity, delegation, consent, and audit properties, but its published A2A adapter description is broad and does not report a focused identifier/caller continuation matrix.
3. [Security Threat Modeling for Emerging AI-Agent Protocols](https://arxiv.org/abs/2602.11327) compares A2A, MCP, Agora, and ANP across protocol lifecycle risks. Its empirical case study is MCP rather than a stateful A2A continuation study.
4. [AIP](https://arxiv.org/abs/2603.24775) proposes public-key verifiable delegation across MCP and A2A. This makes "A2A lacks identity" too broad to claim as new; a study should instead measure how identity is or is not bound to concrete task operations.
5. Unit 42's [agent session smuggling research](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/) demonstrates semantic multi-turn poisoning by a malicious remote agent. Identifier rebinding must be differentiated from this work.
6. [ConVerse](https://aclanthology.org/2026.findings-eacl.170/) contains 864 multi-turn agent-agent privacy/security attacks, but focuses on plausible conversational attacks, tool use, and preference manipulation rather than wire-level task/context binding.
7. [ACIArena](https://aclanthology.org/2026.acl-long.457/) evaluates cascading injection across external inputs, agent profiles, and inter-agent messages. Generic cascading injection is therefore not a strong standalone novelty claim.
8. [Red-Teaming LLM Multi-Agent Systems via Communication Attacks](https://aclanthology.org/2025.findings-acl.349/) already establishes broad communication-based attacks against multiple MAS frameworks.
9. MuleSoft's [A2A Connector release notes](https://docs.mulesoft.com/release-notes/connector/a2a-connector-release-notes-mule-4) are especially relevant empirical motivation. March 2026 fixes added authorization checks for implicit task methods and validation that generated task/context IDs match callback results.
10. The [official Python SDK](https://github.com/a2aproject/a2a-python) now includes a technology compatibility kit and supports protocol 1.0, making reproducible versioned conformance tests a natural contribution.

## Prioritized literature gaps

| Priority | Gap | Novelty after the literature scan | Fit to this framework |
|---|---|---|---|
| 1 | End-to-end continuation binding across caller, agent, task, context, and state | High if framed as a quantitative conformance/isolation study; do not rename it session smuggling | Excellent |
| 2 | Lifecycle-wide replay, equivocation, and concurrency races | High-to-medium; replay is known, but current work rarely measures every state and delivery schedule | Excellent; extends the existing replay baseline |
| 3 | Client-side task/event attribution for streamed, pushed, and aggregated results | High-to-medium; vendor fixes show practical relevance, while academic evaluation is sparse | Good; the host currently trusts yielded event IDs |
| 4 | Agent Card snapshot integrity between discovery, planning, and invocation | Medium; spoofing, cloaking, identity, and TOCTOU concerns are known, but controlled temporal-drift measurement is sparse | Excellent; the host has two resolution moments |
| 5 | Protocol-channel-specific cascading injection through status, artifact, and dependency results | Medium-to-low as a main claim because ConVerse, ACIArena, Unit 42, and communication-attack work now cover the broad class | Good as a secondary experiment |

## Gap 1: Stateful continuation binding

### Attack model

Create two interrupted tasks on the same remote:

- Task A has `(taskId=tA, contextId=cA)` and asks for canary input `ALPHA`.
- Task B has `(taskId=tB, contextId=cB)` and asks for canary input `BRAVO`.

The attack sends a continuation whose identifiers and/or caller are taken from different security domains. No harmful payload is needed; the strings `ALPHA` and `BRAVO` make contamination objectively measurable.

### Trial matrix

| Case | Request | Expected secure behavior |
|---|---|---|
| C0 | caller A, `(tA,cA)`, answer `ALPHA` | Task A advances normally |
| C1 | caller A, `tA` only | Server infers `cA`; Task A advances |
| C2 | caller A, `cA` only, no task | A new task may be created in context A; it must not silently mutate Task A |
| A1 | caller A, `(tA,cB)` | Reject before executor entry |
| A2 | caller A, `(tA,randomContext)` | Reject before executor entry |
| A3 | caller B, `(tA,cA)` | Return the same not-found/not-accessible behavior used for an unknown task; no existence oracle |
| A4 | caller A, `(tA,cA)` after Task A is terminal | Reject as unsupported/invalid; terminal task remains unchanged |
| A5 | caller A, Task A plus `referenceTaskIds=[tB]` | Task B is included only if explicitly authorized and semantically permitted |
| A6 | caller A, valid identifiers from remote 1 sent to remote 2 | Reject without creating or mutating a task |
| A7 | logical user B sends the next host message while user A's work is pending | User B's message must not continue user A's task |

Case A7 is a host-orchestrator isolation test. It matters if the CLI is later exposed as a web service or shared chat endpoint; it is not a vulnerability in the present single-user CLI deployment by itself.

### Measurements

Use these objective outcomes:

- **Mismatch rejection rate:** proportion of A1/A2/A6 trials rejected before executor entry.
- **Executor penetration rate:** attack requests producing `executor_started` or `agent_call_started`.
- **Unauthorized transition rate:** victim tasks whose status, history, or artifacts changed after A3/A7.
- **Cross-context contamination rate:** responses or stored history for A containing B's canary, or vice versa.
- **Wrong-task completion rate:** the attack answer completes a task other than its authorized target.
- **Existence-oracle advantage:** accuracy of distinguishing "foreign task" from "unknown task" using status code, body, size, or latency.
- **Benign continuation completion:** C0/C1 task completion rate.
- **Defense overhead:** added median and p95 continuation latency.

### Required invariants

1. A task's stored `contextId` is immutable.
2. A mismatched task/context pair never reaches the application executor.
3. A task operation is authorized against the caller before the task is retrieved or mutated.
4. A terminal task cannot be reopened by a late message.
5. A host pending continuation is keyed by caller/session, not stored as a single global slot.

### Likely outcome in this repository

Static inspection suggests A1 and A2 should be rejected by A2A Python SDK 1.1.0. That is a useful negative result and validates the harness. A3 and A7 are more likely to expose the research-relevant boundary because the custom server does not currently establish authenticated callers and the host has a single pending slot. These claims must be confirmed experimentally.

## Gap 2: Lifecycle-wide replay and equivocation

The current replay test sends the same initial `messageId` twice sequentially. Expand this into a lifecycle study.

### Trial axes

- **Lifecycle point:** initial request, `input-required` follow-up, cancellation, post-completion message, subscription, and push notification.
- **Schedule:** sequential duplicate, simultaneous duplicate, delayed duplicate, and duplicate after restart.
- **Identifier reuse:** same JSON-RPC request ID only, same `messageId` only, both reused, or new envelope ID with old task identifiers.
- **Payload relation:** byte-identical retry versus same `messageId` with conflicting text.
- **Scope:** same caller, different caller, same context, different context, and different remote.

### Minimum cases

1. Identical initial message delivered twice.
2. Same `messageId`, different text.
3. Identical follow-up delivered twice to `input-required`.
4. Two conflicting follow-ups delivered concurrently.
5. Cancel and follow-up delivered concurrently.
6. Follow-up replayed after completion.
7. Replay after server restart with persistent SQLite state.
8. Duplicate push/status event delivered to the host.

### Measurements

- **Duplicate execution factor:** application/LLM calls divided by unique logical messages.
- **Duplicate side-effect factor:** canary side effects divided by one expected effect.
- **Equivocation acceptance rate:** conflicting payloads accepted under one `messageId`.
- **Terminal-state immutability rate.**
- **State divergence:** disagreement among returned status, persisted status, and host-observed status.
- **Resource amplification:** extra tokens, wall time, task rows, and executor invocations per replay.
- **Benign retry success:** legitimate transport retry still completes without duplicate effect.

Do not automatically label any duplicate delivery a standards violation. The A2A specification gives explicit idempotency guidance for some delivery mechanisms but does not make every `messageId` an exactly-once transaction key. Classify results as:

- spec-mandated conformance failure;
- spec-recommended hardening gap; or
- application-level exactly-once requirement.

## Gap 3: Concurrent continuation and state-transition races

Replay and race attacks overlap, but concurrency deserves its own experiment because a sequentially safe implementation may fail under interleaving.

### Trials

Use a deterministic remote fixture with a barrier so requests enter the handler together:

1. `answer X` versus `answer Y` on one `input-required` task.
2. `cancel` versus valid answer.
3. valid answer versus stale answer.
4. two simultaneous task-only continuations that require context inference.
5. late status update after terminal completion.
6. duplicate terminal events with different terminal states.

Run each schedule repeatedly with randomized sub-millisecond jitter. Record the exact order of HTTP arrival, executor entry, database writes, emitted events, and responses.

### Measurements

- **Single-winner rate:** exactly one conflicting operation takes effect.
- **Double-accept rate:** both operations reach the executor or mutate history.
- **Lost-update rate.**
- **Illegal-transition rate:** observed transition not present in the allowed state machine.
- **Terminal conflict rate:** more than one terminal outcome is accepted.
- **Linearizability result:** whether the trace can be explained by any valid serial ordering.
- **Race window:** jitter interval over which failure remains reproducible.

The deterministic fixture isolates protocol/state behavior. Repeat only accepted or anomalous cases against the Ollama-backed remote to measure semantic impact.

## Gap 4: Response-event attribution and splicing

Most work treats the client as receiving one coherent response from one remote. A malicious or faulty remote can instead mix identifiers across events.

### Trials

Build a controlled malicious A2A test server that emits:

1. Task A followed by an artifact update labeled Task B.
2. Task A followed by a status update with Task A but Context B.
3. A correct artifact followed by a forged `input-required` event carrying another task's identifiers.
4. Events in the wrong order.
5. An event after the stream's terminal state.
6. A duplicate artifact with the same artifact ID but conflicting content.
7. A push notification for an unexpected task.

Test both the official client alone and the framework's `RemoteAgentClient`. The server-side SDK protecting honest servers does not remove the need for a client to distrust a nonconforming or malicious remote.

### Measurements

- **Foreign-event acceptance rate.**
- **Wrong-artifact inclusion rate.**
- **Pending-handle overwrite rate.**
- **Host response contamination rate.**
- **Detection point:** transport parser, SDK client, host wrapper, or nowhere.
- **Benign stream acceptance and latency after adding correlation checks.**

A strong defense pins the expected `(remote identity, taskId, contextId)` after the first task event and rejects every inconsistent subsequent event before text extraction or state updates.

## Gap 5: Agent Card time-of-check/time-of-use drift

The host routes using one fetched Agent Card, then later constructs a client that can resolve the endpoint again. A mutable endpoint can present one card for selection and another for execution.

### Trials

Serve controlled card snapshots:

1. Same card both times (control).
2. Benign skill description during routing, then a different endpoint during invocation.
3. Authentication required during discovery, removed during invocation.
4. Capability disabled during discovery, enabled later.
5. Same semantic card with harmless field ordering changes.
6. Signed/versioned card versus unsigned changed card.
7. Change after a task enters `input-required` but before continuation.

### Measurements

- **Snapshot-binding violation rate:** execution proceeds under a card different from the one approved by routing.
- **Endpoint drift rate.**
- **Security-scheme downgrade rate.**
- **Capability drift acceptance.**
- **False rejection rate for semantically equivalent cards.**
- **Hash/signature verification overhead.**
- **Task utility after card pinning.**

This should be positioned as a temporal extension to AgentCard spoofing and capability cloaking, not as the first discovery attack.

## Secondary experiment: protocol-channel cascading injection

If time remains, evaluate semantic injection at protocol-specific locations:

- Agent Card fields used by the router;
- task status messages;
- artifacts;
- prior-step results inserted into a downstream delegation;
- synthesis inputs.

Measure attack success by deterministic canary behaviors, propagation depth, number of affected agents, task utility, and containment. The novel part would be the **channel and lifecycle comparison** within A2A, not the broad claim that inter-agent prompt injection exists.

## Common experimental methodology

### Two-layer design

1. **Deterministic protocol fixture**
   - No LLM.
   - Forces exact task states and canary outputs.
   - Establishes whether a failure is in parsing, state management, authorization, or correlation.

2. **Live semantic environment**
   - Existing five Ollama-backed specialists.
   - Measures whether an accepted protocol anomaly changes model context or task outcome.
   - Keep temperature and prompts fixed; record model and SDK versions.

### Recommended repetitions

- Deterministic, non-concurrent conformance cases: one result per SDK/version/configuration is logically sufficient, but run 10 times to detect nondeterministic infrastructure behavior.
- Concurrent cases: at least 100 interleavings per case with randomized jitter.
- LLM-dependent semantic cases: at least 30 trials per condition and agent configuration.
- Pair every adversarial condition with a benign control using the same task template and seed where possible.

If local compute is limiting, run all protocol cases deterministically and reserve LLM trials for the two or three conditions that actually penetrate the executor.

### Statistics

- Report Wilson 95% confidence intervals for proportions.
- Report median, p95, and bootstrap confidence intervals for latency and resource cost.
- Use McNemar's test for paired baseline/defense binary outcomes.
- Use Fisher's exact test when counts are small.
- Report absolute counts with every percentage.
- Separate protocol acceptance from semantic attack success.

### Safe canary design

Use fabricated event-planning records only:

- Context A secret: `CANARY-ALPHA-731`
- Context B secret: `CANARY-BRAVO-284`
- Side effect: increment an in-memory or SQLite counter
- Unauthorized action: create a clearly labeled dummy reservation record

No external targets, real credentials, browser scripts, internal-network requests, or stealth/audit bypasses are required.

## Defense ablations

Evaluate one control at a time:

| Defense | Purpose |
|---|---|
| D0: Baseline | Current framework and SDK behavior |
| D1: Pair binding | Reject any stored-task/supplied-context mismatch before executor entry |
| D2: Principal ownership | Resolve a caller identity and scope every get/list/cancel/continue/subscribe operation to it |
| D3: Pending-session map | Replace the host's global pending slot with a map keyed by authenticated user/session |
| D4: Replay/equivocation cache | Store `(principal, messageId, payload hash, outcome)` with a bounded lifetime |
| D5: Transition guard | Atomic compare-and-set on expected state before accepting continuation or cancellation |
| D6: Client event pinning | Pin remote/task/context after the first response and reject foreign updates |
| D7: Agent Card snapshot pinning | Canonicalize and hash/sign the approved card; bind invocation to that snapshot |

For every defense, report both security improvement and benign utility/latency. This follows A2ASecBench's useful safety-utility principle while applying it to a new stateful surface.

## Minimum viable publishable study

An achievable undergraduate project does not need to implement every gap.

### Core study

1. Build the deterministic `input-required` fixture.
2. Implement cases C0-C2 and A1-A7.
3. Extend the replay harness to follow-up replay and conflicting concurrent replies.
4. Add authenticated synthetic principals for controlled cross-principal tests.
5. Add pair, principal, and atomic-transition defenses.
6. Run selected accepted cases against the five live remote-agent configurations.

### Strong extension

Add the malicious event server and client-side correlation tests. This creates a bidirectional study:

- **client-to-server:** can a caller attach input to the wrong task/context/owner?
- **server-to-client:** can a remote attach events or artifacts to the wrong task/context?

### Optional extension

Run the deterministic suite against two or three A2A SDKs or versions. Cross-implementation results would substantially strengthen external validity, but the custom framework alone is enough for a well-scoped systems paper if its claims stay local and precise.

## Claims to avoid

- Do not call the context-switch attack "agent session smuggling"; that name has prior use.
- Do not claim the A2A specification permits mismatched task/context pairs; it explicitly forbids them.
- Do not infer a vulnerability merely because the local prototype has no authentication. Demonstrate the difference between a local trust assumption and an exposed multi-user deployment.
- Do not report an LLM failure when the request should have been rejected before the LLM ran; identify the failing layer.
- Do not treat context-only continuation as automatically malicious. The specification allows a context without a task to create a related new task.
- Do not claim novelty for generic prompt injection, Agent Card spoofing, simple replay, schema violation, half-open flooding, routing deception, SSRF, or artifact script injection.

## Bottom line

The recommended contribution is not "another list of A2A attacks." It is a controlled measurement study showing whether stateful A2A implementations preserve **continuation integrity** across identity, identifiers, event attribution, and concurrent lifecycle transitions.

The user's context-switch idea is the anchor experiment. Even if SDK 1.1.0 correctly rejects the direct mismatch, the complete study remains valuable because:

- pair matching is only one part of state binding;
- caller ownership and host pending-session isolation are separate controls;
- replays and races can bypass checks that work sequentially;
- malicious server events require client-side correlation;
- vendor release notes show that these failures have occurred in real A2A connectors; and
- the supplied academic literature does not yet provide this focused empirical benchmark.
