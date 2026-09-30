# saved experiment evidence

This folder keeps one complete result per case and control, plus the latest five-agent log-review baseline. New runs will add their own reports beside these files. The report names contain the unique run id so results can be matched to their canary and database rows.

For public sharing, only the saved `database_path` display values were changed
from one research computer's absolute path to `data/task_stores/...`. The
experiment observations and results were not regenerated or edited.

The six follow-up pairs below use the current log-review framework and `CYBER-SANDBOX-A`. Each selected run completed all three planned steps with no operational error. An attack completing is not the same as every attack effect succeeding: read its measurements and supporting layers to see what happened.

## six follow-up cases

These reports are in `audit/gap3_live_runs/`. They include requests, responses,
host output, run-specific audit records, and database evidence. The database
layers show the before-run task ids and the new rows observed during and after
the run. The original task databases remain local in `data/task_stores/` and
are intentionally ignored by Git.

| Case | Variant | Framework | Selected report |
| --- | --- | --- | --- |
| TM-1 | control | log review | [gap3-live-tm-1-control-e242fe1684de47049e40713fbca90c27.json](audit/gap3_live_runs/gap3-live-tm-1-control-e242fe1684de47049e40713fbca90c27.json) |
| TM-1 | attack | log review | [gap3-live-tm-1-attack-39e559d4c08642449d39e352ef4caba3.json](audit/gap3_live_runs/gap3-live-tm-1-attack-39e559d4c08642449d39e352ef4caba3.json) |
| TM-2 | control | log review | [gap3-live-tm-2-control-0a49df85818344b6a8989e5440d7acf5.json](audit/gap3_live_runs/gap3-live-tm-2-control-0a49df85818344b6a8989e5440d7acf5.json) |
| TM-2 | attack | log review | [gap3-live-tm-2-attack-bfe443ce3b364c168ad2091a3123e9ce.json](audit/gap3_live_runs/gap3-live-tm-2-attack-bfe443ce3b364c168ad2091a3123e9ce.json) |
| DO-2 | control | log review | [gap3-live-do-2-control-bacc69f93e704a3ba88716044035b530.json](audit/gap3_live_runs/gap3-live-do-2-control-bacc69f93e704a3ba88716044035b530.json) |
| DO-2 | attack | log review | [gap3-live-do-2-attack-69e593b71d2d4c1f9ffd2743d7d8eda3.json](audit/gap3_live_runs/gap3-live-do-2-attack-69e593b71d2d4c1f9ffd2743d7d8eda3.json) |
| DO-3 | control | log review | [gap3-live-do-3-control-7d7f48d68fa141a4972d98e8f7976dbe.json](audit/gap3_live_runs/gap3-live-do-3-control-7d7f48d68fa141a4972d98e8f7976dbe.json) |
| DO-3 | attack | log review | [gap3-live-do-3-attack-f6756a746de34f43b651ec4153bb1e95.json](audit/gap3_live_runs/gap3-live-do-3-attack-f6756a746de34f43b651ec4153bb1e95.json) |
| DO-5 | control | log review | [gap3-live-do-5-control-5b466263ed724c02b36eef076f2d4586.json](audit/gap3_live_runs/gap3-live-do-5-control-5b466263ed724c02b36eef076f2d4586.json) |
| DO-5 | attack | log review | [gap3-live-do-5-attack-69b8a6ead69a4dfaad88795d364b48ba.json](audit/gap3_live_runs/gap3-live-do-5-attack-69b8a6ead69a4dfaad88795d364b48ba.json) |
| DO-6 | control | log review | [gap3-live-do-6-control-9f01b06024f8484eb2a227c061b0da25.json](audit/gap3_live_runs/gap3-live-do-6-control-9f01b06024f8484eb2a227c061b0da25.json) |
| DO-6 | attack | log review | [gap3-live-do-6-attack-b747e593cb504addaf64a0e1d2a38b5d.json](audit/gap3_live_runs/gap3-live-do-6-attack-b747e593cb504addaf64a0e1d2a38b5d.json) |

## current deterministic EA-A3 and control

| Case | Variant | Scope | Selected report |
| --- | --- | --- | --- |
| EA-A3 | attack | September 6 deterministic one-step run; no LLM | [gap3-ea-a3-e974043a8f6748e397252b56394a2851.json](audit/gap3_runs/gap3-ea-a3-e974043a8f6748e397252b56394a2851.json) |
| EA-C0 | control | September 6 deterministic one-step run; no LLM | [gap3-ea-c0-3cf620219f8f4fff8cee2619e1b24e80.json](audit/gap3_runs/gap3-ea-c0-3cf620219f8f4fff8cee2619e1b24e80.json) |

There is no retained standalone live EA-A3 report from the log-review framework.
The log-review DO attack reports use the EA-A3 response sequence inside their
fixed delegation orders. A new live EA-A3 pair can be produced with the command
in the root README.

## five-agent baseline

[cyber-baseline-cyber-sandbox-a-95fb5b71f6594379800fca522ce0b8cb.json](audit/cyber_baselines/cyber-baseline-cyber-sandbox-a-95fb5b71f6594379800fca522ce0b8cb.json) records a normal five-agent log review. It is useful for checking the framework's regular behavior, alongside the control for each attack case.

The selected reports are representative evidence, not the complete trial
history or a basis for calculating a success rate across all past runs.
