# Dynamic Investigation Planning

## Purpose

The model is an investigation planner, not an execution authority.  It may
choose the next useful static action from the current evidence, but the core
policy layer decides whether that action is valid and safe.  Samples are never
executed and analysis tools do not receive network access.

## Generic investigation loop

1. **Intake and scope**: identify the submitted bytes, archive members, file
   format, parent/child provenance, and resource budgets.  Background reports
   remain a separate trust channel.
2. **Baseline action set**: create mandatory static actions for every artifact.
   PE artifacts receive both `pe-parser` and `ghidra-headless`; scripts,
   documents, and other formats receive their corresponding safe parser.
3. **Planning turn**: send the model a bounded manifest of artifacts, current
   evidence, allowed tools, mandatory coverage, and completed actions.  The
   model returns priorities, reasons, expected evidence, focus areas, and
   dependencies in `dynamic-analysis-plan-v1`.
4. **Policy validation**: reject unknown artifacts, tools outside the allow-list,
   incompatible parser/format pairs, sample execution, network access, and
   actions outside the resource budget.  Rejected actions are recorded with a
   reason and never reach a worker.
5. **Action scheduling**: expand the plan into individual
   `(artifact, tool)` actions.  A dependency-aware queue runs model-prioritized
   actions first while retaining every baseline action.  A malformed dependency
   cycle is broken deterministically so the queue cannot deadlock.
6. **Evidence-driven replan**: after the first parser observation, send the
   newly completed action history and remaining artifacts back to the model.
   The resulting plan can reorder the remaining actions, including a PE's
   Ghidra pass, without replaying completed work.
7. **Inference and report**: deterministic and model claims reference the
   immutable Evidence rows produced by ToolRuns.  ATT&CK mapping, validation,
   snapshot freezing, report generation, and audit sealing run after the
   bounded queue drains.

## Example decision pattern

For a password-protected archive containing a loader script and an inner PE,
the planner may first prioritize the script parser to inspect decoding and
network indicators.  If that evidence exposes an embedded PE or high-entropy
payload, the replan can prioritize `pe-parser` and then `ghidra-headless` for
imports, functions, Xrefs, and CFG.  If the evidence is inconclusive, the
baseline queue still completes the required safe static coverage.

The UI exposes the plan status, selected actions, priorities, completed action
history, policy rejections, and evidence-linked audit events.  It does not
display private chain-of-thought; the auditable substitute is the structured
reason, tool result, evidence reference, and limitation.

## Failure and safety behavior

- A model timeout, invalid response, or unavailable fallback produces a
  `DETERMINISTIC_FALLBACK` planning record and runs the baseline queue.
- A worker failure becomes a ToolRun error and a report limitation; other
  independent actions continue within the configured byte, node, CPU, and
  memory budgets.
- Every plan round is persisted in `AnalysisTask.strategy_snapshot` and linked
  to model-call and audit records.  Raw prompts/responses remain restricted
  audit assets.
