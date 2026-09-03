# OpenCode-Inspired Agent Runtime Adaptation

Date: 2026-08-23

## Scope

The project uses the MIT-licensed `anomalyco/opencode` repository as an
architectural reference only. The TypeScript runtime was not copied into this
Python service, and untrusted samples are never passed to an agent code or
shell tool. The existing policy and static Worker boundaries remain the only
authority for sample processing.

## Adopted patterns

- An explicit `AgentRuntime` owns one bounded structured-output turn.
- Each run has a stable `run_id` and immutable lifecycle events:
  `agent.run.started`, `agent.context.checked`, `agent.run.completed`,
  `agent.run.failed`, or `agent.run.cancelled`.
- Provider selection and primary/fallback behavior stay behind the existing
  `ModelGateway`; the runtime does not know vendor-specific HTTP protocols.
- Context size is controlled by `MODEL_CONTEXT_MAX_BYTES` and is rejected
  before a provider call when the budget is exceeded.
- Cancellation is checked before and after the provider call. A cancelled or
  failed model run retains deterministic static Claims and adds an explicit
  task limitation rather than being presented as a complete model result.
- Every provider attempt is persisted as `ModelCall` with `agent_run_id`,
  encrypted payload references, hashes, status, latency, and error metadata.
  Runtime events are written to the task audit chain, yielding the trace:
  `Case -> AnalysisTask -> AgentRun -> ModelCall -> Claim -> Evidence`.

## Security boundary

The runtime receives bounded, explicitly marked analysis Evidence. It has no
sample execution capability, no arbitrary filesystem/network tool, and no
permission to create a ToolRun. Model output can only create
`STATIC_INFERRED` Claims that cite allowed non-background Evidence. Original
reference reports remain outside the analysis context.

## Verification

The runtime has deterministic tests for success, immutable events, context
budget rejection, cancellation, all-provider failure, and rejection of
`BACKGROUND_REPORTED` Evidence. The full local suite passes with 144 tests;
Ruff, compileall, JavaScript syntax, and Compose configuration checks pass.

## Boundary of the claim

GPT, Claude, Qwen, Kimi, and GLM protocol contracts are implemented and
fixture-tested. Real vendor calls require deployment credentials and are not
claimed by offline tests. The default deployment remains deterministic static
analysis with an explicit optional model enrichment path. Adversarial
consensus, full ATT&CK/RAG, benchmark calibration, and production hardening
remain later-stage work.
