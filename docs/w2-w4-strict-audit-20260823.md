# W2S/W3/W4 Strict Audit Addendum

Date: 2026-08-23

## Result

The remediation in this addendum was implemented and re-tested against the
current working tree. The local deterministic acceptance suite now reports
144 passing tests. Ruff, Python compileall, JavaScript syntax validation, and
`docker compose config --quiet` all pass.

## Findings resolved

- Background context is persisted as an isolated `BACKGROUND_REPORTED`
  Evidence row with source, observed time, confidence, human confirmation, and
  trust-zone metadata. It has its own ingestion ToolRun. Model context can
  display it, but model Claim citation IDs exclude it.
- Ghidra function call references now produce conservative
  `STATIC_INFERRED` atomic behavior Claims. Claims include the function entry
  in the subject and link to function, call, Xref, CFG, and interface Evidence
  generated for that function.
- Decoded child artifacts automatically receive observed `DROPS` and
  `EXTRACTED_FROM` relations. Behavior Claims project `LOADS`, `DECRYPTS`, or
  `INJECTS` relations to available child components with `INFERRED` status.
  When no child is available, the report keeps the attack-chain state
  `unknown` instead of inventing a target.
- Embedded OOXML/PDF/OLE child artifacts receive both observed `CONTAINS` and
  `EXTRACTED_FROM` relations. PostgreSQL and SQLite enforce the same structural
  relation contract, and the live carrier probe verifies both relations through
  the public API.
- Deterministic Claim creation and function-priority Claim creation pass through
  the same Evidence-reference validation hook used by model output. The task
  view exposes `claim_evidence` so every Claim-to-Evidence edge is auditable.
- Static execution indicators create an `execution` Claim and project an
  inferred `EXECUTES` relation when an extracted child component exists.
- The unified ModelGateway now exposes explicit protocol contracts for GPT,
  Claude, Qwen, Kimi, and GLM. Offline fixtures verify endpoint paths,
  authentication headers, structured JSON parsing, and the existing primary
  to fallback audit path. No production vendor credentials were used.
- The model path now runs through a bounded `AgentRuntime` with explicit
  success/failure/cancellation states, immutable lifecycle events, configurable
  context budget, and an `agent_run_id` persisted on every ModelCall. Runtime
  events are part of the task audit chain and failures retain deterministic
  Claims while marking the task partial.
- Ghidra output is versioned (`schema_version: 1.0`) and malformed JSON or
  malformed top-level output is classified as a failed ToolRun. The repeatable
  `scripts/verify_ghidra.py` probe requires a successful run with non-zero
  function evidence and writes `.data/ghidra-acceptance-latest.json`.

## Runtime evidence

The prior acceptance record used a 25-function DLL fixture. That historical
path is retained only as an audit record and is not assumed to exist in every
checkout. The current rerun is recorded below and uses a present DLL fixture.

## Live infrastructure acceptance

The live Compose stack was started on the configured F: Docker data disk and
passed the repeatable `scripts/live_acceptance.py` probe. The probe verified API
health, PostgreSQL/MinIO availability, Temporal scheduling, object-store output
references, `BACKGROUND_REPORTED` Evidence, editable report snapshot creation,
and audit integrity. A second live DLL run verified the Ghidra Worker path:
`ghidra-headless` `SUCCEEDED`, `B0 x D3`, 25 functions, 25 function SimHashes,
92 similarity Evidence rows, 15 priority Claims, and one function behavior
Claim. These were static-only runs; no sample code executed.

The repeatable `scripts/live_carrier_acceptance.py` probe also passed against
the rebuilt API and live PostgreSQL stack. A synthetic OOXML carrier produced
child Artifacts and both `CONTAINS` and `EXTRACTED_FROM` relations. The input was
benign and no embedded code was executed.

## Final boundary validation

The API now exposes `validate_ghidra_output()` as the single version/schema
boundary for both local Headless runs and Temporal Worker output. Legacy Worker
payloads that omit `schema_version` are normalized to the 1.0 contract; invalid
function, symbol, or collection shapes fail the ToolRun before Evidence is
materialized. Regression coverage includes malformed Temporal function output,
and a real DLL replay through the running API and the existing Ghidra Worker
passed `SUCCEEDED/COMPLETE`, `B0 x D3`, with 25 functions and 25 SimHashes.

The API and static Worker images were rebuilt from the current source. The
Ghidra image was intentionally left on the previously accepted digest because
its original local download service (`host.docker.internal:18765`) was no
longer running; this does not bypass validation, since the API boundary accepts
and validates the legacy image output. Rebuilding that image requires restoring
the signed local archive service or supplying the same verified HTTPS archive.

The default deterministic mode remains explicit in task strategy metadata. A
configured model gateway is optional and all model attempts, AgentRuntime
events, failures, and fallbacks remain auditable. Production settings still
enforce Temporal Worker execution and non-demo authentication.

## Final disposition

W2S/W3/W4 implementation and live Compose acceptance are complete and usable
through the public AnalysisService/API path, with static-only safety boundaries
and editable report snapshots. Real vendor model calls remain intentionally
offline because no vendor credentials were supplied; all five protocol
contracts and fallback behavior are covered by deterministic fixtures.

This completion claim is limited to the worksheet scope: the model gateway is
an optional integration seam with explicit GPT/Claude/Qwen/Kimi/GLM contracts,
not a claim that vendor credentials or production network calls were exercised.

## Final rerun after AgentRuntime integration

The current API image was rebuilt and restarted. `scripts/live_acceptance.py`
and `scripts/live_carrier_acceptance.py` both passed against the running
PostgreSQL/MinIO/Temporal stack. The live static probe returned `B0 x D3`,
`COMPLETE`, Temporal tool execution, isolated background Evidence, editable
report output, and valid audit integrity; the carrier probe returned
`CONTAINS` and `EXTRACTED_FROM`.

The direct Ghidra probe was rerun against the currently present
`libcurl.dll` fixture (the older `greha_dll_x86.dll` path is no longer present)
and completed read-only with 891 functions. This is a valid current Ghidra
boundary check, not a claim that every historical sample path is available.

Docker cleanup after the rebuild reports five active images, ten active
containers, three data volumes, and zero BuildKit cache. No sample execution
was performed.
