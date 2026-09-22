# Code map

Retrieval index for the Analysis Task runtime. Domain words come from `CONTEXT.md`. Architecture words (module, seam, interface) are for navigation only.

## Start here

| Question | Read |
|----------|------|
| What is an Analysis Task / Claim / Evidence? | `CONTEXT.md` |
| Who owns Investigation vs DSH chat? | `docs/architecture-final.md`, ADR-0002 |
| What is frozen for a report? | ADR-0024, `docs/session-event-contract.md` |
| Current Investigation loop rules | `docs/behavior-driven-investigation-plan-reviewed-20260907.md` |

## Runtime modules (`src/threat_report_agent`)

| Module | Owns |
|--------|------|
| `service.py` | Analysis Task lifecycle, workbench, `_run_investigation_loop`, controlled emulation dispatch. Giant; prefer searching by method name. |
| `analysis_task_orchestration.py` | Work-ledger phases, persist HOW skip (`resolve_persist_how_skip`), loop path (`next_investigation_loop_path`), 受控模拟 interleave (`run_analysis_task_investigation` / `continue_investigation_after_action`) |
| `persist_how.py` | Persist HOW mint: ranked Ghidra symbols → Claim specs and snapshot stamp |
| `mechanism_ready.py` | 机制就绪 façade: `inspect_mechanism_ready` (completeness / persist HOW / claim_eligible / critical_ready). CANDIDATE is never critical_ready. |
| `mechanism_completeness.py` | Semantic field scoring and `mechanism_is_critical_ready` |
| `investigation.py` | ActionType / playbooks / ClaimGate / mechanism verifiers / `InvestigationLoopDriver` |
| `investigation_ledger.py` | Work ledger statuses (OPEN / DEFERRED / CLOSED / UNKNOWN) |
| `behavior_catalog.py` | 行为目录 and evidence contracts |
| `static_analysis.py` | PE / decode / process / PPID recoveries from bytes |
| `tool_execution.py` + `ghidra_adapter.py` | ToolRun execution |
| `simulation_adapters.py` + `emulation_plan.py` | 受控模拟 adapters and granted windows (not 动态分析) |
| `controlled_emulation.py` | Placeholder vs real `simulation_result`; `post_static_emulation_needed`. Does not run Temporal/Docker. |
| `reporting.py` | V3 Report Document from Analysis Snapshot |
| `analyst_report.py` | Official analyst markdown overlay |
| `model_gateway.py` | 模型网关 |
| `intake.py` | 样本包 expansion |
| `database.py` + `models.py` | Durable Case / Artifact / Evidence / Claim |
| `content_store.py` | Content Blob bytes |
| `policy.py` + `contracts.py` | Action Proposal policy seam |
| `main.py` | HTTP surface |

`orchestration.py`, `agents.py`, and `turn_lifecycle.py` are not the live Investigation planner. The live planner is `service._run_investigation_loop` + `DeepMiningPlanner`. First-round analyze enters through `analysis_task_orchestration.run_analysis_task_investigation`; DSH workbench continues through `continue_investigation_after_action`.

## Product shell

| Path | Owns |
|------|------|
| `threat-dsh-workbench/` | DSH presentation; talks to `/api/v1/workbench/*` only |
| `src/threat_report_agent/static/` | Legacy compatibility UI (`docs/legacy-retirement.md`) |
| `tool-worker/` | Isolated emu-worker images |

## Do not treat as product source

| Path | Why |
|------|-----|
| `.scratch/` | Local run dumps (gitignored) |
| `docs/*audit*`, `docs/w2-*`, `docs/round*` | Historical ledgers; ADRs supersede them |
| `.agents/skills` vs `.claude/skills` | Skill bodies vs Claude wrappers; canonical bodies live under `.agents/skills` |

## Highest-friction seams

1. Persist HOW skip and TIMEBOX — `resolve_persist_how_skip` + `next_investigation_loop_path` + `persist_how.emit_ranked_symbols_then_stage` + `investigation.how_timebox_disposition`
2. 机制就绪 — `inspect_mechanism_ready` for projection scoring; playbook ClaimGate / catalog evaluate / protocol fill / report FUN-dump HOW stay in their modules
3. 受控模拟 — `controlled_emulation.post_static_emulation_needed` / `apply_emulation_reverification`; Temporal `static-emu` and Docker emu-worker stay on AnalysisService / tool_execution
