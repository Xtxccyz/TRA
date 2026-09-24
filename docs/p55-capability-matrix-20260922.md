# P5.5 capability re-verification matrix (2026-09-22)

**Read-only report.** This document is the capability half that plan step P5.5 requires to be reported
SEPARATELY from the structural half. It adds no code, no test and no status file; it records what the
authoritative records already state about each capability item, what would close it, and whether this phase's
structural work moved it.

## 0. The rule that makes this document necessary

Quoted from `docs/code-structure-optimization-execution-plan-reviewed-20260922.md`:

- (Phase 5, line 558) 「“目录完成”不是“最终目标完成”。本阶段必须单独记录结构结果和能力结果。」
- (P5.5 最终状态, lines 614–619) 最终状态必须拆成两个字段：
  `structure_status`: `NOT_STARTED / IN_PROGRESS / READY / BLOCKED`；
  `capability_status`: `UNVERIFIED / PARTIAL / BLOCKED / ACCEPTED`。
  「**不能因为 `structure_status=READY` 就写 `capability_status=ACCEPTED`。**」
- (P5.2, line 594) 「**DSH 测试失败不能用 Python pytest 通过来抵消。**」
- (非目标, line 7) 「本方案不直接完成 T1-T8、G5、3080 最终验收，**也不把结构完成伪装成能力完成**。」
- (line 52) 「把结构状态和能力状态分开，避免结构目录完成被误报成 G5/3080 或人工报告深度完成。」

And `.scratch/structure-status.json`'s `capability_status`, verbatim:

> "UNCHANGED in substance and now backed by this round's separate-toolchain evidence: the capability items
> (T4 route B2, T8, T3, T6, T7, the diagnostic channel, undeclared truncation) remain OPEN, and the DSH suite
> that gates the product side reports 4 pass / 4 fail (typecheck, test, test:runtime, smoke:dsh) - recorded in
> the P5.1 step record and NOT offset by any pytest result. `structure_status=READY` must never be read as
> implying `capability_status=ACCEPTED`."

**Label precision.** The *matrix* is plan step **P5.4** (能力复验矩阵); **P5.5** is the two-field final state
whose rule this matrix satisfies. P5.4's own rows (report/chat/revision 同源; decode → WinHTTP/CreateProcess
object-level join; emulation failure distinction; T3/T4/T7/T8; G5 3080) each answer 「结构完成是否足够 = 否」.

**Structural position at the time of writing.** `.scratch/structure-status.json` records
`structure_status: "IN_PROGRESS"`, `current_step: "P3.7-recount"`. This matrix is therefore not qualifying a
READY structure; it is being recorded while the structural work is still incomplete, which is strictly stronger
than the rule demands.

## 1. The matrix

State vocabulary as given: **OPEN / PARTIAL / DEMONSTRATED / BLOCKED**. "DEMONSTRATED" is used only where the
record contains a reproduced *artifact*; no row below is DEMONSTRATED in the sense of "capability accepted".

| # | Item | What it REQUIRES (source) | Current state, as the record states it (last measured) | Evidence that would close it | Did this phase's structural work change its state? |
|---|---|---|---|---|---|
| 1 | **T4 route B2** (criteria B2-C1…C4) | `.scratch/plan-ghidra-b3-c3-20260921.md` T4-D1 rerouted by R1: 「B2 = 保留 headless 一次性导出产出 dump（下游零改动），另起一个常驻 Ghidra 仅用于追问查询」；B2 acceptance = 「追问查询返回的伪 C 与 headless 针对同一函数的结果一致」. The four criteria with negative controls are in `.scratch/u1-b2-decision.md` §2 | **OPEN.** `u1-b2-decision.md`: "B2-C1..C3 are **not yet implemented**"; `HANDOFF-round29.md` §1: "T4 resident Ghidra service \| **NOT STARTED.** Route now decided: B2"; `AUTHORITATIVE-STATE.md` §OPEN 5: "T4 (route B2) … — untouched". Last measured: the U1 measurement in `u1-b2-decision.md` (handoff labels it round 29 of 30); the one sub-question it left open was later closed at rounds 45+ — "intrinsic to Ghidra's headless auto-analysis, not induced by machine load" (`AUTHORITATIVE-STATE.md:8-17`) | One test per criterion, each with a negative control required to FAIL. B2-C1 frozen-dump pseudo-C equality (control: a function not in D, or one instruction mutated in D's stored pseudo-C). B2-C2 keying on `entry` identity (control: two dumps with reordered/substituted symbol lists). B2-C3 the dump stored WITH its measured instability — 8 named fields, 4/8,826 symbols — so `signature`/`fuzzy_fingerprint`/`cfg_blocks` are not read as reproducible (control: a dump without the record rejected as incomplete). B2-C4/plan D3 the service-down degradation, re-specified by the plan as an EXTRA observable evidence row. Prerequisite: the resident service itself — no such component exists | **No.** Phase 3 moved `service.py` clusters behind the `TaskHost` / workbench / coordinator seams; no structural step adds a resident Ghidra, a frozen-dump artifact or a follow-up query path, and no B2 criterion has a test |
| 2 | **T8** (decompiler + `--include-ghidra`) | `plan-ghidra-b3-c3-20260921.md` T8: 「伪 C 真正进入产品，且 `GET_DECOMPILE` 不再名不符实」; H1 `DecompInterface` called and pseudo-C in evidence; H1b behaviour-not-constant (fast/slow fixtures); H2 product/description consistency machine-decidable; H3 zero gating violations. Basis F7: 「`DecompInterface` / `decompileFunction` 在 `src/` 零出现」 | **OPEN.** `HANDOFF-round29.md` §1: "T8 decompiler + turn on `--include-ghidra` \| **not done** — `ghidra-worker` is deliberately STALE and excluded from the gate; T8 owns turning it on"; `AUTHORITATIVE-STATE.md` §OPEN 5: "T8 … untouched". Last measured: rounds 45+ (capability record). NOTE: the ghidra-worker deploy sub-fact has since moved on the structural side — see §3, contradiction 1 | `DecompInterface` in the Ghidra Java export; pseudo-C present in evidence rows; the H1b fast/slow fixture pair; the H2 consistency test bound to the PRODUCT; H3 gating counts 0; and `scripts/check-deployed-code-hashes.py --strict` green with `ghidra-worker` in the service list (plan line 567; line 220: 「禁止跳过 ghidra-worker 或用旧镜像继续下一阶段」) | **No.** No structural step adds a decompiler or rebuilds the Ghidra image for decompilation; P5.4's own row already answers 「结构完成是否足够 = 否」 |
| 3 | **T3** (C3b runtime model library) | `plan-ghidra-b3-c3-20260921.md` T3: 「模型仍是人写的；"该加载哪个模型"由探测自动决定」; the measured loop 「跑一次 → 读 `stop_reason` 里的导出名 → 建模它 → 再跑」; C1 (VB6 path's deterministic part unchanged, measured on a FIXED document fixture), C2 (a new runtime's minimal model loads on detection, not otherwise), C3 (any entry disabled → the path degrades rather than errors), plus the can-fail case 「探测说需要模型 X、但模型库无 X」 → 如实报告缺少模型 | **OPEN.** `HANDOFF-round29.md` §1: "T3 C3b runtime model library \| **not done.** First concrete target: `MSVBVM60.ordinal_648` (shim models 132 exports; the run stops there)"; `AUTHORITATIVE-STATE.md` §OPEN 5: untouched. Last measured: rounds 45+; the underlying stop reason `unsupported_api api=MSVBVM60.ordinal_648` was re-measured by R9 on the deployed worker | The declarative runtime → export → semantics registry with the VB6 shim as its FIRST entry; a fixed-fixture C1 test (the plan moved C1 off live runs precisely because 正文 contains model prose); C2 and C3 tests; the honest "model missing" report; a re-run whose `stop_reason` names the next unmodelled export with a rising API count | **No.** `vb6_runtime_shim` moved path-only to `emulation/vb6_runtime_shim.py` under P2 (`docs/import-policy.json` rename map) with the old path kept as a shim; no criterion changed state |
| 4 | **T6** (spliced string published as API names) | `plan-ghidra-b3-c3-20260921.md` T6: 「该行改为逐条列出**逐字命中**的名称，或明确标注拼接；不得把拼接文本呈现为结构化列表」(F1); F2 `primary_analyst_violations` 与组合门 jargon 均为 0 | **OPEN — and the defect is DEMONSTRATED in published report text.** `.scratch/t6-confirmed-in-published-body.md`: revision `2f695156` (Resume, 88,705 chars) publishes `` `explorer.exeInitializeProcThreadAttributeList failedUpdateProcThreadAt `` under a heading claiming these are API names; `\.exe[A-Za-z]` is true for the two large Resume revisions and false for 8 others. `AUTHORITATIVE-STATE.md` §OPEN 4: "T6 — proven live in the published body, **not fixed**". Last measured: rounds 45+ (corpus query and verbatim text are in that file) | The fix at the point where the value is JOINED — not a `.exe` substring rejection, because the same regex over-matches a genuine VERSIONINFO string (`…AcroRd32.exeAcroCEF.exeAdobe PDF Library 23.`); a test asserting the published heading no longer carries a concatenated token, with the version-info string as a negative control that must still be published; F2's two counters at 0 | **No.** `analyst_report` and `reporting` moved path-only into `report/`; the join logic is unchanged, and the defect was reproduced from a revision published BEFORE the structural phase. Plan §1.2 states these problems 「不能由结构提交偷偷修复或放宽」 |
| 5 | **T7** (`consumer` token cross-namespace collision) | `plan-ghidra-b3-c3-20260921.md` T7: 「机器令牌在正文中**只保留一个含义**；数据流占位改以散文呈现」(G1); G2: `check-slot-grounding.py` 的该条 note 消失 | **OPEN.** `.scratch/ledger-append-CY.md:69-73`: 「但它同时是个真实的可用性缺陷，值得单独记下（**本轮不改**）」; the three `UNKNOWN(consumer)` occurrences are a status line, prose and a cross-reference — none is a slot-table entry — while `consumer` IS resolved in the slot-table namespace, so the same token means two things in one document. `HANDOFF-round29.md` §1: "T6/T7 … \| not done". Last measured: the CY ledger round (before round 29 of the Ghidra plan) | The renderer change so the machine token keeps one meaning and the data-flow placeholder is prose; `check-slot-grounding.py`'s note gone; an assertion on a REAL revision's body, not a fixture alone | **No.** No structural step touches the report renderer's token vocabulary; `check-slot-grounding.py` is a capability-side grader outside the structure plan's gates |
| 6 | **The diagnostic channel** | `.scratch/AUDIT-both-axes-corrections.md`, "Confirmed defects NOT yet fixed" #4: "**No diagnostics channel exists**: the only logger writes to stdout and is configured only in `create_app`, never in `run_static_worker`; six containers emitted **0 log bytes**; the ctypes-swallowed Speakeasy traceback lands on emu-worker stderr and is **destroyed on recreate**." Its user-visible consequence is recorded in `AUTHORITATIVE-STATE.md`: the CAUSE of an `EXECUTION_ERROR` (Speakeasy's own handler crashing because the process object was `None`, `speakeasy/windows/win32.py:694`) is published nowhere, so "A reader therefore attributes the stop to the sample's behaviour when it was the emulator's" | **OPEN.** Defect audit `b077e4fb` (round 45 end); no fix recorded. Last measured: round 45+ — six containers at 0 log bytes; the swallowed traceback observed on emu-worker stderr | A logger configured on the WORKER composition root(s) as well as `create_app`; a container that demonstrably emits non-zero log bytes; the worker's stderr captured into EVIDENCE so a swallowed exception can reach the report; a can-fail proof that the capture is absent when the exception is absent | **No.** The structural phase separated the worker composition root into `control_activities.py` (P2-T.0) — a path move. It added no logging configuration, no evidence capture and no stderr retention |
| 7 | **Undeclared truncation (silent caps)** | EC-4 as the plan's T8 wording states it: 「**如实报告截断** … 让**不完整可见**，而不是静默截断」. Concretely (`AUDIT-both-axes-corrections.md` #2 and #6): "**Silent 256 cap** on observed APIs (`simulation_adapters.py:1350`), rendered as a total at `analyst_report.py:4936`; 102 evidence rows sit exactly at 256, none above. The cap must be named and the remainder reported"; "Unannounced truncation at `reporting.py:8207` `[:6]`, `:8211` `[:12]`, `analyst_report.py:4908` `[:12]`, `:4934` `[:8]`, `simulation_adapters.py:1007` `[:8]`" | **OPEN.** `AUDIT-both-axes-corrections.md`, "Confirmed defects NOT yet fixed" #2 and #6 (audit `b077e4fb`, round 45+). Measurement basis: 102 evidence rows sit at exactly 256, none above. `AUTHORITATIVE-STATE.md` records the required shape: "The cap must be named and the remainder reported, as `analyst_report.py:4997` already does for `named[:4]`" | Each cap named in the published body with the remainder it dropped (a rendered "showing M of N" statement); a test where a 257+ row input publishes the remainder; a negative control where an input under the cap publishes no truncation sentence. NOTE: the recorded line numbers predate the `report/` relocation and must be re-located, not trusted | **No.** The truncation sites moved path-only into `report/`; no structural step added a remainder statement, and P1.4/§1.2 forbid smuggling a behaviour change into a structural step |
| 8 | **Truncation / limitation notice visible to the reader** (EC-4's consumer) | The plan's T8 requirement above, applied to the notice that already exists: `truncated_fields` 「had **no consumer**」; after the round-36 fix the audit corrected the claim — "the **published body** is `analyst_report.render_official_markdown` (`analyst_report.py:5620`), which **never reads `task.limitations`**. Measured: revision `414cb724`'s markdown contains **zero** occurrences of `限制`/`limitation`… The honest statement is: the notice reaches `task.limitations` only. **EC-4 is still broken for the reader.**" | **OPEN / PARTIAL.** The wire into `service.py:14206-14210, :14648-14655` and the stored `document` JSON exists; the PUBLISHED body does not read it. Last measured: revision `414cb724` (round 45+) — zero `限制`/`limitation` occurrences, and none of its ~30 persisted limitation strings appeared | An executable test that a limitation string reaches the RENDERED markdown of a revision — mechanism 4 of `.scratch/AUDIT-VERDICT-and-corrections.md`: a symbol is complete only if grep finds a hit outside its module and its test **and** an executable test proves the value reaches a rendered document — plus the renderer actually reading `task.limitations` | **No.** The renderer moved path-only; the round-36 producer+consumer pairing was corrected by audit as "a consumer that no renderer reads", and no structural step closes it |
| 9 | **T1** (extra row: Speakeasy full-PE window reachability + recovered start) | `plan-ghidra-b3-c3-20260921.md` T1: A1 a `simulator=speakeasy` row appears on Resume while 白象 keeps its 3 Speakeasy runs; A2 「Speakeasy 的观测数 > 该样本 Unicorn 的最大观测数」, and if unmet, the window must be proven to carry `start_basis=recovered_function_entry`; T1b a caller-free fallback with an **explicit** degradation | **PARTIAL.** `AUTHORITATIVE-STATE.md` first wrote "**T1-A1 IS SATISFIED**", then `AUDIT-both-axes-corrections.md` #2 corrected it: "**PARTIAL, and substantively misleading** … *T1-A1's syntactic criterion is met; the budget fix is confirmed; **it did not make Speakeasy productive on Resume**"* (the row is `api_count: 0 / modelled_calls: 0 / strings_observed: 0`, stopping on `UC_ERR_READ_UNMAPPED`). T1b 「is still not what the plan asked」, and the plan-named suppression point `emulation_plan.py:159-160` is diagnosed but NOT fixed. A2's claimed unsatisfiability was itself corrected by measurement (AUDIT-both-axes #3: the delivered anchor DOES carry `start_basis=recovered_function_entry`) | A Resume run whose Speakeasy observation count EXCEEDS the sample's Unicorn maximum, or a published `start_basis=recovered_function_entry` window that actually produces observations; the explicit caller-free fallback with its degradation reported; and a 白象 regression test that `granted_windows` stays empty (F10b) | **No.** `emulation_plan`/`emulation.emulation_plan` and the worker path were relocated/renamed only |
| 10 | **T2** (extra row: runtime-dependency detection) | `plan-ghidra-b3-c3-20260921.md` T2: B1 白象 AND Resume each run once and the body carries 「仿真卡在 `<DLL>!<导出>`」; B2 the stop point must agree with the INDEPENDENT probe `.scratch/probe-emulation-blocker.py`; B3 the detection does not change the 24 criteria; plus the can-fail case that a sample where emulation never ran reports "not run", not "stuck" | **PARTIAL.** `AUTHORITATIVE-STATE.md` §OPEN 1 RESULT: "**T2-B1 is NOT satisfied, and the reason is not a T2 defect.** … Its actual emulation status is `speakeasy FAILED / EXECUTION_ERROR` … **Do not record T2-B1 as met.**" The 白象 half had been met before the fix (`HANDOFF-round29.md` §1). The "never-attempted published as attempted" defect (T2's own audit MED) is recorded as FIXED at commit `1953510` (`AUTHORITATIVE-STATE.md` DONE table) | A Resume run whose stop IS an unsupported API, or a deliberate restatement of B1; the B2 cross-check against the independent probe; the B3 non-regression on the 24 criteria; the "emulation never ran → not run" can-fail case | **No.** `simulation_adapters`, `tool_execution` and the investigation siblings were relocated path-only or re-exported; no T2 criterion changed state |

### Row count per state

| state | rows | items |
|---|---|---|
| **OPEN** | **8** | T4/B2, T8, T3, T6 (defect demonstrated, fix open), T7, diagnostic channel, undeclared truncation, reader-visible truncation notice |
| **PARTIAL** | **2** | T1 (A1 syntactic only; T1b not as required), T2 (B1 met on 白象 only) |
| **BLOCKED** | **0** | — (the diagnosis-and-no-counterexample items here are OPEN, not BLOCKED: BLOCKED is reserved for the plan's own condition — image absent / source hash ≠ HEAD / container import fails) |
| **DEMONSTRATED as a *closing* state** | **0** | T6 is the only row with a reproduced artifact, and it demonstrates the DEFECT, not the capability |

Total: 10 rows.

## 2. What a reader must NOT conclude

1. **Structure is not capability.** `structure_status` and `capability_status` are separate fields with separate
   vocabularies, and the rule is explicit: 「不能因为 `structure_status=READY` 就写 `capability_status=ACCEPTED`」
   (plan P5.5). The structural plan's own non-goal says it does not complete T1–T8, G5 or 3080, and does not
   disguise structural completion as capability completion. At the time of writing `structure_status` is
   `IN_PROGRESS`, so nothing here is even a qualification of a READY structure. **No row above changes state
   because a directory moved, a shim was kept, or an import graph reported 0 cycles.**
2. **A green pytest run does not offset the separate DSH suite result.** The plan is explicit: 「DSH 测试失败不能
   用 Python pytest 通过来抵消」 (P5.2). The DSH suite, run on its own toolchain, currently reports **4 pass /
   4 fail**: `typecheck`, `test`, `test:runtime` and `smoke:dsh` FAIL; `manifest`, `security`, `legacy-guard`
   and `core-guard` pass. That is recorded in the P5.1 step record of `.scratch/structure-status.json` with the
   exact error per script, and with the verdict 「**P5.1's GREEN CONDITION IS NOT MET AND IS RECORDED AS SUCH**」
   and 「the plan's final report must carry this DSH table and must NOT let a green pytest run stand in for it」.
   The Python suite's `6 failed / N passed` baseline — however green the pass count looks — is a different
   instrument measuring a different axis.
3. **No item above may be upgraded without its own evidence.** Not by a green suite, not by a structural move,
   not by rewriting a description (plan H2 refuses 「改一句字符串就算通过」), and not by a count
   (`AUTHORITATIVE-STATE.md`: "A count is not always the right observable" — the `8,826 vs 8,826` symbols case
   hid a 4-in/4-out substitution). Each row's closing evidence names the artifact or test that would close it,
   and for every B2/plan criterion that artifact must come with the negative control that FAILS.
4. **"No structural change" is not "nothing to re-check".** The path relocations invalidate the recorded line
   numbers the audits cite (`reporting.py:8207`, `analyst_report.py:4936`, `simulation_adapters.py:1350`, …).
   Anyone implementing rows 6–8 must re-locate the sites by measurement, not by the audit's offsets.
5. **This matrix is not independently verified.** Its rows are quoted from records in `.scratch/`, which is
   gitignored and therefore absent from a clone; and `.scratch/AUDIT-VERDICT-and-corrections.md` records that
   the session's G5 self-audits were 「self-certification with no blocking power」 and that the 24/24 Resume
   harness 「is not a general health signal」. Nothing here should be read as accepted on an audit's say-so.

## 3. Contradictions between the authoritative records (both named, neither picked silently)

1. **Is `ghidra-worker` STALE or SYNCED?** `AUTHORITATIVE-STATE.md:138` says "`ghidra-worker` is excluded from
   the gate by design (T8 turns `--include-ghidra` on) and is currently **STALE**";
   `.scratch/structure-status.json` `ghidra_worker_blocker._resolved` says "**RESOLVED** … the local archive
   server is started, the fleet rebuilds with exit 0, and the strict deployment gate reports **122 files x 8
   services with missing=0 differing=0 container-only=0**", and its `deployment` block has `services: 8`,
   `missing: 0`, `differing: 0`. The structural record is later and measured; the capability record was not
   updated. **Resolution path: re-run the gate with `ghidra-worker` included** — do not assume either. Scope
   note: even the synced reading unblocks only T8's *deployment prerequisite*, not T8 itself, which both records
   call not done.
2. **Which commit is HEAD?** Four values are in play: `AUTHORITATIVE-STATE.md` states `main = 563f6bd` (head of
   file) and also `main = 1953510` (line 41-42); `.scratch/AUDIT-both-axes-corrections.md` #6 says HEAD =
   origin/main = `022111a` and that `AUTHORITATIVE-STATE.md:24` is stale; `.scratch/structure-status.json`
   carries `head_sha: 9ae5f609f7d9…` while its `baseline.captured_at` is "P0.2, HEAD 5165a86". Every
   "last measured" statement above therefore cites the RECORD it came from, not a verified SHA.
3. **B2-C4 restates a criterion the plan already replaced.** `.scratch/u1-b2-decision.md`'s B2-C4 is "The
   resident service being down/unloaded/timed-out does not fail the report and produces no pseudo-C \
   (this is T4-D3, unchanged)". But the plan's T4-D3 was REWRITTEN precisely because that wording 「字面上就是
   今天的行为 … 它永远为真」 (plan C-11, lines 235-239), replaced by an assertion that **an extra degradation
   evidence row appears only when the service is unavailable**. B2-C4 as written inherits the superseded,
   unfalsifiable D3; it must be corrected before implementation or it will be born vacuous.
4. **Contradictions already resolved by a later document** (recorded so no reader re-litigates them):
   T1-A1 "satisfied" (`AUTHORITATIVE-STATE.md`) vs "PARTIAL, substantively misleading"
   (`AUDIT-both-axes-corrections.md` #2) — the audit wins; A2's `start_basis=recovered_function_entry`
   "unsatisfiable" (plan A2, `HANDOFF-round29.md`) vs "contradicted — this run's anchor carries it"
   (`AUDIT-both-axes-corrections.md` #3) — measurement wins; ③ confidence-from-absence "fixed" vs "PARTIAL —
   absence→`MEDIUM` survives at `reporting.py:1172` and `models.py:423`" (#5); "ALL DEPLOYED MODULES MATCH src/"
   vs "PARTIAL — 14 of 58 modules compared; ghidra-worker excluded" (#4).

## Appendix — capability items the record already treats as closed

Listed so this matrix is not read as "everything is open": **T0** (deployment gate + negative control), **R6**
(out-of-tree backup), **R8** (Temporal 2 MiB payload limit, measured), **R9** (the 1000× discrepancy does not
exist; worker path reproduces `256 / 1031 / 1028`), **T5** (duplicate slot silently overwritten, with real-data
verification), **③** (provider confidence from absence — partial, see §3.4), **④** (the `max_length` plan-list
rejection — schema layer only; its missing half is row 8), **⑤** (stale R9 comment), **⑥** (G2 bookkeeping),
**②** (never-attempted published as attempted, commit `1953510`), and the empty-emulator-report defect
(`_speakeasy_stop` no longer returns `SUCCEEDED / END_ADDRESS / ""` for a report with no entry points).
These entries mean "the record's latest statement is that the specific criterion now fails before the fix and
passes after it" — **not** "independently verified", for the reason in §2.5.
