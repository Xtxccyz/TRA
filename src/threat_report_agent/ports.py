"""Ports: the seams the later steps depend on instead of depending on `AnalysisService`. PURE TYPES ONLY.

Plan step P1.2 asks for `ModelPlanningPort`, `ToolExecutionPort`, `EmulationPort`, `StaticEvidencePort`,
`ReportRevisionWriter` and `WorkbenchQueryReader`, each stating its inputs, outputs, errors, budget and ordering,
with at least one deterministic test adapter. It also mandates a **deletion test**: a port that merely forwards a
large class's methods verbatim has FAILED and must go back to P1 to be narrowed.

THIS FILE IS NOW P1.2's SIX PORTS. The first slice defined the two whose contracts the plan describes precisely
enough to write on their own:

  * `ReportRevisionWriter` - plan section P3.4: assemble a Report Document from an immutable Analysis Snapshot,
    run the compose gate, write a Report Revision.
  * `WorkbenchQueryReader`  - plan section P3.6: read-only queries (evidence, timeline, report revision) that
    must not enter the analysis loop and must not change a snapshot or revision.

The other four (`ModelPlanningPort`, `ToolExecutionPort`, `EmulationPort`, `StaticEvidencePort`) were added after
four independent read-only surveys of their real consumers, because writing them from a summary would have
produced exactly the forwarding-shaped port the deletion test exists to reject. Every field of every view below
cites the call site that sets or reads it.

WHAT IS STILL NOT DONE, stated so this file is not read as more than it is: these are DECLARATIONS. No production
class implements any of them yet; `EmulationOutcomeView` in particular has no producer at all today. The adapters
arrive with the phases that move the implementations (P3.4, P3.5, P3.6). A port that nothing implements is a
design, not a decoupling.

WHY THE SURFACE IS CAPPED AND CHECKED IN A TEST: "interfaces smaller than their implementations" is otherwise an
opinion. `tests/test_ports.py` asserts each port here exposes at most two callables, so a future edit that grows
one into a façade of the whole service fails rather than passing review by looking reasonable.

This module must stay free of persistence, transport, SDK and ORM imports.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from threat_report_agent.contracts import DynamicPlanAction as DynamicPlanAction
from threat_report_agent.projection_protocols import AnalysisSnapshotView, ReportRevisionView

#: ``DynamicPlanAction`` is re-exported above so the MODEL PORT exposes the type a model-authored plan action is - the
#: action P3.3 layer item 4 asks for, and the one ``investigation/`` needs for P3.3c(2)'s three members (plan section
#: 3.2 line 132 lists "model port" among the things ``investigation/`` may import).
#:
#: WHY IT COMES FROM `contracts` AND NOT FROM `model/model_gateway.py`: the gateway imports httpx, and this module's own
#: rule is that it stays free of persistence, transport, SDK and ORM imports. The class therefore lives in the pure
#: contract layer and this is a RE-EXPORT of the same object - not a second implementation (plan section 3.2 line 142).
#: MEASURED: importing this module pulls no httpx and no `model_gateway`.


@runtime_checkable
class ReportRevisionWriter(Protocol):
    """Assemble and persist one Report Revision from an immutable Analysis Snapshot (ADR-0024/0025/0036).

    CONTRACT
      input   : a snapshot, plus an optional model-authored `draft`.
      output  : the published revision. `compose` returns the markdown that WOULD be published.
      errors  : never raises for a gate rejection. Per ADR-0036 a rejected draft is not a failure - the
                deterministic body is published instead - so the outcome is carried by the returned revision,
                not by an exception. Raising here would turn "the model wrote something unsuitable" into "the
                run failed", which is the failure shape recorded as `8e75f6dc`.
      ordering: `compose` is pure and must not persist; `write` persists exactly once and must not mutate its
                snapshot. A late-arriving result must produce a NEW snapshot and revision, never edit an existing
                revision's markdown.

    WHY TWO METHODS AND NOT MORE: a caller needs to (a) know what would be published and (b) publish it. Anything
    else - gate internals, draft selection, snapshot bookkeeping - is implementation the caller must not see; the
    deletion test would reject a wider surface.
    """

    def compose(self, snapshot: AnalysisSnapshotView, *, draft: str = "") -> str:
        """The markdown that would be published for this snapshot. MUST NOT persist anything."""
        ...

    def write(
        self,
        snapshot: AnalysisSnapshotView,
        *,
        draft: str = "",
        parent_revision_id: str | None = None,
    ) -> ReportRevisionView:
        """Publish a revision. MUST NOT mutate `snapshot` or any existing revision."""
        ...


@runtime_checkable
class WorkbenchQueryReader(Protocol):
    """Read-only queries for the workbench surfaces (plan section P3.6).

    CONTRACT
      input   : a task id (and, where relevant, a revision id).
      output  : the revision, or a sequence of evidence rows. Both come from the P1.1 projection protocols so a
                caller never needs `models.py`.
      errors  : a missing task or revision raises `LookupError`; absence is NOT returned as an empty result,
                because "no rows" and "no such task" mean different things to a reader.
      ordering: results are returned in a stable order so two identical queries can be compared; a query MUST
                NOT change a snapshot, a revision or any evidence row.

    `evidence` returns `object` rather than a concrete row type on purpose: the row shape is not settled enough to
    freeze, and pinning it here would make this port a second canonical definition of the evidence projection.
    """

    def revision(self, task_id: str, revision_id: str | None = None) -> ReportRevisionView:
        """The named revision, or the latest published one for the task."""
        ...

    def evidence(self, task_id: str, limit: int | None = None) -> tuple[object, ...]:
        """Evidence rows for the task, in a stable order."""
        ...


# ===================================================================================================
# The four remaining P1.2 ports, written from MEASURED call sites (round 65, four independent read-only
# consumer surveys), not from their names. Each view below lists the file:line that sets or reads every field.
#
# WHY EVERY INPUT/OUTPUT IS A PROTOCOL *VIEW* RATHER THAN THE EXISTING CLASS: the canonical classes are
# transport-bound. `model_gateway.ModelRequest` (model_gateway.py:118) is defined in a module that imports httpx
# (model_gateway.py:549 mentions its transport), `tool_execution.ToolRunRequest` (:97) lives beside `temporalio`
# workflow definitions, and `ghidra_adapter.GhidraRun` is produced by a subprocess runner. Importing any of them
# here would make `ports.py` depend on the layer it exists to hide, which the purity test bans. A view declares
# exactly the fields the measured call sites set and read, so a consumer can be written against the seam and the
# adapter maps the canonical class into it - the same route as P1.1's projection protocols.
# ===================================================================================================


@runtime_checkable
class PlanningRequestView(Protocol):
    """One bounded model turn, as the pipeline actually issues it.

    MEASURED: exactly three pipeline sites build one - `service.py:13900` (planning, module="planning"),
    `service.py:22086` (candidate Claims), `service.py:23843` (report polishing) - and all three set the same
    fields. The DSH proxy (`service.py:28043`) maps an operation to a schema in one dict and calls the same path.
    Deliberately absent: `temperature`, `top_p`, `stream` (left `None`/`False` at all three pipeline sites,
    `model_gateway.py:118-119`; only the DSH proxy forwards them) and every provider/HTTP switch.
    """

    task_id: str
    case_id: str
    trace_id: str
    module: str
    prompt_id: str
    prompt_version: str
    prompt_sha256: str
    messages: tuple[dict[str, str], ...]
    response_schema: object
    timeout_s: float
    max_tokens: int


@runtime_checkable
class PlanningAttemptView(Protocol):
    """One provider attempt inside a turn. MEASURED reads: `service.py:22201` reads `error_type`; the overlay
    caller writes `http_status`, `error_detail`, `input_tokens`, `output_tokens` into
    `document["analyst_report_unavailable"]` (`service.py:23929-23968`)."""

    status: str
    error_type: str | None
    http_status: int | None
    error_detail: str | None
    input_tokens: int | None
    output_tokens: int | None


@runtime_checkable
class PlanningOutcomeView(Protocol):
    """What a caller may read from one turn.

    MEASURED reads: `.status`/`.error` (`service.py:14151`, `:22188-22195`), `.run_id` (`:14119`),
    `.attempts[].error_type` (`:22201`), `.parsed` (`:14125`, `:22146`, `:23984`), `.model_call_id` (`:22231`),
    `.raw_response` (`:14082`, `:22212`). The canonical type nests `parsed`/`model_call_id`/`raw_response` under
    `AgentRunResult.response` (`agent_runtime.py:39-45`); FLATTENING that is the adapter's job, which is why this
    view is not the canonical class.
    """

    status: str
    error: str | None
    run_id: str
    attempts: tuple[PlanningAttemptView, ...]
    parsed: object | None
    model_call_id: str | None
    raw_response: bytes | None


@runtime_checkable
class ModelPlanningPort(Protocol):
    """Ask the model for one bounded structured-output turn (P1.2).

    CONTRACT
      input   : a `PlanningRequestView`. Correlation ids, prompt identity, the built messages and the response
                envelope, plus this turn's timeout and token budget.
      output  : a `PlanningOutcomeView`. `status` is the only thing a caller may branch on before touching the
                rest; `parsed` is None exactly when the turn did not succeed.
      errors  : NEVER raises for a provider failure, a parse failure, an exhausted context budget or a
                cancellation. MEASURED why: the canonical runtime already converts all four into
                `status="FAILED"`/`"CANCELLED"` plus a stable error code (`agent_runtime.py:97-132`), and every
                caller reads that code to write a limitation (`service.py:14190`, `:22190-22207`, `:23922-23973`).
                A port that raised would turn "the model wrote nothing" into "the run failed", which is the shape
                the limitation-propagation work exists to avoid.
      budget  : `timeout_s` and `max_tokens` are per-turn and caller-supplied; the context budget is the
                adapter's (measured at `agent_runtime.py:83-86`). Turn-COUNT budgets stay with the caller
                (`service.py:1231-1232` `_MAX_MODEL_REPLAN_TURNS`, `_MAX_CONSECUTIVE_REPLAN_NO_GAIN`).
      ordering: ONE method, and no database transaction may be open across it. MEASURED: all three pipeline call
                sites sit outside the retrieval transaction (`service.py:13938`, `:22120`, `:28068` are outside
                the `with` blocks at `:13740` and `:21995`), and the overlay caller passes `observing=` purely so
                the probe cannot roll back the caller's session (`service.py:23905-23911`).

    WHY ONE METHOD AND NOT TWO: the three sites differ only in the envelope object and in messages the caller
    already builds; the caller-side re-asks (`service.py:13995`, `:14049`) are the SAME call with rebuilt
    messages. No call site needs a pre-flight eligibility check - the guards are config reads
    (`service.py:13729`, `:21845`, `:23835`, `:28008`).
    """

    def plan(self, request: PlanningRequestView) -> PlanningOutcomeView:
        """One turn. MUST NOT raise for provider, parse, budget or cancellation outcomes."""
        ...


@runtime_checkable
class ToolRunRequestView(Protocol):
    """One tool execution request, address-only. MEASURED fields set by the callers
    (`service.py:2833`, `:15738`, `:17084`, `:18842`) and by `tool_execution.ToolRunRequest` (:97)."""

    case_id: str
    task_id: str
    trace_id: str
    artifact_id: str
    tool_run_id: str
    tool_name: str
    tool_version: str
    content_sha256: str
    storage_key: str
    logical_path: str
    parameters: object
    max_cpu_seconds: int
    max_memory_mb: int
    task_queue: str
    environment_version: str
    sample_execution: bool
    network_access: bool
    storage_access: object


@runtime_checkable
class ToolRunResultView(Protocol):
    """What a caller may read back. MEASURED: `status` (`service.py:15766`, `:17113`, `:18876`), `error`
    (`:15776`, `:17130`, `:18877`), `output_storage_key` (`:15766`, `:17112`, `:18866`), `output_sha256`
    (`:17337`), `started_at`/`finished_at` (`:15756-15757`, `:17340-17341`), `worker_metadata` (`:18879`).

    NO PAYLOAD: every caller reads `output_storage_key` itself and decodes per tool kind (`:15768`, `:17116`,
    `:18868`, `:2848`). Returning bytes here would force the port to own all four decoders.
    """

    status: str
    output_sha256: str | None
    output_storage_key: str | None
    error: str | None
    started_at: object | None
    finished_at: object | None
    worker_metadata: object


@runtime_checkable
class ToolExecutionPort(Protocol):
    """Run a tool and report its outcome (P1.2).

    CONTRACT
      input   : an address-only `ToolRunRequestView` - a storage key plus a content hash, never bytes.
      output  : a `ToolRunResultView`. Failure must be EXPRESSIBLE as `status != "SUCCEEDED"`; it may also raise,
                and MEASURED, the call sites depend on that distinction: a transport exception must reach the
                intake caller (`service.py:1795` is not wrapped - its result is used directly at `:1796` and a
                missing output raises at `:1809`; `tests/test_tool_execution.py:1279` requires it to escape and
                fail the task), while the three other execute sites turn the same exception into a
                `status="FAILED"` result in place (`service.py:7070-7082`, `:8416-8426`, `:10155-10165`).
      budget  : `max_cpu_seconds` comes from the caller's policy and the client wait is derived from it
                (`tool_execution.py:1185-1192`). Retry policy lives INSIDE the workflow (the three `RetryPolicy`
                constructions at `tool_execution.py:152`, `:176`, `:215`) and is invisible here.
      ordering: one call per request and idempotent - the workflow id is derived from content hash, tool name,
                version, parameters, budgets, queue and environment (`tool_execution.py:112-130`), so a re-run
                attaches to the existing workflow (`:1210-1211`).
      cancel  : `cancel` takes a WORKFLOW ID, not a request view. The asymmetry is MEASURED, and it is this
                port's one deliberate input asymmetry (decided in P3.5-0, `docs/p35-prep-measurement-20260922.md`
                section 5's R2 resolution): every real cancellation caller holds an id STRING taken from the
                persisted row's `environment["workflow_id"]` (`task/task_runner.py:508`, `:625`) and calls
                `cancel_workflow(workflow_id)` (`task/task_runner.py:531`, `:640`), while `execute` takes the
                view. The id is DERIVED inside the implementation from ten fields the view already carries
                (`tool_execution.py:112-130`: canonical JSON, sha256, `toolrun-` prefix), so carrying `workflow_id`
                as a view field would give the same value a SECOND source of truth - a caller-supplied id could
                disagree with the id `execute` starts, and the started workflow is the side that must win.

    WHY TWO METHODS: cancellation is issued by a DIFFERENT caller from the one awaiting the result
    (`task/task_runner.py:531` and `:640` cancel by workflow id while the four execute sites await), so folding
    it into `execute` would force a return before the outcome, which no call site does. Two is P1.2's cap.

    STALE CITATIONS, recorded rather than quoted: the `service.py:NNNNN` numbers in this docstring that are NOT
    re-measured above date from a ~29,000-line `service.py` and now point past EOF (`service.py` is 18,752 lines
    as measured at P3.5-0/D-2), so citations such as `:28189` no longer denote anything. Re-measuring all of them
    is its own step; the ones this port's change touched (`cancel`, the four execute sites, the budget derivation)
    WERE re-measured then, and no un-measured citation is added here.
    """

    async def execute(self, request: ToolRunRequestView) -> ToolRunResultView:
        """Run the tool once. Failure may be a non-SUCCEEDED status or a raised transport error."""
        ...

    async def cancel(self, workflow_id: str) -> None:
        """Best-effort cancellation BY WORKFLOW ID; tolerates a run that already finished. A late result must not
        resurrect it. The id is the one `ToolRunRequestView` does NOT carry - see the class docstring's `cancel`
        clause for why the view must not carry it."""
        ...


@runtime_checkable
class StaticEvidenceView(Protocol):
    """Deterministic parser evidence for one artifact. MEASURED reads: `detected_type` (`service.py:15892`),
    `facts` with `module`/`kind`/`value`/`anchor` (`:15899-16093`), `summary["pe"]` (`:16451`, `:16706`,
    `:17164`, `:18767`, `:19280`), `limitations` (`:16440`)."""

    detected_type: str
    facts: tuple[object, ...]
    pe: object | None
    limitations: tuple[str, ...]


@runtime_checkable
class StaticDisassemblyView(Protocol):
    """Disassembly evidence, or absent-with-reason. MEASURED: `status` in
    {SUCCEEDED, FAILED, TIMED_OUT, CANCELLED} (`ghidra_adapter.py:142`, `:194`, `:224`, `:229`), `error` - a
    stable reason code or a `GHIDRA_ARCHITECTURE_INCONSISTENT` message (`service.py:17209`), `output` with
    `image_base`/`functions`/`symbols` (`service.py:19266`, `:17255`)."""

    status: str
    error: str | None
    output: object


@runtime_checkable
class StaticEvidencePort(Protocol):
    """Produce static evidence for one artifact (P1.2).

    CONTRACT
      input   : the artifact's bytes and logical path. The path selects the parser (`static_analysis.py:6803`,
                `:7082`, `:7125`); no execution and no network happens in either method.
      output  : parser evidence is a `StaticEvidenceView`; disassembly is a `StaticDisassemblyView`.
      errors  : `analyze` does NOT raise for a malformed artifact - a PE parse failure becomes a limitation and
                the facts recovered before it are kept (`static_analysis.py:7080-7081`) - though unexpected shapes
                may still raise, and every production caller wraps it and degrades to a default
                (`tool_execution.py:694-695`, `:799-800`; `service.py:18770-18771`, `:19283-19284`).
                `disassemble` does NOT raise for tool-missing, timeout, cancellation, non-zero exit or unreadable
                output: all of those are a status plus a reason (`ghidra_adapter.py:142`, `:194`, `:224`, `:229`,
                `:265`, `:269`, `:273`).
      budget  : `analyze` has none (the caller bounds its own input, `service.py:18262-18263`);
                `disassemble` takes `budget_seconds` and returns `TIMED_OUT` rather than raising
                (`ghidra_adapter.py:192-195`).
      ordering: `facts` in producer emission order; function rows in exporter order and NOT pre-truncated - the
                caller applies its own bounded selection (`service.py:19408-19414`).

    WHY TWO METHODS: the measured read-outs are two disjoint sets - no production site mixes a parser result with
    a disassembly run - and the two ABSENCE shapes differ, which callers depend on. Parser absence is a `None`
    result plus a limitation naming `execution.error or execution.status` (`service.py:15874-15878`);
    disassembler absence is a status code the caller branches on (`service.py:17358-17362`). Collapsing them
    would merge "no decompiler / not attempted" with "the tool failed", which
    `service.py:15892-15896` currently states separately.
    """

    def analyze(self, content: bytes, logical_path: str) -> StaticEvidenceView:
        """Deterministic parser evidence. MUST NOT execute, decompile or open a network connection."""
        ...

    def disassemble(
        self,
        content: bytes,
        logical_path: str,
        *,
        budget_seconds: int,
        cancelled: object | None = None,
        processor: str | None = None,
    ) -> StaticDisassemblyView:
        """Disassembly evidence or absent-with-reason. `TIMED_OUT` is returned, never raised."""
        ...


@runtime_checkable
class EmulationOutcomeView(Protocol):
    """What one emulation pass produced.

    NO CLASS IN THE TREE SATISFIES THIS TODAY, and that is recorded rather than papered over: the orchestrator
    currently gets a `list[str]` of limitations (`analysis_task_orchestration.py:246`, `:379`) and infers whether
    anything ran by re-counting rows before and after (`:432-435` -> `service.py:8579-8593`). `real_result_count`
    and `real_result_count_delta` replace that re-query. The adapter that builds this view is P3.5's job; this
    port is a declaration until then.
    """

    real_result_count: int
    real_result_count_delta: int
    placeholder_status: str
    cancelled: bool
    output_read_error: str | None
    limitations: tuple[str, ...]


@runtime_checkable
class EmulationPort(Protocol):
    """Run the policy-authorized emulation pass for one task and artifact (P1.2).

    CONTRACT
      input   : ids only - `task_id`, `artifact_id`, an optional scheduler label and the planned tool names.
                NEVER bytes, never a window plan, never a policy, never a storage key.
      output  : an `EmulationOutcomeView`. A deferral or a refusal is a PLACEHOLDER, never an exception and never
                an empty result (`service.py:18866-18875`, `:23765-23785`).
      errors  : `LookupError` for an unknown task or artifact (`service.py:18740-18741`); policy denial is a
                placeholder; a transport failure degrades to a placeholder carrying the reason
                (`service.py:18845-18855`).
      budget  : adapter-owned (`service.py:18835`; `tool_execution.py:907`; `simulation_adapters.py:1937-1945`).
                The caller must not pass one.
      ordering: plan order; results are appended in the order the planner granted them, and budget-excluded
                windows are appended after executed ones (`tool_execution.py:917-922`, `:1017-1030`).

    WHY TWO METHODS: the second exists because the port must OWN the placeholder rule rather than let a caller
    re-derive it from a status constant. MEASURED, that rule is currently spelled two different ways and they
    DISAGREE: the dispatch gate uses `PLACEHOLDER_STATUSES` membership (`controlled_emulation.py:94` via
    `post_static_emulation_needed`; `service.py:8591-8592` via `_real_simulation_result_count`), while
    `emulation.policy._POLICY_OR_PLACEHOLDER_STATUSES` (moved there by P3.3 layer item 2 - it used to live in
    `simulation_adapters`, which re-exports it; `policy.py:137`) additionally treats `DISABLED_BY_POLICY`,
    `NO_GRANTED_WINDOW`, `UNSUPPORTED`, `UNAVAILABLE` and `INPUT_REQUIRED` as non-observed. The consequence is
    measured: `is_real_simulation_row({"status": "UNSUPPORTED"})` is True while
    `evidence_nature_for_simulation_status("UNSUPPORTED")` is `STATIC_INFERRED`. `is_real_result` names which rule
    this seam uses so a reader can see the disagreement instead of inheriting whichever spelling they happened to
    call. Recognising a placeholder is in scope; BUILDING one is not - the placeholder literals stay where the
    pipeline writes them (`service.py:390-401`, `:23752-23785`).
    """

    def emulate(
        self,
        task_id: str,
        artifact_id: str,
        *,
        scheduler: str | None = None,
        planned_tool_names: tuple[str, ...] = (),
        cancellation_requested: object | None = None,
    ) -> EmulationOutcomeView:
        """One emulation pass. Deferral and refusal are placeholders in the outcome, not exceptions."""
        ...

    def is_real_result(self, row: object) -> bool:
        """True only for a simulator-executed simulation_result. Uses `PLACEHOLDER_STATUSES` membership,
        the same predicate the dispatch gate uses - stated here because two spellings disagree today."""
        ...


#: name -> the plan section that describes its contract.
P12_PORTS: dict[str, str] = {
    "ReportRevisionWriter": "written (P3.4)",
    "WorkbenchQueryReader": "written (P3.6)",
    "ModelPlanningPort": "written; one method (32 measured call sites read)",
    "ToolExecutionPort": "written; two methods, cancellation is a separate caller AND takes the workflow id, not the view",
    "EmulationPort": "written; the outcome view has no producer yet - the adapter is P3.5",
    "StaticEvidencePort": "written; two methods, the two absence shapes differ",
}
