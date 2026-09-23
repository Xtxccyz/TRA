"""Report Revision writing: assembling the Report Document, gating it and persisting the revision (plan §P3.4).

This module is the new home of the revision-writer slice of `AnalysisService`. It is filled in TWO steps, because the
design (docs/p34-revision-writer-design-20260922.md) measured the slice as two layers with an upward-only dependency:

* **P3.4-1** (done) - the assembly/selection layer: `_snapshot_report_context` (138), `_select_report_evidence_rows`
  (171), `_migrate_snapshot_payload` (47) and `_canonical_sha256` (6), plus the constant they close over,
  `_REPORT_PROJECTION_EVIDENCE_LIMIT`.
* **P3.4-2** - the lifecycle: `_create_report_revision`, `edit_report`, `get_report_revision`, `recompose_report`,
  `publish_report`, `submit_analyst_draft`, `workbench_submit_analyst_draft` and the `ReportComposeGateRejected`
  exception.

WHAT THIS MODULE MAY DEPEND ON. Plan section 3.2's row for `report/` admits `contracts`, `facts` and the read-only
`investigation` projections; this module imports `report/*` siblings, `models` and stdlib only. `service.py` keeps
one-statement delegations for every moved method, so `service.<name>` keeps working for all 36 syntactic test call sites
the design counted - moving the TEST surface off private methods is P3.7/P4's job, not this step's.

THE HOST. The moved bodies still reach some host state, and the pin below is the EXACT set they reach - measured, not
written from memory by `py .scratch/p34-pin.py --assert`, which asserts the pin equals the receiver set in both
directions and that every pin member carries a reason. A pin missing a member makes the mover emit a bare name, i.e. a
`NameError` when a report is written rather than at import time; that is the defect P3.4-0 found in the pin instrument
itself (`cls.` receivers were invisible to its first version).

`_REPORT_PROJECTION_EVIDENCE_LIMIT` TRAVELS rather than staying on the host, and that was a MEASURED decision taken after
the first application disagreed with the design: the mover treats a CLASS attribute as host state by default (almost all
of them are), so it produced `host._REPORT_PROJECTION_EVIDENCE_LIMIT` and a 3-member pin. The constant has exactly ONE
reader - the `_snapshot_report_context` that moved - so the move was re-run with it named explicitly and it travels as a
module constant, which is the tool's documented path for exactly this case (the same mechanism the P3.3d instruction
regexes use). With P3.4-2 the pin is the design's ELEVEN members, each with a reason in section 2 and summarised
below the pin.
"""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace
from typing import Iterable, Mapping, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AnalysisSnapshot, AnalysisTask, Artifact, AuditEvent, CaseRecord, ReportRevision
from .analyst_report import (
    compose_official_markdown,
    stamp_official_report_chrome,
)
from .report_verification import corrections_summary, correctness_summary, verify_report_correctness
from .reporting import (
    build_report_document,
    instruction_window_carries_process_creation_flags,
    normalize_modules,
    report_analytical_violations,
    report_bloat_violations,
    report_v3_quality_violations,
    string_fact_class,
)

#: The host members the P3.4-1 bodies reach, i.e. what `ReportRevisionWriterHost` must provide. Read by the mover
#: (`p33-extract.py --port-constant REVISION_WRITER_HOST_MEMBERS`) and asserted against the bodies by the contract test.
#: The full pin the design measured (section 2), with the reason for each member stated below.
#: WHY EACH MEMBER STAYS ON THE HOST (the design's section 2 rule: a pin without a reason is a pin nobody can audit):
#:   `SNAPSHOT_SCHEMA_VERSION`          - snapshot-seal schema constant, read by `_migrate_snapshot_payload` through `cls.`
#:   `_canonical_json_chunks`           - chunked canonical-JSON primitive, read by `_canonical_sha256` through `cls.`
#:   `_apply_honest_analysis_outcome`   - static, writes `AnalysisOutcome.PARTIAL` from `task.status` (a `task` layer the
#:                                        `report/` row of plan section 3.2 does not admit); a test reads it directly
#:   `_t6_revision_diff_payload`        - static, calls `AnalysisService._t6_trace_gains` BY CLASS NAME, so moving it
#:                                        would drag the class itself into this module
#:   `_overlay_analyst_report_plan`     - needs `model_gateway`/`prompts`/`settings`: implementation modules the matrix
#:                                        excludes from `report/`
#:   `_audit`                           - the service's audit writer, shared by every step
#:   `audit_integrity`                  - audit-integrity helper owned by the service
#:   `database`                         - the session factory, host state
#:   `workbench_task_for_session`       - workbench session lookup, unrelated to revision writing
#:   `_postgres_safe_text`              - generic persistence sanitiser shared across the service
#:   `_postgres_safe_value`             - generic persistence sanitiser shared across the service
REVISION_WRITER_HOST_MEMBERS: tuple[str, ...] = (
    "SNAPSHOT_SCHEMA_VERSION",
    "_apply_honest_analysis_outcome",
    "_audit",
    "_canonical_json_chunks",
    "_overlay_analyst_report_plan",
    "_postgres_safe_text",
    "_postgres_safe_value",
    "_t6_revision_diff_payload",
    "audit_integrity",
    "database",
    "workbench_task_for_session",
)


class ReportRevisionWriterHost(Protocol):
    """What the moved revision-writer bodies may use on the object that owns them.

    ELEVEN members as of P3.4-2, generated from `AnalysisService`'s REAL signatures by
    `.scratch/extend-derivation-host.py` (generalised for this slice with `--target`, `--port-constant` and
    `--protocol`), because the contract test asserts that the pin, this Protocol and the bodies' actual references
    are the same SET - and writing members by hand is exactly where a wrong parameter list hides. The reason each
    member stays on the host is stated with the pin above.
    """

    SNAPSHOT_SCHEMA_VERSION: str
    @staticmethod
    def _apply_honest_analysis_outcome(task: AnalysisTask, document: dict[str, object]) -> None: ...
    def _audit(self, session: Session, *, case_id: str | None, event_type: str, actor: str, object_type: str, object_id: str, payload: dict[str, object], task_id: str | None = None) -> AuditEvent: ...
    def _canonical_json_chunks(self, value: object, *, exclude_keys: Iterable[str] = (), chunk_bytes: int | None = None) -> Iterable[bytes]: ...
    def _overlay_analyst_report_plan(self, task: AnalysisTask, document: dict[str, object]) -> dict[str, object]: ...
    @staticmethod
    def _postgres_safe_text(value: str) -> str: ...
    def _postgres_safe_value(self, value: object) -> object: ...
    @staticmethod
    def _t6_revision_diff_payload(parent_markdown: str | None, markdown: str, parent_document: Mapping[str, object] | None = None, document: Mapping[str, object] | None = None) -> dict[str, object]: ...
    def audit_integrity(self, task_id: str) -> dict[str, object]: ...
    database: object  # instance attribute set in __init__
    def workbench_task_for_session(self, dsh_session_id: str) -> dict[str, object] | None: ...


# ---------------------------------------------------------------------------
# Moved implementation (P3.4-1 slice): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: ReportRevisionWriterHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it. P3.4-0 made the label a parameter for the
# same reason - a `report/` module appended under a banner claiming a P3.3 slice is that defect again.
# ---------------------------------------------------------------------------


def _snapshot_report_context(host: ReportRevisionWriterHost, snapshot: AnalysisSnapshot) -> dict[str, object]:
    # The snapshot is immutable.  Report projection enriches nested
    # investigation rows with protocol metadata and may bound Evidence; the
    # sealed JSON must never be mutated or its content digest invalidated.
    #
    # That guarantee used to cost a ``copy.deepcopy`` of the WHOLE payload plus
    # a materialised canonical JSON string of it on every report build.  Both
    # are needless at this size: a live snapshot carries ~100 MB of Evidence
    # (``analysis_snapshots`` totals 16 GB; the largest payloads are ~600 MB),
    # while the report consumes a bounded projection of it.  Measured on a real
    # 116 MB snapshot: 3.9 s of deep copy + 1.0 s of whole-payload
    # serialisation (a further 110 MB string plus 110 MB of encoded bytes),
    # 186 MB of resident copy, and 178 MB off the measured peak RSS.
    #
    # The invariant is preserved structurally instead of by copying:
    #   * the digest is streamed into ``hashlib`` in bounded chunks so the
    #     canonical bytes are never materialised (same algorithm, same digest);
    #   * ``payload`` is a shallow top-level copy and every row this projection
    #     rewrites is copied first (copy-on-write), so no object reachable from
    #     ``snapshot.object_versions`` is mutated;
    #   * ``tests/test_report_synthesis_performance.py`` locks that down by
    #     re-verifying the sealed digest after a full report build and asserting
    #     the ORM attribute is never marked dirty.
    sealed = snapshot.object_versions
    if not isinstance(sealed, Mapping):
        raise ValueError(f"Analysis Snapshot {snapshot.id} has a non-object payload")
    expected_digest = sealed.get("content_sha256")
    actual_digest = _canonical_sha256(host, sealed, exclude_keys=("content_sha256",))
    if expected_digest != actual_digest:
        raise ValueError(f"Analysis Snapshot {snapshot.id} failed integrity validation")
    payload: dict[str, object] = dict(sealed)
    payload.pop("content_sha256", None)
    payload = _migrate_snapshot_payload(host, snapshot.id, payload)
    payload.setdefault("model_calls", [])
    payload.setdefault("analysis_turns", [])
    payload.setdefault("analysis_turn_results", [])
    payload.setdefault("investigation_threads", [])
    payload.setdefault("investigation_hypotheses", [])
    payload.setdefault("investigation_actions", [])
    strategy = (
        payload.get("task", {}).get("strategy_snapshot", {})
        if isinstance(payload.get("task"), dict)
        else {}
    )
    investigation = strategy.get("investigation", {}) if isinstance(strategy, dict) else {}
    payload.setdefault(
        "mechanisms",
        investigation.get("mechanisms", []) if isinstance(investigation, dict) else [],
    )
    thread_protocols = investigation.get("thread_protocols", {}) if isinstance(investigation, dict) else {}
    snapshot_threads = {
        str(item.get("id")): item
        for item in (investigation.get("threads") or [])
        if isinstance(item, dict) and item.get("id")
    }
    thread_rows: list[object] = []
    for row in payload.get("investigation_threads") or []:
        if not isinstance(row, dict):
            thread_rows.append(row)
            continue
        thread_id = str(row.get("id") or "")
        meta = snapshot_threads.get(thread_id) or (
            thread_protocols.get(thread_id) if isinstance(thread_protocols, dict) else None
        )
        if not isinstance(meta, dict):
            thread_rows.append(row)
            continue
        # Copy-on-write: enriching protocol metadata must not touch the sealed
        # snapshot row, and only the few rows that are enriched pay for a copy.
        enriched = copy.copy(row)
        if isinstance(meta.get("protocol"), dict):
            enriched["protocol"] = meta["protocol"]
        if isinstance(meta.get("s_ladder"), dict):
            enriched["s_ladder"] = meta["s_ladder"]
        thread_rows.append(enriched)
    if "investigation_threads" in payload:
        payload["investigation_threads"] = thread_rows
    # Snapshot storage is intentionally lossless, but rendering a report
    # from tens of thousands of low-signal parser rows is not.  Build a
    # bounded analyst projection while retaining every Evidence row in
    # ``AnalysisSnapshot.object_versions`` for audit/replay.
    evidence_rows = payload.get("evidence", [])
    if (
        isinstance(evidence_rows, list)
        and len(evidence_rows) > _REPORT_PROJECTION_EVIDENCE_LIMIT
    ):
        referenced_ids: set[str] = set()
        for link in payload.get("claim_evidence", []):
            if isinstance(link, Mapping) and link.get("evidence_id"):
                referenced_ids.add(str(link["evidence_id"]))
        for relation in payload.get("relations", []):
            if isinstance(relation, Mapping) and relation.get("evidence_id"):
                referenced_ids.add(str(relation["evidence_id"]))
        for mechanism in payload.get("mechanisms", []):
            if isinstance(mechanism, Mapping):
                referenced_ids.update(
                    str(item)
                    for item in (mechanism.get("evidence_ids") or ())
                    if str(item).strip()
                )
        selected = _select_report_evidence_rows(
            evidence_rows,
            referenced_ids=referenced_ids,
            limit=_REPORT_PROJECTION_EVIDENCE_LIMIT,
        )
        task_payload = dict(payload.get("task") or {})
        task_snapshot = dict(task_payload.get("strategy_snapshot") or {})
        task_snapshot["report_projection"] = {
            "evidence_total_count": len(evidence_rows),
            "evidence_included_count": len(selected),
            "evidence_omitted_count": max(0, len(evidence_rows) - len(selected)),
            "bounded": True,
        }
        task_payload["strategy_snapshot"] = task_snapshot
        payload["task"] = task_payload
        payload["evidence"] = selected
    return {
        "case": SimpleNamespace(**payload["case"]),
        "task": SimpleNamespace(**payload["task"]),
        **{
            name: [SimpleNamespace(**item) for item in payload[name]]
            for name in (
                "artifacts",
                "tool_runs",
                "evidence",
                "claims",
                "claim_evidence",
                "relations",
                "gates",
                "model_calls",
                "investigation_threads",
                "investigation_hypotheses",
                "investigation_actions",
                "analysis_turn_results",
                "mechanisms",
            )
        },
    }


def _select_report_evidence_rows(
    rows: list[object],
    *,
    referenced_ids: set[str],
    limit: int,
) -> list[object]:
    """Select a bounded report view without deleting ledger evidence."""
    if limit <= 0:
        return []

    def row_id(row: object) -> str:
        if isinstance(row, Mapping):
            return str(row.get("id") or "")
        return str(getattr(row, "id", "") or "")

    def row_kind(row: object) -> str:
        if isinstance(row, Mapping):
            return str(row.get("kind") or "")
        return str(getattr(row, "kind", "") or "")

    priority = {
        "mechanism_dynamic_api_link": 120,
        "mechanism_http_transport_link": 120,
        "mechanism_shell_output_link": 120,
        "mechanism_etw_patch_link": 120,
        "resolved_api": 118,
        "function_semantic_summary": 117,
        "mechanism_chain": 116,
        "decode_result": 115,
        "mechanism_decode_window": 114,
        "investigation_seed_map": 113,
        "decode_candidate": 112,
        "function_context": 110,
        "function_call": 108,
        "function_instruction_window": 106,
        "function_data_correlation": 104,
        "api_argument_trace": 102,
        "pe_structure": 100,
        "simulation_result": 200,
        "decoded_artifact": 198,
        "import_symbol": 90,
        "export_symbol": 90,
        "string": 10,
    }
    must_keep_kinds = {
        "simulation_result",
        "decode_result",
        "decode_candidate",
        "pe_structure",
        "decoded_artifact",
    }
    semantic_kind = "function_semantic_summary"
    semantic_cap = min(256, max(32, limit // 8))
    selected: list[object] = []
    selected_ids: set[str] = set()
    # Isolated emu / decode / PE must survive even when Claim citations
    # already fill the bounded report view. Semantic HOW is capped so a
    # large decompiler dump cannot starve those rows.
    for row in rows:
        identifier = row_id(row)
        kind = row_kind(row).casefold()
        if not identifier or identifier in selected_ids:
            continue
        if kind not in must_keep_kinds:
            continue
        if len(selected) >= limit:
            break
        selected.append(row)
        selected_ids.add(identifier)

    def _semantic_blob(row: object) -> str:
        if isinstance(row, Mapping):
            return str(row.get("value") or "").casefold()
        return str(getattr(row, "value", "") or "").casefold()

    def _semantic_rank(row: object) -> tuple[int, str]:
        blob = _semantic_blob(row)
        score = 0
        for token, weight in (
            ("crypt", 12),
            ("calg", 12),
            ("0x6801", 12),
            ("rc4", 8),
            ("createthread", 6),
            ("virtualprotect", 4),
        ):
            if token in blob:
                score += weight
        return (-score, row_id(row))

    semantic_rows = [
        row
        for row in rows
        if row_kind(row).casefold() == semantic_kind and row_id(row) not in selected_ids
    ]
    semantic_rows.sort(key=_semantic_rank)
    for row in semantic_rows[:semantic_cap]:
        identifier = row_id(row)
        if not identifier or identifier in selected_ids:
            continue
        if len(selected) >= limit:
            break
        selected.append(row)
        selected_ids.add(identifier)
    for row in rows:
        identifier = row_id(row)
        kind = row_kind(row).casefold()
        if kind != "function_instruction_window" or identifier in selected_ids:
            continue
        value = row.get("value") if isinstance(row, Mapping) else getattr(row, "value", None)
        blob = str(value or "").casefold()
        # Two reasons a disassembly window is worth 341 KB of the bounded report view:
        # it decides a recovered crypto algorithm, or it decides the process-creation
        # argument slot.  The crypto test was the only one, so no window carrying a
        # `MOV dword ptr [RSP + 0x28],0x9080008` / `CALL <thunk>` pair was ever kept
        # and the published body said `UNKNOWN(creation_flags)` while evidence held the
        # value.  The predicate lives next to the disassembly rules it applies.
        if "0x6801" not in blob and "calg" not in blob:
            if not instruction_window_carries_process_creation_flags(value):
                continue
        if len(selected) >= limit:
            break
        selected.append(row)
        selected_ids.add(identifier)
    reserved = min(512, max(64, limit // 8)) if limit >= 64 else 0
    referenced_budget = max(0, limit - len(selected) - reserved)
    for row in rows:
        identifier = row_id(row)
        if identifier and identifier in referenced_ids and identifier not in selected_ids:
            if referenced_budget <= 0:
                break
            selected.append(row)
            selected_ids.add(identifier)
            referenced_budget -= 1

    # Raw strings all share one `kind`, so ranking them by kind cannot tell a
    # `:Zone.Identifier` MOTW marker from a disassembly byte fragment, and the
    # tiebreak was `row_id` - a UUID.  Selection among the ~3,000 string rows
    # was therefore arbitrary, and on task 1359f2a6 the bounded window dropped
    # every string-only benchmark fact: the composed body fell from 24/24 on
    # the full ledger to 13/24, with `:Zone.Identifier`, the `schtasks` blob,
    # `.tmp` and the three Defender registry keys all missing while every one
    # of their Evidence IDs was present in the unbounded trace.
    #
    # This must be the FIRST sort key and it must be a rank over all rows, not
    # a boolean about strings: `0` was already the default for every non-string
    # row, so a two-valued key still let the `-kind_priority` tiebreak put
    # 2,545 `function_call` rows ahead of all 13 significant strings.
    def _string_priority(row: object) -> int:
        kind = row_kind(row).casefold()
        if kind != "string":
            return 2
        value = row.get("value") if isinstance(row, Mapping) else getattr(row, "value", None)
        text = ""
        if isinstance(value, Mapping):
            text = str(value.get("text") or "")
        elif isinstance(value, str):
            text = value
        return 0 if string_fact_class(text) else 1

    candidates = [row for row in rows if row_id(row) not in selected_ids]
    candidates.sort(
        key=lambda row: (
            _string_priority(row),
            -priority.get(row_kind(row).casefold(), 0),
            row_id(row),
        )
    )
    selected.extend(candidates[: max(0, limit - len(selected))])
    return selected


def _migrate_snapshot_payload(
    host: ReportRevisionWriterHost, snapshot_id: str, payload: dict[str, object]
) -> dict[str, object]:
    """Read-only migration registry for immutable Analysis Snapshot payloads."""
    version = payload.get("schema_version")
    if version == host.SNAPSHOT_SCHEMA_VERSION:
        return payload
    if version == "1.0":
        migrated = dict(payload)
        migrated["schema_version"] = host.SNAPSHOT_SCHEMA_VERSION
        for name in (
            "relations",
            "gates",
            "model_calls",
            "analysis_turns",
            "investigation_threads",
            "investigation_hypotheses",
            "investigation_actions",
            "mechanism_effectiveness_traces",
        ):
            migrated.setdefault(name, [])
        migrated["investigation_actions"] = [
            {
                **dict(item),
                "target_selector": dict(item.get("target_selector", {}))
                if isinstance(item, Mapping)
                and isinstance(item.get("target_selector", {}), Mapping)
                else {},
                "expected_evidence_kinds": list(item.get("expected_evidence_kinds", []))
                if isinstance(item, Mapping)
                and isinstance(item.get("expected_evidence_kinds", []), list)
                else [],
                "success_condition": str(item.get("success_condition", "new_targeted_evidence"))
                if isinstance(item, Mapping)
                else "new_targeted_evidence",
                "failure_interpretation": str(item.get("failure_interpretation", "UNKNOWN"))
                if isinstance(item, Mapping)
                else "UNKNOWN",
                "cost_units": int(item.get("cost_units", 1))
                if isinstance(item, Mapping)
                else 1,
            }
            for item in migrated.get("investigation_actions", [])
            if isinstance(item, Mapping)
        ]
        return migrated
    raise ValueError(f"Analysis Snapshot {snapshot_id} uses an unsupported schema")


def _canonical_sha256(host: ReportRevisionWriterHost, value: object, *, exclude_keys: Iterable[str] = ()) -> str:
    """sha256 of the canonical JSON bytes, computed without materialising them."""
    digest = hashlib.sha256()
    for chunk in host._canonical_json_chunks(value, exclude_keys=exclude_keys):
        digest.update(chunk)
    return digest.hexdigest()


_REPORT_PROJECTION_EVIDENCE_LIMIT = 4096


# ---------------------------------------------------------------------------
# Moved implementation (P3.4-2 slice): the compose gate's exception, identical to its old home in service.py, and
# re-exported from there so `service.ReportComposeGateRejected IS report.revision_writer.ReportComposeGateRejected` -
# identity matters because callers catch it (the workbench route's 422, the plugin's GATE_REJECTED branch) and a
# second definition would silently stop catching.
# ---------------------------------------------------------------------------


class ReportComposeGateRejected(ValueError):
    """An agent draft introduced facts the deterministic fragments do not hold.

    ADR-0036 报告合成门 rejection. It stays a ``ValueError`` so every existing
    handler (the workbench route's 422, the plugin's ``GATE_REJECTED`` branch)
    keeps working unchanged, and it carries the structured violation list
    because :meth:`AnalysisService.workbench_write_report_file` writes the
    analyst's file regardless and reports the gate outcome as data instead of
    letting the write look failed.
    """

    code = "REPORT_COMPOSE_GATE_REJECTED"

    def __init__(self, violations: Iterable[str]) -> None:
        self.violations: tuple[str, ...] = tuple(violations)
        super().__init__(
            "analyst draft failed the report compose gate: "
            + "; ".join(self.violations[:8])
        )


# ---------------------------------------------------------------------------
# Moved implementation (P3.4-2 slice): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: ReportRevisionWriterHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it. P3.4-0 made the label a parameter for the
# same reason - a `report/` module appended under a banner claiming a P3.3 slice is that defect again.
# ---------------------------------------------------------------------------


def _create_report_revision(
    host: ReportRevisionWriterHost,
    session: Session,
    task: AnalysisTask,
    snapshot: AnalysisSnapshot,
    modules: list[str],
    *,
    parent_revision_id: str | None = None,
    author: str = "system",
) -> ReportRevision:
    document = build_report_document(
        selected_modules=modules,
        **_snapshot_report_context(host, snapshot),
    )
    document = host._postgres_safe_value(document)
    if not isinstance(document, dict):
        raise TypeError("report document must be an object")
    document = host._overlay_analyst_report_plan(task, document)
    document = host._postgres_safe_value(document)
    if not isinstance(document, dict):
        raise TypeError("report document must be an object")
    host._apply_honest_analysis_outcome(task, document)
    document = stamp_official_report_chrome(document)
    document = host._postgres_safe_value(document)
    if not isinstance(document, dict):
        raise TypeError("report document must be an object")
    # ADR-0036 / plan §8.3: the official GET is published through the report
    # composition entry point, so a model-polished draft (when one exists) is
    # admitted only if it passes the 报告合成门; otherwise the deterministic
    # fragments are published. Routing the live path here is what puts the gate
    # on the user-visible surface instead of leaving it test-only.
    draft = document.get("analyst_report_draft")
    markdown = host._postgres_safe_text(
        compose_official_markdown(
            document,
            draft=str(draft) if isinstance(draft, str) else "",
        )
    )
    violations = report_bloat_violations(markdown)
    violations.extend(report_analytical_violations(document))
    violations.extend(report_v3_quality_violations(document))
    if violations:
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.anti_bloat_rejected",
            actor=author,
            object_type="AnalysisSnapshot",
            object_id=snapshot.id,
            payload={"violations": violations, "markdown_bytes": len(markdown.encode("utf-8"))},
        )
        raise ValueError("report anti-bloat gate rejected document: " + "; ".join(violations))
    parent_markdown = ""
    parent_document: dict[str, object] | None = None
    if parent_revision_id:
        parent = session.get(ReportRevision, parent_revision_id)
        if parent is not None:
            parent_markdown = str(parent.markdown or "")
            if isinstance(parent.document, dict):
                parent_document = parent.document
    document["t6_revision_diff"] = host._t6_revision_diff_payload(
        parent_markdown or None,
        markdown,
        parent_document,
        document,
    )
    # Correctness verification, at the point the body is built.
    #
    # The gates above answer "may this text be published" (ADR-0036, anti-bloat, analytical and v3
    # quality) and the acceptance instrument answers "are the benchmark facts present". Neither
    # answers "is what it says TRUE", and the difference is measurable: the published revision of
    # task `ce7e310e` passed 24/24 existence assertions while its YARA rule declared two `sha256`
    # indicators that could not identify the sample - one was the digest the rule NAME was derived
    # from, the other the digest of PE resource payload `RT_ICON[5]`.
    #
    # Verification here is recorded, not fatal. A report states its own limitations and a
    # correctness finding is a fact about the artefact a reviewer must see, so the findings ride
    # along in the document and the audit trail rather than blocking publication - the same
    # treatment the investigation ledger gives a rejected action. `error_count` is the number a
    # reviewer should treat as "do not deploy this artefact yet".
    try:
        correctness = correctness_summary(
            verify_report_correctness(markdown, document)
        )
    except Exception as exc:  # noqa: BLE001 - verification must never break publication
        correctness = {
            "findings": [],
            "by_class": {},
            "error_count": 0,
            "verification_failed": f"{type(exc).__name__}: {exc}"[:240],
            "skill": "analysis-verification",
        }
    document["report_correctness"] = correctness
    # Which body-visible renderer corrections this revision carries.
    #
    # `markdown` is written once, so a fix changes only future revisions: measured on this deployment,
    # 342 of 345 tasks have a newest published revision that predates a section added since round 77, and
    # 20 revisions still carry a detection rule named after a digest. Recording the markers with the
    # artefact is what lets a consumer tell that a stored report is stale - and WHICH correction is
    # missing - instead of re-rendering every document to find out.
    try:
        document["report_corrections"] = corrections_summary(markdown)
    except Exception as exc:  # noqa: BLE001 - marker recording must never break publication
        document["report_corrections"] = {
            "markers": {},
            "missing": [],
            "current": False,
            "recording_failed": f"{type(exc).__name__}: {exc}"[:240],
        }
    if correctness.get("error_count"):
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.correctness_findings",
            actor=author,
            object_type="AnalysisSnapshot",
            object_id=snapshot.id,
            payload={
                "error_count": correctness.get("error_count"),
                "by_class": correctness.get("by_class"),
                "first": (correctness.get("findings") or [{}])[0].get("title", "")[:200],
            },
        )
    revision = ReportRevision(
        task_id=task.id,
        snapshot_id=snapshot.id,
        parent_revision_id=parent_revision_id,
        selected_modules=modules,
        document=document,
        markdown=markdown,
        author=author,
    )
    session.add(revision)
    session.flush()
    host._audit(
        session,
        case_id=task.case_id,
        task_id=task.id,
        event_type="report.generated",
        actor=author,
        object_type="ReportRevision",
        object_id=revision.id,
        payload={
            "snapshot_id": snapshot.id,
            "selected_modules": modules,
            "edit_kind": revision.edit_kind,
            "t6_substantive": bool(
                (document.get("t6_revision_diff") or {}).get("substantive")
            )
            if isinstance(document.get("t6_revision_diff"), dict)
            else False,
        },
    )
    return revision


def edit_report(
    host: ReportRevisionWriterHost,
    revision_id: str,
    markdown: str,
    actor: str = "demo-analyst",
) -> dict[str, object]:
    if not markdown.strip():
        raise ValueError("Edited report cannot be empty")
    with host.database.session_factory.begin() as session:
        parent = session.get(ReportRevision, revision_id)
        if parent is None:
            raise LookupError(revision_id)
        task = session.get(AnalysisTask, parent.task_id)
        if task is None:
            raise LookupError(parent.task_id)
        document = dict(parent.document)
        document["manual_edit"] = {
            "base_revision_id": parent.id,
            "author": actor,
            "claim_or_evidence_created": False,
        }
        document = host._postgres_safe_value(document)
        if not isinstance(document, dict):
            raise TypeError("report document must be an object")
        revision = ReportRevision(
            task_id=parent.task_id,
            snapshot_id=parent.snapshot_id,
            parent_revision_id=parent.id,
            status="DRAFT",
            author=actor,
            selected_modules=parent.selected_modules,
            document=document,
            markdown=host._postgres_safe_text(markdown),
            edit_kind="MANUAL_EDIT",
        )
        session.add(revision)
        session.flush()
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.manually_edited",
            actor=actor,
            object_type="ReportRevision",
            object_id=revision.id,
            payload={
                "base_revision_id": parent.id,
                "requires_external_publish_gate": True,
            },
        )
        new_revision_id = revision.id
    return get_report_revision(host, new_revision_id)


def get_report_revision(host: ReportRevisionWriterHost, revision_id: str) -> dict[str, object]:
    with host.database.session_factory() as session:
        revision = session.get(ReportRevision, revision_id)
        if revision is None:
            raise LookupError(revision_id)
        disposed = session.scalar(
            select(Artifact.id).where(
                Artifact.task_id == revision.task_id, Artifact.disposed_at.is_not(None)
            )
        )
        document = revision.document
        markdown = revision.markdown
        if disposed:
            document = {"content_access": "REDACTED", "snapshot_id": revision.snapshot_id}
            markdown = "[REDACTED: evidence content has been disposed; audit metadata retained]"
        return {
            "id": revision.id,
            "task_id": revision.task_id,
            "snapshot_id": revision.snapshot_id,
            "parent_revision_id": revision.parent_revision_id,
            "status": revision.status,
            "author": revision.author,
            "selected_modules": revision.selected_modules,
            "document": document,
            "markdown": markdown,
            "edit_kind": revision.edit_kind,
            "created_at": revision.created_at.isoformat(),
        }


def recompose_report(
    host: ReportRevisionWriterHost,
    task_id: str,
    selected_modules: list[str],
    actor: str = "demo-analyst",
) -> dict[str, object]:
    modules = normalize_modules(selected_modules)
    with host.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        if task is None or task.lifecycle != "SUCCEEDED":
            raise LookupError(f"Completed task {task_id} does not exist")
        case = session.get(CaseRecord, task.case_id)
        snapshot = session.scalar(
            select(AnalysisSnapshot)
            .where(AnalysisSnapshot.task_id == task_id)
            .order_by(AnalysisSnapshot.created_at.desc())
        )
        parent = session.scalar(
            select(ReportRevision)
            .where(ReportRevision.task_id == task_id)
            .order_by(ReportRevision.created_at.desc())
        )
        if case is None or snapshot is None:
            raise LookupError(task_id)
        revision = _create_report_revision(host, 
            session,
            task,
            snapshot,
            modules,
            parent_revision_id=parent.id if parent else None,
            author=actor,
        )
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.recomposed",
            actor=actor,
            object_type="ReportRevision",
            object_id=revision.id,
            payload={"selected_modules": modules, "snapshot_id": snapshot.id},
        )
        revision_id = revision.id
    return get_report_revision(host, revision_id)


def publish_report(host: ReportRevisionWriterHost, revision_id: str, *, actor: str) -> dict[str, object]:
    with host.database.session_factory.begin() as session:
        revision = session.get(ReportRevision, revision_id)
        if revision is None:
            raise LookupError(revision_id)
        if revision.status != "APPROVED":
            raise ValueError("only an APPROVED report can be published")
        task = session.get(AnalysisTask, revision.task_id)
        if task is None:
            raise LookupError(revision.task_id)
        integrity = host.audit_integrity(task.id)
        if not integrity.get("valid") or not integrity.get("seals"):
            raise ValueError("publishing requires a valid sealed audit chain")
        revision.status = "PUBLISHED"
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.published",
            actor=actor,
            object_type="ReportRevision",
            object_id=revision.id,
            payload={"snapshot_id": revision.snapshot_id},
        )
    return get_report_revision(host, revision_id)


def submit_analyst_draft(
    host: ReportRevisionWriterHost,
    revision_id: str,
    markdown: str,
    *,
    actor: str = "dsh-agent",
) -> dict[str, object]:
    """Admit an agent-authored analyst narrative through the compose gate.

        ADR-0036 / plan §8.3: a fluent draft may reorganise, explain and shorten
        the deterministic fragments, but it may not introduce a fact they do not
        contain.  ``compose_gate_violations`` rejects a novel endpoint, IPv4,
        process image or creation-flags value, and rejects restating a
        CANDIDATE/UNKNOWN as established.

        This is deliberately a *separate* entry point from ``edit_report``: a
        human manual edit is a superseding act by an accountable analyst, while
        an agent draft is a proposal that must clear the gate before it becomes
        the official body.  ``approve_report``/``publish_report`` do not run the
        gate, so gating has to happen here.

        A rejected draft raises ``ReportComposeGateRejected`` (a ``ValueError``)
        carrying the violations instead of silently falling back, so the agent
        can see what it fabricated and revise rather than believing it published.
        The structured list is on the exception because
        :meth:`workbench_write_report_file` keeps its file write authoritative
        and reports the rejection as data.
        """
    from threat_report_agent.report.analyst_report import (
        compose_gate_violations,
        compose_official_markdown,
        unprovenanced_fact_tokens,
    )

    draft = str(markdown or "")
    if not draft.strip():
        raise ValueError("analyst draft cannot be empty")
    with host.database.session_factory.begin() as session:
        parent = session.get(ReportRevision, revision_id)
        if parent is None:
            raise LookupError(revision_id)
        task = session.get(AnalysisTask, parent.task_id)
        if task is None:
            raise LookupError(parent.task_id)
        document = dict(parent.document)
        fragments = compose_official_markdown(document)
        violations = compose_gate_violations(draft, fragments)
        if violations:
            raise ReportComposeGateRejected(violations)
        # A draft can pass the gate and still carry a fact this analysis never
        # produced: the gate's four classes are endpoint-shaped, so a scheduled-task
        # name, registry key, path or digest lifted from another document passes
        # unchanged.  Measured on the published Resume body this check is quiet (only
        # a trailing `;` tripped it), so recording it costs no false alarms and closes
        # the "nothing detects it" gap - an unprovenanced fact is now auditable
        # evidence rather than an argument.
        unprovenanced = unprovenanced_fact_tokens(draft, fragments)
        gated = host._postgres_safe_text(
            compose_official_markdown(document, draft=draft)
        )
        document["analyst_report_draft"] = host._postgres_safe_text(draft)
        document["analyst_report_draft_gate"] = "PASSED"
        document = host._postgres_safe_value(document)
        if not isinstance(document, dict):
            raise TypeError("report document must be an object")
        revision = ReportRevision(
            task_id=parent.task_id,
            snapshot_id=parent.snapshot_id,
            parent_revision_id=parent.id,
            status="DRAFT",
            author=actor,
            selected_modules=parent.selected_modules,
            document=document,
            markdown=gated,
            edit_kind="AGENT_GENERATED",
        )
        session.add(revision)
        session.flush()
        host._audit(
            session,
            case_id=task.case_id,
            task_id=task.id,
            event_type="report.analyst_draft_admitted",
            actor=actor,
            object_type="ReportRevision",
            object_id=revision.id,
            payload={
                "base_revision_id": parent.id,
                "gate": "report-compose-gate",
                "gate_status": "PASSED",
                "unprovenanced_fact_count": len(unprovenanced),
                "unprovenanced_facts": unprovenanced[:20],
            },
        )
        new_revision_id = revision.id
    return get_report_revision(host, new_revision_id)


def workbench_submit_analyst_draft(
    host: ReportRevisionWriterHost,
    dsh_session_id: str,
    markdown: str,
    *,
    actor: str = "dsh-agent",
) -> dict[str, object]:
    """Session-scoped entry point for an agent-authored report narrative.

        The DSH client refuses any path outside ``/api/v1/workbench/``, so the
        agent cannot reach the analyst-facing ``/api/v1/reports/{id}/analyst-draft``
        route directly.  This resolves the session's authoritative task and its
        newest revision, then defers to :meth:`submit_analyst_draft`, which is
        where 报告合成门 (ADR-0036) is enforced.
        """
    if not str(markdown or "").strip():
        raise ValueError("analyst draft cannot be empty")
    link = host.workbench_task_for_session(dsh_session_id)
    if not link:
        raise ValueError("no authoritative task is bound to this session")
    task_id = str(link.get("task_id") or "")
    with host.database.session_factory() as session:
        revision = session.scalar(
            select(ReportRevision)
            .where(ReportRevision.task_id == task_id)
            .order_by(ReportRevision.created_at.desc())
            .limit(1)
        )
        if revision is None:
            raise ValueError("the bound task has no report revision to revise")
        revision_id = revision.id
    return submit_analyst_draft(host, revision_id, markdown, actor=actor)
