"""Report Revision writing: assembling the Report Document, gating it and persisting the revision (plan §P3.4).

This module is the new home of the revision-writer slice of `AnalysisService`. It is filled in TWO steps, because the
design (docs/p34-revision-writer-design-20260922.md) measured the slice as two layers with an upward-only dependency:

* **P3.4-1** (this step) - the assembly/selection layer: `_snapshot_report_context` (138), `_select_report_evidence_rows`
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
regexes use). The pin is therefore 2 members, as the design measured.
"""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace
from typing import Iterable, Mapping, Protocol

from ..models import AnalysisSnapshot
from .reporting import instruction_window_carries_process_creation_flags, string_fact_class

#: The host members the P3.4-1 bodies reach, i.e. what `ReportRevisionWriterHost` must provide. Read by the mover
#: (`p33-extract.py --port-constant REVISION_WRITER_HOST_MEMBERS`) and asserted against the bodies by the contract test.
#: P3.4-2 will extend this tuple to the full 11-member pin the design measured.
REVISION_WRITER_HOST_MEMBERS: tuple[str, ...] = (
    "_canonical_json_chunks",
    "SNAPSHOT_SCHEMA_VERSION",
)


class ReportRevisionWriterHost(Protocol):
    """What the moved revision-writer bodies may use on the object that owns them.

    TWO members, each measured: `_canonical_json_chunks` is the chunked canonical-JSON primitive `_canonical_sha256`
    reads through `cls.`, and `SNAPSHOT_SCHEMA_VERSION` is the snapshot-seal schema constant
    `_migrate_snapshot_payload` reads through `cls.`. Both stay on `AnalysisService` because more of the service reads
    them than this slice (measured: `self.`/`cls.` sites outside the writer).
    """

    SNAPSHOT_SCHEMA_VERSION: str

    def _canonical_json_chunks(
        self,
        value: object,
        *,
        exclude_keys: Iterable[str] = ...,
        chunk_bytes: int | None = ...,
    ) -> Iterable[bytes]: ...


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
