"""P3.3f-1, cluster B: the seed/evidence-key helpers that `_run_investigation_loop` closes over.

WHY THIS MODULE EXISTS. Twelve module-level names in `service.py` are read by the loop AND by un-moved code or by tests
(MEASURED with `.scratch/p33f-travellers.py`: ten of the thirteen test-read, four also read inside `service.py`). A name
with two readers needs a home BOTH may import - the P3.3e pattern - instead of travelling with the loop and leaving one
of its readers behind.

WHAT IT HOLDS, measured with `.scratch/p33f-sink-measure.py`: the seed-row selection and ranking helpers
(`admit_investigation_seed_clusters`, `coalesce_investigation_seed_clusters`, `_seed_context_rows`, `how_seed_slot_rank`,
`_seed_playbook`), the two budgets (`investigation_seed_step_budget`,
`investigation_budget_charged_action_count`), the action/provenance keys (`_scoped_investigation_action_key`,
`_provenance_free_digest`), the evidence classification tables (`_evidence_anchor_keys`, `_evidence_api_symbols`) and
`_strip_provenance` - twelve functions in all, with SEVEN module constants their closures need
(`_SEED_CATEGORY_PLAYBOOKS`, `_ARTIFACT_WIDE_SCHEDULER_DIMENSIONS`, `_HOW_SLOT_RANK`, `_PLACEHOLDER_EMU_BUDGET_STATUSES`,
`_PER_SLOT_TRACE_CAP`, `_PROVENANCE_STRIP_KEYS` and the `_HOW_SEED_CATEGORIES` alias).

ONE OF THOSE CONSTANTS DID NOT COME FROM `service.py`, AND THAT IS THE PART THE DESIGN DID NOT PREDICT.
`_HOW_SEED_CATEGORIES = HOW_SEED_CATEGORIES` needed a name DEFINED IN
`threat_report_agent.task.analysis_task_orchestration`, which section 3.2 does not admit into `investigation/`, so the
VALUE was sunk here first (`HOW_SEED_CATEGORIES`, a 12-line frozenset) with a re-export left in the task module. That is
the same class of blocker as the five loop-path names layer item 1 moved, and it was found only because a probe walks
the closure of CONSTANTS as well as functions - the extractor's own import guard was checking functions only at the time
and had passed the sink as safe. It also creates an edge the design did not list:
`task.analysis_task_orchestration -> investigation.seed_support`. An earlier revision of this docstring counted six
constants; a Standards-axis review of this step measured seven.

WHAT STAYS IN `service.py`: `_investigation_scheduled_keys`, the ONE name of the thirteen with no reader but the loop, so
it travels with the loop in P3.3f-2 rather than being re-exported here for nothing. That is also the one name the layer
scan still flags - not because a layer forbids it, but because `service.py` defines it itself.

`service.py` re-exports EVERY name in this module as `X as X` (the repo's spelling for an intentional re-export), not
only the ones with readers today: plan section 7.1 step 4 keeps the old path reachable until P4 removes the shims, and a
review of this very step measured six private names and one public constant that had become unreachable while nothing
failed loudly. Those re-exports are a P4 deletion target, recorded in the step's records.
"""
from __future__ import annotations

import hashlib
import json

from typing import Iterable, Mapping

# From the DEFINING submodules, not the package re-exports: the extractor's own lesson is that a package `__init__` can
# be partially initialised while one of its submodules is being imported, and `investigation/__init__.py` is imported
# before this module.
from threat_report_agent.investigation.investigation import (
    ActionType,
    MechanismPlaybookRegistry,
    action_scope_from_plan,
)
from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol
from threat_report_agent.models import Evidence
from threat_report_agent.static.evidence_recovery import canonical_action_key


HOW_SEED_CATEGORIES = frozenset(
    {
        "dynamic_api",
        "loader",
        "decode",
        "network",
        "execution",
        "process",
        "ppid",
        "thread",
    }
)


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py, with the receiver it used to reach
# through `self`/`cls` dropped - none of these bodies needs one (this module declares no host port, and the
# extractor refuses to write a body that still refers to a receiver). This banner is deliberately SLICE-AGNOSTIC.
# ---------------------------------------------------------------------------


# Keyword supporting seeds (persistence/evasion/pe_parser) must not inherit
# leftover TRACE after HOW persist skip. Kunglao priority_ratio: the 64-action
# cap belongs to typed HOW questions, not entrypoint GET_CALLEES.
# RELOCATED WITH ITS CONSTANT: this comment sat above `_HOW_SEED_CATEGORIES` in service.py and did NOT travel with the
# constant when the extractor moved it (that tool carries a definition's span, not the comment block above it), so a
# Standards-axis review of this step found it orphaned above an UNRELATED definition. Comments carry the phase's
# expensive lessons; they belong with the code they explain.
_HOW_SEED_CATEGORIES = HOW_SEED_CATEGORIES


_SEED_CATEGORY_PLAYBOOKS = {
    "dynamic_api": "dynamic-api-resolution",
    "loader": "dynamic-api-resolution",
    "decode": "xor-config-recovery",
    "network": "http-download",
    "execution": "process-execution",
    "process": "process-execution",
    "ppid": "ppid-process-chain",
    "pe_parser": "entrypoint-timeline",
}


# Semantic HOW dimensions share one scheduler thread. Function-scoped copies
# of GetProcAddress/CreateProcess filled the 12-cluster window and spent the
# 64-action cap on empty TRACE. Generic observations stay function-local.
# RELOCATED WITH ITS CONSTANT for the same reason as the comment above.
_ARTIFACT_WIDE_SCHEDULER_DIMENSIONS = frozenset(
    {
        "dynamic_api_resolution",
        "decode_recovery",
        "network_download",
        "process_execution",
        "parent_process_spoofing",
        "ppid_spoofing",
        "unique_os_thread",
        "thread_callback",
    }
)


_HOW_SLOT_RANK = {
    "process": 0,
    "execution": 0,
    "ppid": 1,
    "network": 2,
    "dynamic_api": 3,
    "loader": 3,
    "decode": 4,
    "thread": 5,
}


_PLACEHOLDER_EMU_BUDGET_STATUSES = frozenset(
    {"DEFERRED_TO_WORKER", "WORKER_REQUIRED", "SUPERSEDED_BY_WORKER"}
)


_PER_SLOT_TRACE_CAP = 8


_PROVENANCE_STRIP_KEYS = frozenset(
    {
        "derivation",
        "source_evidence_id",
        "evidence_id",
        "action_id",
        "investigation_action_id",
        "planner_turn_id",
        "model_call_id",
        "origin",
    }
)


def _evidence_anchor_keys(row: Evidence) -> set[str]:
    """Extract static function/RVA identities used to narrow a seed context."""
    keys: set[str] = set()
    for value in (row.anchor, row.value):
        if not isinstance(value, Mapping):
            continue
        for name in ("function_entry", "entry", "entry_rva", "rva", "address", "function"):
            item = value.get(name)
            if isinstance(item, (str, int)) and str(item).strip():
                keys.add(str(item).strip().casefold())
    return keys


def _evidence_api_symbols(row: Evidence) -> set[str]:
    """Return normalized API-like symbols without treating free text as an API."""
    value = row.value if isinstance(row.value, Mapping) else {}
    symbols: set[str] = set()
    for name in ("api", "api_name", "target_name", "target_function"):
        item = value.get(name)
        if isinstance(item, (str, int)) and str(item).strip():
            symbols.add(normalize_api_symbol(item))
    if row.kind in {"import_symbol", "export_symbol", "resolved_api", "function_call"}:
        item = value.get("name")
        if isinstance(item, (str, int)) and str(item).strip():
            symbols.add(normalize_api_symbol(item))
    for name in ("call_targets", "calls", "functions"):
        nested = value.get(name)
        if not isinstance(nested, (list, tuple)):
            continue
        for item in nested:
            if isinstance(item, Mapping):
                for field in ("api", "api_name", "target_name", "target_function", "name"):
                    candidate = item.get(field)
                    if isinstance(candidate, (str, int)) and str(candidate).strip():
                        symbols.add(normalize_api_symbol(candidate))
            elif isinstance(item, (str, int)) and str(item).strip():
                symbols.add(normalize_api_symbol(item))
    return {item for item in symbols if item}


def _provenance_free_digest(item: object) -> str:
    """Stable digest of an observation with provenance removed."""
    return hashlib.sha256(
        json.dumps(
            _strip_provenance(item),
            ensure_ascii=True,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _scoped_investigation_action_key(
    action_type: str,
    selector: Mapping[str, object],
    plan: Mapping[str, object] | None = None,
) -> str:
    """Build the durable action key with the mechanism scope, if available."""
    scope = action_scope_from_plan(plan)
    payload: dict[str, object] = {"target_selector": dict(selector)}
    if scope:
        payload["action_scope"] = scope
    return canonical_action_key(action_type, payload)


def _seed_context_rows(
    rows: list[Evidence],
    cluster: Mapping[str, object] | None,
    *,
    limit: int = 160,
) -> list[Evidence]:
    """Build one seed-local context without losing explicit evidence bridges.

    Direct seed Evidence, same-function/RVA observations, and derived rows
    naming a seed source are admissible. This blocks unrelated artifact-wide
    imports from steering a specialist thread while retaining the exact bridge
    required by a cross-function static verifier.
    """
    if not isinstance(cluster, Mapping):
        return rows[:limit]
    source_ids = {
        str(item)
        for item in cluster.get("evidence_ids", ())
        if isinstance(item, (str, int)) and str(item).strip()
    }
    anchors = (
        {str(cluster.get("function")).strip().casefold()}
        if str(cluster.get("function") or "").strip()
        else set()
    )
    direct = [row for row in rows if row.id in source_ids]
    for row in direct:
        anchors.update(_evidence_anchor_keys(row))
    # A seed may initially identify an imported API or a compact function-call
    # fact without carrying the Ghidra function identity. Recover the local
    # function context by exact API symbol, then pull its instruction/CFG/call
    # siblings by the resulting RVA. This is bounded evidence closure, not an
    # artifact-wide expansion: only the seed's explicit API symbols are used.
    seed_api_symbols = {
        symbol for row in direct for symbol in _evidence_api_symbols(row)
    }
    if seed_api_symbols:
        for row in rows:
            if row.kind != "function_context":
                continue
            if _evidence_api_symbols(row) & seed_api_symbols:
                anchors.update(_evidence_anchor_keys(row))
    if not direct and not anchors:
        # Older snapshots did not attach evidence IDs to every seed. Keep a
        # bounded fallback for replay rather than creating an empty question.
        return rows[:limit]

    selected: list[tuple[int, int, Evidence]] = []
    bridge_source_ids: set[str] = set()
    for row in rows:
        value = row.value if isinstance(row.value, Mapping) else {}
        bridge_ids = {
            str(item)
            for item in value.get("source_evidence_ids", ())
            if isinstance(item, (str, int)) and str(item).strip()
        }
        # A derived mechanism link is only useful to a verifier when the
        # bounded context also carries the exact rows it cites.  Pull those
        # rows forward before the cap is applied; otherwise a large PE can
        # silently turn a provenance-bearing link into an unverifiable label.
        if bridge_ids:
            bridge_source_ids.update(bridge_ids)
        same_anchor = bool(anchors & _evidence_anchor_keys(row))
        if (
            row.id in source_ids
            or same_anchor
            or bool(bridge_ids & source_ids)
            or row.kind in {"pe_structure", "file_identity"}
        ):
            selected.append((0, len(selected), row))

    # Add the source rows named by an admissible derived link even when they do
    # not share the seed's first anchor (cross-function links are intentionally
    # represented this way).  This remains bounded because the link itself was
    # already present in the artifact-local corpus and only exact IDs are
    # admitted.
    for index, row in enumerate(rows):
        if row.id in bridge_source_ids and not any(item[2].id == row.id for item in selected):
            selected.append((1, index, row))

    # Prefer explicit seed rows and derived links, then same-function context,
    # while retaining deterministic source order within each priority.  The
    # previous source-order-only slice could discard the one link that carried
    # the resolver/consumer bridge on large samples.
    prioritized: list[tuple[int, int, Evidence]] = []
    for index, (priority, _old_index, row) in enumerate(selected):
        value = row.value if isinstance(row.value, Mapping) else {}
        bridge_ids = {
            str(item)
            for item in value.get("source_evidence_ids", ())
            if isinstance(item, (str, int)) and str(item).strip()
        }
        if row.id in source_ids:
            priority = 0
        elif row.id in bridge_source_ids:
            priority = min(priority, 1)
        elif bridge_ids or row.kind.startswith("mechanism_"):
            priority = min(priority, 1)
        elif anchors & _evidence_anchor_keys(row):
            priority = max(priority, 2)
        elif row.kind in {"pe_structure", "file_identity"}:
            priority = max(priority, 3)
        prioritized.append((priority, index, row))
    prioritized.sort(key=lambda item: (item[0], item[1], str(item[2].id)))
    return [row for _priority, _index, row in prioritized[:limit]]


def _seed_playbook(
    registry: MechanismPlaybookRegistry,
    cluster: Mapping[str, object] | None,
):
    """Resolve an explicit seed contract before considering artifact-wide text.

    An artifact frequently contains several unrelated capabilities. Choosing a
    playbook from every artifact row lets a prominent loader import override a
    transport, decoder, or process seed. The seed map is the scheduler's
    declared question, so it is authoritative when it names a known profile.
    """
    if not isinstance(cluster, Mapping):
        return None
    requested = str(cluster.get("playbook_id") or "").strip()
    if not requested:
        requested = _SEED_CATEGORY_PLAYBOOKS.get(str(cluster.get("category") or ""), "")
    return registry.by_id(requested) if requested else None


def admit_investigation_seed_clusters(
    clusters: object,
    *,
    max_evidence_ids: int = 96,
) -> list[dict[str, object]]:
    """Keep one thread per HOW dimension. Keyword seeds stay in the seed map.

    Persistence/evasion/pe_parser/generic clusters used to become UNKNOWN
    threads with no results. The DSH planner then saw a 12-thread OPEN
    frontier and asked for another investigation round.
    """
    admitted: list[dict[str, object]] = []
    for cluster in coalesce_investigation_seed_clusters(
        clusters,
        max_evidence_ids=max_evidence_ids,
    ):
        if str(cluster.get("category") or "").strip() in _HOW_SEED_CATEGORIES:
            admitted.append(cluster)
    return admitted


def coalesce_investigation_seed_clusters(
    clusters: object,
    *,
    max_evidence_ids: int = 96,
) -> list[dict[str, object]]:
    """Merge equivalent static seed clusters before scheduling threads.

    The parser intentionally keeps function-local seed groups separate so the
    evidence ledger remains precise.  The investigation scheduler, however,
    needs one bounded question per mechanism dimension.  Without this second
    step several GetProcAddress/LoadLibrary observations can create identical
    resolver hypotheses and spend the action budget on duplicate work.

    This only changes the scheduler frontier: original seed-map Evidence and
    the full queue are retained.  The highest-priority group supplies the
    thread identity/question while the merged row carries every contributing
    cluster ID, hypothesis, question and Evidence ID for audit/replay.
    """
    if not isinstance(clusters, (list, tuple)):
        return []

    aliases = {
        "dynamic_api": "dynamic_api_resolution",
        "dynamic_api_resolution": "dynamic_api_resolution",
        "decode": "decode_recovery",
        "decode_recovery": "decode_recovery",
        "network": "network_download",
        "network_download": "network_download",
        "execution": "process_execution",
        "process_execution": "process_execution",
        "ppid": "parent_process_spoofing",
        "ppid_spoofing": "parent_process_spoofing",
        "parent_process_spoofing": "parent_process_spoofing",
        "thread": "unique_os_thread",
        "unique_os_thread": "unique_os_thread",
        "thread_callback": "unique_os_thread",
        "persistence": "persistence",
        "evasion": "evasion",
        "pe_parser": "pe_parser",
    }

    ranked: list[tuple[int, str, int, dict[str, object]]] = []
    for position, raw in enumerate(clusters):
        if not isinstance(raw, Mapping):
            continue
        question = str(raw.get("question", "")).strip()
        if not question:
            continue
        cluster = dict(raw)
        try:
            priority = int(cluster.get("priority", 0))
        except (TypeError, ValueError):
            priority = 0
        cluster_id = str(cluster.get("id", f"cluster-{position}"))
        ranked.append((-priority, cluster_id, position, cluster))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))

    result: list[dict[str, object]] = []
    by_dimension: dict[str, dict[str, object]] = {}
    for _negative_priority, cluster_id, _position, cluster in ranked:
        category = str(cluster.get("category", "generic")).strip() or "generic"
        raw_dimension = str(
            cluster.get("mechanism_type")
            or cluster.get("dimension")
            or category
        ).strip().casefold()
        # Generic observations remain function-local. Semantic HOW dimensions
        # share one artifact-wide thread so GetProcAddress in FUN_A and FUN_B
        # do not each consume a 12-cluster slot and five TRACE actions.
        if raw_dimension in {"", "generic"}:
            dimension = "generic:" + str(
                cluster.get("function") or cluster.get("question")
            ).casefold()
        else:
            dimension = aliases.get(raw_dimension, raw_dimension)
        function_scope = cluster.get("function")
        if not function_scope:
            for key in ("function_entry", "entry", "rva"):
                candidate = cluster.get(key)
                if isinstance(candidate, (str, int)) and str(candidate).strip():
                    function_scope = candidate
                    break
        if (
            dimension not in _ARTIFACT_WIDE_SCHEDULER_DIMENSIONS
            and isinstance(function_scope, (str, int))
            and str(function_scope).strip()
        ):
            dimension = f"{dimension}:function:{str(function_scope).strip().casefold()}"
        current = by_dimension.get(dimension)
        if current is None:
            merged = dict(cluster)
            merged["priority"] = max(0, -_negative_priority)
            merged["scheduler_dimension"] = dimension
            merged["source_cluster_ids"] = [cluster_id]
            merged["frontier_questions"] = [str(cluster["question"])]
            merged["evidence_ids"] = list(
                dict.fromkeys(
                    str(item)
                    for item in cluster.get("evidence_ids", [])
                    if str(item).strip()
                )
            )[:max_evidence_ids]
            merged["hypotheses"] = list(
                dict.fromkeys(
                    str(item)
                    for item in cluster.get("hypotheses", [])
                    if str(item).strip()
                )
            )
            by_dimension[dimension] = merged
            result.append(merged)
            continue

        current["source_cluster_ids"] = list(
            dict.fromkeys([*current["source_cluster_ids"], cluster_id])
        )
        current["frontier_questions"] = list(
            dict.fromkeys([*current["frontier_questions"], str(cluster["question"])])
        )
        current["evidence_ids"] = list(
            dict.fromkeys(
                [*current.get("evidence_ids", []), *(
                    str(item)
                    for item in cluster.get("evidence_ids", [])
                    if str(item).strip()
                )]
            )
        )[:max_evidence_ids]
        current["hypotheses"] = list(
            dict.fromkeys(
                [*current.get("hypotheses", []), *(
                    str(item)
                    for item in cluster.get("hypotheses", [])
                    if str(item).strip()
                )]
            )
        )
    return result


def how_seed_slot_rank(seed: Mapping[str, object] | None) -> int:
    """Lower is higher value. Keyword/supporting seeds sort last."""
    payload = seed if isinstance(seed, Mapping) else {}
    cluster = payload.get("_seed_cluster")
    cluster = cluster if isinstance(cluster, Mapping) else {}
    category = str(cluster.get("category") or payload.get("category") or "").strip()
    return _HOW_SLOT_RANK.get(category, 9)


def investigation_budget_charged_action_count(
    *,
    attempted_ids: Iterable[object],
    actions: Iterable[object] = (),
    evidence: Iterable[object] = (),
) -> int:
    """Count investigation invocations that consumed real work, not emu tickets.

    Kunglao cost-is-noise: an isolated-worker CONTROLLED_EMULATE placeholder
    is a dispatch ticket. Charging it against the 64-action cap left DECODE
    and TRACE unqueued after 12 threads each emitted DEFERRED_TO_WORKER.
    """
    charged = {str(item) for item in attempted_ids if str(item).strip()}
    if not charged:
        return 0
    rows = [item for item in evidence if isinstance(item, Mapping)]
    for action in actions:
        action_id = str(getattr(action, "id", "") or "").strip()
        action_type = getattr(action, "action_type", None)
        type_name = str(getattr(action_type, "value", action_type) or "")
        if action_id not in charged or type_name != ActionType.CONTROLLED_EMULATE.value:
            continue
        statuses = [
            str((row.get("value") or {}).get("status") or "").upper()
            for row in rows
            if str(row.get("source_action_id") or "") == action_id
            and str(row.get("kind") or "") == "simulation_result"
            and isinstance(row.get("value"), Mapping)
        ]
        if statuses and all(item in _PLACEHOLDER_EMU_BUDGET_STATUSES for item in statuses):
            charged.discard(action_id)
    return len(charged)


def investigation_seed_step_budget(*, remaining: int, slot_cap: int = _PER_SLOT_TRACE_CAP) -> int:
    """Return the actions one seed thread may attempt from the leftover budget.

    ``slot_cap`` is a *fair-share* admission helper: a caller that wants to
    spread a small leftover across many seeds evenly can pass a cap, and
    ``slot_cap=0`` means "no per-slot quota, only the invocation's remaining
    budget".  The live investigation path passes ``0``.  It previously passed
    ``_PER_SLOT_TRACE_CAP`` for every seed that matched a mechanism playbook,
    which clipped each thread to eight actions per invocation regardless of the
    configured ``investigation_max_steps``; the configured budget could not
    deepen anything because this total was the binding number.

    Kunglao priority_ratio / dead-letter context: persist CLAIM_READY already
    skips TRACE, so an OPEN slot that cannot close from persist still ends
    bounded by its own frontier rather than by an equal split across seeds.
    """
    try:
        leftover = int(remaining)
    except (TypeError, ValueError):
        leftover = 0
    leftover = max(0, leftover)
    try:
        cap = int(slot_cap)
    except (TypeError, ValueError):
        cap = _PER_SLOT_TRACE_CAP
    cap = max(0, cap)
    if cap <= 0:
        return leftover
    return min(leftover, cap)


def _strip_provenance(item: object) -> object:
    """Recursively drop provenance fields, keeping the semantic payload.

    Action/tool IDs and provenance envelopes describe *who* produced an
    observation, not the observation itself, so they must not defeat reuse when two
    mechanism threads ask the same bounded static query.

    MEASURED NOTE - do not "optimise" the copy away.  This function builds a cleaned
    copy of the whole payload and the caller then `json.dumps` it, which looks
    wasteful: a live stack caught it recursing for minutes over 2.1 MB payloads, once
    per produced row.  Replacing it with a Python-level serialiser that skipped the
    provenance keys while walking the ORIGINAL (no copy at all) was implemented,
    verified byte-identical, and then measured **3-6x SLOWER**:

        instruction window 20000   718 kB   copy+json 0.006 s   direct 0.032 s
        data references 8000       396 kB   copy+json 0.017 s   direct 0.052 s

    `json.dumps` is C and the intermediate copy is cheap next to per-token Python
    string building.  The copy is not the bottleneck; the payload size is.
    """
    if isinstance(item, Mapping):
        cleaned: dict[str, object] = {}
        for raw_key, raw_value in item.items():
            key = str(raw_key)
            normalized = key.casefold()
            if normalized in _PROVENANCE_STRIP_KEYS or normalized.endswith(
                "_evidence_ids"
            ):
                continue
            cleaned[key] = _strip_provenance(raw_value)
        return cleaned
    if isinstance(item, (list, tuple, set, frozenset)):
        return [_strip_provenance(value) for value in item]
    return item
