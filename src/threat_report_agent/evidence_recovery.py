"""Typed retrieval primitives for evidence-driven static investigation.

The module deliberately works on plain serialized Evidence rows.  Database
adapters decide how to obtain a bounded candidate set; this layer decides which
of those candidates answer one investigation question and why.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import re
from typing import Iterable, Mapping

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from threat_report_agent.evidence_index import canonical_selector, target_search_keys
from threat_report_agent.models import Evidence, EvidenceSearchKey


class EvidenceStage(StrEnum):
    PRODUCED = "PRODUCED"
    NORMALIZED = "NORMALIZED"
    PERSISTED = "PERSISTED"
    ELIGIBLE = "ELIGIBLE"
    CANDIDATE = "CANDIDATE"
    SELECTED = "SELECTED"
    DELIVERED = "DELIVERED"
    REFERENCED_BY_MODEL = "REFERENCED_BY_MODEL"
    ACCEPTED_AS_SUPPORT = "ACCEPTED_AS_SUPPORT"


class ContextRole(StrEnum):
    CORE_SUPPORT = "CORE_SUPPORT"
    CORROBORATING = "CORROBORATING"
    NAVIGATION = "NAVIGATION"
    EXPANSION = "EXPANSION"


class FailureInterpretation(StrEnum):
    UNKNOWN = "UNKNOWN"
    NO_NEW_EVIDENCE = "NO_NEW_EVIDENCE"
    STATIC_BOUNDARY = "STATIC_BOUNDARY"


@dataclass(frozen=True)
class EvidenceDeliveryEvent:
    evidence_id: str
    stage: EvidenceStage
    turn_id: str
    thread_id: str
    details: dict[str, object]


class EvidenceDeliveryLedger:
    """Append-only, in-memory funnel used before persisting a model turn."""

    _ORDER = (
        EvidenceStage.PRODUCED,
        EvidenceStage.NORMALIZED,
        EvidenceStage.PERSISTED,
        EvidenceStage.ELIGIBLE,
        EvidenceStage.CANDIDATE,
        EvidenceStage.SELECTED,
        EvidenceStage.DELIVERED,
        EvidenceStage.REFERENCED_BY_MODEL,
        EvidenceStage.ACCEPTED_AS_SUPPORT,
    )

    def __init__(self, *, turn_id: str, thread_id: str) -> None:
        self.turn_id = turn_id
        self.thread_id = thread_id
        self._events: list[EvidenceDeliveryEvent] = []
        self._last_stage: dict[str, EvidenceStage] = {}

    @property
    def events(self) -> tuple[EvidenceDeliveryEvent, ...]:
        return tuple(self._events)

    @property
    def counts(self) -> dict[EvidenceStage, int]:
        return {
            stage: len({event.evidence_id for event in self._events if event.stage == stage})
            for stage in self._ORDER
        }

    def stage_for(self, evidence_id: str) -> EvidenceStage | None:
        """Return the latest recorded funnel stage for one Evidence item."""
        return self._last_stage.get(evidence_id)

    def advance(
        self,
        evidence_id: str,
        stage: EvidenceStage,
        *,
        details: Mapping[str, object] | None = None,
    ) -> EvidenceDeliveryEvent:
        if not evidence_id:
            raise ValueError("evidence_id is required")
        if evidence_id in self._last_stage:
            current_index = self._ORDER.index(self._last_stage[evidence_id])
            target_index = self._ORDER.index(stage)
            if target_index != current_index + 1:
                raise ValueError(
                    f"illegal evidence funnel transition: {self._last_stage[evidence_id]}->{stage}"
                )
        elif stage != EvidenceStage.PRODUCED:
            raise ValueError("evidence funnel must begin at PRODUCED")
        event = EvidenceDeliveryEvent(
            evidence_id=evidence_id,
            stage=stage,
            turn_id=self.turn_id,
            thread_id=self.thread_id,
            details=dict(details or {}),
        )
        self._events.append(event)
        self._last_stage[evidence_id] = stage
        return event


_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,127}|0x[0-9a-fA-F]+|\d+")
_PRIMARY_KINDS = frozenset(
    {
        "xref",
        "function_context",
        "function_instruction_window",
        "pcode_slice",
        "cfg_block",
        "data_reference",
        "function_call",
        "abstract_execution_trace",
        "decode_result",
        "decoded_artifact",
        "mechanism_decode_window",
        "api_argument_trace",
    }
)

_DEEP_CONTEXT_KINDS = frozenset({
    "function_context", "function_instruction_window", "pcode_slice",
    "api_argument_trace", "value_flow", "resolved_api", "decode_result",
    "mechanism_decode_window", "abstract_execution_trace",
})


def canonical_token(value: object) -> str:
    return " ".join(str(value).casefold().split())


_ACTION_SELECTOR_KEYS = frozenset(
    {"target", "api", "function", "function_entry", "entry", "rva", "address"}
)
_FUNCTION_SELECTOR_KEYS = frozenset({"function", "function_entry", "entry", "rva", "address"})
_FUNCTION_LOCATOR = re.compile(r"^(?:0x[0-9a-f]+|[0-9a-f]{5,}|fun_[0-9a-f]+|sub_[0-9a-f]+)$", re.IGNORECASE)


def _canonical_action_selector(value: Mapping[str, object]) -> dict[str, str]:
    """Normalize selector aliases without merging API and function scopes.

    Historical actions used ``function_entry`` while the deep-mining planner
    intentionally uses ``target`` for the same RVA.  The normal form makes
    those queries dedupe, while an API name stays in a distinct scope so an
    API-oriented query cannot suppress a function-oriented query by accident.
    """
    selector = {
        str(key): item
        for key, item in value.items()
        if str(key) in _ACTION_SELECTOR_KEYS
        and isinstance(item, (str, int))
        and str(item).strip()
    }
    if not selector:
        return {}
    function_key = next((key for key in _FUNCTION_SELECTOR_KEYS if key in selector), None)
    if function_key is not None:
        return {
            "scope": "function",
            "target": canonical_token(selector[function_key]),
        }
    if "api" in selector:
        return {"scope": "api", "target": canonical_token(selector["api"])}
    target = canonical_token(selector["target"])
    scope = (
        "function"
        if _FUNCTION_LOCATOR.fullmatch(target) or target in {"entry", "entrypoint", "main"}
        else "symbol"
    )
    return {"scope": scope, "target": target}


def canonical_action_key(action_type: str, parameters: Mapping[str, object]) -> str:
    """Return a target- and investigation-scope-sensitive action key.

    ``action_scope`` is deliberately optional for backwards compatibility.
    Legacy callers that only know the target keep their historical key, while
    mechanism-scoped investigations can run the same action type against the
    same function for independent questions (for example decode and process
    execution) without suppressing one another.
    """
    payload = dict(parameters)
    nested_selector = payload.get("target_selector")
    if isinstance(nested_selector, Mapping):
        normalized_selector = _canonical_action_selector(nested_selector)
        if normalized_selector:
            # Retain a single shape so old persisted ``function_entry``
            # selectors dedupe against newer ``target`` RVAs.
            payload = {"target_selector": normalized_selector}
    else:
        normalized_selector = _canonical_action_selector(payload)
        if normalized_selector:
            payload = {"target_selector": normalized_selector}
    scope = parameters.get("action_scope")
    if isinstance(scope, (str, int)) and str(scope).strip():
        payload["action_scope"] = canonical_token(scope)
    canonical_parameters = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical_parameters.encode("utf-8")).hexdigest()[:20]
    return f"{str(action_type).upper()}:{digest}"


@dataclass(frozen=True)
class RetrievalRequest:
    thread_id: str
    artifact_id: str
    hypothesis_type: str
    target_anchors: tuple[str, ...]
    required_evidence_kinds: tuple[str, ...]
    hypothesis_id: str | None = None
    caller_depth: int = 0
    callee_depth: int = 0
    data_xref_depth: int = 0
    playbook_id: str = "generic"
    version: str = "retrieval-v2"
    candidate_limit: int = 512
    # Explicit modes make the retrieval contract inspectable.  The repository
    # still applies artifact scoping and budgets for every mode.
    retrieval_modes: tuple[str, ...] = (
        "anchor-driven", "graph-driven", "evidence-kind-driven", "data-flow-driven", "call-flow-driven"
    )

    def __post_init__(self) -> None:
        if not self.thread_id or not self.artifact_id or not self.hypothesis_type:
            raise ValueError("thread_id, artifact_id, and hypothesis_type are required")
        if self.candidate_limit < 1 or self.candidate_limit > 4096:
            raise ValueError("candidate_limit must be between 1 and 4096")
        if min(self.caller_depth, self.callee_depth, self.data_xref_depth) < 0:
            raise ValueError("graph depths cannot be negative")
        allowed = {"anchor-driven", "graph-driven", "evidence-kind-driven", "data-flow-driven", "call-flow-driven"}
        if not self.retrieval_modes or any(item not in allowed for item in self.retrieval_modes):
            raise ValueError("retrieval_modes contains an unsupported mode")

    @property
    def anchor_tokens(self) -> frozenset[str]:
        return frozenset(_tokens(" ".join(self.target_anchors)))

    def as_dict(self) -> dict[str, object]:
        return {
            "thread_id": self.thread_id,
            "hypothesis_id": self.hypothesis_id,
            "artifact_id": self.artifact_id,
            "hypothesis_type": self.hypothesis_type,
            "target_anchors": list(self.target_anchors),
            "required_evidence_kinds": list(self.required_evidence_kinds),
            "graph_expansion": {
                "caller_depth": self.caller_depth,
                "callee_depth": self.callee_depth,
                "data_xref_depth": self.data_xref_depth,
            },
            "playbook_id": self.playbook_id,
            "version": self.version,
            "candidate_limit": self.candidate_limit,
            "retrieval_modes": list(self.retrieval_modes),
        }


@dataclass(frozen=True)
class CandidateEvidenceBatch:
    """The bounded data returned by an indexed static evidence lookup."""

    rows: tuple[Evidence, ...]
    candidate_count: int
    query_count: int
    selector_keys: tuple[str, ...]
    graph_expansions: tuple[dict[str, object], ...] = ()


class BoundedEvidenceRepository:
    """Obtain artifact-scoped candidates without scanning a task's Evidence ledger."""

    version = "bounded-evidence-repository-v2"

    @staticmethod
    def _value_selectors(value: object) -> set[str]:
        if isinstance(value, Mapping):
            values: set[str] = set()
            for key in (
                "name", "entry", "function_entry", "rva", "address", "from", "to",
                "target", "target_name", "target_function", "caller", "callee",
            ):
                item = value.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    values.add(canonical_selector(item))
            return values
        return {canonical_selector(value)} if isinstance(value, (str, int)) and str(value).strip() else set()

    @classmethod
    def _row_matches(cls, row: Evidence, targets: set[str]) -> bool:
        if not targets:
            return False
        values = cls._value_selectors(row.value) | cls._value_selectors(row.anchor)
        return bool(values & targets)

    @classmethod
    def _directional_selectors(
        cls,
        rows: Iterable[Evidence],
        *,
        targets: set[str],
        direction: str,
    ) -> set[str]:
        """Follow only typed static call/data edges from already retrieved rows."""
        selectors: set[str] = set()
        for row in rows:
            value = row.value if isinstance(row.value, Mapping) else {}
            anchor = row.anchor if isinstance(row.anchor, Mapping) else {}
            own = cls._value_selectors({
                "name": value.get("name"),
                "entry": value.get("entry", anchor.get("entry")),
                "function_entry": anchor.get("function_entry"),
                "rva": value.get("entry_rva", anchor.get("rva")),
            })
            calls = value.get("call_targets", value.get("callees", ()))
            call_rows = calls if isinstance(calls, list) else ()
            call_targets = set().union(*(cls._value_selectors(item) for item in call_rows if isinstance(item, Mapping)))
            data = value.get("data_references", value.get("references", ()))
            data_rows = data if isinstance(data, list) else ()
            data_targets = set().union(*(cls._value_selectors(item) for item in data_rows if isinstance(item, Mapping)))
            direct_from = cls._value_selectors({"from": value.get("from", anchor.get("from"))})
            direct_to = cls._value_selectors({
                "to": value.get("to"),
                "target_name": value.get("target_name"),
                "target_function": value.get("target_function"),
            })
            if direction == "caller":
                if call_targets & targets or direct_to & targets:
                    selectors.update(own | direct_from)
            elif direction == "callee":
                if own & targets or direct_from & targets:
                    selectors.update(call_targets | direct_to)
            elif direction == "data":
                # A function row can be selected because one of its call
                # targets matched the investigation anchor (for example
                # GetProcAddress).  Its typed data references are still part
                # of the same mechanism and must be eligible for the next
                # graph hop; otherwise data_xref_depth silently returns no
                # data evidence for a correctly targeted function.
                if own & targets or call_targets & targets or direct_from & targets or direct_to & targets:
                    selectors.update(data_targets)
        return {item for item in selectors if item}

    @staticmethod
    def _rows_for_ids(session: Session, *, task_id: str, artifact_id: str, ids: Iterable[str]) -> tuple[Evidence, ...]:
        values = tuple(dict.fromkeys(str(item) for item in ids if item))
        if not values:
            return ()
        return tuple(
            session.scalars(
                select(Evidence)
                .where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == artifact_id,
                    Evidence.id.in_(values),
                )
                .order_by(Evidence.id)
            ).all()
        )

    def retrieve(
        self,
        session: Session,
        *,
        task_id: str,
        request: RetrievalRequest,
    ) -> CandidateEvidenceBatch:
        """Use indexed IDs first, then fetch only the selected Evidence rows.

        The two query families are intentionally bounded independently: exact
        target selectors and requested evidence kinds.  This makes an anchor
        written late in a large static run just as visible as an early one.
        """
        selector_keys = target_search_keys(request.target_anchors)
        candidate_ids: list[str] = []
        query_count = 0
        exact_limit = max(1, min(request.candidate_limit, 256))
        if selector_keys and "anchor-driven" in request.retrieval_modes:
            priority = case(
                (EvidenceSearchKey.kind.in_(tuple(sorted(_DEEP_CONTEXT_KINDS))), 0),
                (EvidenceSearchKey.kind.in_(request.required_evidence_kinds), 1),
                else_=2,
            )
            exact_ids = session.scalars(
                select(EvidenceSearchKey.evidence_id)
                .where(
                    EvidenceSearchKey.task_id == task_id,
                    EvidenceSearchKey.artifact_id == request.artifact_id,
                    EvidenceSearchKey.selector.in_(selector_keys),
                )
                .group_by(EvidenceSearchKey.evidence_id, EvidenceSearchKey.kind)
                .order_by(priority, EvidenceSearchKey.evidence_id)
                .limit(exact_limit)
            ).all()
            candidate_ids.extend(str(item) for item in exact_ids)
            query_count += 1
        unique_ids = tuple(dict.fromkeys(candidate_ids))[: request.candidate_limit]

        # Expand from compact typed graph edges only. This never scans the
        # artifact ledger and it cannot turn untrusted natural-language text
        # into a query selector.
        rows = self._rows_for_ids(
            session, task_id=task_id, artifact_id=request.artifact_id, ids=unique_ids
        )
        query_count += bool(unique_ids)
        rows_by_id = {row.id: row for row in rows}
        all_ids = list(unique_ids)
        graph_expansions: list[dict[str, object]] = []
        depths = (
            ("caller", request.caller_depth if {"graph-driven", "call-flow-driven"} & set(request.retrieval_modes) else 0),
            ("callee", request.callee_depth if {"graph-driven", "call-flow-driven"} & set(request.retrieval_modes) else 0),
            ("data", request.data_xref_depth if {"graph-driven", "data-flow-driven"} & set(request.retrieval_modes) else 0),
        )
        for direction, depth in depths:
            frontier = set(selector_keys)
            frontier_rows = rows
            for level in range(depth):
                selectors = self._directional_selectors(
                    frontier_rows, targets=frontier, direction=direction
                )
                selectors.difference_update(target_search_keys(request.target_anchors) if level == 0 else ())
                if not selectors or len(set(all_ids)) >= request.candidate_limit:
                    break
                remaining = request.candidate_limit - len(set(all_ids))
                edge_ids = session.scalars(
                    select(EvidenceSearchKey.evidence_id)
                    .distinct()
                    .where(
                        EvidenceSearchKey.task_id == task_id,
                        EvidenceSearchKey.artifact_id == request.artifact_id,
                        EvidenceSearchKey.selector.in_(tuple(sorted(selectors))[:128]),
                        EvidenceSearchKey.evidence_id.not_in(tuple(all_ids)),
                    )
                    .order_by(EvidenceSearchKey.evidence_id)
                    .limit(min(remaining, 128))
                ).all()
                query_count += 1
                new_ids = [str(item) for item in edge_ids if str(item) not in set(all_ids)]
                if not new_ids:
                    graph_expansions.append(
                        {
                            "direction": direction,
                            "depth": level + 1,
                            "selectors": sorted(selectors)[:128],
                            "evidence_ids": [],
                            "result": "already_in_candidate_set_or_no_match",
                        }
                    )
                    break
                new_rows = self._rows_for_ids(
                    session, task_id=task_id, artifact_id=request.artifact_id, ids=new_ids
                )
                query_count += 1
                all_ids.extend(new_ids)
                rows_by_id.update((row.id, row) for row in new_rows)
                frontier_rows = new_rows
                frontier = selectors
                graph_expansions.append(
                    {
                        "direction": direction,
                        "depth": level + 1,
                        "selectors": sorted(selectors)[:128],
                        "evidence_ids": [row.id for row in new_rows],
                    }
                )
        # Unrelated kind matches are discovery backfill, not a reason to skip
        # the requested graph hops. Reuse loaded rows instead of fetching the
        # whole candidate set again after expansion.
        remaining = request.candidate_limit - len(rows_by_id)
        if remaining > 0 and request.required_evidence_kinds and "evidence-kind-driven" in request.retrieval_modes:
            required_rows = session.scalars(
                select(Evidence)
                .where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == request.artifact_id,
                    Evidence.kind.in_(request.required_evidence_kinds),
                    Evidence.id.not_in(tuple(rows_by_id)),
                )
                .order_by(Evidence.id)
                .limit(min(remaining, 256))
            ).all()
            rows_by_id.update((row.id, row) for row in required_rows)
            query_count += 1
        rows = tuple(rows_by_id[key] for key in sorted(rows_by_id))
        return CandidateEvidenceBatch(
            rows,
            len(rows),
            query_count,
            selector_keys,
            tuple(graph_expansions),
        )


@dataclass(frozen=True)
class ContextItem:
    evidence_id: str
    kind: str
    role: ContextRole
    score: int
    rationale: tuple[str, ...]
    quota_group: str
    value: object
    anchor: object


@dataclass(frozen=True)
class ContextPacket:
    request: RetrievalRequest
    items: tuple[ContextItem, ...]
    core: tuple[ContextItem, ...]
    expansion: tuple[ContextItem, ...]
    exclusion_reasons: dict[str, str]
    candidate_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "retrieval_request": self.request.as_dict(),
            "core_context": [self._item(item) for item in self.core],
            "expansion_context": [self._item(item) for item in self.expansion],
            "candidate_count": self.candidate_count,
            "omitted_evidence_count": len(self.exclusion_reasons),
            "exclusion_reasons": dict(self.exclusion_reasons),
        }

    @staticmethod
    def _item(item: ContextItem) -> dict[str, object]:
        return {
            "evidence_id": item.evidence_id,
            "kind": item.kind,
            "context_role": item.role.value,
            "selection_score": item.score,
            "selection_rationale": list(item.rationale),
            "quota_group": item.quota_group,
            "value": item.value,
            "anchor": item.anchor,
            "trust_zone": "untrusted_analysis_data",
        }


def _flatten(value: object, *, limit: int = 12_000) -> str:
    if isinstance(value, Mapping):
        return " ".join(
            f"{key} {_flatten(item, limit=limit)}"
            for key, item in list(value.items())[:128]
        )[:limit]
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(item, limit=limit) for item in list(value)[:128])[:limit]
    return str(value)[:limit]


def _tokens(value: object) -> tuple[str, ...]:
    return tuple(token.casefold() for token in _TOKEN.findall(_flatten(value)))


class QuestionCentricRetriever:
    """Select compact evidence context from a bounded candidate set.

    Generic function existence rows retain value as navigation hints, but never
    displace direct call/data/CFG evidence from the core context.
    """

    def __init__(self, *, max_items: int = 48) -> None:
        if max_items < 1:
            raise ValueError("max_items must be positive")
        self.max_items = max_items

    @staticmethod
    def _profile_floors(request: RetrievalRequest) -> dict[str, int]:
        floors = {
            "dynamic-api-resolution": {"xref": 1, "function_context": 1, "data_reference": 1},
            "xor-config-recovery": {"mechanism_decode_window": 1, "data_reference": 1, "function_context": 1},
            "ppid-process-chain": {"function_call": 2, "constant": 1, "function_context": 1},
            "entrypoint-timeline": {"pe_structure": 1, "function_context": 1, "cfg_block": 1},
        }
        # ``decode-config`` was emitted by pre-v2 snapshots; retain a read-only
        # compatibility alias while new requests use the canonical playbook id.
        if request.playbook_id == "decode-config":
            return floors["xor-config-recovery"]
        return floors.get(request.playbook_id, {})

    def _adaptive_maximum(self, *, kind: str, request: RetrievalRequest) -> int:
        if kind == "function":
            return max(2, self.max_items // 6)
        if kind == "string":
            return max(2, self.max_items // 8)
        if request.playbook_id in {"xor-config-recovery", "decode-config"} and kind in {
            "data_reference", "mechanism_decode_window", "function_instruction_window",
        }:
            return max(4, self.max_items // 2)
        return self.max_items

    def build(
        self,
        request: RetrievalRequest,
        evidence: Iterable[Mapping[str, object]],
    ) -> ContextPacket:
        required = frozenset(request.required_evidence_kinds)
        anchors = request.anchor_tokens
        scored: list[tuple[ContextItem, bool]] = []
        exclusions: dict[str, str] = {}
        for row in evidence:
            evidence_id = str(row.get("evidence_id") or row.get("id") or "")
            if not evidence_id:
                continue
            if str(row.get("artifact_id", "")) != request.artifact_id:
                exclusions[evidence_id] = "wrong_artifact"
                continue
            kind = str(row.get("kind", ""))
            observed_tokens = frozenset(_tokens((row.get("value"), row.get("anchor"))))
            matched = anchors & observed_tokens
            rationale: list[str] = []
            score = 0
            if kind in required:
                score += 60
                rationale.append("required_evidence_kind")
            if matched:
                score += 120 + min(20, len(matched) * 5)
                rationale.append("target_anchor:" + ",".join(sorted(matched)[:4]))
            if kind in _PRIMARY_KINDS:
                score += 25
                rationale.append("mechanism_anchor_kind")
            if kind == "function":
                score -= 20
                rationale.append("navigation_only")
            if not rationale:
                exclusions[evidence_id] = "low_relevance"
                continue
            is_core = bool(matched and kind in required | _PRIMARY_KINDS) or (
                kind in required and kind in _PRIMARY_KINDS
            )
            if is_core:
                role = ContextRole.CORE_SUPPORT
            elif kind == "function":
                role = ContextRole.NAVIGATION
            elif kind in required:
                role = ContextRole.CORROBORATING
            else:
                role = ContextRole.EXPANSION
            scored.append(
                (
                    ContextItem(
                        evidence_id=evidence_id,
                        kind=kind,
                        role=role,
                        score=score,
                        rationale=tuple(rationale),
                        quota_group=kind,
                        value=row.get("value"),
                        anchor=row.get("anchor"),
                    ),
                    is_core,
                )
            )

        scored.sort(key=lambda pair: (not pair[1], -pair[0].score, pair[0].evidence_id))
        floors = self._profile_floors(request)
        selected: list[tuple[ContextItem, bool]] = []
        selected_ids: set[str] = set()
        selected_by_kind: dict[str, int] = {}
        for kind, minimum in floors.items():
            if len(selected) >= self.max_items:
                break
            for item, is_core in scored:
                if item.kind != kind or item.evidence_id in selected_ids:
                    continue
                selected.append((item, is_core))
                selected_ids.add(item.evidence_id)
                selected_by_kind[kind] = selected_by_kind.get(kind, 0) + 1
                if selected_by_kind[kind] >= minimum or len(selected) >= self.max_items:
                    break
        for item, is_core in scored:
            if len(selected) >= self.max_items:
                break
            if item.evidence_id in selected_ids:
                continue
            maximum = self._adaptive_maximum(kind=item.kind, request=request)
            if selected_by_kind.get(item.kind, 0) >= maximum:
                exclusions[item.evidence_id] = "type_budget_exhausted"
                continue
            selected.append((item, is_core))
            selected_ids.add(item.evidence_id)
            selected_by_kind[item.kind] = selected_by_kind.get(item.kind, 0) + 1
        for item, _ in scored:
            if item.evidence_id not in selected_ids and item.evidence_id not in exclusions:
                exclusions[item.evidence_id] = "budget"
        items = tuple(item for item, _ in selected)
        core = tuple(item for item in items if item.role == ContextRole.CORE_SUPPORT)
        expansion = tuple(item for item in items if item.role != ContextRole.CORE_SUPPORT)
        return ContextPacket(
            request=request,
            items=items,
            core=core,
            expansion=expansion,
            exclusion_reasons=exclusions,
            candidate_count=len(scored),
        )
