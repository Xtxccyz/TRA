"""Evaluator-only Evidence Funnel and Agentic effectiveness scorecards.

This module deliberately lives outside ``src/threat_report_agent``.  It reads a
serialized Task View and an evaluator-owned rubric, then reports where Gold
evidence was lost between static production and verifier acceptance.  The Gold
rubric never enters the runtime planner, retriever, or Claim Gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping


_STAGES = (
    "available",
    "candidate",
    "selected",
    "delivered",
    "referenced",
    "accepted",
)

ROUND10_THRESHOLDS = {
    "retrieval_recall": 0.90,
    "delivery_recall": 0.90,
    "model_utilization": 0.70,
    "verified_support_conversion": 0.60,
    "critical_action_productivity": 0.60,
    "case_action_productivity": 0.50,
    "invalid_action_rate": 0.02,
    "duplicate_action_rate": 0.05,
    "mechanism_recall": 0.85,
    "mechanism_precision": 0.95,
    "mechanism_completeness": 0.80,
}


def _text(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str).casefold()


def _matching_ids(
    evidence: list[Mapping[str, Any]], tokens: object,
) -> set[str]:
    """Return evidence rows covering a component's tokens.

    A Gold component is a set of required observations, not a requirement that
    every token be serialized into one Evidence row.  Static extractors often
    emit one API, constant, or call edge per row, so coverage is the union of
    rows matching each token.
    """
    if not isinstance(tokens, list) or not tokens:
        return set()
    required = tuple(str(token).casefold() for token in tokens if str(token))
    if not required:
        return set()
    return {
        str(row.get("id"))
        for row in evidence
        if row.get("id")
        and any(
            token in _text({"value": row.get("value"), "anchor": row.get("anchor")})
            for token in required
        )
    }


def _stage_ids(records: object, stage_names: set[str]) -> set[str]:
    if not isinstance(records, list):
        return set()
    return {
        str(record.get("evidence_id"))
        for record in records
        if isinstance(record, Mapping)
        and record.get("evidence_id")
        and str(record.get("stage", "")).casefold() in stage_names
    }


def _discovered_thread_ids(task_view: Mapping[str, Any]) -> set[str]:
    investigation = task_view.get("investigation", {})
    rows = investigation.get("threads", []) if isinstance(investigation, Mapping) else []
    return {
        str(row.get("id"))
        for row in rows
        if isinstance(row, Mapping) and row.get("id")
    }


def _gold_thread_ids(gold: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("threads", "investigation_threads"):
        rows = gold.get(key, [])
        if isinstance(rows, list):
            result.update(
                str(row.get("id"))
                for row in rows
                if isinstance(row, Mapping) and row.get("id")
            )
    for mechanism in gold.get("mechanisms", []):
        if not isinstance(mechanism, Mapping):
            continue
        values = mechanism.get("thread_ids", [])
        if isinstance(values, list):
            result.update(str(value) for value in values if str(value).strip())
    return result


def _gold_thread_specs(gold: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Normalize exact and semantic Gold thread references for evaluation.

    Runtime thread IDs are content/task scoped and therefore cannot be known in
    advance by a blind Gold rubric.  Structured semantic references can match
    stable fields such as ``seed_kind`` or a question/path fragment while exact
    ``id`` references remain supported for fixtures and replayed runs.
    """
    specs: list[Mapping[str, Any]] = []
    for key in ("threads", "investigation_threads"):
        rows = gold.get(key, [])
        if isinstance(rows, list):
            specs.extend(row for row in rows if isinstance(row, Mapping))
    for mechanism in gold.get("mechanisms", []):
        if not isinstance(mechanism, Mapping):
            continue
        values = mechanism.get("thread_ids", [])
        if isinstance(values, list):
            specs.extend({"id": str(value)} for value in values if str(value).strip())
        semantic = mechanism.get("thread_matches", mechanism.get("thread_match", []))
        if isinstance(semantic, Mapping):
            semantic = [semantic]
        if isinstance(semantic, list):
            specs.extend(row for row in semantic if isinstance(row, Mapping))
    return specs


def _thread_matches(runtime: Mapping[str, Any], spec: Mapping[str, Any]) -> bool:
    if spec.get("id") and str(runtime.get("id")) == str(spec.get("id")):
        return True
    predicates = (
        ("seed_kind", "seed_kind", False),
        ("artifact_id", "artifact_id", False),
        ("question_contains", "question", True),
        ("artifact_path_contains", "artifact_path", True),
        ("label", "seed_kind", True),
        ("semantic_label", "seed_kind", True),
    )
    checked = False
    for spec_key, runtime_key, contains in predicates:
        expected = spec.get(spec_key)
        if expected is None:
            continue
        checked = True
        actual = str(runtime.get(runtime_key, "")).casefold()
        target = str(expected).casefold()
        matches = target in actual if contains else actual == target
        if matches:
            continue
        return False
    return checked


def _thread_recall(task_view: Mapping[str, Any], gold: Mapping[str, Any]) -> tuple[float, int, int]:
    investigation = task_view.get("investigation", {})
    runtime = (
        [row for row in investigation.get("threads", []) if isinstance(row, Mapping)]
        if isinstance(investigation, Mapping)
        else []
    )
    specs = _gold_thread_specs(gold)
    if not specs:
        return 1.0, 0, 0
    matched = sum(1 for spec in specs if any(_thread_matches(row, spec) for row in runtime))
    return matched / len(specs), matched, len(specs)


@dataclass(frozen=True)
class FunnelResult:
    mechanism_id: str
    available: int
    candidate: int
    selected: int
    delivered: int
    referenced: int
    accepted: int
    gold_evidence_ids: tuple[str, ...]
    loss_reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        values = {
            stage: getattr(self, stage)
            for stage in _STAGES
        }
        denominator = self.available or 1
        return {
            "mechanism_id": self.mechanism_id,
            **values,
            "candidate_recall": self.candidate / denominator,
            "selection_recall": self.selected / denominator,
            "delivery_recall": self.delivered / denominator,
            "model_utilization": self.referenced / (self.delivered or 1),
            "verified_support_conversion": self.accepted / (self.delivered or 1),
            "gold_evidence_ids": list(self.gold_evidence_ids),
            "loss_reasons": list(self.loss_reasons),
        }


def _loss_reasons(result: dict[str, int], task_view: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if result["available"] and not result["candidate"]:
        reasons.append("retrieval_failure")
    elif result["candidate"] and not result["selected"]:
        reasons.append("selection_or_budget_failure")
    elif result["selected"] and not result["delivered"]:
        reasons.append("delivery_failure")
    elif result["delivered"] and not result["referenced"]:
        reasons.append("model_utilization_failure")
    elif result["referenced"] and not result["accepted"]:
        reasons.append("verifier_or_claim_gate_failure")
    if not result["available"]:
        limitations = " ".join(str(item).casefold() for item in task_view.get("limitations", []))
        reasons.append(
            "requires_authorized_dynamic_phase"
            if "dynamic" in limitations
            else "missing_static_evidence"
        )
    return tuple(reasons)


def _explicitly_excluded_ids(records: list[Mapping[str, Any]]) -> set[str]:
    """Evidence with an explicit exclusion is explainable loss, not silent loss."""
    return {
        str(record.get("evidence_id"))
        for record in records
        if record.get("evidence_id") and record.get("exclusion_reason")
    }


def _action_rates(actions: list[Mapping[str, Any]]) -> dict[str, float | int]:
    if not actions:
        return {
            "productive": 0,
            "invalid": 0,
            "duplicate": 0,
            "critical": 0,
            "critical_productive": 0,
            "case_productive": 0,
            "case_rate": 1.0,
            "critical_rate": 1.0,
            "invalid_rate": 0.0,
            "duplicate_rate": 0.0,
        }
    def outcome(action: Mapping[str, Any]) -> str:
        explicit = str(action.get("outcome", "")).upper()
        if explicit in {"PRODUCTIVE", "NEUTRAL", "WASTED", "INVALID", "DUPLICATE"}:
            return explicit
        if action.get("invalid") is True:
            return "INVALID"
        if action.get("duplicate") is True:
            return "DUPLICATE"
        if action.get("result_evidence_ids") or action.get("new_evidence_ids"):
            return "PRODUCTIVE"
        return "NEUTRAL"
    outcomes = [outcome(item) for item in actions]
    critical = [item for item in actions if item.get("critical") is True or str(item.get("thread_priority", "")).upper() == "CRITICAL"]
    critical_outcomes = [outcome(item) for item in critical]
    productive = outcomes.count("PRODUCTIVE")
    invalid = outcomes.count("INVALID")
    duplicate = outcomes.count("DUPLICATE")
    return {
        "productive": productive,
        "invalid": invalid,
        "duplicate": duplicate,
        "critical": len(critical),
        "critical_productive": critical_outcomes.count("PRODUCTIVE"),
        "case_productive": productive,
        "case_rate": productive / len(actions),
        "critical_rate": critical_outcomes.count("PRODUCTIVE") / len(critical) if critical else 1.0,
        "invalid_rate": invalid / len(actions),
        "duplicate_rate": duplicate / len(actions),
    }


def _mechanism_quality(task_view: Mapping[str, Any]) -> dict[str, float | int]:
    """Evaluate runtime mechanism projections when present, otherwise stay neutral."""
    rows = task_view.get("mechanisms", [])
    if not isinstance(rows, list) or not rows:
        return {"recall": 1.0, "precision": 1.0, "completeness": 1.0, "critical_count": 0}
    critical = [row for row in rows if isinstance(row, Mapping) and row.get("critical", True)]
    if not critical:
        return {"recall": 1.0, "precision": 1.0, "completeness": 1.0, "critical_count": 0}
    supported = [row for row in critical if str(row.get("status", "")).upper() in {"VERIFIED", "CONFIRMED", "SUPPORTED"}]
    scores = [float(row.get("completeness_score", row.get("completeness", 0.0))) for row in supported]
    normalized = [score / 100 if score > 1 else score for score in scores]
    return {
        "recall": len(supported) / len(critical),
        "precision": sum(1 for row in critical if str(row.get("status", "")).upper() not in {"FALSE", "REFUTED", "UNSUPPORTED"}) / len(critical),
        "completeness": sum(normalized) / len(normalized) if normalized else 0.0,
        "critical_count": len(critical),
    }


def build_evidence_funnel(
    task_view: Mapping[str, Any],
    gold: Mapping[str, Any],
) -> dict[str, object]:
    """Build a per-mechanism funnel scorecard from an evaluator Gold rubric."""
    if gold.get("evaluator_only") is not True:
        raise ValueError("Evidence Funnel Gold rubric must be evaluator-only")
    evidence = [row for row in task_view.get("evidence", []) if isinstance(row, Mapping)]
    delivery = task_view.get("evidence_delivery", {})
    records = delivery.get("records", []) if isinstance(delivery, Mapping) else []
    available_ids = {str(row.get("id")) for row in evidence if row.get("id")}
    candidate_ids = _stage_ids(records, {"candidate", "selected", "delivered", "referenced_by_model", "accepted_as_support"})
    selected_ids = _stage_ids(records, {"selected", "delivered", "referenced_by_model", "accepted_as_support"})
    delivered_ids = _stage_ids(records, {"delivered", "referenced_by_model", "accepted_as_support"})
    referenced_ids = _stage_ids(records, {"referenced_by_model", "accepted_as_support"})
    accepted_ids = _stage_ids(records, {"accepted_as_support"})

    results: list[FunnelResult] = []
    for mechanism in gold.get("mechanisms", []):
        if not isinstance(mechanism, Mapping):
            continue
        mechanism_id = str(mechanism.get("id", ""))
        components = mechanism.get("components", {})
        if not mechanism_id or not isinstance(components, Mapping):
            continue
        gold_ids: set[str] = set()
        for tokens in components.values():
            gold_ids.update(_matching_ids(evidence, tokens))
        gold_ids &= available_ids
        counts = {
            "available": len(gold_ids),
            "candidate": len(gold_ids & candidate_ids),
            "selected": len(gold_ids & selected_ids),
            "delivered": len(gold_ids & delivered_ids),
            "referenced": len(gold_ids & referenced_ids),
            "accepted": len(gold_ids & accepted_ids),
        }
        results.append(
            FunnelResult(
                mechanism_id,
                **counts,
                gold_evidence_ids=tuple(sorted(gold_ids)),
                loss_reasons=_loss_reasons(counts, task_view),
            )
        )

    claims = [row for row in task_view.get("claims", []) if isinstance(row, Mapping)]
    claim_evidence = [
        row for row in task_view.get("claim_evidence", []) if isinstance(row, Mapping)
    ]
    evidence_ids = {str(row.get("id")) for row in evidence if row.get("id")}
    claim_ids = {str(row.get("id")) for row in claims if row.get("id")}
    traceability = sum(
        bool(row.get("claim_id") in claim_ids and row.get("evidence_id") in evidence_ids)
        for row in claim_evidence
    ) / len(claim_evidence) if claim_evidence else (1.0 if not claims else 0.0)
    unsupported_critical = sum(
        1
        for row in claims
        if str(row.get("confidence", "")).upper() == "HIGH"
        and not any(link.get("claim_id") == row.get("id") for link in claim_evidence)
    )
    candidate_union = candidate_ids
    gold_union = set().union(*(set(item.gold_evidence_ids) for item in results)) if results else set()
    explicit_exclusions = _explicitly_excluded_ids(records)
    # Only an expected transition with no explicit reason is silent loss.
    silent_evidence_loss = len((gold_union - candidate_union) - explicit_exclusions)
    undelivered_gold = len(gold_union - delivered_ids)
    refuted_from_absence = sum(
        1
        for row in claims
        if str(row.get("status", "")).upper() == "REFUTED"
        and not any(link.get("claim_id") == row.get("id") for link in claim_evidence)
        and not row.get("counter_evidence_ids")
    )
    thread_recall, matched_threads, gold_thread_count = _thread_recall(task_view, gold)
    investigation = task_view.get("investigation", {})
    actions = investigation.get("actions", []) if isinstance(investigation, Mapping) else []
    action_rows = [action for action in actions if isinstance(action, Mapping)]
    action_rates = _action_rates(action_rows)
    productive = int(action_rates["productive"])
    mechanism_quality = _mechanism_quality(task_view)
    summary = {
        "mechanism_count": len(results),
        "delivery_recall": (
            sum(item.delivered for item in results)
            / sum(item.available for item in results)
            if sum(item.available for item in results)
            else 1.0
        ),
        "retrieval_recall": (
            sum(item.candidate for item in results)
            / sum(item.available for item in results)
            if sum(item.available for item in results)
            else 1.0
        ),
        "model_utilization": (
            sum(item.referenced for item in results)
            / sum(item.delivered for item in results)
            if sum(item.delivered for item in results)
            else 1.0
        ),
        "verified_support_conversion": (
            sum(item.accepted for item in results)
            / sum(item.delivered for item in results)
            if sum(item.delivered for item in results)
            else 1.0
        ),
        "claim_evidence_traceability": traceability,
        "critical_unsupported_claims": unsupported_critical,
        "action_productivity": productive / len(actions) if actions else 1.0,
        "critical_action_productivity": action_rates["critical_rate"],
        "invalid_action_rate": action_rates["invalid_rate"],
        "duplicate_action_rate": action_rates["duplicate_rate"],
        "mechanism_recall": mechanism_quality["recall"],
        "mechanism_precision": mechanism_quality["precision"],
        "mechanism_completeness": mechanism_quality["completeness"],
        "thread_discovery_recall": thread_recall,
        "silent_evidence_loss": silent_evidence_loss,
        "undelivered_gold_evidence": undelivered_gold,
        "refuted_from_absence_errors": refuted_from_absence,
    }
    mechanism_total = len(gold.get("critical_mechanisms", [])) if isinstance(gold.get("critical_mechanisms"), list) else min(4, len(results))
    mechanism_passed = sum(
        item.available > 0 and item.accepted >= item.available
        for item in results[:mechanism_total]
    )
    failures: list[str] = []
    if summary["delivery_recall"] < 0.9:
        failures.append("delivery_recall")
    if summary["claim_evidence_traceability"] < 1.0:
        failures.append("claim_evidence_traceability")
    if summary["critical_unsupported_claims"]:
        failures.append("critical_unsupported_claims")
    if mechanism_total and mechanism_passed < min(3, mechanism_total):
        failures.append("critical_mechanisms")
    if summary["refuted_from_absence_errors"]:
        failures.append("refuted_from_absence_errors")
    if summary["silent_evidence_loss"]:
        failures.append("silent_evidence_loss")
    if summary["thread_discovery_recall"] < 0.8:
        failures.append("thread_discovery_recall")
    if summary["action_productivity"] < 0.5:
        failures.append("action_productivity")
    if summary["critical_action_productivity"] < ROUND10_THRESHOLDS["critical_action_productivity"]:
        failures.append("critical_action_productivity")
    if summary["invalid_action_rate"] > ROUND10_THRESHOLDS["invalid_action_rate"]:
        failures.append("invalid_action_rate")
    if summary["duplicate_action_rate"] > ROUND10_THRESHOLDS["duplicate_action_rate"]:
        failures.append("duplicate_action_rate")
    if mechanism_quality["critical_count"]:
        if summary["mechanism_recall"] < ROUND10_THRESHOLDS["mechanism_recall"]:
            failures.append("mechanism_recall")
        if summary["mechanism_precision"] < ROUND10_THRESHOLDS["mechanism_precision"]:
            failures.append("mechanism_precision")
        if summary["mechanism_completeness"] < ROUND10_THRESHOLDS["mechanism_completeness"]:
            failures.append("mechanism_completeness")
    blind_runs = task_view.get("blind_runs", [])
    if any(
        isinstance(run, Mapping)
        and (run.get("snapshot", {}) or {}).get("reference_isolated") is False
        for run in blind_runs
    ):
        failures.append("blind_reference_leakage")
    return {
        "evaluator_only": True,
        "gold_version": str(gold.get("version", "unversioned")),
        "task_id": task_view.get("id"),
        "mechanisms": [item.as_dict() for item in results],
        "summary": summary,
        "gate": {
            "status": "PASS" if not failures else "FAIL",
            "failures": failures,
            "thresholds": {
                **ROUND10_THRESHOLDS,
                "claim_evidence_traceability": 1.0,
                "critical_unsupported_claims": 0,
                "critical_mechanisms": "3/4",
                "refuted_from_absence_errors": 0,
                "silent_evidence_loss": 0,
                "thread_discovery_recall": 0.8,
                "action_productivity": 0.5,
                "blind_reference_leakage": 0,
            },
            "thread_discovery": {
                "matched": matched_threads,
                "gold": gold_thread_count,
            },
        },
    }
