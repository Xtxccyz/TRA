"""Classify 受控模拟 results versus worker placeholders.

This module does not run emulators. Temporal ``static-emu`` and Docker
emu-worker stay on AnalysisService / tool_execution. Placeholder
DEFERRED_TO_WORKER rows are dispatch tickets, not real simulation_result.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

PLACEHOLDER_STATUSES = frozenset(
    {
        "",
        "DEFERRED_TO_WORKER",
        "WORKER_REQUIRED",
        "SUPERSEDED_BY_WORKER",
        # A window the worker's per-run budget excluded. It is a placeholder in the strictest sense: the
        # simulator was never invoked. MEASURED why it must be listed (T1a audit finding F3): without it
        # `is_real_simulation_value` returned True for the truncation row, `has_real_simulation_result`
        # matched it (the row carries `simulator="unicorn"`), and the CONTROLLED_EMULATE gate in
        # `analysis_task_orchestration.py` reads that predicate as "a real simulation landed" - so a
        # displaced, never-executed window could satisfy the gate and stop the loop retrying a capability
        # that never ran. That is fabricated evidence, which is the one failure class this product must not
        # have.
        "NOT_EXECUTED",
        # `NOT_APPLICABLE` is deliberately NOT added here: it is a planner decision carried into evidence on
        # purpose, and its handling is pinned by existing tests. Changing it is out of this item's scope.
    }
)


def simulation_status(item: object) -> str:
    """Return the simulation_result status, or empty when the row is another kind."""
    if isinstance(item, Mapping):
        kind = str(item.get("kind") or "")
        value = item.get("value") if isinstance(item.get("value"), Mapping) else {}
    else:
        kind = str(getattr(item, "kind", "") or "")
        raw = getattr(item, "value", None)
        value = raw if isinstance(raw, Mapping) else {}
    if kind and kind != "simulation_result":
        return ""
    return str(value.get("status") or "").upper() if isinstance(value, Mapping) else ""


def is_placeholder_status(status: object) -> bool:
    return str(status or "").upper() in PLACEHOLDER_STATUSES


def is_real_simulation_value(value: Mapping[str, object]) -> bool:
    return not is_placeholder_status(value.get("status"))


def is_real_simulation_row(item: object) -> bool:
    status = simulation_status(item)
    return bool(status) and status not in PLACEHOLDER_STATUSES


def emulation_entry_key(value: Mapping[str, object] | str | None) -> str:
    """Normalize a CONTROLLED_EMULATE selector or simulation_result entry."""
    from threat_report_agent.emulation.emulation_plan import _as_int_address

    if isinstance(value, Mapping):
        raw = (
            value.get("function_entry")
            or value.get("entry")
            or value.get("address")
            or value.get("start")
            or value.get("target")
            or ""
        )
    else:
        raw = value or ""
    text = str(raw).strip()
    if not text:
        return ""
    parsed = _as_int_address(text)
    if parsed is not None:
        return hex(parsed)
    try:
        return hex(int(text, 16))
    except ValueError:
        return text.casefold()


def simulation_covers_request(
    value: Mapping[str, object],
    requested_entry: str,
    *,
    simulator: str | None = None,
) -> bool:
    if is_placeholder_status(value.get("status")):
        return False
    if simulator and str(value.get("simulator") or "").casefold() != simulator.casefold():
        return False
    wanted = emulation_entry_key(requested_entry)
    if not wanted:
        return True
    observed = emulation_entry_key(value)
    return bool(observed) and observed == wanted


def matching_simulation_results(
    rows: Iterable[Any],
    selector: Mapping[str, object],
    *,
    require_success: bool = True,
) -> tuple[Any, ...]:
    requested = emulation_entry_key(selector)
    matched: list[Any] = []
    for row in rows:
        if str(getattr(row, "kind", "") or "") not in {"", "simulation_result"}:
            continue
        value = row.value if isinstance(getattr(row, "value", None), dict) else None
        if not isinstance(value, dict):
            continue
        if not simulation_covers_request(value, requested):
            continue
        if require_success and str(value.get("status") or "").upper() != "SUCCEEDED":
            continue
        matched.append(row)
    return tuple(matched)


def has_real_simulation_result(rows: Iterable[Any], simulator: str) -> bool:
    wanted = simulator.casefold()
    for row in rows:
        value = row.value if isinstance(getattr(row, "value", None), dict) else None
        if not isinstance(value, dict):
            continue
        if str(value.get("simulator") or "").casefold() != wanted:
            continue
        if is_real_simulation_value(value):
            return True
    return False


def has_uncovered_emulation_entry(
    rows: Iterable[Any],
    simulator: str,
    planned_entries: Iterable[str],
) -> bool:
    wanted = tuple(emulation_entry_key(item) for item in planned_entries if str(item).strip())
    if not wanted:
        return not has_real_simulation_result(rows, simulator)
    for entry in wanted:
        if not any(
            isinstance(getattr(row, "value", None), dict)
            and simulation_covers_request(row.value, entry, simulator=simulator)
            for row in rows
        ):
            return True
    return False


def post_static_emulation_needed(
    *,
    allowed_simulators: Iterable[str],
    artifact_type: str,
    results: Iterable[Any],
    planned_entries: Iterable[str],
) -> bool:
    """Whether isolated post-static emu still has an uncovered granted window.

    Speakeasy is PE-only. A Unicorn success must not skip a still-deferred
    Unicorn window. Never treats DEFERRED_TO_WORKER as coverage.
    """
    allowed = {str(item).casefold() for item in allowed_simulators}
    artifact = str(artifact_type or "").casefold()
    if "unicorn" in allowed and has_uncovered_emulation_entry(
        results, "unicorn", planned_entries
    ):
        return True
    if (
        "speakeasy" in allowed
        and artifact == "pe"
        and has_uncovered_emulation_entry(results, "speakeasy", planned_entries)
    ):
        return True
    if "qiling" in allowed and has_uncovered_emulation_entry(
        results, "qiling", planned_entries
    ):
        return True
    return False
