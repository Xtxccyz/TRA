"""Durable investigation work ledger: one row per discovered question.

This is not a second investigation engine. Each row is an index onto the
existing Artifact → Evidence → Claim graph. The scheduler uses it to:

- register every discovered seed before any thread is allowed to finish
- work one (or a few) OPEN items at a time
- park a timeboxed item as DEFERRED (待完成) instead of UNKNOWN
- return to DEFERRED items in a dedicated tail pass
- refuse completion while OPEN or DEFERRED remain

Honest UNKNOWN / UNSUPPORTED after the tail pass is a terminal status. It is
not the same as DEFERRED.
"""

from __future__ import annotations

from typing import Iterable, Mapping

LEDGER_OPEN = "OPEN"
LEDGER_IN_PROGRESS = "IN_PROGRESS"
LEDGER_DEFERRED = "DEFERRED"
LEDGER_CLOSED = "CLOSED"
LEDGER_UNKNOWN = "UNKNOWN"
LEDGER_UNSUPPORTED = "UNSUPPORTED"

LEDGER_TERMINAL = frozenset({LEDGER_CLOSED, LEDGER_UNKNOWN, LEDGER_UNSUPPORTED})
LEDGER_ACTIVE = frozenset({LEDGER_OPEN, LEDGER_IN_PROGRESS, LEDGER_DEFERRED})


def _as_id(value: object) -> str:
    return str(value or "").strip()


def _copy_ids(values: Iterable[object] | None) -> list[str]:
    return list(dict.fromkeys(str(item).strip() for item in (values or ()) if str(item).strip()))


def _row(item: Mapping[str, object]) -> dict[str, object]:
    item_id = _as_id(item.get("id") or item.get("thread_id"))
    thread_id = _as_id(item.get("thread_id") or item_id)
    return {
        "id": item_id,
        "thread_id": thread_id,
        "artifact_id": _as_id(item.get("artifact_id")),
        "question": str(item.get("question") or "").strip(),
        "seed_kind": str(item.get("seed_kind") or "artifact_triage"),
        "status": str(item.get("status") or LEDGER_OPEN).upper(),
        "reason": str(item.get("reason") or ""),
        "next_method": str(item.get("next_method") or "") or None,
        "pass": int(item.get("pass") or 0),
        "evidence_ids": _copy_ids(item.get("evidence_ids") if isinstance(item.get("evidence_ids"), (list, tuple)) else ()),
        "claim_ids": _copy_ids(item.get("claim_ids") if isinstance(item.get("claim_ids"), (list, tuple)) else ()),
        "action_ids": _copy_ids(item.get("action_ids") if isinstance(item.get("action_ids"), (list, tuple)) else ()),
    }


def register_work_item(
    ledger: Iterable[Mapping[str, object]] | None,
    item: Mapping[str, object],
) -> list[dict[str, object]]:
    """Append or refresh a discovered seed without dropping prior results."""
    rows = [_row(existing) for existing in ledger or ()]
    incoming = _row(item)
    if not incoming["id"]:
        return rows
    for index, existing in enumerate(rows):
        if existing["id"] == incoming["id"]:
            merged = dict(existing)
            for key in ("artifact_id", "question", "seed_kind"):
                if incoming.get(key):
                    merged[key] = incoming[key]
            if incoming.get("status") and existing.get("status") == LEDGER_OPEN:
                merged["status"] = incoming["status"]
            rows[index] = merged
            return rows
    if incoming["status"] not in {LEDGER_OPEN, LEDGER_IN_PROGRESS, LEDGER_DEFERRED, *LEDGER_TERMINAL}:
        incoming["status"] = LEDGER_OPEN
    rows.append(incoming)
    return rows


def item_by_id(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
) -> dict[str, object] | None:
    wanted = _as_id(item_id)
    for item in ledger or ():
        row = _row(item)
        if row["id"] == wanted:
            return row
    return None


def _replace(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
    **updates: object,
) -> list[dict[str, object]]:
    wanted = _as_id(item_id)
    rows = [_row(item) for item in ledger or ()]
    for index, row in enumerate(rows):
        if row["id"] != wanted:
            continue
        updated = dict(row)
        for key, value in updates.items():
            if key in {"evidence_ids", "claim_ids", "action_ids"}:
                updated[key] = _copy_ids([*(row.get(key) or ()), *(value or ())])  # type: ignore[arg-type]
            else:
                updated[key] = value
        rows[index] = updated
        return rows
    return rows


def begin_item(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
) -> list[dict[str, object]]:
    return _replace(ledger, item_id, status=LEDGER_IN_PROGRESS, reason="")


def defer_item(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
    *,
    reason: str,
    next_method: str | None = None,
) -> list[dict[str, object]]:
    """Park an unfinished item. DEFERRED is not terminal."""
    return _replace(
        ledger,
        item_id,
        status=LEDGER_DEFERRED,
        reason=str(reason or "TIMEBOX"),
        next_method=str(next_method or "") or None,
    )


def close_item(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
    *,
    evidence_ids: Iterable[object] = (),
    claim_ids: Iterable[object] = (),
    action_ids: Iterable[object] = (),
) -> list[dict[str, object]]:
    return _replace(
        ledger,
        item_id,
        status=LEDGER_CLOSED,
        reason="CLAIM_READY",
        evidence_ids=evidence_ids,
        claim_ids=claim_ids,
        action_ids=action_ids,
    )


def terminate_item(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
    status: str = LEDGER_UNKNOWN,
    *,
    reason: str,
    next_method: str | None = None,
    evidence_ids: Iterable[object] = (),
    claim_ids: Iterable[object] = (),
    action_ids: Iterable[object] = (),
) -> list[dict[str, object]]:
    terminal = str(status or LEDGER_UNKNOWN).upper()
    if terminal not in LEDGER_TERMINAL:
        terminal = LEDGER_UNKNOWN
    return _replace(
        ledger,
        item_id,
        status=terminal,
        reason=str(reason or terminal),
        next_method=str(next_method or "") or None,
        evidence_ids=evidence_ids,
        claim_ids=claim_ids,
        action_ids=action_ids,
    )


def attach_results(
    ledger: Iterable[Mapping[str, object]] | None,
    item_id: str,
    *,
    evidence_ids: Iterable[object] = (),
    claim_ids: Iterable[object] = (),
    action_ids: Iterable[object] = (),
) -> list[dict[str, object]]:
    return _replace(
        ledger,
        item_id,
        evidence_ids=evidence_ids,
        claim_ids=claim_ids,
        action_ids=action_ids,
    )


def should_skip_work_item(
    item: Mapping[str, object],
    *,
    phase: str,
    ledger: Iterable[Mapping[str, object]] | None = None,
) -> bool:
    status = str(item.get("status") or LEDGER_OPEN).upper()
    if status in LEDGER_TERMINAL:
        return True
    if phase == "tail":
        return status != LEDGER_DEFERRED
    if status == LEDGER_DEFERRED:
        # A coverage invocation with no remaining OPEN items is the tail
        # pass: later seeds parked as 待完成 must still be admitted.
        return bool(open_item_ids(ledger))
    return False


def next_items(
    ledger: Iterable[Mapping[str, object]] | None,
    *,
    phase: str,
    limit: int = 1,
) -> list[dict[str, object]]:
    wanted = LEDGER_DEFERRED if phase == "tail" else LEDGER_OPEN
    selected: list[dict[str, object]] = []
    for item in ledger or ():
        row = _row(item)
        if row["status"] != wanted:
            continue
        selected.append(row)
        if len(selected) >= max(1, int(limit)):
            break
    return selected


def open_item_ids(ledger: Iterable[Mapping[str, object]] | None) -> tuple[str, ...]:
    return tuple(
        _row(item)["id"]
        for item in ledger or ()
        if _row(item)["status"] in {LEDGER_OPEN, LEDGER_IN_PROGRESS}
    )


def deferred_item_ids(ledger: Iterable[Mapping[str, object]] | None) -> tuple[str, ...]:
    return tuple(_row(item)["id"] for item in ledger or () if _row(item)["status"] == LEDGER_DEFERRED)


def completion_allows_stop(ledger: Iterable[Mapping[str, object]] | None) -> bool:
    """True only when every registered item is terminal.

    An empty ledger is not complete: discovery has not happened yet.
    """
    rows = [_row(item) for item in ledger or ()]
    if not rows:
        return False
    return all(row["status"] in LEDGER_TERMINAL for row in rows)


def status_from_thread_state(state: str | None) -> str:
    value = str(state or "").upper()
    if value in {"CLAIM_READY", "CLOSED"}:
        return LEDGER_CLOSED
    if value in {"BLOCKED"}:
        return LEDGER_DEFERRED
    if value in {"UNKNOWN", "REJECTED", "CONTRADICTED"}:
        # Until a tail pass has actually finished the item, UNKNOWN is a
        # parked question, not a completion-gate terminal.
        return LEDGER_DEFERRED
    return LEDGER_OPEN
