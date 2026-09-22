"""The frontier fingerprint must stay identical while becoming cheap.

`investigation_frontier_fingerprint` is what the investigation loop burns its time
in.  A live stack of a stalled run showed exactly this frame:

    _run_analysis -> run_analysis_task_investigation -> _run_saturated_investigation
      -> _run_investigation_loop -> run_until_converged -> run
      -> investigation.py:1180 investigation_frontier_fingerprint

with the API at ~100% CPU and no database writes for minutes.

The cause: it built a `normalized` list for EVERY evidence row, sorted it with
`json.dumps(item, sort_keys=True, default=str)` as the KEY - so the full nested
payload of all ~38k rows was serialised, once per comparison key - and then kept
only `normalized[:512]`.  Individual `value` payloads reach 333 kB, so the sort
key alone was hundreds of MB of transient strings.  The sort is pointless work on
the 512-selection being made, but it IS observable in the output, so the
optimisation must preserve the selection exactly.

These tests pin the output of the original implementation as the oracle.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping

from threat_report_agent.investigation import investigation_frontier_fingerprint

CAP = 512


def _original_fingerprint(rows: object) -> str:
    """The implementation before the fix, verbatim, as the oracle."""
    if isinstance(rows, Mapping):
        materialized = [rows]
    elif isinstance(rows, (list, tuple, set, frozenset)):
        materialized = list(rows)
    else:
        materialized = []
    normalized: list[dict[str, object]] = []
    for row in materialized:
        if not isinstance(row, Mapping):
            continue
        normalized.append(
            {
                "kind": row.get("kind"),
                "nature": row.get("nature"),
                "value": row.get("value"),
                "anchor": row.get("anchor"),
            }
        )
    normalized.sort(
        key=lambda item: json.dumps(item, ensure_ascii=True, sort_keys=True, default=str)
    )
    payload = json.dumps(
        normalized[:CAP],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rows(count: int) -> list[dict[str, object]]:
    rows = []
    for index in range(count):
        rows.append(
            {
                "id": f"ev-{index}",
                "kind": "string" if index % 3 else "function_instruction_window",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "text": f"value-{index}",
                    "window": [f"mov eax, {index}", f"cmp rax, {index}"] * 4,
                },
                "anchor": {"type": "file_offset", "offset": index},
            }
        )
    return rows


def _selected_fingerprint(rows: object) -> str:
    """The new selection: smallest 512 by fixed digest, then canonical payload.

    Sorting by a 128-bit digest rather than by the full canonical JSON is what
    removes the cost: the original held a canonical JSON string for every row in
    order to sort them (hundreds of MB at 38k rows with 333 kB payloads).  The
    choice of WHICH 512 rows participate therefore changes, but it stays a pure
    function of the row set - deterministic across runs and processes - which is
    all the fingerprint's stated job requires.
    """
    if isinstance(rows, Mapping):
        materialized = [rows]
    elif isinstance(rows, (list, tuple, set, frozenset)):
        materialized = list(rows)
    else:
        materialized = []
    keyed = []
    for index, row in enumerate(materialized):
        if not isinstance(row, Mapping):
            continue
        reduced = {
            "kind": row.get("kind"),
            "nature": row.get("nature"),
            "value": row.get("value"),
            "anchor": row.get("anchor"),
        }
        full = json.dumps(reduced, ensure_ascii=True, sort_keys=True, default=str)
        digest = hashlib.blake2b(full.encode("utf-8"), digest_size=16).digest()
        keyed.append((digest, index, reduced))
    import heapq

    selected = heapq.nsmallest(CAP, keyed, key=lambda item: (item[0], item[1]))
    payload = json.dumps(
        sorted(
            (item[2] for item in selected),
            key=lambda item: json.dumps(item, ensure_ascii=True, sort_keys=True, default=str),
        ),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_fingerprint_matches_the_oracle_including_beyond_the_cap() -> None:
    """The implementation must equal the original for every size.

    Kept as a strict equality oracle rather than a "close enough" check, because a
    digest-ordered rewrite of this function was attempted and reverted: it was 1.6x
    slower on a realistic 39 MB frontier and changed the hash past the cap.  If
    anyone changes this function again, this test says exactly what broke.
    """
    for count in (1, 7, CAP - 1, CAP, CAP + 1, 2000):
        rows = _rows(count)
        assert investigation_frontier_fingerprint(rows) == _original_fingerprint(rows), (
            f"fingerprint diverged at count={count}"
        )


def test_fingerprint_is_stable_across_repeated_calls_beyond_the_cap() -> None:
    """Determinism is the property that actually matters for convergence detection."""
    rows = _rows(2000)
    assert len({investigation_frontier_fingerprint(rows) for _ in range(3)}) == 1


def test_fingerprint_is_order_independent() -> None:
    """It is a frontier hash, so input order must not matter."""
    rows = _rows(300)
    assert investigation_frontier_fingerprint(rows) == investigation_frontier_fingerprint(
        list(reversed(rows))
    )


def test_fingerprint_ignores_provenance_ids() -> None:
    """Only kind/nature/value/anchor participate."""
    base = [
        {
            "id": "a",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": ":Zone.Identifier"},
            "anchor": {"offset": 1},
        }
    ]
    renamed = [{**base[0], "id": "zzz", "tool_run_id": "run-9"}]
    assert investigation_frontier_fingerprint(base) == investigation_frontier_fingerprint(renamed)


def test_fingerprint_handles_mapping_and_non_mapping_inputs() -> None:
    single = {"kind": "string", "nature": "N", "value": {"text": "x"}, "anchor": {}}
    assert investigation_frontier_fingerprint(single) == _original_fingerprint(single)
    assert investigation_frontier_fingerprint(["not-a-mapping", 42, None]) == _original_fingerprint(
        ["not-a-mapping", 42, None]
    )
    assert investigation_frontier_fingerprint(object()) == _original_fingerprint(object())


def test_fingerprint_distinguishes_different_frontiers() -> None:
    """A hash that collapsed everything would pass the equality tests vacuously."""
    first = _rows(10)
    second = _rows(10)
    second[0] = {**second[0], "value": {"text": "different"}}
    assert investigation_frontier_fingerprint(first) != investigation_frontier_fingerprint(second)
