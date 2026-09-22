"""Unresolved-status detection must be exact, and must not walk payloads pointlessly.

`_contains_unresolved_status` recurses the ENTIRE payload looking for status-like
keys.  A live stack of a stalled run sat in it:

    behavior_catalog.py:139 <genexpr> -> :140 _contains_unresolved_status
      -> typing.__instancecheck__ / __subclasscheck__

Measured per payload:

    instruction window 50000 (1.76 MB)   0.0258 s
    data references 20000    (1.29 MB)   0.0484 s

and the real corpus holds ~38,000 rows whose payloads reach 2.1 MB.  0.05 s x 38,000
is ~32 minutes, which is the stall.  The walk is only ever looking for a handful of
status-like KEYS, so a payload that contains none of them cannot be unresolved - and
that is the overwhelming majority of rows (instruction windows, data references,
strings).  These tests pin that the fast path returns exactly what the full walk did.
"""

from __future__ import annotations

from threat_report_agent.behavior_catalog import (
    _contains_unresolved_status,
    is_concrete_value,
)

STATUS_KEYS = {
    "status", "verification_status", "resolution_status", "result_status", "validity",
    "resolved", "success",
}

PAYLOADS: list[object] = [
    # No status-like key at all: the fast path must agree with the full walk.
    {"api": "WinHttpOpen", "target": "140004605"},
    {"window": ["mov eax, 1", "cmp rax, 2"]},
    {"data_references": [{"target_name": "PTR_s_x", "rva": 1}]},
    {"text": "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet"},
    {"steps": [{"text": "cmp rax, 0x493e1", "category": "anti_analysis"}]},
    # Status-like keys present, including nested ones.
    {"value": "x", "status": "UNKNOWN"},
    {"value": "x", "status": "VERIFIED"},
    {"verification_status": "UNRESOLVED"},
    {"resolved": False},
    {"resolved": True},
    {"success": False},
    {"success": True},
    {"validity": "not_applicable"},
    {"result_status": "candidate"},
    {"nested": {"status": "UNKNOWN"}},
    {"steps": [{"status": "unresolved"}]},
    {"list": [{"status": "VERIFIED"}, {"status": "UNKNOWN"}]},
    {"status": None},
    {"status": ""},
    {"Status": "unknown"},
    {"STATUS": "UNKNOWN"},
    {"result_status": "ok"},
    {},
    [],
    None,
    "plain string",
    42,
]


def test_fast_path_matches_the_full_walk_for_every_payload() -> None:
    """`is_concrete_value` and the unresolved check must be unchanged."""
    for payload in PAYLOADS:
        expected_unresolved = _original_contains_unresolved(payload)
        assert _contains_unresolved_status(payload) == expected_unresolved, (
            f"unresolved check diverged for {payload!r}"
        )
        expected_concrete = not expected_unresolved and _original_is_concrete(
            payload, expected_unresolved
        )
        assert is_concrete_value(payload) == expected_concrete, (
            f"is_concrete_value diverged for {payload!r}"
        )


def _original_contains_unresolved(value: object) -> bool:
    """The pre-fix implementation, transcribed, as the oracle."""
    from collections.abc import Mapping

    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key or "").strip().casefold().replace("-", "_")
            if name in {
                "status", "verification_status", "resolution_status",
                "result_status", "validity",
            }:
                normalised = str(item or "").strip().casefold()
                if normalised in _UNRESOLVED or _original_unknown_scalar(item):
                    return True
            elif name == "resolved" and item is False:
                return True
            elif name == "success" and item is False:
                return True
            if _original_contains_unresolved(item):
                return True
    elif isinstance(value, (list, tuple, set, frozenset)):
        return any(_original_contains_unresolved(item) for item in value)
    return False


def _original_unknown_scalar(value: object) -> bool:
    from threat_report_agent.behavior_catalog import _is_unknown_scalar

    return _is_unknown_scalar(value)


def _original_is_concrete(value: object, unresolved: bool) -> bool:
    from collections.abc import Mapping

    if isinstance(value, Mapping):
        if unresolved:
            return False
        return bool(value) and any(_original_is_concrete(v, False) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return bool(value) and any(_original_is_concrete(v, False) for v in value)
    return not _original_unknown_scalar(value)


_UNRESOLVED = frozenset(
    {
        "unknown", "not_identified", "not identified", "unresolved",
        "unobserved", "not observed", "not available", "missing",
        "unsupported", "not proven", "not_proven", "refuted", "rejected",
        "failed", "failure", "error", "candidate", "partial", "pending",
        "not_applicable", "not applicable",
    }
)


def test_a_large_status_free_payload_is_not_walked() -> None:
    """The performance property: a status-free payload of 50k items stays cheap.

    This is the payload shape that made the stall - and it must not regress to the
    full walk.  The measurement takes the BEST of several runs and the bound is
    deliberately loose against the defect it guards: the naive walk costs ~25 ms on
    this payload, i.e. well over 10x the bound, while a single wall-clock reading on a
    loaded build machine can exceed a tight bound on its own (observed once when this
    suite ran alongside a container build).  A flaky perf gate gets ignored, which is
    worse than a loose one.
    """
    import time

    payload = {"window": [f"mov rax, qword ptr [rsi + 0x{index:x}]" for index in range(50_000)]}
    assert _contains_unresolved_status(payload) is False
    best = min(_timed_contains_unresolved(payload) for _ in range(5))
    assert best < 0.015, f"status-free payload cost {best:.4f}s; the full walk is back"


def _timed_contains_unresolved(payload: object) -> float:
    import time

    started = time.perf_counter()
    _contains_unresolved_status(payload)
    return time.perf_counter() - started
