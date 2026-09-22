"""Semantic evidence keys must stay identical while getting cheap.

`_semantic_evidence_key` decides whether an action's output is a new observation or
a reuse of one already on the frontier.  It normalized a payload by recursively
building a *cleaned copy* of it (`strip_provenance`) and then JSON-serialising that
copy (twice - once for `value`, once for `anchor`) with `sort_keys=True`.

A live stack of a stalled run sat here for minutes:

    investigate -> execute -> _semantic_evidence_key -> digest -> strip_provenance
      -> strip_provenance -> strip_provenance -> ...

On the real sample the payloads include 2.1 MB instruction-window and 1.4 MB
data-correlation rows, and the loop normalises one key PER PRODUCED ROW - so the
full nested structure was copied and serialised purely to hash it.

The narrow fix keeps the exact same JSON text: the cleaned object is not built at
all, and the serialiser walks the original while skipping the same provenance keys,
emitting the value for an unrepresentable object in the same way `default=str`
would.  These tests pin equality against the original implementation.
"""

from __future__ import annotations

import hashlib
import json

from threat_report_agent.service import _provenance_free_digest

PROVENANCE_KEYS = {
    "derivation",
    "source_evidence_id",
    "evidence_id",
    "action_id",
    "investigation_action_id",
    "planner_turn_id",
    "model_call_id",
    "origin",
}


def _original_digest(item: object) -> str:
    """The original implementation, transcribed verbatim, as the oracle."""

    def strip_provenance(node: object) -> object:
        if isinstance(node, dict):
            cleaned: dict[str, object] = {}
            for raw_key, raw_value in node.items():
                key = str(raw_key)
                normalized = key.casefold()
                if normalized in PROVENANCE_KEYS or normalized.endswith("_evidence_ids"):
                    continue
                cleaned[key] = strip_provenance(raw_value)
            return cleaned
        if isinstance(node, (list, tuple, set, frozenset)):
            return [strip_provenance(value) for value in node]
        return node

    return hashlib.sha256(
        json.dumps(
            strip_provenance(item),
            ensure_ascii=True,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


PAYLOADS: list[object] = [
    {"name": "FUN_140004605", "entry": "140004605", "instruction_count": 4481},
    # Provenance-only fields must be dropped, including the `_evidence_ids` suffix.
    {
        "api": "CreateProcessW",
        "command": "http://69.48.228.74/ComHost.exe",
        "evidence_id": "ev-1",
        "action_id": "a-1",
        "derivation": {"model_call_id": "m-1"},
        "supporting_evidence_ids": ["x", "y"],
        "origin": "investigation",
    },
    {"window": ["mov eax, 1", "cmp rax, 2", "jne 0x140001000"]},
    {"steps": [{"text": "CMP RAX, 0x493E1", "category": "anti_analysis"}]},
    {"nested": {"deep": {"deeper": {"value": 7, "evidence_id": "ev-9"}}}},
    {"mixed": [1, 2.5, True, False, None, "text"]},
    {"empty_dict": {}, "empty_list": [], "none": None},
    {"unicode": "注册表 SOFTWARE\\Microsoft\\Windows Defender"},
    {"provenance_only": {"evidence_id": "e", "model_call_id": "m"}},
    {"tuple": (1, 2, 3), "set_like": frozenset({"a"})},
    {"escape": 'quote " and \\ backslash and \n newline'},
    {"numbers": {"hex": "0x09080008", "int": 300001, "float": 1.5}},
]


def test_provenance_free_digest_matches_the_original_for_every_shape() -> None:
    for payload in PAYLOADS:
        assert _provenance_free_digest(payload) == _original_digest(payload), (
            f"digest diverged for {payload!r}"
        )


def test_provenance_free_digest_is_stable_across_calls() -> None:
    payload = PAYLOADS[1]
    assert _original_digest(payload) == _original_digest(payload)
    assert _provenance_free_digest(payload) == _provenance_free_digest(payload)


def test_provenance_free_digest_separates_different_observations() -> None:
    """A digest that collapsed everything would pass the equality tests vacuously."""
    first = _provenance_free_digest({"api": "CreateProcessW", "flags": "0x1"})
    second = _provenance_free_digest({"api": "CreateProcessW", "flags": "0x2"})
    assert first != second


def test_provenance_free_digest_ignores_provenance_but_not_content() -> None:
    with_provenance = {"api": "WinHttpOpen", "evidence_id": "ev-1", "action_id": "a-1"}
    without_provenance = {"api": "WinHttpOpen"}
    assert _provenance_free_digest(with_provenance) == _provenance_free_digest(
        without_provenance
    )
    assert _provenance_free_digest({"api": "WinHttpSendRequest"}) != _provenance_free_digest(
        without_provenance
    )


def test_provenance_free_digest_handles_a_large_payload() -> None:
    """The payload shape that made this expensive: a multi-kB instruction window."""
    payload = {"window": [f"mov eax, {index}" for index in range(20_000)]}
    assert _provenance_free_digest(payload) == _original_digest(payload)
