"""P-6 focused tests: the frozen dump D and the resident follow-up query (plan §10, route B2).

WHAT THIS FILE IS FOR. `.scratch/u1-b2-decision.md` measured that two headless exports of the SAME bytes differ
in 8 function fields and 4 of 8,826 symbols. B2's consequence is therefore not "the dump is stable" but "the dump
is FROZEN, and every comparison is relative to those bytes". This file asserts that contract at the level that
matters:

  * C1 the pseudo-C a follow-up query returns AGREES with D's own record for that `entry` - and a resident answer
    that disagrees is refused with NO pseudo-C;
  * C2 the identity key is `entry`, so a reordered or substituted symbol table cannot move an answer onto a
    different function - while an index-keyed resolver measurably can;
  * C3 a sealed dump is readable but immutable, and a dump stored WITHOUT its measured instability record is
    rejected as incomplete rather than used;
  * C4 service down / unloaded / timeout is `PARTIAL`/`BLOCKED` with a queryable limitation, no pseudo-C, and the
    limitation reaches the re-rendered official Markdown.

NO TEST HERE NEEDS GHIDRA. The transport is injected, so the seam is exercised deterministically on the host; the
real Ghidra runs happen in the deployed container and are recorded as the step's acceptance evidence.

`_seam()` resolves the P-6 names through the module object on purpose: when the seam is absent every test in this
file FAILS individually with a node id, instead of the whole file dying as one collection error that would hide
which behaviours are missing.
"""
from __future__ import annotations

import hashlib
import json
import stat
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import ghidra_adapter as adapter  # noqa: E402
from threat_report_agent.analyst_report import render_official_markdown  # noqa: E402
from threat_report_agent.task.limitations import merge_operational_limitations  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
PSEUDO_MAIN = "undefined8 main(void)\n{\n  return 0;\n}\n"
PSEUDO_CALLER = "void caller(void)\n{\n  main();\n}\n"


def _seam(name: str):
    value = getattr(adapter, name, None)
    if value is None:
        pytest.fail(
            f"ghidra_adapter.{name} does not exist: the P-6 frozen-dump / resident-query seam is absent, so this "
            "behaviour cannot hold"
        )
    return value


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _document(
    entries: list[str],
    pseudo: dict[str, str] | None = None,
    symbols: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    functions: list[dict[str, object]] = []
    for index, entry in enumerate(entries):
        record: dict[str, object] = {
            "name": f"FUN_{entry}",
            "entry": entry,
            "entry_rva": entry,
            "signature": "void f(void)",
            "mnemonics": ["MOV", "RET"],
            "instructions": [{"address": entry, "mnemonic": "MOV", "text": "MOV EAX,EBX"}],
            "pcode_ops": [],
            "references_from": [],
            "xrefs_to_entry": [],
            "cfg_blocks": [{"start": entry, "end": entry, "destinations": []}],
            "fuzzy_fingerprint": f"{index:016x}",
        }
        if pseudo and entry in pseudo:
            record["pseudo_c"] = {"text": pseudo[entry], "sha256": _sha256(pseudo[entry])}
        functions.append(record)
    return {
        "schema_version": "1.0",
        "exporter": "ExportStaticFacts",
        "image_base": "140000000",
        "functions": functions,
        "strings": [],
        "symbols": list(symbols or []),
    }


def _sealed(tmp_path: Path, document: dict[str, object], comparison: dict[str, object] | None = None,
            requested: tuple[str, ...] = ("140001000",), compare_with: dict[str, object] | None = None):
    compute = _seam("compute_dump_instability")
    seal = _seam("seal_frozen_dump")
    instability = comparison if comparison is not None else compute(document, compare_with or document)
    return seal(
        document,
        instability,
        tmp_path / "dumps",
        requested_entries=requested,
    )


def _answering_transport(answer: dict[str, object], calls: list[dict[str, object]] | None = None):
    def transport(request, deadline_seconds):  # noqa: ANN001 - mirrors the shipped transport signature
        if calls is not None:
            calls.append(dict(request))
        return dict(answer)

    return transport


def _unavailable_transport(message: str):
    def transport(request, deadline_seconds):  # noqa: ANN001
        raise _seam("FollowUpUnavailable")(message)

    return transport


# ---------------------------------------------------------------------------------------------------------------------
# C1 - the query's answer agrees with the FROZEN dump, never with a fresh run
# ---------------------------------------------------------------------------------------------------------------------
def test_c1_a_query_for_an_entry_in_the_dump_returns_the_dumps_own_pseudo_c(tmp_path: Path) -> None:
    document = _document(["140001000", "140002000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    query = _seam("query_frozen_dump")
    outcome = query(
        frozen,
        "140001000",
        transport=_answering_transport(
            {"entry": "140001000", "pseudo_c": {"text": PSEUDO_MAIN, "sha256": _sha256(PSEUDO_MAIN)},
             "decompile_millis": 278, "error": None}
        ),
        deadline_seconds=30,
    )
    assert outcome.status == "SUCCEEDED", outcome.as_evidence()
    assert outcome.pseudo_c == PSEUDO_MAIN
    assert outcome.agreement == "AGREES_WITH_FROZEN_DUMP"
    assert outcome.dump_sha256_before == outcome.dump_sha256_after == frozen.dump_sha256
    assert outcome.limitation is None


def test_c1_a_resident_answer_that_disagrees_with_the_dump_is_blocked_with_no_pseudo_c(tmp_path: Path) -> None:
    """The NEGATIVE direction of C1, at unit level: a different pseudo-C must not be published as agreement."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140001000",
        transport=_answering_transport(
            {"entry": "140001000", "pseudo_c": {"text": PSEUDO_CALLER, "sha256": _sha256(PSEUDO_CALLER)},
             "error": None}
        ),
        deadline_seconds=30,
    )
    assert outcome.status == "BLOCKED"
    assert outcome.pseudo_c is None, "a disagreeing pseudo-C must never be handed to a caller"
    assert outcome.agreement == "DISAGREES_WITH_FROZEN_DUMP"
    assert outcome.limitation is not None
    assert outcome.limitation.code == "GHIDRA_FOLLOW_UP_PSEUDO_C_DISAGREES_WITH_FROZEN_DUMP"
    assert "disagree" in outcome.limitation_text


def test_c1_a_service_that_lies_about_its_own_digest_is_caught(tmp_path: Path) -> None:
    """A declared `sha256` is never trusted: the digest is recomputed from the text actually returned."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140001000",
        transport=_answering_transport(
            {"entry": "140001000",
             "pseudo_c": {"text": PSEUDO_CALLER, "sha256": _sha256(PSEUDO_MAIN)},
             "error": None}
        ),
        deadline_seconds=30,
    )
    assert outcome.status == "BLOCKED"
    assert outcome.pseudo_c is None


def test_c1_an_entry_outside_the_dump_is_refused_without_being_queried(tmp_path: Path) -> None:
    """C1's second negative direction: an entry D does not contain must not reach the resident at all."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    calls: list[dict[str, object]] = []
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140009000",
        transport=_answering_transport({"entry": "140009000", "pseudo_c": {"text": PSEUDO_MAIN}}, calls),
        deadline_seconds=30,
    )
    assert calls == [], "the resident was asked about an entry the frozen dump does not contain"
    assert outcome.status == "PARTIAL"
    assert outcome.pseudo_c is None
    assert outcome.agreement == "NOT_IN_FROZEN_DUMP"
    assert outcome.limitation is not None
    assert outcome.limitation.code == "GHIDRA_FOLLOW_UP_ENTRY_NOT_IN_FROZEN_DUMP"


# ---------------------------------------------------------------------------------------------------------------------
# C2 - the identity key is `entry`
# ---------------------------------------------------------------------------------------------------------------------
def test_c2_symbol_reordering_and_substitution_do_not_move_an_answer_off_its_entry(tmp_path: Path) -> None:
    """The exact hazard the plan names: symbol order is not identity (substitutions were measured, 4/8,826)."""
    symbols_first = [
        {"name": "alpha", "address": "140001000", "type": "Function", "external": True},
        {"name": "beta", "address": "140002000", "type": "Function", "external": True},
    ]
    symbols_reordered = list(reversed(symbols_first))
    symbols_reordered[1] = {"name": "gamma", "address": "140002000", "type": "Label", "external": False}
    document_a = _document(["140001000", "140002000"], pseudo={"140001000": PSEUDO_MAIN}, symbols=symbols_first)
    document_b = _document(
        ["140001000", "140002000"], pseudo={"140001000": PSEUDO_MAIN}, symbols=symbols_reordered
    )
    frozen_a = _sealed(tmp_path / "a", document_a)
    frozen_b = _sealed(tmp_path / "b", document_b)
    record_a = frozen_a.record_for_entry("0x140001000")
    record_b = frozen_b.record_for_entry("140001000")
    assert record_a is not None and record_b is not None
    assert record_a["name"] == record_b["name"], "the same `entry` resolved to different functions"
    assert frozen_a.recorded_pseudo_c("140001000") == frozen_b.recorded_pseudo_c("140001000")


def test_c2_an_index_keyed_resolver_is_not_invariant_to_the_same_reordering() -> None:
    """Why `entry` and not the index: with the function order changed an index-keyed resolver answers wrongly.

    This is the unit-level half of C2's negative control; the artifact records the same mis-keyed resolver as a
    real pytest run that exits 1.
    """
    document_a = _document(
        ["140001000", "140002000"],
        symbols=[{"name": "alpha", "address": "140001000", "type": "Function", "external": True}],
    )
    document_b = _document(
        ["140002000", "140001000"],
        symbols=[{"name": "alpha", "address": "140001000", "type": "Function", "external": True}],
    )
    index_keyed_a = document_a["functions"][0]  # type: ignore[index]
    index_keyed_b = document_b["functions"][0]  # type: ignore[index]
    identity = _seam("entry_identity")
    assert index_keyed_a["entry"] != index_keyed_b["entry"], (
        "the fixture must actually move the function at index 0, or the control is vacuous"
    )
    assert index_keyed_a["name"] != index_keyed_b["name"], (
        "an index-keyed resolver must visibly answer with a different function here"
    )
    assert identity(index_keyed_a["entry"]) == "140001000"
    assert identity(index_keyed_b["entry"]) == "140002000"


def test_c2_entry_identity_normalises_the_shapes_ghidra_and_a_caller_both_produce() -> None:
    identity = _seam("entry_identity")
    assert identity("140001000") == identity("0x140001000") == identity("0X140001000")
    assert identity("00401000") == identity("401000")
    assert identity("not-an-address") is None
    assert identity("") is None


# ---------------------------------------------------------------------------------------------------------------------
# C3 - sealed, readable, immutable, and stored WITH its measured instability
# ---------------------------------------------------------------------------------------------------------------------
def test_c3_a_sealed_dump_is_read_only_and_verifies_before_and_after_a_query(tmp_path: Path) -> None:
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    assert frozen.path.name == f"{frozen.dump_sha256}.json", "the file name must BE the content address"
    assert stat.S_IMODE(frozen.path.stat().st_mode) & 0o222 == 0, "the sealed dump stayed writable"
    assert frozen.verify() == frozen.dump_sha256
    opened = _seam("open_frozen_dump")(frozen.path)
    assert opened.dump_sha256 == frozen.dump_sha256
    outcome = _seam("query_frozen_dump")(
        opened,
        "140001000",
        transport=_answering_transport(
            {"entry": "140001000", "pseudo_c": {"text": PSEUDO_MAIN, "sha256": _sha256(PSEUDO_MAIN)}}
        ),
        deadline_seconds=30,
    )
    assert outcome.dump_sha256_before == outcome.dump_sha256_after == frozen.dump_sha256


def test_c3_a_dump_without_its_instability_record_is_rejected_as_incomplete(tmp_path: Path) -> None:
    """C3's negative control at unit level: no instability record, no usable dump."""
    payload = {
        "schema_version": "1.0",
        "kind": "frozen_static_facts_dump",
        "identity_key": "entry",
        "requested_entries": ["140001000"],
        "dump": _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    path = tmp_path / f"{digest}.json"
    path.write_bytes(encoded)
    with pytest.raises(_seam("FrozenDumpIncomplete")):
        _seam("open_frozen_dump")(path)


def test_c3_an_instability_record_without_the_symbol_set_diff_is_rejected(tmp_path: Path) -> None:
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    complete = _seam("compute_dump_instability")(document, document)
    truncated = {key: value for key, value in complete.items() if key != "symbols"}
    with pytest.raises(_seam("FrozenDumpIncomplete")):
        _seam("seal_frozen_dump")(document, truncated, tmp_path / "dumps")
    with pytest.raises(_seam("FrozenDumpIncomplete")):
        _seam("seal_frozen_dump")(document, {}, tmp_path / "dumps")


def test_c3_the_instability_record_is_recomputed_and_enumerates_its_members() -> None:
    document_a = _document(["140001000", "140002000"], pseudo={"140001000": PSEUDO_MAIN})
    document_b = _document(["140001000", "140002000"], pseudo={"140001000": PSEUDO_CALLER})
    document_b["functions"][1]["signature"] = "int f(int a)"  # type: ignore[index]
    instability = _seam("compute_dump_instability")(document_a, document_b)
    assert instability["identity_key"] == "entry"
    assert instability["unstable_field_entries"]["pseudo_c"] == ["140001000"]
    assert instability["unstable_field_entries"]["signature"] == ["140002000"]
    assert "signature" in instability["unstable_fields"]
    assert "pseudo_c" in instability["unstable_fields"]
    assert instability["function_entries"]["only_in_a"] == []
    assert instability["function_entries"]["only_in_b"] == []
    # The historical numbers may appear ONLY as a source note - never as the measured set.
    assert "8 unstable fields" in instability["source_note"]
    assert instability["source_note"].count("source note") or "SOURCE NOTE ONLY" in instability["source_note"]


def test_c3_a_symbol_set_difference_is_enumerated_not_counted() -> None:
    document_a = _document(["140001000"], symbols=[
        {"name": "alpha", "address": "140001000", "type": "Function", "external": True},
        {"name": "beta", "address": "140002000", "type": "Function", "external": True},
    ])
    document_b = _document(["140001000"], symbols=[
        {"name": "alpha", "address": "140001000", "type": "Function", "external": True},
        {"name": "gamma", "address": "140002000", "type": "Function", "external": True},
    ])
    instability = _seam("compute_dump_instability")(document_a, document_b)
    assert instability["symbols"]["only_in_a"] == ["beta|140002000|Function"]
    assert instability["symbols"]["only_in_b"] == ["gamma|140002000|Function"]
    assert instability["symbols"]["common"] == ["alpha|140001000|Function"]


def test_c3_rewriting_the_stored_pseudo_c_makes_the_dump_unreadable(tmp_path: Path) -> None:
    """C1's second negative direction, at byte level: tampering with D's stored pseudo-C must be non-zero."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document)
    frozen.path.chmod(0o644)
    raw = frozen.path.read_bytes()
    marker = b"undefined8 main(void)"
    assert marker in raw, "the fixture must store the pseudo-C in a form this tamper can reach"
    tampered = raw.replace(marker, b"undefined8 MAIN(void)", 1)
    assert tampered != raw
    frozen.path.write_bytes(tampered)
    with pytest.raises(_seam("FrozenDumpTampered")):
        _seam("open_frozen_dump")(frozen.path)
    with pytest.raises(_seam("FrozenDumpTampered")):
        frozen.verify()


def test_c3_a_replaced_dump_is_refused_even_when_the_replacement_is_a_valid_dump(tmp_path: Path) -> None:
    """'Replacing D' must be non-zero: a different, perfectly valid dump is still not the sealed one."""
    original = _sealed(tmp_path / "one", _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    replacement = _sealed(tmp_path / "two", _document(["140003000"], pseudo={"140003000": PSEUDO_CALLER}))
    with pytest.raises(_seam("FrozenDumpTampered")):
        _seam("open_frozen_dump")(replacement.path, expected_sha256=original.dump_sha256)


# ---------------------------------------------------------------------------------------------------------------------
# C4 - down / unloaded / timeout: terminal, queryable, and NEVER pseudo-C
# ---------------------------------------------------------------------------------------------------------------------
def test_c4_a_down_resident_is_blocked_with_a_queryable_limitation_and_no_pseudo_c(tmp_path: Path) -> None:
    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140001000",
        transport=_unavailable_transport("GHIDRA_RESIDENT_UNAVAILABLE: nothing is listening"),
        deadline_seconds=30,
    )
    assert outcome.status == "BLOCKED"
    assert outcome.pseudo_c is None
    assert outcome.limitation is not None and outcome.limitation.code == "GHIDRA_RESIDENT_UNAVAILABLE"
    assert "No pseudo-C was produced" in outcome.limitation_text


def test_c4_an_unloaded_resident_is_blocked_and_is_never_reported_as_succeeded(tmp_path: Path) -> None:
    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140001000",
        transport=_unavailable_transport("GHIDRA_RESIDENT_UNLOADED: closed without answering"),
        deadline_seconds=30,
    )
    assert outcome.status in {"BLOCKED", "PARTIAL"}
    assert outcome.status != "SUCCEEDED"
    assert outcome.pseudo_c is None


def test_c4_a_timeout_is_not_reported_as_succeeded(tmp_path: Path) -> None:
    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))

    def timing_out(request, deadline_seconds):  # noqa: ANN001
        raise TimeoutError("deadline reached")

    outcome = _seam("query_frozen_dump")(
        frozen, "140001000", transport=timing_out, deadline_seconds=0.001
    )
    assert outcome.status == "BLOCKED"
    assert outcome.pseudo_c is None
    assert outcome.limitation is not None and outcome.limitation.code == "GHIDRA_FOLLOW_UP_TIMEOUT"


def test_c4_the_summary_reports_a_non_success_status_and_publishes_the_set_difference(tmp_path: Path) -> None:
    """M5: the summary publishes ENUMERATED sets, so "one entry failed" can never read as "all entries done"."""
    document = _document(["140001000", "140002000"], pseudo={"140001000": PSEUDO_MAIN})
    frozen = _sealed(tmp_path, document, requested=("140001000", "140002000"))
    summary = _seam("_follow_up_summary")(
        frozen,
        ["140001000", "140002000"],
        [
            _seam("query_frozen_dump")(
                frozen,
                "140001000",
                transport=_answering_transport(
                    {"entry": "140001000",
                     "pseudo_c": {"text": PSEUDO_MAIN, "sha256": _sha256(PSEUDO_MAIN)}}
                ),
                deadline_seconds=30,
            )
        ],
        deadline_source={"key": "tools[ghidra-headless].max_cpu_seconds", "value": 900},
        transcript="",
        resident_error="GHIDRA_RESIDENT_UNAVAILABLE",
    )
    assert summary["status"] == "BLOCKED"
    difference = summary["entry_set_difference"]
    assert difference["identity_key"] == "entry"
    assert difference["enumerated_set"] == ["140001000", "140002000"]
    assert difference["retrieved_set"] == ["140001000"]
    assert difference["expected_minus_actual"] == ["140002000"]
    assert difference["actual_minus_expected"] == []
    assert summary["deadline"]["value"] == 900
    assert summary["summary_limitation"], "a non-SUCCEEDED batch must publish a limitation"
    assert summary["limitations"], "the per-entry reason must survive into the summary"


def test_c4_the_limitation_reaches_the_official_markdown(tmp_path: Path) -> None:
    """M4's reader half, at the level that counts: the string the PRODUCT projects appears in the RENDERED body.

    MEASURED (gate-owner finding #3): an earlier version of this test fed `merge_operational_limitations` the
    per-outcome `outcome.limitation_text` and then asserted the entry was in the render - which held only for
    that test-built string, because the service projects `summary_limitation`, which named no entry. So this test
    now builds the task's limitations with the REAL projection (`AnalysisService._follow_up_limitations`) from the
    REAL batch summary, and asserts what a reader can actually see: the reason code AND the `entry`.

    The chain is the product's own: `ghidra_adapter` produces the batch -> `service.py::_follow_up_limitations`
    projects it onto the task -> `merge_operational_limitations` labels and merges it into
    `analyst_report_limitations` -> `render_official_markdown` prints it. Nothing here reads a JSON field and
    calls it a projection.
    """
    from threat_report_agent.service import AnalysisService

    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    summary = _seam("_follow_up_summary")(
        frozen,
        ["140001000"],
        [
            _seam("query_frozen_dump")(
                frozen,
                "140001000",
                transport=_unavailable_transport("GHIDRA_RESIDENT_UNAVAILABLE: nothing is listening"),
                deadline_seconds=30,
            )
        ],
        deadline_source={"key": "tools[ghidra-headless].max_cpu_seconds", "value": 900},
        transcript="",
    )
    projected = AnalysisService._follow_up_limitations({"follow_up": summary})
    assert projected, "the service projected nothing for a BLOCKED batch"

    class _Task:
        limitations = projected

    document: dict[str, object] = {
        "analyst_report_limitations": [],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }
    merge_operational_limitations(document, _Task())
    rendered = render_official_markdown(document)
    assert "GHIDRA_RESIDENT_UNAVAILABLE" in rendered, (
        "the follow-up limitation never reached the official Markdown, so no reader can see why an entry has no "
        f"pseudo-C; rendered head={rendered[:400]!r}"
    )
    assert "140001000" in rendered, (
        "the reason code reached the body but the ENTRY did not, so a reader cannot tell WHICH function has no "
        "pseudo-C"
    )


def test_c4_the_limitation_channel_is_the_only_reason_it_renders(tmp_path: Path) -> None:
    """NEGATIVE CONTROL for the test above: with an EMPTY limitation list the same text is not rendered."""
    document: dict[str, object] = {
        "analyst_report_limitations": [],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }

    class _Task:
        limitations: list[str] = []

    merge_operational_limitations(document, _Task())
    rendered = render_official_markdown(document)
    assert "GHIDRA_RESIDENT_UNAVAILABLE" not in rendered


def test_c4_the_three_terminal_causes_have_their_own_reason_tokens(tmp_path: Path) -> None:
    """C4 names down / unloaded / timeout. One bucket for all three would not be a distinguishable state."""
    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    query = _seam("query_frozen_dump")
    codes = {}
    for label, message in (
        ("down", "GHIDRA_RESIDENT_UNAVAILABLE: nothing is listening on the resident follow-up port"),
        ("unloaded", "GHIDRA_RESIDENT_UNLOADED: accepted the connection and closed it without answering"),
        ("timeout", "GHIDRA_FOLLOW_UP_TIMEOUT: the resident did not answer before the external deadline"),
    ):
        outcome = query(
            frozen,
            "140001000",
            transport=_unavailable_transport(message),
            deadline_seconds=30,
        )
        assert outcome.status == "BLOCKED", label
        assert outcome.pseudo_c is None, label
        codes[label] = outcome.limitation.code
    assert len(set(codes.values())) == 3, f"the three C4 causes share a reason token: {codes}"
    assert codes == {
        "down": "GHIDRA_RESIDENT_UNAVAILABLE",
        "unloaded": "GHIDRA_RESIDENT_UNLOADED",
        "timeout": "GHIDRA_FOLLOW_UP_TIMEOUT",
    }
    details = adapter._RESIDENT_ERROR_DETAIL
    assert "DOWN" in details["GHIDRA_RESIDENT_UNAVAILABLE"]
    assert "UNLOADED" in details["GHIDRA_RESIDENT_UNLOADED"]
    assert "TIMEOUT" in details["GHIDRA_FOLLOW_UP_TIMEOUT"]
    assert "GHIDRA_RESIDENT_CLOSED_MID_ANSWER" in details
    assert "GHIDRA_RESIDENT_CONNECT_TIMEOUT" in details


def _listening_socket():
    import socket as _socket

    server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    return server, server.getsockname()[1]


def test_c4_the_wire_taxonomy_is_produced_by_REAL_SOCKETS_not_by_stubbed_exceptions(tmp_path: Path) -> None:
    """MEASURED GAP THIS CLOSES (gate-owner finding F-1): the previous C4 tests injected the very exception the
    production transport was supposed to raise, so they passed while the WIRE behaviour was wrong - an
    accept-then-close peer produced `ConnectionResetError` (WinError 10054 / Errno 104), which the old code
    reported as `GHIDRA_RESIDENT_UNAVAILABLE` ("nothing is listening"). These four cases each drive the SHIPPED
    transport over a REAL loopback socket, so the reason token is the one the wire event actually produces.
    """
    import socket as _socket
    import threading

    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    query = _seam("query_frozen_dump")
    transport_factory = _seam("loopback_query_transport")

    # 1. DOWN - connect to a port with nothing listening. The server is closed first, so the refusal is real.
    #
    # MEASURED (`.scratch/ghidra-c3/preflight/p6-refusal-probe.json`, this host): a closed LOOPBACK port on
    # Windows yields `TimeoutError("timed out")` after the FULL connect timeout with `errno=None` - the SYN is
    # dropped, not refused - while on Linux it is an immediate `ECONNREFUSED`. The taxonomy therefore keeps
    # DOWN and CONNECT-TIMEOUT as separate reasons and this assertion states the truth for the platform it runs
    # on; the LINUX expectation (the deployed platform) is exercised by the container control
    # `control_c4_resident_down_is_reported_as_succeeded`.
    server, port = _listening_socket()
    server.close()
    down = query(frozen, "140001000", transport=transport_factory(port, connect_timeout_seconds=0.6),
                 deadline_seconds=2)
    assert down.status == "BLOCKED", down.as_evidence()
    assert down.pseudo_c is None
    expected_down_code = (
        "GHIDRA_RESIDENT_CONNECT_TIMEOUT" if sys.platform == "win32" else "GHIDRA_RESIDENT_UNAVAILABLE"
    )
    assert down.limitation.code == expected_down_code, (
        f"a refused connect must be DOWN (Linux) or CONNECT-TIMEOUT (Windows); got {down.limitation.code}"
    )

    # 2. UNLOADED - the peer accepts, drains the request, then HALF-CLOSES with no answer body (clean FIN).
    def half_close_peer(listener):
        connection, _ = listener.accept()
        with connection:
            connection.recv(65536)
            connection.shutdown(_socket.SHUT_WR)

    server, port = _listening_socket()
    thread = threading.Thread(target=half_close_peer, args=(server,), daemon=True)
    thread.start()
    unloaded = query(frozen, "140001000", transport=transport_factory(port, connect_timeout_seconds=2),
                     deadline_seconds=3)
    thread.join(timeout=5)
    server.close()
    assert unloaded.status == "BLOCKED", unloaded.as_evidence()
    assert unloaded.pseudo_c is None
    assert unloaded.limitation.code == "GHIDRA_RESIDENT_UNLOADED", (
        f"a clean empty answer must be UNLOADED; got {unloaded.limitation.code}"
    )

    # 3. CLOSED MID-ANSWER - the peer accepts and RESETS (SO_LINGER 0), which is what a JVM killed between
    #    accept and answer does. This is the case the gate owner measured; it must NOT be reported as DOWN.
    def resetting_peer(listener):
        connection, _ = listener.accept()
        connection.recv(65536)
        connection.setsockopt(_socket.SOL_SOCKET, _socket.SO_LINGER, struct.pack("ii", 1, 0))
        connection.close()

    server, port = _listening_socket()
    thread = threading.Thread(target=resetting_peer, args=(server,), daemon=True)
    thread.start()
    reset = query(frozen, "140001000", transport=transport_factory(port, connect_timeout_seconds=2),
                  deadline_seconds=3)
    thread.join(timeout=5)
    server.close()
    assert reset.status == "BLOCKED", reset.as_evidence()
    assert reset.pseudo_c is None
    assert reset.limitation.code == "GHIDRA_RESIDENT_CLOSED_MID_ANSWER", (
        f"a reset after accept must be CLOSED_MID_ANSWER, not DOWN; got {reset.limitation.code}"
    )

    # 4. TIMEOUT - the peer accepts and stays silent past the deadline.
    def silent_peer(listener):
        connection, _ = listener.accept()
        with connection:
            connection.recv(65536)
            threading.Event().wait(30)

    server, port = _listening_socket()
    thread = threading.Thread(target=silent_peer, args=(server,), daemon=True)
    thread.start()
    timed_out = query(frozen, "140001000", transport=transport_factory(port, connect_timeout_seconds=2),
                      deadline_seconds=1)
    server.close()
    assert timed_out.status == "BLOCKED", timed_out.as_evidence()
    assert timed_out.pseudo_c is None
    assert timed_out.limitation.code == "GHIDRA_FOLLOW_UP_TIMEOUT", (
        f"a silent peer must be TIMEOUT; got {timed_out.limitation.code}"
    )
    assert len({down.limitation.code, unloaded.limitation.code, reset.limitation.code,
                timed_out.limitation.code}) == 4, (
        "the four terminal causes must not collapse onto fewer reason tokens"
    )


# ---------------------------------------------------------------------------------------------------------------------
# The command-shape contract and the sourced deadline (§10.3 / M2)
# ---------------------------------------------------------------------------------------------------------------------
def test_the_export_script_arguments_keep_the_output_path_last() -> None:
    runner = adapter.GhidraHeadlessRunner(REPO_ROOT, REPO_ROOT)
    legacy = runner._export_script_args("/tmp/out.json", (), 900)
    assert legacy == ["/tmp/out.json"], "a caller that asks for no pseudo-C must get the legacy command verbatim"
    asked = runner._export_script_args(
        "/tmp/out.json", ("0x140001000", "140002000", "not-an-entry"), 900
    )
    assert asked == ["140001000,140002000", "900", "/tmp/out.json"], (
        "the per-decompile budget must come from the caller's deadline, and the output path must stay last"
    )
    command = runner._headless_command(
        "/tmp/project", import_path="/tmp/sample.exe", script=Path("/tmp/scripts/ExportStaticFacts.java"),
        script_args=asked,
    )
    assert command[-1] == "/tmp/out.json", "the exporter reads its output path as the LAST argument"
    assert command[-2] == "900"


def test_no_decompile_budget_is_chosen_inside_the_product() -> None:
    """§11.2: a `[:N]`-shaped constant inside the decompile path must be sourced, never silent."""
    for relative in (
        "src/threat_report_agent/ghidra_scripts/ExportStaticFacts.java",
        "src/threat_report_agent/ghidra_scripts/ServeFollowUpQueries.java",
    ):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "decompileFunction(function, 120" not in text, f"{relative} still hardcodes 120 seconds"
        assert "budgetSeconds" in text, f"{relative} does not derive its decompile budget"


def test_the_deadline_is_the_sourced_policy_value_and_not_a_new_number(tmp_path: Path) -> None:
    """§10.3/the fixed design: the external deadline comes from the tool policy the run already carries."""
    policy = json.loads(
        (REPO_ROOT / "src" / "threat_report_agent" / "policies" / "tool-policy.json").read_text(encoding="utf-8")
    )
    ghidra = next(item for item in policy["tools"] if item["name"] == "ghidra-headless")
    assert ghidra["max_cpu_seconds"] == 900
    assert policy.get("version") == "1.0.0"
    frozen = _sealed(tmp_path, _document(["140001000"]))
    summary = _seam("_follow_up_summary")(
        frozen,
        [],
        [],
        deadline_source={
            "key": "tools[ghidra-headless].max_cpu_seconds",
            "value": ghidra["max_cpu_seconds"],
            "policy_file": "src/threat_report_agent/policies/tool-policy.json",
            "policy_version": policy.get("version"),
        },
        transcript="",
        resident_error="GHIDRA_RESIDENT_UNAVAILABLE",
    )
    assert summary["deadline"]["value"] == 900
    assert summary["deadline"]["policy_version"] == "1.0.0"


# ---------------------------------------------------------------------------------------------------------------------
# The product call sites: the service's projection, and the durability seam the two callers share
# ---------------------------------------------------------------------------------------------------------------------
def test_the_service_projection_carries_the_producers_limitation_and_invents_nothing(tmp_path: Path) -> None:
    """M4's writer half: `service.py` must MOVE the producer's sentences, not write its own about the same fact."""
    from threat_report_agent.service import AnalysisService

    frozen = _sealed(tmp_path, _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN}))
    outcome = _seam("query_frozen_dump")(
        frozen,
        "140001000",
        transport=_unavailable_transport("GHIDRA_RESIDENT_UNAVAILABLE: nothing is listening"),
        deadline_seconds=30,
    )
    summary_limitation = "Ghidra resident follow-up query: BLOCKED for the frozen dump deadbeef"
    limitations = AnalysisService._follow_up_limitations(
        {
            "follow_up": {
                "status": "BLOCKED",
                "summary_limitation": summary_limitation,
                "limitations": [outcome.limitation_text],
            }
        }
    )
    assert limitations[0] == summary_limitation
    assert outcome.limitation_text in limitations, (
        "the per-entry reason must reach the task too, or a reader cannot tell which entry has no pseudo-C"
    )
    assert outcome.limitation_text not in AnalysisService._follow_up_limitations(
        {"follow_up": {"status": "BLOCKED", "summary_limitation": summary_limitation}}
    ), "nothing must be invented when the producer published no per-entry line"


def test_the_service_projection_is_empty_for_a_successful_or_absent_follow_up() -> None:
    from threat_report_agent.service import AnalysisService

    assert AnalysisService._follow_up_limitations(
        {"follow_up": {"status": "SUCCEEDED", "summary_limitation": "", "limitations": []}}
    ) == []
    assert AnalysisService._follow_up_limitations({"follow_up": {"status": "SUCCEEDED"}}) == []
    assert AnalysisService._follow_up_limitations({}) == []
    assert AnalysisService._follow_up_limitations(None) == []


def test_run_follow_up_batch_seals_the_same_digest_in_the_store_and_in_the_summary(tmp_path: Path) -> None:
    """The durability seam: three independent digests of ONE artifact must agree."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})

    class _Runner:
        def follow_up_batch(self, content, logical_path, export_output, **kwargs):  # noqa: ANN001
            frozen = _seam("seal_frozen_dump")(
                document,
                _seam("compute_dump_instability")(document, document),
                kwargs["dump_directory"],
                requested_entries=kwargs["entries"],
            )
            return {"status": "BLOCKED", "dump_sha256": frozen.dump_sha256,
                    "summary_limitation": "x", "frozen_dump_path": str(frozen.path)}

    class _Store:
        def __init__(self) -> None:
            self.puts: list[bytes] = []

        def put(self, payload: bytes):  # noqa: ANN201
            self.puts.append(payload)
            digest = hashlib.sha256(payload).hexdigest()
            return type("Stored", (), {"sha256": digest, "storage_key": f"content/{digest}"})()

    store = _Store()
    summary = _seam("run_follow_up_batch")(
        _Runner(), b"MZ", "sample.exe", document,
        entries=["140001000"], timeout_seconds=900, content_store=store,
    )
    assert store.puts, "the sealed dump must reach the content store, or it dies with the tmpfs"
    assert summary["sealed_digest_matches_store"] is True
    assert summary["frozen_dump_sha256"] == summary["dump_sha256"]
    assert "frozen_dump_path" not in summary, "a local tmpfs path is not durable evidence"


def test_a_follow_up_batch_with_no_requested_entries_is_blocked_and_not_successful(tmp_path: Path) -> None:
    """Absence of a request is not evidence of success: an empty set must not report SUCCEEDED."""
    document = _document(["140001000"], pseudo={"140001000": PSEUDO_MAIN})
    runner = adapter.GhidraHeadlessRunner(REPO_ROOT, REPO_ROOT)
    summary = runner.follow_up_batch(
        b"MZ", "sample.exe", document, entries=[], timeout_seconds=900, dump_directory=tmp_path / "dumps"
    )
    assert summary["status"] == "BLOCKED"
    assert summary["outcomes"] == []
    assert summary["summary_limitation"]


def test_the_legacy_tool_request_digest_is_unchanged_by_the_new_field() -> None:
    """MEASURED GAP THIS CLOSES (gate-owner finding #2): `ToolRunRequest.follow_up_entries` first joined the
    idempotency material UNCONDITIONALLY, which changed `workflow_id` for EVERY ghidra-headless request - and
    the deployed database holds 463 such `tool_runs` whose workflow ids would then stop matching, so a replay
    would run a second time instead of de-duplicating.

    The expected digest is computed here from the PRE-P-6 material LITERALLY - typed out in this test, not taken
    from the new code path - so this cannot pass by agreeing with itself.
    """
    from threat_report_agent.tools.tool_execution import ToolRunRequest

    request = ToolRunRequest(
        case_id="00000000-0000-0000-0000-000000000001",
        task_id="00000000-0000-0000-0000-000000000002",
        trace_id="00000000-0000-0000-0000-000000000003",
        artifact_id="00000000-0000-0000-0000-000000000004",
        tool_run_id="00000000-0000-0000-0000-000000000005",
        tool_name="ghidra-headless",
        tool_version="12.1.2",
        content_sha256="a" * 64,
        storage_key="content/" + "a" * 64,
        logical_path="sample.exe",
        parameters={"timeout_seconds": 900},
        max_cpu_seconds=900,
        max_memory_mb=8192,
        task_queue="static-ghidra",
    )
    legacy_material = {
        "task_id": "00000000-0000-0000-0000-000000000002",
        "artifact_id": "00000000-0000-0000-0000-000000000004",
        "content_sha256": "a" * 64,
        "tool_name": "ghidra-headless",
        "tool_version": "12.1.2",
        "parameters": {"timeout_seconds": 900},
        "max_cpu_seconds": 900,
        "max_memory_mb": 8192,
        "task_queue": "static-ghidra",
        "environment_version": "static-worker-v1",
    }
    legacy_encoded = json.dumps(
        legacy_material, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    legacy_digest = hashlib.sha256(legacy_encoded.encode("utf-8")).hexdigest()
    assert request.follow_up_entries == ()
    assert request.idempotency_key == legacy_digest, (
        "a request that asks for NO follow-up query changed its workflow id, so a replay of an already-recorded "
        "request would execute a second time"
    )
    opted_in = request.model_copy(update={"follow_up_entries": ("140001000",)})
    assert opted_in.idempotency_key != legacy_digest, (
        "a request that DOES ask for a follow-up query must get its own identity"
    )
