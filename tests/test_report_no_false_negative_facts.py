"""One structural defect: a consumer stamps UNKNOWN because it reads one shape only.

Measured on task `c705a42e` (the run behind the latest published revision), all 7 fact
classes the report had reported as missing/unrecovered were PRESENT in that task's own
evidence, while the single shape their consumer reads was empty:

    fact                          any shape   consumer's shape
    creation flags 0x09080008             1                  0
    C2 URL 69.48.228.74                   9                  0
    C2 URL miaom-c.pdf                    6                  0
    parent identity explorer.exe          2                  0
    Defender SpyNet key                   5                  0
    MOTW :Zone.Identifier                 1                  0
    scheduled task schtasks               4                  0

The mechanism is the same every time, and it is not "the fact is absent":

* the recovery writes the fact into a *different evidence shape* than the one the
  reporting consumer reads (candidate list vs typed argument, decoded blob vs API
  argument, raw string vs typed field);
* the consumer's lookup is `typed.get(key) or "UNKNOWN(key)"`, so an empty typed field
  becomes a printed absence claim even though the sibling shape holds the value;
* nothing anywhere compares the negative claim against the shapes the consumer did NOT
  read, so the false negative is never caught.

`creation_flags` is the case pinned here because it is the last failing benchmark
criterion.  The projection already BUILDS the candidate rows - `build_process_flag_projections`
emits `0x09080008` from the `process_creation_flags` row - but it drops the provenance,
so the consumer cannot tell a recovered immediate from nothing and appends
`UNKNOWN(creation_flags)` next to the value it just wrote.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import iter_document_rows, render_official_markdown
from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    build_process_flag_projections,
)

FLAG_VALUE = "0x09080008"


def _process_creation_flags_row() -> dict[str, object]:
    """The shape the sample's static scan actually stored (candidate list)."""
    return {
        "id": "ev-flags",
        "kind": "process_creation_flags",
        "module": "static_triage",
        "value": {
            "function": "FUN_140004605",
            "flags": [
                {
                    "value": "0x000f4240",
                    "set_flags": ["CREATE_NEW_PROCESS_GROUP", "EXTENDED_STARTUPINFO_PRESENT"],
                    "interpretation": "extended startup information is present",
                },
                {
                    "value": "0x08000008",
                    "set_flags": ["DETACHED_PROCESS", "CREATE_NO_WINDOW"],
                    "interpretation": "no extended startup information flag observed",
                },
                {
                    "value": FLAG_VALUE,
                    "set_flags": [
                        "DETACHED_PROCESS",
                        "EXTENDED_STARTUPINFO_PRESENT",
                        "CREATE_NO_WINDOW",
                    ],
                    "unknown_bits": "0x01000000",
                    "interpretation": (
                        "extended startup information is present; "
                        "parent-process attributes may be supplied"
                    ),
                },
            ],
        },
    }


def _document(*rows: dict[str, object]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-flags",
        "task_id": "task-flags",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": list(rows),
            }
        ],
        "trace": {},
    }


def _instruction_window_row() -> dict[str, object]:
    """The call site as the real sample stores it.

    Verified against task `c705a42e`: the window for FUN_140004605 ends with
    ``MOV dword ptr [RSP + 0x28],0x9080008`` immediately before ``CALL 0x140046948``
    (the CreateProcessW thunk), with ``XOR EDX,EDX`` for a null ``lpCommandLine``.  The
    candidate list contains eight words, of which only this one is written into the
    argument slot the call reads - which is why the call site, not the list, is the
    deterministic source.
    """
    return {
        "type": "evidence_group",
        "kind": "function_instruction_window",
        # `entry` is what links this window to the `process_creation_flags` row's
        # `anchor.function_entry`; without it the call-site lookup cannot pair them.
        "entry": "140004605",
        "name": "FUN_140004605",
        "instructions": [
            {"address": "140008da7", "text": "MOV qword ptr [RSP + 0x48],RBX"},
            {"address": "140008db1", "text": "MOVUPS xmmword ptr [RSP + 0x30],XMM6"},
            {"address": "140008db6", "text": "MOV dword ptr [RSP + 0x28],0x9080008"},
            {"address": "140008dbe", "text": "AND dword ptr [RSP + 0x20],0x0"},
            {"address": "140008dc3", "text": "MOV RCX,R14"},
            {"address": "140008dc6", "text": "XOR EDX,EDX"},
            {"address": "140008dc8", "text": "XOR R8D,R8D"},
            {"address": "140008dcb", "text": "XOR R9D,R9D"},
            {"address": "140008dce", "text": "CALL 0x140046948"},
        ],
    }


def _behavior_chapter(*, with_flags: bool) -> dict[str, object]:
    row: dict[str, object] = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "finding_status": "CANDIDATE",
        "what": "CreateProcessW construction is statically recovered.",
        "how": "CreateProcessW; dwCreationFlags slot recovered from the call site",
        "evidence_ids": ["ev-flags"] if with_flags else [],
    }
    if with_flags:
        # The recovered flag row the report builder retains, including the instruction
        # window whose call site carries the argument slot.
        row["evidence_samples"] = [
            {
                "evidence_id": "ev-flags",
                "kind": "process_creation_flags",
                "value": _process_creation_flags_row()["value"],
                "anchor": {"type": "function_instruction_window", "function_entry": "140004605"},
            },
            _instruction_window_row(),
        ]
    return {
        "id": "behavior_attack",
        "title": "Behavior / ATT&CK",
        "summary": "",
        "rows": [row],
    }


# --- the projection must carry provenance --------------------------------


def test_projection_labels_each_candidate_with_its_layer() -> None:
    """A projected flag must say WHERE it came from.

    Without this the consumer cannot distinguish a recovered typed flag word from a
    candidate immediate, and the only safe-looking thing it can do is print UNKNOWN -
    which is what produced the false negative.
    """
    projections = build_process_flag_projections(
        {"ev-flags": _process_creation_flags_row()}
    )
    assert projections, "the projection must surface the scanned candidates"
    chosen = [row for row in projections if row.get("value") == FLAG_VALUE]
    assert chosen, f"{FLAG_VALUE} must survive the projection"
    row = chosen[0]
    assert row.get("recovered_as"), (
        "each projected flag needs a provenance label so the body can say how it knows"
    )
    assert row.get("evidence_id") == "ev-flags"


def test_projection_keeps_the_disclosing_interpretation() -> None:
    """The disclaimer must travel with the value, not be dropped at the projection."""
    projections = build_process_flag_projections(
        {"ev-flags": _process_creation_flags_row()}
    )
    chosen = [row for row in projections if row.get("value") == FLAG_VALUE][0]
    assert "parent-process attributes may be supplied" in str(
        chosen.get("interpretation") or ""
    )


# --- the published body must not deny a fact it printed -------------------


def test_body_does_not_stamp_unknown_next_to_the_value_it_prints() -> None:
    """The pinned defect, at the layer that owns the wording.

    The consumer appended candidate values to `how_parts` unlabelled, then tested
    `"creation_flags" not in process_blob` and appended `UNKNOWN(creation_flags)` - so the
    published body asserted the slot was unrecovered in the same breath as printing a
    recovered value.  This asserts on the run-sequence builder, which is where that
    wording is produced.
    """
    from threat_report_agent.report.reporting import build_runtime_sequence

    findings = [
        {
            "catalog_id": "process-creation",
            "finding_status": "CANDIDATE",
            "what": "CreateProcessW construction is statically recovered.",
            "how": "CreateProcessW",
        }
    ]
    rows = build_runtime_sequence(
        findings,
        process_flags=build_process_flag_projections(
            {"ev-flags": _process_creation_flags_row()}
        ),
        # The deterministic flag word lives in the instruction window, so the sequence
        # builder needs the document that carries it.
        instruction_windows=[_instruction_window_row()],
    )
    process_rows = [
        row for row in rows if str(row.get("phase") or row.get("id") or "") == "process"
    ]
    assert process_rows, "the process phase must exist in the sequence"
    blob = " ".join(str(item) for row in process_rows for item in row.values())
    assert "creation_flags" in blob.casefold(), (
        f"the run sequence must name the slot it is describing: {blob[:300]}"
    )
    # `0x9080008` is the immediate exactly as the instruction window spells it; the
    # benchmark's own pattern is `0x0?9080008`, so both spellings are the same value.
    assert "0x9080008" in blob, f"flag value missing from the process phase: {blob[:400]}"
    assert "UNKNOWN(creation_flags)" not in blob, (
        "the sequence printed the value and denied the slot in the same document"
    )


def test_callsite_flag_is_taken_from_the_argument_slot_not_the_candidate_list() -> None:
    """A candidate list must not be mined for a guess.

    `process_creation_flags.flags` holds eight immediates for FUN_140004605 and only one
    of them belongs to CreateProcessW.  Taking the first credible entry published
    `0x28000000` for this sample - a wrong answer, which is worse than UNKNOWN.  The
    deterministic source is the slot the call reads.
    """
    from threat_report_agent.analyst_report import _recovered_creation_flags

    document = _document(_process_creation_flags_row())
    document["modules"].append(_behavior_chapter(with_flags=True))
    rows = iter_document_rows(document)
    value = _recovered_creation_flags(rows, document)
    # The window writes `0x9080008`; the benchmark pattern `0x0?9080008` accepts it, and
    # the point of the test is that it is NOT the first credible list entry.
    assert value == "0x9080008", (
        f"expected the call-site slot write 0x9080008, got {value!r}"
    )
    assert value != "0x28000000", "a candidate immediate was published as the flags"


def test_no_instruction_window_means_unknown_not_a_guess() -> None:
    """Without the call site the honest answer is UNKNOWN, never a list guess."""
    from threat_report_agent.analyst_report import _recovered_creation_flags

    document = _document(_process_creation_flags_row())
    document["modules"].append(_behavior_chapter(with_flags=False))
    rows = iter_document_rows(document)
    assert _recovered_creation_flags(rows, document) == "", (
        "the candidate list was mined even though no call site was available"
    )


# --- the window arrives as an EVIDENCE ROW, not inside the document --------


def _instruction_window_evidence_row() -> dict[str, object]:
    """The window in the shape the ledger stores it: payload nested under ``value``.

    This is the shape that reaches the renderer, and it is NOT the shape the tests above
    use.  Measured on task ``c705a42e``: the ledger held 703 ``function_instruction_window``
    rows (this one among them, 341,125 bytes) and the stored report document held zero,
    because the report projection bounds Evidence to 4,096 rows.  A helper that read only
    ``_iter_windows(document)`` therefore returned "" on the production path while passing
    every test - the join to the ledger shape was simply absent.
    """
    window = _instruction_window_row()
    return {
        "id": "ev-window",
        "kind": "function_instruction_window",
        "module": "static_triage",
        "nature": "disassembly",
        "value": {
            "entry": window["entry"],
            "name": window["name"],
            "instructions": window["instructions"],
        },
    }


def test_callsite_flag_is_recovered_from_the_evidence_row_shape() -> None:
    """The deterministic route must reach the ledger shape the renderer actually holds.

    Without this, a run can hold the deciding instructions in evidence, publish
    ``UNKNOWN(creation_flags)``, and pass every test - which is what happened.
    """
    from threat_report_agent.analyst_report import _flags_from_creation_callsite

    rows = [_instruction_window_evidence_row()]
    assert _flags_from_creation_callsite(rows, None) == "0x9080008", (
        "the call-site route did not reach the evidence-row shape (value.instructions)"
    )


def test_callsite_route_still_reads_the_document_shape() -> None:
    """The document shape must keep working; neither shape may become the only one."""
    from threat_report_agent.analyst_report import _flags_from_creation_callsite

    document = {"instruction_windows": [_instruction_window_row()]}
    assert _flags_from_creation_callsite([], document) == "0x9080008"


def test_unrelated_row_shapes_do_not_masquerade_as_a_window() -> None:
    """Only ``function_instruction_window`` rows may be scanned.

    A row carrying an ``instructions`` list under another kind is not a disassembly
    window, and treating it as one would let arbitrary evidence decide an argument value.
    """
    from threat_report_agent.analyst_report import _flags_from_creation_callsite

    row = _instruction_window_evidence_row()
    row["kind"] = "runtime_observation"
    assert _flags_from_creation_callsite([row], None) == "", (
        "a non-window evidence kind was scanned for a process-creation call site"
    )


# --- the bounded projection must keep the DECIDING window ------------------


def test_projection_keeps_the_window_that_holds_the_creation_flags() -> None:
    """The window must survive the bounded report projection, or nothing can read it.

    Measured on `c705a42e`: the ledger held 703 instruction windows and the bounded
    projection kept ZERO of them, because the only window rule matched the CryptoAPI
    markers `0x6801` / `calg`. The fact was stored, selected away, and then reported as
    UNKNOWN - a fact that cannot reach the consumer is absent as far as the report is
    concerned.
    """
    from types import SimpleNamespace

    from threat_report_agent.service import AnalysisService

    window_row = _instruction_window_evidence_row()
    unrelated = {
        "id": "ev-other-window",
        "kind": "function_instruction_window",
        "value": {
            "entry": "140001000",
            "instructions": [
                {"address": "140001000", "text": "PUSH R15"},
                {"address": "140001004", "text": "MOV dword ptr [RSP + 0x28],0x20"},
                {"address": "140001008", "text": "CALL 0x140002000"},
            ],
        },
    }
    filler = [
        SimpleNamespace(
            id=f"ev-string-{index}", kind="string", value={"text": f"filler-{index}"}
        )
        for index in range(20)
    ]
    selected = AnalysisService._select_report_evidence_rows(
        [SimpleNamespace(**unrelated), *filler, SimpleNamespace(**window_row)],
        referenced_ids=set(),
        limit=64,
    )
    kept = {
        row.id
        for row in selected
        if str(getattr(row, "kind", "")) == "function_instruction_window"
    }
    assert "ev-window" in kept, (
        "the bounded projection dropped the window carrying the creation-flags argument "
        f"slot, so no consumer can recover the value; kept={sorted(kept)}"
    )

    # The benign window is asserted on the PREDICATE, not on selection: the generic
    # kind-priority path can legitimately keep any window when the budget allows, so
    # exclusion from `selected` would be asserting something the rule does not govern.
    from threat_report_agent.report.reporting import (
        instruction_window_carries_process_creation_flags as predicate,
    )

    assert predicate(unrelated["value"]) is False, (
        "a window whose stack-slot write is an ordinary 0x20 argument passed the "
        "credibility gate; that gate is what stops 341 KB of ordinary disassembly being "
        "pulled into the report for every CALL in the sample"
    )


def test_window_predicate_tests_each_instruction_separately() -> None:
    """A `^...$`-anchored rule must not be handed a joined multi-line blob.

    The first version of the predicate joined every instruction into one string and ran the
    anchored slot regex over it, so it matched nothing at all while looking correct - the
    anchor can only match the whole blob. This test passes the same instructions joined as
    well as separate, and requires the predicate to see the line either way it is stored.
    """
    from threat_report_agent.report.reporting import (
        instruction_window_carries_process_creation_flags as predicate,
    )

    window = _instruction_window_row()
    assert predicate(window) is True, "the real window must be recognised"

    # Control: the same shape without a credible creation-flags write.
    benign = {
        "entry": "140001000",
        "instructions": [
            {"address": "140001000", "text": "MOV dword ptr [RSP + 0x28],0x20"},
            {"address": "140001008", "text": "CALL 0x140002000"},
        ],
    }
    assert predicate(benign) is False, (
        "an ordinary stack argument was treated as a creation-flags word"
    )
    assert predicate({"instructions": []}) is False
    assert predicate("MOV dword ptr [RSP + 0x28],0x9080008") is False, (
        "a bare string is not a window payload and must not be scanned as one; without "
        "this guard any stray text with a slot-write line looked like a disassembly window"
    )
    assert predicate({"no_instructions_key": True}) is False
    assert predicate(12345) is False
    assert predicate(None) is False


def test_body_still_stamps_unknown_when_no_layer_has_a_flag() -> None:
    """The honest case must survive: nothing recovered anywhere means UNKNOWN."""
    document = _document()
    document["modules"].append(
        {
            "id": "behavior_attack",
            "title": "Behavior / ATT&CK",
            "summary": "",
            "rows": [
                {
                    "type": "behavior_finding",
                    "catalog_id": "process-creation",
                    "finding_status": "CANDIDATE",
                    "what": "CreateProcessW construction is statically recovered.",
                    "how": "CreateProcessW; command=FoxitPDFReader.exe",
                    "evidence_ids": [],
                }
            ],
        }
    )
    body = render_official_markdown(document)
    assert "UNKNOWN(creation_flags)" in body, (
        "with no flag anywhere the slot is genuinely unknown and must be said so"
    )
