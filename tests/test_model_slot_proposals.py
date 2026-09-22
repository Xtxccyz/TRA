"""Model slot proposals are only usable when a substring backs them, checked against a named corpus.

Why this exists: the eight official slots are asked about the HOST BINARY, while for the 白象 VB6 loader the
behaviour lives in a decoded SCRIPT. MEASURED: the recovered text contains `On Error`, `Resume`, `Loop`,
`XMLHTTP`, `ADODB`, `Exec` - the answers were present all along and nothing attributed them to a slot. So the
model is allowed to propose slot NAMES (open vocabulary) and to choose WHICH corpus backs each one.

What keeps that safe is not a cap or a template but this function: every proposal must name an
`evidence_substring` that occurs literally in the corpus it names. The check is mechanical and independent of
the model. It does NOT check that the substring means what the model says it means - that is the honest
limit, and the reason a supported slot is written as `CANDIDATE` (a Claim status in `CONTEXT.md`), never as a
verified fact.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from threat_report_agent.analyst_report import (
    _SLOT_EVIDENCE_BOUNDARY,
    AnalystReportPlanEnvelope,
    verify_model_slot_proposals,
)

SCRIPT = (
    "... xtsrPrf = Ge : On Error Resume Next : Do While x : Loop ... "
    'CreateObject("WScript.Shell") ... XMLHTTP ... ADODB ... Resume Next ...'
)
CORPORA = {"recovered_script": SCRIPT, "imports": "MSVBVM60.DLL VBA6.DLL"}


def _proposal(**kwargs) -> dict:
    base = {
        "slot": "failure_fallback",
        "value": "脚本含 On Error Resume Next",
        "evidence_substring": "On Error Resume Next",
        "evidence_source": "recovered_script",
    }
    base.update(kwargs)
    return base


def test_a_substring_that_occurs_is_supported_and_declares_its_support_kind() -> None:
    supported, rejected = verify_model_slot_proposals([_proposal()], CORPORA)
    assert rejected == []
    assert len(supported) == 1
    entry = supported[0]
    assert entry["slot"] == "failure_fallback"
    # NOT a Claim status: CANDIDATE belongs to Claims (CONTEXT.md), and a slot proposal has no evidence_id.
    # Stamping a Claim status on it would be cross-layer promotion by field name (behavior plan §12.5 item 1).
    assert entry["support"] == "substring_matched"
    assert "status" not in entry, "a Claim status must not be stamped on a non-Claim proposal"
    assert "On Error Resume Next" in entry["boundary"] or "构造" in entry["boundary"]


def test_the_boundary_is_derived_from_the_source_not_written_once() -> None:
    """Three corpora license three different statements; one template would let a string read as a fact."""
    script_slot, _ = verify_model_slot_proposals([_proposal()], CORPORA)
    import_slot, _ = verify_model_slot_proposals(
        [_proposal(slot="target", evidence_substring="MSVBVM60.DLL", evidence_source="imports")],
        CORPORA,
    )
    assert script_slot[0]["boundary"] != import_slot[0]["boundary"]
    assert script_slot[0]["boundary"] == _SLOT_EVIDENCE_BOUNDARY["recovered_script"]
    assert import_slot[0]["boundary"] == _SLOT_EVIDENCE_BOUNDARY["imports"]
    assert "不证明" in script_slot[0]["boundary"], "the boundary must state what the evidence does not show"


def test_an_absent_substring_is_rejected_and_the_reason_is_kept() -> None:
    supported, rejected = verify_model_slot_proposals(
        [_proposal(evidence_substring="Scripting.FileSystemObject")], CORPORA
    )
    assert supported == []
    assert len(rejected) == 1
    assert "not found" in rejected[0]["reason"]


def test_an_unrecognised_source_is_rejected_not_passed() -> None:
    """Otherwise a model invents a corpus name and the substring is 'verified' against nothing."""
    supported, rejected = verify_model_slot_proposals(
        [_proposal(evidence_source="made_up_corpus")], CORPORA
    )
    assert supported == []
    assert "unknown evidence_source" in rejected[0]["reason"]


def test_a_missing_substring_or_unusable_slot_name_is_rejected() -> None:
    supported, rejected = verify_model_slot_proposals(
        [
            _proposal(evidence_substring=""),
            _proposal(slot="", evidence_substring="On Error"),
            _proposal(slot="UNKNOWN(consumer)", evidence_substring="On Error"),
            _proposal(value="", evidence_substring="On Error"),
        ],
        CORPORA,
    )
    assert supported == []
    assert len(rejected) == 4


def test_there_is_no_cap_on_how_many_proposals_survive() -> None:
    """The count emerges from verification. A cap would be the crude limit the plan rejects - and it would
    not work, since an invented slot sorts exactly as high as a real one."""
    proposals = [_proposal(slot=f"slot_{index}") for index in range(40)]
    supported, rejected = verify_model_slot_proposals(proposals, CORPORA)
    assert len(supported) == 40
    assert rejected == []


def test_the_envelope_no_longer_silently_drops_slots() -> None:
    """`extra="ignore"` meant a model emitting `slots` had them discarded without a trace."""
    envelope = AnalystReportPlanEnvelope.model_validate(
        {"chapters": [], "limitations": [], "slots": [_proposal()]}
    )
    assert len(envelope.slots) == 1
    assert envelope.slots[0].evidence_source == "recovered_script"


def test_unknown_fields_on_a_proposal_are_tolerated() -> None:
    """A model will add fields; tolerating them is not the same as trusting them."""
    supported, _ = verify_model_slot_proposals([_proposal(confidence=0.9, note="extra")], CORPORA)
    assert len(supported) == 1
    assert "confidence" not in supported[0], "model-supplied metadata must not be promoted into the entry"


@pytest.mark.skipif(
    not Path(
        r"D:\test\白象_revers_AGENT\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    ).is_dir(),
    reason="白象 sample is not present on this machine",
)
def test_the_real_recovered_script_supports_the_slots_that_were_unknown() -> None:
    """The point of the whole phase: the answers were in the recovered text all along."""
    import struct

    sys_path = Path(__file__).resolve().parents[1] / "src"
    import sys

    sys.path.insert(0, str(sys_path))
    from threat_report_agent.literal_table import discover_hex_literal_table

    sample_dir = Path(
        r"D:\test\白象_revers_AGENT\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    )
    payload = next(path for path in sample_dir.iterdir() if path.is_file()).read_bytes()
    pe = struct.unpack_from("<I", payload, 0x3C)[0]
    opt = pe + 24
    image_base = struct.unpack_from("<I", payload, opt + 28)[0]
    size_of_image = struct.unpack_from("<I", payload, opt + 56)[0]
    count = struct.unpack_from("<H", payload, pe + 6)[0]
    opt_size = struct.unpack_from("<H", payload, pe + 20)[0]
    sections = []
    for index in range(count):
        off = opt + opt_size + index * 40
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", payload, off + 8)
        sections.append(
            {
                "name": payload[off : off + 8].rstrip(b"\x00").decode("latin1"),
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_offset": raw,
                "raw_size": rsize,
            }
        )
    text = discover_hex_literal_table(
        payload, {"sections": sections, "image_base": image_base, "size_of_image": size_of_image}
    ).text
    assert text, "the sample's script was not recovered"

    proposals = [
        {"slot": "failure_fallback", "value": "含 On Error / Resume", "evidence_substring": "On Error"},
        {"slot": "loop", "value": "含循环构造", "evidence_substring": "Loop"},
        {"slot": "consumer", "value": "含 XMLHTTP 传输", "evidence_substring": "XMLHTTP"},
    ]
    supported, rejected = verify_model_slot_proposals(proposals, {"recovered_script": text})
    assert not rejected, f"the recovered script does not contain: {rejected}"
    assert {entry["slot"] for entry in supported} == {"failure_fallback", "loop", "consumer"}
