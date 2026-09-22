"""The hex literal table must decode to the script it holds, and must not invent one.

This capability did not exist, which is why the published report for the 白象 sample `64da3378` carried a
`TOOL_AUTHORING_REQUIRED: DECODE_CONFIG` ticket whose missing-evidence list read
`cipher/data, key, algorithm, counter, step, plaintext, consumer`. Every one of those items belongs to a
CIPHER, and the sample's encoding is not a cipher at all - which is why `recover_static_xor_configs`
correctly found 0 configs and no XOR-based tool could ever have satisfied the ticket.

The real chain, derived from the bytes and anchored on the constructor's own `MOV EDX,0x402c08` operand:

    every 48 bytes:   20 ASCII-HEX chars as UTF-16LE code units (40 B)
                      00 00 00 00                             (4 B terminator)
                      28 00 00 00  -> 0x28 = 40               (4 B size field)
    1. decode UTF-16LE, cut at the first NUL   ->  "61636528227620626120"
    2. unhexlify                               ->  b'ace("v ba '
    3. the bytes are script text (latin-1)

The stride is 48, not 40: the size field records the PAYLOAD size, so it is not the record length. Three
wrong readings are pinned as tests below, because each one produced a plausible-looking wrong answer.
"""
from __future__ import annotations

import binascii
import struct

import pytest

from threat_report_agent.literal_table import (
    RECORD_STRIDE,
    discover_anchored_literal_tables,
    recover_hex_literal_table,
)

SAMPLE = (
    r"D:\test\白象_revers_AGENT"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
)


def _record(text: str) -> bytes:
    """One table record holding up to 10 bytes of `text`, in the sample's own layout.

    A slot holds 20 ASCII-hex characters stored as UTF-16LE code units (40 bytes), a 4-byte terminator and
    the 4-byte size field `0x28`. 20 hex chars = **10 bytes**, which is exactly why the sample's recovered
    fragments are 10 characters long and why longer API names appear only where consecutive records happen
    to join. Pass at most 10 bytes, or use `_records`, which chunks for you.
    """
    hex_text = binascii.hexlify(text.encode("latin-1")).decode("ascii")
    assert len(hex_text) <= 20, "a slot holds at most 20 hex characters (10 bytes)"
    payload = hex_text.encode("utf-16-le").ljust(40, b"\x00")
    return payload + b"\x00\x00\x00\x00" + b"\x28\x00\x00\x00"


def _records(*texts: str) -> tuple[bytes, int]:
    """Chunk each text into 10-byte records; returns the bytes and the record count."""
    chunks: list[bytes] = []
    for text in texts:
        raw = text.encode("latin-1")
        for start in range(0, len(raw), 10):
            chunks.append(_record(raw[start : start + 10].decode("latin-1")))
    return b"".join(chunks), len(chunks)


def _pe_summary(records: int, *, raw_offset: int = 0x1000) -> dict:
    """A section whose RVA and file offset both start at 0x1000.

    The caller places the record bytes at file offset 0x1000, so `raw_offset` must be 0x1000 as well;
    passing 0 made the decoder read the zero padding that precedes the records.
    """
    return {
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": records * RECORD_STRIDE + 0x10,
                "raw_size": records * RECORD_STRIDE + 0x10,
                "raw_offset": raw_offset,
            }
        ]
    }


def _sample_summary(content: bytes) -> dict:
    pe = struct.unpack_from("<I", content, 0x3C)[0]
    opt = pe + 24
    count = struct.unpack_from("<H", content, pe + 6)[0]
    opt_size = struct.unpack_from("<H", content, pe + 20)[0]
    table = opt + opt_size
    sections = []
    for index in range(count):
        off = table + index * 40
        name = content[off : off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", content, off + 8)
        sections.append(
            {
                "name": name,
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "raw_offset": raw_ptr,
            }
        )
    return {"sections": sections}


def _sample_bytes() -> bytes | None:
    try:
        with open(SAMPLE, "rb") as handle:
            return handle.read()
    except OSError:
        return None


# --------------------------------------------------------------------------- synthetic
def test_the_chain_decodes_a_record() -> None:
    payload, count = _records("WScript.Cr", "eateObject")
    content = b"\x00" * 0x1000 + payload
    result = recover_hex_literal_table(
        content, _pe_summary(count), table_rva=0x1000, table_end_rva=0x1000 + count * RECORD_STRIDE,
    )
    assert result.decoded
    assert "WScript.CreateObject" in result.text, (
        "consecutive records must join: they are sequential fragments of one script"
    )
    assert result.stride == RECORD_STRIDE
    assert result.records_decoded == count


def test_the_stride_is_48_not_40() -> None:
    """40 is the size field's value, not the record length. Using it cuts every literal."""
    assert RECORD_STRIDE == 48
    payload, count = _records(*(["abcdefghij"] * 4))
    content = b"\x00" * 0x1000 + payload
    result = recover_hex_literal_table(
        content, _pe_summary(count), table_rva=0x1000, table_end_rva=0x1000 + count * RECORD_STRIDE,
    )
    assert result.text.count("abcdefghij") == 4, (
        "a 40-byte stride misaligns the walk and truncates the literals"
    )


def test_no_table_yields_an_empty_result_not_an_error() -> None:
    """A sample without this table is a normal outcome, not a failure."""
    result = recover_hex_literal_table(b"\x00" * 64, {"sections": []})
    assert not result.decoded
    assert result.text == ""
    assert result.records_walked == 0


def test_a_non_hex_record_does_not_become_text() -> None:
    """The decoder must not emit whatever bytes happen to sit in a slot.

    The noise must be non-hex CHARACTERS in the slot. A first version built it with `.hex()`, which of
    course produced hex digits - so the decoder correctly decoded it and the test asserted the opposite of
    what it meant.
    """
    not_hex = "ZZZZZZZZZZ".encode("utf-16-le").ljust(40, b"\x00")
    content = b"\x00" * 0x1000 + (not_hex + b"\x00" * 8) * 4
    result = recover_hex_literal_table(
        content, _pe_summary(4), table_rva=0x1000, table_end_rva=0x1000 + 4 * RECORD_STRIDE,
    )
    assert not result.decoded, f"non-hex slots produced {result.text[:40]!r}"
    assert "ZZZZ" not in result.text


def test_a_short_record_is_decoded() -> None:
    """Some slots hold fewer than 20 hex chars; the decoder must cut at the terminator, not at 20."""
    payload, count = _records("WScript.Cr", "eateOb")
    content = b"\x00" * 0x1000 + payload
    result = recover_hex_literal_table(
        content, _pe_summary(count), table_rva=0x1000, table_end_rva=0x1000 + count * RECORD_STRIDE,
    )
    assert result.records_decoded == count, (
        f"only {result.records_decoded}/{count} records decoded; a short record was rejected"
    )


def test_marker_classes_are_matched_as_literal_substrings() -> None:
    payload, count = _records(
        "WScript.Cr", "eateObject",
        "OpenTextFi", "le(Path, T",
        "WinHttp.Wi", "nHttpReque",
        "Winmgmts:", "rootcimv2",
        "Osre.ExecQ", "uery(Sele",
        "Svr & \"/he", "lp.php?fo",
    )
    content = b"\x00" * 0x1000 + payload
    result = recover_hex_literal_table(
        content, _pe_summary(count), table_rva=0x1000, table_end_rva=0x1000 + count * RECORD_STRIDE,
    )
    classes = set(result.class_names())
    assert {"script_host", "filesystem", "http_transport", "wmi", "process_execution"} <= classes, (
        f"marker classes matched: {sorted(classes)}"
    )
    for hits in result.markers.values():
        for needle in hits:
            assert needle in result.text, f"{needle!r} was claimed but is not in the recovered text"


def test_the_evidence_projection_states_its_boundary() -> None:
    """Recovered source is not evidence that the script ran."""
    payload, count = _records(*(["WScript.Cr"] * 4))
    content = b"\x00" * 0x1000 + payload
    result = recover_hex_literal_table(
        content, _pe_summary(count), table_rva=0x1000, table_end_rva=0x1000 + count * RECORD_STRIDE,
    )
    evidence = result.as_evidence()
    assert evidence["encoding"] == "utf16le-asciihex-record-table"
    assert isinstance(evidence["decode_chain"], list) and evidence["decode_chain"]
    assert "不证明脚本已被执行" in str(evidence["boundary"])


# --------------------------------------------------------------------------- real sample
@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_the_sample_script_is_recovered() -> None:
    content = _sample_bytes()
    assert content is not None
    result = recover_hex_literal_table(content, _sample_summary(content))
    assert result.decoded, "the sample's literal table was not decoded"
    assert len(result.text) > 3000, f"only {len(result.text)} chars recovered"

    # EVERY string below was verified present in the recovered text before being asserted here
    # (`.scratch/probe-present-substrings.py`). Names NOT asserted, and why: a slot holds 10 bytes, so a
    # longer API name survives only where consecutive records happen to join. `WinHttp.WinHttpRequest.5.1`,
    # `Win32_OperatingSystem`, `ExecQuery`, `OpenTextFile`, `FolderExists`, `help.php?fol=` and
    # `Quick-Heal` are all PARTIALLY present and were deliberately not asserted - a test demanding a string
    # the recoverer cannot produce would have to be weakened later.
    for needle in (
        "WScript.CreateOb",
        "XMLHTTP",
        ".Open ",
        "Win32_",
        "Osre.Exec",
        "Shell",
        "Svr",
        "SvrSubStr",
        "folderIdx",
        "paypth",
        "UserName",
        "Write",
        "GetFlSz",
        "Sleep",
        "new_down",
        "ADODB.",
    ):
        assert needle in result.text, f"{needle!r} is missing from the recovered script"
    assert result.class_names(), "no marker class matched, so classification is broken"


@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_xor_recovery_is_correctly_silent_for_this_sample() -> None:
    """The sample has no XOR config, which is why an XOR-shaped ticket could never be closed."""
    from threat_report_agent.static_analysis import recover_static_xor_configs

    content = _sample_bytes()
    assert content is not None
    summary = _sample_summary(content)
    summary["image_base"] = struct.unpack_from("<I", content, struct.unpack_from("<I", content, 0x3C)[0] + 52)[0]
    summary["machine"] = 0x014C
    assert recover_static_xor_configs(content, summary) == (), (
        "an XOR config was reported for a sample whose encoding is a hex literal table"
    )


# --------------------------------------------------------------------------------------------------
# Anchored table discovery: find tables from the CODE that reads them, not from the SHAPE of the data.
#
# Why this exists: `discover_vb6_bstr_literals` was withdrawn after measuring 1,661 false positives from a
# shape scan, with the note that the structural fix is to locate literals from the instructions that
# reference them, the way `discover_hex_literal_table` does. That fix is implemented now, and on the 白象
# sample it finds a SECOND table (0x40bb98, phase 8 mod 48) that `recover_hex_literal_table` cannot see
# because its VA is past the `table_end_rva=0xAA00` bound.
# --------------------------------------------------------------------------------------------------


@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_anchored_discovery_finds_the_table_the_fixed_range_misses() -> None:
    """A fixed scan range is a silent-truncation risk; code-anchored discovery is not bounded that way."""
    content = _sample_bytes()
    assert content is not None
    result = discover_anchored_literal_tables(content, _sample_summary(content))

    assert result.primary is not None, "no anchored literal table was found at all"
    assert result.primary.start_va == 0x402C08, (
        f"primary table starts at {result.primary.start_va:#x}, not at the constructor's own operand"
    )
    assert len(result.tables) >= 2, (
        "only one table was found; the second phase of this sample's storage was not located"
    )

    starts = [table.start_va for table in result.tables]
    assert any(start > 0x40AA00 for start in starts), (
        f"no table starts past table_end_rva=0xAA00, so this test no longer covers the bound it exists "
        f"for; starts were {[hex(s) for s in starts]}"
    )

    # Both phases must decode real script text, not noise.
    for table in result.tables:
        assert table.decoded_slots > 0
        assert "ace(" in table.text or "Replace" in table.text, (
            f"table at {table.start_va:#x} decoded to text with no script markers: {table.text[:80]!r}"
        )


@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_the_second_table_carries_no_marker_the_first_one_lacks() -> None:
    """Pins the completeness claim the report makes.

    MEASURED: table B hits 5 marker categories, 0 of them exclusively, and no API/behaviour token occurs
    only in table B. So quoting the primary table's text does not understate the sample's marker
    vocabulary. If this assertion ever fails, the report's recovered text IS incomplete and must say so.
    """
    content = _sample_bytes()
    assert content is not None
    result = discover_anchored_literal_tables(content, _sample_summary(content))
    assert len(result.tables) >= 2, "the second table is needed for this comparison to mean anything"

    exclusive = result.marker_coverage()
    assert exclusive == {}, (
        f"a secondary literal table carries markers the primary lacks, so publishing only the primary "
        f"understates the sample: {exclusive}"
    )


@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_anchored_discovery_survives_a_section_that_begins_with_data() -> None:
    """The silent-wrong-answer guard: capstone stops at the first undecodable byte.

    This sample's real `.text` begins with data (`c6915173 ...`), and a plain `disasm` sweep over the whole
    0x24000-byte section returned **0 instructions**, which reads as "this sample references no literals".
    The fixture below makes that prefix explicit, and the test first asserts the trap is actually
    reproduced (a non-skipdata pass must yield nothing) so it cannot quietly stop testing anything.
    """
    import capstone

    content = bytearray(_sample_bytes() or b"")
    assert content
    pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
    section_table = pe_offset + 24 + struct.unpack_from("<H", content, pe_offset + 20)[0]
    virtual_address = struct.unpack_from("<I", content, section_table + 12)[0]
    raw_size = struct.unpack_from("<I", content, section_table + 16)[0]
    raw_offset = struct.unpack_from("<I", content, section_table + 20)[0]
    assert raw_size > 0x200, "unexpected .text geometry; this fixture needs a section it can overwrite"

    undecodable = bytes.fromhex("c6915173") * 64
    content[raw_offset : raw_offset + len(undecodable)] = undecodable
    content = bytes(content)

    plain = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    plain.detail = True
    code = content[raw_offset : raw_offset + raw_size]
    trap = list(plain.disasm(code, 0x400000 + virtual_address))
    assert trap == [], (
        f"the fixture no longer reproduces the trap: a non-skipdata pass decoded {len(trap)} instructions "
        f"from a section that is supposed to begin undecodably"
    )

    result = discover_anchored_literal_tables(content, _sample_summary(content))
    assert result.primary is not None and result.primary.start_va == 0x402C08, (
        "anchored discovery returned nothing once .text began with data - this is exactly the "
        "silent-wrong-answer mode the skipdata requirement exists to prevent"
    )


def test_anchored_discovery_degrades_to_empty_on_junk() -> None:
    """No PE, no sections, no exception - a caller must be able to treat "cannot read" as normal."""
    assert discover_anchored_literal_tables(b"", None).tables == ()
    assert discover_anchored_literal_tables(b"not a pe at all", None).tables == ()
    assert discover_anchored_literal_tables(b"MZ" + b"\x00" * 200, {"sections": []}).tables == ()


@pytest.mark.skipif(_sample_bytes() is None, reason="白象 sample is not present on this machine")
def test_the_decode_evidence_carries_the_completeness_verdict() -> None:
    """The pipeline's own discovery must publish the cross-table verdict, not just the probe.

    The point of running the check inside `discover_hex_literal_table` is that the published report can then
    say "only publishing the primary table does not understate the sample" as a MEASURED claim. If this key
    is absent the report has no basis for that sentence and must not write it.
    """
    from threat_report_agent.literal_table import discover_hex_literal_table

    content = _sample_bytes()
    assert content is not None
    summary = _sample_summary(content)
    summary["image_base"] = struct.unpack_from(
        "<I", content, struct.unpack_from("<I", content, 0x3C)[0] + 52
    )[0]
    summary["size_of_image"] = struct.unpack_from(
        "<I", content, struct.unpack_from("<I", content, 0x3C)[0] + 24 + 56
    )[0]

    result = discover_hex_literal_table(content, summary)
    assert result.decoded

    check = result.second_table_check
    assert check is not None, (
        "the pipeline's discovery ran without the completeness check, so the report cannot claim the "
        "primary table is not truncated"
    )
    assert check["tables_found"] >= 2
    assert check["markers_only_in_secondary"] == []
    assert check["verdict"] == "no_extra_markers"

    # And it must survive into the projection the pipeline actually stores.
    evidence = result.as_evidence()
    assert "second_table_check" in evidence
    assert evidence["second_table_check"]["verdict"] == "no_extra_markers"

    # The check must be SHORT: a per-row diagnostic that grows with the recovered text is how the published
    # revision previously ballooned 9,084 -> 22,452 characters through duplication.
    assert len(str(check)) < 900, "the completeness check is too large to travel with every decode row"


def test_the_evidence_omits_the_check_when_it_did_not_run() -> None:
    """"The check did not happen" must not be published as "the check passed"."""
    from threat_report_agent.literal_table import RecoveredScript

    empty = RecoveredScript("", 0, 0, 0, 0, RECORD_STRIDE)
    assert "second_table_check" not in empty.as_evidence()
