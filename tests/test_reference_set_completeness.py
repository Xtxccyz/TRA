"""The recovered reference set and the instruction window must not be truncated.

Provenance for the numbers used here: the persisted Ghidra artifact for the
551KB Rust PE ``6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145``
(``.scratch/ppid-diag/ghidra_toolrun.json``, 704 functions, 9.4 MB) reports
871 non-call references from ``FUN_140004605`` and 4481 instructions.  The
Windows Defender registry block sits at non-call reference ordinals 619-909 and
instruction indexes 3007-3249, so both the old ``rows[:64]`` cut and the old
256-instruction preview deleted it before it could become Evidence.  These
tests use synthetic rows shaped like that artifact and never require the sample.
"""

from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.static_analysis import (
    MAX_FUNCTION_DATA_REFERENCES,
    MAX_INSTRUCTION_WINDOW_ITEMS,
    build_instruction_window_payload,
    correlate_data_references,
    data_reference_truncation,
    evidence_function_body,
    resolve_data_strings_chunked,
    select_instruction_window_indices,
)

IMAGE_BASE = 0x140000000
DEFENDER_LEA_SITE = 0x140007E2F
DEFENDER_KEY_VA = 0x14004C3B9
DEFENDER_POLICY_VA = 0x14004C62F
MAPS_REPORTING_VA = 0x14004C418
SPYNET_REPORTING_VA = 0x14004C43B


def _data_reference(index: int, target: int) -> dict[str, object]:
    return {
        "from": f"{IMAGE_BASE + 0x4600 + index * 4:x}",
        "to": f"{target:x}",
        "type": "DATA",
        "target_name": f"DAT_{target:x}",
    }


def _defender_reference(target: int, site: int) -> dict[str, object]:
    return {
        "from": f"{site:x}",
        "to": f"{target:x}",
        "type": "DATA",
        "target_name": f"s_{target:x}",
    }


def _function_with_references(count: int) -> dict[str, object]:
    """A function whose reference set is far past the old 64-row cut.

    The Defender literals land at ordinals 619-622 in this fixture, exactly
    where the real artifact places them (619-909).
    """
    references: list[dict[str, object]] = []
    for index in range(count):
        if index == 619:
            references.append(_defender_reference(DEFENDER_KEY_VA, DEFENDER_LEA_SITE))
            continue
        if index == 620:
            references.append(_defender_reference(DEFENDER_POLICY_VA, 0x140008323))
            continue
        if index == 621:
            references.append(_defender_reference(MAPS_REPORTING_VA, 0x140007E6E))
            continue
        if index == 622:
            references.append(_defender_reference(SPYNET_REPORTING_VA, 0x140007ED4))
            continue
        references.append(_data_reference(index, 0x14004D000 + index * 8))
    return {
        "name": "FUN_140004605",
        "entry": f"{IMAGE_BASE + 0x4605:x}",
        "references_from": references,
    }


def _function_with_defender_tail(count: int = 871) -> dict[str, object]:
    """A function whose reference set ends with the Defender registry block."""
    references: list[dict[str, object]] = [
        _data_reference(index, 0x14004D000 + index * 8) for index in range(count - 4)
    ]
    references.append(_defender_reference(DEFENDER_KEY_VA, DEFENDER_LEA_SITE))
    references.append(_defender_reference(DEFENDER_POLICY_VA, 0x140008323))
    references.append(_defender_reference(MAPS_REPORTING_VA, 0x140007E6E))
    references.append(_defender_reference(SPYNET_REPORTING_VA, 0x140007ED4))
    return {
        "name": "FUN_140004605",
        "entry": f"{IMAGE_BASE + 0x4605:x}",
        "references_from": references,
    }


def _defender_strings() -> dict[str, str]:
    return {
        f"{DEFENDER_KEY_VA:x}": r"SOFTWARE\Microsoft\Windows Defender\SpyNet",
        f"{DEFENDER_POLICY_VA:x}": (
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
        ),
        f"{MAPS_REPORTING_VA:x}": "MAPSReporting",
        f"{SPYNET_REPORTING_VA:x}": "SpynetReporting",
    }


def test_function_keeps_more_than_64_data_references() -> None:
    """Exactly 64 references was the old cut; a complete set must survive it."""
    function = _function_with_references(96)
    result = correlate_data_references(function, _defender_strings())
    assert len(result) == 96
    assert len(result) != 64


def test_reference_set_is_not_cut_before_the_defender_block() -> None:
    """A function with hundreds of references keeps every one of them.

    The real artifact places the Windows Defender registry block at reference
    ordinals 619-909, i.e. entirely past the old 64-row cut.
    """
    function = _function_with_defender_tail(871)
    strings = _defender_strings()
    result = correlate_data_references(function, strings)
    assert len(result) == 871
    assert len(result) != 64

    by_target = {row["to"]: row for row in result}
    assert by_target[f"{DEFENDER_KEY_VA:x}"]["resolved_string"] == (
        r"SOFTWARE\Microsoft\Windows Defender\SpyNet"
    )
    assert by_target[f"{DEFENDER_POLICY_VA:x}"]["resolved_string"] == (
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    )
    assert by_target[f"{MAPS_REPORTING_VA:x}"]["resolved_string"] == "MAPSReporting"
    assert by_target[f"{SPYNET_REPORTING_VA:x}"]["resolved_string"] == "SpynetReporting"

    # The old cut ended at reference 63; the Defender rows must be past it.
    ordinal = {
        row["to"]: index for index, row in enumerate(function["references_from"])
    }
    assert ordinal[f"{DEFENDER_KEY_VA:x}"] > 63
    assert ordinal[f"{DEFENDER_POLICY_VA:x}"] > 63

    # The guard is a degenerate-input bound, not a quota.
    assert MAX_FUNCTION_DATA_REFERENCES > 871
    assert data_reference_truncation(function, result) is None


def test_guarded_reference_cut_records_what_it_dropped() -> None:
    """If the degenerate guard ever fires the drop count must be visible."""
    function = _function_with_references(300)
    result = correlate_data_references(function, {}, max_references=64)
    assert len(result) == 64
    truncation = data_reference_truncation(function, result, max_references=64)
    assert truncation is not None
    assert truncation["references_total"] == 300
    assert truncation["references_kept"] == 64
    assert truncation["references_dropped"] == 236
    assert truncation["reason"] == "degenerate_input_guard"


def _long_function_instructions(count: int) -> list[dict[str, object]]:
    rows = [
        {"address": f"{IMAGE_BASE + 0x4605 + index:x}", "mnemonic": "NOP", "text": "NOP"}
        for index in range(count)
    ]
    # The Defender block sits where the real artifact places it.
    if count > 3007:
        rows[3007] = {
            "address": f"{DEFENDER_LEA_SITE:x}",
            "mnemonic": "LEA",
            "text": "LEA RAX,[0x14004c3b9]",
        }
    if count > 3248:
        rows[3248] = {
            "address": "140008323",
            "mnemonic": "LEA",
            "text": "LEA RAX,[0x14004c62f]",
        }
    return rows


def test_instruction_window_covers_the_whole_recovered_function() -> None:
    """The stored window is the analysed body, so nothing may be dropped."""
    instructions = _long_function_instructions(4481)
    payload = build_instruction_window_payload(
        name="FUN_140004605",
        entry="140004605",
        entry_rva=0x4605,
        instructions=instructions,
        pinned_indexes=(),
        max_items=MAX_INSTRUCTION_WINDOW_ITEMS,
    )
    assert payload["instructions_total"] == 4481
    assert payload["instructions_selected"] == 4481
    assert payload["instructions_omitted"] == 0
    assert payload["selection"] == "complete_function_body"
    assert "truncation" not in payload

    addresses = {row["address"] for row in payload["instructions"]}
    assert f"{DEFENDER_LEA_SITE:x}" in addresses
    assert "140008323" in addresses

    texts = [row["text"] for row in payload["instructions"]]
    assert "LEA RAX,[0x14004c3b9]" in texts
    assert "LEA RAX,[0x14004c62f]" in texts

    # The old preview kept 418 of 4481 instructions and omitted both LEAs.
    assert len(payload["instructions"]) != 418
    assert MAX_INSTRUCTION_WINDOW_ITEMS > 4481


def test_guarded_instruction_window_records_what_it_omitted() -> None:
    """A bounded window must never be mistakable for a short function."""
    instructions = _long_function_instructions(4481)
    payload = build_instruction_window_payload(
        name="FUN_140004605",
        entry="140004605",
        entry_rva=0x4605,
        instructions=instructions,
        pinned_indexes=(3007, 3248),
        max_items=256,
    )
    assert payload["instructions_total"] == 4481
    assert payload["instructions_selected"] < 4481
    assert payload["instructions_omitted"] == (
        payload["instructions_total"] - payload["instructions_selected"]
    )
    assert payload["selection"] == "degenerate_input_guard"
    truncation = payload["truncation"]
    assert truncation["instructions_dropped"] == payload["instructions_omitted"]
    assert truncation["guard"] == "max_items"

    # Pinned sites are admitted even when the guard binds.
    addresses = {row["address"] for row in payload["instructions"]}
    assert f"{DEFENDER_LEA_SITE:x}" in addresses
    assert "140008323" in addresses


def test_default_window_selection_returns_every_instruction() -> None:
    """``max_items=None`` means "the function", not "a page of it"."""
    instructions = _long_function_instructions(4481)
    indexes = select_instruction_window_indices(instructions)
    assert len(indexes) == 4481
    assert indexes[0] == 0
    assert indexes[-1] == 4480


class _Row:
    def __init__(self, kind: str, value: dict[str, object]) -> None:
        self.kind = kind
        self.value = value


def test_abstract_executor_input_keeps_the_whole_function_body() -> None:
    """Decompile/CFG projections must see the tail, not a 256-instruction head."""
    instructions = _long_function_instructions(4481)
    target_rows = [
        (_Row("function_instruction_window", {"instructions": instructions}), ""),
        (
            _Row(
                "function_context",
                {
                    "name": "FUN_140004605",
                    "entry": "140004605",
                    "cfg_blocks": [{"start": "140008323", "end": "140008400"}],
                    "references": [{"to": "14004c3b9"}],
                },
            ),
            "",
        ),
    ]
    action = SimpleNamespace(parameters={"function": "FUN_140004605"}, action_type="GET_DECOMPILE")

    body = evidence_function_body(action=action, target_rows=target_rows)
    assert body["instructions_total"] == 4481
    assert len(body["instructions"]) == 4481
    assert body["instructions"][3007]["text"] == "LEA RAX,[0x14004c3b9]"
    assert body["data_references"] == [{"to": "14004c3b9"}]
    assert body["context"]["cfg_blocks"]
    assert body["name"] == "FUN_140004605"


def test_partial_context_instructions_are_still_complete() -> None:
    """A context-only function body is used as-is, never re-cut."""
    instructions = _long_function_instructions(3000)
    target_rows = [
        (_Row("function_context", {"name": "FUN_x", "instructions": instructions}), "")
    ]
    action = SimpleNamespace(parameters={}, action_type="GET_DECOMPILE")

    body = evidence_function_body(action=action, target_rows=target_rows)
    assert len(body["instructions"]) == 3000


def _pe_summary_identity() -> dict[str, object]:
    """Map every address to itself so a literal can be placed by file offset."""
    return {
        "image_base": 0,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0,
                "virtual_size": 1 << 20,
                "raw_offset": 0,
                "raw_size": 1 << 20,
            }
        ],
    }


def test_chunked_resolution_reaches_literals_past_the_first_256_addresses() -> None:
    """The retired flat cap resolved 78 of 9727 addresses on this sample."""
    content = bytearray(b"\x00" * 120000)
    literal = b"SOFTWARE\\Microsoft\\Windows Defender\\SpyNet\x00"
    content[100000 : 100000 + len(literal)] = literal
    # Six-digit addresses so the literal scanner accepts them; the resolvable
    # one sits far past the retired 256-address cut.
    literal_offset = 100000
    addresses = [f"{index:06x}" for index in range(0, 1800, 2)]
    addresses.append(f"{literal_offset:06x}")

    assert len(addresses) > 256
    assert addresses.index(f"{literal_offset:06x}") > 256
    resolved = resolve_data_strings_chunked(content, addresses, _pe_summary_identity())
    assert resolved[f"{literal_offset:06x}"] == (
        r"SOFTWARE\Microsoft\Windows Defender\SpyNet"
    )


def test_chunked_resolution_keeps_a_degenerate_guard() -> None:
    """The guard bounds one call; it does not silently page a task-wide set."""
    content = bytearray(b"\x00" * 4096)
    literal = b"GuardProbe\x00"
    content[40 : 40 + len(literal)] = literal
    resolved = resolve_data_strings_chunked(
        content,
        ["000028", "000050", "000060", "000070"],
        _pe_summary_identity(),
        max_addresses=2,
    )
    # Only the first two addresses were considered, so the literal at 0x28 is
    # resolved and the call never walks the rest.
    assert resolved == {"000028": "GuardProbe"}
