"""Parent identity recovery for the Resume PPID-spoofing orchestrator.

The sample compares an enumerated process name against one merged ``.rdata``
literal::

    explorer.exeInitializeProcThreadAttributeList failedUpdateProcThreadAttribute
    failedCreateProcessW failedOpenProcess failedexplorer not foundsnapshot failed

Two bounded steps previously kept that literal out of the PPID join, so the
report could state ``PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`` but never name the
parent:

* ``resolve_static_data_strings`` reads a 512-byte window and requires the
  NUL-terminated part to decode as UTF-8; the binary bytes that follow the
  literal abort the decode and the address is dropped.
* the task-wide table only resolves the first 256 addresses, and the literal is
  the 831st data address of the sample's 96 selected functions.

These tests pin the corrected behaviour without changing the shared table.
"""

from __future__ import annotations

import pytest

from threat_report_agent.static_analysis import (
    import_api_thunks,
    leading_process_image_name,
    recover_parent_process_attribute,
    resolve_function_data_strings,
    resolve_static_data_strings,
)

IMAGE_BASE = 0x140000000
RDATA_VA = IMAGE_BASE + 0x2000
RDATA_OFFSET = 0x1400
MERGED_LITERAL = (
    b"explorer.exe"
    b"InitializeProcThreadAttributeList failed"
    b"UpdateProcThreadAttribute failed"
    b"CreateProcessW failed"
    b"OpenProcess failed"
    b"explorer not found"
    b"snapshot failed"
)


def _image(*, literal_offset: int = RDATA_OFFSET) -> tuple[bytes, dict[str, object]]:
    """Build a minimal PE-like image whose .rdata holds the merged literal.

    The literal is followed by non-UTF-8 bytes and no early NUL, exactly like
    the sample (whose window ends on an odd byte), so neither the strict UTF-8
    decode nor the UTF-16LE fallback can accept the address.
    """
    content = bytearray(b"\x00" * max(literal_offset + 0x200, 0x1000))
    content[literal_offset : literal_offset + len(MERGED_LITERAL)] = MERGED_LITERAL
    tail = literal_offset + len(MERGED_LITERAL)
    content[tail : tail + 25] = bytes(range(0xA7, 0xC0))
    pe_summary: dict[str, object] = {
        "image_base": IMAGE_BASE,
        "entry_rva": 0x1000,
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x1000,
                "raw_offset": 0x400,
                "raw_size": 0x1000,
                "executable": True,
            },
            {
                "name": ".rdata",
                "virtual_address": 0x2000,
                "virtual_size": 0x1000,
                "raw_offset": RDATA_OFFSET,
                "raw_size": 0x1000,
                "executable": False,
            },
        ],
    }
    return bytes(content), pe_summary


def _ppid_thunks() -> dict[int, str]:
    return import_api_thunks(
        (
            {
                "name": "OpenProcess",
                "entry": "1400467d8",
                "instructions": [{"address": "1400467d8", "text": "JMP qword ptr [0x14005e728]"}],
            },
            {
                "name": "UpdateProcThreadAttribute",
                "entry": "140046758",
                "instructions": [{"address": "140046758", "text": "JMP qword ptr [0x14005e7a8]"}],
            },
            {
                "name": "CreateProcessW",
                "entry": "140046948",
                "instructions": [{"address": "140046948", "text": "JMP qword ptr [0x14005e5b8]"}],
            },
        )
    )


def _orchestrator(literal_va: int) -> dict[str, object]:
    """Ghidra-shaped row for the Resume PPID orchestrator around its calls."""
    return {
        "name": "FUN_140004605",
        "entry": "140004605",
        "instructions": [
            {"address": "140008c64", "text": "MOV ECX,0x80"},
            {"address": "140008c6e", "text": "CALL 0x1400467d8"},
            {"address": "140008cf0", "text": "MOV R8D,0x20000"},
            {"address": "140008cfb", "text": "CALL 0x140046758"},
            {"address": "140008db6", "text": "MOV dword ptr [RSP + 0x28],0x9080008"},
            {"address": "140008dce", "text": "CALL 0x140046948"},
            {"address": "140008b21", "text": f"LEA RDX,[0x{literal_va:x}]"},
        ],
        "references_from": [
            {
                "from": "140008c6e",
                "to": "1400467d8",
                "target_name": "OpenProcess",
                "type": "UNCONDITIONAL_CALL",
            },
            {
                "from": "140008cfb",
                "to": "140046758",
                "target_name": "UpdateProcThreadAttribute",
                "type": "UNCONDITIONAL_CALL",
            },
            {
                "from": "140008dce",
                "to": "140046948",
                "target_name": "CreateProcessW",
                "type": "UNCONDITIONAL_CALL",
            },
            {
                "from": "140008b21",
                "to": f"{literal_va:x}",
                "target_name": f"DAT_{literal_va:x}",
                "type": "DATA",
            },
        ],
    }


def test_merged_literal_resolves_only_when_printable_prefix_is_allowed() -> None:
    content, pe_summary = _image()
    address = f"{RDATA_VA:x}"

    assert resolve_static_data_strings(content, [address], pe_summary) == {}
    recovered = resolve_static_data_strings(
        content, [address], pe_summary, allow_printable_prefix=True
    )
    assert recovered[address] == MERGED_LITERAL.decode("ascii")


def test_clean_literals_are_unchanged_by_the_prefix_option() -> None:
    content, pe_summary = _image()
    clean_offset = RDATA_OFFSET + 0x100
    content = bytearray(content)
    content[clean_offset : clean_offset + 12] = b"explorer.exe"
    content[clean_offset + 12] = 0
    address = f"{IMAGE_BASE + 0x2000 + (clean_offset - RDATA_OFFSET):x}"

    strict = resolve_static_data_strings(bytes(content), [address], pe_summary)
    tolerant = resolve_static_data_strings(
        bytes(content), [address], pe_summary, allow_printable_prefix=True
    )
    assert strict == tolerant == {address: "explorer.exe"}


def test_function_local_literals_pass_the_task_wide_256_address_cap() -> None:
    content, pe_summary = _image()
    literal_va = RDATA_VA
    function = _orchestrator(literal_va)
    # 300 earlier data references push the parent literal past the shared cap.
    function["references_from"] = [
        {
            "from": f"{0x140003000 + index * 4:x}",
            "to": f"{0x14006000 + index * 8:x}",
            "target_name": f"DAT_{0x14006000 + index * 8:x}",
            "type": "DATA",
        }
        for index in range(300)
    ] + function["references_from"]

    flat_addresses = [
        str(row["to"])
        for row in function["references_from"]
        if "call" not in str(row["type"]).lower()
    ]
    assert f"{literal_va:x}" not in resolve_static_data_strings(content, flat_addresses, pe_summary)
    local = resolve_function_data_strings(content, function, pe_summary)
    assert local[f"{literal_va:x}"] == MERGED_LITERAL.decode("ascii")


def test_parent_process_join_names_the_parent_from_the_merged_literal() -> None:
    content, pe_summary = _image()
    function = _orchestrator(RDATA_VA)
    thunks = _ppid_thunks()
    # The shared table is exactly as bounded as in production: the merged
    # literal is absent from it.
    shared = {"0x140060000": "unrelated.bin"}

    without_image = recover_parent_process_attribute(function, shared, thunks=thunks)
    assert without_image is not None
    assert "parent_selection" not in without_image
    assert without_image["attribute"] == "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"

    recovered = recover_parent_process_attribute(
        function, shared, thunks=thunks, content=content, pe_summary=pe_summary
    )
    assert recovered is not None
    assert recovered["parent_selection"] == "explorer.exe"
    assert recovered["attribute"] == "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
    assert recovered["access_mask"] == "PROCESS_CREATE_PROCESS"
    assert recovered["callsite"] == "140008cfb"
    assert recovered["open_process"] == "OpenProcess"
    assert recovered["create_process"] == "CreateProcessW"


def test_join_still_rejects_functions_without_the_ppid_chain() -> None:
    content, pe_summary = _image()
    function = _orchestrator(RDATA_VA)
    function["instructions"] = [
        row for row in function["instructions"] if row["address"] != "140008cfb"
    ]
    function["references_from"] = [
        row
        for row in function["references_from"]
        if row["target_name"] != "UpdateProcThreadAttribute"
    ]
    assert (
        recover_parent_process_attribute(
            function, {}, thunks=_ppid_thunks(), content=content, pe_summary=pe_summary
        )
        is None
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        (MERGED_LITERAL.decode("ascii"), "explorer.exe"),
        ("explorer.exe", "explorer.exe"),
        (r"C:\Windows\explorer.exe", r"C:\Windows\explorer.exe"),
        ("InitializeProcThreadAttributeList failed", None),
        ("", None),
    ),
)
def test_leading_process_image_name_projection(value: str, expected: str | None) -> None:
    assert leading_process_image_name(value) == expected
