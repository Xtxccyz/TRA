"""Address scoping for the PPID parent-literal widening.

``recover_parent_process_attribute`` may now resolve the literals of the
function it is given, but that widening must stay address-scoped: a merged
``explorer.exe...`` literal elsewhere in ``.rdata`` must not be attributed to a
function that never names it, and a literal named only by a non-call data
reference must still resolve.  Both properties are pinned here on a synthetic
image so no sample bytes are needed.
"""

from __future__ import annotations

from threat_report_agent.static_analysis import (
    import_api_thunks,
    recover_parent_process_attribute,
    resolve_function_data_strings,
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


def _image() -> tuple[bytes, dict[str, object]]:
    content = bytearray(b"\x00" * 0x1800)
    # Merged, non-NUL-terminated literal followed by binary bytes.
    content[RDATA_OFFSET : RDATA_OFFSET + len(MERGED_LITERAL)] = MERGED_LITERAL
    tail = RDATA_OFFSET + len(MERGED_LITERAL)
    content[tail : tail + 25] = bytes(range(0xA7, 0xC0))
    # A clean, unrelated literal the orchestrator may legitimately name.
    clean = RDATA_OFFSET + 0x100
    content[clean : clean + 13] = b"unrelated.bin"
    content[clean + 13] = 0
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


def _thunks() -> dict[int, str]:
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


def _orchestrator(*, literal_va: int | None) -> dict:
    instructions = [
        {"address": "140008c64", "text": "MOV ECX,0x80"},
        {"address": "140008c6e", "text": "CALL 0x1400467d8"},
        {"address": "140008cf0", "text": "MOV R8D,0x20000"},
        {"address": "140008cfb", "text": "CALL 0x140046758"},
        {"address": "140008db6", "text": "MOV dword ptr [RSP + 0x28],0x9080008"},
        {"address": "140008dce", "text": "CALL 0x140046948"},
    ]
    if literal_va is not None:
        instructions.append({"address": "140008b21", "text": f"LEA RDX,[0x{literal_va:x}]"})
    references = [
        {"from": "140008c6e", "to": "1400467d8", "target_name": "OpenProcess", "type": "UNCONDITIONAL_CALL"},
        {
            "from": "140008cfb",
            "to": "140046758",
            "target_name": "UpdateProcThreadAttribute",
            "type": "UNCONDITIONAL_CALL",
        },
        {"from": "140008dce", "to": "140046948", "target_name": "CreateProcessW", "type": "UNCONDITIONAL_CALL"},
    ]
    if literal_va is not None:
        references.append(
            {
                "from": "140008b21",
                "to": f"{literal_va:x}",
                "target_name": f"DAT_{literal_va:x}",
                "type": "DATA",
            }
        )
    return {
        "name": "FUN_140004605",
        "entry": "140004605",
        "instructions": instructions,
        "references_from": references,
    }


def test_parent_literal_is_not_borrowed_from_an_unreferenced_address() -> None:
    """The widening resolves only the addresses this function names."""
    content, pe_summary = _image()
    clean_va = IMAGE_BASE + 0x2000 + 0x100
    function = _orchestrator(literal_va=clean_va)

    recovered = recover_parent_process_attribute(
        function,
        {f"{clean_va:x}": "unrelated.bin"},
        thunks=_thunks(),
        content=content,
        pe_summary=pe_summary,
    )
    assert recovered is not None
    assert recovered["attribute"] == "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
    assert recovered["access_mask"] == "PROCESS_CREATE_PROCESS"
    # The merged explorer.exe literal exists in .rdata but this function never
    # names it, so no parent identity may be projected.
    assert "parent_selection" not in recovered


def test_literal_named_only_by_a_data_reference_still_resolves() -> None:
    """Ghidra data references, not only LEA text, carry the literal address."""
    content, pe_summary = _image()
    function = _orchestrator(literal_va=None)
    # The data reference is the only place the literal address appears.
    function["references_from"].append(
        {
            "from": "1400089a0",
            "to": f"{RDATA_VA:x}",
            "target_name": f"DAT_{RDATA_VA:x}",
            "type": "PARAM",
        }
    )
    assert not any(f"{RDATA_VA:x}" in str(row["text"]).lower() for row in function["instructions"])

    local = resolve_function_data_strings(content, function, pe_summary)
    assert local[f"{RDATA_VA:x}"] == MERGED_LITERAL.decode("ascii")

    recovered = recover_parent_process_attribute(
        function, {}, thunks=_thunks(), content=content, pe_summary=pe_summary
    )
    assert recovered is not None
    assert recovered["parent_selection"] == "explorer.exe"
