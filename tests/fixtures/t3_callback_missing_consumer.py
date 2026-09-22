"""T3 compiled Windows PE: TLS callback + global producer, missing consumer.

The image is assembled in-process (no assembler toolchain, no network).  It is
a real PE32, not a Ghidra database.  Pytest proves the investigation protocol
against a seeded snapshot of this fixture when headless Ghidra is unavailable.
"""

from __future__ import annotations

import struct
from pathlib import Path

IMAGE_BASE = 0x400000
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SIZE_OF_HEADERS = 0x200
TEXT_RAW = SIZE_OF_HEADERS
DATA_RAW = TEXT_RAW + FILE_ALIGNMENT
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
ENTRY_RVA = TEXT_RVA
TLS_CALLBACK_RVA = TEXT_RVA + 0x20
WORKER_RVA = TEXT_RVA + 0x40
GLOBAL_RVA = DATA_RVA
TLS_INDEX_RVA = DATA_RVA + 4
TLS_CALLBACKS_RVA = DATA_RVA + 8
TLS_DIRECTORY_RVA = DATA_RVA + 0x10
IMPORT_DIR_RVA = DATA_RVA + 0x28
ILT_RVA = DATA_RVA + 0x50
IAT_RVA = DATA_RVA + 0x58
DLL_NAME_RVA = DATA_RVA + 0x60
HINT_NAME_RVA = DATA_RVA + 0x70
GLOBAL_NAME = "g_stage"
GLOBAL_MARKER = 0x33543354  # 'T3T3'
FIXTURE_BIN = Path(__file__).with_suffix(".bin")


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _va(rva: int) -> int:
    return IMAGE_BASE + rva


def t3_callback_missing_consumer_pe() -> bytes:
    """Return a tiny PE32 with a TLS callback that writes ``g_stage``.

    Layout (no consumer of ``g_stage`` exists):

    * entry at ``0x401000`` calls ``CreateThread(worker)``
    * TLS callback at ``0x401020`` writes the global marker
    * worker at ``0x401040`` returns without reading the global
    """
    text = bytearray(FILE_ALIGNMENT)
    # Entry: CreateThread(NULL, 0, worker, NULL, 0, NULL); ret
    entry = (
        b"\x6a\x00"  # push 0  lpThreadId
        + b"\x6a\x00"  # push 0  dwCreationFlags
        + b"\x6a\x00"  # push 0  lpParameter
        + b"\x68"
        + _u32(_va(WORKER_RVA))  # push worker
        + b"\x6a\x00"  # push 0  dwStackSize
        + b"\x6a\x00"  # push 0  lpThreadAttributes
        + b"\xff\x15"
        + _u32(_va(IAT_RVA))  # call [IAT CreateThread]
        + b"\xc3"  # ret
    )
    text[0 : len(entry)] = entry
    # TLS callback: mov eax, g_stage; mov dword [eax], marker; ret 12
    callback = (
        b"\xb8"
        + _u32(_va(GLOBAL_RVA))
        + b"\xc7\x00"
        + _u32(GLOBAL_MARKER)
        + b"\xc2\x0c\x00"
    )
    text[0x20 : 0x20 + len(callback)] = callback
    # Worker: xor eax, eax; ret  — does not read g_stage
    text[0x40:0x43] = b"\x31\xc0\xc3"

    data = bytearray(FILE_ALIGNMENT)
    data[GLOBAL_RVA - DATA_RVA : GLOBAL_RVA - DATA_RVA + 4] = b"\x00\x00\x00\x00"
    data[TLS_INDEX_RVA - DATA_RVA : TLS_INDEX_RVA - DATA_RVA + 4] = b"\x00\x00\x00\x00"
    callbacks_off = TLS_CALLBACKS_RVA - DATA_RVA
    data[callbacks_off : callbacks_off + 8] = _u32(_va(TLS_CALLBACK_RVA)) + _u32(0)
    tls_off = TLS_DIRECTORY_RVA - DATA_RVA
    data[tls_off : tls_off + 24] = (
        _u32(_va(GLOBAL_RVA))
        + _u32(_va(GLOBAL_RVA + 4))
        + _u32(_va(TLS_INDEX_RVA))
        + _u32(_va(TLS_CALLBACKS_RVA))
        + _u32(0)
        + _u32(0)
    )
    import_off = IMPORT_DIR_RVA - DATA_RVA
    data[import_off : import_off + 20] = (
        _u32(ILT_RVA)
        + _u32(0)
        + _u32(0)
        + _u32(DLL_NAME_RVA)
        + _u32(IAT_RVA)
    )
    ilt_off = ILT_RVA - DATA_RVA
    iat_off = IAT_RVA - DATA_RVA
    data[ilt_off : ilt_off + 8] = _u32(HINT_NAME_RVA) + _u32(0)
    data[iat_off : iat_off + 8] = _u32(HINT_NAME_RVA) + _u32(0)
    dll_off = DLL_NAME_RVA - DATA_RVA
    data[dll_off : dll_off + 13] = b"KERNEL32.dll\x00"
    hint_off = HINT_NAME_RVA - DATA_RVA
    data[hint_off : hint_off + 2] = _u16(0)
    data[hint_off + 2 : hint_off + 15] = b"CreateThread\x00"

    optional = bytearray(0xE0)
    optional[0:2] = _u16(0x10B)
    optional[16:20] = _u32(ENTRY_RVA)
    optional[20:24] = _u32(TEXT_RVA)
    optional[24:28] = _u32(DATA_RVA)
    optional[28:32] = _u32(IMAGE_BASE)
    optional[32:36] = _u32(SECTION_ALIGNMENT)
    optional[36:40] = _u32(FILE_ALIGNMENT)
    optional[40:42] = _u16(4)
    optional[42:44] = _u16(0)
    optional[48:50] = _u16(4)
    optional[56:60] = _u32(0x3000)
    optional[60:64] = _u32(SIZE_OF_HEADERS)
    optional[68:70] = _u16(3)  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    optional[72:76] = _u32(0x100000)
    optional[76:80] = _u32(0x1000)
    optional[80:84] = _u32(0x100000)
    optional[84:88] = _u32(0x1000)
    optional[92:96] = _u32(16)
    optional[104:112] = _u32(IMPORT_DIR_RVA) + _u32(40)
    optional[168:176] = _u32(TLS_DIRECTORY_RVA) + _u32(24)

    coff = (
        _u16(0x14C)
        + _u16(2)
        + _u32(0)
        + _u32(0)
        + _u32(0)
        + _u16(len(optional))
        + _u16(0x010F)
    )
    text_section = (
        b".text\x00\x00\x00"
        + _u32(len(entry) + 0x40)
        + _u32(TEXT_RVA)
        + _u32(FILE_ALIGNMENT)
        + _u32(TEXT_RAW)
        + _u32(0)
        + _u32(0)
        + _u16(0)
        + _u16(0)
        + _u32(0x60000020)
    )
    data_section = (
        b".data\x00\x00\x00"
        + _u32(0x80)
        + _u32(DATA_RVA)
        + _u32(FILE_ALIGNMENT)
        + _u32(DATA_RAW)
        + _u32(0)
        + _u32(0)
        + _u16(0)
        + _u16(0)
        + _u32(0xC0000040)
    )
    pe_offset = 0x80
    headers = bytearray(SIZE_OF_HEADERS)
    headers[0:2] = b"MZ"
    headers[0x3C:0x40] = _u32(pe_offset)
    headers[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    start = pe_offset + 4
    headers[start : start + len(coff)] = coff
    opt_start = start + len(coff)
    headers[opt_start : opt_start + len(optional)] = optional
    sec_start = opt_start + len(optional)
    headers[sec_start : sec_start + 40] = text_section
    headers[sec_start + 40 : sec_start + 80] = data_section
    return bytes(headers + text + data)


def write_t3_fixture_bin(path: Path | None = None) -> Path:
    target = path or FIXTURE_BIN
    target.write_bytes(t3_callback_missing_consumer_pe())
    return target


def parse_pe_tls_callbacks(data: bytes) -> tuple[dict[str, object], ...]:
    """Read IMAGE_DIRECTORY_ENTRY_TLS callback VAs without Ghidra."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return ()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return ()
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != 0x10B:
        return ()
    image_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    section_offset = optional_offset + optional_size
    sections: list[tuple[int, int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            break
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections.append((virtual_address, max(virtual_size, raw_size), raw_offset))

    def rva_to_offset(rva: int) -> int | None:
        for start, span, raw in sections:
            if start <= rva < start + span:
                translated = raw + (rva - start)
                return translated if translated < len(data) else None
        return None

    directory_base = optional_offset + 96
    tls_rva = struct.unpack_from("<I", data, directory_base + 9 * 8)[0]
    tls_off = rva_to_offset(tls_rva) if tls_rva else None
    if tls_off is None or tls_off + 24 > len(data):
        return ()
    start_raw, end_raw, index_va, callbacks_va = struct.unpack_from("<IIII", data, tls_off)
    callbacks_rva = callbacks_va - image_base if callbacks_va >= image_base else callbacks_va
    callbacks_off = rva_to_offset(callbacks_rva)
    if callbacks_off is None:
        return ()
    found: list[dict[str, object]] = []
    for index in range(8):
        item_off = callbacks_off + index * 4
        if item_off + 4 > len(data):
            break
        callback_va = struct.unpack_from("<I", data, item_off)[0]
        if callback_va == 0:
            break
        callback_rva = callback_va - image_base if callback_va >= image_base else callback_va
        found.append(
            {
                "entry": hex(callback_va),
                "rva": hex(callback_rva),
                "role": "tls_callback",
                "tls_data_start": hex(start_raw),
                "tls_data_end": hex(end_raw),
                "tls_index": hex(index_va),
            }
        )
    return tuple(found)


def t3_seeded_snapshot(*, artifact_id: str = "artifact-t3") -> list[dict[str, object]]:
    """Ghidra-like Evidence for the compiled fixture: callback + missing consumer."""
    pe = t3_callback_missing_consumer_pe()
    tls = parse_pe_tls_callbacks(pe)
    callback_entry = hex(_va(TLS_CALLBACK_RVA))
    worker_entry = hex(_va(WORKER_RVA))
    spawn_entry = hex(_va(ENTRY_RVA))
    global_addr = hex(_va(GLOBAL_RVA))
    return [
        {
            "id": "t3-pe",
            "artifact_id": artifact_id,
            "kind": "pe_structure",
            "nature": "STATIC_OBSERVED",
            "value": {
                "format": "PE32",
                "entry_rva": hex(ENTRY_RVA),
                "image_base": IMAGE_BASE,
                "imports": [{"module": "KERNEL32.dll", "functions": ["CreateThread"]}],
                "tls_callbacks": [dict(item) for item in tls],
            },
            "anchor": {"type": "pe_header"},
        },
        {
            "id": "t3-tls-callback",
            "artifact_id": artifact_id,
            "kind": "tls_callback",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": "tls_callback",
                "entry": callback_entry,
                "role": "tls_callback",
                "global": GLOBAL_NAME,
                "writes": True,
            },
            "anchor": {"function_entry": callback_entry, "role": "tls_callback"},
        },
        {
            "id": "t3-spawn",
            "artifact_id": artifact_id,
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": "entry",
                "entry": spawn_entry,
                "call_targets": [{"target_name": "CreateThread", "from": spawn_entry}],
            },
            "anchor": {"function_entry": spawn_entry},
        },
        {
            "id": "t3-create-call",
            "artifact_id": artifact_id,
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateThread", "from": spawn_entry, "function_entry": spawn_entry},
            "anchor": {"function_entry": spawn_entry, "callsite": spawn_entry},
        },
        {
            "id": "t3-create-trace",
            "artifact_id": artifact_id,
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateThread",
                "function_entry": spawn_entry,
                "resolved": True,
                "arguments": [
                    {"index": 2, "name": "lpStartAddress", "value": worker_entry, "resolved": True},
                    {"index": 3, "name": "lpParameter", "value": "0x0", "resolved": True},
                ],
            },
            "anchor": {"function_entry": spawn_entry},
        },
        {
            "id": "t3-tls-fn",
            "artifact_id": artifact_id,
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": "tls_callback",
                "entry": callback_entry,
                "role": "tls_callback",
            },
            "anchor": {"function_entry": callback_entry, "role": "tls_callback"},
        },
        {
            "id": "t3-worker",
            "artifact_id": artifact_id,
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "worker", "entry": worker_entry},
            "anchor": {"function_entry": worker_entry, "role": "os_thread_start_routine"},
        },
        {
            "id": "t3-global-write",
            "artifact_id": artifact_id,
            "kind": "data_reference",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": GLOBAL_NAME,
                "address": global_addr,
                "access": "write",
                "function_entry": callback_entry,
            },
            "anchor": {"function_entry": callback_entry, "address": global_addr},
        },
    ]


def t3_global_usage_relation(*, artifact_id: str = "artifact-t3") -> dict[str, object]:
    """Relation recovered by TRACE_GLOBAL_USAGE: producer without a consumer."""
    callback_entry = hex(_va(TLS_CALLBACK_RVA))
    global_addr = hex(_va(GLOBAL_RVA))
    return {
        "id": "t3-global-usage",
        "artifact_id": artifact_id,
        "kind": "global_usage",
        "nature": "STATIC_DERIVED",
        "value": {
            "name": GLOBAL_NAME,
            "address": global_addr,
            "writer": "tls_callback",
            "writer_entry": callback_entry,
            "readers": [],
            "role": "producer",
            "writes": True,
            "relation": "producer_to_global",
            "source_role": "producer",
            "output_buffer": GLOBAL_NAME,
        },
        "anchor": {"function_entry": callback_entry, "address": global_addr},
    }


def t3_value_flow_relation(*, artifact_id: str = "artifact-t3") -> dict[str, object]:
    callback_entry = hex(_va(TLS_CALLBACK_RVA))
    global_addr = hex(_va(GLOBAL_RVA))
    return {
        "id": "t3-producer-flow",
        "artifact_id": artifact_id,
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "name": GLOBAL_NAME,
            "relation": "producer_to_global",
            "source_role": "producer",
            "source_function": "tls_callback",
            "output_buffer": GLOBAL_NAME,
            "global": GLOBAL_NAME,
            "address": global_addr,
            "writes": True,
            "consumer": None,
            "readers": [],
        },
        "anchor": {"function_entry": callback_entry, "address": global_addr},
    }
