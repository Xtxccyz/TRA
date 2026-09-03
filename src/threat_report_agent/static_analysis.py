from __future__ import annotations

import ast
import hashlib
import io
import math
import re
import struct
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from threat_report_agent.function_simhash import fingerprint_mnemonics, hamming_distance
from threat_report_agent.semantic_predicates import (
    is_anti_analysis_signal,
    is_injection_call,
    semantic_category,
)

try:  # Optional dependency; PE parsing remains usable without it.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:  # pragma: no cover - exercised only in minimal worker images
    Cs = None
    CS_ARCH_X86 = CS_MODE_32 = None


ANALYSIS_MODULES = (
    "intake",
    "static_triage",
    "decryption",
    "loader",
    "c2_network",
    "anti_analysis",
    "attribution",
)

NETWORK_RE = re.compile(
    r"(?i)(?:https?|wss?)://[^\s\x00<>]{4,}|"
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w.])|"
    r"(?<![\\\w.-])(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|cn|ru|top|xyz|info|biz|io|cc|me|su|in|co|uk)(?![\\\w.-])"
)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])")

CRYPTO_TERMS = {
    "CryptDecrypt",
    "CryptEncrypt",
    "BCryptDecrypt",
    "BCryptEncrypt",
    "AES",
    "RC4",
    "ChaCha20",
    "XOR",
}
LOADER_TERMS = {
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "QueueUserAPC",
    "SetThreadContext",
}
EXECUTION_TERMS = {
    "CreateProcessA",
    "CreateProcessW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "system",
    "popen",
    "subprocess",
    "execve",
    "execvp",
}
ANTI_ANALYSIS_TERMS = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugString",
    "GetTickCount",
    "QueryPerformanceCounter",
    "vmware",
    "vbox",
    "sandbox",
    "wireshark",
    "procmon",
}

WINDOWS_PROCESS_CREATION_FLAGS: tuple[tuple[int, str], ...] = (
    (0x00000001, "DEBUG_PROCESS"),
    (0x00000002, "DEBUG_ONLY_THIS_PROCESS"),
    (0x00000004, "CREATE_SUSPENDED"),
    (0x00000008, "DETACHED_PROCESS"),
    (0x00000010, "CREATE_NEW_CONSOLE"),
    (0x00000200, "CREATE_NEW_PROCESS_GROUP"),
    (0x00000400, "CREATE_UNICODE_ENVIRONMENT"),
    (0x00040000, "CREATE_PROTECTED_PROCESS"),
    (0x00080000, "EXTENDED_STARTUPINFO_PRESENT"),
    (0x00100000, "CREATE_BREAKAWAY_FROM_JOB"),
    (0x08000000, "CREATE_NO_WINDOW"),
)


def decode_windows_process_creation_flags(value: int) -> dict[str, object]:
    """Decode known CreateProcess flags without inferring runtime behavior."""
    flags = int(value) & 0xFFFFFFFF
    names = [name for bit, name in WINDOWS_PROCESS_CREATION_FLAGS if flags & bit]
    known_mask = 0
    for bit, _ in WINDOWS_PROCESS_CREATION_FLAGS:
        known_mask |= bit
    return {
        "value": f"0x{flags:08x}",
        "set_flags": names,
        "unknown_bits": f"0x{flags & ~known_mask:08x}",
        "contains_create_suspended": bool(flags & 0x00000004),
        "contains_create_new_console": bool(flags & 0x00000010),
        "interpretation": (
            "extended startup information is present; parent-process attributes may be supplied"
            if flags & 0x00080000
            else "no extended startup information flag observed"
        ),
        "runtime_effect_proven": False,
    }


@dataclass(frozen=True)
class StaticFact:
    module: str
    kind: str
    value: dict[str, object]
    anchor: dict[str, object]


@dataclass(frozen=True)
class FormatIdentity:
    detected_type: str
    mime_type: str
    source: str


@dataclass(frozen=True)
class ClaimSpec:
    module: str
    subject: str
    action: str
    object: str
    mechanism: str
    condition: str
    statement: str
    fact_indexes: tuple[int, ...]
    confidence: str = "MEDIUM"
    attack_mapping: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class StaticResult:
    detected_type: str
    summary: dict[str, object]
    facts: tuple[StaticFact, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class ScriptResult:
    detected_type: str
    language: str
    functions: tuple[dict[str, object], ...]
    imports: tuple[str, ...]
    import_details: tuple[dict[str, object], ...]
    calls: tuple[dict[str, object], ...]
    indicators: tuple[dict[str, object], ...]
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class DocumentResult:
    detected_type: str
    summary: dict[str, object]
    urls: tuple[dict[str, object], ...]
    javascript: tuple[dict[str, object], ...]
    embedded_objects: tuple[dict[str, object], ...]
    limitations: tuple[str, ...] = ()


def _parse_int_literal(value: str) -> int | None:
    """Parse an assembly immediate without accepting arbitrary expressions."""
    token = value.strip().rstrip(",")
    token = token.replace("0X", "0x")
    try:
        return int(token, 0)
    except ValueError:
        return None


def analyze_xor_decode_window(
    instructions: list[dict[str, object]],
    *,
    max_bytes: int = 4096,
) -> dict[str, object] | None:
    """Extract a bounded XOR-loop hypothesis from an instruction window.

    This is a structural detector, not an emulator. It records the observed
    operands and loop shape so an analyst or a later bounded decoder can verify
    the hypothesis. No arbitrary sample code is executed.
    """
    rows = [item for item in instructions if isinstance(item, dict)]
    xor_rows = [item for item in rows if str(item.get("mnemonic", "")).upper() == "XOR"]
    if len(xor_rows) < 2:
        return None
    # ``xor reg, reg`` with identical operands is the canonical compiler
    # idiom for zeroing a register.  Counting it as a decoder was the source
    # of a large false-positive population in packed and C++ binaries.
    zeroing_rows: list[dict[str, object]] = []
    transform_rows: list[dict[str, object]] = []
    for item in xor_rows:
        match = re.search(
            r"\bXOR\s+([A-Za-z][A-Za-z0-9]*),\s*([A-Za-z][A-Za-z0-9]*)\b",
            str(item.get("text", "")),
            re.I,
        )
        if match and match.group(1).casefold() == match.group(2).casefold():
            zeroing_rows.append(item)
        else:
            transform_rows.append(item)
    # At least one non-zeroing XOR must participate in a bounded loop.  A
    # window containing only register initialisation is not a decode
    # candidate, even when it contains many XOR instructions.
    if not transform_rows:
        return None
    loop_branches = [
        item for item in rows
        if str(item.get("mnemonic", "")).upper() in {"JNZ", "JNE", "JZ", "LOOP", "JL", "JG", "JB", "JA"}
    ]
    # Prefer an actual back-edge when addresses are available.  Synthetic
    # exporter windows often omit addresses; in that case a bounded
    # conditional branch remains the conservative fallback.
    has_back_edge = False
    for branch in loop_branches:
        branch_text = str(branch.get("text") or "")
        target_match = re.search(r"(?:0x)?([0-9A-Fa-f]{2,16})", branch_text)
        source_raw = branch.get("address") or branch.get("from")
        if target_match and source_raw is not None:
            try:
                source_int = int(str(source_raw), 0)
            except ValueError:
                try:
                    source_int = int(str(source_raw), 16)
                except ValueError:
                    continue
            target_int = int(target_match.group(1), 16)
            if target_int <= source_int:
                has_back_edge = True
                break
    if not loop_branches or (any((item.get("address") or item.get("from")) is not None for item in loop_branches) and not has_back_edge):
        # Repeated XORs in straight-line code are commonly register mixing,
        # parity checks, or compiler lowering.  A loop/conditional back-edge
        # is the minimum structural discriminator for a decoder hypothesis.
        return None
    immediate_values: list[int] = []
    register_initializers: dict[str, int] = {}
    xor_register_pairs: list[tuple[str, str]] = []
    for item in rows:
        text = str(item.get("text", ""))
        for token in re.findall(r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]+|-?\d+)(?![A-Za-z0-9_])", text):
            parsed = _parse_int_literal(token)
            if parsed is not None:
                immediate_values.append(parsed)
        initializer = re.search(
            r"\b(?:MOV|LEA)\s+([A-Za-z][A-Za-z0-9]*),\s*(0x[0-9A-Fa-f]+|-?\d+)\b",
            text,
            re.I,
        )
        if initializer:
            parsed = _parse_int_literal(initializer.group(2))
            if parsed is not None:
                register_initializers[initializer.group(1).upper()] = parsed
        xor_match = re.search(
            r"\bXOR\s+([A-Za-z][A-Za-z0-9]*),\s*([A-Za-z][A-Za-z0-9]*)\b",
            text,
            re.I,
        )
        if xor_match:
            xor_register_pairs.append((xor_match.group(1).upper(), xor_match.group(2).upper()))
    counter_updates = [
        str(item.get("text", ""))
        for item in rows
        if str(item.get("mnemonic", "")).upper() in {"INC", "DEC", "ADD", "SUB"}
    ]
    memory_operands = [
        str(item.get("text", ""))
        for item in rows
        if "[" in str(item.get("text", "")) and "]" in str(item.get("text", ""))
    ]
    memory_addresses = sorted({
        int(token, 16)
        for item in rows
        for token in re.findall(r"0x([0-9A-Fa-f]{6,16})", str(item.get("text", "")))
    })
    key_candidates = [
        register_initializers[register]
        for _, register in xor_register_pairs
        if register in register_initializers
    ]
    key_steps = [
        parsed
        for text in counter_updates
        for parsed in (
            _parse_int_literal(match)
            for match in re.findall(r"(?:ADD|SUB)\s+[A-Za-z][A-Za-z0-9]*,\s*(0x[0-9A-Fa-f]+|-?\d+)", text, re.I)
        )
        if parsed is not None
    ]
    # Some loaders use a fixed byte table plus a rolling counter rather than
    # a single XOR key.  Exporter integrations may provide the table as a
    # structured ``key_table``/``key_table_hex`` field on an instruction row;
    # accepting that metadata keeps verification deterministic and bounded.
    key_table_candidates: list[list[int]] = []
    counter_initial: int | None = None
    counter_step: int | None = None
    process_creation_flag_semantics: list[dict[str, object]] = []
    for item in rows:
        raw_table = item.get("key_table")
        if isinstance(raw_table, (list, tuple)):
            table = [int(value) & 0xFF for value in raw_table if isinstance(value, int)]
            if len(table) >= 2:
                key_table_candidates.append(table[:64])
        raw_hex = item.get("key_table_hex")
        if isinstance(raw_hex, str):
            tokens = re.findall(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])", raw_hex)
            if len(tokens) >= 2:
                key_table_candidates.append([int(token, 16) for token in tokens[:64]])
        metadata = item.get("decode_metadata")
        if isinstance(metadata, dict):
            table = metadata.get("key_table")
            if isinstance(table, (list, tuple)):
                parsed_table = [int(value) & 0xFF for value in table if isinstance(value, int)]
                if len(parsed_table) >= 2:
                    key_table_candidates.append(parsed_table[:64])
            if isinstance(metadata.get("counter_initial"), int):
                counter_initial = int(metadata["counter_initial"]) & 0xFF
            if isinstance(metadata.get("counter_step"), int):
                counter_step = int(metadata["counter_step"]) & 0xFF
        process_flags = item.get("process_creation_flags")
        if isinstance(process_flags, int):
            process_creation_flag_semantics.append(decode_windows_process_creation_flags(process_flags))
    if counter_initial is None and immediate_values:
        # The first small initializer is the least-surprising counter seed;
        # this remains a hypothesis and is labelled structural-only below.
        small = [value for value in immediate_values if 0 <= value <= 0xFF]
        if small:
            counter_initial = small[0] & 0xFF
    if counter_step is None and key_steps:
        counter_step = key_steps[0] & 0xFF
    return {
        "algorithm": "xor_loop_candidate",
        "confidence": "MEDIUM" if loop_branches else "LOW",
        "xor_count": len(xor_rows),
        "register_zeroing_xor_count": len(zeroing_rows),
        "data_transform_present": bool(transform_rows),
        "semantic_requirements": {
            "non_zeroing_transform": bool(transform_rows),
            "bounded_loop": bool(loop_branches),
            "state_or_key_signal": bool(key_candidates or key_steps or register_initializers),
            "input_output_buffers": bool(memory_operands),
            "consumer": False,
        },
        "loop_branch_count": len(loop_branches),
        "counter_updates": counter_updates[:16],
        "immediate_constants": list(dict.fromkeys(immediate_values))[:32],
        "memory_operands": memory_operands[:32],
        "memory_addresses": memory_addresses[:32],
        "register_initializers": register_initializers,
        "key_candidates": list(dict.fromkeys(key_candidates))[:8],
        "key_steps": list(dict.fromkeys(key_steps))[:8],
        "key_table_candidates": [list(table) for table in dict.fromkeys(tuple(item) for item in key_table_candidates)][:8],
        "counter_initial": counter_initial,
        "counter_step": counter_step,
        "process_creation_flags_semantics": process_creation_flag_semantics[:8],
        "window_instruction_count": len(rows),
        "max_verification_bytes": max_bytes,
        "verification": "structural_only; decoded output not observed",
    }


def verify_xor_decode_candidate(
    candidate: dict[str, object],
    content: bytes,
    pe_summary: dict[str, object] | None = None,
    *,
    max_bytes: int = 256,
) -> dict[str, object]:
    """Verify a simple XOR hypothesis against file bytes, never executing code."""
    summary = pe_summary or {}
    image_base = int(summary.get("image_base", 0) or 0)
    sections = summary.get("sections", [])
    section_rows = sections if isinstance(sections, list) else []

    def to_offset(address: int) -> int | None:
        rva = address - image_base if image_base and address >= image_base else address
        for section in section_rows:
            if not isinstance(section, dict):
                continue
            start = int(section.get("virtual_address", 0) or 0)
            span = max(int(section.get("virtual_size", 0) or 0), int(section.get("raw_size", 0) or 0))
            if start <= rva < start + span:
                offset = int(section.get("raw_offset", 0) or 0) + (rva - start)
                return offset if 0 <= offset < len(content) else None
        return rva if 0 <= rva < len(content) else None

    addresses = candidate.get("memory_addresses", [])
    addresses = [int(item) for item in addresses if isinstance(item, int)] if isinstance(addresses, list) else []
    keys = candidate.get("key_candidates", [])
    keys = [int(item) & 0xFF for item in keys if isinstance(item, int)] if isinstance(keys, list) else []
    steps = candidate.get("key_steps", [])
    steps = [int(item) & 0xFF for item in steps if isinstance(item, int)] if isinstance(steps, list) else []
    raw_tables = candidate.get("key_table_candidates", candidate.get("key_tables", []))
    tables: list[list[int]] = []
    if isinstance(raw_tables, list):
        for table in raw_tables:
            if isinstance(table, (list, tuple)):
                parsed = [int(item) & 0xFF for item in table if isinstance(item, int)]
                if len(parsed) >= 2:
                    tables.append(parsed[:64])
    raw_table = candidate.get("key_table")
    if isinstance(raw_table, (list, tuple)):
        parsed = [int(item) & 0xFF for item in raw_table if isinstance(item, int)]
        if len(parsed) >= 2:
            tables.append(parsed[:64])
    raw_table_hex = candidate.get("key_table_hex")
    if isinstance(raw_table_hex, str):
        tokens = re.findall(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?![0-9A-Fa-f])", raw_table_hex)
        if len(tokens) >= 2:
            tables.append([int(token, 16) for token in tokens[:64]])
    counter_initial = int(candidate.get("counter_initial", 0) or 0) & 0xFF
    counter_step = int(candidate.get("counter_step", steps[0] if steps else 0) or 0) & 0xFF
    if not addresses or (not keys and not tables):
        return {
            "status": "UNVERIFIED_STATIC_CANDIDATE",
            "reason": "absolute data address or stable XOR key was not recoverable",
        }
    best: dict[str, object] | None = None
    for address in addresses:
        offset = to_offset(address)
        if offset is None:
            continue
        length = min(max_bytes, len(content) - offset)
        if length < 4:
            continue
        candidates: list[tuple[bytes, dict[str, object]]] = []
        if keys:
            key = keys[0]
            step = steps[0] if steps else 0
            candidates.append(
                (
                    bytes(content[offset + index] ^ ((key + index * step) & 0xFF) for index in range(length)),
                    {"initial_key": key, "key_step": step, "formula": "single_key_plus_step"},
                )
            )
        for table in tables:
            candidates.append(
                (
                    bytes(
                        content[offset + index]
                        ^ table[index % len(table)]
                        ^ ((counter_initial + index * counter_step) & 0xFF)
                        for index in range(length)
                    ),
                    {
                        "key_table": table,
                        "counter_initial": counter_initial,
                        "counter_step": counter_step,
                        "formula": "key_table_modulo_xor_counter",
                    },
                )
            )
        for decoded, metadata in candidates:
            printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in decoded) / max(1, length)
            markers = [marker for marker in (b"MZ", b"PE\\x00\\x00", b"http", b"\\\\", b".exe") if marker.lower() in decoded.lower()]
            score = printable + (0.25 if markers else 0.0)
            result = {
                "status": "VERIFIED_STATIC_DATA" if score >= 0.72 else "UNVERIFIED_STATIC_CANDIDATE",
                "file_offset": offset,
                "virtual_address": address,
                **metadata,
                "length": length,
                "printable_ratio": round(printable, 4),
                "markers": [marker.decode("ascii", errors="replace") for marker in markers],
                "decoded_preview": decoded[:128].decode("utf-8", errors="replace"),
            }
            if best is None or float(result["printable_ratio"]) > float(best["printable_ratio"]):
                best = result
    return best or {
        "status": "UNVERIFIED_STATIC_CANDIDATE",
        "reason": "data reference could not be mapped to file bytes",
    }


def correlate_data_references(
    function: dict[str, object],
    strings_by_address: dict[str, str] | None = None,
) -> tuple[dict[str, object], ...]:
    """Associate non-call references with bounded printable data when known."""
    mapping = strings_by_address or {}
    references = function.get("references_from", [])
    if not isinstance(references, list):
        return ()
    rows: list[dict[str, object]] = []
    for reference in references:
        if not isinstance(reference, dict) or "call" in str(reference.get("type", "")).lower():
            continue
        target = str(reference.get("to", ""))
        text = mapping.get(target)
        rows.append({
            "from": reference.get("from"),
            "to": target,
            "reference_type": reference.get("type"),
            "target_name": reference.get("target_name"),
            "resolved_string": text[:512] if isinstance(text, str) else None,
        })
    return tuple(rows[:64])


def resolve_static_data_strings(
    content: bytes,
    addresses: list[str],
    pe_summary: dict[str, object] | None = None,
    *,
    max_length: int = 512,
) -> dict[str, str]:
    """Resolve a bounded set of virtual addresses to printable file strings."""
    summary = pe_summary or {}
    image_base = int(summary.get("image_base", 0) or 0)
    sections = summary.get("sections", [])
    section_rows = sections if isinstance(sections, list) else []
    resolved: dict[str, str] = {}
    for raw_address in addresses[:256]:
        try:
            address = int(str(raw_address), 16)
        except ValueError:
            continue
        rva = address - image_base if image_base and address >= image_base else address
        offset: int | None = None
        for section in section_rows:
            if not isinstance(section, dict):
                continue
            start = int(section.get("virtual_address", 0) or 0)
            span = max(int(section.get("virtual_size", 0) or 0), int(section.get("raw_size", 0) or 0))
            if start <= rva < start + span:
                offset = int(section.get("raw_offset", 0) or 0) + rva - start
                break
        if offset is None and 0 <= rva < len(content):
            offset = rva
        if offset is None or offset < 0 or offset >= len(content):
            continue
        raw = content[offset : min(len(content), offset + max_length)]
        end = raw.find(b"\x00")
        candidate = raw[: end if end >= 0 else len(raw)]
        try:
            text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = candidate.decode("utf-16le").rstrip("\x00")
            except UnicodeDecodeError:
                continue
        if text and sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text) >= 0.8:
            resolved[str(raw_address)] = text[:max_length]
    return resolved


def build_cross_function_chains(
    functions: list[dict[str, object]],
    *,
    max_depth: int = 3,
) -> tuple[dict[str, object], ...]:
    """Build bounded call-graph paths from function-level mechanism signals."""
    by_name = {
        str(item.get("name")): item
        for item in functions
        if isinstance(item, dict) and item.get("name")
    }
    edges: dict[str, list[str]] = {}
    edge_kinds: dict[tuple[str, str], str] = {}
    for name, function in by_name.items():
        targets: list[str] = []
        calls = function.get("references_from", [])
        if isinstance(calls, list):
            for call in calls:
                if not isinstance(call, dict) or "call" not in str(call.get("type", "")).lower():
                    continue
                # Direct calls use target_function/target_name.  Exporters may
                # label pointer/table dispatch as resolved_target or
                # pointer_target; retain those edges while preserving the
                # indirect provenance for analysts.
                target = str(
                    call.get("target_function")
                    or call.get("resolved_target")
                    or call.get("pointer_target")
                    or call.get("global_table_target")
                    or call.get("target_name")
                    or ""
                )
                if target in by_name and target != name:
                    targets.append(target)
                    dispatch_fields = ("resolved_target", "pointer_target", "global_table_target")
                    edge_kinds[(name, target)] = (
                        "indirect_or_global_dispatch"
                        if any(call.get(field) and str(call.get(field)) == target for field in dispatch_fields)
                        else "direct_call"
                    )
        # Static simulation adapters may attach resolved pointer links instead
        # of mutating the original Ghidra call rows.  Consume those links as
        # indirect edges while preserving their provenance.
        pointer_links = function.get("indirect_function_pointer_links") or function.get("indirect_calls") or []
        if isinstance(pointer_links, list):
            for link in pointer_links:
                if not isinstance(link, Mapping):
                    continue
                target = str(link.get("target_function") or link.get("resolved_target") or link.get("consumer_function") or "")
                if target in by_name and target != name:
                    targets.append(target)
                    edge_kinds[(name, target)] = "indirect_or_global_dispatch"
        edges[name] = list(dict.fromkeys(targets))

    def categories(function: dict[str, object]) -> set[str]:
        result: set[str] = set()
        calls = function.get("references_from", [])
        rows = calls if isinstance(calls, list) else []
        for call in rows:
            if not isinstance(call, dict) or "call" not in str(call.get("type", "")).lower():
                continue
            name = str(call.get("target_name") or call.get("target_function") or "")
            category = semantic_category(name)
            if is_injection_call(name):
                result.add("injection")
            if category in {"dynamic_resolution", "network", "execution", "persistence", "file_io", "loader"}:
                result.add("loader" if category == "loader" else category)
            if is_anti_analysis_signal(name):
                result.add("anti_analysis")
        return result

    paths: list[dict[str, object]] = []
    for start, function in by_name.items():
        start_categories = categories(function)
        if not start_categories:
            continue
        queue: list[tuple[str, tuple[str, ...], set[str]]] = [(start, (start,), set(start_categories))]
        while queue:
            current, path, path_categories = queue.pop(0)
            if len(path) >= 2 and len(path_categories) >= 2:
                paths.append({
                    "chain_type": "cross_function_mechanism",
                    "functions": list(path),
                    "categories": sorted(path_categories),
                    "static_only": True,
                    "confidence": "MEDIUM" if len(path_categories) >= 3 else "LOW",
                    "edge_provenance": [
                        {
                            "from": source,
                            "to": target,
                            "kind": edge_kinds.get((source, target), "direct_call"),
                        }
                        for source, target in zip(path, path[1:])
                    ],
                })
            if len(path) >= max_depth:
                continue
            for target in edges.get(current, []):
                if target in path:
                    continue
                target_categories = categories(by_name[target])
                queue.append((target, (*path, target), path_categories | target_categories))
    unique: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, object]] = {}
    for path in paths:
        key = (tuple(path["functions"]), tuple(path["categories"]))
        unique[key] = path
    return tuple(unique.values())


def extract_embedded_bytes(data: bytes, logical_path: str) -> tuple[dict[str, object], ...]:
    """Return bounded carrier payloads without executing active content.

    The parser deliberately exposes bytes separately from the fact model so raw
    payloads never enter JSON tool output or model context implicitly.
    """
    identity = identify_format(data, logical_path)
    extracted: list[dict[str, object]] = []
    if identity.detected_type == "ooxml":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    lowered = info.filename.lower()
                    if info.is_dir() or "/embeddings/" not in lowered:
                        continue
                    if info.file_size > 4 * 1024 * 1024:
                        continue
                    extracted.append(
                        {
                            "internal_path": info.filename,
                            "content": archive.read(info),
                            "kind": "ooxml_embedded_object",
                            "anchor": {"type": "ooxml_path", "internal_path": info.filename},
                        }
                    )
        except (zipfile.BadZipFile, OSError):
            return ()
    elif identity.detected_type == "pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(data), strict=False)
            attachments = getattr(reader, "attachments", {}) or {}
            for name, values in attachments.items():
                payloads = values if isinstance(values, list) else [values]
                for index, payload in enumerate(payloads):
                    if (
                        not isinstance(payload, bytes)
                        or not payload
                        or len(payload) > 4 * 1024 * 1024
                    ):
                        continue
                    extracted.append(
                        {
                            "internal_path": f"{name}-{index}",
                            "content": payload,
                            "kind": "pdf_embedded_file",
                            "anchor": {"type": "pdf_attachment", "name": name},
                        }
                    )
        except Exception:
            # Malformed PDFs remain analyzable as raw bytes; extraction is best effort.
            return ()
    elif identity.detected_type == "ole":
        try:
            import olefile

            with olefile.OleFileIO(io.BytesIO(data)) as compound:
                for path_parts in compound.listdir(streams=True, storages=False):
                    path = "/".join(path_parts)
                    lowered = path.lower()
                    if "vba" in lowered or "macros" in lowered:
                        continue
                    size = compound.get_size(path_parts)
                    if size <= 0 or size > 4 * 1024 * 1024:
                        continue
                    payload = compound.openstream(path_parts).read()
                    if payload:
                        extracted.append(
                            {
                                "internal_path": path,
                                "content": payload,
                                "kind": "ole_embedded_stream",
                                "anchor": {"type": "ole_stream", "internal_path": path},
                            }
                        )
        except (OSError, ValueError, AttributeError):
            return ()
    return tuple(extracted[:100])


SCRIPT_SUFFIX_LANGUAGES = {
    ".js": "javascript",
    ".jse": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".ps1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    ".py": "python",
    ".sh": "shell",
}
SCRIPT_MIME_TYPES = {
    "javascript": "application/javascript",
    "vbscript": "text/vbscript",
    "powershell": "text/x-powershell",
    "batch": "text/x-msdos-batch",
    "python": "text/x-python",
    "shell": "text/x-shellscript",
}


def _decode_text(data: bytes) -> str | None:
    if not data:
        return None
    candidates: list[str] = []
    if data.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append("utf-16")
    else:
        sample = data[:4096]
        even = sample[0::2]
        odd = sample[1::2]
        even_null_ratio = even.count(0) / max(1, len(even))
        odd_null_ratio = odd.count(0) / max(1, len(odd))
        if odd_null_ratio >= 0.3 and even_null_ratio <= 0.05:
            candidates.append("utf-16le")
        elif even_null_ratio >= 0.3 and odd_null_ratio <= 0.05:
            candidates.append("utf-16be")
        candidates.append("utf-8")
    for encoding in candidates:
        try:
            decoded = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if "\x00" in decoded:
            continue
        controls = sum(
            1 for character in decoded if not character.isprintable() and character not in "\r\n\t"
        )
        if controls / max(1, len(decoded)) <= 0.02:
            return decoded
    return None


def _script_language(text: str, logical_path: str) -> tuple[str | None, str | None]:
    suffix_language = SCRIPT_SUFFIX_LANGUAGES.get(PurePosixPath(logical_path).suffix.lower())
    source = text.lstrip("\ufeff")
    first_line = source.splitlines()[0].lower() if source.splitlines() else ""
    if first_line.startswith("#!"):
        if "python" in first_line:
            return "python", "content_signature"
        if "pwsh" in first_line or "powershell" in first_line:
            return "powershell", "content_signature"
        if "node" in first_line or "deno" in first_line:
            return "javascript", "content_signature"
        if any(shell in first_line for shell in ("/sh", "/bash", "/zsh", "/ksh")):
            return "shell", "content_signature"
    signatures = (
        (
            "powershell",
            r"(?im)^\s*(?:#requires\b|param\s*\(|function\s+[\w-]+|"
            r"import-module\b|(?:invoke|new|get|set|start|stop)-[a-z][\w-]+)",
        ),
        (
            "python",
            r"(?m)^\s*(?:async\s+def|def|class)\s+[A-Za-z_]\w*|"
            r"^\s*(?:from\s+[\w.]+\s+import|import\s+[A-Za-z_])",
        ),
        (
            "javascript",
            r"(?m)^\s*(?:function\s+[A-Za-z_$]|(?:const|let|var)\s+[A-Za-z_$]|"
            r"import\s+.+\s+from\s+|(?:module\.)?exports\b)",
        ),
        (
            "vbscript",
            r"(?im)^\s*(?:sub|function|dim|set)\s+[A-Za-z_]|"
            r"\bcreateobject\s*\(",
        ),
        ("batch", r"(?im)^\s*(?:@echo\s+off|setlocal\b|::|rem\s+)"),
    )
    for language, pattern in signatures:
        if re.search(pattern, source):
            return language, "content_signature"
    if suffix_language is not None:
        return suffix_language, "extension_and_text"
    return None, None


def _pdf_anchor(data: bytes, offset: int) -> dict[str, object]:
    object_number = generation = None
    for match in re.finditer(rb"(\d+)\s+(\d+)\s+obj", data[: offset + 1]):
        object_number, generation = int(match.group(1)), int(match.group(2))
    anchor: dict[str, object] = {"type": "pdf_object", "file_offset": offset}
    if object_number is not None:
        anchor.update({"object_number": object_number, "generation": generation})
    return anchor


def analyze_document(data: bytes, logical_path: str) -> DocumentResult:
    identity = identify_format(data, logical_path)
    urls: list[dict[str, object]] = []
    javascript: list[dict[str, object]] = []
    embedded_objects: list[dict[str, object]] = []
    limitations: list[str] = []
    if identity.detected_type == "pdf":
        metadata: dict[str, str] = {}
        for key in ("Title", "Author", "Subject", "Creator", "Producer"):
            match = re.search(rb"/" + key.encode() + rb"\s*\(([^)]*)\)", data)
            if match:
                metadata[key] = match.group(1).decode("utf-8", errors="replace")
        for match in re.finditer(rb"(?:https?|wss?)://[^\s()<>\[\]]+", data, re.I):
            urls.append(
                {
                    "value": match.group().decode("utf-8", errors="replace"),
                    "anchor": _pdf_anchor(data, match.start()),
                }
            )
        for match in re.finditer(rb"/(?:JavaScript|JS)\b", data):
            javascript.append(
                {"kind": "pdf_javascript_action", "anchor": _pdf_anchor(data, match.start())}
            )
        for match in re.finditer(rb"/(?:EmbeddedFile|Filespec)\b", data):
            embedded_objects.append(
                {"kind": "pdf_embedded_object", "anchor": _pdf_anchor(data, match.start())}
            )
        return DocumentResult(
            detected_type="pdf",
            summary={
                "page_count": len(re.findall(rb"/Type\s*/Page\b", data)),
                "metadata": metadata,
            },
            urls=tuple(urls),
            javascript=tuple(javascript),
            embedded_objects=tuple(embedded_objects),
            limitations=tuple(limitations),
        )
    if identity.detected_type == "ooxml":
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            with archive:
                paths = [item.filename for item in archive.infolist() if not item.is_dir()]
        except zipfile.BadZipFile:
            return DocumentResult(
                "ooxml", {"metadata": {}}, (), (), (), ("Invalid OOXML ZIP container.",)
            )
        has_vba = any(path.lower().endswith("vbaproject.bin") for path in paths)
        for path in paths:
            lowered = path.lower()
            if "/embeddings/" in lowered or "oleobject" in lowered:
                embedded_objects.append(
                    {
                        "kind": "ooxml_embedded_object",
                        "internal_path": path,
                        "anchor": {"type": "ooxml_path", "internal_path": path},
                    }
                )
            if lowered.endswith(".rels"):
                with zipfile.ZipFile(io.BytesIO(data)) as relationship_archive:
                    relationships = relationship_archive.read(path)
                for match in re.finditer(rb"https?://[^\s<>]+", relationships, re.I):
                    value = match.group().rstrip(b'"').decode("utf-8", errors="replace")
                    urls.append(
                        {
                            "value": value,
                            "anchor": {
                                "type": "ooxml_path",
                                "internal_path": path,
                                "file_offset": match.start(),
                            },
                        }
                    )
        return DocumentResult(
            "ooxml",
            {"package_entry_count": len(paths), "has_vba": has_vba, "metadata": {}},
            tuple(urls),
            (),
            tuple(embedded_objects),
            (),
        )
    if identity.detected_type == "ole":
        try:
            import olefile

            with olefile.OleFileIO(io.BytesIO(data)) as compound:
                paths = ["/".join(path) for path in compound.listdir()]
        except (OSError, ValueError):
            return DocumentResult(
                "ole", {"metadata": {}}, (), (), (), ("Invalid OLE compound file.",)
            )
        for path in paths:
            lowered = path.lower()
            if "vba" in lowered or "macros" in lowered:
                javascript.append(
                    {
                        "kind": "ole_macro_stream",
                        "anchor": {"type": "ole_stream", "internal_path": path},
                    }
                )
            if "objectpool" in lowered or "ole" in lowered:
                embedded_objects.append(
                    {
                        "kind": "ole_embedded_object",
                        "internal_path": path,
                        "anchor": {"type": "ole_stream", "internal_path": path},
                    }
                )
        return DocumentResult(
            "ole",
            {"stream_count": len(paths), "metadata": {}},
            (),
            tuple(javascript),
            tuple(embedded_objects),
            (),
        )
    return DocumentResult(
        identity.detected_type, {"metadata": {}}, (), (), (), ("Unsupported document carrier.",)
    )


def analyze_script(data: bytes, logical_path: str) -> ScriptResult:
    text = _decode_text(data)
    if text is None:
        return ScriptResult(
            "script",
            "text",
            (),
            (),
            (),
            (),
            (),
            ("Script text encoding could not be decoded safely.",),
        )
    language, _ = _script_language(text, logical_path)
    language = language or "text"
    functions: list[dict[str, object]] = []
    imports: list[str] = []
    import_details: list[dict[str, object]] = []
    calls: list[dict[str, object]] = []
    indicators: list[dict[str, object]] = []
    limitations: list[str] = []
    if language == "python":
        try:
            tree = ast.parse(text, filename=logical_path)
        except SyntaxError as exc:
            limitations.append(f"Python AST parsing incomplete: {exc.msg} at line {exc.lineno}.")
        else:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(
                        {"name": node.name, "line": node.lineno, "end_line": node.end_lineno}
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                        import_details.append(
                            {"name": alias.name, "line": node.lineno, "kind": "import"}
                        )
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.append(module)
                    import_details.append(
                        {"name": module, "line": node.lineno, "kind": "from_import"}
                    )
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr
                    else:
                        name = "<dynamic>"
                    calls.append({"kind": "call", "name": name, "line": node.lineno})
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for match in NETWORK_RE.finditer(node.value):
                        indicators.append(
                            {"kind": "network", "value": match.group(0), "line": node.lineno}
                        )
    if language != "python":
        function_re = re.compile(r"(?i)^\s*(?:function|def|sub)\s+([A-Za-z_][A-Za-z0-9_-]*)")
        call_re = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*\(")
        import_re = re.compile(r"(?i)^\s*(?:import-module|import|require)\s+['\"]?([^'\"\s;]+)")
        for line_number, line in enumerate(text.splitlines(), 1):
            if match := function_re.search(line):
                functions.append({"name": match.group(1), "line": line_number})
            for match in call_re.finditer(line):
                calls.append({"kind": "call", "name": match.group(1), "line": line_number})
            if match := import_re.search(line):
                name = match.group(1)
                imports.append(name)
                import_details.append({"name": name, "line": line_number, "kind": "lexical_import"})
            for match in NETWORK_RE.finditer(line):
                indicators.append({"kind": "network", "value": match.group(0), "line": line_number})
    unique_imports = tuple(dict.fromkeys(imports))
    unique_import_details = tuple(
        {
            (str(item["name"]), int(item["line"]), str(item["kind"])): item
            for item in import_details
        }.values()
    )
    return ScriptResult(
        "script",
        language,
        tuple(functions),
        unique_imports,
        unique_import_details,
        tuple(calls),
        tuple(indicators),
        tuple(limitations),
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _find_crypto_table_candidates(data: bytes) -> tuple[dict[str, object], ...]:
    """Find exact table layouts commonly used by RC4 implementations.

    This is a structural candidate only.  A table in a binary does not prove
    that a particular function uses it or that the sample performs encryption.
    """
    candidates: list[dict[str, object]] = []
    rc4 = bytes(range(256))
    reverse_rc4 = bytes(reversed(range(256)))
    for label, table in (("RC4 ascending S-box candidate", rc4), ("RC4 descending S-box candidate", reverse_rc4)):
        start = 0
        while len(candidates) < 16:
            offset = data.find(table, start)
            if offset < 0:
                break
            candidates.append({"algorithm": "RC4", "pattern": label, "file_offset": offset, "table_size": 256})
            start = offset + 1
    return tuple(candidates)


def function_fuzzy_fingerprint(mnemonics: list[str] | tuple[str, ...]) -> str:
    """Return the finished 64-bit mnemonic 4-gram SimHash fingerprint."""
    return fingerprint_mnemonics(mnemonics)


def fingerprint_hamming_distance(first: str, second: str) -> int:
    return hamming_distance(first, second)


# ---------------------------------------------------------------------------
# Analyst-grade static recovery helpers
# ---------------------------------------------------------------------------

_STRING_URL_RE = re.compile(r"(?i)^(?:https?|wss?)://")
_STRING_REGISTRY_RE = re.compile(r"(?i)^(?:hk(?:ey|lm|cu|cr|u)|software\\|system\\|class)")
_STRING_PATH_RE = re.compile(r"(?i)^(?:[a-z]:[\\/]|\\\\|/tmp/|/var/|%[^%]+%[\\/])")
_STRING_API_RE = re.compile(
    r"(?i)^(?:[a-z][a-z0-9]*(?:a|w)?\.(?:dll|exe)|"
    r"(?:loadlibrary|getprocaddress|virtualalloc|createprocess|winhttp|"
    r"regsetvalue|writefile|readfile|shell|cmd(?:\.exe)?))$"
)
_STRING_COMMAND_RE = re.compile(r"(?i)(?:^|\s)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|rundll32|regsvr32|wscript|cscript)(?:\s|$)")
_STRING_FORMAT_RE = re.compile(r"(?i)(?:%[0-9]*[sdx]|\{[0-9]+\}|json|xml|user-agent|content-type)")
_CODE_BYTE_RE = re.compile(r"^(?:l?\$[a-z0-9.$]+|[.$?@_]{2,}|(?:[0-9a-f]{2}[ .]){2,})$", re.I)


def classify_static_string(
    text: str,
    encoding: str = "ascii",
    *,
    section_name: str | None = None,
    xref_count: int = 0,
) -> dict[str, object]:
    """Classify one extracted string without promoting it to a behavior claim.

    The raw ``string`` evidence contract remains unchanged for compatibility;
    this companion result is intentionally explicit about quality and semantic
    use so investigators can ignore disassembly byte false positives.
    """
    value = str(text or "").strip()
    printable = sum(character.isprintable() for character in value) / max(1, len(value))
    lowered = value.casefold()
    if not value or printable < 0.8 or _CODE_BYTE_RE.fullmatch(value):
        category = "CODE_BYTE_FALSE_POSITIVE"
        confidence = 0.98 if _CODE_BYTE_RE.fullmatch(value) else 0.85
    elif _STRING_URL_RE.search(value) or NETWORK_RE.fullmatch(value):
        category, confidence = "URL", 0.98
    elif _STRING_REGISTRY_RE.search(value):
        category, confidence = "REGISTRY", 0.95
    elif _STRING_PATH_RE.search(value) or "\\" in value and ("." in value or ":" in value):
        category, confidence = "PATH", 0.88
    elif _STRING_COMMAND_RE.search(value):
        category, confidence = "COMMAND", 0.94
    elif _STRING_API_RE.fullmatch(value) or lowered.endswith((".dll", ".exe")):
        category, confidence = "API_NAME", 0.9
    elif _STRING_FORMAT_RE.search(value):
        category, confidence = "FORMAT", 0.82
    elif len(value) >= 6 and any(character.isalpha() for character in value):
        category, confidence = "HUMAN_READABLE", 0.7
    else:
        category, confidence = "UNKNOWN", 0.45
    quality = "HIGH" if category not in {"UNKNOWN", "CODE_BYTE_FALSE_POSITIVE"} and (xref_count or len(value) >= 6) else "LOW"
    return {
        "text": value[:512],
        "encoding": encoding,
        "semantic_class": category,
        "quality": quality,
        "confidence": round(confidence, 3),
        "section": section_name,
        "xref_count": max(0, int(xref_count)),
        "static_only": True,
    }


def cluster_static_seeds(
    evidence: Iterable[Mapping[str, object]],
    *,
    max_clusters: int = 12,
    max_evidence_per_cluster: int = 32,
) -> tuple[dict[str, object], ...]:
    """Aggregate low-level observations into a bounded investigation frontier.

    Imports, strings and xrefs are seeds, not mechanisms.  The returned rows
    carry a concrete question and competing hypotheses so an Agent can select
    discriminating actions instead of creating one candidate per import.
    """
    groups: dict[str, dict[str, object]] = {}
    priority_terms = (
        ("dynamic_api", ("getprocaddress", "loadlibrary", "ldrgetprocedureaddress"), 30),
        ("decode", ("xor", "decode", "decrypt", "encoded", "base64", "rc4"), 25),
        ("network", ("winhttp", "wininet", "socket", "http://", "https://"), 22),
        ("execution", ("createprocess", "shellexecute", "winexec", "virtualalloc"), 22),
        ("persistence", ("regsetvalue", "createservice", "schtasks", "run\\"), 20),
        ("evasion", ("isdebuggerpresent", "etweventwrite", "virtualprotect"), 18),
        ("pe_parser", ("addressOfNames", "numberofnames", "export directory", "mz", "pe\\x00"), 16),
    )
    for row in evidence:
        if not isinstance(row, Mapping) or not row.get("id"):
            continue
        kind = str(row.get("kind", ""))
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        text = f"{kind} {value} {row.get('anchor', '')}".casefold()
        category, score = "generic", 8
        for candidate, terms, weight in priority_terms:
            if any(term.casefold() in text for term in terms):
                category, score = candidate, weight
                break
        function = ""
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        for key in ("function_entry", "entry", "rva"):
            if anchor.get(key):
                function = str(anchor[key])
                break
        identity = f"{category}:{function or str(value.get('api') or value.get('name') or '')[:80].casefold()}"
        group = groups.setdefault(identity, {
            "category": category,
            "priority": score,
            "evidence_ids": [],
            "function": function or None,
            "question": "What input, transformation/control, output, consumer, and side effect are statically linked?",
            "hypotheses": ["intended capability", "benign/library or parser use", "unresolved static boundary"],
        })
        ids = group["evidence_ids"]
        if isinstance(ids, list) and len(ids) < max_evidence_per_cluster:
            ids.append(str(row["id"]))
    ranked = sorted(groups.values(), key=lambda row: (-int(row["priority"]), str(row["category"]), str(row.get("function") or "")))
    output: list[dict[str, object]] = []
    for index, row in enumerate(ranked[:max(1, max_clusters)], 1):
        output.append({"id": f"seed-cluster-{index:03d}", **row, "static_only": True})
    return tuple(output)


def build_investigation_seed_map(
    evidence: Iterable[Mapping[str, object]],
    *,
    max_clusters: int = 12,
) -> dict[str, object]:
    """Return a bounded, serializable seed-map suitable for a model turn."""
    clusters = cluster_static_seeds(evidence, max_clusters=max_clusters)
    high_value = [item for item in clusters if int(item.get("priority", 0)) >= 18]
    return {
        "clusters": [dict(item) for item in clusters],
        "cluster_count": len(clusters),
        "high_value_cluster_count": len(high_value),
        "visible_candidate_budget": max_clusters,
        "static_only": True,
    }


def recognize_hash_algorithm(instructions: Iterable[Mapping[str, object] | str]) -> dict[str, object]:
    """Recognize common export/API hash loops from operation evidence.

    Recognition requires an operation pattern; magic constants alone are not
    treated as proof.  The result is a resolver hypothesis for later matching.
    """
    texts = [str(item.get("text", "")) if isinstance(item, Mapping) else str(item) for item in instructions]
    joined = " ; ".join(texts).casefold()
    constants = sorted({int(token, 0) for token in re.findall(r"(?<![a-z0-9_])(?:0x[0-9a-f]+|\d+)(?![a-z0-9_])", joined)})
    patterns: list[str] = []
    algorithm = "unknown"
    confidence = "LOW"
    if re.search(r"(?:0x0*1505|\b5381\b)", joined) and (re.search(r"0x0*21|\b33\b", joined) or ("imul" in joined and "add" in joined)):
        algorithm, confidence = "DJB2", "HIGH"
        patterns.append("initial=5381; multiply-add by 33")
    elif re.search(r"0x0*1000193|\b16777619\b", joined):
        if "xor" in joined and ("imul" in joined or "multiply" in joined):
            algorithm, confidence = "FNV-1a", "HIGH"
            patterns.append("xor byte; multiply by 0x01000193")
    elif re.search(r"\bror\s+(?:[a-z0-9]+\s*,\s*)?(?:0x0*d|13)\b", joined):
        algorithm, confidence = "ROR13", "MEDIUM"
        patterns.append("rotate-right by 13")
    elif "crc32" in joined or ("polynomial" in joined and "xor" in joined):
        algorithm, confidence = "CRC32", "MEDIUM"
        patterns.append("CRC32/polynomial update")
    elif any(token in joined for token in ("ror", "rol", "imul", "xor")) and "call" in joined:
        algorithm, confidence = "CUSTOM_ROTATE_XOR", "LOW"
        patterns.append("rotate/multiply/xor state update")
    return {
        "algorithm": algorithm,
        "confidence": confidence,
        "constants": constants[:32],
        "evidence": texts[:32],
        "patterns": patterns,
        "static_only": True,
    }


def resolve_export_hashes(
    hash_values: Iterable[str | int],
    exports: Iterable[Mapping[str, object] | str],
    *,
    algorithms: Iterable[str] = ("DJB2", "FNV-1a", "ROR13"),
    module: str | None = None,
) -> tuple[dict[str, object], ...]:
    """Resolve recovered hash constants against a module's named exports.

    Forwarded exports are retained as first-class matches.  A forwarded export
    is still a valid name match, but its implementation lives in another
    module, so callers must not silently present it as a local function.
    """
    names: list[tuple[str, Mapping[str, object] | None]] = []
    for item in exports:
        if isinstance(item, Mapping):
            name = item.get("name")
            if name:
                names.append((str(name), item))
        elif str(item):
            names.append((str(item), None))

    def djb2(name: str) -> int:
        state = 5381
        for byte in name.encode():
            state = ((state << 5) + state + byte) & 0xFFFFFFFF
        return state

    def fnv1a(name: str) -> int:
        state = 0x811C9DC5
        for byte in name.encode():
            state = ((state ^ byte) * 0x01000193) & 0xFFFFFFFF
        return state

    def ror13(name: str) -> int:
        state = 0
        for byte in name.encode():
            state = ((state >> 13) | (state << 19)) & 0xFFFFFFFF
            state = (state + byte) & 0xFFFFFFFF
        return state

    funcs = {"DJB2": djb2, "FNV-1a": fnv1a, "ROR13": ror13}
    output: list[dict[str, object]] = []
    for raw in hash_values:
        try:
            value = int(raw, 0) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            continue
        value &= 0xFFFFFFFF
        matches: list[dict[str, object]] = []
        for algorithm in algorithms:
            func = funcs.get(str(algorithm))
            if func is None:
                continue
            for name, metadata in names:
                if func(name) == value:
                    row: dict[str, object] = {
                        "algorithm": str(algorithm),
                        "name": name,
                        "rva": metadata.get("rva") if metadata else None,
                    }
                    if metadata:
                        forwarder = metadata.get("forwarder")
                        if isinstance(forwarder, str) and forwarder.strip():
                            row["forwarder"] = forwarder.strip()
                            row["forwarded"] = True
                            if "!" in forwarder:
                                target_module, target_name = forwarder.split("!", 1)
                                row["forwarded_module"] = target_module
                                row["forwarded_name"] = target_name
                            elif "." in forwarder:
                                target_module, target_name = forwarder.rsplit(".", 1)
                                row["forwarded_module"] = target_module
                                row["forwarded_name"] = target_name
                    if module:
                        row["module"] = module
                    matches.append(row)
        output.append({"hash": f"0x{value:08x}", "matches": matches[:32], "status": "RESOLVED" if matches else "UNRESOLVED", "static_only": True})
    return tuple(output)


def track_indirect_function_pointers(
    function: Mapping[str, object],
    *,
    max_links: int = 64,
) -> tuple[dict[str, object], ...]:
    """Recover resolver-output -> storage-slot -> indirect-call links.

    This is intentionally an abstract data-flow pass.  It recognises common
    compiler forms (``MOV [slot], RAX`` followed by ``CALL RAX`` or
    ``CALL [slot]``) and never treats a bare indirect call as resolved.
    """
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    calls = [row for row in function.get("references_from", []) if isinstance(row, Mapping)]
    # Headless exporters may place call targets and data references on the
    # function context rather than emitting an instruction window.  Include
    # those typed rows in the resolver/consumer inventory while preserving
    # their original provenance.
    calls.extend(
        row for row in function.get("call_targets", [])
        if isinstance(row, Mapping)
    )
    data_references = [
        row for row in function.get("data_references", [])
        if isinstance(row, Mapping)
    ]
    resolver_calls: list[dict[str, object]] = []
    for row in calls:
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        ref_type = str(row.get("type") or row.get("reference_type") or "").casefold()
        if name and not (name.casefold().startswith("ptr_") and "call" not in ref_type) and any(token in name.casefold() for token in ("getprocaddress", "ldrgetprocedureaddress", "loadlibrary")):
            resolver_calls.append({"name": name, "address": row.get("from") or row.get("address")})
    if not resolver_calls:
        return ()
    slots: dict[str, dict[str, object]] = {}
    loaded_registers: dict[str, str] = {}
    # Ghidra renders imported calls as ``MOV RBX,[PTR_GetProcAddress]; CALL
    # RBX``.  Keep the import-slot label so the indirect call can be tied to
    # the resolver even though its instruction text has no API name.
    import_slot_apis: dict[str, str] = {}
    def _slot_key(value: object) -> str:
        return str(value or "").strip().casefold().removeprefix("0x")

    for row in [*calls, *data_references]:
        target_name = str(row.get("target_name") or "")
        if not target_name:
            continue
        normalized = target_name.casefold()
        if normalized.startswith("ptr_"):
            api = target_name[4:].rsplit("_", 1)[0]
            if api and any(token in api.casefold() for token in ("getprocaddress", "ldrgetprocedureaddress", "loadlibrary")):
                import_slot_apis[_slot_key(row.get("to") or target_name)] = api
                import_slot_apis[_slot_key(target_name)] = api
    last_resolver_call: dict[str, object] | None = None
    returned_pointer_register = "RAX"
    links: list[dict[str, object]] = []
    for index, row in enumerate(instructions):
        text = str(row.get("text") or "").strip()
        address = row.get("address") or row.get("from")
        if re.search(r"(?i)\bCALL\s+(?:\[[^\]]+\]\s*)?(?:GetProcAddress|LdrGetProcedureAddress|LoadLibrary[A-W]?)\b", text):
            api_name = re.search(r"(?i)(GetProcAddress|LdrGetProcedureAddress|LoadLibrary[A-W]?)", text)
            last_resolver_call = {"name": api_name.group(1) if api_name else "dynamic resolver", "address": address}
        load = re.search(r"(?i)\b(?:MOV|LEA)\s+([A-Z][A-Z0-9]*)\s*,\s*(?:qword\s+ptr\s+)?\[([^\]]+)\]", text)
        if load:
            register, slot = load.group(1).upper(), load.group(2).strip()
            loaded_registers[register] = slot
            resolver_name = import_slot_apis.get(_slot_key(slot))
            if resolver_name:
                loaded_registers[f"__resolver__:{register}"] = resolver_name
            continue
        store = re.search(
            r"(?i)\b(?:MOV|XCHG)\s+(?:(?:BYTE|WORD|DWORD|QWORD|XMMWORD)\s+PTR\s+)?\[([^\]]+)\]\s*,\s*([A-Z][A-Z0-9]*)",
            text,
        )
        if store:
            slot, register = store.group(1).strip(), store.group(2).upper()
            prior = last_resolver_call or next((item for item in reversed(resolver_calls) if item.get("address") is not None), None)
            slots[slot.casefold()] = {
                "slot": slot,
                "register": register,
                "resolver": prior,
                "store_address": address,
                "store_index": index,
            }
            continue
        call_match = re.search(r"(?i)\b(CALL|JMP)\s+(?:\[([^\]]+)\]|([A-Z][A-Z0-9]*))", text)
        if not call_match:
            continue
        consumer_kind = "JUMP" if call_match.group(1).upper() == "JMP" else "CALL"
        slot = (call_match.group(2) or "").strip()
        register = (call_match.group(3) or "").upper()
        # Resolve an import-pointer callsite before considering the returned
        # function pointer.  The call itself is the resolver invocation.
        imported_resolver = loaded_registers.get(f"__resolver__:{register}")
        if imported_resolver:
            last_resolver_call = {"name": imported_resolver, "address": address}
        loaded_slot = loaded_registers.get(register, "")
        candidates = [
            item for key, item in slots.items()
            if (slot and key == slot.casefold())
            or (register and item.get("register") == register)
            or (loaded_slot and key == loaded_slot.casefold())
        ]
        for stored in candidates:
            resolver = stored.get("resolver") or {}
            links.append({
                "resolver": resolver.get("name"),
                "resolver_callsite": resolver.get("address"),
                "storage": stored.get("slot"),
                "storage_write": stored.get("store_address"),
                "consumer_callsite": address,
                "consumer": text,
                "consumer_kind": consumer_kind,
                "indirect": True,
                "confidence": "HIGH" if resolver else "MEDIUM",
                "static_only": True,
            })
        # A resolver's return value is commonly consumed directly by ``JMP
        # RAX`` (or ``CALL RAX``) after being stored in a global slot.  This is
        # a valid returned-pointer consumer even when no second load exists.
        if register == returned_pointer_register and last_resolver_call:
            stored_slots = [
                item for item in slots.values()
                if item.get("register") == returned_pointer_register
                and int(item.get("store_index", -1)) <= index
            ]
            if stored_slots:
                for stored in stored_slots:
                    links.append({
                        "resolver": last_resolver_call.get("name"),
                        "resolver_callsite": last_resolver_call.get("address"),
                        "storage": stored.get("slot"),
                        "storage_write": stored.get("store_address"),
                        "consumer_callsite": address,
                        "consumer": text,
                        "consumer_kind": consumer_kind,
                        "indirect": True,
                        "confidence": "HIGH",
                        "static_only": True,
                    })
    # Context-level fallback for stripped/partial Ghidra exports.  Require a
    # resolver call, a writable global/pointer slot, and an explicitly typed
    # COMPUTED_CALL that targets that slot.  A slot write without a consumer is
    # intentionally left unresolved; imports and table bytes alone are not a
    # function-pointer call proof.
    data_references = [
        row for row in function.get("data_references", [])
        if isinstance(row, Mapping)
    ]
    stores: list[dict[str, object]] = []
    for row in data_references:
        ref_type = str(row.get("type") or row.get("reference_type") or "").upper()
        if "WRITE" not in ref_type:
            continue
        slot = str(row.get("target_name") or row.get("to") or "").strip()
        if not slot:
            continue
        stores.append({
            "slot": slot,
            "store_address": row.get("from") or row.get("address"),
            "row": row,
        })
    computed_calls = [
        row for row in [*calls, *data_references]
        if str(row.get("type") or row.get("reference_type") or "").upper() == "COMPUTED_CALL"
    ]
    resolver_candidates = [
        item for item in resolver_calls
        if item.get("address") is not None
    ]
    for store in stores:
        slot_casefold = str(store["slot"]).casefold()
        consumers = [
            row for row in computed_calls
            if slot_casefold in str(
                row.get("target_name") or row.get("target_function") or row.get("to") or ""
            ).casefold()
        ]
        if not consumers:
            continue
        resolver = resolver_candidates[-1] if resolver_candidates else {}
        for consumer in consumers:
            links.append({
                "resolver": resolver.get("name"),
                "resolver_callsite": resolver.get("address"),
                "storage": store["slot"],
                "storage_write": store["store_address"],
                "consumer_callsite": consumer.get("from") or consumer.get("address"),
                "consumer": consumer.get("target_name") or consumer.get("target_function") or consumer.get("to"),
                "indirect": True,
                "confidence": "MEDIUM" if resolver else "LOW",
                "evidence_source": "function_context_data_references",
                "static_only": True,
            })
    # Preserve deterministic order and avoid duplicate rows when a future
    # exporter emits both instruction and context-level representations.
    deduped: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for link in links:
        key = (
            link.get("resolver_callsite"), link.get("storage"),
            link.get("consumer_callsite"), link.get("consumer"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(link)
    return tuple(deduped[:max_links])


def build_pcode_slice(
    function: Mapping[str, object],
    *,
    source_evidence_ids: Iterable[str] = (),
    max_operations: int = 64,
) -> dict[str, object]:
    """Produce a compact semantic P-code-like slice for analyst context.

    The Ghidra exporter currently exposes instruction rows rather than raw
    P-code.  This adapter keeps the source anchor and extracts only data-flow,
    branch, memory and call operations that are useful for mechanism recovery.
    """
    operations: list[dict[str, object]] = []
    conditions: list[dict[str, object]] = []
    critical: list[dict[str, object]] = []
    native_pcode = function.get("pcode_ops")
    if isinstance(native_pcode, list) and native_pcode:
        for index, row in enumerate(native_pcode[:max_operations]):
            if not isinstance(row, Mapping):
                continue
            operation = str(row.get("operation") or row.get("opcode") or "OTHER")
            upper = operation.upper()
            op = (
                "BRANCH_CONDITION" if any(token in upper for token in ("BRANCH", "CBRANCH", "INT_"))
                else "CALL" if "CALL" in upper
                else "MEMORY_ACCESS" if any(token in upper for token in ("LOAD", "STORE"))
                else "ARITHMETIC" if any(token in upper for token in ("INT_", "PTRADD", "SUBPIECE", "PIECE"))
                else "DATA_FLOW"
            )
            item = {
                "op": op,
                "address": row.get("address"),
                "operation": operation,
                "opcode": row.get("opcode"),
                "output": row.get("output"),
                "inputs": row.get("inputs", []),
                "index": index,
                "static_only": True,
            }
            operations.append(item)
            if op in {"CALL", "BRANCH_CONDITION", "MEMORY_ACCESS", "ARITHMETIC"}:
                critical.append(item)
            if op == "BRANCH_CONDITION":
                conditions.append({"address": row.get("address"), "expression": operation, "index": index})
        representation = "ghidra_native_pcode"
    else:
        representation = "instruction_derived"
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    for index, row in enumerate(instructions[:max_operations] if not operations else []):
        text = str(row.get("text") or row.get("mnemonic") or "").strip()
        upper = text.upper()
        if not text:
            continue
        op = "OTHER"
        if re.match(r"^(?:CMP|TEST|J[A-Z]+|LOOP)\b", upper):
            op = "BRANCH_CONDITION"
            conditions.append({"address": row.get("address"), "expression": text, "index": index})
        elif re.match(r"^CALL\b", upper):
            op = "CALL"
        elif any(token in upper for token in ("MOV ", "LEA ", "PUSH ", "POP ")):
            op = "DATA_FLOW"
        elif any(token in upper for token in ("XOR ", "ADD ", "SUB ", "IMUL ", "ROL ", "ROR ", "SHL ", "SHR ")):
            op = "ARITHMETIC"
        elif "[" in text and "]" in text:
            op = "MEMORY_ACCESS"
        item = {"op": op, "address": row.get("address"), "text": text, "index": index, "static_only": True}
        operations.append(item)
        if op in {"CALL", "BRANCH_CONDITION", "MEMORY_ACCESS", "ARITHMETIC"}:
            critical.append(item)
    call_rows = [
        row for row in function.get("references_from", [])
        if isinstance(row, Mapping)
        and (
            "call" in str(row.get("type", "")).casefold()
            or row.get("target_name")
            or row.get("target_function")
            or row.get("api")
        )
    ]
    sinks = [
        {"api": str(row.get("target_name") or row.get("target_function") or row.get("api") or ""), "callsite": row.get("from") or row.get("address"), "static_only": True}
        for row in call_rows[:32]
    ]
    source = {
        "function": function.get("name"),
        "entry": function.get("entry") or function.get("entry_rva"),
        "source_evidence_ids": list(source_evidence_ids)[:24],
    }
    return {
        "kind": "pcode_slice",
        "representation": representation,
        "source": source,
        "operations": operations,
        "critical_operations": critical[:max_operations],
        "conditions": conditions[:32],
        "sinks": sinks,
        "bounded": len(instructions) > max_operations,
        "static_only": True,
    }


# Descriptive aliases used by action executors and external integrations.
# Keeping them aliases (rather than wrappers) preserves one deterministic
# implementation and makes the public static-semantics surface discoverable.
extract_pcode_slice = build_pcode_slice
recover_indirect_function_pointers = track_indirect_function_pointers


def trace_static_api_arguments(
    function: Mapping[str, object],
    api: str,
    argument_index: int | None = None,
) -> tuple[dict[str, object], ...]:
    """Recover simple API argument producers from an ordered instruction view."""
    target = str(api).casefold()
    rows = function.get("references_from", [])
    calls = [row for row in rows if isinstance(row, Mapping) and target in str(row.get("target_name") or row.get("target_function") or row.get("api") or "").casefold()]
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    result: list[dict[str, object]] = []
    # Windows x64 register ABI.  x86 callers use a push-based stack ABI; both
    # are normalised to argument_index so downstream consumers need no ABI
    # specific branching.
    registers = ("rcx", "rdx", "r8", "r9")
    x86_registers = {"ecx", "edx", "r8d", "r9d"}
    architecture = str(function.get("architecture") or function.get("calling_convention") or "").casefold()
    is_x86 = (any(token in architecture for token in ("x86", "i386", "32")) and "64" not in architecture) or (
        not architecture and any(re.match(r"(?i)^PUSH\s+", str(row.get("text") or "")) for row in instructions)
    )
    for call in calls:
        callsite = str(call.get("from") or call.get("address") or "")
        call_index = len(instructions)
        for index, instruction in enumerate(instructions):
            if callsite and callsite.casefold() in str(instruction.get("address") or instruction.get("from") or "").casefold():
                call_index = index
                break
        tracked: dict[str, dict[str, object]] = {}
        pushed: list[dict[str, object]] = []
        last_call: str | None = None
        for instruction in instructions[:call_index]:
            text = str(instruction.get("text", "")).strip()
            push = re.match(r"(?i)PUSH\s+(.+)$", text)
            if push:
                source = push.group(1).strip()
                if re.fullmatch(r"(?:0x[0-9a-f]+|-?\d+)", source, re.I):
                    pushed.append({"source_kind": "constant", "value": source})
                elif source.startswith("[") and source.endswith("]"):
                    pushed.append({"source_kind": "global", "value": source[1:-1]})
                elif source.startswith(('"', "'")):
                    pushed.append({"source_kind": "string", "value": source.strip("\"'")})
                else:
                    pushed.append({"source_kind": "unknown", "value": source})
                continue
            call_match = re.match(r"(?i)CALL\s+(.+)$", text)
            if call_match:
                last_call = call_match.group(1).strip()
                continue
            match = re.match(r"(?i)(?:mov|lea)\s+([a-z][a-z0-9]*),\s*(.+)$", text)
            if not match:
                continue
            register, source = match.group(1).casefold(), match.group(2).strip()
            if register not in set(registers) | x86_registers | {"eax", "ebx", "ecx", "edx"}:
                continue
            if re.fullmatch(r"(?:0x[0-9a-f]+|-?\d+)", source, re.I):
                tracked[register] = {"source_kind": "constant", "value": source}
            elif source.startswith("[") and source.endswith("]"):
                tracked[register] = {"source_kind": "global", "value": source[1:-1]}
            elif source.startswith('"') or source.startswith("'"):
                tracked[register] = {"source_kind": "string", "value": source.strip("\"'")}
            elif register in {"eax", "rax"} and last_call:
                tracked[register] = {"source_kind": "function_return", "value": last_call}
            else:
                tracked[register] = {"source_kind": "register_or_expression", "value": source}
        indexes = (argument_index,) if argument_index is not None else tuple(range(4))
        for index in indexes:
            register = registers[index] if 0 <= index < len(registers) else None
            if is_x86 and pushed and 0 <= index < len(pushed):
                # cdecl/stdcall push arguments right-to-left; the last push is
                # therefore argument 0 at the call site.
                value = list(reversed(pushed))[index]
            else:
                # Accept 32-bit aliases when Ghidra labels a x64 instruction
                # with an E-register, and expose explicit unknown rows.
                value = tracked.get(register or "") or tracked.get((register or "").replace("r", "e", 1))
            result.append({
                "api": api,
                "callsite": callsite,
                "argument_index": index,
                **(value or {"source_kind": "unknown", "value": None}),
                "confidence": "HIGH" if value and value.get("source_kind") in {"constant", "string", "global", "function_return"} else "LOW",
                "function": function.get("name"),
                "static_only": True,
            })
    return tuple(result)


def classify_pe_semantics(
    function: Mapping[str, object],
    pe_summary: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Classify a PE-oriented function using field access and output signals."""
    calls = function.get("references_from", [])
    call_names = [str(row.get("target_name") or row.get("target_function") or row.get("api") or "") for row in calls if isinstance(row, Mapping)]
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    texts = [str(row.get("text", "")) for row in instructions]
    joined = " ; ".join([*call_names, *texts]).casefold()
    hash_info = recognize_hash_algorithm(instructions)
    hash_info = {**hash_info, "resolver_function": function.get("name"), "resolver_entry": function.get("entry") or function.get("entry_rva")}
    export_resolution: tuple[dict[str, object], ...] = ()
    if isinstance(pe_summary, Mapping):
        raw_exports = pe_summary.get("exports")
        export_rows = raw_exports.get("functions", []) if isinstance(raw_exports, Mapping) else []
        if isinstance(export_rows, list) and hash_info.get("algorithm") in {"DJB2", "FNV-1a", "ROR13"}:
            export_resolution = resolve_export_hashes(
                [value for value in hash_info.get("constants", []) if isinstance(value, int)],
                [item for item in export_rows if isinstance(item, Mapping)],
                algorithms=(str(hash_info["algorithm"]),),
                module=str(raw_exports.get("module") or "") if isinstance(raw_exports, Mapping) else None,
            )
    fields = [token for token in ("numberofnames", "addressofnames", "addressofnameordinals", "addressoffunctions", "export directory", "export directory rva") if token in joined]
    looped = bool(re.search(r"\b(?:cmp|test|jnz|jne|loop)\b", joined))
    roles: list[dict[str, object]] = []
    if len(fields) >= 2 and looped:
        evidence = [*fields, *hash_info.get("patterns", [])]
        roles.append({"role": "EXPORT_RESOLVER", "confidence": "HIGH" if len(fields) >= 4 and hash_info["algorithm"] != "unknown" else "MEDIUM", "evidence": evidence[:16], "missing": ["resolved export consumer"], "rationale": "export name/ordinal/function tables are iterated; hash recognition is" + (" present" if hash_info["algorithm"] != "unknown" else " not present"), "static_only": True})
    # Import resolver: walking the IAT/ILT or resolving import names is a
    # distinct role from parsing an export table.  Require table/slot access or
    # an explicit resolver call, never a lone imported API name.
    import_features = [
        token for token in (
            "import directory", "originalfirstthunk", "firstthunk", "iat", "ilt",
            "address of iat", "loadlibrary", "getprocaddress", "getimportaddress",
            "resolve imports", "import name",
        ) if token in joined
    ]
    if len(set(import_features)) >= 2:
        roles.append({
            "role": "IMPORT_RESOLVER",
            "confidence": "HIGH" if len(set(import_features)) >= 3 else "MEDIUM",
            "evidence": import_features[:16],
            "missing": ["resolved import consumer"],
            "rationale": "IAT/ILT fields or dynamic import APIs are combined with a table/slot access",
            "static_only": True,
        })
    # Manual mapping needs an ordered payload path: allocate/write image bytes,
    # apply relocations/imports, then transfer execution.  Header field names
    # and VirtualProtect alone are common in validators and are insufficient.
    manual_features = [token for token in ("section table", "virtualalloc", "virtualprotect", "relocation", "basereloc", "writeprocessmemory", "memcpy", "rwx", "entrypoint", "call entrypoint", "createthread", "createremotethread", "setthreadcontext") if token in joined]
    has_write = any(token in joined for token in ("writeprocessmemory", "memcpy", "memmove", "copy section", "write image"))
    has_map = any(token in joined for token in ("section table", "relocation", "basereloc", "import directory", "map image"))
    has_transfer = any(token in joined for token in ("call entrypoint", "createthread", "createremotethread", "setthreadcontext", "jmp entrypoint"))
    if "virtualalloc" in joined and has_write and has_map and has_transfer:
        roles.append({"role": "MANUAL_MAPPER", "confidence": "HIGH", "evidence": manual_features[:16], "missing": [], "rationale": "ordered allocation, image write, relocation/import preparation, and execution transfer signals co-occur", "static_only": True})
    resource_features = [token for token in ("findresource", "loadresource", "lockresource", "sizeofresource", "resource directory") if token in joined]
    if len(set(resource_features)) >= 2:
        roles.append({"role": "RESOURCE_PARSER", "confidence": "MEDIUM", "evidence": resource_features[:16], "missing": ["embedded payload consumer"], "rationale": "resource directory APIs/fields are used", "static_only": True})
    if any(token in joined for token in ("mz", "pe\\x00\\x00", "dos header", "nt headers")) and not roles:
        roles.append({"role": "PE_VALIDATOR", "confidence": "LOW", "evidence": ["MZ/PE header validation"], "missing": ["field iteration output", "downstream consumer"], "rationale": "header identity alone supports validation only", "static_only": True})
    if not roles:
        roles.append({"role": "UNKNOWN_PE_ROLE", "confidence": "LOW", "evidence": [], "missing": ["discriminating PE field accesses"], "rationale": "insufficient static evidence", "static_only": True})
    for role in roles:
        role["hash_resolver"] = hash_info
        if export_resolution:
            role["resolved_exports"] = list(export_resolution)
    return tuple(roles)


def identify_format(data: bytes, logical_path: str) -> FormatIdentity:
    if data.startswith(b"MZ"):
        return FormatIdentity("pe", "application/vnd.microsoft.portable-executable", "magic")
    if data.startswith(b"\x7fELF"):
        return FormatIdentity("elf", "application/x-elf", "magic")
    if data.startswith(b"%PDF-"):
        return FormatIdentity("pdf", "application/pdf", "magic")
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist())
        except zipfile.BadZipFile:
            names = set()
        is_ooxml = "[Content_Types].xml" in names and any(
            name.startswith(("word/", "xl/", "ppt/")) for name in names
        )
        if is_ooxml:
            return FormatIdentity(
                "ooxml",
                "application/vnd.openxmlformats-officedocument",
                "magic_and_container",
            )
        return FormatIdentity("zip", "application/zip", "magic")
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return FormatIdentity("ole", "application/x-ole-storage", "magic")
    text = _decode_text(data)
    if text is not None:
        language, source = _script_language(text, logical_path)
        if language is not None:
            return FormatIdentity(
                "script",
                SCRIPT_MIME_TYPES[language],
                source or "content_signature",
            )
        return FormatIdentity("text", "text/plain", "content_heuristic")
    return FormatIdentity("binary", "application/octet-stream", "fallback")


def detect_type(data: bytes, logical_path: str) -> str:
    return identify_format(data, logical_path).detected_type


def _extract_strings(data: bytes, minimum: int = 4, limit: int = 5000) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    wide_pattern = re.compile(rb"(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){%d,}" % minimum)
    for match in ascii_pattern.finditer(data):
        results.append(
            {"text": match.group().decode("ascii"), "offset": match.start(), "encoding": "ascii"}
        )
        if len(results) >= limit:
            return results
    for match in wide_pattern.finditer(data):
        results.append(
            {
                "text": match.group().decode("utf-16le"),
                "offset": match.start(),
                "encoding": "utf-16le",
            }
        )
        if len(results) >= limit:
            break
    return sorted(results, key=lambda item: int(item["offset"]))


def _read_c_string(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", errors="replace")


def _parse_rich_header(data: bytes, pe_offset: int) -> dict[str, object]:
    """Decode the bounded Rich header metadata without treating it as attribution."""
    end = min(max(pe_offset, 0), len(data))
    rich_offset = data.rfind(b"Rich", 0, end)
    if rich_offset < 4 or rich_offset + 8 > end:
        return {}
    xor_key = struct.unpack_from("<I", data, rich_offset + 4)[0]
    dans_offset = data.find(b"DanS", 0, rich_offset)
    if dans_offset < 0:
        return {"offset": rich_offset, "xor_key": f"0x{xor_key:08x}", "entries": []}
    cursor = dans_offset + 16
    entries: list[dict[str, int]] = []
    while cursor + 8 <= rich_offset and len(entries) < 128:
        comp_id, count = struct.unpack_from("<II", data, cursor)
        comp_id ^= xor_key
        count ^= xor_key
        entries.append(
            {
                "product_id": (comp_id >> 16) & 0xFFFF,
                "build_id": comp_id & 0xFFFF,
                "count": count,
            }
        )
        cursor += 8
    return {
        "offset": rich_offset,
        "xor_key": f"0x{xor_key:08x}",
        "entries": entries,
    }


def _parse_debug_directory(
    data: bytes,
    sections: list[dict[str, object]],
    debug_rva: int,
    debug_size: int,
    rva_to_offset,
) -> dict[str, object]:
    """Extract CodeView/PDB metadata as a file-backed build observation."""
    if not debug_rva or not debug_size:
        return {"entries": []}
    directory_offset = rva_to_offset(debug_rva)
    if directory_offset is None:
        return {"entries": []}
    entries: list[dict[str, object]] = []
    for index in range(min(debug_size // 28, 32)):
        offset = directory_offset + index * 28
        if offset + 28 > len(data):
            break
        characteristics, timestamp, major, minor, type_id, size, address, pointer = struct.unpack_from(
            "<IIHHIIII", data, offset
        )
        row: dict[str, object] = {
            "type": type_id,
            "timestamp": timestamp,
            "major": major,
            "minor": minor,
            "size": size,
            "file_offset": offset,
        }
        payload_offset = pointer if pointer and pointer < len(data) else rva_to_offset(address)
        if type_id == 2 and payload_offset is not None and payload_offset + 24 <= len(data):
            if data[payload_offset : payload_offset + 4] == b"RSDS":
                pdb_offset = payload_offset + 24
                row["pdb_path"] = _read_c_string(data, pdb_offset, limit=1024)
                row["codeview"] = "RSDS"
        entries.append(row)
    return {"entries": entries}


def _parse_pe(data: bytes, logical_path: str = "") -> dict[str, object]:
    if len(data) < 0x40:
        raise ValueError("truncated DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")
    machine, section_count, timestamp = struct.unpack_from("<HHI", data, pe_offset + 4)
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if optional_offset + optional_size > len(data):
        raise ValueError("truncated optional header")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic not in {0x10B, 0x20B}:
        raise ValueError("unsupported optional header")
    pe_plus = magic == 0x20B
    entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
    image_base_offset = optional_offset + (24 if pe_plus else 28)
    image_base = struct.unpack_from("<Q" if pe_plus else "<I", data, image_base_offset)[0]
    section_offset = optional_offset + optional_size
    sections: list[dict[str, object]] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            raise ValueError("truncated section table")
        name = data[offset : offset + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        raw = data[raw_offset : raw_offset + raw_size] if raw_offset < len(data) else b""
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "entropy": round(_entropy(raw), 3),
            }
        )

    def rva_to_offset(rva: int) -> int | None:
        for section in sections:
            start = int(section["virtual_address"])
            span = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + span:
                translated = int(section["raw_offset"]) + (rva - start)
                return translated if translated < len(data) else None
        return rva if rva < len(data) else None

    directory_base = optional_offset + (112 if pe_plus else 96)
    import_rva = 0
    resource_rva = resource_size = 0
    if directory_base + 16 <= optional_offset + optional_size:
        import_rva = struct.unpack_from("<I", data, directory_base + 8)[0]
        resource_rva, resource_size = struct.unpack_from("<II", data, directory_base + 16)
    imports: list[dict[str, object]] = []
    descriptor_offset = rva_to_offset(import_rva) if import_rva else None
    if descriptor_offset is not None:
        for descriptor_index in range(512):
            current = descriptor_offset + descriptor_index * 20
            if current + 20 > len(data):
                break
            original_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, current
            )
            if not any((original_thunk, name_rva, first_thunk)):
                break
            name_offset = rva_to_offset(name_rva)
            module = _read_c_string(data, name_offset) if name_offset is not None else ""
            thunk_rva = original_thunk or first_thunk
            thunk_offset = rva_to_offset(thunk_rva)
            functions: list[str] = []
            if thunk_offset is not None:
                width = 8 if pe_plus else 4
                ordinal_mask = 1 << (63 if pe_plus else 31)
                unpack = "<Q" if pe_plus else "<I"
                for thunk_index in range(4096):
                    item_offset = thunk_offset + thunk_index * width
                    if item_offset + width > len(data):
                        break
                    value = struct.unpack_from(unpack, data, item_offset)[0]
                    if value == 0:
                        break
                    if value & ordinal_mask:
                        functions.append(f"ordinal:{value & 0xFFFF}")
                    else:
                        hint_name_offset = rva_to_offset(value)
                        if hint_name_offset is not None:
                            function_name = _read_c_string(data, hint_name_offset + 2)
                            if function_name:
                                functions.append(function_name)
            imports.append(
                {
                    "module": module,
                    "functions": functions,
                    "thunk_rva": first_thunk,
                    "thunk_width": 8 if pe_plus else 4,
                }
            )
    export_rva = export_size = 0
    if directory_base + 8 <= optional_offset + optional_size:
        export_rva, export_size = struct.unpack_from("<II", data, directory_base)
    exports: dict[str, object] = {
        "module": logical_path,
        "names": [],
        "functions": [],
        "ordinal_base": 0,
    }
    export_offset = rva_to_offset(export_rva) if export_rva else None
    if export_offset is not None and export_offset + 40 <= len(data):
        (
            _,
            _,
            _,
            _,
            name_rva,
            ordinal_base,
            function_count,
            name_count,
            functions_rva,
            names_rva,
            ordinals_rva,
        ) = struct.unpack_from("<IIHHIIIIIII", data, export_offset)
        exports["ordinal_base"] = ordinal_base
        module_offset = rva_to_offset(name_rva)
        module_name = (
            _read_c_string(data, module_offset) if module_offset is not None else logical_path
        )
        if module_name:
            exports["module"] = module_name
        function_offset = rva_to_offset(functions_rva)
        names_offset = rva_to_offset(names_rva)
        ordinals_offset = rva_to_offset(ordinals_rva)
        named_by_index: dict[int, str] = {}
        if names_offset is not None and ordinals_offset is not None:
            for index in range(min(name_count, 4096)):
                name_rva_item = struct.unpack_from("<I", data, names_offset + index * 4)[0]
                ordinal_index = struct.unpack_from("<H", data, ordinals_offset + index * 2)[0]
                name_offset = rva_to_offset(name_rva_item)
                if name_offset is not None:
                    named_by_index[ordinal_index] = _read_c_string(data, name_offset)
        functions: list[dict[str, object]] = []
        if function_offset is not None:
            for index in range(min(function_count, 4096)):
                rva = struct.unpack_from("<I", data, function_offset + index * 4)[0]
                item: dict[str, object] = {
                    "name": named_by_index.get(index),
                    "ordinal": ordinal_base + index,
                    "rva": rva,
                    "anchor": {"type": "rva", "rva": rva},
                }
                if export_rva <= rva < export_rva + export_size:
                    item["forwarder"] = _read_c_string(data, rva_to_offset(rva) or 0)
                functions.append(item)
        exports["names"] = [named_by_index[index] for index in sorted(named_by_index)]
        exports["functions"] = functions
    resources = _parse_pe_resources(data, sections, resource_rva, resource_size)
    code_signals = _scan_x86_code(data, sections, image_base, imports)
    dll_characteristics_offset = optional_offset + 70
    dll_characteristics = (
        struct.unpack_from("<H", data, dll_characteristics_offset)[0]
        if dll_characteristics_offset + 2 <= optional_offset + optional_size
        else 0
    )
    directory_count_offset = optional_offset + (108 if pe_plus else 92)
    directory_count = (
        struct.unpack_from("<I", data, directory_count_offset)[0]
        if directory_count_offset + 4 <= optional_offset + optional_size
        else 0
    )
    debug_rva = debug_size = 0
    if directory_count > 6 and directory_base + 56 <= optional_offset + optional_size:
        debug_rva, debug_size = struct.unpack_from("<II", data, directory_base + 48)
    debug_directory = _parse_debug_directory(
        data, sections, debug_rva, debug_size, rva_to_offset
    )
    rich_header = _parse_rich_header(data, pe_offset)
    subsystem_offset = optional_offset + (68 if pe_plus else 68)
    subsystem = (
        struct.unpack_from("<H", data, subsystem_offset)[0]
        if subsystem_offset + 2 <= optional_offset + optional_size
        else 0
    )
    checksum_offset = optional_offset + 64
    checksum = (
        struct.unpack_from("<I", data, checksum_offset)[0]
        if checksum_offset + 4 <= optional_offset + optional_size
        else 0
    )
    return {
        "format": "PE32+" if pe_plus else "PE32",
        "machine": f"0x{machine:04x}",
        "timestamp": timestamp,
        "entry_rva": entry_rva,
        "image_base": image_base,
        "subsystem": subsystem,
        "checksum": checksum,
        "dll_characteristics": dll_characteristics,
        "dll_characteristics_flags": {
            "dynamic_base": bool(dll_characteristics & 0x40),
            "nx_compat": bool(dll_characteristics & 0x100),
            "no_seh": bool(dll_characteristics & 0x400),
            "terminal_server_aware": bool(dll_characteristics & 0x8000),
        },
        "rich_header": rich_header,
        "debug_directory": debug_directory,
        "pdb_path": next(
            (
                str(item.get("pdb_path"))
                for item in debug_directory.get("entries", [])
                if isinstance(item, dict) and item.get("pdb_path")
            ),
            None,
        ),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "resources": resources,
        "code_signals": code_signals,
        "pe_header_offset": pe_offset,
    }


def _scan_x86_code(
    data: bytes,
    sections: list[dict[str, object]],
    image_base: int,
    imports: list[dict[str, object]],
) -> dict[str, object]:
    """Recover bounded x86 call/instruction signals for malformed PE headers.

    Ghidra is authoritative when it can identify the architecture. For samples
    with a damaged Machine field, this scanner forces x86 disassembly over
    executable-looking sections and reports only API call sites and stable
    instruction constants. It never emulates or executes sample code.
    """
    if Cs is None:
        return {"architecture": "x86-capstone-unavailable", "api_calls": [], "patterns": []}
    iat: dict[int, str] = {}
    for imported in imports:
        module = str(imported.get("module", ""))
        thunk_rva = int(imported.get("thunk_rva", 0) or 0)
        width = int(imported.get("thunk_width", 4) or 4)
        for index, name in enumerate(imported.get("functions", [])):
            if name.startswith("ordinal:"):
                continue
            iat[image_base + thunk_rva + index * width] = f"{module}!{name}"
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    api_calls: list[dict[str, object]] = []
    patterns: list[dict[str, object]] = []
    compression_format_2 = False
    constants = {0x6033A96D: "xor_state_multiplier", 0xDD483B8F: "xor_state_subtractor"}
    for section in sections:
        name = str(section.get("name", ""))
        if name.lower() in {".rsrc", ".reloc"}:
            continue
        raw_offset = int(section.get("raw_offset", 0))
        raw_size = min(int(section.get("raw_size", 0)), 8 * 1024 * 1024)
        if raw_size <= 0 or raw_offset < 0 or raw_offset + raw_size > len(data):
            continue
        code = data[raw_offset : raw_offset + raw_size]
        start_rva = int(section.get("virtual_address", 0))
        recent: list[str] = []
        for instruction in disassembler.disasm(code, image_base + start_rva):
            text = f"{instruction.mnemonic} {instruction.op_str}".strip()
            if instruction.mnemonic in {"push", "mov", "xor", "or", "and"} and re.search(
                r"(?:^|,\s*)(?:0x)?2(?:\b|$)", instruction.op_str.lower()
            ):
                compression_format_2 = True
            recent.append(text)
            if len(recent) > 8:
                recent.pop(0)
            if instruction.mnemonic == "call" and instruction.operands:
                operand = instruction.operands[0]
                if operand.type == 3:  # X86_OP_MEM
                    target = iat.get(int(operand.mem.disp))
                    if target:
                        api_calls.append(
                            {
                                "api": target,
                                "address": int(instruction.address - image_base),
                                "file_offset": raw_offset + int(instruction.address - image_base - start_rva),
                            }
                        )
            for operand in instruction.operands:
                if operand.type == 2:  # X86_OP_IMM
                    immediate = int(operand.imm) & 0xFFFFFFFF
                    if immediate in constants:
                        patterns.append(
                            {
                                "kind": constants[immediate],
                                "address": int(instruction.address - image_base),
                                "instruction": text,
                            }
                        )
            if instruction.mnemonic in {"xor", "imul", "sub", "shr"}:
                window = " ; ".join(recent).lower()
                if (
                    "imul" in window
                    and "sub" in window
                    and "shr" in window
                    and "xor" in window
                    and "0x6033a96d" in window
                    and "0xdd483b8f" in window
                ):
                    patterns.append(
                        {
                            "kind": "xor_keystream_loop_candidate",
                            "address": int(instruction.address - image_base),
                            "window": recent[-8:],
                        }
                    )
    return {
        "architecture": "x86",
        "api_calls": api_calls[:4096],
        "patterns": patterns[:256],
        "compression_format_2": compression_format_2,
        "api_call_count": len(api_calls),
    }


def _parse_pe_resources(
    data: bytes,
    sections: list[dict[str, object]],
    resource_rva: int,
    resource_size: int,
) -> dict[str, object]:
    """Read the PE resource tree without loading or executing resource data.

    Resource bytes are represented by hashes, sizes, offsets and entropy only.
    The bounded traversal is intentionally conservative because malformed PE
    resource directories are common in packed samples.
    """
    if not resource_rva or not resource_size:
        return {"rva": resource_rva, "size": resource_size, "entries": [], "count": 0}

    def rva_to_offset(rva: int) -> int | None:
        for section in sections:
            start = int(section["virtual_address"])
            span = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + span:
                offset = int(section["raw_offset"]) + (rva - start)
                return offset if 0 <= offset < len(data) else None
        return rva if 0 <= rva < len(data) else None

    root_offset = rva_to_offset(resource_rva)
    if root_offset is None:
        return {"rva": resource_rva, "size": resource_size, "entries": [], "count": 0}
    resource_end = min(len(data), root_offset + resource_size)
    entries: list[dict[str, object]] = []
    visited: set[int] = set()

    def walk(directory_rva: int, path: tuple[object, ...], depth: int) -> None:
        if depth > 4 or len(entries) >= 512:
            return
        directory_offset = rva_to_offset(resource_rva + directory_rva)
        if directory_offset is None or directory_offset in visited:
            return
        if directory_offset + 16 > resource_end:
            return
        visited.add(directory_offset)
        named_count, id_count = struct.unpack_from("<HH", data, directory_offset + 12)
        total = min(named_count + id_count, 512)
        for index in range(total):
            entry_offset = directory_offset + 16 + index * 8
            if entry_offset + 8 > resource_end:
                break
            name_or_id, child = struct.unpack_from("<II", data, entry_offset)
            if name_or_id & 0x80000000:
                name_offset = rva_to_offset(resource_rva + (name_or_id & 0x7FFFFFFF))
                if name_offset is None or name_offset + 2 > resource_end:
                    label: object = "#name"
                else:
                    length = struct.unpack_from("<H", data, name_offset)[0]
                    raw = data[name_offset + 2 : name_offset + 2 + length * 2]
                    label = raw.decode("utf-16le", errors="replace")
            else:
                label = int(name_or_id & 0xFFFF)
            child_rva = child & 0x7FFFFFFF
            if child & 0x80000000:
                walk(child_rva, path + (label,), depth + 1)
                continue
            data_offset = rva_to_offset(resource_rva + child_rva)
            if data_offset is None or data_offset + 16 > resource_end:
                continue
            payload_rva, payload_size, code_page, _ = struct.unpack_from(
                "<IIII", data, data_offset
            )
            payload_offset = rva_to_offset(payload_rva)
            if payload_offset is None or payload_offset + payload_size > len(data):
                continue
            payload = data[payload_offset : payload_offset + payload_size]
            entries.append(
                {
                    "type": path[0] if path else label,
                    "name": path[1] if len(path) > 1 else label,
                    "language": path[2] if len(path) > 2 else None,
                    "rva": payload_rva,
                    "file_offset": payload_offset,
                    "size": payload_size,
                    "code_page": code_page,
                    "entropy": round(_entropy(payload), 5),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )

    walk(0, (), 0)
    rcdata = [item for item in entries if item.get("type") == 10]
    return {
        "rva": resource_rva,
        "size": resource_size,
        "entries": entries,
        "count": len(entries),
        "rcdata_count": len(rcdata),
        "rcdata_total_size": sum(int(item["size"]) for item in rcdata),
        "high_entropy_count": sum(float(item["entropy"]) >= 7.2 for item in entries),
    }


def derive_mechanism_facts(
    facts: tuple[StaticFact, ...],
    *,
    subject: str = "",
    ghidra_output: dict[str, object] | None = None,
) -> tuple[StaticFact, ...]:
    """Aggregate low-level observations into evidence-ready mechanism signals.

    This is deliberately deterministic: it does not claim execution and does
    not infer behavior from one isolated API. A signal is emitted only when a
    known API/string/function combination supports a coherent static mechanism.
    """
    result: list[StaticFact] = []
    names: set[str] = set()
    name_sources: dict[str, str] = {}
    instruction_texts: set[str] = set()
    pe_structures: list[dict[str, object]] = []
    for fact in facts:
        if fact.kind == "pe_structure":
            pe_structures.append(fact.value)
            for imported in fact.value.get("imports", []):
                if isinstance(imported, dict):
                    for function in imported.get("functions", []):
                        lowered = str(function).lower()
                        names.add(lowered)
                        name_sources.setdefault(lowered, "pe_import")
        elif fact.kind == "string":
            lowered = str(fact.value.get("text", "")).lower()
            if lowered:
                names.add(lowered)
                name_sources.setdefault(lowered, "string")
    function_rows = []
    call_api_names: set[str] = set()
    if ghidra_output:
        raw_functions = ghidra_output.get("functions", [])
        function_rows = raw_functions if isinstance(raw_functions, list) else []
        for function in function_rows:
            if not isinstance(function, dict):
                continue
            for call in function.get("references_from", []):
                if not isinstance(call, dict):
                    continue
                target = str(call.get("target_name") or call.get("target_function") or "")
                if target:
                    lowered = target.lower()
                    call_api_names.add(lowered)
                    names.add(lowered)
                    name_sources.setdefault(lowered, "ghidra_call")
            for instruction in function.get("instructions", []):
                if isinstance(instruction, dict):
                    text = str(instruction.get("text", "")).lower()
                    if text:
                        instruction_texts.add(text)
                        names.add(text)
                        name_sources.setdefault(text, "ghidra_instruction")

    def has_any(*terms: str) -> bool:
        return any(any(term.lower() in name for name in names) for term in terms)

    def emit(module: str, kind: str, value: dict[str, object], anchor_type: str) -> None:
        result.append(StaticFact(module, kind, value, {"type": anchor_type, "subject": subject}))

    for pe in pe_structures:
        resources = pe.get("resources")
        if isinstance(resources, dict) and int(resources.get("count", 0)):
            entries = resources.get("entries", [])
            rcdata_count = int(resources.get("rcdata_count", 0))
            total_size = int(resources.get("rcdata_total_size", 0))
            emit(
                "static_triage",
                "resource_inventory",
                {
                    "count": int(resources.get("count", 0)),
                    "rcdata_count": rcdata_count,
                    "rcdata_total_size": total_size,
                    "high_entropy_count": int(resources.get("high_entropy_count", 0)),
                    "entries": list(entries)[:64] if isinstance(entries, list) else [],
                },
                "pe_resource_directory",
            )
            if rcdata_count and int(resources.get("high_entropy_count", 0)):
                emit(
                    "decryption",
                    "mechanism_resource_payload",
                    {
                        "resource_type": "RT_RCDATA",
                        "count": rcdata_count,
                        "total_size": total_size,
                        "high_entropy": True,
                    },
                    "pe_resource_directory",
                )
        machine = str(pe.get("machine", "")).lower()
        if machine in {"0x0000", "0x0000"} or int(pe.get("subsystem", 0) or 0) == 0:
            emit(
                "static_triage",
                "pe_header_anomaly",
                {"machine": pe.get("machine"), "subsystem": pe.get("subsystem"), "checksum": pe.get("checksum")},
                "pe_header",
            )
        signals = pe.get("code_signals")
        if isinstance(signals, dict):
            if signals.get("compression_format_2") and any(
                "rtldecompressbuffer" in name.replace(" ", "") for name in names
            ):
                emit(
                    "decryption",
                    "mechanism_decompression_format",
                    {"api": "RtlDecompressBuffer", "compression_format": 2, "format": "LZNT1 candidate"},
                    "x86_instruction_pattern",
                )
            api_calls = signals.get("api_calls", [])
            if isinstance(api_calls, list) and api_calls:
                by_api: dict[str, list[dict[str, object]]] = {}
                for call in api_calls:
                    if isinstance(call, dict):
                        by_api.setdefault(str(call.get("api", "")), []).append(call)
                for api, calls in by_api.items():
                    lowered_api = api.lower()
                    if any(token in lowered_api for token in ("findresource", "loadresource", "sizeofresource", "lockresource")):
                        emit(
                            "loader",
                            "mechanism_resource_extraction",
                            {"api": api, "call_sites": calls[:32]},
                            "x86_call_site",
                        )
                    elif "virtualprotect" in lowered_api:
                        emit(
                            "loader",
                            "mechanism_memory_permission",
                            {"api": api, "call_sites": calls[:32]},
                            "x86_call_site",
                        )
                    elif any(token in lowered_api for token in ("globalmemorystatusex", "getsysteminfo", "virtualquery")):
                        emit(
                            "anti_analysis",
                            "mechanism_environment_check",
                            {"api": api, "call_sites": calls[:32]},
                            "x86_call_site",
                        )
                    elif any(token in lowered_api for token in ("openscmanager", "openservice", "queryservicestatus")):
                        emit(
                            "anti_analysis",
                            "mechanism_service_query",
                            {"api": api, "call_sites": calls[:32]},
                            "x86_call_site",
                        )
            patterns = signals.get("patterns", [])
            if isinstance(patterns, list):
                for pattern in patterns:
                    if not isinstance(pattern, dict):
                        continue
                    if pattern.get("kind") == "xor_keystream_loop_candidate":
                        emit(
                            "decryption",
                            "mechanism_decode",
                            {
                                "operation": "custom XOR keystream loop candidate",
                                "algorithm_constants": ["0x6033A96D", "0xDD483B8F"],
                                "location": pattern.get("address"),
                                "window": pattern.get("window", []),
                            },
                            "x86_instruction_pattern",
                        )

    if has_any("findresource", "loadresource", "lockresource") and not any(
        item.kind == "mechanism_resource_extraction" for item in result
    ):
        emit(
            "loader",
            "mechanism_resource_extraction",
            {
                "apis": [term for term in ("FindResource", "LoadResource", "SizeofResource", "LockResource") if has_any(term)],
                "relationship": "resource -> allocated buffer",
            },
            "api_call_chain",
        )
    if has_any("rtl decompressbuffer", "rtlcompressbuffer", "decompress"):
        emit(
            "decryption",
            "mechanism_decompression",
            {
                "api": "RtlDecompressBuffer"
                if any("rtldecompressbuffer" in name.replace(" ", "") for name in names)
                else "decompression API",
                "dynamic_resolution": has_any("loadlibrary", "getprocaddress"),
                "compression_format": "LZNT1 candidate"
                if any(re.search(r"(?:,|\s)(?:0x)?2(?:\b|\s)", text) for text in instruction_texts)
                else "unknown",
            },
            "api_call_chain",
        )
    # A cryptographic API call may seed a decode investigation, but an XOR
    # mnemonic by itself is never a mechanism.  The latter requires the
    # bounded data-flow/loop detector used by derive_function_mechanism_facts.
    crypto_api_present = any(
        any(token in name for token in ("cryptdecrypt", "bcryptdecrypt", "cryptencrypt", "bcryptencrypt"))
        for name in call_api_names
    )
    crypto_dataflow_context = any(
        any(
            "[" in str(instruction.get("text") or "")
            and "]" in str(instruction.get("text") or "")
            for instruction in (function.get("instructions", []) if isinstance(function, dict) else [])
            if isinstance(instruction, dict)
        )
        for function in function_rows
        if isinstance(function, dict)
        and any(
            any(token in str(call.get("target_name") or call.get("target_function") or call.get("api") or "").casefold() for token in ("cryptdecrypt", "bcryptdecrypt", "cryptencrypt", "bcryptencrypt"))
            for call in (function.get("references_from", []) if isinstance(function.get("references_from", []), list) else [])
            if isinstance(call, dict)
        )
    )
    if crypto_api_present and crypto_dataflow_context:
        emit(
            "decryption",
            "mechanism_decode",
            {"operation": "cryptographic API decode candidate", "standard": True, "apis": sorted(call_api_names)[:16]},
            "function_or_instruction",
        )
    if has_any("crc", "checksum") or any(
        "imul" in name and "shr" in name and "xor" in name for name in names
    ):
        emit(
            "decryption",
            "mechanism_integrity_check",
            {"algorithm": "CRC-like or table/state integrity check candidate"},
            "function_or_instruction",
        )
    if has_any("virtualprotect") and not any(
        item.kind == "mechanism_memory_permission" for item in result
    ):
        emit(
            "loader",
            "mechanism_memory_permission",
            {"api": "VirtualProtect", "protection": "PAGE_EXECUTE_READWRITE candidate"},
            "api_call_chain",
        )
    if has_any("globalmemorystatusex", "getsysteminfo", "virtualquery", "isdebuggerpresent"):
        emit(
            "anti_analysis",
            "mechanism_environment_check",
            {"apis": [term for term in ("GlobalMemoryStatusEx", "GetSystemInfo", "VirtualQuery", "IsDebuggerPresent") if has_any(term)]},
            "api_call_chain",
        )
    if has_any("openscmanager", "openservice", "queryservicestatus"):
        emit(
            "anti_analysis",
            "mechanism_service_query",
            {"apis": [term for term in ("OpenSCManager", "OpenService", "QueryServiceStatus") if has_any(term)]},
            "api_call_chain",
        )
    if has_any("loadlibrary", "getprocaddress"):
        emit(
            "loader",
            "mechanism_dynamic_resolution",
            {"apis": [term for term in ("LoadLibrary", "GetProcAddress") if has_any(term)]},
            "api_call_chain",
        )
    return tuple(result)


def derive_function_mechanism_facts(
    function: dict[str, object],
    *,
    subject: str = "",
) -> tuple[StaticFact, ...]:
    """Turn one ordered disassembly function into bounded mechanism candidates.

    The exporter gives us instruction/call order, but not analyst prose.  This
    seam deliberately keeps the transformation deterministic and conservative:
    a chain requires at least two related observations in the same function,
    and every step retains its original call address.  It is therefore useful
    to an Agent without turning one imported API into proof of execution.
    """
    calls = function.get("references_from", [])
    if not isinstance(calls, list):
        calls = []
    steps: list[dict[str, object]] = []
    for call in calls:
        if not isinstance(call, dict):
            continue
        name = str(call.get("target_name") or call.get("target_function") or "")
        if not name:
            continue
        reference_type = str(call.get("type", "")).lower()
        is_call_reference = "call" in reference_type or "call" in str(call.get("target_function", "")).lower()
        # Ghidra emits DATA/READ references alongside CALL references.  A
        # source filename such as ``src/http.rs`` must not become a network
        # transport step merely because it contains the token ``http``.
        if not is_call_reference:
            continue
        category: str | None = None
        if is_anti_analysis_signal(name):
            category = "anti_analysis"
        elif is_injection_call(name):
            category = "injection"
        elif semantic_category(name) in {"timing_query", "environment_query"}:
            # Timing and environment APIs are observations. They only become
            # anti-analysis candidates when paired with an explicit signal or
            # control-flow predicate; an imported query alone is not behaviour.
            category = "environment_query"
        elif semantic_category(name) == "execution":
            category = "execution"
        elif semantic_category(name) in {"dynamic_resolution", "loader"}:
            category = "dynamic_resolution" if semantic_category(name) == "dynamic_resolution" else "loader"
        elif semantic_category(name) == "network":
            category = "network"
        elif semantic_category(name) == "persistence":
            category = "persistence"
        elif semantic_category(name) == "file_io":
            category = "file_io"
        elif semantic_category(name) == "generic_runtime":
            category = "generic_runtime"
        else:
            category = None
        if category is not None:
            steps.append({
                "category": category,
                "name": name,
                "address": call.get("from"),
                "target": call.get("to"),
                "reference_type": call.get("type"),
            })

    instructions = function.get("instructions", [])
    instruction_text = [
        str(item.get("text", ""))
        for item in instructions
        if isinstance(item, dict) and item.get("text")
    ] if isinstance(instructions, list) else []
    process_flag_facts: list[dict[str, object]] = []
    process_names = {
        str(step.get("name", "")).lower()
        for step in steps
        if str(step.get("category", "")) == "execution"
    }
    if any("createprocess" in name for name in process_names):
        for text in instruction_text:
            if "createprocess" not in text.lower():
                continue
            for token in re.findall(r"0x[0-9A-Fa-f]{1,8}", text):
                value = _parse_int_literal(token)
                if value is not None:
                    process_flag_facts.append(decode_windows_process_creation_flags(value))
    # Do not promote an XOR count to a decoder.  Register-zeroing idioms and
    # compiler-generated parity checks are ubiquitous.  Only the bounded
    # window detector, which requires a non-zeroing transform and loop shape,
    # can create a decode investigation seed.
    instruction_rows = [item for item in instructions if isinstance(item, dict)] if isinstance(instructions, list) else []
    decode_window = analyze_xor_decode_window(instruction_rows)
    if decode_window is not None:
        requirements = decode_window.get("semantic_requirements", {})
        if isinstance(requirements, Mapping) and requirements.get("non_zeroing_transform"):
            steps.append({
                "category": "decode_candidate",
                "name": "bounded XOR transform loop",
                "count": decode_window.get("xor_count", 0),
                "window": decode_window,
            })

    chains: list[StaticFact] = []
    if process_flag_facts:
        chains.append(StaticFact(
            "execution",
            "process_creation_flags",
            {
                "function": function.get("name"),
                "flags": process_flag_facts[:8],
                "runtime_effect_proven": False,
            },
            {
                "type": "function_instruction_window",
                "function_entry": function.get("entry"),
                "rva": function.get("entry_rva"),
                "subject": subject,
            },
        ))
    def emit(module: str, chain_type: str, categories: tuple[str, ...], rationale: str) -> None:
        selected = [step for step in steps if step.get("category") in categories]
        present = tuple(dict.fromkeys(str(step["category"]) for step in selected))
        if len(present) < 2:
            return
        chains.append(StaticFact(
            module,
            "mechanism_chain",
            {
                "chain_type": chain_type,
                "function": function.get("name"),
                "entry": function.get("entry"),
                "entry_rva": function.get("entry_rva"),
                "steps": selected[:40],
                "categories": list(present),
                "rationale": rationale,
                "static_only": True,
            },
            {
                "type": "function_mechanism_chain",
                "function_entry": function.get("entry"),
                "rva": function.get("entry_rva"),
                "subject": subject,
            },
        ))

    emit(
        "anti_analysis", "environment_gate",
        ("anti_analysis", "decode_candidate"),
        "environment checks are sequenced with a transformation/guard pattern",
    )
    emit(
        "loader", "dynamic_loader",
        ("dynamic_resolution", "network", "file_io", "decode_candidate"),
        "dynamic resolution or decoded data is sequenced with transport or file preparation",
    )
    emit(
        "c2_network", "network_download",
        ("network", "file_io", "execution"),
        "transport, file output, and execution-related operations occur in one function",
    )
    emit(
        "execution", "process_execution",
        ("injection", "execution"),
        "process creation is combined with parent/process attribute manipulation",
    )
    emit(
        "loader", "persistence_fallback",
        ("execution", "persistence"),
        "execution and persistence operations are present in the same function; branch order requires validation",
    )
    return tuple(chains)


def analyze_bytes(
    data: bytes,
    logical_path: str,
    *,
    string_xrefs: Mapping[int | str, int] | None = None,
) -> StaticResult:
    """Parse one artifact and emit bounded observations plus semantic views.

    ``string_xrefs`` is optional because the raw parser has no disassembler;
    Ghidra integrations can supply an offset/RVA keyed count to make the
    section-aware string quality projection xref-aware without changing the
    lossless raw string evidence contract.
    """
    format_identity = identify_format(data, logical_path)
    detected_type = format_identity.detected_type
    facts: list[StaticFact] = []
    limitations: list[str] = []
    identity = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "size": len(data),
        "detected_type": detected_type,
        "mime_type": format_identity.mime_type,
        "type_source": format_identity.source,
        "entropy": round(_entropy(data), 3),
    }
    facts.append(StaticFact("static_triage", "file_identity", identity, {"type": "file"}))
    strings = _extract_strings(data)
    semantic_string_count = 0
    for extracted in strings:
        facts.append(
            StaticFact(
                "static_triage",
                "string",
                {"text": extracted["text"], "encoding": extracted["encoding"]},
                {"type": "file_offset", "offset": extracted["offset"]},
            )
        )
        # Keep the original lossless string observation and add a separate
        # semantic-quality row.  Consumers may safely filter false positives
        # without breaking the historical ``string`` evidence contract.
        if semantic_string_count < 1024:
            facts.append(
                StaticFact(
                    "static_triage",
                    "string_semantics",
                    classify_static_string(str(extracted["text"]), str(extracted.get("encoding", "ascii"))),
                    {"type": "file_offset", "offset": extracted["offset"]},
                )
            )
            semantic_string_count += 1
    pe: dict[str, object] | None = None
    script: ScriptResult | None = None
    document: DocumentResult | None = None
    if detected_type == "pe":
        try:
            pe = _parse_pe(data, logical_path)
            facts.append(
                StaticFact(
                    "static_triage",
                    "pe_structure",
                    pe,
                    {"type": "file_offset", "offset": pe["pe_header_offset"]},
                )
            )
            # Enrich semantic string projections with the PE section that
            # contains the original bytes.  Raw strings remain lossless and
            # retain their historical anchor contract.
            sections = pe.get("sections", []) if isinstance(pe, dict) else []
            if isinstance(sections, list):
                for index, fact in enumerate(facts):
                    if fact.kind != "string_semantics":
                        continue
                    offset = fact.anchor.get("offset") if isinstance(fact.anchor, dict) else None
                    if not isinstance(offset, int):
                        continue
                    section_name: str | None = None
                    for section in sections:
                        if not isinstance(section, dict):
                            continue
                        start = int(section.get("raw_offset", 0) or 0)
                        size = int(section.get("raw_size", 0) or 0)
                        if start <= offset < start + size:
                            section_name = str(section.get("name") or "") or None
                            break
                    if section_name is not None:
                        enriched = classify_static_string(
                            str(fact.value.get("text", "")),
                            str(fact.value.get("encoding", "ascii")),
                            section_name=section_name,
                            xref_count=(
                                int(fact.value.get("xref_count", 0) or 0)
                                or int((string_xrefs or {}).get(offset, (string_xrefs or {}).get(str(offset), 0)) or 0)
                            ),
                        )
                        facts[index] = StaticFact(fact.module, fact.kind, enriched, fact.anchor)
        except ValueError as exc:
            limitations.append(f"PE parsing incomplete: {exc}")
    elif detected_type == "script":
        script = analyze_script(data, logical_path)
        limitations.extend(script.limitations)
        for function in script.functions:
            facts.append(
                StaticFact(
                    "static_triage",
                    "script_function",
                    {"name": function["name"], "language": script.language},
                    {"type": "script_line", "line": function["line"]},
                )
            )
        for imported in script.import_details:
            facts.append(
                StaticFact(
                    "static_triage",
                    "script_import",
                    {
                        "name": imported["name"],
                        "language": script.language,
                        "kind": imported["kind"],
                    },
                    {"type": "script_line", "line": imported["line"]},
                )
            )
        for call in script.calls:
            facts.append(
                StaticFact(
                    "static_triage",
                    "script_call",
                    {"name": call["name"], "language": script.language},
                    {"type": "script_line", "line": call["line"]},
                )
            )
        for indicator in script.indicators:
            facts.append(
                StaticFact(
                    "c2_network" if indicator["kind"] == "network" else "static_triage",
                    "script_indicator",
                    {"indicator": indicator["value"], "kind": indicator["kind"]},
                    {"type": "script_line", "line": indicator["line"]},
                )
            )
    elif detected_type in {"pdf", "ooxml", "ole"}:
        document = analyze_document(data, logical_path)
        limitations.extend(document.limitations)
        for url in document.urls:
            facts.append(
                StaticFact("c2_network", "document_url", {"indicator": url["value"]}, url["anchor"])
            )
        for action in document.javascript:
            facts.append(
                StaticFact(
                    "static_triage",
                    "document_active_content",
                    {"kind": action["kind"]},
                    action["anchor"],
                )
            )
        for embedded in document.embedded_objects:
            facts.append(
                StaticFact(
                    "static_triage",
                    "document_embedded_object",
                    {"kind": embedded["kind"], "internal_path": embedded.get("internal_path")},
                    embedded["anchor"],
                )
            )

    searchable: list[dict[str, object]] = list(strings)
    if pe:
        for imported in pe["imports"]:  # type: ignore[index]
            for function in imported["functions"]:  # type: ignore[index]
                searchable.append(
                    {
                        "text": str(function),
                        "offset": int(pe["pe_header_offset"]),
                        "encoding": "pe_import",
                        "module": imported["module"],
                    }
                )

    def add_indicator(module: str, kind: str, item: dict[str, object]) -> int:
        facts.append(
            StaticFact(
                module,
                kind,
                {"indicator": item["text"], "encoding": item.get("encoding", "ascii")},
                {"type": "file_offset", "offset": int(item["offset"])},
            )
        )
        return len(facts) - 1

    lowered_seen: set[tuple[str, str]] = set()
    crypto_indexes: list[int] = []
    loader_indexes: list[int] = []
    execution_indexes: list[int] = []
    anti_indexes: list[int] = []
    network_indexes: list[int] = []
    for item in searchable:
        text = str(item["text"])
        lowered = text.lower()
        exact_import = item.get("encoding") == "pe_import"

        def term_matches(term: str) -> bool:
            normalized = term.lower()
            # Import names are already tokenized; substring matching would turn
            # GetSystemInfo into a false `system` execution signal. Strings and
            # script text retain the broader substring behavior for triage.
            if lowered == normalized:
                return True
            if exact_import:
                return False
            return re.search(
                rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])",
                lowered,
            ) is not None

        for term in CRYPTO_TERMS:
            key = ("crypto", term.lower())
            if term_matches(term) and key not in lowered_seen:
                crypto_indexes.append(add_indicator("decryption", "crypto_indicator", item))
                lowered_seen.add(key)
        for term in LOADER_TERMS:
            key = ("loader", term.lower())
            if term_matches(term) and key not in lowered_seen:
                loader_indexes.append(add_indicator("loader", "loader_indicator", item))
                lowered_seen.add(key)
        for term in EXECUTION_TERMS:
            key = ("execution", term.lower())
            if term_matches(term) and key not in lowered_seen:
                execution_indexes.append(add_indicator("execution", "execution_indicator", item))
                lowered_seen.add(key)
        for term in ANTI_ANALYSIS_TERMS:
            key = ("anti", term.lower())
            if term_matches(term) and key not in lowered_seen:
                anti_indexes.append(add_indicator("anti_analysis", "anti_analysis_indicator", item))
                lowered_seen.add(key)
        for match in NETWORK_RE.finditer(text):
            indicator = match.group(0).rstrip(".,);]")
            key = ("network", indicator.lower())
            if key in lowered_seen:
                continue
            network_item = {
                "text": indicator,
                "offset": int(item["offset"]) + match.start(),
                "encoding": item.get("encoding", "ascii"),
            }
            network_indexes.append(add_indicator("c2_network", "network_indicator", network_item))
            lowered_seen.add(key)

    base64_indexes: list[int] = []
    for item in strings:
        match = BASE64_RE.search(str(item["text"]))
        if match:
            encoded_item = {
                "text": match.group(0)[:160],
                "offset": int(item["offset"]) + match.start(),
                "encoding": item["encoding"],
            }
            base64_indexes.append(add_indicator("decryption", "encoded_blob", encoded_item))
            if len(base64_indexes) >= 20:
                break
    high_entropy_indexes: list[int] = []
    if pe:
        for section in pe["sections"]:  # type: ignore[index]
            if float(section["entropy"]) >= 7.2:
                facts.append(
                    StaticFact(
                        "decryption",
                        "high_entropy_section",
                        {"section": section["name"], "entropy": section["entropy"]},
                        {"type": "file_offset", "offset": section["raw_offset"]},
                    )
                )
                high_entropy_indexes.append(len(facts) - 1)

    for candidate in _find_crypto_table_candidates(data):
        facts.append(
            StaticFact(
                "decryption",
                "crypto_pattern",
                candidate,
                {"type": "file_offset", "offset": candidate["file_offset"]},
            )
        )

    # Promote compatible low-level observations into a deterministic mechanism
    # view. The Agent consumes these facts alongside raw parser facts, so the
    # report can explain a chain without treating one API name as proof.
    facts.extend(derive_mechanism_facts(tuple(facts), subject=logical_path))

    summary = {
        "identity": identity,
        "string_count": len(strings),
        "pe": pe,
        "script": {
            "language": script.language,
            "functions": list(script.functions),
            "imports": list(script.imports),
            "import_details": list(script.import_details),
            "calls": list(script.calls),
        }
        if script
        else None,
        "document": document.summary if document else None,
        "indicator_counts": {
            "decryption": len(crypto_indexes) + len(base64_indexes) + len(high_entropy_indexes),
            "loader": len(loader_indexes),
            "c2_network": len(network_indexes),
            "anti_analysis": len(anti_indexes),
        },
    }
    return StaticResult(
        detected_type,
        summary,
        tuple(facts),
        tuple(limitations),
    )
