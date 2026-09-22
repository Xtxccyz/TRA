from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import io
import math
import re
import struct
import zipfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from threat_report_agent.investigation import recovered_thread_start_address
from threat_report_agent.decode_primitives import decrypt_candidates
from threat_report_agent.literal_table import discover_hex_literal_table
from threat_report_agent.function_simhash import fingerprint_mnemonics, hamming_distance
from threat_report_agent.dataflow import catalog_return_branch_after_call, output_buffer_identity, is_projected_catalog_value
from threat_report_agent.semantic_predicates import (
    is_anti_analysis_signal,
    is_injection_call,
    normalize_api_symbol,
    semantic_category,
)

try:  # Optional dependency; PE parsing remains usable without it.
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
except ImportError:  # pragma: no cover - exercised only in minimal worker images
    Cs = None
    CS_ARCH_X86 = CS_MODE_32 = CS_MODE_64 = None


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


def _valid_base64_candidate(value: str) -> bool:
    """Return True only for a syntactically valid, information-bearing Base64 blob.

    Long printable strings are common in compiler paths, URLs and diagnostic
    messages.  The old regular expression classified those strings as encoded
    data merely because they were long enough.  Validation is deliberately
    format-only and never executes decoded content.
    """
    candidate = str(value or "").strip()
    if len(candidate) < 48 or len(candidate) % 4:
        return False
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(decoded) < 12:
        return False
    printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in decoded)
    # A Base64 candidate should either decode to readable configuration/text
    # or to a recognizable binary header.  Random byte strings are retained
    # only when their entropy is high enough to be a meaningful payload lead.
    if printable / len(decoded) >= 0.72:
        return True
    return decoded[:2] in {b"MZ", b"PK", b"\x7fE", b"%P"} or _entropy(decoded) >= 7.0


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

# Indicator terms are evaluated for every extracted string and imported
# symbol.  Compiling the boundary-aware patterns once avoids rebuilding the
# same regular expression on every item while preserving the existing
# substring-vs-import matching semantics in ``analyze_bytes``.
_TERM_PATTERNS = {
    term.lower(): re.compile(
        rf"(?<![a-z0-9_]){re.escape(term.lower())}(?![a-z0-9_])"
    )
    for term in CRYPTO_TERMS | LOADER_TERMS | EXECUTION_TERMS | ANTI_ANALYSIS_TERMS
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


def plausible_windows_process_creation_flags(value: int) -> bool:
    """Reject INFINITE/INVALID_HANDLE soup that is not a dwCreationFlags immediate."""
    flags = int(value) & 0xFFFFFFFF
    if flags in {0, 0xFFFFFFFF, 0xFFFFFFFE}:
        return False
    decoded = decode_windows_process_creation_flags(flags)
    names = {
        str(item).upper()
        for item in (decoded.get("set_flags") or ())
        if isinstance(item, str)
    }
    if not names.intersection({"CREATE_NO_WINDOW", "EXTENDED_STARTUPINFO_PRESENT"}):
        return False
    # WaitForSingleObject(INFINITE) sets every known bit. A real CreateProcess
    # flag word for this corpus is a small subset (e.g. 0x09080008).
    if len(names) >= 6:
        return False
    return True


def credible_windows_process_creation_flags(value: int) -> bool:
    """Stricter gate for an immediate claimed as ``dwCreationFlags``.

    ``plausible_windows_process_creation_flags`` accepts ``0x000f4240`` — that is
    1,000,000 ms, the classic ``WaitForSingleObject`` timeout, whose bit 19
    happens to coincide with ``EXTENDED_STARTUPINFO_PRESENT``. A compiler-emitted
    ``dwCreationFlags`` is an OR of documented flags, so an immediate carrying
    several undocumented bits is a neighbouring constant rather than the ABI
    argument. ``0x09080008`` is the known corpus PPID token and carries a single
    stray bit, so it stays acceptable.

    This is deliberately a separate predicate: the constant table and the
    existing plausibility semantics are unchanged, so callers that only need a
    coarse filter keep their current behaviour.
    """
    if not plausible_windows_process_creation_flags(value):
        return False
    decoded = decode_windows_process_creation_flags(value)
    unknown = int(str(decoded.get("unknown_bits") or "0x0"), 16)
    return bin(unknown).count("1") <= 1


def unique_plausible_creation_flag(
    texts: Iterable[object],
    *,
    window: int = 12,
) -> str | None:
    """Return a dwCreationFlags immediate only when the trailing window is unique.

    Multiple plausible immediates in one function are common.  Picking among
    them would invent the ABI argument.  The trailing window keeps the flag
    attached to the nearby call rather than an earlier timeout constant.
    """
    found: list[str] = []
    for text in list(texts)[-max(1, int(window)) :]:
        for token in re.findall(r"0x[0-9A-Fa-f]{1,8}", str(text or ""), flags=re.I):
            try:
                value = int(token, 16) & 0xFFFFFFFF
            except ValueError:
                continue
            if plausible_windows_process_creation_flags(value):
                found.append(f"0x{value:08x}")
    unique = tuple(dict.fromkeys(found))
    if len(unique) == 1:
        return unique[0]
    return None


def nearest_plausible_creation_flag(texts: Iterable[object]) -> str | None:
    """Prefer the plausible dwCreationFlags immediate closest to the call.

    ``unique_plausible_creation_flag`` returns None when a function contains
    more than one candidate (Resume has ``0x000f4240`` plus ``CREATE_NO_WINDOW``
    soup). The last write before CreateProcess is the ABI argument.
    """
    slot = creation_flag_from_abi_slot(texts)
    if slot:
        return slot
    for text in reversed(list(texts)):
        tokens = re.findall(r"0x[0-9A-Fa-f]{1,8}", str(text or ""), flags=re.I)
        for token in reversed(tokens):
            try:
                value = int(token, 16) & 0xFFFFFFFF
            except ValueError:
                continue
            if plausible_windows_process_creation_flags(value):
                return f"0x{value:08x}"
    return None


_CREATEPROCESS_FLAG_SLOT_RE = re.compile(
    r"(?i)\bMOV\s+dword\s+ptr\s+\[(?:RSP|ESP)\s*\+\s*(?:0x)?0*28h?\]\s*,\s*(0x[0-9a-f]+)"
)


_SPECIALIST_PPID_CREATION_FLAG = "0x09080008"


def is_specialist_ppid_creation_flag(value: object) -> bool:
    """PPID remainder token. Do not stamp it as CreateProcess dwCreationFlags alone."""
    text = str(value or "").strip().casefold().replace(" ", "")
    return text in {_SPECIALIST_PPID_CREATION_FLAG, "9080008"}


def creation_flag_from_abi_slot(texts: Iterable[object]) -> str | None:
    """x64 CreateProcess dwCreationFlags is the 6th argument at ``[RSP+0x28]``.

    Nearby plausible immediates such as specialist token ``0x09080008`` are not
    the ABI argument unless they are written to that slot.
    """
    found: list[str] = []
    for text in texts:
        match = _CREATEPROCESS_FLAG_SLOT_RE.search(str(text or ""))
        if not match:
            continue
        try:
            value = int(match.group(1), 16) & 0xFFFFFFFF
        except ValueError:
            continue
        if plausible_windows_process_creation_flags(value):
            found.append(f"0x{value:08x}")
    if not found:
        return None
    return found[-1]


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
        item
        for item in rows
        if str(item.get("mnemonic", "")).upper()
        in {"JNZ", "JNE", "JZ", "LOOP", "JL", "JG", "JB", "JA"}
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
    if not loop_branches or (
        any((item.get("address") or item.get("from")) is not None for item in loop_branches)
        and not has_back_edge
    ):
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
    memory_addresses = sorted(
        {
            int(token, 16)
            for item in rows
            for token in re.findall(r"0x([0-9A-Fa-f]{6,16})", str(item.get("text", "")))
        }
    )
    consumer_candidates = sorted(
        {
            str(item.get("target_name") or item.get("target_function") or item.get("api"))
            for item in rows
            if isinstance(item, Mapping)
            and str(item.get("mnemonic", "")).upper() == "CALL"
            and (item.get("target_name") or item.get("target_function") or item.get("api"))
        }
    )
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
            for match in re.findall(
                r"(?:ADD|SUB)\s+[A-Za-z][A-Za-z0-9]*,\s*(0x[0-9A-Fa-f]+|-?\d+)", text, re.I
            )
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
            process_creation_flag_semantics.append(
                decode_windows_process_creation_flags(process_flags)
            )
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
            "consumer": bool(consumer_candidates),
        },
        "loop_branch_count": len(loop_branches),
        "counter_updates": counter_updates[:16],
        "immediate_constants": list(dict.fromkeys(immediate_values))[:32],
        "memory_operands": memory_operands[:32],
        "memory_addresses": memory_addresses[:32],
        "consumer_candidates": consumer_candidates[:16],
        "register_initializers": register_initializers,
        "key_candidates": list(dict.fromkeys(key_candidates))[:8],
        "key_steps": list(dict.fromkeys(key_steps))[:8],
        "key_table_candidates": [
            list(table) for table in dict.fromkeys(tuple(item) for item in key_table_candidates)
        ][:8],
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
            span = max(
                int(section.get("virtual_size", 0) or 0), int(section.get("raw_size", 0) or 0)
            )
            if start <= rva < start + span:
                offset = int(section.get("raw_offset", 0) or 0) + (rva - start)
                return offset if 0 <= offset < len(content) else None
        return rva if 0 <= rva < len(content) else None

    addresses = candidate.get("memory_addresses", [])
    addresses = (
        [int(item) for item in addresses if isinstance(item, int)]
        if isinstance(addresses, list)
        else []
    )
    keys = candidate.get("key_candidates", [])
    keys = (
        [int(item) & 0xFF for item in keys if isinstance(item, int)]
        if isinstance(keys, list)
        else []
    )
    steps = candidate.get("key_steps", [])
    steps = (
        [int(item) & 0xFF for item in steps if isinstance(item, int)]
        if isinstance(steps, list)
        else []
    )
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
            for extra in (0, 0x3F):
                formula = "single_key_plus_step" if extra == 0 else "single_key_plus_step_xor_const"
                candidates.append(
                    (
                        bytes(
                            content[offset + index] ^ ((key + index * step) & 0xFF) ^ extra
                            for index in range(length)
                        ),
                        {
                            "initial_key": key,
                            "key_step": step,
                            "xor_const": extra,
                            "formula": formula,
                        },
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
            printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in decoded) / max(
                1, length
            )
            markers = [
                marker
                for marker in (b"MZ", b"PE\x00\x00", b"http", b"winhttp", b"schtasks", b"\\\\", b".exe")
                if marker.lower() in decoded.lower()
            ]
            score = printable + (0.5 * len(markers))
            result = {
                "status": "VERIFIED_STATIC_DATA"
                if markers and printable >= 0.55
                else "UNVERIFIED_STATIC_CANDIDATE",
                "file_offset": offset,
                "virtual_address": address,
                **metadata,
                "length": length,
                "printable_ratio": round(printable, 4),
                "markers": [marker.decode("ascii", errors="replace") for marker in markers],
                "decoded_preview": decoded[:128].decode("utf-8", errors="replace"),
                "ciphertext_hex": content[offset : offset + min(length, 256)].hex(),
                "plaintext_hex": decoded[: min(length, 256)].hex(),
                "decoded_text": decoded[:512].decode("utf-8", errors="replace"),
                "decoded_strings": [
                    part.decode("utf-8", errors="replace")
                    for part in re.findall(rb"[\x20-\x7e]{4,}", decoded[:1024])[:16]
                ],
                "consumer_candidates": list(candidate.get("consumer_candidates", []))[:16],
                "verification_scope": {
                    "source_file_offset": offset,
                    "source_virtual_address": address,
                    "max_bytes": max_bytes,
                },
            }
            if best is None or score > float(best.get("_score", -1)):
                result["_score"] = score
                best = result
    if best is not None:
        best.pop("_score", None)
        identity = output_buffer_identity(
            address_space="image",
            address=best.get("virtual_address"),
            length=best.get("length"),
        )
        if identity is not None:
            best["output_buffer"] = identity
    return best or {
        "status": "UNVERIFIED_STATIC_CANDIDATE",
        "reason": "data reference could not be mapped to file bytes",
    }


_CONFIG_DECODE_MARKERS = (
    b"http://",
    b"https://",
    b"ftp://",
    b"winhttp",
    b"wininet",
    b"urlmon",
    b"schtasks",
    b"explorer.exe",
    b"powershell",
    b"cmd.exe",
    b"rundll32",
    b"loadlibrary",
    b"getprocaddress",
    b"virtualalloc",
    b"createprocess",
)
_ROLLING_XOR_FAMILIES = (
    (3, 7, 0x3F),
    (3, 7, 0),
    (1, 1, 0),
)
# One compiled scan replaces `any(marker.lower() in decoded.lower() for marker in
# _CONFIG_DECODE_MARKERS)`.  All markers are ASCII, and every call site needs a
# case-insensitive byte test, so a single `re.IGNORECASE` pattern is exactly
# equivalent while avoiding 15 `bytes.lower()` calls per candidate - on the real
# sample the generator expression ran 24.4M times at line 945 and cost 24.9 s.
_CONFIG_DECODE_MARKER_PATTERN = re.compile(
    b"|".join(re.escape(marker) for marker in _CONFIG_DECODE_MARKERS),
    re.IGNORECASE,
)


def _decoded_has_config_marker(decoded: bytes) -> bool:
    """Case-insensitive marker test shared by the decode-candidate scans."""
    return _CONFIG_DECODE_MARKER_PATTERN.search(decoded) is not None


# NOTE on the remaining known cost, corrected by measurement.
#
# The earlier note here recorded that "`bytes.translate` cannot remove this: it maps byte VALUES
# through one table, so it cannot express a position-dependent mask".  That is true of `translate`,
# but the conclusion drawn from it - that the per-byte generator has to stay - was wrong.  The mask
# IS period-16 (`i % 16` for the key table, plus a counter term), so it can be materialised as a
# `bytes` mask of the cipher's length and applied with `bytes(map(operator.xor, cipher, mask))`, which
# runs the loop in C and creates no Python frame per byte.
#
# Measured on this machine over 20,000 decodes x 7 lengths x 4 counter/step pairs, all four
# implementations verified byte-identical:
#
#     per-byte generator (previous)   2.198 s   1.00x
#     list comprehension              2.424 s   0.91x
#     mask + bytes(map(xor))          1.680 s   1.31x
#     cached mask + bytes(map(xor))   1.593 s   1.38x
#
# Against the module's own figure of 9.5 s of a 16 s `analyze_bytes` for the 551 KB sample, the C-level
# form projects to 6.67 s, i.e. ~13.2 s total.  So this removes about a third of the decode-candidate
# cost, NOT all of it: the per-byte work is still O(candidates x length) and the candidate COUNT is
# what dominates (1.52M candidates for that sample, of which the marker gate keeps ~44k).  A further
# step would have to cut the candidate count itself rather than the per-candidate constant.
_MASK_CACHE: dict[tuple[bytes, int, int, int], bytes] = {}


def _masked_xor(cipher: bytes, table_bytes: bytes, counter0: int, step: int) -> bytes:
    """`cipher[i] ^ table[i % 16] ^ ((counter0 + i * step) & 0xFF)`, computed without a Python frame.

    The mask depends only on `(table, length, counter0, step)` - all four are part of the cache key, so
    a different key table can never reuse another table's mask.  The XOR itself is
    `bytes(map(operator.xor, ...))`, which releases the loop to C.
    """
    length = len(cipher)
    key = (table_bytes, length, counter0, step)
    mask = _MASK_CACHE.get(key)
    if mask is None:
        mask = bytes(
            table_bytes[i % 16] ^ ((counter0 + i * step) & 0xFF) for i in range(length)
        )
        _MASK_CACHE[key] = mask
    return bytes(map(_xor_bytes, cipher, mask))


def _xor_bytes(left: int, right: int) -> int:
    return left ^ right


_URL_DECODE_TOKEN = re.compile(rb"(?i)(?:https?|ftp)://[^\s\x00<>]{4,}")
_DLL_DECODE_TOKEN = re.compile(rb"(?i)[a-z][a-z0-9_-]{1,24}\.dll")
_API_DECODE_TOKEN = re.compile(rb"(?:WinHttp|Internet|WSA|Http)[A-Za-z][A-Za-z0-9]+")


def _trim_decoded_config(decoded: bytes) -> bytes:
    """Keep a leading URL, DLL, or API token when rolling XOR leaves a tail."""
    url = _URL_DECODE_TOKEN.match(decoded)
    if url is not None:
        return url.group(0)
    dll = _DLL_DECODE_TOKEN.match(decoded)
    if dll is not None:
        return dll.group(0)
    api = _API_DECODE_TOKEN.match(decoded)
    if api is not None:
        return api.group(0)
    return decoded


def _decode_config_hit(
    decoded: bytes,
    *,
    offset: int,
    va: int,
    metadata: Mapping[str, object],
    content: bytes,
) -> dict[str, object] | None:
    """The one marker/printability gate every static decode candidate must pass.

    Both the rolling-XOR families in :func:`recover_static_xor_configs` and the
    ``decode_primitives`` candidates in :func:`recover_primitive_decode_configs`
    run through here, so an additional candidate source cannot smuggle in rows
    the downstream verifier and the ADR-0035 consumer Join were never sized for.
    Returns ``None`` when the candidate carries no configuration marker or is
    not printable enough to be a recovered config.
    """
    nul = decoded.find(b"\x00")
    if 8 <= nul <= len(decoded):
        visible = decoded[:nul]
    else:
        matched = re.match(rb"[\x20-\x7e]{8,}", decoded)
        visible = matched.group(0) if matched else decoded
    visible = _trim_decoded_config(visible)
    markers = [
        marker.decode("ascii")
        for marker in _CONFIG_DECODE_MARKERS
        if marker.lower() in visible.lower()
    ]
    if not markers:
        return None
    printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in visible) / max(
        1, len(visible)
    )
    if printable < 0.55:
        return None
    text = visible[:512].decode("utf-8", errors="replace")
    return {
        "status": "VERIFIED_STATIC_DATA",
        "file_offset": offset,
        "virtual_address": va,
        "length": len(visible),
        "printable_ratio": round(printable, 4),
        "markers": markers,
        "decoded_preview": text[:128],
        "decoded_text": text,
        "decoded_strings": [
            part.decode("utf-8", errors="replace")
            for part in re.findall(rb"[\x20-\x7e]{4,}", decoded[:1024])[:16]
        ],
        "ciphertext_hex": content[offset : offset + min(len(decoded), 256)].hex(),
        "plaintext_hex": decoded[: min(len(decoded), 256)].hex(),
        "output_buffer": {
            "address_space": "image",
            "address": va,
            "length": len(visible),
        },
        **dict(metadata),
        "verification_scope": {
            "source_file_offset": offset,
            "source_virtual_address": va,
            "max_bytes": len(decoded),
        },
    }


def recover_static_xor_configs(
    content: bytes,
    pe_summary: Mapping[str, object] | None = None,
    *,
    max_hits: int = 24,
) -> tuple[dict[str, object], ...]:
    """Replay bounded rolling-XOR families against PE readable sections.

    Ghidra metadata is not required.  Hits are kept only when decoded bytes
    contain a configuration marker (URL, common loader/network APIs, scheduler, or explorer).
    This does not execute the sample.
    """
    summary = pe_summary or {}
    image_base = int(summary.get("image_base", 0) or 0)
    sections = summary.get("sections", [])
    section_rows = [item for item in sections if isinstance(item, Mapping)] if isinstance(sections, list) else []
    if not section_rows:
        section_rows = [
            {
                "name": ".blob",
                "virtual_address": 0,
                "virtual_size": len(content),
                "raw_size": len(content),
                "raw_offset": 0,
            }
        ]
    hits: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()

    def keep(decoded: bytes, *, offset: int, va: int, metadata: Mapping[str, object]) -> None:
        if len(hits) >= max(max_hits * 4, 64):
            return
        row = _decode_config_hit(
            decoded, offset=offset, va=va, metadata=metadata, content=content
        )
        if row is None:
            return
        identity = (offset, str(metadata.get("formula") or ""))
        if identity in seen:
            existing = next(
                (item for item in hits if item.get("file_offset") == offset and item.get("formula") == metadata.get("formula")),
                None,
            )
            if existing is None or int(row.get("length") or 0) <= int(existing.get("length") or 0):
                return
            hits.remove(existing)
        else:
            seen.add(identity)
        hits.append(row)

    for section in section_rows:
        raw_offset = int(section.get("raw_offset", 0) or 0)
        raw_size = min(int(section.get("raw_size", 0) or 0), 65536, max(0, len(content) - raw_offset))
        if raw_size < 12:
            continue
        raw = content[raw_offset : raw_offset + raw_size]
        va_base = int(section.get("virtual_address", 0) or 0)
        section_name = str(section.get("name") or "").casefold().rstrip("\x00")
        # Config blobs live in readable data.  Scanning .text at byte
        # granularity is too expensive and not where these tables sit.
        table_stride = 1 if any(token in section_name for token in (".rdata", ".data", ".rsrc")) else 4
        # Prefer adjacent table+ciphertext pairs in readable data.  Encoded
        # C2/API blobs often sit immediately after a 16-byte key table.
        for table_off in range(0, max(0, len(raw) - 28), table_stride):
            table_bytes = raw[table_off : table_off + 16]
            if len(set(table_bytes)) < 8:
                continue
            for length in (10, 16, 24, 31, 32, 48, 64):
                cipher = raw[table_off + 16 : table_off + 16 + length]
                if len(cipher) < 10:
                    continue
                for counter0 in (0, 3):
                    for step in (1, 7):
                        decoded = _masked_xor(cipher, table_bytes, counter0, step)
                        # `keep` delegates to `_decode_config_hit`, which returns
                        # None unless a marker is present.  Calling it first
                        # therefore could only ever return None for a marker-free
                        # candidate, so test the marker once and use the result for
                        # both gates: the real `keep`, and the extended pre-window
                        # scan below.  On the real sample this removes ~1.57M
                        # `_decode_config_hit` calls (34 s) and the second call that
                        # the inner loop used to make for the same bytes.
                        has_marker = _decoded_has_config_marker(decoded)
                        if not has_marker:
                            continue
                        keep(
                            decoded,
                            offset=raw_offset + table_off + 16,
                            va=(image_base + va_base + table_off + 16) if image_base else va_base + table_off + 16,
                            metadata={
                                "key_table": list(table_bytes),
                                "counter_initial": counter0,
                                "counter_step": step,
                                "formula": "key_table_modulo_xor_counter",
                            },
                        )
                        for pre_len in range(10, 65):
                            if table_off < pre_len:
                                continue
                            pre = raw[table_off - pre_len : table_off]
                            decoded_pre = _masked_xor(pre, table_bytes, counter0, step)
                            keep(
                                decoded_pre,
                                offset=raw_offset + table_off - pre_len,
                                va=(image_base + va_base + table_off - pre_len) if image_base else va_base + table_off - pre_len,
                                metadata={
                                    "key_table": list(table_bytes),
                                    "counter_initial": counter0,
                                    "counter_step": step,
                                    "formula": "key_table_modulo_xor_counter",
                                },
                            )
        if any(token in section_name for token in (".rdata", ".data")):
            # Independently encoded C-string prefixes (WinHTTP names) are not
            # packed behind one table and are not NUL-terminated.  Replay the
            # rolling key+const family at each offset and keep marker hits.
            for off in range(0, max(0, len(raw) - 8)):
                for key0, step, extra in _ROLLING_XOR_FAMILIES:
                    decoded = bytearray()
                    for index in range(min(40, len(raw) - off)):
                        byte = raw[off + index] ^ ((key0 + index * step) & 0xFF) ^ extra
                        if not (32 <= byte <= 126):
                            break
                        decoded.append(byte)
                    if len(decoded) < 8:
                        continue
                    keep(
                        bytes(decoded),
                        offset=raw_offset + off,
                        va=(image_base + va_base + off) if image_base else va_base + off,
                        metadata={
                            "initial_key": key0,
                            "key_step": step,
                            "xor_const": extra,
                            "formula": "single_key_plus_step_xor_const",
                        },
                    )
        spans: list[tuple[int, int]] = []
        index = 0
        while index < len(raw) and len(spans) < 48:
            window = raw[index : index + 16]
            if len(window) < 8:
                break
            printable = sum(32 <= byte <= 126 for byte in window) / len(window)
            if printable < 0.5:
                length = min(80, len(raw) - index)
                spans.append((index, max(12, length)))
                index += 8
            else:
                index += 4
        for span_off, span_len in spans:
            blob = raw[span_off : span_off + span_len]
            file_offset = raw_offset + span_off
            va = image_base + va_base + span_off if image_base else va_base + span_off
            for key in (1, 3, 7, 16, 0x3F):
                for step in (1, 3, 7, 16):
                    for extra in (0, 0x3F):
                        decoded = bytes(
                            blob[i] ^ ((key + i * step) & 0xFF) ^ extra for i in range(len(blob))
                        )
                        formula = (
                            "single_key_plus_step"
                            if extra == 0
                            else "single_key_plus_step_xor_const"
                        )
                        keep(
                            decoded,
                            offset=file_offset,
                            va=va,
                            metadata={
                                "initial_key": key,
                                "key_step": step,
                                "xor_const": extra,
                                "formula": formula,
                            },
                        )
            table_candidates: list[tuple[int, bytes, bytes]] = []
            if len(blob) > 28:
                table_candidates.append((file_offset + 16, blob[:16], blob[16:]))
            for rel in (-32, -16, span_len, span_len + 16):
                table_at = span_off + rel
                if table_at < 0 or table_at + 16 > len(raw):
                    continue
                table_bytes = raw[table_at : table_at + 16]
                table_candidates.append((file_offset, table_bytes, blob))
            for cipher_off, table_bytes, cipher in table_candidates:
                if len(table_bytes) != 16 or len(cipher) < 12:
                    continue
                if len(set(table_bytes)) < 8:
                    continue
                for counter0 in (0, 3):
                    for step in (1, 7):
                        decoded = _masked_xor(cipher, table_bytes, counter0, step)
                        keep(
                            decoded,
                            offset=cipher_off,
                            va=va + (cipher_off - file_offset),
                            metadata={
                                "key_table": list(table_bytes),
                                "counter_initial": counter0,
                                "counter_step": step,
                                "formula": "key_table_modulo_xor_counter",
                            },
                        )
        if len(hits) >= max(max_hits * 4, 64):
            break
    def _marker_rank(item: Mapping[str, object]) -> tuple[int, int, int, int]:
        markers = [str(marker).casefold() for marker in item.get("markers") or []]
        has_url = any(
            marker.startswith("http://") or marker.startswith("https://") or marker.startswith("ftp://")
            for marker in markers
        )
        has_api_name = any(
            token in marker
            for marker in markers
            for token in ("winhttp", "wininet", "urlmon", "loadlibrary", "getprocaddress")
        )
        return (
            0 if has_url else 1,
            0 if has_api_name else 1,
            -int(item.get("length") or 0),
            int(item.get("file_offset") or 0),
        )

    hits.sort(key=_marker_rank)
    return tuple(hits[:max_hits])


# Wiring A: bounded seed/key material is taken from the section's own 16-byte
# tables, never invented, so every candidate this pass emits is anchored to bytes
# that are present in the sample.
_PRIMITIVE_CIPHER_LENGTHS = (32, 48, 64)
_PRIMITIVE_TABLE_STRIDE = 1
_PRIMITIVE_MAX_TABLES = 96


def recover_primitive_decode_configs(
    content: bytes,
    pe_summary: Mapping[str, object] | None = None,
    *,
    max_hits: int = 24,
) -> tuple[dict[str, object], ...]:
    """Additional static decode candidates from the audited primitive library.

    This is an *additional candidate source* next to
    :func:`recover_static_xor_configs`, not a replacement and not a judge:

    * key material is the section's own 16-byte tables (the same
      "at least 8 distinct bytes" rule the rolling-XOR scan uses), and the LCG
      seeds are those tables read as little-endian ``uint32`` -- nothing is
      guessed, so a candidate can always be traced back to sample bytes;
    * every candidate passes the same :func:`_decode_config_hit` marker and
      printability gate the rolling-XOR families pass;
    * rows carry the same keys, so the existing verifier and the ADR-0035
      ``decoded_output_consumer`` Join decide whether a consumer exists.  If no
      object-level consumer is recovered the slot stays ``UNKNOWN(consumer)``.

    ``decrypt_candidates`` covers families the rolling-XOR replay does not:
    RC4 over a table key, the CR-001/CR-011/CR-013 LCG variants, and the CR-007
    substitution table.  Nothing here executes the sample.
    """
    summary = pe_summary or {}
    image_base = int(summary.get("image_base", 0) or 0)
    sections = summary.get("sections", [])
    section_rows = (
        [item for item in sections if isinstance(item, Mapping)]
        if isinstance(sections, list)
        else []
    )
    if not section_rows:
        section_rows = [
            {
                "name": ".blob",
                "virtual_address": 0,
                "virtual_size": len(content),
                "raw_size": len(content),
                "raw_offset": 0,
            }
        ]
    hits: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()
    tables_scanned = 0

    for section in section_rows:
        if tables_scanned >= _PRIMITIVE_MAX_TABLES:
            break
        raw_offset = int(section.get("raw_offset", 0) or 0)
        raw_size = min(
            int(section.get("raw_size", 0) or 0), 65536, max(0, len(content) - raw_offset)
        )
        if raw_size < 28:
            continue
        raw = content[raw_offset : raw_offset + raw_size]
        va_base = int(section.get("virtual_address", 0) or 0)
        section_name = str(section.get("name") or "").casefold().rstrip("\x00")
        # Same rule as the rolling-XOR scan: readable data gets byte granularity
        # because that is where key tables sit, everything else is walked coarsely
        # rather than skipped -- otherwise the no-PE-summary ``.blob`` fallback
        # would never be covered at all.
        table_stride = (
            1
            if any(token in section_name for token in (".rdata", ".data", ".rsrc"))
            else 4
        )
        for table_off in range(0, max(0, len(raw) - 28), table_stride):
            if tables_scanned >= _PRIMITIVE_MAX_TABLES:
                break
            table_bytes = raw[table_off : table_off + 16]
            if len(set(table_bytes)) < 8:
                continue
            tables_scanned += 1
            seed = int.from_bytes(table_bytes[:4], "little")
            for length in _PRIMITIVE_CIPHER_LENGTHS:
                cipher = raw[table_off + 16 : table_off + 16 + length]
                if len(cipher) < 12:
                    continue
                for candidate in decrypt_candidates(
                    cipher, keys=(table_bytes,), seeds=(seed,)
                ):
                    algorithm = str(candidate.get("algorithm") or "")
                    label = str(candidate.get("key_or_seed") or "")
                    plaintext = candidate.get("plaintext")
                    if not algorithm or not isinstance(plaintext, (bytes, bytearray)):
                        continue
                    formula = f"decode_primitive:{algorithm}"
                    file_offset = raw_offset + table_off + 16
                    va = (
                        image_base + va_base + table_off + 16
                        if image_base
                        else va_base + table_off + 16
                    )
                    row = _decode_config_hit(
                        bytes(plaintext),
                        offset=file_offset,
                        va=va,
                        metadata={
                            "formula": formula,
                            "decode_primitive": algorithm,
                            "key_or_seed": label,
                            "key_table": list(table_bytes),
                            "primitive_source": "decode_primitives",
                        },
                        content=content,
                    )
                    if row is None:
                        continue
                    identity = (file_offset, formula + label)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    hits.append(row)
                    if len(hits) >= max(max_hits * 4, 64):
                        break
                if len(hits) >= max(max_hits * 4, 64):
                    break
            if len(hits) >= max(max_hits * 4, 64):
                break

    def _primitive_rank(item: Mapping[str, object]) -> tuple[int, int, int]:
        markers = [str(marker).casefold() for marker in item.get("markers") or []]
        has_url = any(
            marker.startswith(("http://", "https://", "ftp://")) for marker in markers
        )
        return (
            0 if has_url else 1,
            -len(markers),
            -int(item.get("length") or 0),
        )

    hits.sort(key=_primitive_rank)
    return tuple(hits[:max_hits])


# A single function's non-call reference set is a recovered-data inventory, not
# a display page.  The previous ``rows[:64]`` cut was silent data loss: on the
# 551KB Rust PE 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145
# Ghidra reports 871 non-call references from FUN_140004605 and the Windows
# Defender registry block (LEA RAX,[0x14004c3b9] ... MAPSReporting /
# SpynetReporting) sits at reference ordinals 619-909, i.e. entirely past the
# cut.  The reference set never became Evidence, so no later stage could state
# the tampering.  This constant is therefore a degenerate-input guard against a
# crafted image that makes the exporter emit a reference per byte -- it is not
# an analysis quota.  4096 is ~2.5x the largest set observed on the live system
# (1615 non-call references, 4.5 MB exporter JSON, 704 recovered functions) and
# 64x the median (7).  When the guard does fire the dropped count is recorded in
# the payload, so a reader can never mistake a capped set for an empty one.
MAX_FUNCTION_DATA_REFERENCES = 4096

# The stored instruction window IS the analysed function body (the abstract
# executor, CFG slice and decompile projections all read it), so a bounded
# preview is not a substitute for the function.  A 256-item preview kept 418 of
# ``FUN_140004605``'s 4481 instructions on the sample above and omitted every
# LEA in its Windows Defender registry block.  This constant is the
# degenerate-input guard for that seam -- not a quota.  65_536 is ~15x the
# largest function observed on the live system (4481 instructions; the whole
# 704-function exporter dump is 4.5 MB of instruction JSON) and the complete
# exporter JSON stays in object storage regardless.  When the guard does fire,
# :func:`build_instruction_window_payload` records
# ``instructions_total`` / ``instructions_selected`` / ``instructions_omitted``
# so a cut window can never be read as a short function.
MAX_INSTRUCTION_WINDOW_ITEMS = 65_536


def correlate_data_references(
    function: dict[str, object],
    strings_by_address: dict[str, str] | None = None,
    *,
    max_references: int | None = None,
) -> tuple[dict[str, object], ...]:
    """Associate every non-call reference with printable data when known.

    The complete recovered reference set is returned.  ``max_references`` is a
    degenerate-input guard only; passing it does not change the shape of a row,
    and the caller can learn the drop count from
    :func:`data_reference_truncation`.
    """
    mapping = strings_by_address or {}
    references = function.get("references_from", [])
    if not isinstance(references, list):
        return ()
    limit = MAX_FUNCTION_DATA_REFERENCES if max_references is None else int(max_references)
    rows: list[dict[str, object]] = []
    for reference in references:
        if not isinstance(reference, dict) or "call" in str(reference.get("type", "")).lower():
            continue
        target = str(reference.get("to", ""))
        text = mapping.get(target)
        rows.append(
            {
                "from": reference.get("from"),
                "to": target,
                "reference_type": reference.get("type"),
                "target_name": reference.get("target_name"),
                "resolved_string": text[:512] if isinstance(text, str) else None,
            }
        )
        if limit > 0 and len(rows) >= limit:
            break
    return tuple(rows)


def data_reference_truncation(
    function: Mapping[str, object],
    correlated: Sequence[Mapping[str, object]],
    *,
    max_references: int | None = None,
) -> dict[str, object] | None:
    """Describe a degenerate-guard cut so a capped set is never read as empty.

    Returns ``None`` while the guard is not binding, which is the normal case.
    """
    references = function.get("references_from", [])
    if not isinstance(references, list):
        return None
    available = sum(
        1
        for reference in references
        if isinstance(reference, Mapping)
        and "call" not in str(reference.get("type", "")).lower()
    )
    limit = MAX_FUNCTION_DATA_REFERENCES if max_references is None else int(max_references)
    kept = len(correlated)
    if available <= kept:
        return None
    return {
        "reason": "degenerate_input_guard",
        "guard": "MAX_FUNCTION_DATA_REFERENCES",
        "limit": limit,
        "references_total": available,
        "references_kept": kept,
        "references_dropped": available - kept,
        "complete_exporter_json": "object storage retains every reference",
    }


def resolve_static_data_strings(
    content: bytes,
    addresses: list[str],
    pe_summary: dict[str, object] | None = None,
    *,
    max_length: int = 512,
    allow_printable_prefix: bool = False,
    max_addresses: int = 256,
) -> dict[str, str]:
    """Resolve a bounded set of virtual addresses to printable file strings.

    ``max_addresses`` bounds *one call*, not one task.  It is a per-call guard
    against an unbounded address list, and it must not be used as a task-wide
    resolution budget: the caller that builds the shared table iterates tens of
    thousands of addresses, and a flat 256 silently resolved 78 of 9727 on the
    551KB Rust PE 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145
    -- including every Windows Defender registry literal.  Pass the addresses
    in chunks (see :func:`resolve_function_data_strings`) so every address is
    resolved while each individual call stays bounded.

    ``allow_printable_prefix`` keeps the printable head of a literal whose
    window is followed by non-text bytes.  The MSVC linker merges adjacent
    ``.rdata`` literals into one NUL-terminated blob, so a compared parent
    image such as ``explorer.exe`` can be immediately followed by the error
    templates of the same function; the strict UTF-8 decode aborts on those
    bytes and the address would otherwise be dropped entirely.  The default
    stays strict so the shared task-wide string table does not change.
    """
    summary = pe_summary or {}
    image_base = int(summary.get("image_base", 0) or 0)
    sections = summary.get("sections", [])
    section_rows = sections if isinstance(sections, list) else []
    resolved: dict[str, str] = {}
    for raw_address in addresses[: max(1, int(max_addresses))]:
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
            span = max(
                int(section.get("virtual_size", 0) or 0), int(section.get("raw_size", 0) or 0)
            )
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
        except UnicodeDecodeError as error:
            if not allow_printable_prefix or error.start <= 0:
                try:
                    text = candidate.decode("utf-16le").rstrip("\x00")
                except UnicodeDecodeError:
                    continue
            else:
                try:
                    text = candidate[: error.start].decode("utf-8")
                except UnicodeDecodeError:
                    continue
        if (
            text
            and sum(character.isprintable() or character in "\r\n\t" for character in text)
            / len(text)
            >= 0.8
        ):
            resolved[str(raw_address)] = text[:max_length]
    return resolved


_LITERAL_ADDRESS_RE = re.compile(r"(?i)(?:0x)?[0-9a-f]{6,}")
_STATIC_STRING_RESOLVE_CHUNK = 256


def resolve_data_strings_chunked(
    content: bytes,
    addresses: Iterable[object],
    pe_summary: Mapping[str, object] | None = None,
    *,
    max_addresses: int = 65_536,
) -> dict[str, str]:
    """Resolve *every* address, in bounded chunks, instead of the first 256.

    ``resolve_static_data_strings`` bounds one call so it cannot walk an
    unbounded list.  The shared task-wide table needs more than one call:
    iterating the recovered non-call reference targets of the 551KB Rust PE
    6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145 yields
    9727 distinct addresses of which 6522 carry a printable literal, but a flat
    call resolved 78 -- dropping every Windows Defender registry literal, so no
    later join could name the key it writes.  Chunking keeps each call bounded
    while resolving the whole recovered set.

    ``max_addresses`` is a degenerate-input guard, not a quota: 65_536 is ~6.7x
    the largest address set observed on the live system (9727 for this sample)
    and the complete exporter JSON stays in object storage regardless.
    """
    summary = dict(pe_summary or {})
    ordered: list[str] = []
    seen: set[str] = set()
    budget = max(1, int(max_addresses))
    for raw in addresses:
        key = str(raw or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(key)
        if len(ordered) >= budget:
            break
    resolved: dict[str, str] = {}
    for start in range(0, len(ordered), _STATIC_STRING_RESOLVE_CHUNK):
        chunk = ordered[start : start + _STATIC_STRING_RESOLVE_CHUNK]
        for address, text in resolve_static_data_strings(
            content,
            chunk,
            summary,
            allow_printable_prefix=True,
        ).items():
            resolved.setdefault(address, text)
    return resolved


def resolve_function_data_strings(
    content: bytes,
    function: Mapping[str, object],
    pe_summary: Mapping[str, object] | None = None,
    *,
    max_addresses: int = 4096,
) -> dict[str, str]:
    """Resolve the data literals one static function names, past the per-call cap.

    ``resolve_static_data_strings`` bounds a single call, so a function that
    names hundreds of data addresses keeps losing the literal it actually
    compares against: the Resume PPID orchestrator ``FUN_140004605`` names 1146
    distinct literals and the ``explorer.exe`` blob sits at index 831.  Joins
    that need one specific literal therefore resolve their *own* addresses in
    bounded chunks and merge the result locally.
    """

    if not content or not isinstance(function, Mapping):
        return {}
    sources: list[object] = [
        row.get("text")
        for row in (function.get("instructions") or ())
        if isinstance(row, Mapping)
    ]
    for key in ("data_references", "references_from", "call_targets"):
        for row in function.get(key) or ():
            if isinstance(row, Mapping):
                sources.append(row.get("to") or row.get("target") or row.get("address"))
    addresses: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for match in _LITERAL_ADDRESS_RE.finditer(str(source or "")):
            key = match.group(0)[2:] if match.group(0)[:2].casefold() == "0x" else match.group(0)
            key = key.casefold()
            if key in seen:
                continue
            seen.add(key)
            addresses.append(key)
            if len(addresses) >= max(1, max_addresses):
                break
        if len(addresses) >= max(1, max_addresses):
            break
    return resolve_data_strings_chunked(
        content,
        addresses,
        pe_summary,
        max_addresses=max(1, max_addresses),
    )


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
                        if any(
                            call.get(field) and str(call.get(field)) == target
                            for field in dispatch_fields
                        )
                        else "direct_call"
                    )
        # Static simulation adapters may attach resolved pointer links instead
        # of mutating the original Ghidra call rows.  Consume those links as
        # indirect edges while preserving their provenance.
        pointer_links = (
            function.get("indirect_function_pointer_links") or function.get("indirect_calls") or []
        )
        if isinstance(pointer_links, list):
            for link in pointer_links:
                if not isinstance(link, Mapping):
                    continue
                target = str(
                    link.get("target_function")
                    or link.get("resolved_target")
                    or link.get("consumer_function")
                    or ""
                )
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
            if category in {
                "dynamic_resolution",
                "network",
                "execution",
                "persistence",
                "file_io",
                "loader",
            }:
                result.add("loader" if category == "loader" else category)
            if is_anti_analysis_signal(name):
                result.add("anti_analysis")
        return result

    paths: list[dict[str, object]] = []
    for start, function in by_name.items():
        start_categories = categories(function)
        if not start_categories:
            continue
        queue: list[tuple[str, tuple[str, ...], set[str]]] = [
            (start, (start,), set(start_categories))
        ]
        while queue:
            current, path, path_categories = queue.pop(0)
            if len(path) >= 2 and len(path_categories) >= 2:
                paths.append(
                    {
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
                    }
                )
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
    for label, table in (
        ("RC4 ascending S-box candidate", rc4),
        ("RC4 descending S-box candidate", reverse_rc4),
    ):
        start = 0
        while len(candidates) < 16:
            offset = data.find(table, start)
            if offset < 0:
                break
            candidates.append(
                {"algorithm": "RC4", "pattern": label, "file_offset": offset, "table_size": 256}
            )
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
_STRING_COMMAND_RE = re.compile(
    r"(?i)(?:^|\s)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|rundll32|regsvr32|wscript|cscript)(?:\s|$)"
)
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
    quality = (
        "HIGH"
        if category not in {"UNKNOWN", "CODE_BYTE_FALSE_POSITIVE"}
        and (xref_count or len(value) >= 6)
        else "LOW"
    )
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


_SEED_MECHANISM_PROFILES: dict[str, dict[str, object]] = {
    "dynamic_api": {
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "playbook_id": "dynamic-api-resolution",
        "question": "Which APIs are resolved statically, and which recovered consumer uses each resolved pointer?",
        "hypothesis_statement": "The artifact may resolve API addresses dynamically and route them to a statically visible consumer.",
        "hypothesis_dimension": "dynamic_api_resolution",
    },
    "decode": {
        "mechanism_type": "DECODE_CONFIG",
        "playbook_id": "xor-config-recovery",
        "question": "Which encoded input, transform, decoded output, and downstream consumer form the static decode path?",
        "hypothesis_statement": "The artifact may contain a bounded, recoverable decode path whose output feeds a later mechanism.",
        "hypothesis_dimension": "decode_recovery",
    },
    "network": {
        "mechanism_type": "HTTP_DOWNLOAD",
        "playbook_id": "http-download",
        "question": "Which endpoint or host, request path, response path, and response consumer are statically linked?",
        "hypothesis_statement": "The artifact may contain a statically recoverable transport path that receives data for a downstream consumer.",
        "hypothesis_dimension": "network_transport",
    },
    "execution": {
        "mechanism_type": "PROCESS_EXECUTION",
        "playbook_id": "process-execution",
        "question": "Which process API, inputs, flags, control condition, and downstream consumer form the static execution path?",
        "hypothesis_statement": "The artifact may construct a process or command execution path from statically traceable inputs.",
        "hypothesis_dimension": "process_execution",
    },
    "ppid": {
        "mechanism_type": "PPID_SPOOFING",
        "playbook_id": "ppid-process-chain",
        "question": "Does the artifact construct a parent-process spoofing chain, and which recovered handles prove it?",
        "hypothesis_statement": "The artifact may construct a child process with a spoofed parent identity through an attribute-list chain.",
        "hypothesis_dimension": "parent_process_spoofing",
    },
    "thread": {
        "mechanism_type": "THREAD_CALLBACK",
        "playbook_id": "",
        "question": "Which same-process OS thread start, parameter, loop, and exit are statically recovered?",
        "hypothesis_statement": "The artifact may start a same-process OS thread whose start routine is statically recoverable.",
        "hypothesis_dimension": "unique_os_thread",
    },
    "persistence": {
        "mechanism_type": "PERSISTENCE",
        "playbook_id": "",
        "question": "Which persistence-relevant input, write or command, condition, and consumer are statically linked?",
        "hypothesis_statement": "The artifact may contain a persistence-relevant path that requires an evidence-backed static reconstruction.",
        "hypothesis_dimension": "persistence",
    },
    "evasion": {
        "mechanism_type": "EVASION",
        "playbook_id": "",
        "question": "Which anti-analysis or evasion control, target, condition, and side effect are statically linked?",
        "hypothesis_statement": "The artifact may contain an anti-analysis or evasion path requiring a mechanism-specific verifier.",
        "hypothesis_dimension": "evasion",
    },
    "pe_parser": {
        "mechanism_type": "ENTRY_TIMELINE",
        "playbook_id": "entrypoint-timeline",
        "question": "What bounded static control-flow path leaves the entrypoint and reaches a high-value mechanism?",
        "hypothesis_statement": "The artifact entrypoint may lead to a statically recoverable high-value behavior path.",
        "hypothesis_dimension": "entrypoint_timeline",
    },
}


_ARTIFACT_WIDE_SEED_CATEGORIES = frozenset(
    {"dynamic_api", "decode", "network", "execution", "ppid", "thread"}
)


def cluster_static_seeds(
    evidence: Iterable[Mapping[str, object]],
    *,
    max_clusters: int | None = 12,
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
        # Bare ``winhttp`` matches "WinHTTP export not found"; ``http://`` in a
        # decoded blob belongs to the decode thread. HTTP seeds need a recovered
        # transport API, not a missing-export string.
        (
            "network",
            (
                "winhttpopen",
                "winhttpsendrequest",
                "winhttpreceiveresponse",
                "winhttpconnect",
                "internetopen",
                "httpsendrequest",
                "wininet",
            ),
            22,
        ),
        ("execution", ("createprocess", "shellexecute", "winexec", "virtualalloc"), 22),
        # OpenProcess alone is forbidden as PPID proof. Seed only from the
        # attribute-list API, the recovered constant, or a persist-time relation.
        (
            "ppid",
            (
                "updateprocthreadattribute",
                "proc_thread_attribute_parent_process",
                "parent_handle_to_attribute",
            ),
            24,
        ),
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
        matches = [
            (candidate, weight)
            for candidate, terms, weight in priority_terms
            if any(term.casefold() in text for term in terms)
        ]
        # One function can resolve a transport API, decode its configuration,
        # and invoke a consumer.  Treating the first matching category as the
        # only seed silently discards the other open mechanism questions.
        # These are still bounded per category/function below.
        if not matches:
            matches = [("generic", 8)]
        if recovered_thread_start_address(value if isinstance(value, Mapping) else {}):
            matches.append(("thread", 23))
        function = ""
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        value_mapping = value if isinstance(value, Mapping) else {}
        # Ghidra-derived correlations often retain the function locator in a
        # nested ``source_anchors`` list instead of copying it to the top
        # level.  Recover that locator before falling back to an API/global
        # seed; otherwise a concrete function mechanism is downgraded to a
        # broad import question and never receives function-level deep mining.
        anchor_candidates: list[Mapping[str, object]] = [anchor, value_mapping]
        for container in (anchor, value_mapping):
            nested = container.get("source_anchors")
            if isinstance(nested, (list, tuple)):
                anchor_candidates.extend(
                    item for item in nested if isinstance(item, Mapping)
                )
        for candidate in anchor_candidates:
            for key in ("function_entry", "entry", "rva"):
                if candidate.get(key) not in (None, ""):
                    function = str(candidate[key])
                    break
            if function:
                break
        for category, score in matches:
            profile = _SEED_MECHANISM_PROFILES.get(category, {})
            if category in _ARTIFACT_WIDE_SEED_CATEGORIES:
                identity = category
            else:
                identity = f"{category}:{function or str(value.get('api') or value.get('name') or '')[:80].casefold()}"
            group = groups.setdefault(
                identity,
                {
                    "category": category,
                    "priority": score,
                    "evidence_ids": [],
                    "function": function or None,
                    "question": profile.get(
                        "question",
                        "What input, transformation/control, output, consumer, and side effect are statically linked?",
                    ),
                    "hypothesis_statement": profile.get(
                        "hypothesis_statement",
                        "The artifact may contain an ordered static mechanism requiring evidence-backed reconstruction.",
                    ),
                    "hypothesis_dimension": profile.get("hypothesis_dimension", "mechanism_discovery"),
                    "mechanism_type": profile.get("mechanism_type", "GENERIC_MECHANISM_INVESTIGATION"),
                    "playbook_id": profile.get("playbook_id", ""),
                    "hypotheses": [
                        "intended security-relevant behavior",
                        "benign/library or parser use",
                        "unresolved static boundary",
                    ],
                },
            )
            group["priority"] = max(int(group["priority"]), score)
            if function and group.get("function") not in (None, "", function):
                group["function"] = None
            ids = group["evidence_ids"]
            if isinstance(ids, list) and len(ids) < max_evidence_per_cluster:
                ids.append(str(row["id"]))
    ranked = sorted(
        groups.values(),
        key=lambda row: (
            -int(row["priority"]),
            str(row["category"]),
            str(row.get("function") or ""),
        ),
    )
    output: list[dict[str, object]] = []
    selected = ranked if max_clusters is None else ranked[: max(1, max_clusters)]
    for index, row in enumerate(selected, 1):
        output.append({"id": f"seed-cluster-{index:03d}", **row, "static_only": True})
    return tuple(output)


def build_investigation_seed_map(
    evidence: Iterable[Mapping[str, object]],
    *,
    max_clusters: int = 12,
) -> dict[str, object]:
    """Return a bounded, serializable seed-map suitable for a model turn."""
    # Keep the visible map bounded for prompts/reports, but count the complete
    # deterministic frontier before truncation.  The count lets the scheduler
    # and UI distinguish "no seed" from "seed deferred by the current
    # admission window" instead of silently presenting a partial analysis.
    materialized = tuple(evidence)
    all_clusters = cluster_static_seeds(materialized, max_clusters=None)
    clusters = all_clusters[: max(1, max_clusters)]
    high_value = [item for item in clusters if int(item.get("priority", 0)) >= 18]
    return {
        "clusters": [dict(item) for item in clusters],
        "cluster_count": len(clusters),
        "total_cluster_count": len(all_clusters),
        "deferred_cluster_count": max(0, len(all_clusters) - len(clusters)),
        "high_value_cluster_count": len(high_value),
        "visible_candidate_budget": max_clusters,
        "static_only": True,
    }


def recognize_hash_algorithm(
    instructions: Iterable[Mapping[str, object] | str],
) -> dict[str, object]:
    """Recognize common export/API hash loops from operation evidence.

    Recognition requires an operation pattern; magic constants alone are not
    treated as proof.  The result is a resolver hypothesis for later matching.
    """
    texts = [
        str(item.get("text", "")) if isinstance(item, Mapping) else str(item)
        for item in instructions
    ]
    joined = " ; ".join(texts).casefold()
    constants = sorted(
        {
            int(token, 0)
            for token in re.findall(r"(?<![a-z0-9_])(?:0x[0-9a-f]+|\d+)(?![a-z0-9_])", joined)
        }
    )
    patterns: list[str] = []
    algorithm = "unknown"
    confidence = "LOW"
    if re.search(r"(?:0x0*1505|\b5381\b)", joined) and (
        re.search(r"0x0*21|\b33\b", joined) or ("imul" in joined and "add" in joined)
    ):
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
        output.append(
            {
                "hash": f"0x{value:08x}",
                "matches": matches[:32],
                "status": "RESOLVED" if matches else "UNRESOLVED",
                "static_only": True,
            }
        )
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
    calls.extend(row for row in function.get("call_targets", []) if isinstance(row, Mapping))
    data_references = [
        row for row in function.get("data_references", []) if isinstance(row, Mapping)
    ]
    resolver_calls: list[dict[str, object]] = []
    for row in calls:
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        ref_type = str(row.get("type") or row.get("reference_type") or "").casefold()
        if (
            name
            and not (name.casefold().startswith("ptr_") and "call" not in ref_type)
            and any(
                token in name.casefold()
                for token in ("getprocaddress", "ldrgetprocedureaddress", "loadlibrary")
            )
        ):
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
            if api and any(
                token in api.casefold()
                for token in ("getprocaddress", "ldrgetprocedureaddress", "loadlibrary")
            ):
                import_slot_apis[_slot_key(row.get("to") or target_name)] = api
                import_slot_apis[_slot_key(target_name)] = api
    last_resolver_call: dict[str, object] | None = None
    returned_pointer_register = "RAX"
    links: list[dict[str, object]] = []
    for index, row in enumerate(instructions):
        text = str(row.get("text") or "").strip()
        address = row.get("address") or row.get("from")
        if re.search(
            r"(?i)\bCALL\s+(?:\[[^\]]+\]\s*)?(?:GetProcAddress|LdrGetProcedureAddress|LoadLibrary[A-W]?)\b",
            text,
        ):
            api_name = re.search(
                r"(?i)(GetProcAddress|LdrGetProcedureAddress|LoadLibrary[A-W]?)", text
            )
            last_resolver_call = {
                "name": api_name.group(1) if api_name else "dynamic resolver",
                "address": address,
            }
        load = re.search(
            r"(?i)\b(?:MOV|LEA)\s+([A-Z][A-Z0-9]*)\s*,\s*(?:qword\s+ptr\s+)?\[([^\]]+)\]", text
        )
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
            prior = last_resolver_call or next(
                (item for item in reversed(resolver_calls) if item.get("address") is not None), None
            )
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
            item
            for key, item in slots.items()
            if (slot and key == slot.casefold())
            or (register and item.get("register") == register)
            or (loaded_slot and key == loaded_slot.casefold())
        ]
        for stored in candidates:
            resolver = stored.get("resolver") or {}
            links.append(
                {
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
                }
            )
        # A resolver's return value is commonly consumed directly by ``JMP
        # RAX`` (or ``CALL RAX``) after being stored in a global slot.  This is
        # a valid returned-pointer consumer even when no second load exists.
        if register == returned_pointer_register and last_resolver_call:
            stored_slots = [
                item
                for item in slots.values()
                if item.get("register") == returned_pointer_register
                and int(item.get("store_index", -1)) <= index
            ]
            if stored_slots:
                for stored in stored_slots:
                    links.append(
                        {
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
                        }
                    )
    # Context-level fallback for stripped/partial Ghidra exports.  Require a
    # resolver call, a writable global/pointer slot, and an explicitly typed
    # COMPUTED_CALL that targets that slot.  A slot write without a consumer is
    # intentionally left unresolved; imports and table bytes alone are not a
    # function-pointer call proof.
    data_references = [
        row for row in function.get("data_references", []) if isinstance(row, Mapping)
    ]
    stores: list[dict[str, object]] = []
    for row in data_references:
        ref_type = str(row.get("type") or row.get("reference_type") or "").upper()
        if "WRITE" not in ref_type:
            continue
        slot = str(row.get("target_name") or row.get("to") or "").strip()
        if not slot:
            continue
        stores.append(
            {
                "slot": slot,
                "store_address": row.get("from") or row.get("address"),
                "row": row,
            }
        )
    computed_calls = [
        row
        for row in [*calls, *data_references]
        if str(row.get("type") or row.get("reference_type") or "").upper() == "COMPUTED_CALL"
    ]
    resolver_candidates = [item for item in resolver_calls if item.get("address") is not None]
    for store in stores:
        slot_casefold = str(store["slot"]).casefold()
        consumers = [
            row
            for row in computed_calls
            if slot_casefold
            in str(
                row.get("target_name") or row.get("target_function") or row.get("to") or ""
            ).casefold()
        ]
        if not consumers:
            continue
        resolver = resolver_candidates[-1] if resolver_candidates else {}
        for consumer in consumers:
            links.append(
                {
                    "resolver": resolver.get("name"),
                    "resolver_callsite": resolver.get("address"),
                    "storage": store["slot"],
                    "storage_write": store["store_address"],
                    "consumer_callsite": consumer.get("from") or consumer.get("address"),
                    "consumer": consumer.get("target_name")
                    or consumer.get("target_function")
                    or consumer.get("to"),
                    "indirect": True,
                    "confidence": "MEDIUM" if resolver else "LOW",
                    "evidence_source": "function_context_data_references",
                    "static_only": True,
                }
            )
    # Preserve deterministic order and avoid duplicate rows when a future
    # exporter emits both instruction and context-level representations.
    deduped: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for link in links:
        key = (
            link.get("resolver_callsite"),
            link.get("storage"),
            link.get("consumer_callsite"),
            link.get("consumer"),
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
                "BRANCH_CONDITION"
                if any(token in upper for token in ("BRANCH", "CBRANCH", "INT_"))
                else "CALL"
                if "CALL" in upper
                else "MEMORY_ACCESS"
                if any(token in upper for token in ("LOAD", "STORE"))
                else "ARITHMETIC"
                if any(token in upper for token in ("INT_", "PTRADD", "SUBPIECE", "PIECE"))
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
                conditions.append(
                    {"address": row.get("address"), "expression": operation, "index": index}
                )
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
        elif any(
            token in upper
            for token in ("XOR ", "ADD ", "SUB ", "IMUL ", "ROL ", "ROR ", "SHL ", "SHR ")
        ):
            op = "ARITHMETIC"
        elif "[" in text and "]" in text:
            op = "MEMORY_ACCESS"
        item = {
            "op": op,
            "address": row.get("address"),
            "text": text,
            "index": index,
            "static_only": True,
        }
        operations.append(item)
        if op in {"CALL", "BRANCH_CONDITION", "MEMORY_ACCESS", "ARITHMETIC"}:
            critical.append(item)
    call_rows = [
        row
        for row in function.get("references_from", [])
        if isinstance(row, Mapping)
        and (
            "call" in str(row.get("type", "")).casefold()
            or row.get("target_name")
            or row.get("target_function")
            or row.get("api")
        )
    ]
    sinks = [
        {
            "api": str(
                row.get("target_name") or row.get("target_function") or row.get("api") or ""
            ),
            "callsite": row.get("from") or row.get("address"),
            "static_only": True,
        }
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
    *,
    callsite: object | None = None,
) -> tuple[dict[str, object], ...]:
    """Recover simple API argument producers from an ordered instruction view.

    ``callsite`` scopes the trace to one invocation when a function calls the
    same API more than once.  Without that scope, callers would receive a
    merged set of producers from every invocation and could attach a constant
    or string to the wrong API call in a mechanism chain.
    """
    target = str(api).casefold()
    requested_callsite = str(callsite or "").strip().casefold()
    rows = function.get("references_from", [])
    calls = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and target
        in str(
            row.get("target_name") or row.get("target_function") or row.get("api") or ""
        ).casefold()
        and (
            not requested_callsite
            or str(row.get("from") or row.get("address") or "").strip().casefold()
            == requested_callsite
        )
    ]
    # The persisted context and function-call projections can describe one
    # invocation twice.  Deduplicate by API identity and callsite before
    # producing argument rows so coverage/counts remain meaningful.
    unique_calls: list[Mapping[str, object]] = []
    seen_calls: set[tuple[str, str]] = set()
    for row in calls:
        row_api = str(
            row.get("target_name") or row.get("target_function") or row.get("api") or ""
        ).strip().casefold()
        row_site = str(row.get("from") or row.get("address") or "").strip().casefold()
        key = (row_api, row_site)
        if row_site and key in seen_calls:
            continue
        if row_site:
            seen_calls.add(key)
        unique_calls.append(row)
    calls = unique_calls
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    instruction_index_by_address = {
        str(row.get("address") or row.get("from") or "").strip().casefold(): index
        for index, row in enumerate(instructions)
        if str(row.get("address") or row.get("from") or "").strip()
    }
    result: list[dict[str, object]] = []
    # Windows x64 register ABI.  x86 callers use a push-based stack ABI; both
    # are normalised to argument_index so downstream consumers need no ABI
    # specific branching.
    registers = ("rcx", "rdx", "r8", "r9")
    x86_registers = {"ecx", "edx", "r8d", "r9d"}
    architecture = str(
        function.get("architecture") or function.get("calling_convention") or ""
    ).casefold()
    instruction_text = "\n".join(str(row.get("text") or "") for row in instructions)
    # A 64-bit prologue commonly starts with PUSH R15/RBX/etc.  Treating any
    # PUSH as an x86 stack argument (the old fallback) made every x64 call
    # inherit saved-register values.  Prefer explicit architecture metadata,
    # then use register/pointer width signals; only use x86 when no 64-bit
    # signal is present.
    explicit_x64 = bool(
        re.search(r"(?:x86[_ -]?64|amd64|x64|64[_ -]?bit)", architecture)
    )
    explicit_x86 = bool(
        re.search(r"(?:i[3-6]86|x86|32[_ -]?bit|win32)", architecture)
    ) and not explicit_x64
    has_64bit_operands = bool(
        re.search(
            r"\b(?:R(?:AX|BX|CX|DX|SI|DI|BP|SP|IP|[89]|1[0-5])|QWORD\s+PTR)\b",
            instruction_text,
            re.IGNORECASE,
        )
    )
    has_32bit_operands = bool(
        re.search(
            r"\b(?:E(?:AX|BX|CX|DX|SI|DI|BP|SP|IP)|DWORD\s+PTR)\b",
            instruction_text,
            re.IGNORECASE,
        )
    )
    is_x86 = explicit_x86 or (
        not explicit_x64 and has_32bit_operands and not has_64bit_operands
    )
    for call in calls:
        callsite = str(call.get("from") or call.get("address") or "")
        call_index = instruction_index_by_address.get(callsite.casefold(), len(instructions))
        if call_index == len(instructions) and callsite:
            # Preserve compatibility with exporters that qualify an address
            # with a namespace while keeping the common path O(1).
            for index, instruction in enumerate(instructions):
                if callsite.casefold() in str(
                    instruction.get("address") or instruction.get("from") or ""
                ).casefold():
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
                    pushed.append(
                        {
                            "source_kind": "constant",
                            "value": source,
                            "register": None,
                            "source_instruction": text,
                            "source_callsite": instruction.get("address") or instruction.get("from"),
                        }
                    )
                elif source.startswith("[") and source.endswith("]"):
                    source_kind = "stack_local" if re.search(
                        r"\b(?:RSP|ESP|RBP|EBP)\b", source, re.IGNORECASE
                    ) else "global"
                    pushed.append(
                        {
                            "source_kind": source_kind,
                            "value": source[1:-1],
                            "register": None,
                            "source_instruction": text,
                            "source_callsite": instruction.get("address") or instruction.get("from"),
                        }
                    )
                elif source.startswith(('"', "'")):
                    pushed.append(
                        {
                            "source_kind": "string",
                            "value": source.strip("\"'"),
                            "register": None,
                            "source_instruction": text,
                            "source_callsite": instruction.get("address") or instruction.get("from"),
                        }
                    )
                else:
                    pushed.append(
                        {
                            "source_kind": "unknown",
                            "value": source,
                            "register": None,
                            "source_instruction": text,
                            "source_callsite": instruction.get("address") or instruction.get("from"),
                        }
                    )
                continue
            call_match = re.match(r"(?i)CALL\s+(.+)$", text)
            if call_match:
                last_call = call_match.group(1).strip()
                # Argument producers belong to the next call.  Leaving RCX/RDX
                # live across a CALL attached CryptGenKey's Algid onto CryptEncrypt.
                tracked.clear()
                pushed.clear()
                continue
            match = re.match(r"(?i)(?:mov|lea)\s+([a-z][a-z0-9]*),\s*(.+)$", text)
            if not match:
                continue
            register, source = match.group(1).casefold(), match.group(2).strip()
            if register not in set(registers) | x86_registers | {"eax", "ebx", "ecx", "edx"}:
                continue
            if re.fullmatch(r"(?:0x[0-9a-f]+|-?\d+)", source, re.I):
                tracked[register] = {
                    "source_kind": "constant",
                    "value": source,
                    "register": match.group(1).upper(),
                    "source_instruction": text,
                    "source_callsite": instruction.get("address") or instruction.get("from"),
                }
            elif source.startswith("[") and source.endswith("]"):
                source_kind = "stack_local" if re.search(
                    r"\b(?:RSP|ESP|RBP|EBP)\b", source, re.IGNORECASE
                ) else "global"
                tracked[register] = {
                    "source_kind": source_kind,
                    "value": source[1:-1],
                    "register": match.group(1).upper(),
                    "source_instruction": text,
                    "source_callsite": instruction.get("address") or instruction.get("from"),
                }
            elif source.startswith('"') or source.startswith("'"):
                tracked[register] = {
                    "source_kind": "string",
                    "value": source.strip("\"'"),
                    "register": match.group(1).upper(),
                    "source_instruction": text,
                    "source_callsite": instruction.get("address") or instruction.get("from"),
                }
            elif register in {"eax", "rax"} and last_call:
                tracked[register] = {
                    "source_kind": "function_return",
                    "value": last_call,
                    "register": match.group(1).upper(),
                    "source_instruction": text,
                    "source_callsite": instruction.get("address") or instruction.get("from"),
                }
            else:
                tracked[register] = {
                    "source_kind": "register_or_expression",
                    "value": source,
                    "register": match.group(1).upper(),
                    "source_instruction": text,
                    "source_callsite": instruction.get("address") or instruction.get("from"),
                }
        indexes = (argument_index,) if argument_index is not None else tuple(
            range(6 if "createprocess" in str(api).casefold() else 4)
        )
        for index in indexes:
            register = registers[index] if 0 <= index < len(registers) else None
            if is_x86 and pushed and 0 <= index < len(pushed):
                # cdecl/stdcall push arguments right-to-left; the last push is
                # therefore argument 0 at the call site.
                value = list(reversed(pushed))[index]
            else:
                # Accept 32-bit aliases when Ghidra labels a x64 instruction
                # with an E-register (EDX for RDX, R8D for R8), and expose
                # explicit unknown rows.
                aliases: list[str] = []
                if register:
                    aliases.append(register)
                    aliases.append(register.replace("r", "e", 1))
                    if register in {"r8", "r9"}:
                        aliases.extend((f"{register}d", f"{register}w"))
                    elif register.startswith("r") and len(register) == 3:
                        aliases.append("e" + register[1:])
                value = next((tracked[alias] for alias in aliases if alias in tracked), None)
            result.append(
                {
                    "api": api,
                    "callsite": callsite,
                    "argument_index": index,
                    "register": value.get("register") if value else register,
                    "source_instruction": value.get("source_instruction") if value else None,
                    "source_callsite": value.get("source_callsite") if value else None,
                    **(value or {"source_kind": "unknown", "value": None}),
                    "confidence": "HIGH"
                    if value
                    and value.get("source_kind")
                    in {"constant", "string", "global", "function_return"}
                    else "LOW",
                    "function": function.get("name"),
                    "static_only": True,
                }
            )
    return tuple(result)


def build_function_semantic_summary(
    function: Mapping[str, object],
    *,
    max_calls: int = 48,
    max_inputs: int = 96,
    max_conditions: int = 32,
) -> dict[str, object]:
    """Build an analyst-facing, static-only explanation for one function.

    Ghidra gives us several independent rows (calls, instructions, data
    references and CFG blocks).  This projection joins only rows belonging to
    the same function and keeps the result bounded.  It is intentionally a
    *hypothesis* surface: it describes ordered static observations and marks
    runtime reachability, branch outcomes and successful side effects as
    unknown instead of inventing them.
    """
    name = str(function.get("name") or "unknown")
    entry = function.get("entry") or function.get("entry_rva")
    instructions = [
        row for row in function.get("instructions", [])
        if isinstance(row, Mapping)
    ]
    index_by_address = {
        str(row.get("address") or row.get("from") or "").casefold(): index
        for index, row in enumerate(instructions)
        if str(row.get("address") or row.get("from") or "").strip()
    }

    def is_call_reference(row: Mapping[str, object]) -> bool:
        """Return whether an exporter row explicitly represents a call.

        ``references_from`` also contains data, stack, and CFG references. A
        target label alone is not enough to infer a call: Ghidra commonly
        emits ``READ`` rows for imported function pointers and ``JUMP`` rows
        for local labels.  Keep the explicit boolean flags as a compatibility
        path for newer exporters that do not provide a textual reference
        type.
        """
        for key in ("type", "reference_type"):
            reference_type = str(row.get(key) or "").strip().casefold()
            if reference_type and "call" in reference_type:
                return True
        for key in ("is_call", "call"):
            flag = row.get(key)
            if isinstance(flag, str):
                if flag.strip().casefold() in {"1", "true", "yes", "y"}:
                    return True
            elif flag is True:
                return True
        return False

    reference_rows: list[Mapping[str, object]] = []
    for source_key in ("references_from", "call_targets"):
        rows = function.get(source_key, [])
        if not isinstance(rows, Iterable) or isinstance(rows, (str, bytes)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            # ``call_targets`` is an exporter-level projection whose rows are
            # calls by contract, but older versions omit ``type``. Preserve
            # that meaning without weakening the filtering of references_from.
            if source_key == "call_targets" and not any(
                row.get(key) is not None
                for key in ("type", "reference_type", "is_call", "call")
            ):
                # A legacy exporter can still leak navigation/data labels into
                # this projection. They are never callable API identities;
                # keep the compatibility path for real symbols and internal
                # functions, but reject the unambiguous label families.
                candidate = str(
                    row.get("target_name")
                    or row.get("target_function")
                    or row.get("api")
                    or row.get("target")
                    or ""
                ).strip()
                # ``call_targets`` is a legacy compatibility projection.  It
                # can contain data/navigation labels and imported pointer
                # symbols alongside real calls.  Only retain symbols that can
                # represent a callable destination; the concrete API row in
                # ``references_from`` remains the authoritative call record.
                if (
                    re.match(r"^(?:PTR_)?(?:LAB|DAT)_", candidate, re.IGNORECASE)
                    or re.match(r"^PTR_", candidate, re.IGNORECASE)
                    or re.match(r"^[su]_", candidate)
                    or re.match(r"^EXTERNAL:\s*\d+$", candidate, re.IGNORECASE)
                ):
                    continue
                row = {**row, "is_call": True}
            reference_rows.append(row)
    raw_calls = [row for row in reference_rows if is_call_reference(row)]
    # Ghidra-backed persistence can expose one call twice: once in the
    # function context's ``call_targets`` projection and once as a dedicated
    # ``function_call`` row.  Both are useful provenance inputs, but they are
    # the same semantic callsite.  Deduplicate by explicit destination and
    # source address while retaining distinct repeated invocations.
    unique_calls: list[Mapping[str, object]] = []
    seen_call_keys: set[tuple[str, str, str]] = set()
    for row in raw_calls:
        api = str(
            row.get("target_name") or row.get("target_function") or row.get("api") or ""
        ).strip().casefold()
        # Ghidra may project one callsite through an import-qualified symbol
        # and an unqualified/pointer alias.  Normalize the API identity before
        # deduplication so the analyst-facing sequence retains one semantic
        # call while the source Evidence rows remain fully auditable.
        api_key = normalize_api_symbol(api) or api
        callsite = str(row.get("from") or row.get("address") or "").strip().casefold()
        target = str(row.get("to") or row.get("target_function") or "").strip().casefold()
        # A callsite may be projected once as a concrete API and once as an
        # import-pointer alias.  The source address is the stable identity;
        # retaining target labels here would duplicate the same call in the
        # analyst narrative.
        key = (api_key, callsite, target)
        # Rows with no source address are intentionally not collapsed by
        # destination alone: exporter order is the only available evidence
        # for those records and merging them could erase distinct calls.
        callsite_key = (api_key, callsite, "")
        if callsite and (
            key in seen_call_keys
            or any(existing[:2] == callsite_key[:2] for existing in seen_call_keys)
        ):
            continue
        if callsite:
            seen_call_keys.add(key)
        unique_calls.append(row)
    raw_calls = unique_calls

    def call_position(row: Mapping[str, object], fallback: int) -> tuple[int, int]:
        address = str(row.get("from") or row.get("address") or "").casefold()
        return (index_by_address.get(address, len(instructions) + fallback), fallback)

    ordered_calls = sorted(enumerate(raw_calls), key=lambda item: call_position(item[1], item[0]))
    # Long compiler-generated helpers often contain dozens of local cleanup
    # calls before a security-relevant API at the tail of the function. A
    # plain prefix cap would hide that tail from the semantic summary and
    # make the downstream investigator appear unproductive. Reserve the
    # bounded budget for typed/high-signal calls first, then fill remaining
    # slots with the earliest low-information calls. The final sequence is
    # sorted back into source order so the projection remains a timeline.
    def call_signal(row: Mapping[str, object]) -> bool:
        api = str(
            row.get("target_name") or row.get("target_function") or row.get("api") or ""
        ).strip()
        normalized_api = normalize_api_symbol(api)
        explicit_high_signal = {
            "etweventwrite",
            "flushinstructioncache",
            "writeprocessmemory",
            "createremotethread",
            "updateprocthreadattribute",
            "proc_thread_attribute_parent_process",
            "getprocaddress",
            "ldrgetprocedureaddress",
            "loadlibrarya",
            "loadlibraryw",
            "virtualalloc",
            "virtualprotect",
            "createprocessa",
            "createprocessw",
            "shellexecutea",
            "shellexecutew",
            "winexec",
            "winhttpsendrequest",
            "winhttpreceiveresponse",
            "internetopenurl",
            "urldownloadtofilea",
            "urldownloadtofilew",
        }
        return bool(
            semantic_category(api)
            or is_injection_call(api)
            or is_anti_analysis_signal(api)
            or normalized_api in explicit_high_signal
        )

    if len(ordered_calls) > max_calls:
        high_signal = [item for item in ordered_calls if call_signal(item[1])]
        selected_calls = high_signal[:max_calls]
        if len(selected_calls) < max_calls:
            selected_ids = {id(item[1]) for item in selected_calls}
            selected_calls.extend(
                item
                for item in ordered_calls
                if id(item[1]) not in selected_ids
            )
            selected_calls = selected_calls[:max_calls]
        ordered_calls = sorted(selected_calls, key=lambda item: call_position(item[1], item[0]))
    call_sequence: list[dict[str, object]] = []
    inputs: list[dict[str, object]] = []
    consumers: list[dict[str, object]] = []
    semantic_calls = {
        "execution", "network", "dynamic_resolution", "loader", "persistence",
        "file_io", "injection", "anti_analysis", "environment_query",
    }
    for ordinal, (_, row) in enumerate(ordered_calls):
        api = str(row.get("target_name") or row.get("target_function") or row.get("api") or "").strip()
        if not api:
            continue
        category = semantic_category(api)
        if is_injection_call(api):
            category = "injection"
        elif is_anti_analysis_signal(api):
            category = "anti_analysis"
        callsite = row.get("from") or row.get("address")
        trace = trace_static_api_arguments(function, api, callsite=callsite)
        call_record = {
            "ordinal": ordinal,
            "api": api,
            "category": category or "unclassified_call",
            "callsite": callsite,
            "target": row.get("to") or row.get("target_function"),
            "reference_type": row.get("type") or row.get("reference_type"),
            "arguments": [dict(item) for item in trace[:8]],
            "recovered_argument_count": sum(
                1 for item in trace if item.get("value") not in (None, "")
            ),
            "static_only": True,
        }
        call_sequence.append(call_record)
        for item in trace:
            if item.get("source_kind") == "unknown" and item.get("value") in (None, ""):
                continue
            inputs.append({
                "api": api,
                "callsite": callsite,
                "argument_index": item.get("argument_index"),
                "register": item.get("register"),
                "source_kind": item.get("source_kind"),
                "value": item.get("value"),
                "confidence": item.get("confidence", "LOW"),
            })
        if ordinal > 0 and category in semantic_calls:
            consumers.append({
                "api": api,
                "category": category or "unclassified_call",
                "callsite": callsite,
                "role": "downstream_static_call",
                "static_only": True,
            })

    conditions: list[dict[str, object]] = []
    for row in instructions:
        text = str(row.get("text") or row.get("mnemonic") or "").strip()
        if not text:
            continue
        if re.match(r"(?i)^(?:CMP|TEST|J[A-Z]+|LOOP|SET[A-Z]+)\b", text):
            conditions.append({
                "address": row.get("address") or row.get("from"),
                "text": text,
                "kind": "branch_or_predicate",
                "outcome": "UNKNOWN",
                "static_only": True,
            })
            if len(conditions) >= max_conditions:
                break

    unknowns: list[str] = []
    if not call_sequence:
        unknowns.append("no typed call sequence was recovered")
    if call_sequence and not inputs:
        unknowns.append("call argument producers were not recovered")
    if call_sequence and not consumers:
        unknowns.append("a downstream consumer was not recovered")
    if conditions:
        unknowns.append("branch outcomes and runtime reachability are unobserved")
    else:
        unknowns.append("no typed branch or predicate was recovered")
    recovered_inputs = sum(
        1 for item in inputs if item.get("value") not in (None, "")
    )
    if len(call_sequence) >= 2 and (recovered_inputs or conditions):
        confidence = "HIGH" if recovered_inputs and consumers else "MEDIUM"
    elif call_sequence:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    return {
        "kind": "function_semantic_summary",
        "function": name,
        "function_entry": entry,
        "call_sequence": call_sequence,
        "arguments": call_sequence,
        "inputs": inputs[:max_inputs],
        "conditions": conditions,
        "consumers": consumers[:max_calls],
        "recovered_argument_count": recovered_inputs,
        "confidence": confidence,
        "unknowns": list(dict.fromkeys(unknowns)),
        "boundary": "Static evidence only; runtime execution is unobserved, as are branch outcomes, reachability, and successful side effects.",
        "static_only": True,
    }


_PTR_IMPORT_RE = re.compile(r"(?i)^PTR_(.+?)(?:_[0-9A-Fa-f]{6,})?$")
_PTR_IN_TEXT_RE = re.compile(r"(?i)\bPTR_([A-Za-z_][A-Za-z0-9]*)(?:_[0-9A-Fa-f]{6,})?\b")
_CANONICAL_IMPORT_APIS = {
    "getprocaddress": "GetProcAddress",
    "ldrgetprocedureaddress": "LdrGetProcedureAddress",
    "getmodulehandlea": "GetModuleHandleA",
    "getmodulehandlew": "GetModuleHandleW",
    "loadlibrarya": "LoadLibraryA",
    "loadlibraryw": "LoadLibraryW",
    "createprocessw": "CreateProcessW",
    "createprocessa": "CreateProcessA",
    "winexec": "WinExec",
    "shellexecutew": "ShellExecuteW",
    "shellexecutea": "ShellExecuteA",
    "openprocess": "OpenProcess",
    "updateprocthreadattribute": "UpdateProcThreadAttribute",
    "initializeprocthreadattributelist": "InitializeProcThreadAttributeList",
    "createthread": "CreateThread",
    "createthreadex": "CreateThreadEx",
    "tpallocwork": "TpAllocWork",
    "submitthreadpoolwork": "SubmitThreadpoolWork",
    "createthreadpoolwait": "CreateThreadpoolWait",
    "createthreadpooltimer": "CreateThreadpoolTimer",
}
_PROCESS_IMPORT_NAMES = {
    "createprocessw",
    "createprocessa",
    "winexec",
    "shellexecutew",
    "shellexecutea",
}
_THREAD_IMPORT_NAMES = {
    "createthread",
    "createthreadex",
    "tpallocwork",
    "submitthreadpoolwork",
    "createthreadpoolwait",
    "createthreadpooltimer",
}
_PPID_IMPORT_NAMES = {
    "openprocess",
    "updateprocthreadattribute",
    "initializeprocthreadattributelist",
}
_RESOLVER_IMPORT_NAMES = {
    "getprocaddress",
    "ldrgetprocedureaddress",
    "getmodulehandlea",
    "getmodulehandlew",
    "loadlibrarya",
    "loadlibraryw",
}


def _api_name_from_ptr_symbol(name: object) -> str | None:
    match = _PTR_IMPORT_RE.match(str(name or "").strip())
    if not match:
        return None
    api = str(match.group(1) or "").strip()
    return api or None


def _canonical_api_name(name: object, allowed: set[str]) -> str | None:
    raw = str(name or "").strip()
    folded = raw.casefold()
    if folded in allowed:
        return _CANONICAL_IMPORT_APIS.get(folded, raw)
    ptr = _api_name_from_ptr_symbol(raw)
    if ptr and ptr.casefold() in allowed:
        return _CANONICAL_IMPORT_APIS.get(ptr.casefold(), ptr)
    return None


def _call_api_from_instruction(text: object, allowed: set[str]) -> str | None:
    raw = str(text or "")
    if not re.search(r"(?i)\bCALL\b", raw):
        return None
    ptr = _PTR_IN_TEXT_RE.search(raw)
    if ptr and ptr.group(1).casefold() in allowed:
        return _CANONICAL_IMPORT_APIS.get(ptr.group(1).casefold(), ptr.group(1))
    for api in allowed:
        if re.search(rf"(?i)\b{re.escape(api)}\b", raw):
            return _CANONICAL_IMPORT_APIS.get(api, api)
    return None


def decoded_config_string_table(
    hits: Iterable[Mapping[str, object]],
) -> dict[str, str]:
    """Image-address -> string table for statically decoded configuration.

    A sample that resolves its APIs dynamically keeps the procedure *names*
    inside an encoded blob, so those names only exist at their image addresses
    after the decode.  ``recover_dynamic_api_resolutions`` maps a
    ``GetProcAddress`` argument through ``strings_by_address``; without this
    table that join can only ever name APIs that are already plaintext in the
    image, and the decode -> consumer link can never close.

    Pure.  Only entries carrying both an address and a printable preview are
    emitted; the caller merges them with ``setdefault`` so a genuinely static
    string at the same address always wins.
    """
    table: dict[str, str] = {}
    for hit in hits:
        if not isinstance(hit, Mapping):
            continue
        address = hit.get("virtual_address")
        if address in (None, ""):
            continue
        text = str(hit.get("decoded_preview") or "").split("\x00", 1)[0].strip()
        if not text:
            text = str(hit.get("decoded_text") or "").split("\x00", 1)[0].strip()
        if not text:
            continue
        keys = [str(address)]
        try:
            number = int(address)
        except (TypeError, ValueError):
            number = None
        if number is not None and number > 0:
            keys.extend((str(number), f"0x{number:x}", f"{number:x}"))
        for key in keys:
            table.setdefault(key, text)
    return table


def recover_dynamic_api_resolutions(
    function: Mapping[str, object],
    strings_by_address: Mapping[str, str] | None = None,
    *,
    max_resolutions: int = 64,
    lookback_instructions: int = 48,
    consumer_lookahead: int = 24,
    thunks: Mapping[int, str] | None = None,
    string_index: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], ...]:
    """Recover explicit ``GetProcAddress`` name arguments from static facts.

    ``GetProcAddress`` receives the procedure name in ``RDX``/``EDX`` on the
    Windows x64 ABI.  Ghidra often renders the import as an IAT thunk
    (``JMP qword ptr [PTR_GetProcAddress]``) called from a site whose address
    lacks the ``0x`` prefix.  The module handle commonly comes from a nearby
    ``GetModuleHandle``/``LoadLibrary`` whose ``RCX`` names ``kernel32.dll``.
    This helper joins those observations and records the resolver plus a
    bounded indirect consumer.  It emits no row when the name cannot be mapped
    to an actual printable string.

    ``string_index`` is an optional prebuilt :func:`build_command_string_index`.  This function used to
    build its own copy of that index by walking the entire ``strings_by_address`` mapping, and it is
    called once per analysed function - the SAME defect removed from
    ``recover_process_creation_arguments`` in this round.  Captured with `faulthandler` while a 1 MB PE
    sat at 7,332 evidence rows with the API at 100% CPU:

        static_analysis.py:3663 in _address_variants
        static_analysis.py:3678 in recover_dynamic_api_resolutions
        service.py:19487 in _record_ghidra_evidence
    """

    resolver_names = {
        "getprocaddress",
        "ldrgetprocedureaddress",
    }
    module_loader_names = {
        "getmodulehandlea",
        "getmodulehandlew",
        "loadlibrarya",
        "loadlibraryw",
    }
    mapping = strings_by_address or {}
    thunk_map = {int(key): str(value) for key, value in (thunks or {}).items()}

    def _address_variants(value: object) -> tuple[str, ...]:
        return command_address_variants(value)

    canonical_strings: dict[str, str] = (
        dict(string_index)
        if string_index is not None
        else build_command_string_index(mapping)
    )

    def _looks_like_api_name(value: object) -> bool:
        text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
        if not text or text.startswith("#") or len(text) > 160:
            return False
        if re.match(r"(?i)^(fun_|sub_|lab_|thunk_)", text):
            return False
        # Procedure names are symbols, not paths/URLs or free-form prose.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@$?.]{2,159}", text):
            return False
        return any(character.isupper() for character in text) or any(
            token in text.casefold()
            for token in (
                "api",
                "crypt",
                "create",
                "get",
                "set",
                "open",
                "read",
                "write",
                "load",
                "http",
                "win",
                "nt",
                "rtl",
                "virtual",
                "process",
                "thread",
                "file",
                "reg",
                "shell",
                "internet",
                "dns",
                "etw",
                "co",
                "free",
            )
        )

    def _lookup_string(address: object) -> tuple[str | None, str | None]:
        for variant in _address_variants(address):
            text = canonical_strings.get(variant)
            if text and _looks_like_api_name(text):
                return text, variant
        return None, None

    def _looks_like_module_name(value: object) -> bool:
        text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
        if not is_projected_catalog_value(text) or len(text) > 160:
            return False
        lower = text.casefold()
        if lower.endswith((".dll", ".exe", ".ocx", ".sys", ".cpl")):
            return True
        return lower in {
            "kernel32",
            "ntdll",
            "user32",
            "advapi32",
            "winhttp",
            "wininet",
            "ws2_32",
            "ole32",
            "oleaut32",
            "shell32",
            "gdi32",
            "crypt32",
            "iphlpapi",
            "bcrypt",
        }

    def _lookup_module(address: object) -> str | None:
        for variant in _address_variants(address):
            text = canonical_strings.get(variant)
            if text and _looks_like_module_name(text):
                return text
        return None

    def _instruction_address(row: Mapping[str, object]) -> str:
        return str(row.get("address") or row.get("from") or "").strip()

    def _named_or_thunk(name: object, target: object, allowed: set[str]) -> str | None:
        canonical = _canonical_api_name(name, allowed)
        if canonical is not None:
            return canonical
        key = _addr_key(target)
        if key.startswith("0x"):
            mapped = thunk_map.get(int(key, 16))
            if mapped and mapped.casefold() in allowed:
                return mapped
        return None

    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    references = [row for row in function.get("references_from", []) if isinstance(row, Mapping)]
    references.extend(row for row in function.get("call_targets", []) if isinstance(row, Mapping))
    data_references = [
        row for row in function.get("data_references", []) if isinstance(row, Mapping)
    ]
    data_references.extend(
        row
        for row in function.get("references_from", [])
        if isinstance(row, Mapping) and "call" not in str(row.get("type", "")).casefold()
    )
    refs_by_from: dict[str, list[Mapping[str, object]]] = {}
    for row in data_references:
        source = _addr_key(row.get("from") or row.get("address") or "")
        if source:
            refs_by_from.setdefault(source, []).append(row)

    resolver_calls: list[tuple[str, str | None, int | None]] = []
    seen_resolvers: set[tuple[str, str]] = set()
    for row in references:
        name = str(
            row.get("target_name") or row.get("target_function") or row.get("api") or ""
        ).strip()
        canonical = _named_or_thunk(name, row.get("to") or row.get("target"), resolver_names)
        if canonical is None:
            continue
        ref_type = str(row.get("type") or row.get("reference_type") or "").casefold()
        if "call" not in ref_type and "call" not in str(row.get("target_function") or "").casefold():
            continue
        callsite = str(row.get("from") or row.get("address") or "").strip()
        key = (canonical.casefold(), _addr_key(callsite))
        if key in seen_resolvers:
            continue
        seen_resolvers.add(key)
        index = next(
            (
                position
                for position, instruction in enumerate(instructions)
                if callsite
                and _addr_key(callsite) == _addr_key(_instruction_address(instruction))
            ),
            None,
        )
        resolver_calls.append((canonical, callsite or None, index))
    # Exporters can omit ``references_from`` for an imported call while still
    # retaining a useful instruction text.  Include PTR_/qword-ptr slots and
    # ``MOV RBX,[PTR_GetProcAddress]; CALL RBX``.
    loaded_resolver_reg: dict[str, str] = {}
    for index, instruction in enumerate(instructions):
        text = str(instruction.get("text") or "")
        load = re.search(
            r"(?i)\b(?:MOV|LEA)\s+([A-Z][A-Z0-9]*)\s*,\s*(?:qword\s+ptr\s+)?\[([^\]]+)\]",
            text,
        )
        if load:
            slot = load.group(2).strip()
            loaded = _canonical_api_name(slot, resolver_names)
            if loaded is None:
                ptr = _PTR_IN_TEXT_RE.search(slot) or _PTR_IN_TEXT_RE.search(text)
                if ptr and ptr.group(1).casefold() in resolver_names:
                    loaded = _CANONICAL_IMPORT_APIS.get(ptr.group(1).casefold(), ptr.group(1))
            if loaded:
                loaded_resolver_reg[load.group(1).upper()] = loaded
        name = _call_api_from_instruction(text, resolver_names)
        if name is None:
            call_reg = re.search(r"(?i)\bCALL\s+([A-Z][A-Z0-9]*)\s*$", text)
            if call_reg:
                name = loaded_resolver_reg.get(call_reg.group(1).upper())
        if name is None:
            call_imm = re.search(
                r"(?i)\bCALL\s+(?:FUN_|sub_)?(?:0x)?([0-9a-f]{6,})\b",
                text,
            )
            if call_imm:
                mapped = thunk_map.get(int(call_imm.group(1), 16))
                if mapped and mapped.casefold() in resolver_names:
                    name = mapped
        if not name:
            continue
        callsite = _instruction_address(instruction)
        key = (name.casefold(), _addr_key(callsite))
        if key not in seen_resolvers:
            seen_resolvers.add(key)
            resolver_calls.append((name, callsite or None, index))

    if not resolver_calls:
        return ()

    pointer_links = track_indirect_function_pointers(function)
    output: list[dict[str, object]] = []
    seen_rows: set[tuple[str, str, str]] = set()
    for resolver, callsite, call_index in resolver_calls:
        if call_index is None:
            continue
        lower_bound = max(0, call_index - max(1, lookback_instructions))
        producer: dict[str, object] | None = None
        producer_index: int | None = None
        for index in range(call_index - 1, lower_bound - 1, -1):
            instruction = instructions[index]
            text = str(instruction.get("text") or "").strip()
            match = re.match(r"(?i)^(?:MOV|LEA)\s+(RDX|EDX)\s*,\s*(.+?)\s*$", text)
            if not match:
                continue
            register, source = match.group(1).upper(), match.group(2).strip()
            producer = {
                "register": register,
                "source": source,
                "source_instruction": text,
                "source_callsite": _instruction_address(instruction) or None,
            }
            producer_index = index
            # The closest write wins, including an unresolved write.  This
            # prevents a stale API name from crossing a register clobber.
            break
        if producer is None:
            continue

        source = str(producer["source"])
        source_address: str | None = None
        source_kind = "unknown"
        if source.startswith(('"', "'")):
            candidate = source.strip("\"'")
            api_name = candidate if _looks_like_api_name(candidate) else None
            source_kind = "inline_string"
        else:
            candidate = source
            cleaned = re.sub(r"(?i)\b(?:offset|flat|ptr|qword|dword)\b", "", candidate)
            numeric = re.search(r"(?i)(?:0x[0-9a-f]+|(?<![a-z])[0-9a-f]{6,})", cleaned)
            if numeric:
                source_address = numeric.group(0)
            if source.startswith("[") and source.endswith("]"):
                source_kind = "address_indirect"
            elif source.casefold().startswith("offset") or source.casefold().startswith("lea"):
                source_kind = "address"
            else:
                source_kind = "immediate_or_expression"
            api_name, _ = _lookup_string(source_address) if source_address else (None, None)

            # Symbolic Ghidra operands (``s_WinHttpOpen_140...``) often have a
            # data reference on the same instruction; use that reference to
            # recover the exact mapped address instead of guessing from text.
            instruction_key = _addr_key(producer.get("source_callsite") or "")
            for reference in refs_by_from.get(instruction_key, []):
                reference_address = reference.get("to") or reference.get("address")
                mapped_name, _ = _lookup_string(reference_address)
                if mapped_name:
                    source_address = str(reference_address)
                    api_name = mapped_name
                    source_kind = "data_reference"
                    break
            if api_name is None:
                symbol = str(
                    next(
                        (
                            reference.get("target_name")
                            for reference in refs_by_from.get(instruction_key, [])
                            if reference.get("target_name")
                        ),
                        "",
                    )
                )
                symbol_match = re.match(r"(?i)^s_(.+?)(?:_[0-9a-f]{6,})?$", symbol)
                if symbol_match and _looks_like_api_name(symbol_match.group(1)):
                    api_name = symbol_match.group(1)
                    source_kind = "symbolic_data_reference"

        if not api_name or not _looks_like_api_name(api_name):
            continue

        module_input: str | None = None
        for index in range(call_index - 1, lower_bound - 1, -1):
            instruction = instructions[index]
            text = str(instruction.get("text") or "")
            loader = _call_api_from_instruction(text, module_loader_names)
            if loader is None:
                call_imm = re.search(
                    r"(?i)\bCALL\s+(?:FUN_|sub_)?(?:0x)?([0-9a-f]{6,})\b",
                    text,
                )
                if call_imm:
                    mapped = thunk_map.get(int(call_imm.group(1), 16))
                    if mapped and mapped.casefold() in module_loader_names:
                        loader = mapped
            if loader is None:
                continue
            for prior in range(index - 1, max(0, index - 16) - 1, -1):
                prior_row = instructions[prior]
                prior_text = str(prior_row.get("text") or "").strip()
                match = re.match(
                    r"(?i)^(?:MOV|LEA)\s+(RCX|ECX)\s*,\s*(.+?)\s*$",
                    prior_text,
                )
                if not match:
                    continue
                source = match.group(2).strip()
                if source.startswith(('"', "'")):
                    candidate = source.strip("\"'")
                    if _looks_like_module_name(candidate):
                        module_input = candidate
                        break
                numeric = re.search(r"(?i)(?:0x[0-9a-f]+|(?<![a-z])[0-9a-f]{6,})", source)
                module_input = _lookup_module(numeric.group(0) if numeric else None)
                prior_key = _addr_key(_instruction_address(prior_row))
                if module_input is None:
                    for reference in refs_by_from.get(prior_key, []):
                        mapped = _lookup_module(reference.get("to") or reference.get("address"))
                        if mapped:
                            module_input = mapped
                            break
                if module_input is None:
                    symbol = str(
                        next(
                            (
                                reference.get("target_name")
                                for reference in refs_by_from.get(prior_key, [])
                                if reference.get("target_name")
                            ),
                            "",
                        )
                    )
                    symbol_match = re.match(r"(?i)^s_(.+?)(?:_[0-9a-f]{6,})?$", symbol)
                    if symbol_match:
                        candidate = symbol_match.group(1).replace("_", ".")
                        if _looks_like_module_name(candidate):
                            module_input = (
                                candidate
                                if "." in candidate
                                else f"{candidate}.dll"
                            )
                if module_input:
                    break
            if module_input:
                break

        consumers = [
            link
            for link in pointer_links
            if str(link.get("resolver_callsite") or "").casefold() == str(callsite or "").casefold()
        ]
        consumer = consumers[0] if consumers else None
        if consumer is None and producer_index is not None:
            # The resolver return value is RAX/EAX, but optimized x64 code
            # commonly moves it into a callee-saved register before the
            # indirect call (for example ``MOV R12,RAX; CALL R12``). Track
            # those bounded copies so the consumer remains linked without
            # assuming that every indirect call in the function is related.
            pointer_registers = {"RAX", "EAX"}
            for instruction in instructions[
                call_index + 1 : call_index + 1 + max(1, consumer_lookahead)
            ]:
                text = str(instruction.get("text") or "").strip()
                copy_match = re.match(
                    r"(?i)^MOV\s+(R[A-Z0-9]+|E[A-Z0-9]+)\s*,\s*(R[A-Z0-9]+|E[A-Z0-9]+)\s*$",
                    text,
                )
                if copy_match and copy_match.group(2).upper() in pointer_registers:
                    pointer_registers.add(copy_match.group(1).upper())
                    continue
                indirect_match = re.search(
                    r"(?i)\b(?:CALL|JMP)\s+(?:[A-Z0-9_ ]+\s+)?\[?\s*(R[A-Z0-9]+|E[A-Z0-9]+)\s*\]?\s*$",
                    text,
                )
                if indirect_match and indirect_match.group(1).upper() in pointer_registers:
                    consumer = {
                        "consumer_callsite": _instruction_address(instruction) or None,
                        "consumer": text,
                        "consumer_register": indirect_match.group(1).upper(),
                        "consumer_kind": "JUMP" if text.casefold().lstrip().startswith("jmp") else "CALL",
                        "indirect": True,
                        "static_only": True,
                    }
                    break
        dedupe_key = (
            str(callsite or "").casefold(),
            str(source_address or "").casefold(),
            api_name.casefold(),
        )
        if dedupe_key in seen_rows:
            continue
        seen_rows.add(dedupe_key)
        row: dict[str, object] = {
            "resolver": resolver,
            "resolver_callsite": callsite,
            "api_name": api_name,
            "module_input": module_input,
            "string_address": source_address,
            "argument_register": str(producer["register"]),
            "argument_source": source,
            "argument_source_kind": source_kind,
            "argument_source_instruction": producer["source_instruction"],
            "argument_source_callsite": producer["source_callsite"],
            "consumer_callsite": consumer.get("consumer_callsite") if consumer else None,
            "consumer": consumer.get("consumer") if consumer else None,
            "consumer_kind": consumer.get("consumer_kind") if consumer else None,
            "confidence": "HIGH" if source_address or source_kind == "inline_string" else "MEDIUM",
            "static_only": True,
        }
        output.append(row)
        if len(output) >= max(1, max_resolutions):
            break
    return tuple(output)


def _looks_like_command_line(value: object) -> bool:
    text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
    if not is_projected_catalog_value(text) or len(text) > 512:
        return False
    lower = text.casefold()
    return any(
        token in lower
        for token in (
            ".exe",
            ".bat",
            ".cmd",
            ".com",
            ".msi",
            "cmd",
            "powershell",
            "pwsh",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
            "schtasks",
            "explorer",
        )
    )


_PROCESS_IMAGE_RE = re.compile(
    r"(?i)^(?:[A-Za-z]:\\)?(?:[\w. $()-]+\\)*[A-Za-z][\w.-]*\.exe$"
)
_PROCESS_IMAGE_NOISE = (
    "failed",
    "invalid",
    "not found",
    "copyright",
    "all rights",
)
_PROCESS_COMMAND_SOURCE_SUFFIXES = (
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".py",
    ".go",
    ".ts",
    ".js",
)


def projected_process_image_name(value: object) -> str | None:
    """Return a clean child-process image. Reject mashed error strings."""
    text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
    if not text or len(text) > 128:
        return None
    lower = text.casefold()
    if any(token in lower for token in _PROCESS_IMAGE_NOISE):
        return None
    if lower.count(".exe") != 1:
        return None
    if not _looks_like_command_line(text):
        return None
    if not _PROCESS_IMAGE_RE.fullmatch(text):
        return None
    return text


_LEADING_PROCESS_IMAGE_RE = re.compile(
    r"(?i)^(?:[A-Za-z]:\\)?(?:[\w. $()-]+\\)*[A-Za-z][\w.-]*\.exe"
)


def leading_process_image_name(value: object) -> str | None:
    """Return the image name at the head of a possibly merged literal.

    The linker concatenates adjacent ``.rdata`` literals, so the value the
    sample compares against (``explorer.exe``) arrives together with the error
    templates that follow it.  Projecting only the leading, well-formed image
    keeps the recovered parent identity equal to what ``memcmp`` actually
    compares instead of quoting the whole blob.  Anything else stays unresolved
    rather than being guessed.
    """
    text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
    if not text:
        return None
    match = _LEADING_PROCESS_IMAGE_RE.match(text)
    if not match:
        return None
    return match.group(0)


def is_process_command_candidate(value: object) -> bool:
    """True for a child command or image, not rust paths or error templates."""
    text = str(value or "").split("\x00", 1)[0].strip().strip("\"'")
    if not text:
        return False
    lower = text.casefold()
    if lower.startswith("hkey_") or lower.startswith("software\\"):
        return False
    if any(token in lower for token in _PROCESS_IMAGE_NOISE):
        return False
    if lower.endswith(_PROCESS_COMMAND_SOURCE_SUFFIXES):
        return False
    if projected_process_image_name(text):
        return True
    return _looks_like_command_line(text)


def _addr_key(value: object) -> str:
    text = str(value or "").strip().casefold()
    if re.fullmatch(r"(?:0x)?[0-9a-f]+", text):
        return f"0x{int(text, 16):x}"
    return text


def import_api_thunks(
    functions: object,
    names: Iterable[str] | None = None,
) -> dict[int, str]:
    """Map IAT JMP thunks such as GetProcAddress at 140046878 to the imported API."""
    allowed = {
        str(item).casefold()
        for item in (
            names
            if names is not None
            else (
                *_PROCESS_IMPORT_NAMES,
                *_RESOLVER_IMPORT_NAMES,
                *_PPID_IMPORT_NAMES,
                *_THREAD_IMPORT_NAMES,
            )
        )
        if str(item).strip()
    }
    mapping: dict[int, str] = {}
    rows = [item for item in functions if isinstance(item, Mapping)] if isinstance(functions, Iterable) else []
    for function in rows:
        name = str(function.get("name") or function.get("symbol") or "")
        canonical = _canonical_api_name(name, allowed)
        instructions = [
            item for item in (function.get("instructions") or ()) if isinstance(item, Mapping)
        ]
        texts = [str(item.get("text") or "") for item in instructions]
        if not texts or len(texts) > 4:
            continue
        if not any(re.search(r"(?i)\bJMP\b", text) for text in texts):
            continue
        if canonical is None:
            for text in texts:
                ptr = _PTR_IN_TEXT_RE.search(text)
                if ptr and ptr.group(1).casefold() in allowed:
                    canonical = _CANONICAL_IMPORT_APIS.get(
                        ptr.group(1).casefold(), ptr.group(1)
                    )
                    break
        if canonical is None:
            continue
        entry = _addr_key(function.get("entry") or function.get("entry_rva"))
        if entry.startswith("0x"):
            mapping[int(entry, 16)] = canonical
        for instruction in instructions:
            address = _addr_key(instruction.get("address"))
            if address.startswith("0x"):
                mapping[int(address, 16)] = canonical
    return mapping


def process_import_thunks(functions: object) -> dict[int, str]:
    """Map IAT JMP thunks such as CreateProcessW at 140046948 to the imported API."""
    return import_api_thunks(functions, _PROCESS_IMPORT_NAMES)


#: Addresses Ghidra renders in several equivalent spellings.  Hoisted out of `_address_variants`,
#: which used to call `re.fullmatch` with an inline pattern once per mapping entry per call.
_HEX_ADDRESS_RE = re.compile(r"[0-9a-fA-F]{6,}")


def command_address_variants(value: object) -> tuple[str, ...]:
    """Every spelling a Ghidra address may appear under, lower-cased and de-duplicated.

    Ghidra renders one address as `0x140050000`, `140050000`, or a decimal; a lookup that only tried
    the rendered form silently missed the others.  The pattern is module-level because this runs once
    per mapping entry: `re.fullmatch` with an inline pattern re-compiles on every call (measured
    0.593 us vs 0.287 us precompiled).
    """
    raw = str(value or "").strip().strip("[]")
    if not raw:
        return ()
    folded = raw.casefold()
    variants: list[str] = [folded, raw.removeprefix("0x").casefold()]
    try:
        if folded.startswith("0x"):
            number = int(raw, 16)
        elif _HEX_ADDRESS_RE.fullmatch(raw):
            number = int(raw, 16)
        else:
            number = int(raw, 10)
    except (TypeError, ValueError):
        return tuple(dict.fromkeys(variants))
    variants.extend((str(number), f"0x{number:x}", f"{number:x}"))
    return tuple(dict.fromkeys(item.casefold() for item in variants))


def build_command_string_index(
    strings_by_address: Mapping[object, object] | None,
) -> dict[str, str]:
    """Index ``{address -> command-line text}`` once, for reuse across every analysed function.

    MEASURED STALL. `recover_process_creation_arguments` builds this index by walking the ENTIRE
    `strings_by_address` mapping, and its caller runs it once per analysed function, so the whole map
    was re-indexed per function. With `faulthandler` armed, a 1 MB PE that stalled at 7,332 evidence
    rows with the API at 100% CPU for 325 s produced this frame:

        static_analysis.py:4296 in _address_variants
        static_analysis.py:4303 in recover_process_creation_arguments
        service.py:19573 in _record_ghidra_evidence

    Measured cost of the redundant rebuild on this machine (one call, then x703 functions):

        10,000 strings   0.039 s ->   27 s
        100,000 strings  0.332 s ->  233 s   (3.9 min)
        500,000 strings  2.032 s -> 1428 s   (23.8 min)

    The mapping itself is built once per artifact (`service.py:19233`), so the index is a
    per-artifact value, not a per-function one. Building it here keeps the call inside one
    GIL-holding frame instead of 703 of them.
    """
    index: dict[str, str] = {}
    for raw_address, raw_text in (strings_by_address or {}).items():
        text = str(raw_text or "").split("\x00", 1)[0].strip().strip("\"'")
        if not text:
            continue
        for variant in command_address_variants(raw_address):
            index.setdefault(variant, text)
    return index


def recover_process_creation_arguments(
    function: Mapping[str, object],
    strings_by_address: Mapping[str, str] | None = None,
    *,
    max_calls: int = 16,
    lookback_instructions: int = 128,
    thunks: Mapping[int, str] | None = None,
    string_index: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], ...]:
    """Join CreateProcess command-line strings and unique flag immediates.

    x64 ``CreateProcessW`` puts ``lpCommandLine`` in ``RDX``. Ghidra often
    renders the import as an IAT thunk (``JMP qword ptr [PTR_CreateProcessW]``)
    called from a far-away site whose address lacks the ``0x`` prefix. Command
    strings may live in a callee-saved register rather than ``RDX``. Stack
    locators such as ``[RSP+0x78]`` stay unresolved.

    ``string_index`` is an optional prebuilt :func:`build_command_string_index`.  Pass it from a loop
    over functions so the mapping is indexed once per artifact rather than once per function; when it
    is omitted the index is built here, which keeps the function correct as a standalone call.
    """

    process_names = {
        "createprocessw",
        "createprocessa",
        "winexec",
        "shellexecutew",
        "shellexecutea",
    }
    command_registers = {
        "createprocessw": {"RDX", "EDX"},
        "createprocessa": {"RDX", "EDX"},
        "winexec": {"RCX", "ECX"},
        "shellexecutew": {"R8", "R8D"},
        "shellexecutea": {"R8", "R8D"},
    }
    mapping = strings_by_address or {}
    thunk_map = {int(key): str(value) for key, value in (thunks or {}).items()}

    def _address_variants(value: object) -> tuple[str, ...]:
        return command_address_variants(value)

    canonical_strings: dict[str, str] = (
        dict(string_index)
        if string_index is not None
        else build_command_string_index(mapping)
    )

    def _lookup_command(address: object) -> str | None:
        for variant in _address_variants(address):
            text = canonical_strings.get(variant)
            if text and _looks_like_command_line(text):
                return text
        return None

    def _instruction_address(row: Mapping[str, object]) -> str:
        return str(row.get("address") or row.get("from") or "").strip()

    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    references = [row for row in function.get("references_from", []) if isinstance(row, Mapping)]
    references.extend(row for row in function.get("call_targets", []) if isinstance(row, Mapping))
    data_references = [
        row for row in function.get("data_references", []) if isinstance(row, Mapping)
    ]
    refs_by_from: dict[str, list[Mapping[str, object]]] = {}
    for row in data_references + references:
        source = _addr_key(row.get("from") or row.get("address") or "")
        if source:
            refs_by_from.setdefault(source, []).append(row)

    process_calls: list[tuple[str, str | None, int | None]] = []
    seen_calls: set[tuple[str, str]] = set()
    for row in references:
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "").strip()
        canonical = _canonical_api_name(name, process_names)
        if canonical is None:
            target = _addr_key(row.get("to") or row.get("target") or "")
            if target.startswith("0x"):
                canonical = thunk_map.get(int(target, 16))
        if canonical is None:
            continue
        ref_type = str(row.get("type") or row.get("reference_type") or "").casefold()
        if "call" not in ref_type and "call" not in str(row.get("target_function") or "").casefold():
            continue
        callsite = str(row.get("from") or row.get("address") or "").strip()
        key = (canonical.casefold(), _addr_key(callsite))
        if key in seen_calls:
            continue
        seen_calls.add(key)
        index = next(
            (
                position
                for position, instruction in enumerate(instructions)
                if callsite
                and _addr_key(callsite) == _addr_key(_instruction_address(instruction))
            ),
            None,
        )
        process_calls.append((canonical, callsite or None, index))

    loaded_process_reg: dict[str, str] = {}
    for index, instruction in enumerate(instructions):
        text = str(instruction.get("text") or "")
        load = re.search(
            r"(?i)\b(?:MOV|LEA)\s+([A-Z][A-Z0-9]*)\s*,\s*(?:qword\s+ptr\s+)?\[([^\]]+)\]",
            text,
        )
        if load:
            slot = load.group(2).strip()
            loaded = _canonical_api_name(slot, process_names)
            if loaded is None:
                ptr = _PTR_IN_TEXT_RE.search(slot) or _PTR_IN_TEXT_RE.search(text)
                if ptr and ptr.group(1).casefold() in process_names:
                    loaded = _CANONICAL_IMPORT_APIS.get(ptr.group(1).casefold(), ptr.group(1))
            if loaded:
                loaded_process_reg[load.group(1).upper()] = loaded
        name = _call_api_from_instruction(text, process_names)
        if name is None:
            call_reg = re.search(r"(?i)\bCALL\s+([A-Z][A-Z0-9]*)\s*$", text)
            if call_reg:
                name = loaded_process_reg.get(call_reg.group(1).upper())
        if name is None:
            call_imm = re.search(
                r"(?i)\bCALL\s+(?:FUN_|sub_)?(?:0x)?([0-9a-f]{6,})\b",
                text,
            )
            if call_imm:
                name = thunk_map.get(int(call_imm.group(1), 16))
        if not name:
            continue
        callsite = _instruction_address(instruction)
        key = (name.casefold(), _addr_key(callsite))
        if key in seen_calls:
            continue
        seen_calls.add(key)
        process_calls.append((name, callsite or None, index))

    def _command_from_lookback(
        call_index: int,
        lower_bound: int,
        allowed_registers: set[str] | None,
    ) -> tuple[str | None, str, str | None]:
        found_command: str | None = None
        found_kind = "unknown"
        found_address: str | None = None
        for index in range(call_index - 1, lower_bound - 1, -1):
            instruction = instructions[index]
            text = str(instruction.get("text") or "").strip()
            match = re.match(
                r"(?i)^(?:MOV|LEA)\s+([A-Z][A-Z0-9]*)\s*,\s*(.+?)\s*$",
                text,
            )
            if not match:
                continue
            if allowed_registers is not None and match.group(1).upper() not in allowed_registers:
                continue
            source = match.group(2).strip()
            if source.startswith(('"', "'")):
                candidate = source.strip("\"'")
                if _looks_like_command_line(candidate):
                    return candidate, "inline_string", None
                continue
            numeric = re.search(r"(?i)(?:0x[0-9a-f]+|(?<![a-z])[0-9a-f]{6,})", source)
            found_address = numeric.group(0) if numeric else None
            found_command = _lookup_command(found_address) if found_address else None
            instruction_key = _addr_key(_instruction_address(instruction))
            if found_command is None:
                for reference in refs_by_from.get(instruction_key, []):
                    mapped = _lookup_command(reference.get("to") or reference.get("address"))
                    if mapped:
                        found_command = mapped
                        found_address = str(reference.get("to") or reference.get("address") or "")
                        found_kind = "data_reference"
                        break
            if found_command is None:
                symbol = str(
                    next(
                        (
                            reference.get("target_name")
                            for reference in refs_by_from.get(instruction_key, [])
                            if reference.get("target_name")
                        ),
                        "",
                    )
                )
                symbol_match = re.match(r"(?i)^s_(.+?)(?:_[0-9a-f]{6,})?$", symbol)
                if symbol_match:
                    candidate = symbol_match.group(1).replace("_", " ").strip()
                    if _looks_like_command_line(candidate):
                        found_command = candidate
                        found_kind = "symbolic_data_reference"
            if found_command:
                if found_kind == "unknown":
                    found_kind = "address"
                return found_command, found_kind, found_address
        return None, "unknown", None

    output: list[dict[str, object]] = []
    for api, callsite, call_index in process_calls:
        if call_index is None:
            continue
        registers = command_registers.get(api.casefold(), {"RDX", "EDX"})
        lower_bound = max(0, call_index - max(1, lookback_instructions))
        command, source_kind, source_address = _command_from_lookback(
            call_index, lower_bound, registers
        )
        if not command:
            command, source_kind, source_address = _command_from_lookback(
                call_index, lower_bound, None
            )
        if not command:
            command, source_kind, source_address = _command_from_lookback(
                call_index, 0, None
            )
        if command and not is_process_command_candidate(command):
            command = None
            source_kind = "unknown"
            source_address = None
        window_texts = [
            str(item.get("text") or item.get("mnemonic") or "")
            for item in instructions[lower_bound : call_index + 1]
        ]
        flag = creation_flag_from_abi_slot(window_texts)
        if not flag:
            flag = creation_flag_from_abi_slot(
                [str(item.get("text") or item.get("mnemonic") or "") for item in instructions]
            )
        if not command and not flag:
            continue
        if not command and is_specialist_ppid_creation_flag(flag):
            continue
        return_branch = catalog_return_branch_after_call(
            instructions[call_index + 1 : call_index + 13]
        )
        row: dict[str, object] = {
            "api": api,
            "callsite": callsite,
            "argument_source_kind": source_kind,
            "string_address": source_address,
            "static_only": True,
        }
        if command:
            row["command"] = command
            row["command_line"] = command
        if flag:
            row["creation_flags"] = flag
            row["flags"] = flag
        if return_branch:
            row["return_branch"] = return_branch
        output.append(row)
        if len(output) >= max(1, max_calls):
            break
    return tuple(output)


def recover_parent_process_attribute(
    function: Mapping[str, object],
    strings_by_address: Mapping[str, str] | None = None,
    *,
    thunks: Mapping[int, str] | None = None,
    content: bytes | None = None,
    pe_summary: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """Join OpenProcess → UpdateProcThreadAttribute → CreateProcess in one function.

    OpenProcess alone is not PPID spoofing. The recovered attribute list and
    child-creation API must be in the same static function. Explorer.exe and
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS are projected only when those values
    are present; creation flags stay the recovered immediate.

    ``content``/``pe_summary`` are optional and only widen where the parent
    literal is looked up: the shared ``strings_by_address`` table is capped, so
    the function's own literals are re-resolved locally when the image bytes are
    supplied. Without them the join behaves exactly as before.
    """
    allowed = {*_PPID_IMPORT_NAMES, "createprocessw", "createprocessa"}
    thunk_map = {int(key): str(value) for key, value in (thunks or {}).items()}
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    seen: set[str] = set()
    for instruction in instructions:
        text = str(instruction.get("text") or "")
        name = _call_api_from_instruction(text, allowed)
        if name is None:
            call_imm = re.search(
                r"(?i)\bCALL\s+(?:FUN_|sub_)?(?:0x)?([0-9a-f]{6,})\b",
                text,
            )
            if call_imm:
                mapped = thunk_map.get(int(call_imm.group(1), 16))
                if mapped and mapped.casefold() in allowed:
                    name = mapped
        if name:
            seen.add(name.casefold())
    for row in function.get("references_from", []) or ():
        if not isinstance(row, Mapping):
            continue
        ref_type = str(row.get("type") or row.get("reference_type") or "").casefold()
        if "call" not in ref_type:
            continue
        name = str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        canonical = _canonical_api_name(name, allowed)
        if canonical is None:
            target = _addr_key(row.get("to") or row.get("target") or "")
            if target.startswith("0x"):
                canonical = thunk_map.get(int(target, 16))
        if canonical:
            seen.add(canonical.casefold())
    if "openprocess" not in seen or "updateprocthreadattribute" not in seen:
        return None
    if "createprocessw" not in seen and "createprocessa" not in seen:
        return None
    texts = " ".join(str(item.get("text") or "") for item in instructions).casefold()
    mapping = strings_by_address or {}
    literal_strings: dict[str, str] = {}

    def _local_string(address: object) -> str | None:
        key = _addr_key(address)
        variants = [key, str(address or "").strip(), str(address or "").strip().removeprefix("0x")]
        try:
            number = int(key, 16) if key.startswith("0x") else None
        except ValueError:
            number = None
        if number is not None:
            variants.extend((hex(number), f"{number:x}", str(number)))
        for variant in variants:
            text = mapping.get(variant) or mapping.get(str(variant).casefold())
            if text:
                return str(text).split("\x00", 1)[0].strip().strip("\"'")
        for variant in variants:
            text = literal_strings.get(variant) or literal_strings.get(str(variant).casefold())
            if text:
                return str(text).split("\x00", 1)[0].strip().strip("\"'")
        return None

    if content:
        # The task-wide string table is capped, so a long orchestrator can lose
        # the literal it compares a process name against. Resolve this
        # function's own literals locally; the shared table stays untouched.
        literal_strings = resolve_function_data_strings(content, function, pe_summary)
    parent_selection = None
    address_sources: list[object] = [
        instruction.get("text") for instruction in instructions
    ]
    # The caller keys ``strings_by_address`` with the non-call reference targets
    # Ghidra reports under ``references_from``; the exporter row normally has no
    # ``data_references`` list at all.  Scan both so a literal that is named
    # only by a data reference, and not repeated as an instruction immediate,
    # is still matched.
    for key in ("data_references", "references_from"):
        for row in function.get(key) or ():
            if not isinstance(row, Mapping):
                continue
            if key == "references_from" and "call" in str(row.get("type") or "").casefold():
                continue
            address_sources.append(row.get("to") or row.get("target") or row.get("address"))
    for source in address_sources:
        if parent_selection:
            break
        blob = str(source or "")
        for match in re.finditer(r"(?i)(?:0x)?[0-9a-f]{6,}", blob):
            found = _local_string(match.group(0))
            if found and "explorer.exe" in found.casefold():
                parent_selection = leading_process_image_name(found) or found
                break
    if parent_selection is None and re.search(r"(?i)\bexplorer\.exe\b", texts):
        parent_selection = "explorer.exe"
    access_mask = None
    if "process_create_process" in texts or re.search(r"\b0x0*80\b", texts):
        access_mask = "PROCESS_CREATE_PROCESS"
    attribute = None
    if re.search(r"(?i)proc_thread_attribute_parent_process", texts) or re.search(
        r"\b0x0*20000\b", texts
    ):
        attribute = "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
    flags = unique_plausible_creation_flag(
        [str(item.get("text") or "") for item in instructions],
        window=len(instructions),
    )
    startup_info = None
    if flags:
        try:
            value = int(flags, 16)
        except ValueError:
            value = 0
        if value & 0x00080000:
            startup_info = "STARTUPINFOEX"
    if "startupinfoex" in texts:
        startup_info = "STARTUPINFOEX"
    callsite = None
    for instruction in instructions:
        text = str(instruction.get("text") or "")
        name = _call_api_from_instruction(
            text, {"updateprocthreadattribute", "createprocessw", "createprocessa"}
        )
        if name is None:
            call_imm = re.search(
                r"(?i)\bCALL\s+(?:FUN_|sub_)?(?:0x)?([0-9a-f]{6,})\b",
                text,
            )
            if call_imm:
                mapped = thunk_map.get(int(call_imm.group(1), 16))
                if mapped and mapped.casefold() in {
                    "updateprocthreadattribute",
                    "createprocessw",
                    "createprocessa",
                }:
                    name = mapped
        if name:
            callsite = str(instruction.get("address") or instruction.get("from") or "").strip() or None
            if name.casefold() == "updateprocthreadattribute":
                break
    payload: dict[str, object] = {
        "api": "UpdateProcThreadAttribute",
        "open_process": "OpenProcess",
        "create_process": "CreateProcessW" if "createprocessw" in seen else "CreateProcessA",
        "static_only": True,
    }
    if callsite:
        payload["callsite"] = callsite
    if parent_selection:
        payload["parent_selection"] = parent_selection
    if access_mask:
        payload["access_mask"] = access_mask
    if attribute:
        payload["attribute"] = attribute
    if startup_info:
        payload["startup_info"] = startup_info
    if flags:
        payload["creation_flags"] = flags
        payload["flags"] = flags
    if not any(payload.get(key) for key in ("parent_selection", "attribute", "startup_info")):
        return None
    return payload


def select_instruction_window_indices(
    instructions: Sequence[Mapping[str, object]],
    *,
    max_items: int | None = None,
    context: int = 3,
) -> tuple[int, ...]:
    """Select the instruction window for one function.

    ``max_items=None`` (the default) returns every instruction: the window is
    stored as the analysed function body, and a coverage-ranked subset is not a
    substitute for the function.  A bounded preview previously kept 418 of
    ``FUN_140004605``'s 4481 instructions and omitted the whole Windows
    Defender registry block, so the tampering never reached Evidence.

    ``max_items`` remains available as a degenerate-input guard for callers
    that must bound one call.  When it binds, the long function's useful
    consumer or cleanup path is still protected because anchors are chosen by
    score across the whole body rather than by prefix.  Callers that pass it are
    responsible for recording what was omitted -- see the
    ``instructions_total`` / ``instructions_selected`` fields of the emitted
    ``function_instruction_window`` payload.
    """
    rows = [row for row in instructions if isinstance(row, Mapping)]
    if not rows:
        return ()
    if max_items is None:
        return tuple(range(len(rows)))
    if max_items <= 0:
        return ()
    limit = min(max_items, len(rows))
    if len(rows) <= limit:
        return tuple(range(len(rows)))

    def score(index: int) -> int:
        text = str(rows[index].get("text") or rows[index].get("mnemonic") or "").casefold()
        value = 0
        if re.search(r"\b(call|jmp)\b", text):
            value += 100
        if re.search(r"\b(j[a-z]+|loop)\b", text):
            value += 60
        if "[" in text and "]" in text:
            value += 35
        if re.search(r"\b(xor|add|sub|cmp|test|lea|mov)\b", text):
            value += 10
        return value

    selected: set[int] = set(range(min(16, len(rows))))
    selected.update(range(max(0, len(rows) - 16), len(rows)))
    anchors = sorted(range(len(rows)), key=lambda item: (-score(item), item))
    for index in anchors:
        if score(index) <= 0:
            break
        for candidate in range(max(0, index - context), min(len(rows), index + context + 1)):
            if len(selected) >= limit:
                break
            selected.add(candidate)
        if len(selected) >= limit:
            break

    # Fill remaining capacity with evenly spaced positions so a low-signal
    # tail is still represented for model context and analyst drill-down.
    if len(selected) < limit:
        stride = max(1, len(rows) // max(1, limit - len(selected)))
        for index in range(0, len(rows), stride):
            if len(selected) >= limit:
                break
            selected.add(index)
    if len(selected) < limit:
        for index in range(len(rows)):
            if len(selected) >= limit:
                break
            selected.add(index)
    return tuple(sorted(selected))


def build_instruction_window_payload(
    *,
    name: object,
    entry: object,
    entry_rva: object,
    instructions: Sequence[Mapping[str, object]],
    pinned_indexes: Iterable[int] = (),
    max_items: int | None = None,
) -> dict[str, object]:
    """Build the stored ``function_instruction_window`` payload.

    The window is Evidence about the analysed function body, so it carries its
    own completeness envelope: ``instructions_total``, ``instructions_selected``
    and ``instructions_omitted`` are always present.  A truncated window can
    therefore never be mistaken for a short function -- which is how a 418-of-
    4481 preview of ``FUN_140004605`` let the Windows Defender registry block
    disappear without anyone noticing.

    ``pinned_indexes`` (recovered decode buffers, API thunks, process-creation
    and PPID callsites) are always admitted; they previously competed with the
    preview for the same slots, so a long function could lose the very callsite
    the pin existed to guarantee.
    """
    rows = [row for row in instructions if isinstance(row, Mapping)]
    selected = set(select_instruction_window_indices(rows, max_items=max_items, context=3))
    selected.update(
        index for index in pinned_indexes if isinstance(index, int) and 0 <= index < len(rows)
    )
    selected_rows = [dict(rows[index]) for index in sorted(selected)]
    omitted = max(0, len(rows) - len(selected_rows))
    payload: dict[str, object] = {
        "name": name,
        "entry": entry,
        "entry_rva": entry_rva,
        "instructions": selected_rows,
        "instructions_total": len(rows),
        "instructions_selected": len(selected_rows),
        "instructions_omitted": omitted,
        "selection": "complete_function_body" if not omitted else "degenerate_input_guard",
        "selected_for": [
            "call/data-flow context",
            "branch and immediate inspection",
            "decode-pattern screening",
        ],
    }
    if omitted:
        payload["truncation"] = {
            "reason": "degenerate_input_guard",
            "guard": "max_items",
            "limit": max_items,
            "instructions_dropped": omitted,
            "complete_exporter_json": "object storage retains every instruction",
        }
    return payload


def evidence_function_body(
    *,
    action: object,
    target_rows: Iterable[tuple[object, str]],
    fallback_name: object = "investigation-target",
    fallback_entry: object = "",
) -> dict[str, object]:
    """Rebuild the analysed function body from already-materialized Evidence.

    This dict is the input to the safe abstract executor, the CFG slice and the
    decompile projection, so it must carry the complete recovered instruction
    list.  It previously carried ``instruction_rows[:256]``, which on the 551KB
    Rust PE 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145
    cut ``FUN_140004605`` before the Windows Defender registry block -- the
    decompile and CFG projections could not see the code even when the window
    did contain it.  The executor's own ``max_steps`` remains the bound.
    """

    parameters = getattr(action, "parameters", None)
    if not isinstance(parameters, Mapping):
        parameters = {}
    instruction_rows: list[dict[str, object]] = []
    call_rows: list[dict[str, object]] = []
    data_reference_rows: list[dict[str, object]] = []
    context: dict[str, object] = {}
    for row, _text in target_rows:
        value = getattr(row, "value", None)
        kind = str(getattr(row, "kind", "") or "")
        if kind == "function_instruction_window" and isinstance(value, dict):
            candidate = value.get("instructions", [])
            if isinstance(candidate, list):
                instruction_rows.extend(item for item in candidate if isinstance(item, dict))
            continue
        if kind == "function_context" and isinstance(value, dict):
            if not context:
                context = dict(value)
            targets = value.get("call_targets", [])
            if isinstance(targets, list):
                call_rows.extend(item for item in targets if isinstance(item, dict))
            references = value.get("data_references", value.get("references", []))
            if isinstance(references, list):
                data_reference_rows.extend(
                    item for item in references if isinstance(item, dict)
                )
            continue
        if kind == "function_call" and isinstance(value, dict):
            call_rows.append(dict(value))
    if not instruction_rows:
        raw_context_instructions = context.get("instructions", [])
        if isinstance(raw_context_instructions, list):
            instruction_rows.extend(
                item for item in raw_context_instructions if isinstance(item, dict)
            )
    return {
        "name": context.get("name") or parameters.get("function") or fallback_name,
        "entry": context.get("entry") or parameters.get("entry") or fallback_entry,
        "architecture": context.get("architecture")
        or context.get("calling_convention")
        or "x86-64",
        "instructions": instruction_rows,
        "instructions_total": len(instruction_rows),
        "references_from": call_rows,
        "call_targets": call_rows,
        "data_references": data_reference_rows,
        # The raw function_context value is still needed by the CFG projection.
        # Expose it under a private key so callers do not re-scan target_rows.
        "context": context,
    }


def classify_pe_semantics(
    function: Mapping[str, object],
    pe_summary: Mapping[str, object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Classify a PE-oriented function using field access and output signals."""
    calls = function.get("references_from", [])
    call_names = [
        str(row.get("target_name") or row.get("target_function") or row.get("api") or "")
        for row in calls
        if isinstance(row, Mapping)
    ]
    instructions = [row for row in function.get("instructions", []) if isinstance(row, Mapping)]
    texts = [str(row.get("text", "")) for row in instructions]
    joined = " ; ".join([*call_names, *texts]).casefold()
    hash_info = recognize_hash_algorithm(instructions)
    hash_info = {
        **hash_info,
        "resolver_function": function.get("name"),
        "resolver_entry": function.get("entry") or function.get("entry_rva"),
    }
    export_resolution: tuple[dict[str, object], ...] = ()
    if isinstance(pe_summary, Mapping):
        raw_exports = pe_summary.get("exports")
        export_rows = raw_exports.get("functions", []) if isinstance(raw_exports, Mapping) else []
        if isinstance(export_rows, list) and hash_info.get("algorithm") in {
            "DJB2",
            "FNV-1a",
            "ROR13",
        }:
            export_resolution = resolve_export_hashes(
                [value for value in hash_info.get("constants", []) if isinstance(value, int)],
                [item for item in export_rows if isinstance(item, Mapping)],
                algorithms=(str(hash_info["algorithm"]),),
                module=str(raw_exports.get("module") or "")
                if isinstance(raw_exports, Mapping)
                else None,
            )
    fields = [
        token
        for token in (
            "numberofnames",
            "addressofnames",
            "addressofnameordinals",
            "addressoffunctions",
            "export directory",
            "export directory rva",
        )
        if token in joined
    ]
    looped = bool(re.search(r"\b(?:cmp|test|jnz|jne|loop)\b", joined))
    roles: list[dict[str, object]] = []
    if len(fields) >= 2 and looped:
        evidence = [*fields, *hash_info.get("patterns", [])]
        roles.append(
            {
                "role": "EXPORT_RESOLVER",
                "confidence": "HIGH"
                if len(fields) >= 4 and hash_info["algorithm"] != "unknown"
                else "MEDIUM",
                "evidence": evidence[:16],
                "missing": ["resolved export consumer"],
                "rationale": "export name/ordinal/function tables are iterated; hash recognition is"
                + (" present" if hash_info["algorithm"] != "unknown" else " not present"),
                "static_only": True,
            }
        )
    # Import resolver: walking the IAT/ILT or resolving import names is a
    # distinct role from parsing an export table.  Require table/slot access or
    # an explicit resolver call, never a lone imported API name.
    import_features = [
        token
        for token in (
            "import directory",
            "originalfirstthunk",
            "firstthunk",
            "iat",
            "ilt",
            "address of iat",
            "loadlibrary",
            "getprocaddress",
            "getimportaddress",
            "resolve imports",
            "import name",
        )
        if token in joined
    ]
    if len(set(import_features)) >= 2:
        roles.append(
            {
                "role": "IMPORT_RESOLVER",
                "confidence": "HIGH" if len(set(import_features)) >= 3 else "MEDIUM",
                "evidence": import_features[:16],
                "missing": ["resolved import consumer"],
                "rationale": "IAT/ILT fields or dynamic import APIs are combined with a table/slot access",
                "static_only": True,
            }
        )
    # Manual mapping needs an ordered payload path: allocate/write image bytes,
    # apply relocations/imports, then transfer execution.  Header field names
    # and VirtualProtect alone are common in validators and are insufficient.
    manual_features = [
        token
        for token in (
            "section table",
            "virtualalloc",
            "virtualprotect",
            "relocation",
            "basereloc",
            "writeprocessmemory",
            "memcpy",
            "rwx",
            "entrypoint",
            "call entrypoint",
            "createthread",
            "createremotethread",
            "setthreadcontext",
        )
        if token in joined
    ]
    has_write = any(
        token in joined
        for token in ("writeprocessmemory", "memcpy", "memmove", "copy section", "write image")
    )
    has_map = any(
        token in joined
        for token in ("section table", "relocation", "basereloc", "import directory", "map image")
    )
    has_transfer = any(
        token in joined
        for token in (
            "call entrypoint",
            "createthread",
            "createremotethread",
            "setthreadcontext",
            "jmp entrypoint",
        )
    )
    if "virtualalloc" in joined and has_write and has_map and has_transfer:
        roles.append(
            {
                "role": "MANUAL_MAPPER",
                "confidence": "HIGH",
                "evidence": manual_features[:16],
                "missing": [],
                "rationale": "ordered allocation, image write, relocation/import preparation, and execution transfer signals co-occur",
                "static_only": True,
            }
        )
    resource_features = [
        token
        for token in (
            "findresource",
            "loadresource",
            "lockresource",
            "sizeofresource",
            "resource directory",
        )
        if token in joined
    ]
    if len(set(resource_features)) >= 2:
        roles.append(
            {
                "role": "RESOURCE_PARSER",
                "confidence": "MEDIUM",
                "evidence": resource_features[:16],
                "missing": ["embedded payload consumer"],
                "rationale": "resource directory APIs/fields are used",
                "static_only": True,
            }
        )
    if (
        any(token in joined for token in ("mz", "pe\\x00\\x00", "dos header", "nt headers"))
        and not roles
    ):
        roles.append(
            {
                "role": "PE_VALIDATOR",
                "confidence": "LOW",
                "evidence": ["MZ/PE header validation"],
                "missing": ["field iteration output", "downstream consumer"],
                "rationale": "header identity alone supports validation only",
                "static_only": True,
            }
        )
    if not roles:
        roles.append(
            {
                "role": "UNKNOWN_PE_ROLE",
                "confidence": "LOW",
                "evidence": [],
                "missing": ["discriminating PE field accesses"],
                "rationale": "insufficient static evidence",
                "static_only": True,
            }
        )
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
    if data.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
        return FormatIdentity("7z", "application/x-7z-compressed", "magic")
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
        characteristics, timestamp, major, minor, type_id, size, address, pointer = (
            struct.unpack_from("<IIHHIIII", data, offset)
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


def _parse_pe_tls_callbacks(
    data: bytes,
    *,
    pe_plus: bool,
    image_base: int,
    optional_offset: int,
    optional_size: int,
    directory_count: int,
    directory_base: int,
    rva_to_offset: Callable[[int], int | None],
) -> list[dict[str, object]]:
    """Read IMAGE_DIRECTORY_ENTRY_TLS callback VAs without executing the image."""
    tls_index = 9
    entry_off = directory_base + tls_index * 8
    if directory_count <= tls_index or entry_off + 8 > optional_offset + optional_size:
        return []
    tls_rva = struct.unpack_from("<I", data, entry_off)[0]
    if not tls_rva:
        return []
    tls_off = rva_to_offset(tls_rva)
    directory_size = 40 if pe_plus else 24
    if tls_off is None or tls_off + directory_size > len(data):
        return []
    width = 8 if pe_plus else 4
    unpack = "<Q" if pe_plus else "<I"
    start_raw = struct.unpack_from(unpack, data, tls_off)[0]
    end_raw = struct.unpack_from(unpack, data, tls_off + width)[0]
    index_va = struct.unpack_from(unpack, data, tls_off + 2 * width)[0]
    callbacks_va = struct.unpack_from(unpack, data, tls_off + 3 * width)[0]
    if not callbacks_va:
        return []
    callbacks_rva = callbacks_va - image_base if callbacks_va >= image_base else callbacks_va
    callbacks_off = rva_to_offset(int(callbacks_rva))
    if callbacks_off is None:
        return []
    found: list[dict[str, object]] = []
    for index in range(32):
        item_off = callbacks_off + index * width
        if item_off + width > len(data):
            break
        callback_va = struct.unpack_from(unpack, data, item_off)[0]
        if callback_va == 0:
            break
        callback_rva = (
            callback_va - image_base if callback_va >= image_base else callback_va
        )
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
    return found


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
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        raw = data[raw_offset : raw_offset + raw_size] if raw_offset < len(data) else b""
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "entropy": round(_entropy(raw), 3),
                "characteristics": characteristics,
                "executable": bool(characteristics & 0x20000000),
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
    code_signals = _scan_x86_code(
        data,
        sections,
        image_base,
        imports,
        is_64=pe_plus or machine == 0x8664,
    )
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
    debug_directory = _parse_debug_directory(data, sections, debug_rva, debug_size, rva_to_offset)
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
    tls_callbacks = _parse_pe_tls_callbacks(
        data,
        pe_plus=pe_plus,
        image_base=image_base,
        optional_offset=optional_offset,
        optional_size=optional_size,
        directory_count=directory_count,
        directory_base=directory_base,
        rva_to_offset=rva_to_offset,
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
        "tls_callbacks": tls_callbacks,
        "pe_header_offset": pe_offset,
    }


def pe_slice_at_rva(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    address: int,
    *,
    length: int = 512,
) -> bytes:
    """Return granted PE file bytes at an RVA or image VA. Empty if unmapped."""
    if not content or length <= 0 or address < 0:
        return b""
    summary = dict(pe_summary or {})
    image_base = int(summary.get("image_base", 0) or 0)
    rva = address - image_base if image_base and address >= image_base else address
    sections = summary.get("sections", [])
    section_rows = sections if isinstance(sections, list) else []
    for section in section_rows:
        if not isinstance(section, dict):
            continue
        start = int(section.get("virtual_address", 0) or 0)
        span = max(int(section.get("virtual_size", 0) or 0), int(section.get("raw_size", 0) or 0))
        if start <= rva < start + span:
            offset = int(section.get("raw_offset", 0) or 0) + (rva - start)
            if 0 <= offset < len(content):
                return content[offset : offset + min(length, len(content) - offset)]
    if 0 <= rva < len(content):
        return content[rva : rva + min(length, len(content) - rva)]
    return b""


def recovered_payload_from_verification(verification: Mapping[str, object] | None) -> bytes:
    """Return recovered transform bytes only when a real payload exists.

    MZ text or a two-byte stub is not a child artifact.  A longer recovered
    buffer that happens to start with MZ remains eligible for the static
    pipeline.
    """
    if not isinstance(verification, Mapping):
        return b""
    status = str(verification.get("status") or "").upper()
    if status not in {"VERIFIED_STATIC_DATA", "SUCCEEDED"}:
        return b""
    hex_text = str(verification.get("plaintext_hex") or verification.get("output_hex") or "").strip()
    payload = b""
    if hex_text and all(char in "0123456789abcdefABCDEF" for char in hex_text) and len(hex_text) % 2 == 0:
        try:
            payload = bytes.fromhex(hex_text)
        except ValueError:
            payload = b""
    raw = verification.get("output_bytes")
    if isinstance(raw, (bytes, bytearray)) and not payload:
        payload = bytes(raw)
    if len(payload) < 16:
        return b""
    return payload


_THREAD_API_NAMES = {
    "createthread",
    "createthreadex",
    "tpallocwork",
    "submitthreadpoolwork",
    "createthreadpoolwait",
    "createthreadpooltimer",
    "tlssetvalue",
    "addvectoredexceptionhandler",
    "setwaitabletimer",
    "createtimerqueuetimer",
}
_REMOTE_THREAD_API_NAMES = {
    "createremotethread",
    "writeprocessmemory",
    "virtualallocex",
    "ntopenprocess",
}
_CALL_IMM_RE = re.compile(
    r"(?i)\bCALL\s+(?:FUN_|sub_|LAB_)?(?:0x)?([0-9a-f]{6,})\b"
)


def unique_thread_function_starts(
    functions: Iterable[Mapping[str, object]] | None,
    thunks: Mapping[int, str] | None = None,
) -> tuple[dict[str, object], ...]:
    """Return same-process thread/callback creators, not remote injection."""
    rows = [item for item in functions or () if isinstance(item, Mapping)]
    thunk_map = {
        int(key): str(value)
        for key, value in (
            thunks if thunks is not None else import_api_thunks(rows, _THREAD_IMPORT_NAMES)
        ).items()
    }
    starts: list[dict[str, object]] = []
    for function in rows:
        names: list[str] = []
        for key in ("references_from", "call_targets", "calls"):
            refs = function.get(key)
            if not isinstance(refs, list):
                continue
            for row in refs:
                if not isinstance(row, Mapping):
                    continue
                label = str(
                    row.get("target_name") or row.get("target_function") or row.get("api") or ""
                )
                if label:
                    names.append(label)
                for locator in (row.get("to"), row.get("target"), row.get("address")):
                    mapped_key = _addr_key(locator)
                    if mapped_key.startswith("0x"):
                        mapped = thunk_map.get(int(mapped_key, 16))
                        if mapped:
                            names.append(mapped)
        for instruction in function.get("instructions") or ():
            if not isinstance(instruction, Mapping):
                continue
            text = str(instruction.get("text") or "")
            api = _call_api_from_instruction(text, _THREAD_API_NAMES | _REMOTE_THREAD_API_NAMES)
            if api:
                names.append(api)
            call_imm = _CALL_IMM_RE.search(text)
            if call_imm:
                mapped = thunk_map.get(int(call_imm.group(1), 16))
                if mapped:
                    names.append(mapped)
        found = {
            str(item).casefold().rsplit("!", 1)[-1].rsplit(".", 1)[-1]
            for item in names
        }
        if found & _THREAD_API_NAMES and not (found & _REMOTE_THREAD_API_NAMES):
            starts.append(dict(function))
    return tuple(starts[:8])


_THREAD_START_REG_RE = re.compile(
    r"(?i)\b(?:LEA|MOV)\s+R8(?:D)?\s*,\s*"
    r"(?:(?:qword\s+ptr\s+)?\[(?:RAM:)?)?(?:FUN_|sub_|LAB_)?(?:0x)?([0-9a-f]{6,})"
)


def unique_thread_start_routine_vas(
    functions: Iterable[Mapping[str, object]] | None,
    thunks: Mapping[int, str] | None = None,
) -> tuple[int, ...]:
    """lpStartAddress targets of same-process CreateThread, not the creator.

    The 96-function Ghidra page ranks WaitForSingleObject bodies below
    CreateProcess helpers. Resume's unique OS loop/exit live in that body.
    Live Ghidra often names the import an IAT JMP thunk, not CreateThread.
    """
    vas: list[int] = []
    for function in unique_thread_function_starts(functions, thunks=thunks):
        for instruction in function.get("instructions") or ():
            if not isinstance(instruction, Mapping):
                continue
            match = _THREAD_START_REG_RE.search(str(instruction.get("text") or ""))
            if not match:
                continue
            try:
                vas.append(int(match.group(1), 16))
            except ValueError:
                continue
        for row in function.get("arguments") or ():
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "").casefold()
            if name not in {"lpstartaddress", "startaddress", "callback"}:
                continue
            raw = str(row.get("value") or "")
            try:
                if raw.casefold().startswith("0x"):
                    vas.append(int(raw, 16))
                elif re.fullmatch(r"[0-9a-fA-F]{6,}", raw):
                    vas.append(int(raw, 16))
            except ValueError:
                continue
    return tuple(dict.fromkeys(vas))[:8]


def unique_thread_start_routine_vas_from_pe(
    pe_summary: Mapping[str, object] | None,
) -> tuple[int, ...]:
    """lpStartAddress from Capstone CreateThread, available before Ghidra ranking.

    Live Resume recovers start=0x140038ae0 in PE ``code_signals`` while Ghidra
    function rows often lack ``LEA R8`` at the 96-function budget cut.
    """
    if not isinstance(pe_summary, Mapping):
        return ()
    try:
        image_base = int(pe_summary.get("image_base") or 0)
    except (TypeError, ValueError):
        image_base = 0
    signals = pe_summary.get("code_signals")
    if not isinstance(signals, Mapping):
        return ()
    vas: list[int] = []
    for call in signals.get("api_calls") or ():
        if not isinstance(call, Mapping):
            continue
        api = str(call.get("api") or "").casefold().rsplit("!", 1)[-1].rsplit(".", 1)[-1]
        if api not in _THREAD_API_NAMES or api in _REMOTE_THREAD_API_NAMES:
            continue
        for row in call.get("arguments") or ():
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "").casefold()
            if name not in {"lpstartaddress", "startaddress", "callback"}:
                continue
            if row.get("resolved") is False:
                continue
            raw = str(row.get("value") or "")
            try:
                if raw.casefold().startswith("0x"):
                    value = int(raw, 16)
                elif re.fullmatch(r"[0-9a-fA-F]{6,}", raw):
                    value = int(raw, 16)
                else:
                    continue
            except ValueError:
                continue
            if 0 < value < 0x10000 and image_base:
                value += image_base
            vas.append(value)
    return tuple(dict.fromkeys(vas))[:8]


_CREATE_THREAD_STDCALL = (
    "lpThreadAttributes",
    "dwStackSize",
    "lpStartAddress",
    "lpParameter",
    "dwCreationFlags",
    "lpThreadId",
)


def _stdcall_create_thread_arguments(
    api: str,
    recent_pushes: list[int | None],
    *,
    is_64: bool,
) -> list[dict[str, object]]:
    """Map PE32 PUSH immediates before CreateThread onto stdcall argument names."""
    if is_64 or "createthread" not in str(api).casefold().replace(" ", ""):
        return []
    stack = list(reversed(recent_pushes[-len(_CREATE_THREAD_STDCALL) :]))
    arguments: list[dict[str, object]] = []
    for index, name in enumerate(_CREATE_THREAD_STDCALL):
        if index >= len(stack):
            break
        value = stack[index]
        arguments.append(
            {
                "index": index,
                "name": name,
                "value": hex(value) if isinstance(value, int) else "UNKNOWN",
                "resolved": isinstance(value, int),
            }
        )
    return arguments


_X64_CREATE_THREAD_REGS = {
    "rcx": 0,
    "ecx": 0,
    "rdx": 1,
    "edx": 1,
    "r8": 2,
    "r8d": 2,
    "r9": 3,
    "r9d": 3,
}


def _x64_create_thread_arguments(
    api: str,
    recent_regs: Mapping[int, int],
    *,
    is_64: bool,
) -> list[dict[str, object]]:
    """Map Windows x64 RCX/RDX/R8/R9 producers onto CreateThread names.

    lpStartAddress is R8 (index 2). A CreateThread call reached through a
    local import thunk still needs that register window; PUSH stdcall does
    not apply.
    """
    if not is_64 or "createthread" not in str(api).casefold().replace(" ", ""):
        return []
    start = recent_regs.get(2)
    if not isinstance(start, int):
        return []
    arguments: list[dict[str, object]] = []
    for index, name in enumerate(_CREATE_THREAD_STDCALL[:4]):
        value = recent_regs.get(index)
        arguments.append(
            {
                "index": index,
                "name": name,
                "value": hex(value) if isinstance(value, int) else "UNKNOWN",
                "resolved": isinstance(value, int),
            }
        )
    return arguments


def _annotate_create_thread_call(
    item: dict[str, object],
    api: str,
    recent_pushes: list[int | None],
    recent_regs: Mapping[int, int],
    *,
    is_64: bool,
) -> dict[str, object]:
    arguments = _stdcall_create_thread_arguments(api, recent_pushes, is_64=is_64)
    if not arguments:
        arguments = _x64_create_thread_arguments(api, recent_regs, is_64=is_64)
    if arguments:
        item["arguments"] = arguments
    return item


def _scan_x86_code(
    data: bytes,
    sections: list[dict[str, object]],
    image_base: int,
    imports: list[dict[str, object]],
    *,
    is_64: bool = False,
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
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    disassembler.detail = True
    api_calls: list[dict[str, object]] = []
    patterns: list[dict[str, object]] = []
    compression_format_2 = False
    constants = {0x6033A96D: "xor_state_multiplier", 0xDD483B8F: "xor_state_subtractor"}
    for section in sections:
        name = str(section.get("name", ""))
        if name.lower() in {".rsrc", ".reloc"}:
            continue
        # PE section characteristics are authoritative when available.  The
        # old fallback fixtures do not carry this field, so keep scanning
        # those explicitly supplied sections for backwards compatibility.
        if "executable" in section and not bool(section.get("executable")):
            continue
        raw_offset = int(section.get("raw_offset", 0))
        raw_size = min(int(section.get("raw_size", 0)), 8 * 1024 * 1024)
        if raw_size <= 0 or raw_offset < 0 or raw_offset + raw_size > len(data):
            continue
        code = data[raw_offset : raw_offset + raw_size]
        start_rva = int(section.get("virtual_address", 0))
        recent: list[str] = []
        recent_pushes: list[int | None] = []
        recent_regs: dict[int, int] = {}
        instructions = list(disassembler.disasm(code, image_base + start_rva))
        # Compilers commonly route external calls through a short local thunk:
        # ``call rel32 -> jmp [rip+disp32] -> IAT``.  Resolve the thunk map in
        # a first pass, then attribute direct relative calls in the second
        # pass.  This remains purely static and does not dereference sample
        # memory or execute any instruction.
        thunk_targets: dict[int, str] = {}
        for instruction in instructions:
            if instruction.mnemonic not in {"jmp", "call"} or not instruction.operands:
                continue
            operand = instruction.operands[0]
            if operand.type != 3:  # X86_OP_MEM
                continue
            target_address = int(operand.mem.disp)
            if is_64 and operand.mem.base and instruction.reg_name(operand.mem.base).lower() == "rip":
                target_address = int(instruction.address + instruction.size + operand.mem.disp)
            target = iat.get(target_address)
            if target:
                thunk_targets[int(instruction.address)] = target

        seen_api_calls: set[tuple[str, int]] = set()
        for instruction in instructions:
            text = f"{instruction.mnemonic} {instruction.op_str}".strip()
            if instruction.mnemonic in {"push", "mov", "xor", "or", "and"} and re.search(
                r"(?:^|,\s*)(?:0x)?2(?:\b|$)", instruction.op_str.lower()
            ):
                compression_format_2 = True
            recent.append(text)
            if len(recent) > 8:
                recent.pop(0)
            if not is_64 and instruction.mnemonic == "push" and instruction.operands:
                operand = instruction.operands[0]
                recent_pushes.append(
                    int(operand.imm) & 0xFFFFFFFF if operand.type == 2 else None
                )
                if len(recent_pushes) > 8:
                    recent_pushes.pop(0)
            if is_64 and instruction.mnemonic in {"mov", "lea", "movabs"} and len(instruction.operands) >= 2:
                dest = instruction.operands[0]
                src = instruction.operands[1]
                if dest.type == 1:  # REG
                    index = _X64_CREATE_THREAD_REGS.get(instruction.reg_name(dest.reg).lower())
                    if index is not None:
                        if src.type == 2:  # IMM
                            recent_regs[index] = int(src.imm) & 0xFFFFFFFFFFFFFFFF
                        elif (
                            instruction.mnemonic == "lea"
                            and src.type == 3
                            and src.mem.base
                            and instruction.reg_name(src.mem.base).lower() == "rip"
                        ):
                            recent_regs[index] = int(
                                instruction.address + instruction.size + src.mem.disp
                            )
            if instruction.mnemonic == "call" and instruction.operands:
                operand = instruction.operands[0]
                if operand.type == 3:  # X86_OP_MEM
                    # x64 import thunks are normally addressed through RIP
                    # relative memory operands.  Capstone exposes only the
                    # displacement, so resolve the effective address from
                    # the current instruction rather than treating the
                    # displacement as an absolute IAT slot.  Legacy x86
                    # absolute operands retain the historical path.
                    target_address = int(operand.mem.disp)
                    if is_64 and operand.mem.base and instruction.reg_name(operand.mem.base).lower() == "rip":
                        target_address = int(instruction.address + instruction.size + operand.mem.disp)
                    target = iat.get(target_address)
                    if target:
                        row = (
                            target,
                            int(instruction.address - image_base),
                        )
                        if row not in seen_api_calls:
                            seen_api_calls.add(row)
                            item = {
                                "api": target,
                                "address": row[1],
                                "file_offset": raw_offset
                                + int(instruction.address - image_base - start_rva),
                            }
                            api_calls.append(
                                _annotate_create_thread_call(
                                    item, target, recent_pushes, recent_regs, is_64=is_64
                                )
                            )
                        recent_regs.clear()
                elif is_64 and operand.type == 2:  # X86_OP_IMM, direct rel32 call
                    target = thunk_targets.get(int(operand.imm))
                    if target:
                        row = (target, int(instruction.address - image_base))
                        if row not in seen_api_calls:
                            seen_api_calls.add(row)
                            api_calls.append(
                                _annotate_create_thread_call(
                                    {
                                        "api": target,
                                        "address": row[1],
                                        "file_offset": raw_offset
                                        + int(instruction.address - image_base - start_rva),
                                        "via_thunk": f"0x{int(operand.imm) - image_base:x}",
                                    },
                                    target,
                                    recent_pushes,
                                    recent_regs,
                                    is_64=is_64,
                                )
                            )
                        recent_regs.clear()
                else:
                    recent_regs.clear()
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
        "architecture": "x86-64" if is_64 else "x86",
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
            payload_rva, payload_size, code_page, _ = struct.unpack_from("<IIII", data, data_offset)
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
                {
                    "machine": pe.get("machine"),
                    "subsystem": pe.get("subsystem"),
                    "checksum": pe.get("checksum"),
                },
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
                    {
                        "api": "RtlDecompressBuffer",
                        "compression_format": 2,
                        "format": "LZNT1 candidate",
                    },
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
                    if any(
                        token in lowered_api
                        for token in (
                            "findresource",
                            "loadresource",
                            "sizeofresource",
                            "lockresource",
                        )
                    ):
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
                    elif any(
                        token in lowered_api
                        for token in ("globalmemorystatusex", "getsysteminfo", "virtualquery")
                    ):
                        emit(
                            "anti_analysis",
                            "mechanism_environment_check",
                            {"api": api, "call_sites": calls[:32]},
                            "x86_call_site",
                        )
                    elif any(
                        token in lowered_api
                        for token in ("openscmanager", "openservice", "queryservicestatus")
                    ):
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
                "apis": [
                    term
                    for term in ("FindResource", "LoadResource", "SizeofResource", "LockResource")
                    if has_any(term)
                ],
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
        any(
            token in name
            for token in ("cryptdecrypt", "bcryptdecrypt", "cryptencrypt", "bcryptencrypt")
        )
        for name in call_api_names
    )
    crypto_dataflow_context = any(
        any(
            "[" in str(instruction.get("text") or "") and "]" in str(instruction.get("text") or "")
            for instruction in (
                function.get("instructions", []) if isinstance(function, dict) else []
            )
            if isinstance(instruction, dict)
        )
        for function in function_rows
        if isinstance(function, dict)
        and any(
            any(
                token
                in str(
                    call.get("target_name") or call.get("target_function") or call.get("api") or ""
                ).casefold()
                for token in ("cryptdecrypt", "bcryptdecrypt", "cryptencrypt", "bcryptencrypt")
            )
            for call in (
                function.get("references_from", [])
                if isinstance(function.get("references_from", []), list)
                else []
            )
            if isinstance(call, dict)
        )
    )
    if crypto_api_present and crypto_dataflow_context:
        emit(
            "decryption",
            "mechanism_decode",
            {
                "operation": "cryptographic API decode candidate",
                "standard": True,
                "apis": sorted(call_api_names)[:16],
            },
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
            {
                "apis": [
                    term
                    for term in (
                        "GlobalMemoryStatusEx",
                        "GetSystemInfo",
                        "VirtualQuery",
                        "IsDebuggerPresent",
                    )
                    if has_any(term)
                ]
            },
            "api_call_chain",
        )
    if has_any("openscmanager", "openservice", "queryservicestatus"):
        emit(
            "anti_analysis",
            "mechanism_service_query",
            {
                "apis": [
                    term
                    for term in ("OpenSCManager", "OpenService", "QueryServiceStatus")
                    if has_any(term)
                ]
            },
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
        is_call_reference = (
            "call" in reference_type or "call" in str(call.get("target_function", "")).lower()
        )
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
            category = (
                "dynamic_resolution"
                if semantic_category(name) == "dynamic_resolution"
                else "loader"
            )
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
            steps.append(
                {
                    "category": category,
                    "name": name,
                    "address": call.get("from"),
                    "target": call.get("to"),
                    "reference_type": call.get("type"),
                }
            )

    instructions = function.get("instructions", [])
    instruction_text = (
        [
            str(item.get("text", ""))
            for item in instructions
            if isinstance(item, dict) and item.get("text")
        ]
        if isinstance(instructions, list)
        else []
    )
    process_flag_facts: list[dict[str, object]] = []
    process_names = {
        str(step.get("name", "")).lower()
        for step in steps
        if str(step.get("category", "")) == "execution"
    }
    if any("createprocess" in name for name in process_names):
        seen_flags: set[int] = set()
        for text in instruction_text:
            for token in re.findall(r"0x[0-9A-Fa-f]{1,8}", text):
                value = _parse_int_literal(token)
                if value is None or value in seen_flags:
                    continue
                if not plausible_windows_process_creation_flags(value):
                    continue
                decoded = decode_windows_process_creation_flags(value)
                seen_flags.add(value)
                process_flag_facts.append(decoded)
    # Do not promote an XOR count to a decoder.  Register-zeroing idioms and
    # compiler-generated parity checks are ubiquitous.  Only the bounded
    # window detector, which requires a non-zeroing transform and loop shape,
    # can create a decode investigation seed.
    instruction_rows = (
        [item for item in instructions if isinstance(item, dict)]
        if isinstance(instructions, list)
        else []
    )
    decode_window = analyze_xor_decode_window(instruction_rows)
    if decode_window is not None:
        requirements = decode_window.get("semantic_requirements", {})
        if isinstance(requirements, Mapping) and requirements.get("non_zeroing_transform"):
            steps.append(
                {
                    "category": "decode_candidate",
                    "name": "bounded XOR transform loop",
                    "count": decode_window.get("xor_count", 0),
                    "window": decode_window,
                }
            )

    chains: list[StaticFact] = []
    if process_flag_facts:
        chains.append(
            StaticFact(
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
            )
        )

    def emit(module: str, chain_type: str, categories: tuple[str, ...], rationale: str) -> None:
        selected = [step for step in steps if step.get("category") in categories]
        present = tuple(dict.fromkeys(str(step["category"]) for step in selected))
        if len(present) < 2:
            return
        chains.append(
            StaticFact(
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
            )
        )

    emit(
        "anti_analysis",
        "environment_gate",
        ("anti_analysis", "decode_candidate"),
        "environment checks are sequenced with a transformation/guard pattern",
    )
    emit(
        "loader",
        "dynamic_loader",
        ("dynamic_resolution", "network", "file_io", "decode_candidate"),
        "dynamic resolution or decoded data is sequenced with transport or file preparation",
    )
    emit(
        "c2_network",
        "network_download",
        ("network", "file_io", "execution"),
        "transport, file output, and execution-related operations occur in one function",
    )
    emit(
        "execution",
        "process_execution",
        ("injection", "execution"),
        "process creation is combined with parent/process attribute manipulation",
    )
    emit(
        "loader",
        "persistence_fallback",
        ("execution", "persistence"),
        "execution and persistence operations are present in the same function; branch order requires validation",
    )
    return tuple(chains)


def _literal_table_plaintext_field(recovered: Any) -> str:
    """A bounded, renderable excerpt of the decoded literal table.

    `analyst_report._plaintext_value` recognises exactly three shapes for the decode section's inline
    value: `plaintext=`...``, a `C:\\...` path, or an `http(s)://` URL. A decoded VB6 literal table is
    fragmented script text and need not contain any of them, so one is supplied from the recovered text
    itself - the longest URL or Windows path when present, otherwise the first clearly script-shaped window.

    Only text that is actually IN the recovered output is used, and the field is bounded, so nothing is
    fabricated and the section cannot be inflated by it.
    """
    text = str(getattr(recovered, "text", "") or "")
    if not text:
        return ""
    import re as _re

    for pattern in (r"https?://[^\s`\"']{4,120}", r"[A-Za-z]:\\\\[^\s`\"']{3,120}"):
        found = _re.search(pattern, text, _re.IGNORECASE)
        if found:
            return found.group(0)[:200]
    # No URL or path recovered: use the longest run that contains a script keyword, so the value is
    # recognisably script source rather than arbitrary bytes.
    for keyword in ("WScript", "CreateObject", "FileSystem", "Exec", "Replace", "InStr"):
        index = text.find(keyword)
        if index >= 0:
            window = text[max(0, index - 40) : index + 120]
            cleaned = " ".join(window.split())
            if cleaned:
                return cleaned[:160]
    return ""


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
                    classify_static_string(
                        str(extracted["text"]), str(extracted.get("encoding", "ascii"))
                    ),
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
            for callback in pe.get("tls_callbacks") or ():
                if not isinstance(callback, dict):
                    continue
                entry = callback.get("entry")
                if not entry:
                    continue
                facts.append(
                    StaticFact(
                        "static_triage",
                        "tls_callback",
                        {
                            "name": "tls_callback",
                            "entry": entry,
                            "rva": callback.get("rva"),
                            "role": "tls_callback",
                        },
                        {
                            "type": "rva",
                            "function_entry": entry,
                            "role": "tls_callback",
                        },
                    )
                )
            image_base = int(pe.get("image_base") or 0)
            signals = pe.get("code_signals") if isinstance(pe.get("code_signals"), dict) else {}
            for call in signals.get("api_calls") or []:
                if not isinstance(call, dict):
                    continue
                arguments = call.get("arguments")
                if not isinstance(arguments, list) or not arguments:
                    continue
                api = str(call.get("api") or "")
                rva = int(call.get("address") or 0)
                callsite = hex(image_base + rva) if image_base else hex(rva)
                entry_rva = int(pe.get("entry_rva") or 0)
                function_entry = (
                    hex(image_base + entry_rva)
                    if image_base and rva == entry_rva
                    else callsite
                )
                facts.append(
                    StaticFact(
                        "static_triage",
                        "api_argument_trace",
                        {
                            "api": api.rsplit("!", 1)[-1],
                            "callsite": callsite,
                            "function_entry": function_entry,
                            "arguments": [dict(item) for item in arguments if isinstance(item, dict)],
                            "trace_quality": "x86_stdcall_push",
                            "static_only": True,
                        },
                        {
                            "type": "x86_call_site",
                            "function_entry": function_entry,
                            "rva": rva,
                        },
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
                                or int(
                                    (string_xrefs or {}).get(
                                        offset, (string_xrefs or {}).get(str(offset), 0)
                                    )
                                    or 0
                                )
                            ),
                        )
                        facts[index] = StaticFact(fact.module, fact.kind, enriched, fact.anchor)
            # Hex-encoded literal tables are a THIRD decode shape, and the only one that fits a VB6
            # literal installer: the script is stored as ASCII hex inside UTF-16LE records and there is no
            # key, counter or algorithm to recover - which is why the XOR and primitive recoverers correctly
            # find nothing on such a sample and why a `DECODE_CONFIG` ticket listing
            # `key, algorithm, counter, step` can never be closed by them. Measured on the 白象 sample
            # `64da3378`: this path yields 5,881 characters of VBScript while both other recoverers yield
            # zero configs.
            literal_table = discover_hex_literal_table(data, pe)
            if literal_table.decoded:
                evidence = literal_table.as_evidence()
                # BOUND EVERY CARRIED COPY OF THE RECOVERED TEXT.
                #
                # MEASURED: with a 5,881-character `output_buffer`, the recovered script was copied into
                # per-row diagnostic fields that the renderer afterwards quotes - `consumer.reason` grew to
                # 5,920 characters and the SAME text appeared in about ten places. The published revision
                # went 9,084 -> 22,452 characters, so most of the growth was duplication rather than content.
                # Those fields carry a SHORT diagnostic by construction, so a full-text copy there is a
                # misuse of the consumer, not extra evidence.
                #
                # The recovered text is still published in full through `recovered_text`/`decoded_text`
                # (bounded at 8 KiB), which is what the decode section renders; the analysis-side fields get
                # a bounded preview.
                _short_preview = " ".join(literal_table.text[:400].split())
                facts.append(
                    StaticFact(
                        "decryption",
                        "decode_result",
                        {
                            "source_kind": "encoded_blob",
                            "verification": evidence,
                            "verification_status": "DECODED_STATIC",
                            "candidate": {
                                "encoding": evidence["encoding"],
                                "decode_chain": evidence["decode_chain"],
                                "memory_addresses": [literal_table.table_offset],
                                # Bounded: this is the analysis-side output slot, quoted into diagnostics.
                                "output_buffer": _short_preview,
                                "output_chars": len(literal_table.text),
                            },
                            "recovered_text": literal_table.text[:8192],
                            # The published body's 编码/解密与配置还原 section reads
                            # `decoded_preview` / `decoded_text` / `decoded_strings` / `plaintext`
                            # (`analyst_report`), so the recovered script is exposed under those names too.
                            # Adding a fourth private spelling would put the fact in the document and leave
                            # it unreachable from the body - the R1/R2 join failure this project exists to
                            # remove, and the exact shape of the model-candidate gap fixed earlier.
                            "decoded_preview": _short_preview,
                            "decoded_text": literal_table.text[:8192],
                            # The section renders a decode result only when the blob carries one of its
                            # recognised shapes: `plaintext=`...``, a `C:\...` path, or an `http(s)://` URL
                            # (`analyst_report._plaintext_value`). Without one the fact is in the document
                            # and absent from the body - R2 again.
                            "plaintext": _literal_table_plaintext_field(literal_table),
                            "marker_classes": list(literal_table.class_names()),
                            "consumer_status": "NOT_IDENTIFIED",
                            "static_only": True,
                        },
                        {
                            "type": "file_offset",
                            "offset": literal_table.table_offset,
                            "virtual_address": literal_table.table_offset,
                        },
                    )
                )
            for recovered in (
                *recover_static_xor_configs(data, pe),
                *recover_primitive_decode_configs(data, pe),
            ):
                facts.append(
                    StaticFact(
                        "decryption",
                        "decode_result",
                        {
                            "source_kind": "encoded_blob",
                            "verification": recovered,
                            "verification_status": recovered.get("status"),
                            "candidate": {
                                "formula": recovered.get("formula"),
                                "memory_addresses": [recovered.get("virtual_address")],
                                "key_table": recovered.get("key_table"),
                                "initial_key": recovered.get("initial_key"),
                                "key_step": recovered.get("key_step"),
                                "output_buffer": recovered.get("output_buffer"),
                            },
                            "consumer_status": "NOT_IDENTIFIED",
                            "static_only": True,
                        },
                        {
                            "type": "file_offset",
                            "offset": recovered.get("file_offset"),
                            "virtual_address": recovered.get("virtual_address"),
                        },
                    )
                )
                facts.append(
                    StaticFact(
                        "static_triage",
                        "encoded_blob",
                        {
                            "memory_addresses": [recovered.get("virtual_address")],
                            "formula": recovered.get("formula"),
                            "verification_result": recovered,
                            "output_buffer": recovered.get("output_buffer"),
                            "key_table_candidates": (
                                [recovered["key_table"]]
                                if isinstance(recovered.get("key_table"), list)
                                else []
                            ),
                            "key_candidates": (
                                [recovered["initial_key"]]
                                if isinstance(recovered.get("initial_key"), int)
                                else []
                            ),
                            "key_steps": (
                                [recovered["key_step"]]
                                if isinstance(recovered.get("key_step"), int)
                                else []
                            ),
                            "counter_initial": recovered.get("counter_initial"),
                            "counter_step": recovered.get("counter_step"),
                        },
                        {
                            "type": "file_offset",
                            "offset": recovered.get("file_offset"),
                        },
                    )
                )
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
            pattern = _TERM_PATTERNS.get(normalized)
            return pattern is not None and pattern.search(lowered) is not None

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
        if match and _valid_base64_candidate(match.group(0)):
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
