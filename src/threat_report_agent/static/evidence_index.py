"""Canonical, bounded search keys for immutable static Evidence.

The index contains normalized selectors only.  It never stores a second copy of
sample strings or decompiler text, and it is used solely to obtain bounded
candidate Evidence IDs before a retriever loads evidence values.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re


_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_@.$:-]{1,127}|0x[0-9A-Fa-f]+")
_SELECTOR_FIELDS = frozenset(
    {
        "api",
        "name",
        "target",
        "target_name",
        "target_function",
        "from",
        "to",
        "function",
        "function_name",
        "caller",
        "callee",
        "entry",
        "function_entry",
        "rva",
        "address",
        "text",
        "string",
        "symbol",
    }
)

# Only evidence that can be addressed by an investigation selector needs an
# entry in the derived exact-match index. Kind-driven retrieval still exposes
# every other immutable row directly from the Evidence table.
INDEXED_EVIDENCE_KINDS = frozenset(
    {
        "function",
        "function_context",
        "function_call",
        "function_instruction_window",
        "function_data_correlation",
        "function_mechanism",
        "function_ioc",
        "function_interface",
        "function_simhash",
        "data_reference",
        "xref",
        "string",
        "string_semantics",
        "import_symbol",
        "export_symbol",
        "api_argument_trace",
        "decode_candidate",
        "decode_result",
        "cross_function_chain",
        "investigation_mechanism_link",
        "static_mechanism_link",
        "pcode_slice",
        "value_flow",
        "resolved_api",
        "mechanism_decode_window",
        "abstract_execution_trace",
        "decompile_slice",
        "code_api_call",
        "cfg_block",
        "constant",
        "encoded_blob",
        "decoded_artifact",
        "mechanism_dynamic_api_link",
        "mechanism_http_transport_link",
        "mechanism_shell_output_link",
        "mechanism_etw_patch_link",
        "indirect_function_pointer_link",
    }
)
MAX_SELECTORS_PER_EVIDENCE = 32


def canonical_selector(value: object) -> str:
    """Normalize a target selector without interpreting untrusted sample data."""
    return " ".join(str(value).strip().casefold().split())[:160]


def _walk(value: object, *, key_hint: str = "", budget: int = 128) -> Iterable[str]:
    if budget <= 0:
        return ()
    if isinstance(value, Mapping):
        collected: list[str] = []
        for key, item in list(value.items())[:32]:
            key_text = str(key).casefold()
            if key_text in _SELECTOR_FIELDS:
                collected.extend(_walk(item, key_hint=key_text, budget=max(1, budget // 2)))
            elif isinstance(item, (Mapping, list, tuple)):
                collected.extend(_walk(item, key_hint=key_text, budget=max(1, budget // 2)))
        return tuple(collected)
    if isinstance(value, (list, tuple, set)):
        collected = []
        for item in list(value)[:32]:
            collected.extend(_walk(item, key_hint=key_hint, budget=max(1, budget // 2)))
        return tuple(collected)
    text = canonical_selector(value)
    if not text:
        return ()
    tokens = [text]
    tokens.extend(canonical_selector(token) for token in _TOKEN.findall(text))
    return tuple(tokens[:budget])


def evidence_search_keys(*, kind: str, value: object, anchor: object) -> tuple[str, ...]:
    """Return a compact exact-selector key set for one Evidence row."""
    if canonical_selector(kind) not in INDEXED_EVIDENCE_KINDS:
        return ()
    values = [f"kind:{canonical_selector(kind)}"]
    # Function identity must survive verbose instruction/data payloads. An
    # alphabetical cut of all tokens can otherwise discard every usable RVA.
    for source in (anchor, value):
        if isinstance(source, Mapping):
            for key in ("function_entry", "entry", "function", "function_name", "rva", "address", "api", "name", "target_name", "target_function"):
                item = source.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    values.append(canonical_selector(item))
    values.extend(_walk(value))
    values.extend(_walk(anchor))
    selected = tuple(dict.fromkeys(value for value in values if value))[:MAX_SELECTORS_PER_EVIDENCE]
    return tuple(sorted(selected))


def target_search_keys(targets: Iterable[object]) -> tuple[str, ...]:
    """Compile validated action/retrieval target values into index selectors."""
    keys: list[str] = []
    for target in targets:
        normalized = canonical_selector(target)
        if not normalized:
            continue
        keys.append(normalized)
        # Bare Ghidra addresses are single selectors. Tokenizing 14000c520
        # into "c520" can retrieve unrelated text and exhaust the row budget.
        if not re.fullmatch(r"(?:0x)?[0-9a-f]{5,}", normalized):
            keys.extend(canonical_selector(token) for token in _TOKEN.findall(normalized))
    return tuple(sorted(set(key for key in keys if key)))[:128]
