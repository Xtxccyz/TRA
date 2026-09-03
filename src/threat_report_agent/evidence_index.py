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
    values = [f"kind:{canonical_selector(kind)}"]
    values.extend(_walk(value))
    values.extend(_walk(anchor))
    return tuple(sorted({value for value in values if value}))[:256]


def target_search_keys(targets: Iterable[object]) -> tuple[str, ...]:
    """Compile validated action/retrieval target values into index selectors."""
    keys: list[str] = []
    for target in targets:
        normalized = canonical_selector(target)
        if not normalized:
            continue
        keys.append(normalized)
        keys.extend(canonical_selector(token) for token in _TOKEN.findall(normalized))
    return tuple(sorted(set(key for key in keys if key)))[:128]
