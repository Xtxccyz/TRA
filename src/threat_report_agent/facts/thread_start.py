"""Thread-start and code-address predicates over a recovered payload mapping.

MOVED here from `investigation.py`, as a GROUP: `recovered_thread_start_address` is not a leaf. It needs
`recovered_thread_argument`, `_thread_api_from_value`, `_THREAD_START_ARG_INDEX`, `canonical_code_address` and the
two code-address regexes, and an attempt to move the single function produced
`NameError: name '_thread_api_from_value' is not defined` in the real suite.

WHY THEY ARE IN `facts/`: these are pure predicates over a `Mapping`, which is what this layer owns (`dataflow.py`
and `decode_primitives.py` are the same kind of thing), and `static_analysis.py` imported
`recovered_thread_start_address` from `investigation` at MODULE level - which is what made plan 7.7's
`investigation/` package impossible to wrap (MEASURED twice: 145 collection errors).

The bodies below are BYTE-IDENTICAL to the ones that left `investigation.py`; only their address changed.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol


_THREAD_START_ARG_INDEX = {
    "createthread": 2,
    "createthreadex": 2,
    "createremotethread": 3,
    "createremotethreadex": 3,
    "tpallocwork": 1,
    "createthreadpoolwait": 1,
    "createthreadpooltimer": 1,
    "addvectoredexceptionhandler": 1,
    "queueuserapc": 0,
    "createtimerqueuetimer": 2,
}
_CODE_ADDRESS_RE = re.compile(r"^(?:0x)?[0-9a-f]{4,16}$", re.I)
_CODE_SYMBOL_RE = re.compile(r"^(?:FUN_|sub_|thunk_)[0-9a-fA-F]+$")

#: APIs that start a thread in ANOTHER process. MEASURED (`tests/test_deep_static_recovery.py::test_seed_clustering_
#: opens_unique_os_thread_from_recovered_start`): `_THREAD_START_ARG_INDEX` covers the remote variants, so a
#: CreateRemoteThread trace seeded the "unique OS thread" HOW question even though its own docstring promises
#: "same-process thread APIs". Remote thread creation is INJECTION evidence; calling it a thread-callback seed answers
#: the wrong question with the right-looking address (the plan's T2 semantic negative).
_REMOTE_THREAD_APIS = frozenset(
    {
        "createremotethread",
        "createremotethreadex",
        "createremotethreadwow64",
        "ntcreatethreadex",
        "rtlcreateuserthread",
    }
)


def is_remote_thread_api(api: object) -> bool:
    """True for an API that starts a thread in another process."""
    return normalize_api_symbol(str(api or "")) in _REMOTE_THREAD_APIS

def canonical_code_address(raw: object) -> str | None:
    """Return a hex or FUN_/sub_ identity; skip memory operands and UNKNOWN."""
    text = str(raw or "").strip().strip(",")
    if not text or text.casefold() in {"unknown", "n/a", "none"}:
        return None
    folded = text.casefold()
    if "[" in text or "ptr" in folded:
        return None
    if _CODE_ADDRESS_RE.fullmatch(text):
        try:
            return hex(int(text, 16))
        except ValueError:
            return None
    if _CODE_SYMBOL_RE.fullmatch(text):
        return text
    return None
def _thread_api_from_value(value: Mapping[str, object]) -> str:
    for key in ("api", "api_name", "target_name", "target_function"):
        text = str(value.get(key) or "").strip()
        if text:
            return normalize_api_symbol(text)
    return ""
def recovered_thread_argument(
    value: Mapping[str, object],
    *,
    index: int,
    names: tuple[str, ...] = (),
    require_code_address: bool = False,
) -> str | None:
    """Read one resolved x64 argument from an api_argument_trace payload."""
    args = value.get("arguments")
    if not isinstance(args, (list, tuple)):
        named = str(value.get("lpStartAddress") or value.get("start_routine") or value.get("start_address") or "")
        if require_code_address:
            return canonical_code_address(named)
        return named.strip() or None
    for item in args:
        if not isinstance(item, Mapping) or not item.get("resolved"):
            continue
        name = str(item.get("name") or "").casefold()
        matched = item.get("index") == index or (
            bool(names) and any(token in name for token in names)
        )
        if not matched:
            continue
        raw = item.get("value")
        if require_code_address:
            return canonical_code_address(raw)
        text = str(raw or "").strip()
        if text and text.casefold() not in {"unknown", "n/a", "none"}:
            return canonical_code_address(raw) or text
    return None
def recovered_thread_start_address(value: Mapping[str, object]) -> str | None:
    """lpStartAddress/callback for thread APIs, else None. Includes the REMOTE variants; see the local-only variant."""
    api = _thread_api_from_value(value)
    index = _THREAD_START_ARG_INDEX.get(api)
    if index is None:
        return None
    return recovered_thread_argument(
        value,
        index=index,
        names=("lpstartaddress", "startaddress", "callback", "pfnapc", "start_routine"),
        require_code_address=True,
    )


def recovered_local_thread_start_address(value: Mapping[str, object]) -> str | None:
    """Same-process thread start only - what the function above DOCUMENTS but does not enforce.

    Use this wherever the question is "is there a thread-callback HOW seed": a CreateRemoteThread trace names a start
    routine in the TARGET process, so it cannot answer that question. Use `recovered_thread_start_address` where the
    question is injection itself.
    """
    if is_remote_thread_api(_thread_api_from_value(value)):
        return None
    return recovered_thread_start_address(value)
