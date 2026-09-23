"""P3.3e preparation: the PURE derivation helpers, in a leaf both `service.py` and the moved derivation can import.

WHY THIS MODULE EXISTS: `_derive_investigation_observations` (2,795 lines) is the largest remaining slice, and
`.scratch/p33e-sink-set.py` measured that most of the fifteen helpers it reaches have readers in un-moved code as well -
so they can neither travel with the slice (other readers would break) nor be imported from `service.py` by the slice
(`investigation -> service` is forbidden). Seven of them are also PURE: after the intra-cluster rewrite none reads
receiver state, and every free name they mention is stdlib or from an allowed layer. Putting them here means the slash's
move needs far fewer new host members (measured: the helper part drops from seven prospective port members to three).

WHAT DOES NOT BELONG HERE, with the reason MEASURED per name rather than asserted -
`_instruction_access_kind` reads the CLASS constants `_DATA_LOAD_INSTRUCTION` / `_DATA_STORE_INSTRUCTION`;
`_reference_access_kind` reads no state of its own but calls it through the receiver; and `_investigation_value_text`
reads NO state at all - it cannot sink only because its recursive call is written `AnalysisService._investigation_value_text(...)`,
so moving it would make this leaf import `service` and create a cycle. (The sink instrument classifies receiver reads by
`ctx == Load` on `self`/`cls` only, so it prints that one as sinkable; anyone "finishing the fixed point" from that
number would create the cycle. Recorded here so the next reader does not.)

WHY `_emulation_entry_key` IS NOT HERE EITHER: its body needs `emulation.controlled_emulation.emulation_entry_key`, and
plan section 3.2 admits only emulation INTERFACES into `investigation/`. It therefore stays on the host as a real method
(one more port member when the giant moves), which costs a member and buys the absence of an unlisted edge.

`service.py` keeps one-statement delegations for every function below, so its callers and the tests that use these
helpers are unchanged and `service.<name>` still resolves.
"""
from __future__ import annotations

import re

from typing import Mapping

# The imports the moved bodies need, declared deliberately because the extractor's guard refuses to add them silently -
# and they are the evidence that this leaf is LEGAL: nothing here reaches `service` or an implementation module.
# MEASURED by the guard's own output, which named exactly these and nothing else.
from threat_report_agent.facts.thread_start import recovered_thread_start_address
from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py, with the receiver it used to reach
# through `cls` / `self` dropped - because NONE of the bodies below needs one (this module declares no host port, and
# the extractor refuses to write a body that still refers to a receiver). This banner is deliberately SLICE-AGNOSTIC.
# ---------------------------------------------------------------------------


def _parse_static_address(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text)
        return int(text, 16)
    except ValueError:
        return None


def _locator_key(raw: object) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    folded = text.casefold()
    if re.fullmatch(r"(?:0x)?[0-9a-f]+", folded):
        return f"0x{int(folded, 16):x}"
    return folded


def _row_own_function_payload(row: object) -> dict[str, object]:
    payload: dict[str, object] = {}
    value = getattr(row, "value", None)
    anchor = getattr(row, "anchor", None)
    if isinstance(value, dict):
        payload.update(value)
    if isinstance(anchor, dict):
        payload.update(anchor)
    return payload


def _code_locator_integers(value: object) -> set[int]:
    text = str(value or "").strip()
    if not text:
        return set()
    parsed = _parse_static_address(text)
    if parsed is not None:
        return {parsed}
    stripped = re.sub(r"^(?:offset|near|far)\s+", "", text, flags=re.I)
    stripped = re.sub(r"^(?:FUN_|sub_|thunk_)", "", stripped, flags=re.I)
    parsed = _parse_static_address(stripped)
    return {parsed} if parsed is not None else set()


def _function_entry_integers(function: Mapping[str, object] | None) -> set[int]:
    """Collect RVA and VA locators from a function/context row."""
    if not isinstance(function, Mapping):
        return set()
    values: set[int] = set()
    for key in ("entry_rva", "entry", "address", "function_entry", "rva"):
        parsed = _parse_static_address(function.get(key))
        if parsed is not None:
            values.add(parsed)
    return values


def _pe_entry_integers(pe_summary: Mapping[str, object] | None) -> set[int]:
    """Return PE AddressOfEntryPoint as both RVA and optional VA."""
    if not isinstance(pe_summary, Mapping):
        return set()
    rva = _parse_static_address(pe_summary.get("entry_rva"))
    image_base = _parse_static_address(pe_summary.get("image_base"))
    values: set[int] = set()
    if rva is not None:
        values.add(rva)
        if image_base is not None:
            values.add(image_base + rva)
    return values


def _overlay_pe_parser_thread_start(
    trace: Mapping[str, object],
    pe_summary: Mapping[str, object] | None,
) -> dict[str, object]:
    """Fill unresolved Ghidra CreateThread traces from PE32 PUSH recovery."""
    payload = dict(trace)
    if recovered_thread_start_address(payload):
        return payload
    api = str(payload.get("api") or payload.get("consumer") or "")
    if "createthread" not in normalize_api_symbol(api):
        return payload
    pe = pe_summary if isinstance(pe_summary, Mapping) else {}
    image_base = int(pe.get("image_base") or 0)
    site = _locator_key(payload.get("callsite"))
    signals = pe.get("code_signals") if isinstance(pe.get("code_signals"), Mapping) else {}
    for call in signals.get("api_calls") or ():
        if not isinstance(call, Mapping):
            continue
        arguments = call.get("arguments")
        if not isinstance(arguments, list) or not arguments:
            continue
        if "createthread" not in normalize_api_symbol(call.get("api")):
            continue
        try:
            rva = int(call.get("address") or 0)
        except (TypeError, ValueError):
            continue
        va = image_base + rva if image_base else rva
        call_keys = {
            _locator_key(hex(va)),
            _locator_key(hex(rva)),
        }
        if site and site not in call_keys:
            continue
        payload["arguments"] = [dict(item) for item in arguments if isinstance(item, dict)]
        pe_64 = bool(pe.get("pe_plus")) or str(pe.get("format") or "").upper() == "PE32+"
        payload["trace_quality"] = "x64_register_window" if pe_64 else "x86_stdcall_push"
        return payload
    return payload
