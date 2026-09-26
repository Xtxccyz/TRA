"""The ten-question protocol, filled from evidence rows - sunk here by P3.5-0/M-4.

WHY THIS MODULE EXISTS: the cluster lived in `investigation/investigation_protocol.py`, so any lower layer that
needed it (P3.5's `EmulationCoordinator`) had to import `investigation/` to get it - an upward edge. The cluster is
pure: it reads rows/counters and needs only the standard library, which is what makes `facts/` its honest home.
The old path re-exports every public name with `X as X`, so no importer changes.

MEASURED when this move was made: 12 definitions / 244 lines; the remainder of the old module is
self-contained (no definition left behind reads any name moved here); the new module imports only the standard
library, so it adds ZERO outgoing edges.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping


TEN_QUESTION_SLOTS: tuple[tuple[str, str], ...] = (
    ("initiator", "Who starts or registers this behavior?"),
    ("input", "What input, buffer, or handle reaches it?"),
    ("state_config", "What state or configuration does it use?"),
    ("transformation", "What transform or control-flow step is recovered?"),
    ("condition", "What condition gates success, failure, or a branch?"),
    ("side_effect", "What side effect is statically visible?"),
    ("output", "What output object or bytes are produced?"),
    ("consumer", "Who consumes that output?"),
    ("loop", "Is there a loop, back-edge, or repetition?"),
    ("failure_fallback", "What happens on failure or the fallback path?"),
)

_EMPTY_MARKERS = frozenset(
    {
        "",
        "unknown",
        "not_identified",
        "not identified",
        "n/a",
        "na",
        "none",
        "null",
        "-",
        "tbd",
    }
)

_THREAD_EXIT_APIS = frozenset(
    {
        "exitthread",
        "terminatethread",
        "exitprocess",
        "rtlexituserthread",
        "ntterminateprocess",
        "ntterminatethread",
    }
)

_THREAD_LOOP_HINTS = _THREAD_EXIT_APIS | frozenset(
    {
        "waitforsingleobject",
        "waitformultipleobjects",
        "ntwaitforsingleobject",
        "msgwaitformultipleobjects",
        "getmessage",
        "peekmessage",
        "sleepex",
    }
)

def is_empty_marker(value: object) -> bool:
    """Return whether a field is an empty or UNKNOWN placeholder."""
    if value is None:
        return True
    if isinstance(value, Mapping):
        return not value
    if isinstance(value, (list, tuple, set, frozenset)):
        return not value
    text = str(value).strip().casefold()
    if text in _EMPTY_MARKERS:
        return True
    return text.startswith("unknown(") or text.startswith("not_identified")

def empty_slot(question: str, *, reason: str = "not recovered from available static evidence") -> dict[str, object]:
    return {
        "status": "UNKNOWN",
        "value": None,
        "evidence_ids": [],
        "reason": reason,
        "question": question,
    }

def empty_protocol() -> dict[str, dict[str, object]]:
    return {slot: empty_slot(question) for slot, question in TEN_QUESTION_SLOTS}

def _api_tail(name: object) -> str:
    text = str(name or "").strip()
    if not text:
        return ""
    return text.rsplit(".", 1)[-1].rsplit("!", 1)[-1].casefold()

def function_call_names(value: Mapping[str, object]) -> list[str]:
    names: list[str] = []
    for key in ("call_targets", "references_from", "calls", "callees", "call_sequence"):
        items = value.get(key)
        if not isinstance(items, (list, tuple)):
            continue
        for item in items:
            if isinstance(item, Mapping):
                name = item.get("target_name") or item.get("target_function") or item.get("api") or item.get("name")
                if name not in (None, ""):
                    names.append(str(name))
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
    return list(dict.fromkeys(names))

def _slots_from_row(row: Mapping[str, object]) -> list[tuple[str, object, str]]:
    """Map one Evidence row onto one or more protocol slots. Do not invent values."""
    kind = str(row.get("kind") or "").casefold()
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    evidence_id = str(row.get("id") or "")
    slots: list[tuple[str, object, str]] = []

    def add(slot: str, raw: object) -> None:
        if raw is None or is_empty_marker(raw):
            return
        slots.append((slot, raw, evidence_id))

    if kind in {"tls_callback", "tls_metadata", "thread_callback"}:
        add("initiator", value.get("name") or value.get("callback") or value.get("entry"))
    if kind in {"function_context", "function", "function_call"}:
        add("initiator", value.get("name") or value.get("api") or value.get("entry"))
    if kind in {"function_context", "function", "function_semantic_summary", "decompile_slice"}:
        add("loop", value.get("loop") or value.get("back_edge"))
        add("failure_fallback", value.get("exit") or value.get("return_condition"))
        add("state_config", value.get("shared_state") or value.get("parameter_object"))
        call_names = function_call_names(value)
        tails = [_api_tail(name) for name in call_names]
        if call_names and any(tail in _THREAD_LOOP_HINTS for tail in tails):
            add("loop", " -> ".join(call_names[:8]))
        exit_names = [
            name for name, tail in zip(call_names, tails) if tail in _THREAD_EXIT_APIS
        ]
        if exit_names:
            add("failure_fallback", "returns via " + ", ".join(exit_names[:4]))
    if kind in {"global_usage", "shared_state"}:
        add("state_config", value.get("name") or value.get("global") or value.get("symbol"))
    if kind in {"api_argument_trace", "value_flow"}:
        if value.get("source_role") == "decoded_output" and value.get("source_buffer"):
            add("consumer", value.get("api") or value.get("source_buffer"))
        add("consumer", value.get("consumer") or value.get("consumer_function"))
        if str(value.get("source_role") or "").casefold() in {"producer", "global_write"} or value.get("writes") is True:
            add("output", value.get("output_buffer") or value.get("global") or value.get("name"))
        if value.get("resolved") is True and value.get("api"):
            add("input", value)
        # Kunglao DISPATCH_VERIFIER: persist CreateProcess HOW is protocol
        # content, not a reason to wait for leftover TRACE.
        add("initiator", value.get("api") or value.get("create_process"))
        add("input", value.get("command") or value.get("command_line") or value.get("image"))
        add("condition", value.get("creation_flags") or value.get("flags"))
        add("side_effect", value.get("return_branch"))
        start = (
            value.get("lpStartAddress")
            or value.get("start_routine")
            or value.get("start_address")
        )
        parameter = value.get("lpParameter") or value.get("parameter")
        arguments = value.get("arguments")
        if isinstance(arguments, (list, tuple)):
            for item in arguments:
                if not isinstance(item, Mapping):
                    continue
                name = str(item.get("name") or "").casefold()
                raw = item.get("value")
                if raw in (None, "", False) or is_empty_marker(raw):
                    continue
                if not start and name in {
                    "lpstartaddress",
                    "startaddress",
                    "callback",
                    "pfnapc",
                    "start_routine",
                }:
                    start = raw
                if not parameter and name in {"lpparameter", "parameter", "context", "dwdata"}:
                    parameter = raw
        start_text = str(start or "").strip()
        if start_text and not is_empty_marker(start_text):
            looks_like_start = start_text.casefold().startswith(("0x", "fun_", "sub_", "thunk_"))
            if not looks_like_start:
                looks_like_start = bool(
                    start_text
                    and all(ch in "0123456789abcdefABCDEF" for ch in start_text)
                    and len(start_text) >= 5
                )
            if looks_like_start:
                add("output", start)
                add("consumer", start)
                add("transformation", value.get("api") or "CreateThread")
        if parameter and not is_empty_marker(parameter):
            add("input", parameter)
        relation = str(value.get("relation") or "").casefold()
        if relation == "command_to_process_sink":
            add("consumer", value.get("api") or value.get("command") or "CreateProcess")
        if relation == "resolved_pointer_to_call":
            add("consumer", value.get("consumer") or value.get("api"))
            add("transformation", value.get("resolver") or value.get("api"))
        if relation == "output_to_consumer":
            add("consumer", value.get("consumer_api") or value.get("api"))
            add("output", value.get("output_buffer") or value.get("plaintext"))
    if kind == "resolved_api":
        add("transformation", value.get("resolver") or "GetProcAddress")
        add("output", value.get("api_name") or value.get("api_identity") or value.get("api"))
        add("consumer", value.get("consumer") or value.get("consumer_callsite"))
        add("input", value.get("module_input") or value.get("module"))
    if kind in {"decode_result", "mechanism_decode_window", "bytes_read"}:
        add("output", value.get("output_buffer") or value.get("decoded_text") or value.get("plaintext"))
        add("transformation", value.get("formula") or value.get("algorithm") or kind)
        consumer = value.get("consumer")
        if isinstance(consumer, Mapping):
            add("consumer", consumer.get("api") or consumer.get("function") or consumer.get("consumer_api"))
        else:
            add("consumer", consumer or value.get("consumer_api"))
    if kind in {"cfg_block", "abstract_execution_trace"}:
        add("condition", value.get("condition") or kind)
    if kind in {"pcode_slice"}:
        add("transformation", value.get("critical_operations") or kind)
    if kind in {"string", "string_reference"}:
        add("state_config", value.get("text") or value.get("string"))
    return slots

def _slot_from_row(row: Mapping[str, object]) -> tuple[str, object, str] | None:
    mapped = _slots_from_row(row)
    return mapped[0] if mapped else None


def _is_address_like(raw: object) -> bool:
    """True for a bare `0x...` address, false for a recovered symbol name.

    MEASURED (T3 callback fixture): the snapshot answers the `output` slot with the thread start address `0x401040`
    before the producer relation names the written global `g_stage`. First-wins then published an ADDRESS where the
    recovered OBJECT is known, and the derived consumer reason read "producer writes 0x401040" - a reader cannot act on
    that. The protocol already distinguishes symbol names from addresses elsewhere (`looks_like_start`,
    `is_ghidra_data_or_string_label`), so the distinction is made explicit here rather than left to row order.
    """
    text = str(raw or "").strip()
    if not text.casefold().startswith("0x"):
        return False
    body = text[2:]
    return bool(body) and all(character in "0123456789abcdefABCDEF" for character in body)


def _outranks(slot: str, candidate: object, current: object) -> bool:
    """A NAMED object outranks a bare address for the same slot, and nothing else changes precedence.

    Applies to `output` and `consumer`, the two slots that answer "what object, and who takes it". A name is always
    more actionable than an address, so the ORDER in which Evidence rows happen to arrive must not decide.
    """
    if slot not in {"output", "consumer"}:
        return False
    if not isinstance(candidate, str) or not isinstance(current, str):
        return False
    return not _is_address_like(candidate) and _is_address_like(current)


def _drop_coupled_consumer(protocol: dict[str, dict[str, object]], producer_evidence_id: object) -> None:
    """Drop a consumer that was answered by the SAME row whose output answer was just superseded.

    MEASURED (T3 callback fixture): one `api_argument_trace` row for CreateThread answers BOTH `output` and `consumer`
    with the thread start address. When a later producer relation supersedes `output` with the named global, that
    consumer consumed the THREAD, not the global - keeping it would publish an incoherent pair (`output = g_stage`,
    `consumer = 0x401040`) and would also suppress the honest "no recovered consumer" reason. Only an address-like,
    same-row answer is dropped; a named consumer from any row keeps its place.
    """
    consumer = protocol.get("consumer")
    if not isinstance(consumer, dict):
        return
    if str(consumer.get("status") or "").upper() != "ANSWERED":
        return
    if consumer.get("value_evidence_id") != producer_evidence_id:
        return
    if not _is_address_like(consumer.get("value")):
        return
    consumer["status"] = "UNKNOWN"
    consumer["value"] = ""
    consumer["reason"] = ""


def fill_protocol(
    evidence: Iterable[Mapping[str, object]],
    *,
    existing: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    """Fill ten-question slots from typed Evidence without inventing answers."""
    protocol = empty_protocol()
    if isinstance(existing, Mapping):
        for slot, current in existing.items():
            if slot in protocol and isinstance(current, Mapping):
                protocol[slot] = dict(current)
    for row in evidence:
        if not isinstance(row, Mapping):
            continue
        for slot, value, evidence_id in _slots_from_row(row):
            current = protocol[slot]
            if is_empty_marker(value):
                continue
            if str(current.get("status") or "").upper() == "ANSWERED":
                ids = list(current.get("evidence_ids") or [])
                if evidence_id and evidence_id not in ids:
                    ids.append(evidence_id)
                if _outranks(slot, value, current.get("value")):
                    # Keep EVERY contributing evidence id: the value is superseded, the provenance is not.
                    superseded_by = current.get("value_evidence_id")
                    current["value"] = value
                    current["value_evidence_id"] = evidence_id
                    if slot == "output" and superseded_by and superseded_by != evidence_id:
                        _drop_coupled_consumer(protocol, superseded_by)
                current["evidence_ids"] = ids[:16]
                continue
            protocol[slot] = {
                "status": "ANSWERED",
                "value": value,
                "value_evidence_id": evidence_id,
                "evidence_ids": [evidence_id] if evidence_id else [],
                "reason": "",
                "question": current.get("question") or "",
            }
    output = protocol["output"]
    consumer = protocol["consumer"]
    if (
        str(output.get("status") or "").upper() == "ANSWERED"
        and str(consumer.get("status") or "").upper() != "ANSWERED"
    ):
        consumer["reason"] = f"producer writes {output.get('value')}; no recovered consumer"
    return protocol
