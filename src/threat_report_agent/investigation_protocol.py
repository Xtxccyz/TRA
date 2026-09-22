"""Ten-question protocol and S0-S4 static upgrade ladder.

These records are investigation obligations, not report filler.  Empty
prose, UNKNOWN tokens, and a single NO_NEW_EVIDENCE result cannot close a
slot or declare a static boundary.
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

_S1_ACTIONS = frozenset(
    {"GET_FUNCTION", "GET_DECOMPILE", "GET_CALLERS", "GET_CALLEES"}
)
_S2_ACTIONS = frozenset(
    {
        "TRACE_API_ARGUMENT",
        "GET_PCODE_SLICE",
        "GET_DATA_REFERENCES",
        "GET_CFG_SLICE",
        "READ_BYTES",
        "EVALUATE_CONSTANT",
    }
)
_S3_ACTIONS = frozenset(
    {
        "TRACE_RETURN_VALUE",
        "TRACE_GLOBAL_USAGE",
        "DECODE_CANDIDATE",
        "GET_CALLEES",
        "GET_XREFS_TO",
        "GET_XREFS_FROM",
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


def _function_call_names(value: Mapping[str, object]) -> list[str]:
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
        call_names = _function_call_names(value)
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
            if str(current.get("status") or "").upper() == "ANSWERED":
                ids = list(current.get("evidence_ids") or [])
                if evidence_id and evidence_id not in ids:
                    ids.append(evidence_id)
                    current["evidence_ids"] = ids[:16]
                continue
            if is_empty_marker(value):
                continue
            protocol[slot] = {
                "status": "ANSWERED",
                "value": value,
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


def _nonempty_action_types(values: object) -> frozenset[str]:
    if isinstance(values, Mapping):
        values = values.keys()
    if not isinstance(values, Iterable) or isinstance(values, (str, bytes)):
        text = str(values or "").strip()
        return frozenset({text.upper()} if text else ())
    return frozenset(str(item).upper() for item in values if str(item).strip())


def _explicit_s1_s3_na(*statuses: str) -> bool:
    return set(statuses) <= {"NOT_APPLICABLE", "UNSUPPORTED"}


def _auditable_s4_closed(
    *,
    s1: str,
    s2: str,
    s3: str,
    attempted: Iterable[str],
    required: Iterable[str],
    pending: Iterable[str] = (),
) -> bool:
    """True only when S4 closed with attempts or an explicit family N/A reason."""
    allowed_closed = {"ATTEMPTED", "NOT_APPLICABLE", "UNSUPPORTED"}
    if pending or s1 not in allowed_closed or s2 not in allowed_closed or s3 not in allowed_closed:
        return False
    if attempted:
        trail = {"ATTEMPTED", "UNSUPPORTED"}
        return s1 in trail and s2 in trail and s3 in trail
    return bool(required) and _explicit_s1_s3_na(s1, s2, s3)


def s_ladder(
    *,
    attempted_action_types: Iterable[str] = (),
    required_action_types: Iterable[str] = (),
    failed_action_types: Iterable[str] = (),
    pending_action_types: Iterable[str] = (),
) -> dict[str, object]:
    """Record S0-S4 progress.  A failed method is a gap, not a boundary."""
    attempted = {str(item).upper() for item in attempted_action_types if str(item).strip()}
    required = {str(item).upper() for item in required_action_types if str(item).strip()}
    failed = {str(item).upper() for item in failed_action_types if str(item).strip()}
    pending = {str(item).upper() for item in pending_action_types if str(item).strip()}

    def stage(names: frozenset[str]) -> str:
        relevant_required = names & required if required else frozenset()
        family_attempted = names & attempted
        family_failed = names & failed
        family_pending = names & pending
        if required and not relevant_required:
            return "NOT_APPLICABLE"
        if family_failed and not (family_attempted - family_failed):
            return "UNSUPPORTED"
        if relevant_required:
            if relevant_required & family_pending or relevant_required - attempted:
                if family_attempted:
                    return "PARTIAL"
                return "MISSING"
            return "ATTEMPTED"
        if family_attempted:
            return "ATTEMPTED"
        return "NOT_APPLICABLE"

    s1 = stage(_S1_ACTIONS)
    s2 = stage(_S2_ACTIONS)
    s3 = stage(_S3_ACTIONS)
    s4 = (
        "CLOSED"
        if _auditable_s4_closed(
            s1=s1,
            s2=s2,
            s3=s3,
            attempted=attempted,
            required=required,
            pending=pending,
        )
        else "OPEN"
    )
    return {
        "s0_seed": "COMPLETE",
        "s1_context": s1,
        "s2_dataflow": s2,
        "s3_consumer": s3,
        "s4_orchestration": s4,
        "attempted_action_types": sorted(attempted),
        "required_action_types": sorted(required),
        "failed_action_types": sorted(failed),
        "pending_action_types": sorted(pending),
    }


def may_record_static_boundary(ladder: Mapping[str, object]) -> bool:
    """STATIC_BOUNDARY is allowed only after a truly closed S1-S3 trail."""
    blocking = {"MISSING", "PARTIAL"}
    s1 = str(ladder.get("s1_context") or "")
    s2 = str(ladder.get("s2_dataflow") or "")
    s3 = str(ladder.get("s3_consumer") or "")
    for status in (s1, s2, s3):
        if status in blocking:
            return False
    if str(ladder.get("s4_orchestration") or "") != "CLOSED":
        return False
    return _auditable_s4_closed(
        s1=s1,
        s2=s2,
        s3=s3,
        attempted=_nonempty_action_types(ladder.get("attempted_action_types")),
        required=_nonempty_action_types(ladder.get("required_action_types")),
        pending=_nonempty_action_types(ladder.get("pending_action_types")),
    )


def s4_closed_has_audit_trail(ladder: Mapping[str, object]) -> bool:
    """Return whether CLOSED S4 is backed by attempts or an explicit family N/A."""
    if _nonempty_action_types(ladder.get("attempted_action_types")):
        return True
    required = _nonempty_action_types(ladder.get("required_action_types"))
    return bool(required) and _explicit_s1_s3_na(
        str(ladder.get("s1_context") or ""),
        str(ladder.get("s2_dataflow") or ""),
        str(ladder.get("s3_consumer") or ""),
    )


# --------------------------------------------------------------------------
# Tool-authoring ticket (G6-B, ticket form)
# --------------------------------------------------------------------------
#
# ADR-0037 lets the agent author tools, but this product has no execution
# surface for authored code, and building one would be new architecture, which
# the working plan forbids.  So the investigation loop records a *ticket*
# instead: "closing this gap needs a tool the product does not have".
#
# The wording matters.  ``TOOL_AUTHORING_REQUIRED`` states a need; it must never
# be read as ``TOOL_AUTHORING_UNRESOLVED``, which would claim an authoring
# attempt actually happened.  Every ticket therefore names the action types the
# loop really exercised and says plainly that authoring was not attempted, so a
# reader can tell an exhausted action set from a skipped one.
TOOL_AUTHORING_REQUIRED_MARKER = "TOOL_AUTHORING_REQUIRED:"
TOOL_AUTHORING_UNRESOLVED_MARKER = "TOOL_AUTHORING_UNRESOLVED:"


def tool_authoring_required_ticket(
    *,
    mechanism_type: object,
    artifact_path: object,
    missing: Iterable[object] = (),
    action_types: Iterable[object] = (),
    static_recovery: object = "",
) -> str:
    """Build the factual ticket for a gap the current tool set cannot close.

    Pure.  ``action_types`` are the action types the loop actually ran for this
    gap, so the ticket is self-evidencing rather than an assertion of effort.

    ``static_recovery`` is the summary of a static decode recovery that ALREADY ran for this task.
    MEASURED reason it exists: the 白象 run published "needs a tool the product does not have; missing
    evidence: key, algorithm, …" while its own evidence held `DECODED_STATIC` with a four-step
    `decode_chain` and 5,881 recovered characters - the tool existed and the algorithm WAS recovered.
    When a recovery is present the ticket must say so and name what is still unclosed, instead of
    reporting a missing capability that ran.
    """
    mechanism = str(mechanism_type or "").strip() or "UNKNOWN_MECHANISM"
    path = str(artifact_path or "").strip() or "UNKNOWN_ARTIFACT"
    missing_items = [str(item).strip() for item in missing if str(item).strip()]
    exercised = sorted({str(item).strip() for item in action_types if str(item).strip()})
    recovery = str(static_recovery or "").strip()
    if recovery:
        return (
            f"{TOOL_AUTHORING_REQUIRED_MARKER} {mechanism} on {path} was partly recovered by the "
            f"built-in static decoder ({recovery}); the verifier still needs "
            f"{', '.join(missing_items) or 'semantic closure fields'}, so the mechanism is not "
            f"claimed as recovered. Action types exercised: {', '.join(exercised) or 'none'}; "
            "tool authoring was not attempted."
        )
    return (
        f"{TOOL_AUTHORING_REQUIRED_MARKER} {mechanism} on {path} needs a tool the "
        f"product does not have; missing evidence: "
        f"{', '.join(missing_items) or 'semantic closure fields'}; "
        f"action types exercised: {', '.join(exercised) or 'none'}; "
        "tool authoring was not attempted."
    )


def tool_authoring_required_entries(limitations: Iterable[object]) -> list[str]:
    """Ticket bodies carried by ``limitations``, in first-seen order."""
    found: list[str] = []
    for item in limitations or []:
        text = str(item or "").strip()
        index = text.find(TOOL_AUTHORING_REQUIRED_MARKER)
        if index < 0:
            continue
        entry = text[index + len(TOOL_AUTHORING_REQUIRED_MARKER) :].strip()
        if entry and entry not in found:
            found.append(entry)
    return found
