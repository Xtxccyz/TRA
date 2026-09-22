"""Object-level evidence checks shared by bounded investigation actions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import re

from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol


_REGISTERS = {
    "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
}
_VOLATILE = {"RAX", "RCX", "RDX", "R8", "R9", "R10", "R11"}
_ARGS = ("RCX", "RDX", "R8", "R9")
_GHIDRA_DATA_OR_STRING_LABEL = re.compile(r"(?i)^(?:s|u|dat|ptr_dat)_")
_REFERENCE_TARGET_KEYS = (
    "to",
    "address",
    "target",
    "target_address",
    "data_address",
    "referenced_address",
)
_NESTED_REFERENCE_KEYS = ("data_references", "references", "xrefs")
_DECODE_REFERENCE_KINDS = frozenset(
    {
        "data_reference",
        "xref",
        "string_reference",
        "global_usage",
        "function_data_correlation",
        "function_context",
        "function_instruction_window",
    }
)


def _register(value: str) -> str | None:
    value = value.strip().upper()
    if value in _REGISTERS:
        return value
    for suffix in ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP"):
        aliases = {"E" + suffix, suffix}
        if suffix in {"AX", "BX", "CX", "DX"}:
            aliases.update({suffix[0] + "L", suffix[0] + "H"})
        else:
            aliases.add(suffix + "L")
        if value in aliases:
            return "R" + suffix
    match = re.fullmatch(r"(R(?:[89]|1[0-5]))[DWB]", value)
    return match[1] if match else None


def is_ghidra_data_or_string_label(value: object) -> bool:
    """True for Ghidra auto labels of data/strings, not recovered API names."""
    text = str(value or "").rsplit("!", 1)[-1].strip()
    return bool(text) and _GHIDRA_DATA_OR_STRING_LABEL.match(text) is not None


def _symbol(value: object) -> str:
    text = str(value or "").strip().casefold()
    address = re.fullmatch(r"(?:fun_|sub_|0x)?([0-9a-f]{4,16})", text)
    return f"0x{int(address[1], 16):x}" if address else text


def trace_return_consumers(
    function: Mapping[str, object],
    producers: tuple[str, ...],
    *,
    max_instructions: int = 4096,
    max_links: int = 64,
) -> tuple[dict[str, object], ...]:
    """Follow x64 return values through full-width register copies to arguments.

    Only straight-line register flow is proven. Branches, partial-register
    copies, unsupported writes and ABI call clobbers kill provenance. This
    does not infer dereference contents or runtime path reachability.
    """
    architecture = str(function.get("architecture") or "").lower()
    if architecture in {"x86", "i386", "arm", "arm64", "aarch64"}:
        return ()
    wanted = {_symbol(value) for value in producers if str(value).strip()}
    if not wanted:
        return ()
    instructions = function.get("instructions")
    if not isinstance(instructions, (list, tuple)):
        return ()
    call_targets: dict[str, str] = {}
    for key in ("references_from", "call_targets"):
        rows = function.get(key, ())
        if not isinstance(rows, (list, tuple)):
            continue
        for row in rows:
            if isinstance(row, Mapping):
                site = str(row.get("from") or row.get("address") or "")
                target = row.get("target_name") or row.get("target_function") or row.get("to")
                if site and target:
                    call_targets[site.casefold()] = str(target)
    registers: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    links: list[dict[str, object]] = []
    for row in instructions[:max_instructions]:
        if not isinstance(row, Mapping):
            registers.clear()
            continue
        address = str(row.get("address") or row.get("from") or "")
        text = str(row.get("text") or "").strip()
        if not address or not text:
            registers.clear()
            continue
        parts = text.split(None, 1)
        operation = parts[0].upper()
        operands = parts[1] if len(parts) > 1 else ""
        if operation.startswith("J") or operation.startswith("RET") or operation in {
            "LOOP", "LOOPE", "LOOPNE", "SYSCALL", "SYSENTER", "INT", "IRET", "UD2",
        }:
            registers.clear()
            continue
        if operation == "CALL":
            api = call_targets.get(address.casefold(), operands.strip())
            for index, register in enumerate(_ARGS):
                source = registers.get(register)
                if source:
                    producer, callsite, copies = source
                    links.append({
                        "producer": producer,
                        "producer_callsite": callsite,
                        "source_role": "return_value",
                        "api": api,
                        "callsite": address,
                        "argument_index": index,
                        "register": register,
                        "copy_sites": list(copies),
                        "resolved": True,
                        "function": function.get("name"),
                        "function_entry": function.get("entry"),
                        "scope": "x64_straight_line_register_flow",
                        "assumptions": ["Windows x64 nonvolatile register convention"],
                        "runtime_observed": False,
                    })
                    if len(links) >= max_links:
                        return tuple(links)
            for register in _VOLATILE:
                registers.pop(register, None)
            if _symbol(api) in wanted or _symbol(operands) in wanted:
                registers["RAX"] = (api, address, ())
            continue
        operands_list = [value.strip() for value in operands.split(",")]
        destination = _register(operands_list[0]) if operands_list else None
        if operation == "MOV" and len(operands_list) == 2:
            destination_name, source_name = (value.upper() for value in operands_list)
            source = registers.get(source_name)
            if destination_name in _REGISTERS and source_name in _REGISTERS and source:
                registers[destination_name] = (source[0], source[1], (*source[2], address))
            elif destination:
                registers.pop(destination, None)
        elif operation not in {"CMP", "TEST", "NOP", "PUSH"}:
            if destination:
                registers.pop(destination, None)
            else:
                registers.clear()
            if operation in {"XCHG", "XADD", "MUL", "IMUL", "DIV", "IDIV", "CPUID"}:
                registers.clear()
    return tuple(links)


def _as_nonneg_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (ValueError, TypeError):
        return None
    return parsed if parsed >= 0 else None


def output_buffer_identity(
    *,
    address_space: object,
    address: object,
    length: object,
) -> dict[str, object] | None:
    """Build a decoder output identity. Missing space, address or length is unresolved."""
    space = str(address_space or "").strip()
    address_i = _as_nonneg_int(address)
    length_i = _as_nonneg_int(length)
    if not space or address_i is None or length_i is None or length_i == 0:
        return None
    return {"address_space": space, "address": address_i, "length": length_i}


def parse_operand_address(value: object) -> int | None:
    """Parse a concrete immediate or memory operand address. Strings are not buffers."""
    text = str(value or "").strip().rstrip(",")
    if not text or text[:1] in {'"', "'"}:
        return None
    match = re.search(r"(?:\[(?:[A-Za-z]+\s+)*)?(?:0x)?([0-9A-Fa-f]{4,16})\]?\s*$", text, re.I)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def addresses_alias(left: object, right: object, image_base: int = 0) -> bool:
    """True when two locators name the same VA, including RVA vs image-base form."""
    left_i = _as_nonneg_int(left)
    right_i = _as_nonneg_int(right)
    if left_i is None or right_i is None:
        return False
    if left_i == right_i:
        return True
    base = _as_nonneg_int(image_base) or 0
    if base <= 0:
        return False
    return left_i + base == right_i or right_i + base == left_i


def _address_forms(address: int, image_base: int) -> set[int]:
    """The locator as written plus its image-base-rebased spelling."""
    forms = {address}
    base = image_base or 0
    if base > 0:
        forms.add(address + base)
    return forms


def decoded_output_reference_match(
    output: Mapping[str, object],
    consumed_address: int,
    *,
    image_base: int = 0,
) -> tuple[bool, bool]:
    """Return ``(is_alias, is_slice)`` for a consumed locator vs a decoder output.

    ADR-0035: the decode consumer Join is an object-alias relation. A decoded
    configuration block is normally referenced through a pointer into its
    interior, so a locator inside ``[address, address + length)`` joins just as
    an exactly-equal locator does. Rebased (RVA vs image-base+RVA) spellings are
    compared through the same forms.
    """
    out_address = _as_nonneg_int(output.get("address"))
    if out_address is None:
        return False, False
    out_forms = _address_forms(out_address, image_base)
    consumed_forms = _address_forms(consumed_address, image_base)
    is_alias = bool(out_forms & consumed_forms)
    length = _as_nonneg_int(output.get("length")) or 0
    is_slice = False
    if length > 0:
        for start in out_forms:
            end = start + length
            if any(start <= candidate < end for candidate in consumed_forms):
                is_slice = True
                break
    return is_alias, is_slice


def decoded_output_from_argument_trace(
    producer_id: str,
    candidate: Mapping[str, object],
    kind: str,
    value: Mapping[str, object],
    anchor: Mapping[str, object],
    *,
    image_base: int = 0,
) -> dict[str, object] | None:
    """Return a B01-shaped trace when a resolved argument names the decoder output.

    Nested TRACE_API_ARGUMENT windows only recover register values. Linking
    still requires the producer output identity; co-located APIs do not qualify.
    """
    if decoded_output_consumer(
        producer_id, candidate, kind, value, anchor, image_base=image_base
    ):
        return dict(value)
    if kind != "api_argument_trace":
        return None
    output = candidate.get("output_buffer")
    if not isinstance(output, Mapping):
        return None
    api = str(value.get("api") or "").strip()
    callsite = value.get("callsite") or anchor.get("callsite")
    args = value.get("arguments")
    indexed: list[Mapping[str, object]] = []
    if isinstance(args, (list, tuple)):
        indexed.extend(item for item in args if isinstance(item, Mapping))
    elif value.get("resolved") is True:
        indexed.append(value)
    for item in indexed:
        if item.get("resolved") is not True:
            continue
        index = item.get("index", item.get("argument_index"))
        operand = parse_operand_address(item.get("value"))
        if operand is None:
            continue
        # ADR-0035: an interior pointer into the decoded range is a Join too.
        is_alias, is_slice = decoded_output_reference_match(
            output, operand, image_base=image_base
        )
        if not (is_alias or is_slice):
            continue
        synthetic = {
            "api": api,
            "callsite": callsite,
            "argument_index": index,
            "resolved": True,
            "producer_evidence_id": producer_id,
            "source_role": "decoded_output",
            "source_buffer": {
                "address_space": output.get("address_space"),
                "address": operand,
                "length": output.get("length"),
            },
        }
        if decoded_output_consumer(
            producer_id,
            candidate,
            "api_argument_trace",
            synthetic,
            anchor,
            image_base=image_base,
        ):
            return synthetic
    return None


def decoded_output_consumer(
    producer_id: str,
    candidate: Mapping[str, object],
    kind: str,
    value: Mapping[str, object],
    anchor: Mapping[str, object],
    *,
    image_base: int = 0,
) -> bool:
    """Require a resolved argument trace to the identified decoder output.

    ADR-0035: the Join is an object-alias relation, not byte equality. A nearby
    API or a call edge still proves neither buffer identity nor use, and the
    producer must identify its output separately from the ciphertext input.
    """
    if kind not in {"api_argument_trace", "value_flow"}:
        return False
    if value.get("resolved") is not True:
        return False
    api = str(value.get("api") or "").strip()
    if not api or api.casefold() in {"unknown", "not_identified", "n/a", "none"}:
        return False
    # A Ghidra FUN_/DAT_ label is not a named consumer: it identifies nothing.
    if not is_named_decode_consumer_api(api):
        return False
    if value.get("producer_evidence_id") != producer_id:
        return False
    if value.get("source_role") != "decoded_output":
        return False
    if not (value.get("callsite") or anchor.get("callsite")):
        return False
    index = value.get("argument_index")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        return False
    output = candidate.get("output_buffer")
    consumed = value.get("source_buffer")
    if not isinstance(output, Mapping) or not isinstance(consumed, Mapping):
        return False
    output_space = str(output.get("address_space") or "").strip()
    if not output_space or output_space != str(consumed.get("address_space") or "").strip():
        return False
    consumed_address = _as_nonneg_int(consumed.get("address"))
    if consumed_address is None:
        consumed_address = parse_operand_address(consumed.get("address"))
    if consumed_address is None:
        return False
    base = _as_nonneg_int(image_base) or _as_nonneg_int(candidate.get("image_base")) or 0
    is_alias, is_slice = decoded_output_reference_match(
        output, consumed_address, image_base=base
    )
    if not (is_alias or is_slice):
        return False
    # Length may legitimately differ (slice) or be unrecorded. With no length the
    # alias alone must be a string-class slot: an interior pointer into decoded
    # bytes is how URLs and command lines are referenced, but dwCreationFlags is
    # a scalar and cannot Join this way.
    consumed_length = _as_nonneg_int(consumed.get("length"))
    if consumed_length is None or consumed_length == 0:
        return is_alias and is_string_class_consumer_argument(api, index)
    return True


_PLACEHOLDER_VALUES = {
    "unknown",
    "not_identified",
    "not identified",
    "unresolved",
    "n/a",
    "none",
    "null",
}
_NULL_POINTER_VALUES = {"0", "0x0", "0x00", "null"}
_POINTER_FIELDS = {
    "image",
    "entry_routine",
    "start_routine",
    "module_input",
    "parameter",
}
_NAME_TO_FIELDS: dict[str, tuple[str, ...]] = {
    "lpapplicationname": ("image",),
    "lpcommandline": ("command", "command_line"),
    "dwcreationflags": ("creation_flags", "flags"),
    "creationflags": ("creation_flags", "flags"),
    "lpstartaddress": ("entry_routine", "start_routine"),
    "startaddress": ("entry_routine", "start_routine"),
    "lpparameter": ("parameter",),
    "lpprocname": ("api_identity",),
    "lplibfilename": ("module_input",),
    "pwszverb": ("request",),
    "pwszobjectname": ("endpoint",),
    "pswzservername": ("endpoint",),
    "lpszverb": ("request",),
    "lpszobjectname": ("endpoint",),
    "lpszservername": ("endpoint",),
}
_API_INDEX_TO_FIELDS: dict[str, dict[int, tuple[str, ...]]] = {
    "createprocessw": {0: ("image",), 1: ("command", "command_line"), 5: ("creation_flags", "flags")},
    "createprocessa": {0: ("image",), 1: ("command", "command_line"), 5: ("creation_flags", "flags")},
    "winexec": {0: ("command", "command_line", "image")},
    "shellexecutew": {2: ("command", "command_line", "image")},
    "shellexecutea": {2: ("command", "command_line", "image")},
    "createthread": {2: ("entry_routine", "start_routine"), 3: ("parameter",), 4: ("creation_flags", "flags")},
    "createthreadex": {2: ("entry_routine", "start_routine"), 3: ("parameter",)},
    "getprocaddress": {1: ("api_identity",)},
    "ldrgetprocedureaddress": {1: ("api_identity",)},
    "loadlibraryw": {0: ("module_input",)},
    "loadlibrarya": {0: ("module_input",)},
    "loadlibraryexw": {0: ("module_input",)},
    "loadlibraryexa": {0: ("module_input",)},
    "winhttpopenrequest": {1: ("request",), 2: ("endpoint",)},
    "winhttpconnect": {1: ("endpoint",)},
    "httpopenrequestw": {1: ("request",), 2: ("endpoint",)},
    "internetconnectw": {1: ("endpoint",)},
}
_PROCESS_EXECUTION_SYMBOLS = {
    "createprocessw",
    "createprocessa",
    "winexec",
    "shellexecutew",
    "shellexecutea",
}
_PROCESS_COMMAND_FIELD_KEYS = {"command", "command_line", "image"}
# Argument slots that receive a pointer to decoded bytes (URL, verb, object name,
# module name, command line) rather than a scalar. Used only when the consumer
# length is absent: a scalar slot must not Join on alias alone.
_STRING_CLASS_FIELD_KEYS = {
    "request",
    "endpoint",
    "command",
    "command_line",
    "image",
    "module_input",
    "api_identity",
    "parameter",
}


def _strip_operand_text(value: object) -> str:
    text = str(value or "").strip().rstrip(",")
    text = re.sub(r"^(?:offset|near)\s+", "", text, flags=re.I)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


_REGISTER_IN_TEXT = re.compile(
    r"(?i)(?:^|[^A-Z0-9_])(?:R(?:AX|BX|CX|DX|SI|DI|BP|SP|8|9|1[0-5])|E(?:AX|BX|CX|DX|SI|DI|BP|SP))(?:$|[^A-Z0-9_])"
)


def is_projected_catalog_value(value: object) -> bool:
    """Return whether a recovered operand can become a catalog fact."""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    text = _strip_operand_text(value)
    if not text or text.casefold() in _PLACEHOLDER_VALUES:
        return False
    if _register(text) is not None:
        return False
    # Stack/register-relative operands are locators, not recovered objects.
    if _REGISTER_IN_TEXT.search(text):
        return False
    return True


def with_artifact_identity(
    buffer: Mapping[str, object] | None,
    artifact_id: object,
) -> dict[str, object] | None:
    """Stamp artifact_id onto an otherwise complete buffer identity."""
    if not isinstance(buffer, Mapping):
        return None
    artifact = str(artifact_id or "").strip()
    if not artifact:
        return None
    payload = dict(buffer)
    payload["artifact_id"] = artifact
    if not payload.get("address_space"):
        payload["address_space"] = f"{artifact}:image"
    return payload


def catalog_fields_from_api_arguments(
    api: object,
    arguments: object,
) -> dict[str, object]:
    """Project ABI-recovered arguments onto catalog fact fields.

    Nested TRACE_API_ARGUMENT windows keep UNKNOWN/register slots for
    analysts. Catalog contracts reject any row that still contains those
    unresolved statuses, so the projection copies only concrete values
    onto a flat payload.
    """
    symbol = normalize_api_symbol(api)
    index_map = _API_INDEX_TO_FIELDS.get(symbol, {})
    fields: dict[str, object] = {}
    if not isinstance(arguments, Iterable) or isinstance(arguments, (str, bytes, Mapping)):
        return fields
    for item in arguments:
        if not isinstance(item, Mapping):
            continue
        if item.get("resolved") is not True:
            continue
        text = _strip_operand_text(item.get("value"))
        if not is_projected_catalog_value(text):
            continue
        keys: tuple[str, ...] = ()
        name = str(item.get("name") or "").strip().casefold()
        if name in _NAME_TO_FIELDS:
            keys = _NAME_TO_FIELDS[name]
        else:
            index = item.get("index", item.get("argument_index"))
            if isinstance(index, int) and not isinstance(index, bool):
                keys = index_map.get(index, ())
        for key in keys:
            if key in _POINTER_FIELDS and text.casefold() in _NULL_POINTER_VALUES:
                continue
            fields.setdefault(key, text)
    if symbol in {"getprocaddress", "ldrgetprocedureaddress"} and "api_identity" in fields:
        fields.setdefault("resolver", str(api or "").rsplit("!", 1)[-1])
    if symbol.startswith("loadlibrary") and "module_input" in fields:
        fields.setdefault("resolver", str(api or "").rsplit("!", 1)[-1])
    return fields


def catalog_relation_from_api_fields(
    api: object,
    fields: Mapping[str, object],
    *,
    artifact_id: object,
    callsite: object = None,
    source_evidence_id: object = None,
    target_evidence_id: object = None,
) -> dict[str, object] | None:
    """Build a provenance-bearing process-creation relation from recovered facts."""
    artifact = str(artifact_id or "").strip()
    source_id = str(source_evidence_id or "").strip()
    target_id = str(target_evidence_id or "").strip()
    if not artifact or not source_id or not target_id:
        return None
    symbol = normalize_api_symbol(api)
    command = fields.get("command") or fields.get("command_line") or fields.get("image")
    if symbol not in {
        "createprocessw",
        "createprocessa",
        "winexec",
        "shellexecutew",
        "shellexecutea",
    } or not is_projected_catalog_value(command):
        return None
    site = str(callsite or source_id).strip() or source_id
    command_buffer = {
        "artifact_id": artifact,
        "address_space": f"{artifact}:image",
        "object_id": f"{site}:command",
    }
    process_sink = {
        "artifact_id": artifact,
        "handle_id": f"{symbol}:{site}",
    }
    return {
        "relation": "command_to_process_sink",
        "api": str(api or "").rsplit("!", 1)[-1],
        "command_buffer": command_buffer,
        "process_sink": process_sink,
        "source_evidence_id": source_id,
        "target_evidence_id": target_id,
        "source_evidence_ids": [source_id],
        "target_evidence_ids": [target_id],
    }


def catalog_parent_handle_identity(
    *,
    artifact_id: object,
    handle_id: object,
) -> dict[str, object] | None:
    """Identity for an OpenProcess or attribute-list handle recovered statically."""
    artifact = str(artifact_id or "").strip()
    handle = str(handle_id or "").strip()
    if not artifact or not handle or not is_projected_catalog_value(handle):
        return None
    return {
        "artifact_id": artifact,
        "handle_id": handle,
    }


def catalog_relation_from_parent_attribute(
    fields: Mapping[str, object] | None,
    *,
    artifact_id: object,
    source_evidence_id: object,
    target_evidence_id: object | None = None,
    callsite: object = None,
) -> dict[str, object] | None:
    """Link a recovered parent-process handle to the STARTUPINFOEX attribute list."""
    if not isinstance(fields, Mapping):
        return None
    artifact = str(artifact_id or "").strip()
    source_id = str(source_evidence_id or "").strip()
    target_id = str(target_evidence_id or source_evidence_id or "").strip()
    site = str(callsite or fields.get("callsite") or source_id).strip() or source_id
    parent_handle = fields.get("parent_handle")
    attribute_handle = fields.get("attribute_handle")
    if not isinstance(parent_handle, Mapping) or not parent_handle.get("handle_id"):
        parent_handle = catalog_parent_handle_identity(
            artifact_id=artifact,
            handle_id=f"openprocess:{site}",
        )
    if not isinstance(attribute_handle, Mapping) or not attribute_handle.get("handle_id"):
        attribute_handle = catalog_parent_handle_identity(
            artifact_id=artifact,
            handle_id=f"updateprocthreadattribute:{site}",
        )
    if (
        not artifact
        or not source_id
        or not target_id
        or parent_handle is None
        or attribute_handle is None
        or not any(
            fields.get(key) not in (None, "")
            for key in ("parent_selection", "attribute", "startup_info", "open_process")
        )
    ):
        return None
    payload: dict[str, object] = {
        "relation": "parent_handle_to_attribute",
        "api": str(fields.get("api") or "UpdateProcThreadAttribute").rsplit("!", 1)[-1],
        "parent_handle": parent_handle,
        "attribute_handle": attribute_handle,
        "source_handle": parent_handle,
        "target_handle": attribute_handle,
        "source_evidence_id": source_id,
        "target_evidence_id": target_id,
        "source_evidence_ids": [source_id] if source_id == target_id else [source_id, target_id],
        "target_evidence_ids": [target_id],
        "static_only": True,
    }
    for key in (
        "parent_selection",
        "access_mask",
        "attribute",
        "startup_info",
        "creation_flags",
        "flags",
        "open_process",
        "create_process",
    ):
        value = fields.get(key)
        if value not in (None, ""):
            payload[key] = value
    return payload


def catalog_resolved_pointer_identity(
    *,
    artifact_id: object,
    callsite: object,
) -> dict[str, object] | None:
    """Identity for a GetProcAddress return pointer consumed by an indirect call."""
    artifact = str(artifact_id or "").strip()
    site = str(callsite or "").strip()
    if not artifact or not site or not is_projected_catalog_value(site):
        return None
    return {
        "artifact_id": artifact,
        "address_space": f"{artifact}:image",
        "object_id": f"{site}:resolved_pointer",
    }


def catalog_relation_from_resolved_api(
    resolution: Mapping[str, object] | None,
    *,
    artifact_id: object,
    source_evidence_id: object,
    target_evidence_id: object | None = None,
) -> dict[str, object] | None:
    """Link a recovered GetProcAddress pointer to its static indirect consumer."""
    if not isinstance(resolution, Mapping):
        return None
    artifact = str(artifact_id or "").strip()
    source_id = str(source_evidence_id or "").strip()
    target_id = str(target_evidence_id or source_evidence_id or "").strip()
    api_name = str(resolution.get("api_name") or resolution.get("api_identity") or "").strip()
    consumer = resolution.get("consumer") or resolution.get("consumer_callsite")
    if (
        not artifact
        or not source_id
        or not target_id
        or not is_projected_catalog_value(api_name)
        or consumer in (None, "")
    ):
        return None
    pointer = resolution.get("resolved_pointer")
    if not isinstance(pointer, Mapping) or not pointer.get("artifact_id"):
        pointer = catalog_resolved_pointer_identity(
            artifact_id=artifact,
            callsite=resolution.get("resolver_callsite") or source_id,
        )
    if pointer is None:
        return None
    payload = {
        "relation": "resolved_pointer_to_call",
        "resolved_pointer": pointer,
        "output_buffer": pointer,
        "consumer_pointer": pointer,
        "input_buffer": pointer,
        "api": api_name,
        "api_identity": api_name,
        "resolver": str(resolution.get("resolver") or "GetProcAddress"),
        "consumer": str(consumer),
        "source_evidence_id": source_id,
        "target_evidence_id": target_id,
        "producer_evidence_id": source_id,
        "consumer_evidence_id": target_id,
        "source_evidence_ids": [source_id] if source_id == target_id else [source_id, target_id],
        "target_evidence_ids": [target_id],
        "static_only": True,
    }
    module = resolution.get("module_input")
    if module not in (None, ""):
        payload["module_input"] = module
    return payload


def catalog_fields_from_decode_verification(
    verification: Mapping[str, object] | None,
    *,
    artifact_id: object = None,
    output_buffer: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Copy a verified XOR/decode replay onto catalog fact fields."""
    if not isinstance(verification, Mapping):
        return {}
    status = str(verification.get("status") or "").strip().upper()
    if status not in {"VERIFIED_STATIC_DATA", "VERIFIED"}:
        return {}
    fields: dict[str, object] = {}
    algorithm = verification.get("formula") or verification.get("algorithm")
    if is_projected_catalog_value(algorithm):
        fields["algorithm"] = str(algorithm)
    key_state = {
        key: verification[key]
        for key in ("initial_key", "key_step", "xor_const", "key_table", "counter_initial", "counter_step")
        if key in verification and verification[key] not in (None, "", [])
    }
    if key_state:
        fields["key_or_state"] = key_state
    step = verification.get("counter_step")
    if step in (None, ""):
        step = verification.get("key_step")
    if step not in (None, ""):
        # Specialist token gate matches values, not keys. Keep the recovered
        # increment in the `counter_step=` form rather than dropping it.
        fields["step"] = f"counter_step={step}"
    ciphertext = verification.get("ciphertext_hex") or verification.get("input_bytes")
    plaintext = (
        verification.get("plaintext_hex")
        or verification.get("decoded_text")
        or verification.get("output_bytes")
    )
    if is_projected_catalog_value(ciphertext):
        fields["input_bytes"] = ciphertext
    if is_projected_catalog_value(plaintext):
        fields["output_bytes"] = plaintext
    digest = verification.get("output_hash") or verification.get("sha256")
    if not is_projected_catalog_value(digest):
        hex_text = str(verification.get("plaintext_hex") or "").strip()
        if re.fullmatch(r"[0-9a-fA-F]+", hex_text) and len(hex_text) % 2 == 0:
            digest = hashlib.sha256(bytes.fromhex(hex_text)).hexdigest()
    if is_projected_catalog_value(digest):
        fields["output_hash"] = digest
    buffer = output_buffer if isinstance(output_buffer, Mapping) else None
    if buffer is None and isinstance(verification.get("output_buffer"), Mapping):
        buffer = verification.get("output_buffer")
    identified = with_artifact_identity(buffer, artifact_id)
    if identified is not None:
        fields["output_buffer"] = identified
    return fields


def catalog_buffers_are_same_object(
    left: Mapping[str, object] | None,
    right: Mapping[str, object] | None,
) -> bool:
    """True when two catalog buffers share artifact_id + address [+ length]."""
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        return False
    if not left.get("artifact_id") or not right.get("artifact_id"):
        return False
    if str(left.get("artifact_id")) != str(right.get("artifact_id")):
        return False
    if left.get("address") in (None, "") or right.get("address") in (None, ""):
        return False
    if left.get("address") != right.get("address"):
        return False
    if left.get("length") not in (None, "") and right.get("length") not in (None, ""):
        return left.get("length") == right.get("length")
    return True


def catalog_output_consumer_relation(
    *,
    producer_id: object,
    consumer_id: object,
    output_buffer: Mapping[str, object] | None,
    consumer_api: object = None,
    artifact_id: object = None,
) -> dict[str, object] | None:
    """Link a decoder output object to the consumer that received the same buffer.

    ADR-0035 / G1 §5.2: a missing ``artifact_id`` on the buffer is not by itself a
    reason to give up. When the producer Evidence knows the artifact, stamp it
    with ``with_artifact_identity`` instead of returning an unresolved relation.
    """
    source_id = str(producer_id or "").strip()
    target_id = str(consumer_id or "").strip()
    if not source_id or not target_id or not isinstance(output_buffer, Mapping):
        return None
    identity = dict(output_buffer)
    if not identity.get("artifact_id") and artifact_id:
        identity = with_artifact_identity(identity, artifact_id) or identity
    if not identity.get("artifact_id"):
        return None
    payload = {
        "relation": "output_to_consumer",
        "output_buffer": identity,
        "input_buffer": identity,
        "source_evidence_id": source_id,
        "target_evidence_id": target_id,
        "producer_evidence_id": source_id,
        "consumer_evidence_id": target_id,
        "source_evidence_ids": [source_id, target_id],
        "target_evidence_ids": [target_id],
    }
    api = str(consumer_api or "").strip()
    if api:
        payload["consumer"] = api
        payload["api"] = api
    return payload


def is_named_decode_consumer_api(api: object) -> bool:
    """True for a recovered Win32/API name, not a Ghidra FUN_/DAT_ label or strlen."""
    name = str(api or "").strip()
    if not name:
        return False
    folded = name.casefold()
    if folded.startswith(("fun_", "dat_", "lab_", "sub_", "thunk_", "s_")):
        return False
    if folded in {"lstrlena", "lstrlenw", "strlen", "wcslen"}:
        return False
    return True


def is_object_level_decode_consumer(candidate: Mapping[str, object] | None) -> bool:
    """True when decoder output entered a named API argument, not a data xref."""
    if not isinstance(candidate, Mapping):
        return False
    link_kind = str(candidate.get("link_kind") or "").casefold()
    if link_kind == "decoded_va_reference":
        return False
    api = (
        candidate.get("api")
        or candidate.get("consumer")
        or candidate.get("consumer_api")
    )
    if not is_named_decode_consumer_api(api):
        return False
    relation = str(candidate.get("relation") or "")
    if relation == "output_to_consumer":
        return True
    if link_kind in {"decoded_pointer_to_call", "decoded_output_consumer"}:
        return True
    return str(candidate.get("kind") or "").casefold() == "api_argument_trace"


def is_process_execution_api(api: object) -> bool:
    """True for CreateProcess/WinExec/ShellExecute, the process-command Join sinks."""
    return normalize_api_symbol(api) in _PROCESS_EXECUTION_SYMBOLS


def is_process_command_argument(api: object, argument_index: object) -> bool:
    """True when a process API argument is lpApplicationName / lpCommandLine / equivalent."""
    if not is_process_execution_api(api):
        return False
    if isinstance(argument_index, bool) or not isinstance(argument_index, int):
        return False
    keys = _API_INDEX_TO_FIELDS.get(normalize_api_symbol(api), {}).get(argument_index, ())
    return any(key in _PROCESS_COMMAND_FIELD_KEYS for key in keys)


def is_string_class_consumer_argument(api: object, argument_index: object) -> bool:
    """True when the traced argument slot carries a pointer to decoded bytes.

    WinHTTP URL/verb/object-name and CreateProcess lpApplicationName /
    lpCommandLine are how a decoded configuration block is consumed. When such an
    argument has no length recorded, an aliasing address still proves the object
    identity; a scalar slot (dwCreationFlags) does not.
    """
    if isinstance(argument_index, bool) or not isinstance(argument_index, int):
        return False
    keys = _API_INDEX_TO_FIELDS.get(normalize_api_symbol(api), {}).get(argument_index, ())
    return any(key in _STRING_CLASS_FIELD_KEYS for key in keys)


def catalog_decode_output_to_process_command_relation(
    *,
    decode_id: object,
    process_id: object,
    output_buffer: Mapping[str, object] | None,
    command_buffer: Mapping[str, object] | None,
    plaintext: object = None,
    command: object = None,
) -> dict[str, object] | None:
    """Join a decoder output object to a CreateProcess command only when the buffers match.

    Matching plaintext text against a command string is co-occurrence, not a Join.
    """
    source_id = str(decode_id or "").strip()
    target_id = str(process_id or "").strip()
    if not source_id or not target_id:
        return None
    if not isinstance(output_buffer, Mapping) or not isinstance(command_buffer, Mapping):
        return None
    if not output_buffer.get("artifact_id") or not command_buffer.get("artifact_id"):
        return None
    if str(output_buffer.get("artifact_id")) != str(command_buffer.get("artifact_id")):
        return None
    out_addr = output_buffer.get("address")
    cmd_addr = command_buffer.get("address")
    if out_addr is None or cmd_addr is None or out_addr != cmd_addr:
        return None
    if output_buffer.get("length") not in (None, "") and command_buffer.get("length") not in (None, ""):
        if output_buffer.get("length") != command_buffer.get("length"):
            return None
    payload = {
        "relation": "decode_output_to_process_command",
        "output_buffer": dict(output_buffer),
        "command_buffer": dict(command_buffer),
        "input_buffer": dict(command_buffer),
        "source_evidence_id": source_id,
        "target_evidence_id": target_id,
        "source_evidence_ids": [source_id, target_id],
        "target_evidence_ids": [target_id],
    }
    text = str(plaintext or "").strip()
    image = str(command or "").strip()
    if text:
        payload["plaintext"] = text
    if image:
        payload["command"] = image
    return payload


def catalog_return_branch_after_call(
    instructions: object,
) -> str | None:
    """Return the first TEST/CMP EAX + Jcc after a callsite, if present."""
    if not isinstance(instructions, Iterable) or isinstance(instructions, (str, bytes, Mapping)):
        return None
    saw_return_test = False
    for row in instructions:
        if not isinstance(row, Mapping):
            continue
        text = str(row.get("text") or row.get("mnemonic") or "").strip()
        if re.search(r"(?i)\b(?:TEST|CMP)\s+(?:E|R)?AX\b", text):
            saw_return_test = True
            continue
        match = re.match(r"(?i)\b(J(?:Z|NZ|E|NE|C|NC))\s+(\S+)", text)
        if match and saw_return_test:
            return f"{match.group(1).upper()} {match.group(2)}"
        if re.match(r"(?i)\b(?:CALL|RET|JMP)\b", text):
            break
        if saw_return_test and not re.match(r"(?i)\b(?:NOP|CDQ|CDQE)\b", text):
            break
    return None


def consumer_from_decoded_pointer(
    instructions: object,
    output_address: object,
    *,
    image_base: int = 0,
) -> dict[str, object] | None:
    """Find the next CALL after an argument register is loaded with decoder output."""
    if output_address in (None, "") or not isinstance(instructions, Iterable) or isinstance(
        instructions, (str, bytes, Mapping)
    ):
        return None
    assign_re = re.compile(r"(?i)\b(?:MOV|MOVABS|LEA)\s+(RCX|RDX|R8|R9)\s*,\s*(.+)$")
    call_re = re.compile(r"(?i)\bCALL\s+(.+)$")
    loaded: dict[str, object] = {}
    for row in instructions:
        if not isinstance(row, Mapping):
            continue
        text = str(row.get("text") or row.get("mnemonic") or "").strip()
        assigned = assign_re.search(text)
        if assigned:
            register, operand = assigned.group(1).upper(), assigned.group(2).strip()
            address = parse_operand_address(operand)
            if address is not None and addresses_alias(address, output_address, image_base):
                loaded[register] = address
            else:
                loaded.pop(register, None)
            continue
        called = call_re.search(text)
        if not called or not loaded:
            continue
        target = called.group(1).strip().split(",")[0].strip()
        register, address = next(iter(loaded.items()))
        api = None
        if _register(target) is None and not is_ghidra_data_or_string_label(target):
            api = target
        return {
            "api": api,
            "callsite": row.get("address"),
            "argument_index": {"RCX": 0, "RDX": 1, "R8": 2, "R9": 3}.get(register, 0),
            "register": register,
            "resolved": True,
            "value": hex(int(address)) if isinstance(address, int) else address,
        }
    return None


def _reference_target_locators(value: Mapping[str, object]) -> tuple[object, ...]:
    locators: list[object] = []
    for key in _REFERENCE_TARGET_KEYS:
        item = value.get(key)
        if item not in (None, ""):
            locators.append(item)
    for key in ("target_name", "name", "label", "text"):
        parsed = parse_operand_address(value.get(key))
        if parsed is not None:
            locators.append(parsed)
    return tuple(locators)


def _iter_reference_blobs(value: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    blobs: list[Mapping[str, object]] = [value]
    for key in _NESTED_REFERENCE_KEYS:
        raw = value.get(key)
        if not isinstance(raw, list):
            continue
        blobs.extend(item for item in raw if isinstance(item, Mapping))
    return tuple(blobs)


def consumer_from_decoded_reference(
    kind: object,
    value: Mapping[str, object] | None,
    anchor: Mapping[str, object] | None,
    output_address: object,
    *,
    image_base: int = 0,
) -> dict[str, object] | None:
    """Link decoder output to a data xref/string reference of the same VA.

    Resume-shaped XOR plaintext often lives in .rdata. Instruction windows
    may never spell the full VA as an LEA-to-RCX operand, but Ghidra still
    exports a data_reference/xref ``to`` that address. That row is the
    consumer of the recovered object; nearby APIs still do not qualify.
    """
    if output_address in (None, "") or str(kind or "") not in _DECODE_REFERENCE_KINDS:
        return None
    if not isinstance(value, Mapping):
        return None
    site_anchor = anchor if isinstance(anchor, Mapping) else {}
    for blob in _iter_reference_blobs(value):
        matched = None
        for locator in _reference_target_locators(blob):
            address = _as_nonneg_int(locator)
            if address is None:
                address = parse_operand_address(locator)
            if address is None:
                address = locator
            if addresses_alias(address, output_address, image_base):
                matched = address
                break
        if matched is None:
            continue
        site = blob.get("from") or value.get("from") or site_anchor.get("callsite")
        api = blob.get("api") or value.get("api")
        if is_ghidra_data_or_string_label(api) or not str(api or "").strip():
            api = None
        parsed = parse_operand_address(matched)
        return {
            "api": api,
            "callsite": site,
            "argument_index": 0,
            "resolved": True,
            "link_kind": "decoded_va_reference",
            "value": hex(int(parsed)) if isinstance(parsed, int) else matched,
        }
    return None
