"""Deterministic PMA static-analysis plan from PE/import/section/string facts.

This is the analyst planning layer: hash/strings/IAT/packer latch, then Windows
object graph, covert-launch sequences, encoding, and anti-RE.  It consumes
plain dict facts only.  Isolated emulation is a static action.  Stub IAT of a
packed image is never treated as payload behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from threat_report_agent.semantic_predicates import normalize_api_symbol


ALLOWED_NEXT_STATIC_ACTIONS: frozenset[str] = frozenset(
    {"GET_DECOMPILE", "TRACE_API_ARGUMENT", "CONTROLLED_EMULATE"}
)

# PMA ch01: a compiler does not emit a Hello-World-smaller IAT that is only
# LoadLibrary/GetProcAddress.  Count unique imported function names.
_PACKED_IMPORT_LIMIT = 8
_VIRTUAL_OVER_RAW_MIN_DELTA = 0x1000

_RESOLVER_LOAD = frozenset(
    {
        "loadlibrary",
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryexa",
        "loadlibraryexw",
        "ldrloaddll",
    }
)
_RESOLVER_PROC = frozenset(
    {
        "getprocaddress",
        "ldrgetprocedureaddress",
        "getprocaddressa",
        "getprocaddressw",
    }
)
_PACKER_SECTION_NAMES = frozenset({"upx0", "upx1", "upx2", "mpress1", "mpress2", ".packed", "aspack"})

_WINDOWS_OBJECT_APIS = {
    "createfilea": "file",
    "createfilew": "file",
    "writefile": "file",
    "readfile": "file",
    "deletefilea": "file",
    "deletefilew": "file",
    "regsetvalueexa": "registry",
    "regsetvalueexw": "registry",
    "regcreatekeyexa": "registry",
    "regcreatekeyexw": "registry",
    "createmutexa": "mutex",
    "createmutexw": "mutex",
    "openmutexa": "mutex",
    "openmutexw": "mutex",
    "createservicea": "service",
    "createservicew": "service",
    "cocreateinstance": "com",
    "internetopena": "network",
    "internetopenw": "network",
    "winhttpopen": "network",
    "socket": "network",
    "connect": "network",
}
_COVERT_LAUNCH_APIS = {
    "createprocessa": "process_create",
    "createprocessw": "process_create",
    "openprocess": "cross_process",
    "virtualallocex": "cross_process",
    "writeprocessmemory": "cross_process",
    "createremotethread": "remote_thread",
    "queueuserapc": "apc",
    "setwindowshookex": "hook",
    "ntunmapviewofsection": "process_replace",
    "zwunmapviewofsection": "process_replace",
    "setthreadcontext": "process_replace",
    "resumethread": "process_replace",
}
_ENCODING_APIS = {
    "cryptimportkey",
    "cryptdecrypt",
    "cryptacquirecontext",
    "cryptacquirecontexta",
    "cryptacquirecontextw",
    "cryptunprotectdata",
}
_ANTI_RE_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "outputdebugstringa",
    "outputdebugstringw",
    "rdtsc",
}

PAYLOAD_BEHAVIOR_CATEGORIES: frozenset[str] = frozenset(
    {
        "loader",
        "network",
        "process",
        "injection",
        "persistence",
        "thread",
        "shell_or_staging",
        "anti_analysis",
        "collection_or_privilege",
        "evasion_or_memory",
        "api",
        "windows_object",
        "covert_launch",
    }
)
DISPATCH_CATEGORIES: frozenset[str] = frozenset(
    {"unpack", "windows_object", "covert_launch", "encoding", "anti_re"}
)


def _row_value(row: Mapping[str, object]) -> Mapping[str, object]:
    value = row.get("value")
    return value if isinstance(value, Mapping) else {}


def _row_id(row: Mapping[str, object]) -> str:
    raw = row.get("id")
    return str(raw).strip() if isinstance(raw, (str, int)) and str(raw).strip() else ""


def _normalize_api(symbol: object) -> str:
    return normalize_api_symbol(symbol)


def iter_import_names(facts: Iterable[Mapping[str, object]]) -> tuple[str, ...]:
    """Collect unique imported function identities from PE and import rows."""
    names: list[str] = []
    seen: set[str] = set()

    def add(raw: object) -> None:
        normalized = _normalize_api(raw)
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        names.append(normalized)

    for row in facts:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind", "")).casefold()
        value = _row_value(row)
        if kind in {"import_symbol", "export_symbol"}:
            add(value.get("name") or value.get("api") or value.get("symbol"))
            continue
        if kind == "pe_structure":
            imports = value.get("imports") or ()
            if isinstance(imports, Mapping):
                imports = (imports,)
            if not isinstance(imports, (list, tuple)):
                continue
            for module in imports:
                if not isinstance(module, Mapping):
                    continue
                functions = module.get("functions") or module.get("names") or ()
                if isinstance(functions, (list, tuple, set)):
                    for item in functions:
                        if isinstance(item, Mapping):
                            add(item.get("name") or item.get("function"))
                        else:
                            add(item)

    return tuple(names)


def stub_import_names(facts: Iterable[Mapping[str, object]]) -> frozenset[str]:
    """Return the import set that must not be treated as payload behavior."""
    return frozenset(iter_import_names(facts))


def _pe_rows(facts: Iterable[Mapping[str, object]]) -> tuple[Mapping[str, object], ...]:
    return tuple(
        row
        for row in facts
        if isinstance(row, Mapping) and str(row.get("kind", "")).casefold() == "pe_structure"
    )


def _section_rows(facts: Iterable[Mapping[str, object]]) -> tuple[Mapping[str, object], ...]:
    sections: list[Mapping[str, object]] = []
    for row in facts:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind", "")).casefold()
        value = _row_value(row)
        if kind in {"pe_section", "section"}:
            sections.append(value)
            continue
        if kind != "pe_structure":
            continue
        nested = value.get("sections") or ()
        if isinstance(nested, Mapping):
            nested = (nested,)
        if isinstance(nested, (list, tuple)):
            sections.extend(item for item in nested if isinstance(item, Mapping))
    return tuple(sections)


def section_unpack_signal(facts: Iterable[Mapping[str, object]]) -> bool:
    """True when VirtualSize >> SizeOfRawData or a known packer section name."""
    for section in _section_rows(facts):
        name = str(section.get("name") or "").strip().casefold()
        if name in _PACKER_SECTION_NAMES:
            return True
        try:
            virtual = int(section.get("virtual_size") or section.get("VirtualSize") or 0)
            raw = int(
                section.get("raw_size")
                or section.get("SizeOfRawData")
                or section.get("size_of_raw_data")
                or 0
            )
        except (TypeError, ValueError):
            continue
        if virtual <= 0:
            continue
        if raw == 0 and virtual >= _VIRTUAL_OVER_RAW_MIN_DELTA:
            return True
        if virtual >= max(raw * 2, raw + _VIRTUAL_OVER_RAW_MIN_DELTA):
            return True
    return False


def _has_resolver_pair(imports: Sequence[str]) -> bool:
    names = set(imports)
    has_load = bool(names & _RESOLVER_LOAD)
    has_proc = bool(names & _RESOLVER_PROC)
    return has_load and has_proc


def packer_latch_active(facts: Iterable[Mapping[str, object]]) -> bool:
    """PMA packer latch: tiny resolver IAT, or a runtime-unpack section shape."""
    rows = tuple(item for item in facts if isinstance(item, Mapping))
    imports = iter_import_names(rows)
    few = 0 < len(imports) <= _PACKED_IMPORT_LIMIT
    if few and _has_resolver_pair(imports):
        return True
    return section_unpack_signal(rows)


def unpack_completed(facts: Iterable[Mapping[str, object]]) -> bool:
    """True after a recovered child / reconstructed IAT exists for this packed image."""
    for row in facts:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind", "")).casefold()
        value = _row_value(row)
        if kind in {"unpacked_payload", "reconstructed_iat"}:
            return True
        if kind == "decoded_artifact":
            source = str(value.get("source") or "").casefold()
            if source in {"controlled_emulation", "unpack", "unpack_stub"} and value.get(
                "child_artifact_id"
            ):
                return True
        if kind == "mechanism_chain" and str(value.get("chain_type") or "") == "recovered_payload":
            child_type = str(value.get("child_detected_type") or "").casefold()
            kinds = value.get("child_fact_kinds") or ()
            if child_type in {"pe", "elf"} or "pe_structure" in kinds or "import_symbol" in kinds:
                return True
    return False


def reconstructed_import_names(facts: Iterable[Mapping[str, object]]) -> tuple[str, ...]:
    """Payload IAT recovered after unpack, never the packed stub listing."""
    names: list[str] = []
    seen: set[str] = set()
    for row in facts:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind", "")).casefold()
        value = _row_value(row)
        raw: object = ()
        if kind == "unpacked_payload":
            raw = value.get("reconstructed_iat") or value.get("imports") or ()
        elif kind == "reconstructed_iat":
            raw = value.get("names") or value.get("imports") or value.get("functions") or ()
        else:
            continue
        if isinstance(raw, Mapping):
            raw = raw.values()
        if not isinstance(raw, (list, tuple, set)):
            continue
        for item in raw:
            candidate = item.get("name") if isinstance(item, Mapping) else item
            normalized = _normalize_api(candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            names.append(normalized)
    return tuple(names)


def _unpacked_oep(facts: Iterable[Mapping[str, object]]) -> str:
    for row in facts:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("kind", "")).casefold() != "unpacked_payload":
            continue
        value = _row_value(row)
        raw = value.get("oep") or value.get("entry_rva") or value.get("entry")
        if isinstance(raw, int) and raw >= 0:
            return hex(raw)
        text = str(raw or "").strip()
        if text:
            return text if text.lower().startswith("0x") else text
    return ""


def _entry_rva(facts: Iterable[Mapping[str, object]]) -> str:
    for row in _pe_rows(facts):
        value = _row_value(row)
        raw = value.get("entry_rva")
        if raw in (None, ""):
            raw = value.get("entry") or value.get("address_of_entry_point")
        if isinstance(raw, int) and raw >= 0:
            return hex(raw)
        text = str(raw or "").strip()
        if text:
            return text if text.lower().startswith("0x") else text
    return ""


def _identity_row(facts: Iterable[Mapping[str, object]]) -> Mapping[str, object] | None:
    for row in facts:
        if isinstance(row, Mapping) and str(row.get("kind", "")).casefold() in {
            "file_identity",
            "hash",
            "file_hash",
        }:
            return row
    return None


def _string_rows(facts: Iterable[Mapping[str, object]]) -> tuple[Mapping[str, object], ...]:
    return tuple(
        row
        for row in facts
        if isinstance(row, Mapping) and str(row.get("kind", "")).casefold() in {"string", "string_semantics"}
    )


def _has_call_evidence(facts: Iterable[Mapping[str, object]], apis: Iterable[str]) -> bool:
    wanted = {_normalize_api(item) for item in apis if _normalize_api(item)}
    if not wanted:
        return False
    for row in facts:
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind", "")).casefold()
        if kind not in {"function_call", "api_argument_trace"}:
            continue
        value = _row_value(row)
        candidates = [
            value.get("api"),
            value.get("api_name"),
            value.get("name"),
            value.get("target_name"),
            value.get("target_function"),
        ]
        if any(_normalize_api(item) in wanted for item in candidates):
            return True
    return False


def _validate_actions(actions: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    for item in actions:
        name = str(item).strip().upper()
        if name in ALLOWED_NEXT_STATIC_ACTIONS and name not in ordered:
            ordered.append(name)
    return tuple(ordered)


@dataclass(frozen=True)
class StaticPlanItem:
    """One ordered static-analysis question with a bounded next-action family."""

    id: str
    title: str
    why: str
    required_facts: tuple[str, ...]
    investigation_category: str
    next_static_actions: tuple[str, ...]
    selector: Mapping[str, str | int] = field(default_factory=dict)
    priority: int = 50
    evidence_ids: tuple[str, ...] = ()
    question: str = ""
    hypothesis: str = ""
    alternatives: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    forbids_stub_iat_payload: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "next_static_actions", _validate_actions(self.next_static_actions))
        object.__setattr__(self, "selector", dict(self.selector))
        if not self.question:
            object.__setattr__(self, "question", self.title)
        if not self.hypothesis:
            object.__setattr__(self, "hypothesis", self.why)

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "why": self.why,
            "required_facts": list(self.required_facts),
            "investigation_category": self.investigation_category,
            "next_static_actions": list(self.next_static_actions),
            "selector": dict(self.selector),
            "priority": self.priority,
            "evidence_ids": list(self.evidence_ids),
            "question": self.question,
            "hypothesis": self.hypothesis,
            "alternatives": list(self.alternatives),
            "missing_evidence": list(self.missing_evidence),
            "forbids_stub_iat_payload": self.forbids_stub_iat_payload,
        }


def _item(
    *,
    item_id: str,
    title: str,
    why: str,
    required_facts: Sequence[str],
    category: str,
    actions: Sequence[str],
    selector: Mapping[str, str | int] | None = None,
    priority: int,
    evidence_ids: Sequence[str] = (),
    alternatives: Sequence[str] = (),
    missing: Sequence[str] = (),
    forbids_stub_iat_payload: bool = False,
    question: str = "",
    hypothesis: str = "",
) -> StaticPlanItem:
    return StaticPlanItem(
        id=item_id,
        title=title,
        why=why,
        required_facts=tuple(required_facts),
        investigation_category=category,
        next_static_actions=tuple(actions),
        selector=dict(selector or {}),
        priority=priority,
        evidence_ids=tuple(item for item in evidence_ids if item),
        alternatives=tuple(alternatives),
        missing_evidence=tuple(missing),
        forbids_stub_iat_payload=forbids_stub_iat_payload,
        question=question,
        hypothesis=hypothesis,
    )


def build_pma_static_plan(facts: Iterable[Mapping[str, object]]) -> tuple[StaticPlanItem, ...]:
    """Emit an ordered PMA static plan from PE/import/section/string facts."""
    rows = tuple(item for item in facts if isinstance(item, Mapping))
    imports = iter_import_names(rows)
    import_set = set(imports)
    shape_packed = packer_latch_active(rows)
    unpacked = unpack_completed(rows)
    reconstructed = reconstructed_import_names(rows)
    payload_import_set = (
        set(reconstructed)
        if unpacked and reconstructed
        else (set() if shape_packed else import_set)
    )
    entry = _entry_rva(rows)
    unpacked_oep = _unpacked_oep(rows)
    entry_selector: dict[str, str | int] = {"function_entry": entry} if entry else {}
    pe_ids = tuple(_row_id(row) for row in _pe_rows(rows) if _row_id(row))
    import_ids = tuple(
        _row_id(row)
        for row in rows
        if str(row.get("kind", "")).casefold() == "import_symbol" and _row_id(row)
    )
    plan: list[StaticPlanItem] = []

    identity = _identity_row(rows)
    identity_ids = (_row_id(identity),) if identity and _row_id(identity) else ()
    plan.append(
        _item(
            item_id="pma-hash-fingerprint",
            title="Hash the sample as a fingerprint, not as behavior proof",
            why="Hashes label and retrieve a file. They do not prove what the image does.",
            required_facts=("file_identity.md5", "file_identity.sha1", "file_identity.sha256"),
            category="fingerprint",
            actions=("GET_DECOMPILE",) if entry else (),
            selector=entry_selector,
            priority=4,
            evidence_ids=identity_ids,
            alternatives=("hash collision is not functional identity",),
            missing=("file_identity",) if identity is None else (),
        )
    )

    strings = _string_rows(rows)
    string_ids = tuple(_row_id(row) for row in strings if _row_id(row))[:16]
    plan.append(
        _item(
            item_id="pma-strings",
            title="Read ASCII/UTF-16 strings as leads, then confirm with decompile",
            why="API names, paths, Run keys, and URLs are hypotheses. Short noise is discarded. Packed images often have almost no readable strings.",
            required_facts=("string.text",),
            category="strings",
            actions=("GET_DECOMPILE",) if entry else (),
            selector=entry_selector,
            priority=5,
            evidence_ids=string_ids,
            alternatives=("compiler/runtime strings", "packed stub with almost no strings"),
            missing=("readable strings",) if not strings else (),
        )
    )

    if shape_packed:
        unpack_missing: list[str] = []
        if not unpacked or not unpacked_oep:
            unpack_missing.append("OEP after unpack")
        if not unpacked or not reconstructed:
            unpack_missing.append("reconstructed payload IAT")
        plan.append(
            _item(
                item_id="pma-packer-latch-unpack",
                title="Packer latch: unpack before treating IAT as payload behavior",
                why=(
                    "Few imports plus LoadLibrary/GetProcAddress, or VirtualSize much larger than "
                    "SizeOfRawData, is a packer/runtime-unpack latch. The stub IAT describes the "
                    "unpacker, not the payload. Isolated emulation of the stub is a static unpack "
                    "attempt. Do not invent payload capabilities from the stub import table."
                ),
                required_facts=("pe_structure.imports", "pe_structure.sections"),
                category="unpack",
                actions=() if not unpack_missing else ("GET_DECOMPILE", "CONTROLLED_EMULATE"),
                selector=entry_selector,
                priority=3,
                evidence_ids=(*pe_ids, *import_ids),
                alternatives=("genuinely tiny native helper", "overlay that is not a packer"),
                missing=tuple(unpack_missing),
                forbids_stub_iat_payload=True,
                question="Where does the stub unpack, and what is the OEP/reconstructed IAT?",
                hypothesis="This image is packed; stub IAT is not payload behavior.",
            )
        )
    if payload_import_set:
        plan.append(
            _item(
                item_id="pma-iat-hypotheses",
                title="Use the import table as a hypothesis generator, then recover call arguments",
                why=(
                    "Imports suggest Windows objects and APIs to prove. An import is not a runtime "
                    "call. Confirm who calls the API and with which arguments."
                    if not unpacked
                    else "The reconstructed payload IAT is a hypothesis generator after unpack. Stub IAT remains non-payload."
                ),
                required_facts=("pe_structure.imports",),
                category="iat",
                actions=("TRACE_API_ARGUMENT", "GET_DECOMPILE"),
                selector=entry_selector,
                priority=8,
                evidence_ids=(*pe_ids, *import_ids),
                alternatives=("imported capability is unused",),
                missing=("callsite", "argument values"),
            )
        )

    object_hits = sorted(
        name for name in payload_import_set if name in _WINDOWS_OBJECT_APIS
    )
    if object_hits:
        families = tuple(dict.fromkeys(_WINDOWS_OBJECT_APIS[name] for name in object_hits))
        plan.append(
            _item(
                item_id="pma-windows-object-graph",
                title="Recover the Windows object graph suggested by the IAT",
                why=(
                    "File, registry, mutex, service, COM, and network APIs name objects to recover: "
                    "path, key, handle producer/consumer, and failure branch. Presence of the import "
                    "is not proof the object is used."
                ),
                required_facts=("import_symbol", "function_call"),
                category="windows_object",
                actions=("TRACE_API_ARGUMENT", "GET_DECOMPILE"),
                selector={"target": object_hits[0], **entry_selector},
                priority=14,
                evidence_ids=import_ids,
                alternatives=("unused import", "ordinary application I/O"),
                missing=("object identity", "handle producer/consumer"),
                question=f"Which Windows objects ({', '.join(families)}) are actually constructed and consumed?",
            )
        )

    covert_hits = sorted(name for name in payload_import_set if name in _COVERT_LAUNCH_APIS)
    covert_call = _has_call_evidence(rows, _COVERT_LAUNCH_APIS) and not (shape_packed and not unpacked)
    if covert_hits or covert_call:
        plan.append(
            _item(
                item_id="pma-covert-launch",
                title="Prove covert-launch sequences from recovered flags and start routines",
                why=(
                    "CreateProcess needs recovered creation_flags; CreateThread/CreateRemoteThread/"
                    "QueueUserAPC need a start routine. Do not invent CREATE_SUSPENDED, explorer.exe, "
                    "or injection from an API listing."
                ),
                required_facts=("function_call", "creation_flags_or_start_routine"),
                category="covert_launch",
                actions=("TRACE_API_ARGUMENT", "GET_DECOMPILE", "CONTROLLED_EMULATE"),
                selector={"target": (covert_hits[0] if covert_hits else "CreateProcessW"), **entry_selector},
                priority=10,
                evidence_ids=import_ids,
                alternatives=("benign child process", "ordinary in-process worker thread"),
                missing=("creation_flags", "start_routine"),
            )
        )

    encoding_hits = sorted(name for name in payload_import_set if name in _ENCODING_APIS)
    has_encode_material = any(
        str(row.get("kind", "")).casefold()
        in {
            "encoded_blob",
            "crypto_indicator",
            "high_entropy_section",
            "mechanism_decode_window",
            "crypto_pattern",
        }
        for row in rows
    )
    if (encoding_hits or has_encode_material) and (not shape_packed or unpacked):
        plan.append(
            _item(
                item_id="pma-encoding",
                title="Identify encoding/crypto to recover configuration, not to claim strength",
                why=(
                    "XOR/Base64/CryptoAPI and high-entropy blobs are leads. Recover algorithm, key "
                    "source, input/output, and consumer. Do not name AES without constants or imports."
                ),
                required_facts=("encoded_blob_or_crypto_api", "output_consumer"),
                category="encoding",
                actions=("GET_DECOMPILE", "CONTROLLED_EMULATE"),
                selector=entry_selector,
                priority=16,
                evidence_ids=tuple(
                    _row_id(row)
                    for row in rows
                    if str(row.get("kind", "")).casefold()
                    in {"encoded_blob", "crypto_indicator", "high_entropy_section", "mechanism_decode_window"}
                    and _row_id(row)
                )[:16],
                alternatives=("checksum", "high-entropy packed payload without a decoder"),
                missing=("algorithm", "key_or_state", "plaintext consumer"),
            )
        )
    elif shape_packed and not unpacked and has_encode_material:
        plan.append(
            _item(
                item_id="pma-encoding-after-unpack",
                title="High-entropy or crypto material is a packed payload lead, not decoded config",
                why=(
                    "A packed image's high-entropy section is the unpack target. Do not report it as "
                    "recovered configuration until the stub has been unpacked."
                ),
                required_facts=("high_entropy_section",),
                category="encoding",
                actions=("GET_DECOMPILE", "CONTROLLED_EMULATE"),
                selector=entry_selector,
                priority=18,
                alternatives=("packed overlay", "genuine encrypted config after unpack"),
                missing=("unpacked bytes", "decoder after OEP"),
                forbids_stub_iat_payload=True,
            )
        )

    anti_hits = sorted(name for name in payload_import_set if name in _ANTI_RE_APIS)
    has_tls = any(str(row.get("kind", "")).casefold() in {"tls_callback", "tls_metadata"} for row in rows)
    if (anti_hits or has_tls) and (not shape_packed or unpacked):
        plan.append(
            _item(
                item_id="pma-anti-re",
                title="Treat anti-debug/anti-disassembly APIs as probes, not as absent behavior",
                why=(
                    "Debugger/VM probes and TLS callbacks can run before WinMain. Isolated emulation "
                    "may fail; record UNKNOWN/UNSUPPORTED instead of concluding the sample does nothing."
                ),
                required_facts=("anti_analysis_api_or_tls", "gated_branch"),
                category="anti_re",
                actions=("GET_DECOMPILE", "CONTROLLED_EMULATE"),
                selector=entry_selector,
                priority=18,
                evidence_ids=import_ids,
                alternatives=("legitimate diagnostics", "compatibility probe"),
                missing=("comparison constant", "gated behavior"),
            )
        )

    return tuple(plan)


def static_analysis_plan_snapshot(
    facts: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Reporting envelope: completed / UNKNOWN / next method, plus packer latch.

    ``StaticPlanItem.as_dict`` stays a planner record. This mapping is the
    live ``investigation.static_analysis_plan`` shape reporting already reads.
    Missing required facts stay UNKNOWN. Empty missing_evidence is COMPLETED
    for that rung only — never HOW closure.
    """
    rows = tuple(item for item in facts if isinstance(item, Mapping))
    items: list[dict[str, object]] = []
    for item in build_pma_static_plan(rows):
        missing = list(item.missing_evidence)
        next_actions = list(item.next_static_actions)
        items.append(
            {
                "id": item.id,
                "title": item.title,
                "status": "COMPLETED" if not missing else "UNKNOWN",
                "unknowns": missing,
                "next_method": next_actions[0] if next_actions else "",
                "kind": item.investigation_category,
                "packer_latch": bool(item.forbids_stub_iat_payload),
            }
        )
    return {
        "schema_version": "1",
        "packer_latch": packer_latch_active(rows),
        "items": items,
    }


def pma_dispatch_items(
    facts: Iterable[Mapping[str, object]],
) -> tuple[StaticPlanItem, ...]:
    """Plan items that should become investigation seeds (not reporting-only rungs).

    Unpack is the only auto-admitted seed. Covert-launch and object-graph items
    stay on the ordered plan; DeepMiningPlanner already promotes recovered
    function/call evidence into process/thread targets. Injecting them from
    IAT/entry_rva would treat a PE header or stub import as a function anchor.
    """
    if not packer_latch_active(facts) or unpack_completed(facts):
        return ()
    items: list[StaticPlanItem] = []
    for item in build_pma_static_plan(facts):
        if item.investigation_category != "unpack":
            continue
        if not item.next_static_actions:
            continue
        selector = dict(item.selector)
        entry = selector.pop("function_entry", None)
        if entry not in (None, ""):
            selector = {"target": entry, "role": "unpack_stub", **selector}
        if not selector.get("target"):
            continue
        items.append(
            StaticPlanItem(
                id=item.id,
                title=item.title,
                why=item.why,
                required_facts=item.required_facts,
                investigation_category=item.investigation_category,
                next_static_actions=item.next_static_actions,
                selector=selector,
                priority=item.priority,
                evidence_ids=item.evidence_ids,
                question=item.question,
                hypothesis=item.hypothesis,
                alternatives=item.alternatives,
                missing_evidence=item.missing_evidence,
                forbids_stub_iat_payload=True,
            )
        )
    return tuple(items)


def blocks_payload_behavior_seed(
    facts: Iterable[Mapping[str, object]],
    *,
    api: object | None = None,
    category: str | None = None,
    source_is_import_only: bool = False,
) -> bool:
    """True when a stub IAT lead must not become a payload investigation thread."""
    rows = tuple(item for item in facts if isinstance(item, Mapping))
    if not packer_latch_active(rows):
        return False
    if unpack_completed(rows):
        if not source_is_import_only or api is None:
            return False
        normalized = _normalize_api(api)
        return bool(normalized and normalized in stub_import_names(rows))
    if category and str(category).casefold() in {"unpack", "fingerprint", "strings", "iat"}:
        return False
    if category and str(category).casefold() in PAYLOAD_BEHAVIOR_CATEGORIES:
        return True
    if source_is_import_only:
        return True
    if api is not None:
        normalized = _normalize_api(api)
        if normalized and normalized in stub_import_names(rows):
            return True
    return False
