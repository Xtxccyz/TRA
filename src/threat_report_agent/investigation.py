"""Evidence-driven investigation primitives.

The static parsers produce observations; this module turns those observations
into a bounded, auditable investigation loop.  It deliberately contains no
sample execution and no model-specific code.  A model may propose an action at
the service seam, but only the catalog and queue can authorize its execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from types import SimpleNamespace
import heapq
import hashlib
import json
import uuid
import re
from typing import AbstractSet, Callable, Iterable, Mapping, Sequence

from threat_report_agent.static.evidence_recovery import (
    FailureInterpretation,
    canonical_action_key,
)
from threat_report_agent.mechanism_completeness import mechanism_completeness_score as _semantic_mechanism_completeness_score
from threat_report_agent.semantic_predicates import normalize_api_symbol
from threat_report_agent.behavior_catalog import (
    BehaviorCatalog,
    ContractEvaluation,
    SupportLevel,
    is_unknown_or_negative,
)
from threat_report_agent.static.pma_static_plan import (
    pma_dispatch_items,
    packer_latch_active,
    reconstructed_import_names,
    stub_import_names,
    unpack_completed,
)
from threat_report_agent.emulation.controlled_emulation import is_real_simulation_row
from threat_report_agent.dataflow import (
    catalog_buffers_are_same_object,
    catalog_decode_output_to_process_command_relation,
    catalog_output_consumer_relation,
    is_named_decode_consumer_api,
    is_process_execution_api,
)
from threat_report_agent.investigation_protocol import (
    fill_protocol,
    may_record_static_boundary,
    s_ladder,
)


SELECTOR_ALIASES: dict[str, str] = {
    "function_name": "function",
    "name": "function",
    "va": "address",
    "virtual_address": "address",
    "entry_point": "function_entry",
    "len": "length",
    "byte_count": "length",
    "byte_length": "length",
    "arg_index": "argument_index",
}

CATALOG_SELECTOR_KEYS: tuple[str, ...] = (
    "target",
    "api",
    "function",
    "function_entry",
    "entry",
    "rva",
    "address",
    "length",
    "size",
    "offset",
    "file_offset",
    "argument_index",
    "index",
    "callsite",
    "max_instructions",
    "formula",
    "limit",
)


def normalize_target_selector(
    selector: Mapping[str, object] | None,
    *,
    allowed_keys: Iterable[str] | None = None,
) -> dict[str, str | int]:
    """Map DSH/model selector aliases and drop unknown keys instead of 422.

    ``function_name`` and ``length`` are the live dialect that burned
    GET_FUNCTION/READ_BYTES turns. Catalog validation still requires at least
    one allowed key after this pass.
    """
    allowed = set(allowed_keys or CATALOG_SELECTOR_KEYS)
    normalized: dict[str, str | int] = {}
    for key, value in dict(selector or {}).items():
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        if not str(value).strip():
            continue
        mapped = SELECTOR_ALIASES.get(str(key).strip(), str(key).strip())
        if mapped in allowed:
            normalized[mapped] = value
    return normalized


def _link_text(row: Mapping[str, object]) -> str:
    """Render one typed static row for bounded semantic-link matching."""
    value = row.get("value")
    anchor = row.get("anchor")
    text = f"{row.get('kind', '')} {value!r} {anchor!r}".casefold()
    patch_bytes = _structured_patch_bytes(row)
    if patch_bytes:
        text += " patch_bytes=" + " ".join(f"{item:02x}" for item in patch_bytes)
    return text


def _mapping_sequence(value: object) -> tuple[Mapping[str, object], ...]:
    """Return mapping items from a scalar/list exporter field."""
    if isinstance(value, Mapping):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(item for item in value if isinstance(item, Mapping))
    return ()


def _identity_tokens(source: object) -> tuple[str, ...]:
    """Extract function/RVA identities from an exporter location object."""
    if not isinstance(source, Mapping):
        return ()
    tokens: list[str] = []
    for key in (
        "function_entry", "entry", "entry_rva", "rva", "address", "function",
        "caller_function", "callee_function", "source_function", "target_function",
    ):
        item = source.get(key)
        if isinstance(item, (str, int)) and str(item).strip():
            tokens.append(str(item).strip().casefold())
    return tuple(dict.fromkeys(tokens))


_FUNCTION_IDENTITY_KEYS = (
    "function_entry",
    "entry",
    "entry_rva",
    "rva",
    "address",
    "function",
)
_FUNCTION_RELATIONSHIP_KEYS = (
    "caller_function",
    "callee_function",
    "source_function",
    "target_function",
)
_FUNCTION_ANCHOR_TYPES = frozenset(
    {
        "function",
        "function_context",
        "function_entry",
        "function_instruction_window",
        "function_call",
        "cfg_block",
        "xref",
    }
)


def _scoped_function_tokens(
    source: object, *, include_relationships: bool = False
) -> tuple[str, ...]:
    """Extract an enclosing function identity without treating callees as one.

    Ghidra/exporter rows often carry ``target_function`` or ``callee_function``
    as the *destination* of a call.  Those names are API/function leads, not
    the location containing the observation.  They are admissible only inside
    an explicitly typed function source anchor; otherwise the row belongs to
    the global bucket and cannot create a function-local mechanism path.
    """
    if not isinstance(source, Mapping):
        return ()
    keys = _FUNCTION_IDENTITY_KEYS
    if include_relationships:
        keys += _FUNCTION_RELATIONSHIP_KEYS
    tokens: list[str] = []
    for key in keys:
        item = source.get(key)
        if isinstance(item, (str, int)) and str(item).strip():
            tokens.append(str(item).strip().casefold())
    return tuple(dict.fromkeys(tokens))


def _link_function_key(row: Mapping[str, object]) -> str:
    """Return the strongest available function/RVA identity for a row."""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
    # Capstone fallback rows have a precise caller RVA but no recovered
    # function boundary.  Coarse executable-region buckets let the static
    # correlator join a bounded sequence such as CreateProcess -> CreatePipe
    # -> ReadFile while keeping the result explicitly fallback-derived.  The
    # bucket is deliberately one page (0x1000), never the whole artifact.
    if str(row.get("kind", "")).casefold() == "code_api_call":
        raw_rva = value.get("rva", anchor.get("rva"))
        try:
            rva = int(raw_rva) if isinstance(raw_rva, int) else int(str(raw_rva), 0)
        except (TypeError, ValueError):
            rva = None
        if rva is not None and rva >= 0:
            return f"fallback_region@0x{rva & ~0xfff:x}"
    # A top-level anchor/value may contain relationship fields such as
    # ``target_function``.  Only stable enclosing-function fields are valid
    # here; relationship names are not locations.
    for source in (anchor, value):
        tokens = _scoped_function_tokens(source)
        if tokens:
            return tokens[0]
        for nested in _mapping_sequence(source.get("source_anchors")):
            source_type = str(nested.get("type", "")).casefold()
            tokens = _scoped_function_tokens(
                nested,
                include_relationships=source_type in _FUNCTION_ANCHOR_TYPES,
            )
            if tokens:
                return tokens[0]
    # Unanchored imports/strings are still useful as global inputs, but are
    # kept in a separate bucket and never create a function-local link alone.
    return "__global__"


_API_NAMES_CACHE: dict[int, tuple[object, tuple[str, ...]]] = {}
# Bounded so a long-lived process cannot retain every row it has ever extracted.
_API_NAMES_CACHE_LIMIT = 200_000
# Same bound for the per-row `str(value)` cache used by `Verifier._corpus_text`.
_ROW_TEXT_CACHE_LIMIT = 200_000


def _link_api_names(rows: Iterable[Mapping[str, object]]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        for key in (
            "api", "api_name", "resolved_api", "referenced_target", "callee",
            "name", "target_name", "target_function", "consumer", "transport",
            "resolver", "export_name", "resolved_symbol",
        ):
            item = value.get(key)
            if isinstance(item, Mapping):
                for nested in ("api", "name", "symbol", "target_name", "target_function"):
                    if item.get(nested):
                        names.add(normalize_api_symbol(item[nested]))
            elif item:
                names.add(normalize_api_symbol(item))
        for key in (
            "apis", "functions", "call_targets", "calls", "consumer_apis",
            "consumer_candidates", "resolved_symbols", "references", "callees",
        ):
            nested = value.get(key)
            if isinstance(nested, (list, tuple, set)):
                for item in nested:
                    if isinstance(item, Mapping):
                        for field in (
                            "api", "api_name", "resolved_api", "name", "symbol",
                            "target_name", "target_function", "callee", "target",
                        ):
                            if item.get(field):
                                names.add(normalize_api_symbol(item[field]))
                    elif item:
                        names.add(normalize_api_symbol(item))
    return {item for item in names if item}


def _structured_patch_bytes(row: Mapping[str, object]) -> tuple[int, ...]:
    """Normalize structured instruction-write fields into byte values.

    Exporters differ in whether they emit ``bytes``, ``opcode_bytes``,
    ``patch_bytes`` or a list of integers.  Only an actual 3-byte value is
    returned; a length field without bytes is intentionally insufficient.
    """
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    candidates: list[object] = []
    for key in (
        "patch_bytes", "opcode_bytes", "write_bytes", "bytes_written",
        "written_bytes", "instruction_bytes", "bytes",
    ):
        if value.get(key) is not None:
            candidates.append(value.get(key))
    for candidate in candidates:
        # Some exporter versions wrap hexadecimal bytes in an object (for
        # example ``{"hex": "33 c0 c3"}``) to carry encoding metadata.  Peel
        # only the known byte-bearing keys; arbitrary mappings are ignored so
        # a length/offset object cannot accidentally become a patch.
        if isinstance(candidate, Mapping):
            for nested_key in ("hex", "bytes", "value", "data"):
                nested = candidate.get(nested_key)
                if nested is not None:
                    candidate = nested
                    break
        if isinstance(candidate, (bytes, bytearray)):
            result = tuple(int(item) for item in candidate)
        elif isinstance(candidate, (list, tuple)):
            try:
                result = tuple(int(item, 0) if isinstance(item, str) else int(item) for item in candidate)
            except (TypeError, ValueError):
                result = ()
        elif isinstance(candidate, str):
            parts = re.findall(r"(?<![0-9a-f])(?:0x)?([0-9a-f]{1,2})(?![0-9a-f])", candidate.casefold())
            try:
                result = tuple(int(item, 16) for item in parts)
            except ValueError:
                result = ()
        else:
            result = ()
        if len(result) >= 3 and tuple(item & 0xFF for item in result[:3]) == (0x33, 0xC0, 0xC3):
            return (0x33, 0xC0, 0xC3)
    return ()


def _has_etw_patch(row: Mapping[str, object]) -> bool:
    """Recognize the exact ``xor eax,eax; ret`` write without text guessing."""
    if _structured_patch_bytes(row) == (0x33, 0xC0, 0xC3):
        return True
    text = _link_text(row)
    return bool(re.search(r"33\s*,?\s*c0\s*,?\s*c3", text))


def derive_static_mechanism_links(
    evidence: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Link co-located Ghidra facts into evaluator-addressable mechanisms.

    This is a read-only static correlator.  It does not execute a sample and
    does not claim runtime reachability.  A link is emitted only when the
    required API/constant/byte facts occur in one function/RVA bucket (with a
    global URL allowed to join a transport bucket).  Every output preserves
    the exact source Evidence IDs for later Claim/Mechanism provenance.
    """
    rows = [dict(row) for row in evidence if isinstance(row, Mapping) and row.get("id")]
    buckets: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        buckets.setdefault(_link_function_key(row), []).append(row)

    results: list[dict[str, object]] = []

    def emit(
        kind: str,
        mechanism_type: str,
        bucket: list[dict[str, object]],
        value: dict[str, object],
    ) -> None:
        source_ids = list(
            dict.fromkeys(str(item["id"]) for item in bucket if item.get("id"))
        )
        if not source_ids:
            return
        # Evidence arrival order is an implementation detail of the parser
        # and may differ across equivalent runs.  Link identity must therefore
        # use a canonical source set while the emitted list keeps first-seen
        # order for human navigation.
        canonical_source_ids = tuple(sorted(source_ids))
        identity = {
            "kind": kind,
            "mechanism_type": mechanism_type,
            "source_evidence_ids": canonical_source_ids,
            "function_key": _link_function_key(bucket[0]),
        }
        if any(
            item.get("kind") == kind
            and tuple(sorted(item.get("value", {}).get("source_evidence_ids", ())))
            == canonical_source_ids
            for item in results
        ):
            return
        results.append(
            {
                # Evidence primary keys are UUID-shaped (36 characters) in
                # every supported database.  Keep the link identity
                # deterministic for replay while avoiding the historical
                # human-readable prefix that overflowed PostgreSQL's
                # varchar(36) column on real PE fallback runs.
                "id": str(
                    uuid.UUID(
                        hashlib.sha256(
                            json.dumps(
                                identity,
                                ensure_ascii=True,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()[:32]
                    )
                ),
                "kind": kind,
                # This row is a deterministic derivation of immutable static
                # observations.  Keep the Evidence nature distinct from an
                # Agent Claim so downstream gates can enforce provenance.
                "nature": "STATIC_DERIVED",
                "value": {
                    **value,
                    "mechanism_type": mechanism_type,
                    "source_evidence_ids": source_ids,
                    "static_only": True,
                    "linkage": str(value.get("linkage") or "same_function_or_rva_static_facts"),
                },
                "anchor": {
                    "type": "static_mechanism_link",
                    "function_entry": _link_function_key(bucket[0]),
                    "source_evidence_ids": source_ids,
                },
            }
        )

    for key, bucket in buckets.items():
        # Imports and standalone strings intentionally live in the global
        # bucket.  They are discovery leads, not proof of a linked mechanism;
        # require a concrete function/RVA anchor before correlating APIs into
        # C1-C4 evidence (otherwise unrelated imports become a false chain).
        if key == "__global__":
            continue
        text = " ".join(_link_text(row) for row in bucket)
        apis = _link_api_names(bucket)
        ids_by_api: dict[str, list[str]] = {}
        for row in bucket:
            for api in _link_api_names((row,)):
                ids_by_api.setdefault(api, []).append(str(row["id"]))

        # C1: resolver + an explicit downstream consumer.  ``function pointer``
        # is an inferred data-flow description, never runtime proof.
        resolver = apis & {"getprocaddress", "loadlibrarya", "loadlibraryw", "ldrgetprocedureaddress"}
        consumers = apis & {
            "winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse",
        }
        pointer_rows = [
            row for row in bucket
            if row.get("kind") == "indirect_function_pointer_link"
        ]
        # A resolver is only linked to a downstream mechanism when either a
        # concrete transport API is co-located or the static data-flow pass
        # explicitly recovered its returned pointer consumer.  Shell APIs
        # (CreateProcess/ReadFile) remain in the separate SHELL_OUTPUT
        # mechanism and cannot inflate C1 by mere co-occurrence.
        if resolver and (consumers or pointer_rows):
            source = [row for row in bucket if str(row.get("id")) in {
                *sum((ids_by_api.get(item, []) for item in resolver | consumers), []),
            }]
            source.extend(row for row in pointer_rows if row not in source)
            emit(
                "mechanism_dynamic_api_link",
                "DYNAMIC_API_RESOLUTION",
                source,
                {
                    "apis": sorted(resolver | consumers),
                    "resolver": sorted(resolver),
                    "module": "dynamically loaded module",
                    "entry_point": "resolved function entry point",
                    "function_pointer": "resolved function pointer",
                    "consumer": sorted(consumers) or ["indirect function-pointer consumer"],
                    "consumer_apis": sorted(consumers),
                    "relationship": "LoadLibrary/GetProcAddress -> function pointer -> consumer",
                },
            )

        # C2 transport: URL/HTTPS and the complete WinHTTP request/response
        # sequence must be present in one statically linked path.
        if {"winhttpsendrequest", "winhttpreceiveresponse"}.issubset(apis) and (
            "winhttpopen" in apis or "https" in text
        ) and ("https" in text or "http" in text):
            required = {"winhttpsendrequest", "winhttpreceiveresponse", "winhttpopen"} & apis
            source = [row for row in bucket if str(row.get("id")) in {
                *sum((ids_by_api.get(item, []) for item in required), []),
            }]
            url_rows = [row for row in bucket if "https" in _link_text(row)]
            source.extend(row for row in url_rows if row not in source)
            emit(
                "mechanism_http_transport_link",
                "HTTP_DOWNLOAD",
                source,
                {
                    "apis": sorted(required),
                    "transport": "WinHTTP",
                    "endpoint": next((str(row.get("value", {}).get("text")) for row in url_rows if isinstance(row.get("value"), Mapping)), "https endpoint"),
                    "consumer": "WinHttpSendRequest",
                    "side_effect": "WinHttpReceiveResponse returns response bytes",
                    "response_side_effect": "WinHttpReceiveResponse",
                    "relationship": "https input -> WinHttpSendRequest -> WinHttpReceiveResponse",
                },
            )

        # C3: a CreateProcess + pipe + read/peek sequence is sufficient to
        # infer a shell-like output channel even when the command string is
        # encoded or absent.  The claim remains STATIC_INFERRED.
        pipe_apis = {"createpipe", "readfile", "peeknamedpipe"}
        if "createprocessw" in apis and pipe_apis.intersection(apis):
            required = {"createprocessw"} | pipe_apis.intersection(apis)
            source = [row for row in bucket if str(row.get("id")) in {
                *sum((ids_by_api.get(item, []) for item in required), []),
            }]
            emit(
                "mechanism_shell_output_link",
                "SHELL_OUTPUT",
                source,
                {
                    "apis": sorted(required),
                    "input": "shell command or child-process standard stream",
                    "shell": "child process command channel",
                    "consumer": "pipe",
                    "side_effect": "output capture",
                    "output_capture": "PeekNamedPipe/ReadFile drains child output",
                    "relationship": "CreateProcess -> CreatePipe -> PeekNamedPipe/ReadFile",
                },
            )

        # C4: require target identity, writable protection, exact patch bytes,
        # and instruction-cache flush in the same function/RVA.
        has_etw = "etweventwrite" in apis or "etweventwrite" in text
        has_vp = "virtualprotect" in apis
        has_flush = "flushinstructioncache" in apis
        # A length field by itself is not a patch.  Require the exact byte
        # sequence, accepting both textual and structured exporter forms.
        has_patch = any(_has_etw_patch(row) for row in bucket)
        if has_etw and has_vp and has_patch and has_flush:
            required_ids = [
                *sum((ids_by_api.get(item, []) for item in ("etweventwrite", "virtualprotect", "flushinstructioncache")), []),
                *[str(row["id"]) for row in bucket if _has_etw_patch(row)],
            ]
            source = [row for row in bucket if str(row.get("id")) in set(required_ids)]
            emit(
                "mechanism_etw_patch_link",
                "ETW_PATCH",
                source,
                {
                    "entry": "EtwEventWrite",
                    "condition": "VirtualProtect changes target protection",
                    "patch_bytes": "33 C0 C3",
                    "side_effect": "FlushInstructionCache commits the patch",
                    "flush": "FlushInstructionCache",
                    "relationship": "EtwEventWrite -> VirtualProtect -> 33 C0 C3 -> FlushInstructionCache",
                },
            )

    # Ghidra commonly places a resolver, its function-pointer store and the
    # eventual consumer in separate functions.  The local bucket pass above
    # intentionally remains strict; this second pass joins only explicit,
    # bounded call-graph paths.  It never treats a shared import list as an
    # edge and therefore cannot turn unrelated functions into a mechanism.
    node_keys = {key for key in buckets if key != "__global__"}

    def _function_token(value: object) -> str:
        token = str(value or "").strip().casefold()
        token = re.sub(r"^(?:fun_|sub_|thunk_|lab_)", "", token)
        return token.removeprefix("0x")

    token_to_node: dict[str, str] = {}
    for node in node_keys:
        token_to_node.setdefault(_function_token(node), node)

    def _resolve_node(value: object) -> str | None:
        raw = str(value or "").strip().casefold()
        if not raw:
            return None
        if raw in node_keys:
            return raw
        return token_to_node.get(_function_token(raw))

    adjacency: dict[str, set[str]] = {node: set() for node in node_keys}
    edge_rows: dict[tuple[str, str], list[dict[str, object]]] = {}
    for source, source_rows in buckets.items():
        if source == "__global__":
            continue
        for row in source_rows:
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            targets: list[object] = []
            for relation_field in (
                "call_targets", "calls", "references_from", "callees", "references",
                "call_edges", "edges",
            ):
                nested = value.get(relation_field)
                if isinstance(nested, Mapping):
                    targets.append(nested)
                elif isinstance(nested, (list, tuple)):
                    targets.extend(nested)
            # Some exporters emit one typed edge object rather than an array.
            # Treat it as an edge only when a destination field is explicit;
            # free-form API labels never become graph edges.
            if any(value.get(field) is not None for field in ("callee", "target", "target_function", "referenced_target")):
                targets.append(value)
            for target in targets:
                if isinstance(target, Mapping):
                    candidate = (
                        target.get("to") or target.get("target_function")
                        or target.get("target_name") or target.get("callee")
                        or target.get("target") or target.get("referenced_target")
                    )
                else:
                    candidate = target
                destination = _resolve_node(candidate)
                if destination is None or destination == source:
                    continue
                adjacency[source].add(destination)
                edge_rows.setdefault((source, destination), []).append(row)
            # Pointer-table tracking can expose the consumer function without
            # putting it in ``call_targets``.  Treat that explicit
            # consumer_function/consumer_entry as a static edge, while still
            # refusing free-form API names or unresolved slots as edges.
            for pointer_field in ("consumer_function", "consumer_entry", "consumer_rva", "target_entry"):
                destination = _resolve_node(value.get(pointer_field))
                if destination is None or destination == source:
                    continue
                adjacency[source].add(destination)
                edge_rows.setdefault((source, destination), []).append(row)

    def _api_rows(path: tuple[str, ...], names: set[str]) -> list[dict[str, object]]:
        selected: list[dict[str, object]] = []
        for node in path:
            for row in buckets[node]:
                if _link_api_names((row,)) & names:
                    selected.append(row)
        return selected

    def _path_rows(path: tuple[str, ...]) -> list[dict[str, object]]:
        selected: list[dict[str, object]] = []
        for index, node in enumerate(path):
            selected.extend(buckets[node])
            if index:
                selected.extend(edge_rows.get((path[index - 1], node), ()))
        # A URL is a global discovery lead, but it may only join an already
        # connected WinHTTP path; it cannot create the path itself.
        deduped: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in selected:
            identity = str(row.get("id"))
            if identity in seen:
                continue
            seen.add(identity)
            deduped.append(row)
        return deduped

    def _prioritize_link_rows(
        mechanism_type: str,
        source: list[dict[str, object]],
        *,
        limit: int = 24,
    ) -> list[dict[str, object]]:
        """Keep mechanism-critical rows inside the bounded action payload.

        A cross-function path can contain hundreds of compiler/context rows.
        The action executor persists at most 24 cited rows, so retaining the
        path's arrival order would routinely drop the resolver or transport
        call that actually closes C1/C2.  Rank only typed semantic signals,
        then restore source order for stable analyst navigation.
        """
        if len(source) <= limit:
            return source
        required_by_type = {
            "DYNAMIC_API_RESOLUTION": {
                "getprocaddress", "ldrgetprocedureaddress", "loadlibrarya",
                "loadlibraryw", "winhttpopen", "winhttpsendrequest",
                "winhttpreceiveresponse",
            },
            "HTTP_DOWNLOAD": {
                "winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse",
            },
            "SHELL_OUTPUT": {
                "createprocessw", "createpipe", "readfile", "peeknamedpipe",
            },
            "ETW_PATCH": {
                "etweventwrite", "virtualprotect", "flushinstructioncache",
            },
        }
        required = required_by_type.get(mechanism_type, set())

        def score(row: Mapping[str, object]) -> int:
            names = _link_api_names((row,))
            text = _link_text(row)
            value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
            result = 100 * len(names & required)
            if mechanism_type == "HTTP_DOWNLOAD" and re.search(r"https?://", text):
                result += 80
            if mechanism_type == "ETW_PATCH" and _has_etw_patch(row):
                result += 120
            if row.get("kind") == "indirect_function_pointer_link":
                result += 90
            if any(value.get(key) for key in ("call_targets", "calls", "edges", "callee")):
                result += 20
            return result

        ranked = sorted(enumerate(source), key=lambda item: (-score(item[1]), item[0]))
        selected_indexes = {index for index, _ in ranked[:limit]}
        return [row for index, row in enumerate(source) if index in selected_indexes]

    def _emit_cross(
        mechanism_type: str,
        kind: str,
        path: tuple[str, ...],
        source: list[dict[str, object]],
        value: dict[str, object],
    ) -> None:
        if not source:
            return
        source = _prioritize_link_rows(mechanism_type, source)
        emit(
            kind,
            mechanism_type,
            source,
            {
                **value,
                "path_functions": list(path),
                "path_roles": [
                    "resolver" if node in resolver_nodes else
                    "consumer" if node in consumer_nodes else
                    "transport" if node in transport_nodes else
                    "patch" if node in patch_nodes else "supporting"
                    for node in path
                ],
                "linkage": "bounded_call_graph_static_facts",
                "static_only": True,
            },
        )

    # Enumerate short simple paths only from nodes carrying a relevant
    # component.  This keeps the correlator deterministic on large binaries.
    resolver_names = {"getprocaddress", "ldrgetprocedureaddress", "loadlibrarya", "loadlibraryw"}
    consumer_names = {
        "winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse",
    }
    transport_names = {"winhttpopen", "winhttpsendrequest", "winhttpreceiveresponse"}
    patch_names = {"etweventwrite", "virtualprotect", "flushinstructioncache"}
    resolver_nodes = {
        node for node in node_keys if _link_api_names(buckets[node]) & resolver_names
    }
    consumer_nodes = {
        node for node in node_keys if _link_api_names(buckets[node]) & consumer_names
    }
    pointer_nodes = {
        node for node in node_keys
        if any(row.get("kind") == "indirect_function_pointer_link" for row in buckets[node])
    }
    consumer_nodes |= pointer_nodes
    transport_nodes = {
        node for node in node_keys if _link_api_names(buckets[node]) & transport_names
    }
    patch_nodes = {
        node for node in node_keys if _link_api_names(buckets[node]) & patch_names
    }
    interesting_nodes = resolver_nodes | consumer_nodes | transport_nodes | patch_nodes
    paths: list[tuple[str, ...]] = []

    def _walk(path: tuple[str, ...]) -> None:
        paths.append(path)
        if len(path) >= 5 or len(paths) >= 1024:
            return
        for destination in sorted(adjacency.get(path[-1], ())):
            if destination in path:
                continue
            _walk((*path, destination))
            if len(paths) >= 1024:
                return

    for start in sorted(interesting_nodes):
        _walk((start,))
        if len(paths) >= 1024:
            break

    seen_paths: set[tuple[str, ...]] = set()
    cross_signatures: set[tuple[str, tuple[str, ...]]] = set()
    for path in paths:
        if path in seen_paths:
            continue
        seen_paths.add(path)
        path_text = " ".join(_link_text(row) for node in path for row in buckets[node])
        path_apis = _link_api_names(row for node in path for row in buckets[node])
        source = _path_rows(path)
        if resolver_nodes.intersection(path) and consumer_nodes.intersection(path):
            resolver = path_apis & resolver_names
            consumers = path_apis & consumer_names
            if pointer_nodes.intersection(path):
                consumers = set(consumers)
                consumers.add("indirect function-pointer consumer")
            component_nodes = {
                node for node in path
                if _link_api_names(buckets[node]) & (resolver_names | consumer_names)
                or node in pointer_nodes
            }
            if len(component_nodes) < 2:
                continue
            component_ids = tuple(sorted(
                str(row.get("id"))
                for node in path
                for row in buckets[node]
                if _link_api_names((row,)) & (resolver_names | consumer_names)
            ))
            signature = ("DYNAMIC_API_RESOLUTION", component_ids)
            if signature in cross_signatures:
                continue
            cross_signatures.add(signature)
            _emit_cross(
                "DYNAMIC_API_RESOLUTION",
                "mechanism_dynamic_api_link",
                path,
                [*source],
                {
                    "apis": sorted(resolver | consumers),
                    "resolver": sorted(resolver),
                    "module": "dynamically loaded module",
                    "entry_point": "resolved function entry point",
                    "function_pointer": "resolved function pointer",
                    "consumer": sorted(consumers),
                    "consumer_apis": sorted(consumers),
                    "relationship": "LoadLibrary/GetProcAddress -> function pointer -> consumer",
                },
            )
        if transport_names.issubset(path_apis) and ("https" in path_text or "http" in path_text):
            component_nodes = {
                node for node in path
                if _link_api_names(buckets[node]) & transport_names
            }
            if len(component_nodes) < 2:
                continue
            url_rows = [
                row for row in [*source, *buckets.get("__global__", [])]
                if "https" in _link_text(row) or "http" in _link_text(row)
            ]
            source = [*source, *[row for row in url_rows if row not in source]]
            component_ids = tuple(sorted(
                str(row.get("id"))
                for node in path
                for row in buckets[node]
                if _link_api_names((row,)) & transport_names
            ))
            signature = ("HTTP_DOWNLOAD", component_ids)
            if signature in cross_signatures:
                continue
            cross_signatures.add(signature)
            _emit_cross(
                "HTTP_DOWNLOAD",
                "mechanism_http_transport_link",
                path,
                source,
                {
                    "apis": sorted(transport_names),
                    "transport": "WinHTTP",
                    "endpoint": next((str(row.get("value", {}).get("text")) for row in url_rows if isinstance(row.get("value"), Mapping)), "https endpoint"),
                    "consumer": "WinHttpSendRequest",
                    "side_effect": "WinHttpReceiveResponse returns response bytes",
                    "response_side_effect": "WinHttpReceiveResponse",
                    "relationship": "https input -> WinHttpSendRequest -> WinHttpReceiveResponse",
                },
            )
        if {"createprocessw", "createpipe"}.issubset(path_apis) and ({"readfile", "peeknamedpipe"} & path_apis):
            component_nodes = {
                node for node in path
                if _link_api_names(buckets[node]) & {"createprocessw", "createpipe", "readfile", "peeknamedpipe"}
            }
            if len(component_nodes) < 2:
                continue
            component_ids = tuple(sorted(
                str(row.get("id"))
                for node in path
                for row in buckets[node]
                if _link_api_names((row,)) & {"createprocessw", "createpipe", "readfile", "peeknamedpipe"}
            ))
            signature = ("SHELL_OUTPUT", component_ids)
            if signature in cross_signatures:
                continue
            cross_signatures.add(signature)
            _emit_cross(
                "SHELL_OUTPUT",
                "mechanism_shell_output_link",
                path,
                source,
                {
                    "apis": sorted(path_apis & consumer_names),
                    "input": "shell command or child-process standard stream",
                    "shell": "child process command channel",
                    "consumer": "pipe",
                    "side_effect": "output capture",
                    "output_capture": "PeekNamedPipe/ReadFile drains child output",
                    "relationship": "CreateProcess -> CreatePipe -> PeekNamedPipe/ReadFile",
                },
            )
        if {"etweventwrite", "virtualprotect", "flushinstructioncache"}.issubset(path_apis):
            component_nodes = {
                node for node in path
                if _link_api_names(buckets[node]) & patch_names
            }
            if len(component_nodes) < 2:
                continue
            patch_rows = [row for row in source if _has_etw_patch(row)]
            if patch_rows:
                component_ids = tuple(sorted(
                    str(row.get("id"))
                    for node in path
                    for row in buckets[node]
                    if _link_api_names((row,)) & patch_names
                    or _has_etw_patch(row)
                ))
                signature = ("ETW_PATCH", component_ids)
                if signature in cross_signatures:
                    continue
                cross_signatures.add(signature)
                _emit_cross(
                    "ETW_PATCH",
                    "mechanism_etw_patch_link",
                    path,
                    source,
                    {
                        "entry": "EtwEventWrite",
                        "condition": "VirtualProtect changes target protection",
                        "patch_bytes": "33 C0 C3",
                        "side_effect": "FlushInstructionCache commits the patch",
                        "flush": "FlushInstructionCache",
                        "relationship": "EtwEventWrite -> VirtualProtect -> 33 C0 C3 -> FlushInstructionCache",
                    },
                )
    return results


class ActionType(str, Enum):
    GET_FUNCTION = "GET_FUNCTION"
    GET_CALLERS = "GET_CALLERS"
    GET_CALLEES = "GET_CALLEES"
    GET_XREFS_TO = "GET_XREFS_TO"
    GET_XREFS_FROM = "GET_XREFS_FROM"
    GET_STRINGS_REFERENCED = "GET_STRINGS_REFERENCED"
    GET_DATA_REFERENCES = "GET_DATA_REFERENCES"
    READ_BYTES = "READ_BYTES"
    GET_DECOMPILE = "GET_DECOMPILE"
    GET_PCODE_SLICE = "GET_PCODE_SLICE"
    GET_CFG_SLICE = "GET_CFG_SLICE"
    TRACE_API_ARGUMENT = "TRACE_API_ARGUMENT"
    TRACE_RETURN_VALUE = "TRACE_RETURN_VALUE"
    TRACE_GLOBAL_USAGE = "TRACE_GLOBAL_USAGE"
    CONTROLLED_EMULATE = "CONTROLLED_EMULATE"
    DECODE_CANDIDATE = "DECODE_CANDIDATE"
    EVALUATE_CONSTANT = "EVALUATE_CONSTANT"
    COMPARE_FUNCTION = "COMPARE_FUNCTION"


@dataclass(frozen=True)
class ActionDefinition:
    action_type: ActionType
    description: str
    sample_execution: bool = False
    network_access: bool = False
    max_attempts: int = 1
    cost_units: int = 1
    selector_keys: tuple[str, ...] = CATALOG_SELECTOR_KEYS


@dataclass(frozen=True)
class ActionSpec:
    id: str
    action_type: ActionType
    thread_id: str
    hypothesis_id: str
    artifact_id: str
    priority: int = 50
    reason: str = ""
    parameters: Mapping[str, object] = field(default_factory=dict)
    target_selector: Mapping[str, str | int] = field(default_factory=dict)
    expected_evidence_kinds: tuple[str, ...] = ()
    success_condition: str = "new_targeted_evidence"
    failure_interpretation: FailureInterpretation = FailureInterpretation.UNKNOWN
    cost_units: int | None = None
    depends_on: tuple[str, ...] = ()
    # Evidence cited by a model when it proposes this action.  The service
    # validates these IDs and the executor uses them as the causal input set;
    # selector and catalog validation remain authoritative as well.
    source_evidence_ids: tuple[str, ...] = ()
    # Planner correlation is attached by the service boundary and is used only
    # to attribute executor output to the immutable planner turn.
    planner_turn_id: str | None = None
    # Service-derived model control metadata.  It is persisted for audit only;
    # executors never treat it as an authorization input.
    provenance: Mapping[str, object] = field(default_factory=dict)
    # Plan-first rationale carried into the durable action parameters by the
    # service.  It is never an authorization input.
    plan: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Keep legacy deterministic callers source-compatible while making the
        # selector explicit on the immutable action contract.  Model actions
        # are normalized at the service boundary before construction.
        parameters = dict(self.parameters)
        raw_selector = dict(self.target_selector)
        if raw_selector:
            selector = normalize_target_selector(raw_selector)
            if parameters:
                aliased: dict[str, object] = {}
                for key, value in parameters.items():
                    mapped = SELECTOR_ALIASES.get(str(key), str(key))
                    aliased[mapped] = value
                parameters = aliased
            else:
                parameters = dict(selector)
        else:
            selector = normalize_target_selector(parameters)
            parameters = dict(selector)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "target_selector", selector)

    @property
    def dedupe_key(self) -> str:
        scope = action_scope_from_plan(self.plan)
        return canonical_action_key(
            self.action_type.value,
            {
                "target_selector": dict(self.target_selector),
                **({"action_scope": scope} if scope else {}),
            },
        )


@dataclass(frozen=True)
class ActionSuggestion:
    """A Playbook proposal before catalog validation and queue admission."""

    action_type: ActionType
    priority: int
    reason: str
    parameters: Mapping[str, object] = field(default_factory=dict)
    expected_evidence_kinds: tuple[str, ...] = ()
    success_condition: str = "new_targeted_evidence"
    failure_interpretation: FailureInterpretation = FailureInterpretation.UNKNOWN
    # The bounded static observations that selected this target.  Propagating
    # them into ActionSpec gives the executor a concrete investigation anchor
    # instead of a task-wide mechanism label.
    source_evidence_ids: tuple[str, ...] = ()
    # Plan-first metadata inspired by evidence-driven reverse engineering
    # workflows.  It is explanatory/auditable only; catalog validation and
    # target selectors remain the authorization surface.
    plan: Mapping[str, object] = field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        scope = action_scope_from_plan(self.plan)
        return canonical_action_key(
            self.action_type.value,
            {
                **dict(self.parameters),
                **({"action_scope": scope} if scope else {}),
            },
        )


def action_scope_from_plan(plan: Mapping[str, object] | None) -> str:
    """Extract a stable mechanism dimension from non-authoritative plan data.

    The selector remains the only executor authorization input.  This value is
    used solely for queue de-duplication so independent mechanism questions do
    not suppress one another when they share a function/RVA target.
    """
    if not isinstance(plan, Mapping):
        return ""
    for key in ("action_scope", "mechanism_type", "mechanism", "playbook_id"):
        value = plan.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip().casefold()
    contract = plan.get("deep_investigation_contract")
    if isinstance(contract, Mapping):
        category = contract.get("category")
        if isinstance(category, (str, int)) and str(category).strip():
            return str(category).strip().casefold()
    focus = plan.get("analysis_focus")
    if isinstance(focus, (list, tuple)):
        for value in focus:
            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip().casefold()
    return ""


def investigation_method_id(
    action_type: ActionType | str,
    selector: Mapping[str, object] | None = None,
    plan: Mapping[str, object] | None = None,
) -> str:
    """Return a stable semantic method identity that ignores reason text.

    Scope/playbook labels and natural-language ``why`` strings are not part of
    the identity.  A rewritten GET_CALLEES against the same selector is the
    same method; the next attempt must change action family or selector.
    """
    try:
        action_name = ActionType(action_type).value
    except ValueError:
        action_name = str(action_type).upper()
    del plan
    normalized = normalize_target_selector(selector)
    payload = json.dumps(
        {"action_type": action_name, "target_selector": normalized},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"{action_name}:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def investigation_scheduled_keys(
    action_type: ActionType | str,
    selector: Mapping[str, object] | None = None,
    plan: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return every planner/loop key that should suppress one durable attempt.

    ``ActionSuggestion`` hashes flattened selectors; ``ActionSpec`` wraps them
    under ``target_selector``.  After NO_NEW_EVIDENCE, a later cluster that
    only changes mechanism scope or reason text must still hit this set.
    """
    try:
        action_name = ActionType(action_type).value
    except ValueError:
        action_name = str(action_type).upper()
    normalized = normalize_target_selector(selector)
    scope = action_scope_from_plan(plan)
    payloads: list[dict[str, object]] = [
        {"target_selector": dict(normalized)},
        dict(normalized),
    ]
    if scope:
        payloads.append({"target_selector": dict(normalized), "action_scope": scope})
        payloads.append({**dict(normalized), "action_scope": scope})
    return tuple(
        dict.fromkeys(canonical_action_key(action_name, payload) for payload in payloads)
    )


def investigation_is_scheduled(
    action_type: ActionType | str,
    selector: Mapping[str, object] | None,
    plan: Mapping[str, object] | None,
    scheduled: set[str],
) -> bool:
    """True when any semantic key for this method is already on the frontier."""
    if not scheduled:
        return False
    return any(key in scheduled for key in investigation_scheduled_keys(action_type, selector, plan))


def investigation_reserve_scheduled(
    scheduled: set[str],
    action_type: ActionType | str,
    selector: Mapping[str, object] | None,
    plan: Mapping[str, object] | None = None,
    extra_key: str | None = None,
) -> None:
    """Record every semantic key that should suppress a later same-method retry."""
    scheduled.update(investigation_scheduled_keys(action_type, selector, plan))
    if extra_key:
        scheduled.add(extra_key)


# How many frontier rows participate in the semantic hash.  Named because the
# fingerprint's cost profile depends on it: the previous implementation sorted ALL
# rows to choose these, which is what made the investigation loop burn minutes of
# CPU per round.
_FRONTIER_CAP = 512


def _frontier_sort_key(value: object) -> str:
    """The canonical sort key of one normalized frontier row (the digest contract).

    Byte-identical to the key this function has always used; extracted so the capped
    selection below can pass it as a callable rather than a lambda.
    """
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)


def investigation_frontier_fingerprint(rows: Iterable[Mapping[str, object]] | object) -> str:
    """Hash the semantic evidence frontier, excluding provenance IDs.

    Measured note.  A live stack of a stalled investigation loop parked in this
    function, so it was rewritten to sort on a fixed-size digest instead of the full
    canonical JSON.  That rewrite was **reverted**: measured on a realistic 39 MB
    frontier (38,400 rows including 333 kB instruction-window payloads) it was 1.6x
    SLOWER (0.406 s vs 0.256 s), because the per-row `blake2b` costs more than the
    key comparisons it removes - and it also changed the hash past the 512-row cap.
    The original shape is kept.  Do not "optimise" this again without measuring it
    on a payload of this size.

    Second measured note (kept, unlike the first - and the numbers are why).

    `sorted(..., key=...)` computes a key for EVERY row, and every key is a full canonical
    JSON string.  On task ``de738f12`` (39,084 rows) that cost 1.630 s, while the sort itself
    cost 0.028 s and the 512-row head cost 0.848 s.  The first 2,000 rows alone account for
    only 0.337 s of it: the cost is concentrated in a few enormous payloads, the largest an
    83.8 MB ``abstract_execution_trace`` (65,536 steps) whose key is ~1.3 s by itself - and
    that row is never in the head, because its key is far larger than the 512th smallest.

    So the fix is not a cheaper key but FEWER keys: `heapq.nsmallest` with a key callable
    consults keys lazily and retains only the best `_FRONTIER_CAP`, so a row whose key cannot
    beat the current worst is discarded after the comparison that rejected it and is never
    serialized.  The result is the same 512 rows in the same order as a full stable sort by
    the same key, so the digest is byte-identical:
    `test_fingerprint_matches_the_oracle` still pins it against the oracle at 1, 7, CAP-1,
    CAP, CAP+1 and 2,000 rows.
    """
    if isinstance(rows, Mapping):
        materialized = [rows]
    elif isinstance(rows, (list, tuple, set, frozenset)):
        materialized = list(rows)
    else:
        materialized = []
    normalized: list[dict[str, object]] = []
    for row in materialized:
        if not isinstance(row, Mapping):
            continue
        normalized.append(
            {
                "kind": row.get("kind"),
                "nature": row.get("nature"),
                "value": row.get("value"),
                "anchor": row.get("anchor"),
            }
        )
    if len(normalized) <= _FRONTIER_CAP:
        # Every row is in the head, but the head is still the rows in KEY order - returning
        # `normalized` here would hash the caller's order instead, which is a different
        # digest (and would make the result order-dependent).
        head = sorted(normalized, key=_frontier_sort_key)
    else:
        head = heapq.nsmallest(_FRONTIER_CAP, normalized, key=_frontier_sort_key)
    payload = json.dumps(
        head,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def completed_investigation_methods(
    actions: Iterable[object],
    evidence: Iterable[object] | None = None,
) -> list[str]:
    """Return method names that actually completed.

    A CONTROLLED_EMULATE that only emitted a worker placeholder is not attempted.
    Isolated emulation remains the next method, not STATIC_BOUNDARY.
    """
    real_emulation = any(is_real_simulation_row(row) for row in evidence or ())
    names: list[str] = []
    for item in actions:
        raw_type = getattr(item, "action_type", None)
        name = str(getattr(raw_type, "value", raw_type) or "").strip()
        if not name:
            continue
        if name == ActionType.CONTROLLED_EMULATE.value and not real_emulation:
            continue
        names.append(name)
    return names


def investigation_next_method(
    action_type: ActionType | str,
    attempted: Iterable[str] | None = None,
) -> str:
    """Return the next action family after a no-gain or failed method.

    STATIC_BOUNDARY is honest only after a real CONTROLLED_EMULATE, not a
    DEFERRED_TO_WORKER placeholder.
    """
    try:
        current = ActionType(action_type)
    except ValueError:
        return "STATIC_BOUNDARY"
    attempted_names = {
        str(item).split(":", 1)[0]
        for item in (attempted or ())
        if str(item).strip()
    }
    alternates = {
        ActionType.GET_CALLEES: (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE),
        ActionType.GET_FUNCTION: (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE),
        ActionType.GET_CALLERS: (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE),
        ActionType.GET_DECOMPILE: (ActionType.CONTROLLED_EMULATE,),
        ActionType.GET_PCODE_SLICE: (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE),
        ActionType.GET_DATA_REFERENCES: (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE),
    }
    for candidate in alternates.get(current, (ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE)):
        if candidate.value not in attempted_names:
            return candidate.value
    if ActionType.CONTROLLED_EMULATE.value not in attempted_names:
        return ActionType.CONTROLLED_EMULATE.value
    return "STATIC_BOUNDARY"


_CATALOG_RECOVERY_METHODS = frozenset(
    {
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.TRACE_RETURN_VALUE.value,
        ActionType.TRACE_GLOBAL_USAGE.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.GET_PCODE_SLICE.value,
        ActionType.GET_DATA_REFERENCES.value,
        ActionType.GET_CALLEES.value,
        ActionType.GET_CFG_SLICE.value,
        ActionType.READ_BYTES.value,
        ActionType.DECODE_CANDIDATE.value,
        ActionType.EVALUATE_CONSTANT.value,
        ActionType.CONTROLLED_EMULATE.value,
    }
)

_MISSING_FIELD_ACTIONS: dict[str, tuple[str, ...]] = {
    "cipher/data": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.READ_BYTES.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "key": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DATA_REFERENCES.value,
        ActionType.READ_BYTES.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "consumer": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_CALLEES.value,
        ActionType.TRACE_RETURN_VALUE.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "plaintext": (
        ActionType.DECODE_CANDIDATE.value,
        ActionType.READ_BYTES.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "algorithm": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "start_routine": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.GET_CALLEES.value,
        ActionType.READ_BYTES.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    "creation_flags": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.EVALUATE_CONSTANT.value,
        ActionType.GET_DECOMPILE.value,
    ),
    # ADR-0035: the decode consumer join is an object-alias relation. Recovering
    # it needs the argument trace, not another callee listing.
    "join": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.READ_BYTES.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
    # 父进程身份 needs an in-image enumeration/name-use chain (Process32*), so the
    # argument trace and the callee walk both stay charged.
    "parent identity": (
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_CALLEES.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.CONTROLLED_EMULATE.value,
    ),
}

# Verifier gaps are free text: they reach here as "unknown(consumer)" or with
# underscores/spacing differences. Normalize before the table lookup so a gap
# name never silently yields zero recovery actions (which would let persist HOW
# mark a mineable thread READY).
_GAP_KEY_ALIASES: dict[str, str] = {
    "parent_identity": "parent identity",
    "parent": "parent identity",
    "ppid": "parent identity",
    "parent process identity": "parent identity",
    "consumer_join": "join",
    "decoded_output_consumer": "join",
    "output_consumer": "consumer",
}


def _normalize_gap_key(item: object) -> str:
    key = str(item or "").strip().casefold()
    wrapped = re.fullmatch(r"unknown\s*\(\s*(.+?)\s*\)", key)
    if wrapped:
        key = wrapped.group(1).strip()
    return _GAP_KEY_ALIASES.get(key, key)


def _attempted_recovery_names(
    attempted: Iterable[str] | None,
    evidence: Iterable[object] | None,
) -> set[str]:
    names = {
        str(item).split(":", 1)[0].upper()
        for item in (attempted or ())
        if str(item).strip()
    }
    if evidence is None:
        return names
    real = {
        str(item).upper()
        for item in completed_investigation_methods(
            (SimpleNamespace(action_type=name) for name in names),
            evidence,
        )
    }
    if ActionType.CONTROLLED_EMULATE.value in names and ActionType.CONTROLLED_EMULATE.value not in real:
        names.discard(ActionType.CONTROLLED_EMULATE.value)
    return names


def how_timebox_disposition(
    next_method: str,
    *,
    attempted: Iterable[str] | None = None,
    evidence: Iterable[object] | None = None,
) -> tuple[str, str]:
    """Decide whether HOW TIMEBOX parks work or stamps an honest static boundary.

    Catalog tools, including CONTROLLED_EMULATE, stay DEFERRED. STATIC_BOUNDARY
    is honest only after a real isolated-emulation result, not a worker ticket.
    """
    method = str(next_method or "").strip().upper()
    completed = _attempted_recovery_names(attempted, evidence)
    if not method:
        method = (
            ActionType.CONTROLLED_EMULATE.value
            if ActionType.CONTROLLED_EMULATE.value not in completed
            else "STATIC_BOUNDARY"
        )
    if method in _CATALOG_RECOVERY_METHODS:
        return ("defer", method)
    if method == "STATIC_BOUNDARY":
        if ActionType.CONTROLLED_EMULATE.value not in completed:
            return ("defer", ActionType.CONTROLLED_EMULATE.value)
        return ("terminate", "STATIC_BOUNDARY")
    return ("defer", method)


def has_typed_process_execution_call(evidence: Iterable[Mapping[str, object]] | None) -> bool:
    """True only when a CreateProcess-family call/trace row is present."""
    return any(
        _typed_call_api(row) in _PROCESS_EXECUTION_APIS
        for row in (evidence or ())
        if isinstance(row, Mapping)
    )


_PROCESS_SEED_TERMS = ("createprocess", "shellexecute", "winexec")
_DYNAMIC_API_SEED_TERMS = (
    "getprocaddress",
    "loadlibrary",
    "ldrgetprocedureaddress",
    "ldrloaddll",
)
_HTTP_TRANSPORT_SEED_TERMS = (
    "winhttpsendrequest",
    "winhttpreceiveresponse",
    "winhttpopenrequest",
    "winhttpconnect",
    "winhttpopen",
    "internetopenurl",
    "httpsendrequest",
    "urldownloadtofile",
)


def _evidence_text_blob(row: Mapping[str, object]) -> str:
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    return " ".join(str(item) for item in (row.get("kind"), value, row.get("anchor"))).casefold()


def _process_seed_has_recoverable_target(
    evidence: Iterable[Mapping[str, object]] | None,
) -> bool:
    """True when a function-local CreateProcess lead can still be traced."""
    for row in evidence or ():
        if not isinstance(row, Mapping):
            continue
        kind = str(row.get("kind") or "").casefold()
        if kind not in {
            "function_context",
            "function",
            "function_instruction_window",
            "function_call",
        }:
            continue
        blob = _evidence_text_blob(row)
        if any(term in blob for term in _PROCESS_SEED_TERMS):
            return True
    return False


def _has_named_resolved_api(evidence: Iterable[Mapping[str, object]] | None) -> bool:
    for row in evidence or ():
        if not isinstance(row, Mapping):
            continue
        if str(row.get("kind") or "").casefold() != "resolved_api":
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if str(value.get("api_name") or value.get("api_identity") or "").strip():
            return True
    return False


def _dynamic_api_seed_has_recoverable_target(
    evidence: Iterable[Mapping[str, object]] | None,
) -> bool:
    for row in evidence or ():
        if not isinstance(row, Mapping):
            continue
        api = _typed_call_api(row)
        if any(term in api for term in _DYNAMIC_API_SEED_TERMS):
            return True
        blob = _evidence_text_blob(row)
        if any(term in blob for term in _DYNAMIC_API_SEED_TERMS):
            return True
    return False


def recovery_actions_for_gap(
    mechanism_type: str,
    missing: Iterable[str] | None = None,
    *,
    attempted: Iterable[str] | None = None,
    evidence: Iterable[Mapping[str, object]] | None = None,
) -> tuple[str, ...]:
    """Map verifier gaps to catalog actions that have not yet been completed."""
    mech = str(mechanism_type or "").upper()
    attempted_names = _attempted_recovery_names(attempted, evidence)
    ordered: list[str] = []

    def add(action: str) -> None:
        name = str(action or "").upper()
        if name and name not in attempted_names and name not in ordered:
            ordered.append(name)

    if mech in {"PROCESS_EXECUTION", "PROCESS_CREATION"}:
        if not has_typed_process_execution_call(evidence):
            if _process_seed_has_recoverable_target(evidence):
                for action in (
                    ActionType.TRACE_API_ARGUMENT.value,
                    ActionType.GET_PCODE_SLICE.value,
                    ActionType.GET_DATA_REFERENCES.value,
                    ActionType.GET_CFG_SLICE.value,
                    ActionType.GET_DECOMPILE.value,
                ):
                    add(action)
            return tuple(ordered)
    for missing_item in missing or ():
        key = _normalize_gap_key(missing_item)
        for action in _MISSING_FIELD_ACTIONS.get(key, ()):
            add(action)
    if mech == "DYNAMIC_API_RESOLUTION" and not _has_named_resolved_api(evidence):
        if _dynamic_api_seed_has_recoverable_target(evidence):
            for action in (
                ActionType.GET_XREFS_TO.value,
                ActionType.GET_PCODE_SLICE.value,
                ActionType.TRACE_RETURN_VALUE.value,
                ActionType.GET_DECOMPILE.value,
            ):
                add(action)
    if mech == "DECODE_CONFIG" and _has_cryptoapi_decode_evidence(evidence or ()):
        for action in (
            ActionType.TRACE_API_ARGUMENT.value,
            ActionType.GET_DECOMPILE.value,
            ActionType.READ_BYTES.value,
            ActionType.CONTROLLED_EMULATE.value,
        ):
            add(action)
    if mech == "HTTP_DOWNLOAD":
        if any(
            any(term in (_typed_call_api(row) + _evidence_text_blob(row)) for term in _HTTP_TRANSPORT_SEED_TERMS)
            for row in (evidence or ())
            if isinstance(row, Mapping)
            and str(row.get("kind") or "").casefold()
            in {"function_call", "api_argument_trace", "function_context", "import_symbol"}
        ):
            for action in (
                ActionType.TRACE_API_ARGUMENT.value,
                ActionType.TRACE_RETURN_VALUE.value,
                ActionType.GET_STRINGS_REFERENCED.value,
                ActionType.GET_DECOMPILE.value,
            ):
                add(action)
    return tuple(ordered)


def apply_emulation_reverification(
    mechanisms: Iterable[Mapping[str, object]],
    evidence: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Re-run specialists after a real simulation_result lands.

    Placeholder DEFERRED_TO_WORKER rows do not change mechanism status.
    """
    evidence_rows = [row for row in evidence if isinstance(row, Mapping)]
    has_real_emu = any(is_real_simulation_row(row) for row in evidence_rows)
    updated: list[dict[str, object]] = []
    for item in mechanisms:
        if not isinstance(item, Mapping):
            continue
        clone = dict(item)
        if not has_real_emu:
            updated.append(clone)
            continue
        mech_type = str(
            clone.get("mechanism_type") or clone.get("type") or clone.get("dimension") or ""
        ).upper().removeprefix("TRACE_")
        if mech_type in {"", "GENERIC_MECHANISM_INVESTIGATION", "MECHANISM_CANDIDATE"}:
            updated.append(clone)
            continue
        verification = verify_mechanism(mech_type, evidence_rows)
        clone["verifier"] = verification.as_dict()
        if verification.status == "NOT_APPLICABLE":
            clone["status"] = "NOT_APPLICABLE"
        elif verification.accepted:
            clone["status"] = "VERIFIED"
        else:
            current = str(clone.get("status") or "").upper()
            if current not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
                clone["status"] = verification.status or "CANDIDATE"
            actions = recovery_actions_for_gap(
                mech_type,
                verification.missing,
                evidence=evidence_rows,
            )
            clone["next_method"] = actions[0] if actions else "STATIC_BOUNDARY"
        updated.append(clone)
    return updated


_CALL_GRAPH_FAMILY = frozenset(
    {
        ActionType.GET_CALLEES,
        ActionType.GET_FUNCTION,
        ActionType.GET_CALLERS,
    }
)


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
    """lpStartAddress/callback for same-process thread APIs, else None."""
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


def recovered_thread_parameter(value: Mapping[str, object]) -> str | None:
    """lpParameter/work context for a recovered thread start, when present."""
    api = _thread_api_from_value(value)
    if api not in _THREAD_START_ARG_INDEX:
        return None
    index = 3 if api in {"createthread", "createthreadex"} else _THREAD_START_ARG_INDEX[api] + 1
    return recovered_thread_argument(
        value,
        index=index,
        names=("lpparameter", "parameter", "context", "dwdata"),
        require_code_address=False,
    )


@dataclass(frozen=True)
class DeepMiningTarget:
    """One high-value static target that deserves a bounded investigation."""

    selector: Mapping[str, str | int]
    category: str
    priority: int
    evidence_ids: tuple[str, ...]
    question: str
    hypothesis: str
    alternatives: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    next_static_actions: tuple[str, ...] = ()
    plan_id: str = ""


class DeepMiningPlanner:
    """Build a deterministic, evidence-first deep-mining frontier.

    The planner borrows three useful ideas from Kunglao: plan before acting,
    assign one worker/action to one concrete question, and re-open planning
    only when the evidence frontier changes.  It remains static-only and
    produces catalog actions rather than executing anything itself.
    """

    _HIGH_VALUE_APIS = {
        "getprocaddress", "ldrgetprocedureaddress", "loadlibrarya", "loadlibraryw",
        "loadlibraryexa", "loadlibraryexw", "ldrloaddll", "freelibrary",
        "createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "winexec",
        "winhttpopen", "winhttpopenrequest", "winhttpconnect", "winhttpsendrequest",
        "winhttpreceiveresponse", "winhttpreaddata", "internetopenurla", "internetopenurlw",
        "urldownloadtofilea", "urldownloadtofilew", "connect", "send", "recv",
        "getaddrinfo", "dnsquerya", "dnsqueryw", "virtualalloc", "virtualallocex",
        "virtualprotect", "virtualprotectex", "writeprocessmemory",
        "createremotethread", "openprocess", "updateprocthreadattribute",
        "queueuserapc", "setthreadcontext", "ntmapviewofsection",
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
        "createservicea", "createservicew", "startservicea", "startservicew",
        "registertaskdefinition", "createfilea", "createfilew", "writefile", "readfile",
        "deletefilea", "deletefilew", "movefileexa", "movefileexw", "createpipe",
        "peeknamedpipe", "etweventwrite", "amsiscanbuffer", "isdebuggerpresent",
        "checkremotedebuggerpresent", "ntqueryinformationprocess", "cryptdecrypt",
        "cryptunprotectdata", "openprocesstoken", "adjusttokenprivileges", "clipboard",
        "createthread", "createthreadex", "tpallocwork", "submitthreadpoolwork",
        "tlssetvalue", "addvectoredexceptionhandler", "setwaitabletimer",
        "createtimerqueuetimer",
    }
    _DECODE_TERMS = ("xor", "decode", "decrypt", "encoded", "base64", "rc4", "cipher")
    _DECODE_MATERIAL_KINDS = frozenset(
        {
            "mechanism_decode_window",
            "encoded_blob",
            "crypto_indicator",
            "mechanism_decryption",
            # Resource-backed transforms are static decode candidates too.
            # They are admitted only as bounded evidence leads; the executor
            # still requires a concrete byte window before replaying bytes.
            "mechanism_resource_payload",
            "mechanism_resource_extraction",
            "mechanism_decompression",
            "mechanism_decompression_format",
            "mechanism_decode",
            "mechanism_integrity_check",
        }
    )
    # Resource-backed payloads are a distinct investigation surface.  The
    # parser can identify a resource directory (and often a high-entropy
    # RT_RCDATA entry) without proving what consumes it.  Keep that lead in
    # the same bounded frontier as scripts/carriers so it cannot disappear
    # after the initial extraction pass.
    _RESOURCE_KINDS = frozenset(
        {
            "resource_inventory",
            "pe_resource",
            "mechanism_resource_payload",
            "mechanism_resource_extraction",
            "mechanism_decompression",
            "mechanism_decompression_format",
            "pe_resource_directory",
        }
    )
    _STAGING_KINDS = frozenset(
        {
            "embedded_artifact",
            "embedded_object",
            "archive_member",
            "document_embedded_object",
            "document_embedded_file",
            "decoded_artifact",
        }
    )
    _NETWORK_TERMS = ("winhttp", "wininet", "socket", "connect", "http://", "https://", "url")
    _PROCESS_TERMS = ("createprocess", "shellexecute", "winexec", "openprocess")
    _THREAD_TERMS = (
        "createthread", "createthreadex", "tpallocwork", "submitthreadpoolwork",
        "tlssetvalue", "addvectoredexception", "setwaitabletimer", "createtimerqueuetimer",
        "tls_callback", "tls callback",
    )
    _THREAD_APIS = {
        "createthread", "createthreadex", "tpallocwork", "submitthreadpoolwork",
        "createthreadpoolwait", "createthreadpooltimer", "tlssetvalue",
        "addvectoredexceptionhandler", "setwaitabletimer", "createtimerqueuetimer",
        "tls_callback",
    }
    _PERSISTENCE_TERMS = (
        "regsetvalue", "regcreatekey", "runonce", "\\run", "createservice",
        "startservice", "registertask", "schtasks", "task scheduler",
    )
    _INJECTION_TERMS = (
        "writeprocessmemory", "createremotethread", "setthreadcontext",
        "ntmapviewofsection", "virtualallocex",
    )
    _LOADER_TERMS = (
        "getprocaddress", "loadlibrary", "ldrload", "freelibrary", "resolve api",
    )
    _STAGING_TERMS = (
        "createfile", "writefile", "readfile", "deletefile", "movefile", "urldownload",
    )
    _SHELL_TERMS = (
        "createpipe", "peeknamedpipe", "cmd.exe", "powershell", "winexec", "shellexecute",
    )
    _ANTI_ANALYSIS_TERMS = (
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "etweventwrite", "amsiscanbuffer", "virtualquery", "sandbox", "debugger",
    )
    _COLLECTION_TERMS = (
        "openprocesstoken", "adjusttokenprivileges", "clipboard", "credential", "logon",
        "sam", "lsass", "keylog",
    )
    _NOISE_TERMS = ("crt", "std::", "__scrt", "seh_", "guard_check", "memset", "memcpy")
    _FUNCTION_SCOPED_KINDS = frozenset(
        {
            "function",
            "xref",
            "cfg_block",
            "data_reference",
            "api_argument_trace",
            "value_flow",
            "tls_callback",
            "tls_metadata",
            "thread_callback",
            "global_usage",
        }
    )

    @staticmethod
    def _row_value(row: Mapping[str, object]) -> Mapping[str, object]:
        value = row.get("value")
        return value if isinstance(value, Mapping) else {}

    @classmethod
    def _function_key(cls, row: Mapping[str, object]) -> str:
        value = cls._row_value(row)
        anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
        kind = str(row.get("kind", ""))
        # A PE header's AddressOfEntryPoint is a navigation lead, not proof of
        # a recovered function. Resolve it to function-scoped Ghidra Evidence
        # before allowing function-level actions to consume budget.
        function_scoped = (
            kind in cls._FUNCTION_SCOPED_KINDS
            or kind.startswith("function_")
            or bool(anchor.get("function_entry"))
            or bool(value.get("function_entry"))
        )
        if not function_scoped:
            return ""
        for item in (
            anchor.get("function_entry"), anchor.get("entry"), anchor.get("rva"),
            value.get("function_entry"), value.get("entry"), value.get("entry_rva"),
        ):
            if isinstance(item, (str, int)) and str(item).strip():
                return str(item).strip()
        # Investigation-derived Xrefs carry the enclosing function as
        # provenance rather than copying it into their semantic payload. That
        # provenance is still a concrete, artifact-local static anchor. Use
        # only function-scoped source anchors; a PE header or file offset must
        # never become a pseudo-function target.
        source_anchors = anchor.get("source_anchors")
        if isinstance(source_anchors, (list, tuple)):
            for source_anchor in source_anchors:
                if not isinstance(source_anchor, Mapping):
                    continue
                source_type = str(source_anchor.get("type", "")).casefold()
                if source_type not in {
                    "function",
                    "function_context",
                    "function_entry",
                    "function_instruction_window",
                    "function_call",
                    "cfg_block",
                    "xref",
                }:
                    continue
                for name in ("function_entry", "entry", "rva"):
                    item = source_anchor.get(name)
                    if isinstance(item, (str, int)) and str(item).strip():
                        return str(item).strip()
        return ""

    @classmethod
    def _function_name(cls, rows: Iterable[Mapping[str, object]]) -> str:
        for row in rows:
            value = cls._row_value(row)
            for key in ("name", "function", "entry"):
                item = value.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    return str(item).strip()
        return ""

    @classmethod
    def _tls_callback_starts(
        cls,
        rows: Iterable[Mapping[str, object]],
    ) -> tuple[tuple[str, Mapping[str, object], str], ...]:
        """Collect TLS/callback entries from typed Evidence or PE TLS metadata."""
        found: list[tuple[str, Mapping[str, object], str]] = []
        seen: set[str] = set()

        def add(start: str | None, row: Mapping[str, object], label: str) -> None:
            if not start or start in seen:
                return
            seen.add(start)
            found.append((start, row, label))

        for row in rows:
            kind = str(row.get("kind", "")).casefold()
            value = cls._row_value(row)
            if kind in {"tls_callback", "tls_metadata", "thread_callback"}:
                add(
                    canonical_code_address(
                        value.get("entry") or value.get("callback") or value.get("address")
                    ),
                    row,
                    "TLS callback",
                )
                continue
            if kind != "pe_structure":
                continue
            callbacks = value.get("tls_callbacks") or ()
            if not isinstance(callbacks, (list, tuple)):
                continue
            for item in callbacks:
                if not isinstance(item, Mapping):
                    continue
                add(
                    canonical_code_address(item.get("entry") or item.get("rva")),
                    row,
                    "TLS callback",
                )
        return tuple(found)

    @classmethod
    def _api_names(cls, row: Mapping[str, object]) -> tuple[str, ...]:
        """Extract every API identity emitted by supported static exporters.

        The deep-mining planner consumes exporter rows directly, while the
        semantic linker uses a broader field vocabulary.  Keeping a second,
        narrower extractor here caused rows containing ``resolved_api``,
        ``referenced_target`` or nested ``symbol`` objects to bypass the
        planner even though the same rows were linkable elsewhere.  Mirror the
        linker vocabulary and retain the raw spelling; normalization happens
        in :meth:`_normalized_api_names`.

        Memoised on the row's nested payload, NOT on the row itself.  ``build_frontier``
        walks the same 39,833-row corpus and calls this once per row in its first loop
        and again inside two per-group comprehensions.  Keying on the row was not
        enough: the planner builds its own ``{"kind": ..., "value": ...}`` dicts, so
        every call was a miss even though the extracted names depend only on ``value``.
        Measured with cProfile on the real corpus: 39,833 calls, 3.4 s of a 4.6 s
        ``build_frontier``, which itself runs once per propose.

        This function runs ~54 ``isinstance``/``str`` checks per call (16 scalar keys
        plus 9 list keys with nested field scans).  The cache is identity-checked and
        holds both objects, so a recycled ``id()`` cannot alias a different payload, and
        it is cleared past a bound so a long-lived process cannot accumulate every row
        it has ever seen.
        """
        if not isinstance(row, Mapping):
            return ()
        raw_value = row.get("value")
        if not isinstance(raw_value, Mapping):
            # Nothing to extract: `_row_value` would hand back a FRESH `{}` for this
            # row, so the memo below could never hit and every call re-ran the 25-key
            # vocabulary over an empty mapping.  Measured: 39,833 calls / 3.4 s of a
            # 4.6 s `build_frontier`, and most real rows (strings, instruction windows,
            # cfg blocks) carry a non-mapping value.
            return ()
        return cls._api_names_for_value(raw_value)

    @classmethod
    def _api_names_for_value(cls, value: Mapping[str, object]) -> tuple[str, ...]:
        """`_api_names` for a payload, memoised on the payload's identity.

        `_api_names_uncached` reads only the row's ``value`` mapping, so caching on that
        object is exact while surviving the planner's freshly-built row dicts.
        """
        key = id(value)
        cached = _API_NAMES_CACHE.get(key)
        if cached is not None and cached[0] is value:
            return cached[1]
        names = cls._api_names_uncached_value(value)
        if len(_API_NAMES_CACHE) >= _API_NAMES_CACHE_LIMIT:
            _API_NAMES_CACHE.clear()
        _API_NAMES_CACHE[key] = (value, names)
        return names

    @classmethod
    def _api_names_uncached(cls, row: Mapping[str, object]) -> tuple[str, ...]:
        return cls._api_names_uncached_value(cls._row_value(row))

    @classmethod
    def _api_names_uncached_value(cls, value: Mapping[str, object]) -> tuple[str, ...]:
        if not value:
            return ()
        candidates: list[str] = []
        scalar_keys = (
            "api", "api_name", "resolved_api", "referenced_target", "callee",
            "name", "target_name", "target_function", "consumer", "transport",
            "resolver", "export_name", "resolved_symbol", "symbol", "target",
            "indicator",
        )
        nested_scalar_keys = ("api", "api_name", "name", "symbol", "target_name", "target_function", "callee", "target")
        for key in scalar_keys:
            item = value.get(key)
            if isinstance(item, Mapping):
                for nested_key in nested_scalar_keys:
                    nested = item.get(nested_key)
                    if isinstance(nested, (str, int)) and str(nested).strip():
                        candidates.append(str(nested).strip())
            elif isinstance(item, (str, int)) and str(item).strip():
                candidates.append(str(item).strip())
        for key in (
            "apis", "functions", "call_targets", "calls", "consumer_apis",
            "consumer_candidates", "resolved_symbols", "references", "callees",
        ):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                nested = (nested,)
            if not isinstance(nested, (list, tuple, set)):
                continue
            for item in nested:
                if isinstance(item, Mapping):
                    for field_name in nested_scalar_keys + ("resolved_api", "resolved_symbol"):
                        field = item.get(field_name)
                        if isinstance(field, (str, int)) and str(field).strip():
                            candidates.append(str(field).strip())
                elif isinstance(item, (str, int)) and str(item).strip():
                    candidates.append(str(item).strip())
        return tuple(dict.fromkeys(item for item in candidates if item))

    @classmethod
    def _has_decode_material(cls, rows: Iterable[Mapping[str, object]]) -> bool:
        """Require a bounded static object or transform before decode replay.

        Capability-like names are useful discovery leads but do not authorize
        a byte replay.  Keeping this guard in the common frontier prevents
        generic deep mining from bypassing the specialist playbook's evidence
        requirement.
        """
        return any(str(row.get("kind", "")) in cls._DECODE_MATERIAL_KINDS for row in rows)

    @staticmethod
    def _normalized_api_names(apis: Iterable[str]) -> set[str]:
        """Normalize DLL-qualified/decompiler API symbols before ranking.

        Ghidra facts, PE imports and derived Xrefs do not use one spelling for
        the same API.  A qualified symbol must retain its function identity;
        otherwise a function that calls ``KERNEL32!CreateProcessW`` silently
        falls into the generic queue instead of receiving argument/data-flow
        investigation.
        """
        return {normalize_api_symbol(api) for api in apis if normalize_api_symbol(api)}

    @staticmethod
    def _deep_coverage_contract(category: str) -> dict[str, object]:
        """Return the bounded evidence facets required for one deep target.

        A function/import can be a legitimate lead without proving a mechanism.
        The contract makes the minimum static work explicit: the loop must
        either inspect every discriminating facet or record a static boundary.
        It is deliberately action-family based, rather than outcome based, so
        an unavailable data-flow fact cannot be mistaken for a negative result.
        """
        semantic_actions = (
            ActionType.TRACE_API_ARGUMENT,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DATA_REFERENCES,
            ActionType.GET_CFG_SLICE,
            ActionType.GET_CALLEES,
            ActionType.GET_DECOMPILE,
            ActionType.READ_BYTES,
            ActionType.CONTROLLED_EMULATE,
        )
        category_actions: dict[str, tuple[ActionType, ...]] = {
            "decode": (
                ActionType.GET_PCODE_SLICE,
                ActionType.GET_DECOMPILE,
                ActionType.GET_DATA_REFERENCES,
                ActionType.READ_BYTES,
                ActionType.DECODE_CANDIDATE,
                ActionType.GET_CALLEES,
                ActionType.CONTROLLED_EMULATE,
            ),
            "resource": (
                ActionType.GET_DATA_REFERENCES,
                ActionType.READ_BYTES,
                ActionType.GET_XREFS_TO,
                ActionType.GET_CALLEES,
                ActionType.DECODE_CANDIDATE,
            ),
            "staging": (
                ActionType.GET_DATA_REFERENCES,
                ActionType.GET_STRINGS_REFERENCED,
                ActionType.GET_XREFS_TO,
                ActionType.GET_CALLEES,
            ),
            "script": (
                ActionType.GET_STRINGS_REFERENCED,
                ActionType.GET_DATA_REFERENCES,
                ActionType.GET_CALLEES,
                ActionType.TRACE_API_ARGUMENT,
            ),
            "carrier": (
                ActionType.GET_STRINGS_REFERENCED,
                ActionType.GET_DATA_REFERENCES,
                ActionType.GET_XREFS_TO,
            ),
            "function": (
                ActionType.GET_DECOMPILE,
                ActionType.GET_PCODE_SLICE,
                ActionType.GET_DATA_REFERENCES,
                ActionType.GET_CFG_SLICE,
                ActionType.GET_CALLEES,
                ActionType.CONTROLLED_EMULATE,
            ),
            "thread": (
                ActionType.TRACE_API_ARGUMENT,
                ActionType.GET_CALLEES,
                ActionType.GET_CFG_SLICE,
                ActionType.GET_DECOMPILE,
                ActionType.READ_BYTES,
                ActionType.CONTROLLED_EMULATE,
            ),
            "thread_start_routine": (
                ActionType.GET_DECOMPILE,
                ActionType.GET_CFG_SLICE,
                ActionType.GET_CALLEES,
                ActionType.GET_PCODE_SLICE,
                ActionType.READ_BYTES,
                ActionType.CONTROLLED_EMULATE,
                ActionType.TRACE_GLOBAL_USAGE,
            ),
            "unpack": (
                ActionType.GET_DECOMPILE,
                ActionType.CONTROLLED_EMULATE,
            ),
            "covert_launch": (
                ActionType.TRACE_API_ARGUMENT,
                ActionType.GET_DECOMPILE,
                ActionType.CONTROLLED_EMULATE,
            ),
            "windows_object": (
                ActionType.TRACE_API_ARGUMENT,
                ActionType.GET_DECOMPILE,
            ),
            "encoding": (
                ActionType.GET_DECOMPILE,
                ActionType.CONTROLLED_EMULATE,
            ),
            "anti_re": (
                ActionType.GET_DECOMPILE,
                ActionType.CONTROLLED_EMULATE,
            ),
            "api": (ActionType.GET_XREFS_TO,),
        }
        actions = category_actions.get(category, semantic_actions)
        evidence_by_action = {
            ActionType.TRACE_API_ARGUMENT.value: ("api_argument_trace",),
            ActionType.GET_PCODE_SLICE.value: ("pcode_slice",),
            ActionType.GET_DATA_REFERENCES.value: ("data_reference", "value_flow"),
            ActionType.GET_CFG_SLICE.value: ("cfg_block", "abstract_execution_trace"),
            ActionType.GET_CALLEES.value: ("function_call",),
            ActionType.GET_DECOMPILE.value: ("abstract_execution_trace",),
            ActionType.GET_STRINGS_REFERENCED.value: ("string_reference",),
            ActionType.GET_XREFS_TO.value: ("xref", "function_call"),
            ActionType.READ_BYTES.value: ("bytes_read", "data_reference"),
            ActionType.CONTROLLED_EMULATE.value: ("simulation_result",),
            ActionType.DECODE_CANDIDATE.value: ("decode_result", "decode_candidate"),
            ActionType.TRACE_GLOBAL_USAGE.value: ("value_flow", "data_reference", "global_usage"),
            ActionType.GET_CALLERS.value: ("function_call",),
            ActionType.TRACE_RETURN_VALUE.value: ("value_flow", "function_call"),
        }
        return {
            "id": f"deep-static-v1:{category}",
            "category": category,
            "required_action_types": [item.value for item in actions],
            "evidence_kinds_by_action": {
                item.value: list(evidence_by_action[item.value]) for item in actions
            },
            "completion_rule": "all_required_facets_attempted_or_static_boundary",
        }

    @classmethod
    def _pma_action_sequence(
        cls,
        target: DeepMiningTarget,
    ) -> list[tuple[ActionType, str, tuple[str, ...]]]:
        """Map a PMA plan item onto the three allowed static next-action families."""
        why_by_type = {
            ActionType.GET_DECOMPILE: (
                "Recover a bounded semantic view for this PMA plan item."
            ),
            ActionType.TRACE_API_ARGUMENT: (
                "Recover typed API arguments (creation flags, start routine, object identity) "
                "for this PMA plan item."
            ),
            ActionType.CONTROLLED_EMULATE: (
                "When static recovery stalls, emulate granted bytes in the isolated worker. "
                "Isolated emulation remains static analysis."
            ),
        }
        expected_by_type = {
            ActionType.GET_DECOMPILE: ("abstract_execution_trace", "function_context"),
            ActionType.TRACE_API_ARGUMENT: ("api_argument_trace", "function_context"),
            ActionType.CONTROLLED_EMULATE: ("simulation_result",),
        }
        actions: list[tuple[ActionType, str, tuple[str, ...]]] = []
        for name in target.next_static_actions:
            try:
                action_type = ActionType(str(name))
            except ValueError:
                continue
            if action_type not in why_by_type:
                continue
            actions.append((action_type, why_by_type[action_type], expected_by_type[action_type]))
        return actions

    method_id = staticmethod(investigation_method_id)
    frontier_fingerprint = staticmethod(investigation_frontier_fingerprint)
    next_method = staticmethod(investigation_next_method)
    scheduled_keys = staticmethod(investigation_scheduled_keys)

    @classmethod
    def _method_plan_fields(
        cls,
        action_type: ActionType,
        selector: Mapping[str, object],
        plan: Mapping[str, object],
    ) -> dict[str, object]:
        """Attach the K01 three-question fields consumed by the service path."""
        next_method = investigation_next_method(action_type)
        return {
            "method_id": investigation_method_id(action_type, selector, plan),
            "method_assumption": (
                f"{action_type.value} on {dict(selector)} should expose "
                "targeted evidence for the current question."
            ),
            "assumption_validity": "untested",
            "next_method": next_method,
            "next_method_action_type": None if next_method == "STATIC_BOUNDARY" else next_method,
            "gain_class": "UNTESTED",
        }

    @classmethod
    def failure_contract(
        cls,
        action: ActionSpec,
        *,
        outcome: str,
        frontier_before: str,
        frontier_after: str,
        existing_method_ids: object = (),
        error_type: str | None = None,
    ) -> dict[str, object]:
        """Build the durable three-question failure record for one attempt."""
        method_id = investigation_method_id(
            action.action_type, action.target_selector, action.plan
        )
        attempted = list(existing_method_ids) if isinstance(existing_method_ids, (list, tuple, set, frozenset)) else []
        attempted.append(method_id)
        next_method = investigation_next_method(
            action.action_type,
            [
                str(item).split(":", 1)[0]
                for item in attempted
                if isinstance(item, str) and item
            ],
        )
        validity = "not_justified" if outcome in {"NO_NEW_EVIDENCE", "EXECUTOR_FAILURE"} else "justified"
        return {
            "attempt_id": action.id,
            "method_id": method_id,
            "method_assumption": (
                str(action.plan.get("method_assumption") or "")
                or (
                    f"{action.action_type.value} on {dict(action.target_selector)} should expose "
                    "targeted evidence for the current question."
                )
            ),
            "assumption_validity": validity,
            "next_method": next_method,
            "next_method_action_type": None if next_method == "STATIC_BOUNDARY" else next_method,
            "frontier_fingerprint_before": frontier_before,
            "frontier_fingerprint_after": frontier_after,
            "outcome": outcome,
            "gain_class": outcome,
            "error_type": error_type,
            "attempted_method_ids": list(dict.fromkeys(str(item) for item in attempted if item))[-16:],
            "requires_alternate": next_method not in {"", "STATIC_BOUNDARY"},
        }

    @classmethod
    def build_frontier(
        cls,
        evidence: Iterable[Mapping[str, object]],
        *,
        max_targets: int | None = 24,
    ) -> tuple[DeepMiningTarget, ...]:
        """Rank function/API targets using observable static signals only.

        ``max_targets`` is a presentation/admission bound, not a discovery
        bound.  Callers that need to page through a previously scheduled
        frontier (the investigation loop) pass ``None`` so targets beyond the
        first page remain discoverable after earlier actions are marked
        scheduled.  Truncating before schedule filtering makes a large binary
        permanently skip every target after the first page.
        """
        rows = [dict(row) for row in evidence if isinstance(row, Mapping) and row.get("id")]
        latch = packer_latch_active(rows)
        suppress_stub = latch and not unpack_completed(rows)
        stub_apis = stub_import_names(rows) if latch else frozenset()
        function_groups: dict[str, list[dict[str, object]]] = {}
        api_rows: dict[str, list[dict[str, object]]] = {}
        for row in rows:
            key = cls._function_key(row)
            if key:
                function_groups.setdefault(key, []).append(row)
            for api in cls._api_names(row):
                normalized = re.sub(r"^[^!]+!", "", api).casefold()
                kind = str(row.get("kind", "")).casefold()
                if latch and normalize_api_symbol(api) in stub_apis:
                    if suppress_stub or kind in {"import_symbol", "pe_structure", "export_symbol"}:
                        continue
                if normalized in cls._HIGH_VALUE_APIS:
                    api_rows.setdefault(api, []).append(row)

        targets: list[DeepMiningTarget] = []
        tls_starts = {entry for entry, _, _ in cls._tls_callback_starts(rows)}
        for key, group in function_groups.items():
            if key in tls_starts:
                # TLS callbacks are OS callback start routines.  A generic
                # function/thread target on the same entry would collide with
                # the dedicated callback contract below.
                continue
            text = " ".join(
                f"{row.get('kind', '')} {cls._row_value(row)}" for row in group
            ).casefold()
            apis = cls._normalized_api_names(
                api for row in group for api in cls._api_names(row)
            )
            if suppress_stub:
                call_apis = cls._normalized_api_names(
                    api
                    for row in group
                    if str(row.get("kind", "")).casefold() in {"function_call", "api_argument_trace"}
                    for api in cls._api_names(row)
                )
                if not (call_apis - stub_apis):
                    # Stub IAT / stub function: unpack is the PMA seed, not payload loader threads.
                    continue
            score = 30
            score += min(30, 10 * len(apis & cls._HIGH_VALUE_APIS))
            score += 12 if any(row.get("kind") in {"function_instruction_window", "function_mechanism"} for row in group) else 0
            score += 8 if any(row.get("kind") in {"function_data_correlation", "data_reference", "xref"} for row in group) else 0
            score -= 16 if any(term in text for term in cls._NOISE_TERMS) and not (apis & cls._HIGH_VALUE_APIS) else 0
            # A single function can carry several independent leads.  Keep
            # one target per mechanism dimension so the recursive investigator
            # asks separate questions and does not let the first matching
            # category hide later decode/network/process/evasion work.
            category_specs: list[tuple[str, str, str, tuple[str, ...]]] = []

            def add_category(
                condition: bool,
                category: str,
                question: str,
                hypothesis: str,
                alternatives: tuple[str, ...],
            ) -> None:
                if condition:
                    category_specs.append((category, question, hypothesis, alternatives))

            add_category(
                any(term in text for term in cls._DECODE_TERMS) and cls._has_decode_material(group),
                "decode",
                "What input, state, formula, output, and consumer form this decode path?",
                "The function transforms a bounded input into a meaningful configuration or payload.",
                ("data validation or checksum", "compiler/runtime noise"),
            )
            add_category(
                any(term in text for term in cls._NETWORK_TERMS)
                or bool(apis & {
                    "winhttpconnect", "winhttpsendrequest", "winhttpreceiveresponse",
                    "winhttpreaddata", "connect", "urldownloadtofilea", "urldownloadtofilew",
                    "getaddrinfo", "dnsquerya", "dnsqueryw",
                }),
                "network",
                "Which endpoint, request arguments, response consumer, and branch form the static transport path?",
                "The function constructs or consumes a network transport path.",
                ("library capability unused by this path", "telemetry or update check"),
            )
            add_category(
                any(term in text for term in cls._PERSISTENCE_TERMS)
                or bool(apis & {
                    "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
                    "createservicea", "createservicew", "startservicea", "startservicew",
                    "registertaskdefinition",
                }),
                "persistence",
                "Which key, task, service, trigger, payload path, condition and cleanup path form this persistence candidate?",
                "The function may establish a statically recoverable persistence mechanism.",
                ("transient configuration", "installer or repair path"),
            )
            add_category(
                any(term in text for term in cls._INJECTION_TERMS)
                or bool(apis & {
                    "writeprocessmemory", "createremotethread", "setthreadcontext",
                    "ntmapviewofsection", "virtualallocex",
                })
                or (
                    "queueuserapc" in apis
                    and bool(apis & {"openprocess", "writeprocessmemory", "virtualallocex", "ntopenprocess"})
                ),
                "injection",
                "Which target process, memory region, bytes, execution primitive and condition form this cross-process candidate?",
                "The function may prepare a statically recoverable cross-process execution or memory-manipulation path.",
                ("debugger or compatibility helper", "incomplete unused capability"),
            )
            add_category(
                bool(apis & cls._THREAD_APIS)
                or (
                    "queueuserapc" in apis
                    and not bool(apis & {"openprocess", "writeprocessmemory", "virtualallocex", "ntopenprocess"})
                ),
                "thread",
                "Which start routine, parameter, shared state, loop and cleanup path form this OS thread or callback?",
                "The function starts or registers a unique in-process thread, APC, TLS, timer, or thread-pool callback.",
                ("ordinary runtime worker", "CRT/thread-pool housekeeping"),
            )
            add_category(
                any(term in text for term in cls._LOADER_TERMS)
                or bool(apis & {
                    "getprocaddress", "ldrgetprocedureaddress", "loadlibrarya", "loadlibraryw",
                    "loadlibraryexa", "loadlibraryexw", "ldrloaddll", "freelibrary",
                }),
                "loader",
                "Which module identity, API identity, resolver result and indirect consumer form this loader or dispatch path?",
                "The function resolves or loads a module/API for a statically recoverable downstream operation.",
                ("ordinary optional dependency", "unused compatibility wrapper"),
            )
            add_category(
                any(term in text for term in cls._SHELL_TERMS)
                or bool(apis & {"createpipe", "peeknamedpipe", "readfile", "writefile"}),
                "shell_or_staging",
                "Which command or file input, pipe/file sink, branch and downstream consumer form this shell or staging path?",
                "The function may stage data or manage child-process input/output through a statically recoverable path.",
                ("benign installer/update helper", "ordinary application I/O"),
            )
            add_category(
                any(term in text for term in cls._ANTI_ANALYSIS_TERMS)
                or bool(apis & {
                    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                    "etweventwrite", "amsiscanbuffer", "virtualquery",
                }),
                "anti_analysis",
                "Which observed environment signal, comparison, branch and protected operation form this anti-analysis candidate?",
                "The function conditionally changes behavior based on a debugger, telemetry, or environment observation.",
                ("legitimate diagnostics", "compatibility or crash-reporting path"),
            )
            add_category(
                any(term in text for term in cls._COLLECTION_TERMS)
                or bool(apis & {"openprocesstoken", "adjusttokenprivileges"}),
                "collection_or_privilege",
                "Which source, access rights, data flow, condition and consumer form this collection or privilege candidate?",
                "The function may inspect sensitive data or alter token privileges through a statically recoverable path.",
                ("ordinary application identity query", "unused administrative helper"),
            )
            add_category(
                any(term in text for term in cls._PROCESS_TERMS)
                or bool(apis & {"createprocessa", "createprocessw", "openprocess"}),
                "process",
                "Which image, command, flags, parent attributes, and control-flow condition reach process creation?",
                "The function prepares a child-process or process-manipulation mechanism.",
                ("benign helper process", "error-recovery path"),
            )
            add_category(
                bool(apis & {"virtualprotect", "etweventwrite", "amsiscanbuffer"}),
                "evasion_or_memory",
                "What target, protection, bytes, consumer, and branch explain this memory or telemetry operation?",
                "The function changes memory or telemetry state for a downstream behavior.",
                ("JIT/runtime setup", "legitimate compatibility shim"),
            )
            if not category_specs:
                category_specs.append(
                    (
                        "function",
                        "What input, calls, data references, conditions, output, and consumer explain this high-value function?",
                        "The function participates in a meaningful static behavior chain.",
                        ("initialization/helper routine", "dead or unreachable code"),
                    )
                )
            ids = tuple(str(row["id"]) for row in group[:24])
            for category, question, hypothesis, alternatives in category_specs:
                rank = max(1, 100 - score)
                if category == "thread":
                    rank = max(1, rank - 20)
                elif category == "decode":
                    # Decode HOW is a first-pass claim.  Ordinary high-value
                    # helpers (CreateFileW, LoadLibrary) otherwise fill the
                    # admission window and leave transform replay/emulation
                    # unqueued, which later becomes empty UNKNOWN threads.
                    rank = max(1, min(rank, 14))
                targets.append(
                    DeepMiningTarget(
                        selector={"function_entry": key},
                        category=category,
                        priority=rank,
                        evidence_ids=ids,
                        question=question,
                        hypothesis=hypothesis,
                        alternatives=alternatives,
                        missing_evidence=("function context", "ordered call/data flow", "consumer or explicit static boundary"),
                    )
                )

        for row in rows:
            if str(row.get("kind", "")) != "api_argument_trace":
                continue
            value = cls._row_value(row)
            start = recovered_thread_start_address(value)
            if not start:
                continue
            caller = cls._function_key(row)
            if start == caller:
                continue
            if any(
                str(item.selector.get("function_entry") or "") == start
                and item.category == "thread_start_routine"
                for item in targets
            ):
                continue
            api = str(value.get("api") or "CreateThread")
            targets.append(
                DeepMiningTarget(
                    selector={"function_entry": start, "role": "os_thread_start_routine"},
                    category="thread_start_routine",
                    priority=12,
                    evidence_ids=(str(row["id"]),),
                    question=(
                        f"What unique loop, APIs, shared state and cleanup path run inside "
                        f"the {api} start routine at {start}?"
                    ),
                    hypothesis=(
                        f"{api} starts an in-process thread whose unique body is at {start}."
                    ),
                    alternatives=("CRT/thread-pool housekeeping", "empty or unreachable stub"),
                    missing_evidence=(
                        "start-routine decompile/CFG",
                        "callees and unique APIs",
                        "shared state or explicit static boundary",
                    ),
                )
            )

        for start, row, label in cls._tls_callback_starts(rows):
            if any(
                str(item.selector.get("function_entry") or "") == start
                and item.category == "thread_start_routine"
                for item in targets
            ):
                continue
            targets.append(
                DeepMiningTarget(
                    selector={"function_entry": start, "role": "tls_callback"},
                    category="thread_start_routine",
                    priority=11,
                    evidence_ids=(str(row.get("id") or ""),),
                    question=(
                        f"What shared state, producer/consumer relation and cleanup path run inside "
                        f"the {label} at {start}?"
                    ),
                    hypothesis=(
                        f"The {label} at {start} writes shared state that may have a consumer."
                    ),
                    alternatives=("CRT TLS initializer", "empty or unreachable stub"),
                    missing_evidence=(
                        "callback body and shared globals",
                        "producer/consumer relation or explicit missing consumer",
                        "loop/cleanup or explicit static boundary",
                    ),
                )
            )

        # Script and carrier artifacts often have no native function/RVA
        # anchor.  Keep one bounded question per artifact surface so they are
        # still investigated instead of being treated as parser-only output.
        for category, kinds, selector, question, hypothesis, alternatives, priority in (
            (
                "script",
                {"script_function", "script_import", "script_call", "script_line", "script_indicator"},
                {"target": "script"},
                "Which script lines, imports, decoded values and consumers form a static behavior chain?",
                "The script contains a statically recoverable decode, network, persistence, or execution path.",
                ("dead code or installer helper", "library import is unused"),
                55,
            ),
            (
                "carrier",
                {"document_url", "document_active_content", "document_embedded_object", "document_embedded_file", "embedded_object"},
                {"target": "document"},
                "Which carrier feature and embedded object path leads to a recursively analyzable child artifact?",
                "The carrier contains active content or an embedded object that may deliver a child artifact.",
                ("benign attachment or document metadata", "embedded object is inert"),
                60,
            ),
            (
                "decode",
                cls._DECODE_MATERIAL_KINDS,
                {"target": "decode"},
                "What input, state, formula, output and consumer form the static decode path?",
                "The encoded data is transformed into a meaningful value used by a downstream mechanism.",
                ("checksum or validation", "high-entropy data without a decoder"),
                48,
            ),
            (
                "resource",
                cls._RESOURCE_KINDS,
                {"target": "resource"},
                "Which resource or embedded payload is extracted, transformed, consumed, or left at a static boundary?",
                "The artifact contains a resource-backed payload whose format and consumer can be recovered statically.",
                ("benign application resource", "high-entropy data without a reachable consumer"),
                50,
            ),
            (
                "staging",
                cls._STAGING_KINDS,
                {"target": "staging"},
                "Which embedded, archived, or decoded child object can be typed and traced to a static consumer?",
                "The carrier yields a child object or decoded artifact that should be followed as a separate static surface.",
                ("inert attachment or archive member", "opaque child without a supported parser"),
                52,
            ),
        ):
            grouped = [row for row in rows if str(row.get("kind", "")) in kinds]
            if not grouped:
                continue
            targets.append(
                DeepMiningTarget(
                    selector=selector,
                    category=category,
                    priority=priority,
                    evidence_ids=tuple(str(row["id"]) for row in grouped[:24]),
                    question=question,
                    hypothesis=hypothesis,
                    alternatives=alternatives,
                    missing_evidence=("typed source context", "ordered transformation or control flow", "consumer or explicit static boundary"),
                )
            )

        # An unanchored import is still a useful global lead.  Create one
        # target per API, but keep it below concrete function targets so API
        # enumeration cannot starve the deeper function investigations.
        for api, group in api_rows.items():
            # A function-call/Xref observation is already a concrete use-site
            # even when a lightweight executor callback omits its enclosing
            # function anchor.  Treating that row as an import-only lead
            # schedules a redundant GET_XREFS_TO target; on a PPID chain this
            # can introduce a spurious open contract after the verifier has
            # already received OpenProcess -> UpdateProcThreadAttribute ->
            # PROC_THREAD_ATTRIBUTE_PARENT_PROCESS evidence.  Only imports
            # and capability indicators without any use-site observation need
            # an API-level Xref target.
            if any(
                cls._function_key(row)
                or str(row.get("kind", ""))
                in {"function_call", "xref", "api_argument_trace", "function_context"}
                for row in group
            ):
                continue
            targets.append(
                DeepMiningTarget(
                    # Use the catalog's canonical ``target`` selector for
                    # API experiments.  This keeps specialist playbook
                    # actions and deep-mining actions on the same dedupe key.
                    selector={"target": api},
                    category="api",
                    priority=75,
                    evidence_ids=tuple(str(row["id"]) for row in group[:16]),
                    question=f"Where is {api} referenced, what arguments reach it, and what consumes its result?",
                    hypothesis=f"{api} participates in a statically recoverable behavior path.",
                    alternatives=("imported capability is unused", "wrapper or compatibility code"),
                    missing_evidence=("xref/caller", "argument or return-value flow", "downstream consumer"),
                )
            )
        for item in pma_dispatch_items(rows):
            selector = dict(item.selector)
            if any(
                dict(existing.selector) == selector and existing.category == item.investigation_category
                for existing in targets
            ):
                continue
            targets.append(
                DeepMiningTarget(
                    selector=selector,
                    category=item.investigation_category,
                    priority=item.priority,
                    evidence_ids=item.evidence_ids,
                    question=item.question or item.title,
                    hypothesis=item.hypothesis or item.why,
                    alternatives=item.alternatives,
                    missing_evidence=item.missing_evidence,
                    next_static_actions=item.next_static_actions,
                    plan_id=item.id,
                )
            )
        targets.sort(key=lambda item: (item.priority, str(item.selector), item.category))
        if max_targets is None:
            return tuple(targets)
        return tuple(targets[: max(1, max_targets)])

    @classmethod
    def plan_actions(
        cls,
        evidence: Iterable[Mapping[str, object]],
        *,
        scheduled: set[str],
        max_actions: int = 48,
    ) -> tuple[ActionSuggestion, ...]:
        """Create a best-first action frontier so the top claim can close in one pass.

        Kunglao ``priority_ratio`` / cheapness: remaining budget belongs to the
        highest-ranked open target until its planned sequence (including
        ``CONTROLLED_EMULATE``) is queued.  Round-robin-by-depth left decode
        replay and isolated emulation unqueued on large PEs because those
        actions sit after the required-facet prefix.
        """
        # Keep a larger ranked frontier than one queue round can consume.
        # Select a small active window below so each admitted target receives
        # several complementary actions before the scheduler advances.
        rows = tuple(
            dict(row)
            for row in evidence
            if isinstance(row, Mapping) and row.get("id")
        )
        rows_by_id = {str(row["id"]): row for row in rows}
        # Discover the complete bounded evidence frontier before filtering
        # scheduled keys.  A fixed ``max_targets=128`` here used to make
        # targets ranked after the first page unreachable forever: once page
        # one was scheduled, every later planner pass saw the same 128 targets
        # and returned no work.  Admission is still bounded below by
        # ``max_actions`` and ``target_budget``; this change only makes paging
        # fair and deterministic for large artifacts.
        targets = cls.build_frontier(rows, max_targets=None)
        catalog = ActionCatalog.default()
        action_sets: list[list[ActionSuggestion]] = []
        # Optional-only targets from an earlier page must not occupy the
        # admission window while later targets still have mandatory contract
        # facets.  Keep a small fallback window for the terminal case where
        # every target has already attempted its required facets.
        optional_window: list[list[ActionSuggestion]] = []
        required_target_count = 0
        # Scan the complete ranked target list, but only materialize a small
        # executable window.  This preserves pagination (we keep scanning
        # past already-scheduled targets) without allocating one ActionSpec
        # list for every function in a large PE.
        target_window_limit = 12
        def is_required_contract_action(action: ActionSuggestion) -> bool:
            contract = action.plan.get("deep_investigation_contract", {})
            required = (
                contract.get("required_action_types", ())
                if isinstance(contract, Mapping)
                else ()
            )
            return action.action_type.value in set(required)

        for target in targets:
            selector = dict(target.selector)
            # The existing static executor identifies function/RVA targets
            # through the canonical ``target`` selector.  Keeping the same
            # shape here prevents a specialist playbook's ``target=0x...``
            # action and a deep-mining ``function_entry=0x...`` action from
            # consuming separate queue slots for the exact same function.
            if "function_entry" in selector:
                selector = {"target": selector["function_entry"]}
            common = {
                "question": target.question,
                "hypothesis": target.hypothesis,
                "alternatives": list(target.alternatives),
                "missing_evidence": list(target.missing_evidence),
                "target_evidence_ids": list(target.evidence_ids),
                # The recursive driver consumes this contract. It prevents a
                # generic candidate threshold from ending a high-risk target
                # after only the first productive query.
                "deep_investigation_contract": cls._deep_coverage_contract(
                    "api"
                    if "function_entry" not in target.selector
                    and target.category
                    not in {
                        "script",
                        "carrier",
                        "decode",
                        "thread_start_routine",
                        "unpack",
                        "windows_object",
                        "covert_launch",
                        "encoding",
                        "anti_re",
                    }
                    else target.category
                ),
            }
            if target.next_static_actions:
                actions = cls._pma_action_sequence(target)
            elif target.selector.get("function_entry") is not None:
                target_rows = [
                    rows_by_id[evidence_id]
                    for evidence_id in target.evidence_ids
                    if evidence_id in rows_by_id
                ]
                # A function-local string action is productive only when its
                # selected evidence already identifies text or a concrete
                # textual data correlation.  A generic function context may
                # have data references, but asking it for strings otherwise
                # simply re-queries a broad artifact corpus and burns depth.
                has_textual_anchor = any(
                    str(row.get("kind", "")) in {"string", "string_reference"}
                    or (
                        str(row.get("kind", "")) == "function_data_correlation"
                        and isinstance(row.get("value"), Mapping)
                        and any(
                            str(row["value"].get(name, "")).strip()
                            for name in ("text", "string", "string_address", "decoded_text")
                        )
                    )
                    for row in target_rows
                )
                # The first round for a function must answer a mechanism
                # question, not merely enumerate what Ghidra already saw.
                # Every sequence therefore starts with the discriminating
                # evidence facets for its category.  The source function is
                # already a concrete Evidence anchor, so GET_FUNCTION is a
                # later navigation fallback rather than the first queue slot.
                if target.category == "decode":
                    actions = [
                        (ActionType.GET_PCODE_SLICE, "Recover the transform loop, state and candidate consumer.", ("pcode_slice", "function_context")),
                        (ActionType.GET_DECOMPILE, "Recover the transform body, constants and consumer calls.", ("abstract_execution_trace", "function_context")),
                        (ActionType.GET_DATA_REFERENCES, "Trace the encoded input, key material and output storage.", ("data_reference", "value_flow")),
                        (ActionType.READ_BYTES, "Read a bounded static input window for deterministic validation.", ("bytes_read", "data_reference")),
                        (ActionType.DECODE_CANDIDATE, "Replay only a bounded deterministic decode candidate.", ("decode_result", "decode_candidate")),
                        (ActionType.GET_CALLEES, "Find consumers reached after the transform returns.", ("function_call", "function_context")),
                        (ActionType.GET_CFG_SLICE, "Recover branch conditions that gate the transform.", ("abstract_execution_trace", "cfg_block")),
                        (ActionType.CONTROLLED_EMULATE, "When static decode stalls, emulate granted transform bytes in the isolated worker.", ("simulation_result",)),
                    ]
                elif target.category == "thread_start_routine":
                    actions = [
                        (ActionType.GET_DECOMPILE, "Recover a bounded semantic view of the unique OS thread start routine.", ("abstract_execution_trace", "function_context")),
                        (ActionType.TRACE_GLOBAL_USAGE, "Track shared state written before the thread starts and read inside it.", ("value_flow", "data_reference", "global_usage")),
                        (ActionType.GET_CFG_SLICE, "Recover the start-routine loop, wait condition and exit path.", ("abstract_execution_trace", "cfg_block")),
                        (ActionType.GET_CALLEES, "Follow unique APIs and downstream logic inside the start routine.", ("function_call", "function_context")),
                        (ActionType.GET_PCODE_SLICE, "Inspect shared state, indirect calls and the unique callback body.", ("pcode_slice", "function_context")),
                        (ActionType.READ_BYTES, "Grant a bounded start-routine window for Unicorn/Speakeasy when policy allows.", ("bytes_read", "data_reference")),
                        (ActionType.CONTROLLED_EMULATE, "When static recovery stalls, emulate the granted start-routine bytes in the isolated worker.", ("simulation_result",)),
                        (ActionType.TRACE_API_ARGUMENT, "Recover arguments of unique APIs inside the start routine.", ("api_argument_trace", "function_context")),
                        (ActionType.GET_CALLERS, "Recover who registered or started this thread/callback.", ("function_call", "function_context")),
                    ]
                elif target.category == "thread":
                    actions = [
                        (ActionType.TRACE_API_ARGUMENT, "Recover lpStartAddress/callback, parameter, and creation flags; a CreateThread listing is not a closed start routine.", ("api_argument_trace", "function_context")),
                        (ActionType.GET_CALLEES, "Follow the start routine and its downstream unique logic.", ("function_call", "function_context")),
                        (ActionType.GET_CFG_SLICE, "Recover the thread/callback loop, wait condition and exit path.", ("abstract_execution_trace", "cfg_block")),
                        (ActionType.GET_DECOMPILE, "Recover a bounded semantic view of the unique thread or callback body.", ("abstract_execution_trace", "function_context")),
                        (ActionType.READ_BYTES, "Grant a bounded function-byte window for Unicorn/Speakeasy when policy allows.", ("bytes_read", "data_reference")),
                        (ActionType.CONTROLLED_EMULATE, "When static recovery stalls, emulate the granted thread/callback bytes in the isolated worker.", ("simulation_result",)),
                        (ActionType.GET_PCODE_SLICE, "Inspect shared state, indirect calls and the unique callback body.", ("pcode_slice", "function_context")),
                        (ActionType.GET_CALLERS, "Recover who registered or started this thread/callback.", ("function_call", "function_context")),
                        (ActionType.TRACE_GLOBAL_USAGE, "Track shared state written before the thread starts and read inside it.", ("value_flow", "data_reference")),
                    ]
                elif target.category in {
                    "network", "process", "evasion_or_memory", "persistence", "injection",
                    "loader", "shell_or_staging", "anti_analysis", "collection_or_privilege",
                }:
                    actions = [
                        (ActionType.TRACE_API_ARGUMENT, "Recover concrete API arguments and call-site conditions.", ("api_argument_trace", "function_context")),
                        (ActionType.GET_PCODE_SLICE, "Inspect operations, data flow and indirect consumers.", ("pcode_slice", "function_context")),
                        (ActionType.GET_DATA_REFERENCES, "Trace input globals, strings and output storage.", ("data_reference", "value_flow")),
                        (ActionType.GET_CFG_SLICE, "Recover branches and ordered control-flow context.", ("abstract_execution_trace", "cfg_block")),
                        (ActionType.GET_CALLEES, "Follow the function's downstream call path.", ("function_call", "function_context")),
                        (ActionType.GET_CALLERS, "Recover the upstream orchestrator and reachability context.", ("function_call", "function_context")),
                        (ActionType.GET_DECOMPILE, "Recover a bounded semantic view after the targeted evidence facets.", ("abstract_execution_trace", "function_context")),
                        (ActionType.READ_BYTES, "Grant a bounded function-byte window for Unicorn/Speakeasy when policy allows.", ("bytes_read", "data_reference")),
                        (ActionType.CONTROLLED_EMULATE, "When static recovery stalls, emulate granted function bytes in the isolated worker.", ("simulation_result",)),
                        (ActionType.GET_STRINGS_REFERENCED, "Correlate semantic strings with this function.", ("string_reference", "function_call")),
                        (ActionType.TRACE_RETURN_VALUE, "Find downstream consumers of returned values or pointers.", ("value_flow", "function_call")),
                    ]
                else:
                    actions = [
                        (ActionType.GET_DECOMPILE, "Recover a bounded semantic view of the function.", ("abstract_execution_trace", "function_context")),
                        (ActionType.GET_PCODE_SLICE, "Inspect operations, data flow and indirect consumers.", ("pcode_slice", "function_context")),
                        (ActionType.GET_DATA_REFERENCES, "Trace input globals, strings and output storage.", ("data_reference", "value_flow")),
                        (ActionType.GET_CALLEES, "Follow the function's downstream call path.", ("function_call", "function_context")),
                        (ActionType.GET_CFG_SLICE, "Recover branches and ordered control-flow context.", ("abstract_execution_trace", "cfg_block")),
                        (ActionType.READ_BYTES, "Grant a bounded function-byte window for Unicorn/Speakeasy when policy allows.", ("bytes_read", "data_reference")),
                        (ActionType.CONTROLLED_EMULATE, "When static recovery stalls, emulate granted function bytes in the isolated worker.", ("simulation_result",)),
                        (ActionType.GET_CALLERS, "Recover the upstream orchestrator and reachability context.", ("function_call", "function_context")),
                        (ActionType.GET_STRINGS_REFERENCED, "Correlate semantic strings with this function.", ("string_reference", "function_call")),
                        (ActionType.TRACE_RETURN_VALUE, "Find downstream consumers of returned values or pointers.", ("value_flow", "function_call")),
                    ]
                if not has_textual_anchor:
                    actions = [
                        item
                        for item in actions
                        if item[0] != ActionType.GET_STRINGS_REFERENCED
                    ]
            elif target.category == "script":
                actions = [
                    (ActionType.GET_STRINGS_REFERENCED, "Correlate suspicious, decoded and command-like values with script lines.", ("string_reference", "script_line")),
                    (ActionType.GET_DATA_REFERENCES, "Trace script inputs and constructed values without executing the script.", ("data_reference", "script_line")),
                    (ActionType.GET_CALLEES, "Expand statically visible script calls and their consumers.", ("script_call", "script_line")),
                    (ActionType.TRACE_API_ARGUMENT, "Recover literal arguments at statically visible script callsites.", ("api_argument_trace", "script_call")),
                ]
            elif target.category == "carrier":
                actions = [
                    (ActionType.GET_STRINGS_REFERENCED, "Correlate URLs, commands and active-content markers with the carrier.", ("string_reference", "document_url")),
                    (ActionType.GET_DATA_REFERENCES, "Trace embedded streams and child-object relationships.", ("data_reference", "embedded_object")),
                    (ActionType.GET_XREFS_TO, "Resolve references to the embedded object or active content.", ("xref", "embedded_object")),
                ]
            elif target.category == "resource":
                # Resource evidence is not a function anchor.  Start with
                # bounded entry metadata/bytes, then look for an explicit
                # extraction/consumer path and only attempt a deterministic
                # payload classification when bytes are available.
                actions = [
                    (ActionType.GET_DATA_REFERENCES, "Enumerate resource entries, offsets, sizes and parent/child relationships.", ("data_reference", "resource_inventory")),
                    (ActionType.READ_BYTES, "Read a bounded static window for the selected resource payload.", ("bytes_read", "data_reference")),
                    (ActionType.GET_XREFS_TO, "Resolve static references from resource extraction APIs to the payload.", ("xref", "embedded_object")),
                    (ActionType.GET_CALLEES, "Recover statically visible consumers after resource extraction or decompression.", ("function_call", "resource_consumer")),
                    (ActionType.DECODE_CANDIDATE, "Classify or replay only a bounded resource/decompression candidate.", ("decode_result", "decode_candidate", "decoded_artifact")),
                ]
            elif target.category == "staging":
                # Child objects are first-class static surfaces. Keep the
                # initial actions focused on typing, provenance and explicit
                # carrier relationships; no embedded content is executed.
                actions = [
                    (ActionType.GET_DATA_REFERENCES, "Trace embedded/archive offsets, names and parent-child relationships.", ("data_reference", "embedded_object", "archive_member")),
                    (ActionType.GET_STRINGS_REFERENCED, "Correlate child metadata, URLs and command-like strings with the carrier.", ("string_reference", "embedded_artifact", "document_embedded_object")),
                    (ActionType.GET_XREFS_TO, "Resolve static references to the child object or decoded output.", ("xref", "embedded_artifact", "archive_member")),
                    (ActionType.GET_CALLEES, "Follow statically visible consumers associated with the child object.", ("function_call", "decoded_artifact")),
                ]
            elif target.category == "decode":
                actions = [
                    (ActionType.GET_DATA_REFERENCES, "Resolve the encoded input and its static data references.", ("data_reference", "mechanism_decode_window")),
                    (ActionType.GET_PCODE_SLICE, "Recover a bounded transform/state slice when function context exists.", ("pcode_slice", "function_context")),
                    (ActionType.DECODE_CANDIDATE, "Replay only a bounded deterministic decode candidate.", ("decode_result", "decode_candidate")),
                ]
            else:
                # A standalone import/API is only a discovery lead.  It has
                # no call-site, argument or function-local data-flow anchor
                # yet, so the only useful first question is where the API is
                # referenced.  A later loop turn receives that Xref evidence
                # and upgrades the work to a concrete function/RVA target.
                # Scheduling the rest of this list eagerly caused real PE
                # runs to spend most of their budget rediscovering the import
                # table as ``NO_NEW_EVIDENCE``.
                actions = [
                    (ActionType.GET_XREFS_TO, "Locate every concrete static reference to this API.", ("xref", "function_context")),
                ]
            planned: list[ActionSuggestion] = []
            for offset, (action_type, why, expected) in enumerate(actions):
                plan = {
                    **common,
                    "action": action_type.value,
                    "why": why,
                    "expected_result": list(expected),
                    "failure_meaning": "record NO_NEW_EVIDENCE or a bounded static limitation; never treat absence as refutation",
                    **cls._method_plan_fields(action_type, selector, common),
                }
                action = ActionSuggestion(
                    action_type=action_type,
                    priority=target.priority + offset,
                    reason=f"{why} Question: {target.question} Alternative explanations: {', '.join(target.alternatives)}.",
                    parameters=selector,
                    expected_evidence_kinds=expected,
                    success_condition="new_targeted_evidence_or_explicit_static_boundary",
                    source_evidence_ids=target.evidence_ids,
                    plan=plan,
                )
                if not investigation_is_scheduled(
                    action.action_type, action.parameters, action.plan, scheduled
                ):
                    planned.append(action)
            if planned:
                required_planned = [
                    action for action in planned if is_required_contract_action(action)
                ]
                if required_planned:
                    if required_target_count == 0:
                        # A required target appeared after a prefix of
                        # optional-only targets.  Discard that prefix so it
                        # cannot starve the real frontier.
                        action_sets = []
                    required_target_count += 1
                    if len(action_sets) < target_window_limit:
                        action_sets.append(planned)
                    if len(action_sets) >= target_window_limit:
                        break
                elif required_target_count == 0 and len(optional_window) < target_window_limit:
                    optional_window.append(planned)

        if required_target_count == 0:
            action_sets = optional_window

        # Never let optional navigation work for an already-admitted target
        # consume the next target's mandatory evidence contract. ``scheduled``
        # carries completed/queued action keys across planner passes, so once
        # the first window has its required facets, the next pass naturally
        # advances to the highest-ranked target with an unscheduled contract.
        # This gives the frontier bounded fairness without inventing an
        # unbounded work queue.
        required_actions_remain = any(
            is_required_contract_action(action)
            for actions in action_sets
            for action in actions
        )
        if required_actions_remain:
            # A target with at least one still-planned required action is new
            # or incomplete, so retain its complete bounded sequence. A set
            # containing only optional actions has already received all of its
            # mandatory facets in an earlier planner pass and must yield.
            action_sets = [
                [
                    action
                    for action in actions
                    if is_required_contract_action(action)
                    or any(is_required_contract_action(item) for item in actions)
                ]
                for actions in action_sets
            ]
            action_sets = [actions for actions in action_sets if actions]

        # Admission is coupled to the mandatory deep-coverage contract. The
        # former fixed four-action divisor could admit six semantic targets
        # into a 24-action round even though each requires five facets. That
        # guarantees shallow, budget-truncated work. Every admitted target
        # now has room for its complete minimum static contract before any
        # optional navigation actions consume the remaining budget.
        contract_depth = max(
            (
                len(
                    {
                        str(item)
                        for action in actions
                        for item in (
                            action.plan.get("deep_investigation_contract", {})
                            .get("required_action_types", ())
                            if isinstance(
                                action.plan.get("deep_investigation_contract", {}), Mapping
                            )
                            else ()
                        )
                    }
                )
                for actions in action_sets
            ),
            default=1,
        )
        target_budget = max(1, min(12, max_actions // max(1, contract_depth)))
        action_sets = action_sets[:target_budget]

        output: list[ActionSuggestion] = []
        for actions in action_sets:
            required = [
                item for item in actions if is_required_contract_action(item)
            ]
            optional = [
                item for item in actions if not is_required_contract_action(item)
            ]
            # Required facets, including CONTROLLED_EMULATE, stay ahead of
            # optional navigation so GET_CALLERS / unanchored strings cannot
            # starve the active claim.  Unanswered work stays unadmitted
            # rather than becoming a budget-truncated UNKNOWN thread.
            ordered = [*required, *optional]
            if len(output) + len(ordered) <= max_actions:
                output.extend(ordered)
                continue
            if required and len(output) + len(required) <= max_actions:
                output.extend(required)
            break
        # Validate the generated shape at the planner seam; the service still
        # performs the authoritative validation before persistence/execution.
        for action in output:
            action = action  # keeps the loop explicit for debuggers/reviewers
            catalog.require(action.action_type)
        return tuple(output)


@dataclass(frozen=True)
class MechanismPlaybook:
    """Versioned, generic static investigation profile.

    Triggers are evidence characteristics, never benchmark labels, report text,
    decoded values, family names, or runtime ground truth.
    """

    id: str
    version: str
    trigger_terms: tuple[str, ...]
    preferred_actions: tuple[ActionType, ...]
    required_evidence_kinds: tuple[str, ...]
    evidence_thresholds: tuple[tuple[str, ...], ...] = ()
    spawned_threads: tuple[str, ...] = ()
    failure_interpretation: FailureInterpretation = FailureInterpretation.UNKNOWN
    question_templates: tuple[str, ...] = ()
    verifier_contract: tuple[str, ...] = ()
    forbidden_inferences: tuple[str, ...] = ()
    # Stable release-plan identifier. ``id`` remains the legacy storage key.
    mechanism_type: str = ""


class MechanismPlaybookRegistry:
    """Closed, versioned static playbooks used by the deterministic investigator."""

    def __init__(
        self,
        playbooks: Iterable[MechanismPlaybook] | None = None,
        *,
        behavior_catalog: BehaviorCatalog | None = None,
    ) -> None:
        self._playbooks = tuple(playbooks or self.default_playbooks())
        self.behavior_catalog = behavior_catalog or BehaviorCatalog()

    @staticmethod
    def default_playbooks() -> tuple[MechanismPlaybook, ...]:
        return (
            MechanismPlaybook(
                "generic-mechanism-investigation",
                "1.0.0",
                (),
                (
                    ActionType.GET_FUNCTION,
                    ActionType.GET_CALLEES,
                    ActionType.GET_CALLERS,
                    ActionType.GET_XREFS_TO,
                    ActionType.GET_XREFS_FROM,
                    ActionType.GET_DATA_REFERENCES,
                    ActionType.GET_DECOMPILE,
                    ActionType.GET_PCODE_SLICE,
                    ActionType.GET_CFG_SLICE,
                    ActionType.TRACE_API_ARGUMENT,
                    ActionType.TRACE_RETURN_VALUE,
                ),
                ("function_context", "function_call", "data_reference", "value_flow"),
                (),
                ("generic-mechanism-thread",),
                question_templates=(
                    "What input reaches the target?",
                    "What transformation or control condition is applied?",
                    "What consumes the output and what side effect would follow if executed?",
                    "Which evidence is still missing to verify this mechanism?",
                ),
                verifier_contract=("target", "input", "transformation_or_control", "condition", "output", "side_effect", "consumer"),
                forbidden_inferences=("a prominent string, import, or function alone proves a mechanism",),
                mechanism_type="GENERIC_MECHANISM_INVESTIGATION",
            ),
            MechanismPlaybook(
                "dynamic-api-resolution",
                "2.0.0",
                ("getprocaddress", "loadlibrary", "ldrgetprocedureaddress"),
                (ActionType.GET_XREFS_TO, ActionType.GET_CALLERS, ActionType.GET_PCODE_SLICE, ActionType.TRACE_RETURN_VALUE),
                ("import_symbol", "xref", "function_context", "data_reference"),
                (("GetProcAddress",), ("function_context", "xref"), ("data_reference",)),
                ("resolver-callers", "resolved-api-consumers"),
                question_templates=("Which APIs are resolved by the candidate resolver and where are they consumed?",),
                verifier_contract=("resolver", "API identity", "consumer"),
                forbidden_inferences=("GetProcAddress import alone proves dynamic resolution",),
                mechanism_type="DYNAMIC_API_RESOLUTION",
            ),
            MechanismPlaybook(
                "xor-config-recovery",
                "2.0.0",
                ("xor", "encoded_blob", "crypto_indicator", "decode"),
                (
                    ActionType.GET_DATA_REFERENCES,
                    ActionType.GET_PCODE_SLICE,
                    ActionType.READ_BYTES,
                    ActionType.DECODE_CANDIDATE,
                    ActionType.TRACE_API_ARGUMENT,
                    ActionType.GET_DECOMPILE,
                    ActionType.CONTROLLED_EMULATE,
                ),
                ("mechanism_decode_window", "data_reference", "function_context", "decode_result"),
                (("mechanism_decode_window",), ("VERIFIED_STATIC_DATA", "decode_result")),
                ("decode-window", "config-consumers"),
                question_templates=("What transformation and consumer are recovered from the decode candidate?",),
                verifier_contract=("cipher/data", "key", "algorithm", "plaintext", "consumer"),
                forbidden_inferences=("high entropy alone proves encryption",),
                mechanism_type="DECODE_CONFIG",
            ),
            MechanismPlaybook(
                "ppid-process-chain",
                "2.0.0",
                ("openprocess", "updateprocthreadattribute", "parent_process", "explorer.exe"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.EVALUATE_CONSTANT),
                ("function_call", "constant", "function_context"),
                (("OpenProcess",), ("UpdateProcThreadAttribute",), ("PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",)),
                ("process-enumeration", "parent-process-attribute"),
                question_templates=("Does the process attribute chain set an explorer.exe parent?",),
                verifier_contract=("parent selection", "access mask", "attribute", "flags"),
                forbidden_inferences=("OpenProcess alone proves PPID spoofing",),
                mechanism_type="PPID_SPOOFING",
            ),
            MechanismPlaybook(
                "entrypoint-timeline",
                "2.0.0",
                ("entrypoint", "entry_point", "address_of_entry_point"),
                (ActionType.GET_FUNCTION, ActionType.GET_CALLEES, ActionType.GET_CFG_SLICE),
                ("pe_structure", "function_context", "cfg_block", "function_call"),
                (("entrypoint",), ("function_context", "cfg_block")),
                ("entrypoint-call-chain",),
                question_templates=("What ordered path leaves the entrypoint and reaches high-value behavior?",),
                verifier_contract=("entrypoint", "ordered calls", "terminal behavior"),
                forbidden_inferences=("static call order proves runtime execution",),
                mechanism_type="ENTRY_TIMELINE",
            ),
            MechanismPlaybook(
                "http-download", "2.0.0",
                ("winhttp", "wininet", "httpopen", "https", "download"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.TRACE_RETURN_VALUE, ActionType.GET_STRINGS_REFERENCED),
                ("import_symbol", "function_call", "string", "value_flow", "function_context"),
                (("WinHttpOpen", "WinHttpSendRequest"), ("WinHttpReceiveResponse",)),
                ("network-consumer",),
                question_templates=("Which endpoint and transport call path receives response bytes?",),
                verifier_contract=("transport identity", "endpoint or host", "consumer",),
                forbidden_inferences=("network import alone proves C2",),
                mechanism_type="HTTP_DOWNLOAD",
            ),
            MechanismPlaybook(
                "process-execution", "2.0.0",
                ("createprocess", "shellexecute", "winexec", "cmd.exe", "powershell"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.EVALUATE_CONSTANT, ActionType.GET_DECOMPILE),
                ("function_call", "constant", "value_flow", "function_context"),
                (("CreateProcess",), ("command", "creation_flags")),
                ("process-execution-consumer",),
                question_templates=("What command, flags, and input data reach the process creation API?",),
                verifier_contract=("process API", "command/input", "flags",),
                forbidden_inferences=("import alone proves execution",),
                mechanism_type="PROCESS_EXECUTION",
            ),
            MechanismPlaybook(
                "defender-modification", "2.0.0",
                ("defender", "disableantispyware", "mpreffer", "registry", "regsetvalue"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.TRACE_GLOBAL_USAGE),
                ("string", "function_call", "value_flow", "registry_path"),
                (("regsetvalue", "registry"), ("defender",)),
                ("defender-write",),
                question_templates=("Which Defender registry path, value name, and data reach the write operation?",),
                verifier_contract=("registry path", "value name", "write operation",),
                forbidden_inferences=("Defender service killed", "complete disablement without value evidence",),
                mechanism_type="DEFENDER_MODIFICATION",
            ),
            MechanismPlaybook(
                "etw-patch", "2.0.0",
                ("etweventwrite", "virtualprotect", "flushinstructioncache", "33 c0 c3", "etw"),
                (ActionType.GET_XREFS_TO, ActionType.GET_CALLEES, ActionType.READ_BYTES, ActionType.TRACE_API_ARGUMENT, ActionType.GET_DECOMPILE),
                ("function_call", "patch_bytes", "constant", "value_flow", "function_context"),
                (("EtwEventWrite", "VirtualProtect"), ("patch_bytes",), ("FlushInstructionCache",)),
                ("etw-patch-target",),
                question_templates=("Does a protection change target EtwEventWrite and write the expected patch bytes?",),
                verifier_contract=("EtwEventWrite identity", "VirtualProtect target", "patch bytes", "restore/flush",),
                forbidden_inferences=("ETW patch from string alone",),
                mechanism_type="ETW_PATCH",
            ),
            MechanismPlaybook(
                "scheduled-task-execution", "2.0.0",
                ("schtasks", "/create", "/sc once", "/run", "/delete", "scheduled task"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.GET_CALLEES, ActionType.GET_DECOMPILE, ActionType.TRACE_API_ARGUMENT),
                ("string", "function_call", "value_flow", "script_line"),
                (("/create", "/sc once"), ("/run",), ("/delete",)),
                ("scheduled-task-fallback",),
                question_templates=("What scheduled-task command sequence is statically reconstructed?",),
                verifier_contract=("create", "schedule", "run", "delete",),
                forbidden_inferences=("durable persistence without trigger evidence",),
                mechanism_type="SCHEDULED_TASK_EXECUTION",
            ),
            MechanismPlaybook(
                "plugin-module-load", "2.0.0",
                ("loadlibrary", "freelibrary", "plugin", "module", "dll"),
                (ActionType.GET_CALLEES, ActionType.TRACE_RETURN_VALUE, ActionType.GET_XREFS_TO, ActionType.TRACE_GLOBAL_USAGE),
                ("import_symbol", "function_call", "function_context", "value_flow"),
                (("LoadLibrary",), ("GetProcAddress", "module")),
                ("module-lifecycle",),
                question_templates=("Which module is loaded, initialized, used, and released?",),
                verifier_contract=("module identity", "load call", "consumer",),
                forbidden_inferences=("DLL import alone proves plugin execution",),
                mechanism_type="PLUGIN_MODULE_LOAD",
            ),
            # Round 11 v3 generic profiles.  These profiles intentionally
            # describe questions and evidence contracts only; no sample or
            # family-specific indicator is embedded in the catalog.  Legacy
            # v2 aliases above remain for replay compatibility.
            MechanismPlaybook(
                "v3-config-decoder", "3.0.0", ("config", "decode", "decrypt", "encoded_blob"),
                (ActionType.GET_DATA_REFERENCES, ActionType.GET_PCODE_SLICE, ActionType.DECODE_CANDIDATE),
                ("data_reference", "function_context", "decode_result"),
                (("input",), ("transformation", "xor", "decrypt"), ("consumer", "downstream")),
                ("config-decoder",), question_templates=("Which input, transformation, state, output, and consumer form the configuration decoder?",),
                verifier_contract=("input", "transformation", "state", "output", "consumer"),
                forbidden_inferences=("encoded bytes alone prove a configuration decoder",), mechanism_type="CONFIG_DECODER",
            ),
            MechanismPlaybook(
                "v3-string-decoder", "3.0.0", ("decoded_string", "string_decode", "string_decrypt"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.GET_PCODE_SLICE, ActionType.DECODE_CANDIDATE),
                ("string", "function_context", "decode_result"),
                (("encoded string",), ("decoded string", "plaintext")), ("string-decoder",),
                question_templates=("Which encoded string is recovered, by what formula, and where is it consumed?",),
                verifier_contract=("encoded input", "formula", "decoded value", "consumer"),
                forbidden_inferences=("an opaque string alone proves malicious intent",), mechanism_type="STRING_DECODER",
            ),
            MechanismPlaybook(
                "v3-api-hash-resolver", "3.0.0", ("api_hash", "hash resolver", "djb2", "fnv", "ror13"),
                (ActionType.GET_DECOMPILE, ActionType.GET_PCODE_SLICE, ActionType.TRACE_RETURN_VALUE, ActionType.COMPARE_FUNCTION),
                ("function_context", "value_flow", "resolved_api"),
                (("hash", "hash constant"), ("export", "module"), ("consumer", "indirect_call")), ("api-hash-resolver",),
                question_templates=("Which module export names match the recovered hash algorithm and where are the pointers consumed?",),
                verifier_contract=("algorithm", "module", "hash", "resolved API", "consumer"),
                forbidden_inferences=("a magic constant alone identifies an API",), mechanism_type="API_HASH_RESOLVER",
            ),
            MechanismPlaybook(
                "v3-network-transport", "3.0.0", ("network", "socket", "winhttp", "wininet", "connect", "http"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.TRACE_RETURN_VALUE, ActionType.GET_STRINGS_REFERENCED),
                ("function_call", "value_flow", "function_context"),
                (("transport", "socket", "winhttp"), ("endpoint", "host", "url"), ("response", "consumer")), ("network-transport",),
                question_templates=("What endpoint, request inputs, response consumer, and control path define the static transport?",),
                verifier_contract=("transport", "endpoint", "request", "response consumer"),
                forbidden_inferences=("a network import proves an active C2 connection",), mechanism_type="NETWORK_TRANSPORT",
            ),
            MechanismPlaybook(
                "v3-download-drop", "3.0.0", ("download", "urlmon", "urldownload", "drop", "writefile", "tempfile"),
                (ActionType.TRACE_API_ARGUMENT, ActionType.GET_CALLEES, ActionType.TRACE_RETURN_VALUE),
                ("function_call", "value_flow", "file_write"),
                (("download source", "url", "response"), ("file sink", "writefile", "drop path")), ("download-drop",),
                question_templates=("What remote or embedded source is written to which local path, and what consumes the file?",),
                verifier_contract=("source", "write path", "write API", "consumer"),
                forbidden_inferences=("a URL string proves a download occurred",), mechanism_type="DOWNLOAD_DROP",
            ),
            MechanismPlaybook(
                "v3-process-creation", "3.0.0", ("process_creation", "createprocess", "shellexecute", "winexec"),
                (ActionType.GET_XREFS_TO, ActionType.TRACE_API_ARGUMENT, ActionType.GET_CFG_SLICE, ActionType.EVALUATE_CONSTANT),
                ("function_call", "value_flow", "function_context"),
                (("process API", "createprocess", "shellexecute"), ("command", "image", "application"), ("flags", "creation_flags")), ("process-creation",),
                question_templates=("Which image, command line, flags, and branch conditions reach process creation?",),
                verifier_contract=("process API", "image/command", "flags", "condition"),
                forbidden_inferences=("CreateProcess import alone proves execution",), mechanism_type="PROCESS_CREATION",
            ),
            MechanismPlaybook(
                "v3-ppid-spoof", "3.0.0", ("ppid", "parent_process", "startupinfoex", "updateprocthreadattribute"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.EVALUATE_CONSTANT),
                ("function_call", "constant", "value_flow"),
                (("parent handle", "openprocess"), ("parent attribute", "proc_thread_attribute_parent_process"), ("extended startup", "startupinfoex")), ("ppid-spoof",),
                question_templates=("Does a parent handle reach the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS startup attribute before child creation?",),
                verifier_contract=("parent handle", "attribute", "CreateProcess", "startup flags"),
                forbidden_inferences=("OpenProcess alone proves PPID spoofing",), mechanism_type="PPID_SPOOF",
            ),
            MechanismPlaybook(
                "v3-command-execution", "3.0.0", ("command_execution", "cmd.exe", "powershell", "shell_execute", "command line"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.TRACE_API_ARGUMENT, ActionType.GET_DECOMPILE),
                ("function_call", "string", "value_flow"),
                (("command input", "command line", "cmd.exe", "powershell"), ("execution sink", "createprocess", "shellexecute")), ("command-execution",),
                question_templates=("What command text reaches the execution sink and under which branch or trigger?",),
                verifier_contract=("command", "sink", "condition"),
                forbidden_inferences=("command-like text without a sink proves execution",), mechanism_type="COMMAND_EXECUTION",
            ),
            MechanismPlaybook(
                "v3-memory-permission-change", "3.0.0", ("virtualprotect", "virtualalloc", "protect", "memory_permission"),
                (ActionType.TRACE_API_ARGUMENT, ActionType.GET_CALLEES, ActionType.GET_PCODE_SLICE),
                ("function_call", "value_flow", "function_context"),
                (("protection API", "virtualprotect", "virtualalloc"), ("address", "size", "protection"), ("consumer", "execute", "read")), ("memory-permission-change",),
                question_templates=("Which address and size change protection, to what value, and who later consumes the region?",),
                verifier_contract=("address", "size", "new protection", "consumer"),
                forbidden_inferences=("VirtualProtect alone proves injection or unpacking",), mechanism_type="MEMORY_PERMISSION_CHANGE",
            ),
            MechanismPlaybook(
                "v3-manual-pe-load", "3.0.0", ("manual_mapper", "manual map", "relocation", "tls callback", "section copy"),
                (ActionType.GET_DECOMPILE, ActionType.GET_PCODE_SLICE, ActionType.GET_CFG_SLICE, ActionType.TRACE_API_ARGUMENT),
                ("function_context", "function_call", "value_flow", "pe_structure"),
                (("allocation", "virtualalloc"), ("section copy", "write"), ("relocation", "base relocation"), ("entrypoint", "tls")), ("manual-pe-load",),
                question_templates=("Is an image allocated, copied, relocated, import-fixed, and transferred to an entrypoint?",),
                verifier_contract=("allocation", "copy", "relocations", "imports", "entry transfer"),
                forbidden_inferences=("MZ/PE magic checks alone prove manual mapping",), mechanism_type="MANUAL_PE_LOAD",
            ),
            MechanismPlaybook(
                "v3-registry-configuration", "3.0.0", ("registry_configuration", "regsetvalue", "regopenkey", "registry"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.TRACE_API_ARGUMENT, ActionType.TRACE_GLOBAL_USAGE),
                ("function_call", "registry_path", "value_flow"),
                (("registry key", "regopenkey", "hkey"), ("value name", "regsetvalue", "data")), ("registry-configuration",),
                question_templates=("Which registry key/value is written, with what data and consumer-visible effect?",),
                verifier_contract=("hive/key", "value name", "type/data", "condition"),
                forbidden_inferences=("a registry API import proves persistence",), mechanism_type="REGISTRY_CONFIGURATION",
            ),
            MechanismPlaybook(
                "v3-registry-persistence", "3.0.0", ("registry_persistence", "run\\", "runonce", "startup", "appdata"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.TRACE_API_ARGUMENT, ActionType.GET_CALLEES),
                ("function_call", "registry_path", "value_flow"),
                (("persistence key", "runonce", "startup"), ("payload path", "command", "image")), ("registry-persistence",),
                question_templates=("Does a registry write establish an autorun value pointing to a payload under a defined condition?",),
                verifier_contract=("autorun key", "value", "payload", "trigger"),
                forbidden_inferences=("generic registry writes are not persistence",), mechanism_type="REGISTRY_PERSISTENCE",
            ),
            MechanismPlaybook(
                "v3-scheduled-task", "3.0.0", ("scheduled_task", "schtasks", "task scheduler", "/create"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.TRACE_API_ARGUMENT, ActionType.GET_DECOMPILE),
                ("string", "function_call", "value_flow"),
                (("create", "/create", "task"), ("trigger", "/sc", "schedule"), ("payload", "/tr", "command")), ("scheduled-task",),
                question_templates=("What task name, trigger, payload, and cleanup/fallback branches are reconstructed?",),
                verifier_contract=("task", "trigger", "payload", "cleanup"),
                forbidden_inferences=("a schtasks string alone proves durable persistence",), mechanism_type="SCHEDULED_TASK",
            ),
            MechanismPlaybook(
                "v3-service", "3.0.0", ("service", "createservice", "startservice", "sc.exe"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.TRACE_API_ARGUMENT, ActionType.GET_CALLEES),
                ("function_call", "value_flow", "string"),
                (("service create", "createservice", "sc.exe"), ("binary path", "service name"), ("start", "startservice")), ("service",),
                question_templates=("Which service identity and binary path are created, configured, and started?",),
                verifier_contract=("service name", "binary path", "create", "start"),
                forbidden_inferences=("service-related strings alone prove persistence",), mechanism_type="SERVICE",
            ),
            MechanismPlaybook(
                "v3-environment-guard", "3.0.0", ("environment_guard", "debugger", "sandbox", "gettickcount", "isdebuggerpresent"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.GET_CFG_SLICE, ActionType.EVALUATE_CONSTANT),
                ("function_call", "constant", "cfg_block", "value_flow"),
                (("probe", "isdebuggerpresent", "gettickcount"), ("comparison", "threshold", "branch"), ("gated capability", "exit", "skip")), ("environment-guard",),
                question_templates=("Which environment value is queried, compared against what, and which capability is gated?",),
                verifier_contract=("probe", "threshold", "branch", "gated behavior"),
                forbidden_inferences=("an environment API import proves anti-analysis",), mechanism_type="ENVIRONMENT_GUARD",
            ),
            MechanismPlaybook(
                "v3-etw-amsi-patch", "3.0.0", ("amsi", "etw_patch", "etw", "etweventwrite", "amsiscanbuffer"),
                (ActionType.GET_XREFS_TO, ActionType.TRACE_API_ARGUMENT, ActionType.READ_BYTES, ActionType.GET_PCODE_SLICE),
                ("function_call", "patch_bytes", "value_flow", "function_context"),
                (("target", "etweventwrite", "amsiscanbuffer"), ("protection", "virtualprotect"), ("patch", "patch_bytes", "33 c0 c3"), ("flush", "flushinstructioncache")), ("etw-amsi-patch",),
                question_templates=("Is a telemetry or AMSI target made writable, patched with exact bytes, and flushed?",),
                verifier_contract=("target", "protection", "bytes", "flush"),
                forbidden_inferences=("ETW/AMSI strings alone prove a patch",), mechanism_type="ETW_AMSI_PATCH",
            ),
            MechanismPlaybook(
                "v3-plugin-load", "3.0.0", ("plugin_load", "plugin", "loadlibrary", "freelibrary", "module"),
                (ActionType.GET_CALLEES, ActionType.TRACE_RETURN_VALUE, ActionType.TRACE_GLOBAL_USAGE),
                ("function_call", "function_context", "value_flow"),
                (("module source", "dll", "path"), ("load", "loadlibrary"), ("consumer", "getprocaddress", "call")), ("plugin-load",),
                question_templates=("Which module is loaded, initialized, consumed, and optionally released?",),
                verifier_contract=("module", "load", "consumer", "release"),
                forbidden_inferences=("a DLL import proves plugin execution",), mechanism_type="PLUGIN_LOAD",
            ),
            MechanismPlaybook(
                "v3-ipc", "3.0.0", ("ipc", "named pipe", "pipe", "mailslot", "rpc", "shared memory"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.TRACE_GLOBAL_USAGE),
                ("function_call", "value_flow", "string"),
                (("channel", "pipe", "rpc", "shared memory"), ("read/write", "connect", "send", "receive"), ("consumer", "dispatch", "handler")), ("ipc",),
                question_templates=("What IPC channel is opened, what data crosses it, and which handler consumes it?",),
                verifier_contract=("channel", "operation", "payload", "consumer"),
                forbidden_inferences=("an IPC API import proves command and control",), mechanism_type="IPC",
            ),
            MechanismPlaybook(
                "v3-command-dispatch", "3.0.0", ("command_dispatch", "dispatcher", "strcmp", "switch", "opcode"),
                (ActionType.GET_STRINGS_REFERENCED, ActionType.GET_CALLEES, ActionType.GET_CFG_SLICE, ActionType.TRACE_API_ARGUMENT),
                ("function_context", "function_call", "string", "cfg_block"),
                (("command input", "opcode", "strcmp"), ("branch", "switch", "dispatch"), ("handler", "callee")), ("command-dispatch",),
                question_templates=("Which command or opcode reaches which handler and what mechanism does each branch invoke?",),
                verifier_contract=("input", "dispatch", "handler", "mechanism"),
                forbidden_inferences=("command strings without dispatch control flow prove a backdoor",), mechanism_type="COMMAND_DISPATCH",
            ),
            MechanismPlaybook(
                "v3-cleanup-self-delete", "3.0.0", ("self_delete", "deletefile", "movefileex", "cleanup", "uninstall"),
                (ActionType.GET_CALLEES, ActionType.TRACE_API_ARGUMENT, ActionType.GET_CFG_SLICE),
                ("function_call", "value_flow", "cfg_block"),
                (("delete API", "deletefile", "movefileex"), ("target", "path", "self"), ("condition", "cleanup", "exit")), ("cleanup-self-delete",),
                question_templates=("Which file is deleted or scheduled for deletion, under what condition, and after which activity?",),
                verifier_contract=("delete API", "target", "condition", "preceding activity"),
                forbidden_inferences=("a delete API import proves self-deletion",), mechanism_type="CLEANUP_SELF_DELETE",
            ),
        )

    def matching(
        self,
        evidence: Iterable[Mapping[str, object]],
        *,
        folded_text: str | None = None,
        folded_kinds: AbstractSet[str] | None = None,
    ) -> tuple[MechanismPlaybook, ...]:
        """Return every playbook whose trigger terms appear in the corpus.

        ``folded_text``/``folded_kinds`` let a caller that already projected the
        same row list for its own use hand the projection in instead of making
        this scan re-serialise every Evidence ``value`` a second time.  They
        must be ``" ".join(str(value))``-casefolded and the casefolded kind set
        respectively; when omitted they are derived here exactly as before.

        Cost note - a "one regex pass" rewrite was implemented, verified, measured,
        and REVERTED.  On the real sample the corpus text is **58.1 MB** and there are
        139 trigger terms across 31 playbooks:

            original (per-term `in`)   0.657 s
            one regex alternation     10.059 s   (15x SLOWER)

        C's `str.__contains__` per term beats a 139-alternative regex over tens of
        megabytes.  This function is NOT the bottleneck (0.66 s); do not rewrite it
        again without measuring on a payload of this size.
        """
        if folded_text is None or folded_kinds is None:
            rows = tuple(evidence)
            # Each projection is computed only when it is actually missing.  The
            # previous `or` rebuilt BOTH whenever either was absent, so a caller that
            # supplied `folded_text` still paid the full corpus serialisation - which
            # is how `Verifier.evaluate` ended up joining the corpus twice per gate
            # check despite passing its own projection in.
            if folded_text is None:
                folded_text = " ".join(str(row.get("value", "")) for row in rows).casefold()
            if folded_kinds is None:
                folded_kinds = {str(row.get("kind", "")).casefold() for row in rows}
        text = folded_text
        kinds = folded_kinds
        matches = [
            item
            for item in self._playbooks
            if any(term in text or term in kinds for term in item.trigger_terms)
        ]
        return tuple(matches)

    def fallback(self) -> MechanismPlaybook:
        """Return the generic playbook for evidence without a specialist match."""
        return next(item for item in self._playbooks if item.id == "generic-mechanism-investigation")

    def best_match(
        self,
        evidence: Iterable[Mapping[str, object]],
        *,
        folded_text: str | None = None,
    ) -> MechanismPlaybook | None:
        """Return the most specific matched playbook with deterministic ties.

        ``folded_text`` lets a caller that already projected the same rows hand the
        projection in rather than paying another O(payload) join - on the real sample
        that join is 71 MB, and `Verifier.evaluate` used to trigger it twice per call.
        """
        rows = tuple(evidence)
        text = (
            folded_text
            if folded_text is not None
            else " ".join(str(row.get("value", "")) for row in rows).casefold()
        )
        kinds = {str(row.get("kind", "")).casefold() for row in rows}
        # Prefer a release playbook with an actual verifier over a broader
        # lifecycle/navigation profile.  Large PE outputs commonly contain
        # ``module``/``dll``/``FreeLibrary`` strings around a more specific
        # resolver or decode chain; raw trigger counts would otherwise select
        # PLUGIN_MODULE_LOAD and leave the semantic mechanism unverifiable.
        verifier_types = {
            "DECODE_CONFIG",
            "DYNAMIC_API_RESOLUTION",
            "PPID_SPOOFING",
            "ETW_PATCH",
        }

        def signal_bonus(item: MechanismPlaybook) -> int:
            bonus = 0
            if item.mechanism_type in verifier_types:
                bonus += 100
            if item.id == "dynamic-api-resolution":
                if "mechanism_dynamic_resolution" in kinds:
                    bonus += 40
                if "getprocaddress" in text:
                    bonus += 20
                if "loadlibrary" in text:
                    bonus += 15
            elif item.id == "xor-config-recovery":
                if "mechanism_decode_window" in kinds:
                    bonus += 40
                if "encoded_blob" in kinds or "crypto_indicator" in kinds:
                    bonus += 20
            return bonus

        ranked = [
            (
                signal_bonus(item)
                + sum(1 for term in item.trigger_terms if term.casefold() in text or term.casefold() in kinds),
                -index,
                item,
            )
            for index, item in enumerate(self._playbooks)
            if any(term.casefold() in text or term.casefold() in kinds for term in item.trigger_terms)
        ]
        return max(ranked, key=lambda value: (value[0], value[1]))[2] if ranked else None

    def by_id(self, playbook_id: str) -> MechanismPlaybook | None:
        """Return one declared profile without allowing artifact-wide matches to override it."""
        normalized = str(playbook_id or "").strip()
        return next((item for item in self._playbooks if item.id == normalized), None)

    def behavior_entry(self, playbook_id: str) -> object | None:
        """Resolve a playbook/mechanism ID through the versioned behaviour map.

        Legacy playbook IDs and mechanism-type IDs are aliases in the
        catalogue.  Keeping this lookup on the registry makes the migration
        explicit without replacing the existing playbook queue.
        """
        playbook = self.by_id(playbook_id)
        candidate = playbook.mechanism_type if playbook is not None else playbook_id
        return self.behavior_catalog.by_id(candidate) or self.behavior_catalog.by_id(playbook_id)

    @property
    def digest(self) -> str:
        source = "|".join(
            f"{item.id}@{item.version}:{','.join(item.spawned_threads)}"
            for item in self._playbooks
        )
        return canonical_action_key(
            "mechanism-playbooks",
            {"profiles": source, "behavior_catalog": self.behavior_catalog.digest},
        )


class ActionCatalog:
    """Closed catalog of actions that an investigation may execute."""

    def __init__(self, definitions: Iterable[ActionDefinition]) -> None:
        self._definitions = {item.action_type: item for item in definitions}

    @classmethod
    def default(cls) -> "ActionCatalog":
        descriptions = {
            ActionType.GET_FUNCTION: "Locate a function by entry or name.",
            ActionType.GET_CALLERS: "Resolve functions that call the target.",
            ActionType.GET_CALLEES: "Resolve calls made by the target.",
            ActionType.GET_XREFS_TO: "Resolve data and code references to a target.",
            ActionType.GET_XREFS_FROM: "Resolve references originating at a target.",
            ActionType.GET_STRINGS_REFERENCED: "Correlate strings with a function or address.",
            ActionType.GET_DATA_REFERENCES: "Resolve referenced globals and data objects.",
            ActionType.READ_BYTES: "Read bounded bytes at a static anchor.",
            ActionType.CONTROLLED_EMULATE: "Emulate granted function bytes in the isolated worker after static recovery stalls.",
            ActionType.GET_DECOMPILE: "Obtain a bounded decompiler view.",
            ActionType.GET_PCODE_SLICE: "Obtain a bounded P-code slice.",
            ActionType.GET_CFG_SLICE: "Obtain a bounded control-flow slice.",
            ActionType.TRACE_API_ARGUMENT: "Track an API argument through static data flow.",
            ActionType.TRACE_RETURN_VALUE: "Track a return value to its consumers.",
            ActionType.TRACE_GLOBAL_USAGE: "Track reads and writes of a global.",
            ActionType.DECODE_CANDIDATE: "Replay a bounded, deterministic decode candidate.",
            ActionType.EVALUATE_CONSTANT: "Decode and label a constant or flag value.",
            ActionType.COMPARE_FUNCTION: "Compare a function with an approved fingerprint index.",
        }
        costs = {
            ActionType.READ_BYTES: 2,
            ActionType.CONTROLLED_EMULATE: 5,
            ActionType.GET_DECOMPILE: 3,
            ActionType.GET_PCODE_SLICE: 3,
            ActionType.GET_CFG_SLICE: 2,
            ActionType.TRACE_API_ARGUMENT: 3,
            ActionType.TRACE_RETURN_VALUE: 3,
            ActionType.TRACE_GLOBAL_USAGE: 3,
            ActionType.DECODE_CANDIDATE: 4,
            ActionType.COMPARE_FUNCTION: 2,
        }
        return cls(
            ActionDefinition(action_type, description, cost_units=costs.get(action_type, 1))
            for action_type, description in descriptions.items()
        )

    def require(self, action_type: ActionType | str) -> ActionDefinition:
        try:
            return self._definitions[ActionType(action_type)]
        except (KeyError, ValueError) as exc:
            raise ValueError(f"action is not in the catalog: {action_type}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(item.value for item in self._definitions)

    def validate(self, action: ActionSpec) -> None:
        definition = self.require(action.action_type)
        if definition.sample_execution:
            raise PermissionError(f"sample execution is not allowed for {action.action_type.value}")
        if definition.network_access:
            raise PermissionError(f"network access is not allowed for {action.action_type.value}")
        selector = dict(action.target_selector)
        if not selector:
            raise ValueError(f"{action.action_type.value} requires a validated target selector")
        if set(selector) - set(definition.selector_keys):
            raise ValueError(f"{action.action_type.value} contains unsupported action parameters")
        if set(action.parameters) != set(selector) or any(
            action.parameters.get(key) != value for key, value in selector.items()
        ):
            raise ValueError(f"{action.action_type.value} parameters must equal its target selector")
        if not action.expected_evidence_kinds or not all(
            isinstance(item, str) and item.strip() for item in action.expected_evidence_kinds
        ):
            raise ValueError(f"{action.action_type.value} requires expected evidence kinds")
        if not action.success_condition.strip():
            raise ValueError(f"{action.action_type.value} requires a success condition")
        if action.cost_units is not None and action.cost_units != definition.cost_units:
            raise ValueError(f"{action.action_type.value} does not match its deterministic cost profile")


class InvestigationQueue:
    """Priority queue with dependency, de-duplication and step budgets."""

    def __init__(
        self, *, max_steps: int = 32, initial_completed: Iterable[str] = ()
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.max_steps = max_steps
        self._items: dict[str, ActionSpec] = {}
        # ``contract_rank`` keeps discriminating work ahead of optional
        # navigation.  Priority remains the tie-breaker inside each layer so
        # legacy callers retain their original ordering semantics.
        self._heap: list[tuple[int, int, int, str]] = []
        self._counter = 0
        self._completed: set[str] = {str(item) for item in initial_completed if str(item).strip()}
        self._failed: set[str] = set()
        self._dedupe_keys: set[str] = set()
        self.steps = 0

    def enqueue(self, action: ActionSpec) -> bool:
        if (
            action.id in self._items
            or action.id in self._completed
            or action.id in self._failed
            or action.dedupe_key in self._dedupe_keys
        ):
            return False
        self._items[action.id] = action
        self._dedupe_keys.add(action.dedupe_key)
        heapq.heappush(
            self._heap,
            (self._contract_rank(action), action.priority, self._counter, action.id),
        )
        self._counter += 1
        return True

    @staticmethod
    def _contract_rank(action: ActionSpec) -> int:
        """Rank required deep facets ahead of optional actions.

        The plan is explanatory metadata, not an authorization surface.  It
        is nevertheless the scheduler's explicit contract: a required facet
        must be attempted before broad callers/callees or other navigation can
        consume a bounded investigation budget.
        """
        contract = action.plan.get("deep_investigation_contract")
        if not isinstance(contract, Mapping):
            return 1
        required = contract.get("required_action_types", ())
        if not isinstance(required, (list, tuple, set, frozenset)):
            return 1
        return 0 if action.action_type.value in {str(item) for item in required} else 1

    def pop(self) -> ActionSpec | None:
        if self.steps >= self.max_steps:
            return None
        deferred: list[tuple[int, int, int, str]] = []
        selected: ActionSpec | None = None
        while self._heap:
            contract_rank, priority, counter, action_id = heapq.heappop(self._heap)
            action = self._items.get(action_id)
            if action is None:
                continue
            if all(dependency in self._completed for dependency in action.depends_on):
                selected = action
                break
            deferred.append((contract_rank, priority, counter, action_id))
        for item in deferred:
            heapq.heappush(self._heap, item)
        return selected

    def complete(self, action_id: str) -> None:
        if action_id not in self._items:
            raise KeyError(action_id)
        self._items.pop(action_id)
        self._completed.add(action_id)
        self.steps += 1

    def fail(self, action_id: str) -> None:
        if action_id not in self._items:
            raise KeyError(action_id)
        self._items.pop(action_id)
        self._failed.add(action_id)
        self.steps += 1

    def drop_pending(self, action_id: str) -> bool:
        """Remove a queued action without consuming a step or marking failure.

        Used when a no-gain method makes remaining same-family probes for the
        same selector redundant.  Stale heap entries are skipped by ``pop``.
        """
        if action_id not in self._items:
            return False
        self._items.pop(action_id)
        return True

    @property
    def pending(self) -> tuple[ActionSpec, ...]:
        return tuple(self._items.values())

    @property
    def completed(self) -> frozenset[str]:
        return frozenset(self._completed)


class MultiSeedInvestigationScheduler:
    """Bounded scheduler for independent investigation seeds.

    Seed discovery can produce many observations for one artifact.  This
    scheduler admits a deterministic, de-duplicated frontier and keeps only
    ``max_active_threads`` investigations active at a time.  It is deliberately
    independent of persistence and executors so callers can mirror the state
    transitions in their own audit store.
    """

    def __init__(self, *, max_active_threads: int = 12, max_seeds: int = 50) -> None:
        if max_active_threads < 1 or max_seeds < 1:
            raise ValueError("max_active_threads and max_seeds must be positive")
        self.max_active_threads = max_active_threads
        self.max_seeds = max_seeds
        self._seeds: dict[str, dict[str, object]] = {}
        self._order: list[str] = []
        self._completed: set[str] = set()

    @staticmethod
    def _key(seed: Mapping[str, object]) -> str:
        artifact = str(seed.get("artifact_id", "")).strip()
        question = str(seed.get("question", "")).strip().casefold()
        kind = str(seed.get("seed_kind", seed.get("kind", ""))).strip().casefold()
        if not artifact:
            raise ValueError("investigation seed requires artifact_id")
        if not question:
            raise ValueError("investigation seed requires question")
        return hashlib.sha256(f"{artifact}|{kind}|{question}".encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _normalize(seed: Mapping[str, object]) -> dict[str, object]:
        item = dict(seed)
        item["artifact_id"] = str(item.get("artifact_id", "")).strip()
        item["question"] = str(item.get("question", "")).strip()
        item["seed_kind"] = str(item.get("seed_kind", item.get("kind", "generic"))).strip() or "generic"
        try:
            item["priority"] = int(item.get("priority", 100))
        except (TypeError, ValueError):
            item["priority"] = 100
        return item

    @staticmethod
    def _identity(seed: Mapping[str, object]) -> str:
        return str(seed.get("thread_id") or seed.get("artifact_id"))

    def admit(self, seeds: Iterable[Mapping[str, object]]) -> tuple[dict[str, object], ...]:
        """Admit at most ``max_seeds`` unique seeds and return rank order."""
        for raw in seeds:
            item = self._normalize(raw)
            key = self._key(item)
            existing = self._seeds.get(key)
            # Keep the stronger priority when the same semantic seed arrives
            # from several extractors; retain all other explanatory fields.
            if existing is None or int(item["priority"]) < int(existing["priority"]):
                self._seeds[key] = item
        ranked = sorted(
            self._seeds.items(),
            key=lambda pair: (int(pair[1]["priority"]), str(pair[1]["artifact_id"]), str(pair[1]["question"])),
        )[: self.max_seeds]
        self._seeds = dict(ranked)
        self._order = [key for key, _ in ranked]
        return tuple(dict(item) for _, item in ranked)

    @property
    def active_threads(self) -> tuple[str, ...]:
        """Artifact IDs occupying the active thread slots in rank order."""
        active: list[str] = []
        seen: set[str] = set()
        for key in self._order:
            if key in self._completed:
                continue
            identity = self._identity(self._seeds[key])
            if identity in seen:
                continue
            active.append(identity)
            seen.add(identity)
            if len(active) >= self.max_active_threads:
                break
        return tuple(active)

    def next_seed(self) -> dict[str, object] | None:
        """Return the highest-priority uncompleted seed in an active slot."""
        active = set(self.active_threads)
        for key in self._order:
            if key in self._completed:
                continue
            item = self._seeds[key]
            if self._identity(item) in active:
                return dict(item)
        return None

    def complete(self, artifact_id: str, *, question: str | None = None, seed_kind: str | None = None) -> bool:
        """Release one seed slot; return whether a matching seed was found."""
        artifact = str(artifact_id).strip()
        completed = False
        for key in self._order:
            item = self._seeds[key]
            if str(item["artifact_id"]) != artifact and str(item.get("thread_id", "")) != artifact:
                continue
            if question is not None and str(item["question"]) != str(question).strip():
                continue
            if seed_kind is not None and str(item["seed_kind"]) != str(seed_kind).strip():
                continue
            self._completed.add(key)
            completed = True
            break
        return completed

    @property
    def pending(self) -> tuple[dict[str, object], ...]:
        return tuple(dict(self._seeds[key]) for key in self._order if key not in self._completed)


class InvestigationThreadState(str, Enum):
    DISCOVERED = "DISCOVERED"
    PRIORITIZED = "PRIORITIZED"
    CONTEXT_READY = "CONTEXT_READY"
    HYPOTHESIZING = "HYPOTHESIZING"
    INVESTIGATING = "INVESTIGATING"
    VERIFYING = "VERIFYING"
    MECHANISM_READY = "MECHANISM_READY"
    CLAIM_READY = "CLAIM_READY"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"
    CONTRADICTED = "CONTRADICTED"
    CLOSED = "CLOSED"


class ThreadStateMachine:
    _ALLOWED: dict[InvestigationThreadState, frozenset[InvestigationThreadState]] = {
        InvestigationThreadState.DISCOVERED: frozenset({InvestigationThreadState.PRIORITIZED}),
        InvestigationThreadState.PRIORITIZED: frozenset({InvestigationThreadState.CONTEXT_READY}),
        InvestigationThreadState.CONTEXT_READY: frozenset({InvestigationThreadState.HYPOTHESIZING}),
        InvestigationThreadState.HYPOTHESIZING: frozenset({InvestigationThreadState.INVESTIGATING, InvestigationThreadState.UNKNOWN, InvestigationThreadState.BLOCKED, InvestigationThreadState.REJECTED}),
        InvestigationThreadState.INVESTIGATING: frozenset({InvestigationThreadState.INVESTIGATING, InvestigationThreadState.VERIFYING, InvestigationThreadState.UNKNOWN, InvestigationThreadState.BLOCKED, InvestigationThreadState.CONTRADICTED}),
        InvestigationThreadState.VERIFYING: frozenset({InvestigationThreadState.MECHANISM_READY, InvestigationThreadState.UNKNOWN, InvestigationThreadState.CONTRADICTED}),
        InvestigationThreadState.MECHANISM_READY: frozenset({InvestigationThreadState.CLAIM_READY}),
        InvestigationThreadState.CLAIM_READY: frozenset({InvestigationThreadState.CLOSED}),
        InvestigationThreadState.UNKNOWN: frozenset({InvestigationThreadState.CLOSED}),
        InvestigationThreadState.BLOCKED: frozenset({InvestigationThreadState.INVESTIGATING, InvestigationThreadState.CLOSED}),
        InvestigationThreadState.REJECTED: frozenset({InvestigationThreadState.CLOSED}),
        InvestigationThreadState.CONTRADICTED: frozenset({InvestigationThreadState.HYPOTHESIZING, InvestigationThreadState.CLOSED}),
        InvestigationThreadState.CLOSED: frozenset(),
    }

    def transition(self, current: InvestigationThreadState | str, target: InvestigationThreadState | str) -> InvestigationThreadState:
        current_state = InvestigationThreadState(current)
        target_state = InvestigationThreadState(target)
        if target_state not in self._ALLOWED[current_state]:
            raise ValueError(f"illegal investigation transition: {current_state.value}->{target_state.value}")
        return target_state


@dataclass(frozen=True)
class GateDecision:
    accepted: bool
    status: str
    reason: str
    evidence_ids: tuple[str, ...]
    missing: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()


@dataclass(frozen=True)
class MechanismVerification:
    """Deterministic semantic verifier result for one mechanism."""

    mechanism_type: str
    status: str
    accepted: bool
    checks: tuple[dict[str, object], ...]
    evidence_ids: tuple[str, ...]
    missing: tuple[str, ...] = ()
    reason: str = ""
    attempted_action_types: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "mechanism_type": self.mechanism_type,
            "status": self.status,
            "accepted": self.accepted,
            "checks": [dict(item) for item in self.checks],
            "evidence_ids": list(self.evidence_ids),
            "missing": list(self.missing),
            "reason": self.reason,
            "attempted_action_types": list(self.attempted_action_types),
        }


_ROW_TEXT_CACHE: dict[int, tuple[object, str]] = {}
_ROW_TEXT_BOUND = 200_000


def _row_text(row: Mapping[str, object]) -> str:
    """Render only typed evidence values for specialist matching.

    ``repr(mapping)`` includes field names (``consumer``, ``output``,
    ``target``), which made the old token gate pass on a schema label with no
    value.  Keep the evidence kind and scalar values, but never use mapping
    keys as semantic tokens.  Anchors are locators and are deliberately not
    treated as behaviour facts here.

    Memoised on the nested ``value`` payload's identity.  The walk is O(payload) and
    builds one string per scalar it finds, and `EvidencePredicate.evaluate` calls it
    for EVERY row for EVERY predicate: a cProfile of one `Verifier.evaluate` on the
    real 39,833-row / 78 MB corpus measured **482,365 calls / 36.6 s self / 134 s
    cumulative**, the largest single cost in the gate the investigation loop runs each
    iteration.  The rows are dicts recreated by the caller, but they carry the same
    ``value`` object throughout a task, so keying on that recovers the reuse; the
    result depends only on it, so a miss costs work but never changes the answer.
    The cache is bounded and identity-checked, holding the payload so a recycled
    ``id()`` cannot alias a different one.
    """
    payload = row.get("value")
    if isinstance(payload, (Mapping, list, tuple, set, frozenset)):
        key = id(payload)
        cached = _ROW_TEXT_CACHE.get(key)
        if cached is not None and cached[0] is payload:
            return _with_kind(cached[1], row)
    else:
        key = 0
        cached = None
    values: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, Mapping):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for nested in value:
                collect(nested)
        elif value is not None:
            values.append(str(value))

    collect(payload)
    body = " ".join(values).casefold()
    if key:
        if len(_ROW_TEXT_CACHE) >= _ROW_TEXT_BOUND:
            _ROW_TEXT_CACHE.clear()
        _ROW_TEXT_CACHE[key] = (payload, body)
    return _with_kind(body, row)


def _with_kind(body: str, row: Mapping[str, object]) -> str:
    """Prefix the row's kind, which is cheap and varies independently of the payload."""
    return f"{str(row.get('kind', ''))} {body}".casefold()


def _row_anchor_tokens(row: Mapping[str, object]) -> set[str]:
    """Return normalized function/RVA identities for one Evidence row."""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
    tokens: set[str] = set()
    for source in (anchor, value):
        # ``target_function``/``callee_function`` identify a call destination,
        # not the function containing the observation.  Treating them as
        # anchor tokens lets unrelated rows appear co-located and can close a
        # mechanism solely through matching API names.  Use the same scoped
        # identity rules as the semantic linker; relationship fields are only
        # accepted from explicitly typed function source anchors.
        tokens.update(_scoped_function_tokens(source))
        for nested in _mapping_sequence(source.get("source_anchors")):
            source_type = str(nested.get("type", "")).casefold()
            tokens.update(
                _scoped_function_tokens(
                    nested,
                    include_relationships=source_type in _FUNCTION_ANCHOR_TYPES,
                )
            )
    return tokens


def _groups_share_static_path(
    rows: tuple[Mapping[str, object], ...],
    match_ids: tuple[set[str], ...],
) -> bool:
    """Require a common function/RVA or an explicit derived-evidence bridge."""
    if not match_ids or any(not item for item in match_ids):
        return False
    by_id = {str(row.get("id")): row for row in rows if row.get("id")}
    anchor_sets: list[set[str]] = []
    for ids in match_ids:
        anchors = set().union(
            *(_row_anchor_tokens(by_id[item]) for item in ids if item in by_id)
        )
        anchor_sets.append(anchors)
    if anchor_sets and set.intersection(*anchor_sets):
        return True
    # Cross-function correlators are allowed only when a derived row names all
    # source Evidence IDs.  Mere co-occurrence in a task is insufficient.
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        source_ids = value.get("source_evidence_ids")
        if not isinstance(source_ids, (list, tuple, set)):
            continue
        source_set = {str(item) for item in source_ids if str(item)}
        # A provenance bridge is only valid when it points at evidence that is
        # actually present in this verification input.  Merely naming IDs
        # that happen to intersect the matcher sets would let an untrusted
        # derived row manufacture a cross-function path.
        if source_set and source_set.issubset(by_id) and all(source_set & ids for ids in match_ids):
            return True
    return False


_DATA_SHAPED_EVIDENCE_KINDS = frozenset(
    {
        "string",
        "string_semantics",
        "decode_result",
        "encoded_blob",
        "decoded_artifact",
    }
)
_CALL_TARGET_VALUE_KEYS = (
    "api",
    "api_name",
    "callee",
    "target_function",
    "referenced_target",
    "target_name",
)


def _object_level_binding_ids(
    rows: tuple[Mapping[str, object], ...],
    tokens: tuple[str, ...],
) -> list[str]:
    """Rows where the token is a *recovered call*, not a name sitting in data.

    Accepts:

    * ``api_argument_trace`` naming the token -- a call site with traced
      arguments, the strongest form;
    * a call-shaped row that names the token as its call target
      (``api``/``api_name``/``callee``/``target_function``/``referenced_target``
      /``target_name``) -- a recovered call exists;
    * a row carrying an explicit ``JOINED_STATIC`` marker together with an
      ``output_buffer`` / ``input_buffer`` identity pair.

    Rejects a token that only appears inside data-shaped evidence (``string``,
    ``decode_result``, ``encoded_blob``).  A WinHTTP name recovered from decoded
    plaintext is configuration: it proves the sample *names* the API, not that a
    call consumes the decoded buffer.  Treating the two as the same is the
    string co-occurrence ADR-0035 and plan 5.2/5.3 forbid, and it is how a
    name-only row used to confirm ``request consumer``.
    """
    folded = tuple(token.casefold() for token in tokens)
    matched: list[str] = []
    for row in rows:
        row_id = str(row.get("id") or "")
        if not row_id:
            continue
        kind = str(row.get("kind") or "").casefold()
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        candidates: list[str] = []
        if kind == "api_argument_trace":
            candidates.append(str(value.get("api") or value.get("name") or ""))
        if kind not in _DATA_SHAPED_EVIDENCE_KINDS:
            candidates.extend(
                str(value.get(key) or "") for key in _CALL_TARGET_VALUE_KEYS
            )
        marker_blob = " ".join(
            str(value.get(key) or "")
            for key in ("join_status", "status", "relation", "join")
        ).casefold()
        if (
            "joined_static" in marker_blob
            and value.get("output_buffer")
            and value.get("input_buffer")
        ):
            candidates.append(_row_text(row))
        for candidate in candidates:
            blob = candidate.casefold()
            if any(token in blob for token in folded):
                matched.append(row_id)
                break
    return matched


def _verify_groups(
    mechanism_type: str,
    evidence: Iterable[Mapping[str, object]],
    groups: tuple[tuple[str, tuple[str, ...]], ...],
    *,
    require_anchor: bool = False,
    object_level_groups: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> MechanismVerification:
    rows = tuple(evidence)
    checks: list[dict[str, object]] = []
    used: list[str] = []
    missing: list[str] = []
    match_sets: list[set[str]] = []
    for name, tokens in groups:
        matches = [
            str(row.get("id"))
            for row in rows
            if row.get("id") and any(token.casefold() in _row_text(row) for token in tokens)
        ]
        if matches:
            used.extend(matches)
            match_sets.append(set(matches))
        else:
            missing.append(name)
            match_sets.append(set())
        checks.append({"name": name, "passed": bool(matches), "evidence_ids": matches[:8]})
    for name, tokens in object_level_groups:
        matches = _object_level_binding_ids(rows, tokens)
        if matches:
            used.extend(matches)
            match_sets.append(set(matches))
        else:
            missing.append(name)
            match_sets.append(set())
        checks.append(
            {
                "name": name,
                "passed": bool(matches),
                "object_level": True,
                "evidence_ids": matches[:8],
            }
        )
    if require_anchor:
        coherent = _groups_share_static_path(rows, tuple(match_sets))
        checks.append({"name": "evidence anchor coherence", "passed": coherent, "evidence_ids": []})
        if not coherent:
            missing.append("evidence anchor coherence")
    accepted = not missing
    return MechanismVerification(
        mechanism_type=mechanism_type,
        status="VERIFIED" if accepted else "UNKNOWN",
        accepted=accepted,
        checks=tuple(checks),
        evidence_ids=tuple(dict.fromkeys(used)),
        missing=tuple(missing),
        reason=("all semantic verifier checks passed" if accepted else "; ".join(f"missing {item}" for item in missing)),
    )


_WINHTTP_CONSUMER_APIS = frozenset(
    {
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "winhttpreceiveresponse",
        "winhttpreaddata",
        "internetopen",
        "internetopenurl",
        "internetconnect",
        "httpopenrequest",
        "httpsendrequest",
    }
)
_PAYLOAD_EXECUTION_CONSUMER_APIS = frozenset(
    {
        "virtualalloc",
        "virtualallocex",
        "ntallocatevirtualmemory",
        "queueuserapc",
        "ntqueueapcthread",
        "ntqueueapcthreadex",
    }
)
_JOIN_ATTEMPT_ACTION_TYPES = frozenset(
    {
        "GET_DECOMPILE",
        "TRACE_API_ARGUMENT",
        "CONTROLLED_EMULATE",
    }
)


def _attempted_action_types_from_evidence(
    evidence: Iterable[Mapping[str, object]],
) -> tuple[str, ...]:
    """Record action types that actually appear on evidence; never invent attempts."""
    names: list[str] = []
    for row in evidence:
        if not isinstance(row, Mapping):
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        candidates: list[object] = [
            row.get("source_action_type"),
            row.get("action_type"),
            value.get("source_action_type"),
            value.get("action_type"),
            value.get("attempted_action_type"),
        ]
        extra = value.get("attempted_action_types")
        if isinstance(extra, (list, tuple, set, frozenset)):
            candidates.extend(extra)
        elif extra not in (None, ""):
            candidates.append(extra)
        for candidate in candidates:
            if isinstance(candidate, (list, tuple, set, frozenset)):
                continue
            name = str(candidate or "").strip().upper()
            if name in _JOIN_ATTEMPT_ACTION_TYPES:
                names.append(name)
    return tuple(dict.fromkeys(names))


def is_process_command_text_decode_consumer(
    plaintext: object = None,
    command: object = None,
    *,
    output_buffer: Mapping[str, object] | None = None,
    command_buffer: Mapping[str, object] | None = None,
    decode_id: object = "decode",
    process_id: object = "process",
) -> bool:
    """True only for object-level decode→process Join, never matching command text.

    Equal plaintext and CreateProcess/schtasks command strings are co-occurrence.
    Identity is the dataflow Join: same artifact_id+address[+length].
    """
    return (
        catalog_decode_output_to_process_command_relation(
            decode_id=decode_id,
            process_id=process_id,
            output_buffer=output_buffer,
            command_buffer=command_buffer,
            plaintext=plaintext,
            command=command,
        )
        is not None
    )


def _relation_consumer_buffers(
    value: Mapping[str, object],
) -> tuple[Mapping[str, object] | None, Mapping[str, object] | None]:
    output_buffer = value.get("output_buffer") if isinstance(value.get("output_buffer"), Mapping) else None
    command_buffer = (
        value.get("command_buffer")
        if isinstance(value.get("command_buffer"), Mapping)
        else (value.get("input_buffer") if isinstance(value.get("input_buffer"), Mapping) else None)
    )
    return output_buffer, command_buffer


def _object_level_named_output_to_consumer(
    value: Mapping[str, object],
    *,
    decode_id: object,
    consumer_id: object,
    api: object,
) -> bool:
    """True only when output_to_consumer names an API and the buffers share identity."""
    if not is_named_decode_consumer_api(api):
        return False
    output_buffer, input_buffer = _relation_consumer_buffers(value)
    if not catalog_buffers_are_same_object(output_buffer, input_buffer):
        return False
    return (
        catalog_output_consumer_relation(
            producer_id=decode_id,
            consumer_id=consumer_id,
            output_buffer=output_buffer,
            consumer_api=api,
        )
        is not None
    )


def _xor_row_is_join(row: Mapping[str, object]) -> bool:
    """Object-level same-buffer Join to WinHTTP/VirtualAlloc/APC or process command.

    Matching plaintext, URL, or command text is not a Join. LoadLibrary and
    other named consumers may still satisfy the consumer slot without this Join.
    """
    if not _xor_row_is_object_consumer(row):
        return False
    value = row.get("value")
    if not isinstance(value, Mapping):
        return False
    relation = str(value.get("relation") or "")
    if relation == "decode_output_to_process_command":
        return True
    api = value.get("api") or value.get("consumer") or value.get("consumer_api")
    token = normalize_api_symbol(api)
    if token in _WINHTTP_CONSUMER_APIS or token in _PAYLOAD_EXECUTION_CONSUMER_APIS:
        return True
    return is_process_execution_api(api)


def _xor_resume_sink_present(rows: Iterable[Mapping[str, object]]) -> bool:
    """True when evidence names a Resume Join sink that must be connected if present."""
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        relation = str(value.get("relation") or "")
        if relation == "decode_output_to_process_command":
            return True
        api = (
            value.get("api")
            or value.get("consumer")
            or value.get("consumer_api")
            or value.get("target_name")
            or value.get("target_function")
            or value.get("name")
        )
        token = normalize_api_symbol(api)
        if token in _WINHTTP_CONSUMER_APIS or token in _PAYLOAD_EXECUTION_CONSUMER_APIS:
            return True
        if is_process_execution_api(api):
            return True
    return False


def _xor_row_is_object_consumer(row: Mapping[str, object]) -> bool:
    """Accept a named object-level consumer; reject process command string match."""
    value = row.get("value")
    if not isinstance(value, Mapping):
        return False
    relation = str(value.get("relation") or "")
    output_buffer, command_buffer = _relation_consumer_buffers(value)
    decode_id = value.get("source_evidence_id") or value.get("producer_evidence_id") or row.get("id")
    process_id = value.get("target_evidence_id") or value.get("consumer_evidence_id") or "process"
    if relation == "decode_output_to_process_command":
        return is_process_command_text_decode_consumer(
            value.get("plaintext"),
            value.get("command") or value.get("command_line") or value.get("image"),
            output_buffer=output_buffer,
            command_buffer=command_buffer,
            decode_id=decode_id,
            process_id=process_id,
        )
    if relation != "output_to_consumer":
        return False
    api = value.get("api") or value.get("consumer") or value.get("consumer_api")
    if is_process_execution_api(api) or value.get("command") or value.get("command_line"):
        return is_process_command_text_decode_consumer(
            value.get("plaintext"),
            value.get("command") or value.get("command_line") or value.get("image"),
            output_buffer=output_buffer,
            command_buffer=command_buffer,
            decode_id=decode_id,
            process_id=process_id,
        )
    return _object_level_named_output_to_consumer(
        value,
        decode_id=decode_id,
        consumer_id=process_id,
        api=api,
    )


def verify_xor_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify XOR/DECODE transform facts without treating co-occurrence as a consumer.

    Whole-chain VERIFIED requires an object-level consumer. A Resume Join
    sink (WinHTTP/VirtualAlloc/APC/process command) present in evidence must
    also be connected; otherwise Join stays UNKNOWN. Matching plaintext vs
    process command text is not a consumer or a Join. Missing Join records
    attempted_action_types from evidence only.
    """
    rows = tuple(evidence)

    def value_of(row: Mapping[str, object]) -> Mapping[str, object]:
        value = row.get("value")
        return value if isinstance(value, Mapping) else {}

    def nested_values(row: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
        value = value_of(row)
        extras = [value]
        for key in ("verification_result", "key_or_state"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                extras.append(nested)
        return tuple(extras)

    def filename_plaintext(text: str) -> bool:
        """True when a decoded value is only a placeholder name, not a config value.

        Plan §2 #2: the previous version also rejected one specific sample's file
        name. Naming a sample here is exactly the cross-sample residue the plan
        forbids, so that special case is removed rather than generalised — a
        recovered payload name is legitimate plaintext; only placeholders are not.
        """
        folded = text.casefold().strip()
        if not folded:
            return True
        return folded in {"sample.exe", "sample.dll", "malware.exe"}

    def recoverable_plaintext(text: str) -> bool:
        if filename_plaintext(text):
            return False
        stripped = text.strip()
        if stripped.startswith(("http://", "https://", "\\\\")) or ":\\" in stripped:
            return True
        printable = sum(1 for char in stripped if char.isprintable())
        return bool(stripped) and printable / max(len(stripped), 1) >= 0.85 and len(stripped) >= 4

    def plaintext_from(item: Mapping[str, object]) -> str:
        for key in ("decoded_text", "plaintext"):
            candidate = str(item.get(key) or "").strip()
            if candidate and recoverable_plaintext(candidate):
                return candidate
        for key in ("plaintext_hex", "output_bytes"):
            hex_text = str(item.get(key) or "").strip()
            if not re.fullmatch(r"[0-9a-fA-F]+", hex_text) or len(hex_text) % 2:
                continue
            try:
                decoded = bytes.fromhex(hex_text).decode("utf-8", "replace")
            except ValueError:
                continue
            if recoverable_plaintext(decoded):
                return decoded
        return ""

    cipher_ids: list[str] = []
    key_ids: list[str] = []
    algorithm_ids: list[str] = []
    counter_ids: list[str] = []
    step_ids: list[str] = []
    plaintext_ids: list[str] = []
    consumer_ids: list[str] = []
    join_ids: list[str] = []
    for row in rows:
        row_id = str(row.get("id") or "").strip()
        if not row_id:
            continue
        kind = str(row.get("kind") or "")
        text = _row_text(row)
        blobs = nested_values(row)
        has_cipher_field = any(
            item.get("ciphertext_hex") or item.get("cipher") or item.get("encoded")
            for item in blobs
        )
        if kind in {"encoded_blob", "mechanism_decode_window"} or has_cipher_field or any(
            token in text for token in ("encoded", "encrypted", "ciphertext", "data_block")
        ):
            cipher_ids.append(row_id)
        if any(
            isinstance(item.get("key_table"), (list, tuple)) or item.get("key") not in (None, "")
            for item in blobs
        ) or "key_table" in text or "16-byte" in text:
            key_ids.append(row_id)
        formula_text = " ".join(
            str(item.get("formula") or item.get("algorithm") or "") for item in blobs
        )
        if "xor" in formula_text.casefold() or (
            "xor" in text and ("key_table" in text or "counter" in text or kind == "decode_result")
        ):
            algorithm_ids.append(row_id)
        if any(item.get("counter_initial") not in (None, "") or "counter=" in text for item in blobs) or "initial_counter" in text:
            counter_ids.append(row_id)
        if any(item.get("counter_step") not in (None, "") for item in blobs) or "counter_step" in text or "increment" in text:
            step_ids.append(row_id)
        for item in blobs:
            if plaintext_from(item):
                plaintext_ids.append(row_id)
                break
        if _xor_row_is_object_consumer(row):
            consumer_ids.append(row_id)
        if _xor_row_is_join(row):
            join_ids.append(row_id)
    checks = (
        {"name": "cipher/data", "passed": bool(cipher_ids), "evidence_ids": cipher_ids[:8]},
        {"name": "key", "passed": bool(key_ids), "evidence_ids": key_ids[:8]},
        {"name": "algorithm", "passed": bool(algorithm_ids), "evidence_ids": algorithm_ids[:8]},
        {"name": "counter", "passed": bool(counter_ids), "evidence_ids": counter_ids[:8]},
        {"name": "step", "passed": bool(step_ids), "evidence_ids": step_ids[:8]},
        {"name": "plaintext", "passed": bool(plaintext_ids), "evidence_ids": plaintext_ids[:8]},
        {"name": "consumer", "passed": bool(consumer_ids), "evidence_ids": consumer_ids[:8]},
        {
            "name": "join",
            "passed": bool(join_ids) or not _xor_resume_sink_present(rows),
            "evidence_ids": join_ids[:8],
        },
    )
    match_sets = (
        set(cipher_ids),
        set(key_ids),
        set(algorithm_ids),
        set(counter_ids),
        set(step_ids),
        set(plaintext_ids),
        set(consumer_ids),
        set(join_ids),
    )
    missing = [str(item["name"]) for item in checks if not item["passed"]]
    present_sets = tuple(item for item in match_sets if item)
    coherent = (not present_sets) or _groups_share_static_path(rows, present_sets)
    checks = checks + (
        {"name": "evidence anchor coherence", "passed": coherent, "evidence_ids": []},
    )
    if not coherent:
        missing.append("evidence anchor coherence")
    used = tuple(dict.fromkeys([*cipher_ids, *key_ids, *algorithm_ids, *counter_ids, *step_ids, *plaintext_ids, *consumer_ids, *join_ids]))
    accepted = not missing
    return MechanismVerification(
        "DECODE_CONFIG",
        "VERIFIED" if accepted else "UNKNOWN",
        accepted,
        checks,
        used,
        tuple(missing),
        (
            "all semantic verifier checks passed"
            if accepted
            else "; ".join(f"missing {item}" for item in missing)
        ),
        attempted_action_types=_attempted_action_types_from_evidence(rows),
    )


def verify_dynamic_api_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify a statically reconstructed LoadLibrary/GetProcAddress chain.

    The old verifier required words such as ``hash`` and ``function pointer``
    that are not emitted by ordinary Ghidra exports.  This implementation
    uses typed observations and exact API identities instead: a resolver, a
    module/entry input, and a downstream consumer must all be present.  It
    remains static-only; a computed call is evidence of a possible path, not
    proof that the sample ran.
    """
    rows = tuple(evidence)
    checks: list[dict[str, object]] = []
    used: list[str] = []

    def row_value(row: Mapping[str, object]) -> Mapping[str, object]:
        value = row.get("value")
        return value if isinstance(value, Mapping) else {}

    def api_names(row: Mapping[str, object]) -> set[str]:
        return _link_api_names((row,))

    def text(row: Mapping[str, object]) -> str:
        return _link_text(row)

    by_id = {str(row.get("id")): row for row in rows if row.get("id")}

    def bridge_sources(row: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
        """Return provenance rows for a derived mechanism link.

        A link is not evidence merely because it labels itself a resolver or
        consumer.  It may participate in verification only when every source
        ID it cites is present in this bounded context.  This keeps the
        verifier useful on large samples without allowing a self-authored
        label to manufacture a complete mechanism.
        """
        value = row_value(row)
        raw_ids = value.get("source_evidence_ids")
        if not isinstance(raw_ids, (list, tuple, set)):
            return ()
        ids = tuple(dict.fromkeys(str(item) for item in raw_ids if str(item).strip()))
        if not ids or any(item not in by_id for item in ids):
            return ()
        return tuple(by_id[item] for item in ids)

    resolver_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            str(row.get("kind", "")) != "mechanism_dynamic_api_link"
            or bool(bridge_sources(row))
        )
            and (
                str(row.get("kind", "")) == "mechanism_dynamic_resolution"
                or bool(
                    api_names(row)
                    & {"getprocaddress", "loadlibrarya", "loadlibraryw", "ldrgetprocedureaddress"}
                )
            )
    ]
    module_input_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
            and (
            (
                any(token in text(row) for token in ("lpfilename", "module", "dll", "library", "entryname", "entry_point", "entry point"))
                or (
                    str(row.get("kind", "")) == "resolved_api"
                    and isinstance(row.get("value"), Mapping)
                    and bool(row.get("value", {}).get("string_address") or row.get("value", {}).get("api_name"))
                )
            )
            and str(row.get("kind", "")) in {"function_context", "function_data_correlation", "data_reference", "function_call", "string_reference", "mechanism_dynamic_api_link", "resolved_api"}
            and (
                str(row.get("kind", "")) != "mechanism_dynamic_api_link"
                or bool(bridge_sources(row))
            )
        )
    ]
    # The deterministic correlator emits a typed link when the exporter does
    # not expose a standalone ``resolved_api`` row.  Accept that link as the
    # module/entry facet only when its cited source rows contain a concrete
    # DLL/module or loader call; the generic word ``module`` in the link value
    # alone is deliberately insufficient.
    for row in rows:
        if str(row.get("kind", "")) != "mechanism_dynamic_api_link":
            continue
        sources = bridge_sources(row)
        if not sources:
            continue
        source_text = " ".join(text(item) for item in sources)
        if any(token in source_text for token in (".dll", "loadlibrary", "getmodulehandle", "entry_point")):
            module_input_ids.append(str(row["id"]))
    consumer_ids: list[str] = []
    resolver_api_names = {"loadlibrarya", "loadlibraryw", "getprocaddress", "ldrgetprocedureaddress"}
    for row in rows:
        if not row.get("id"):
            continue
        if (
            str(row.get("kind", "")) == "mechanism_dynamic_api_link"
            and not bridge_sources(row)
        ):
            continue
        value = row_value(row)
        names = api_names(row)
        explicit_pointer = str(row.get("kind", "")) == "indirect_function_pointer_link" or bool(value.get("indirect"))
        explicit_consumer = any(
            bool(value.get(key))
            for key in (
                "consumer", "consumer_callsite", "consumer_kind", "consumer_apis",
                "calling_entry_point", "resolved_entry", "invoke", "indirect_call",
            )
        ) or any(
            token in text(row)
            for token in ("calling_entry_point", "calling entry point", "resolved entry", "indirect_call")
        )
        # Do not treat an unrelated shell/file API as proof that a resolver's
        # return value was consumed.  A consumer needs an explicit pointer or
        # consumer annotation; a named lifecycle consumer (for example
        # FreeLibrary) remains valid for the typed verifier fixtures.
        typed_direct_consumer = (
            str(row.get("kind", "")) == "function_call"
            and bool(names - resolver_api_names)
            and (bool(value.get("consumer")) or bool(value.get("indirect")) or "freelibrary" in names)
        )
        resolved_api_consumer = (
            str(row.get("kind", "")) == "resolved_api"
            and bool(names - resolver_api_names)
            and bool(value.get("api_name"))
        )
        linked_consumer = False
        if str(row.get("kind", "")) == "mechanism_dynamic_api_link":
            sources = bridge_sources(row)
            source_text = " ".join(text(item) for item in sources)
            source_has_pointer = any(
                str(item.get("kind", "")) == "indirect_function_pointer_link"
                or "indirect" in text(item)
                for item in sources
            )
            source_has_nonresolver_api = any(
                api_names(item) - resolver_api_names
                for item in sources
            )
            linked_consumer = bool(sources) and bool(
                value.get("function_pointer")
                or value.get("consumer_apis")
                or source_has_pointer
                or source_has_nonresolver_api
                or any(
                    bool(source_row.get("value", {}).get("consumer"))
                    for source_row in sources
                    if isinstance(source_row.get("value"), Mapping)
                )
            )
        if explicit_pointer or explicit_consumer or typed_direct_consumer or resolved_api_consumer or linked_consumer:
            consumer_ids.append(str(row["id"]))
    checks.extend(
        (
            {"name": "resolver identity", "passed": bool(resolver_ids), "evidence_ids": resolver_ids[:8]},
            {"name": "module/entry input", "passed": bool(module_input_ids), "evidence_ids": module_input_ids[:8]},
            {"name": "resolved consumer", "passed": bool(consumer_ids), "evidence_ids": consumer_ids[:8]},
        )
    )
    coherent = _groups_share_static_path(
        rows,
        (set(resolver_ids), set(module_input_ids), set(consumer_ids)),
    )
    checks.append({"name": "evidence anchor coherence", "passed": coherent, "evidence_ids": []})
    used.extend(resolver_ids)
    used.extend(module_input_ids)
    used.extend(consumer_ids)
    missing = tuple(item["name"] for item in checks if not item["passed"])
    accepted = not missing
    return MechanismVerification(
        mechanism_type="DYNAMIC_API_RESOLUTION",
        status="VERIFIED" if accepted else "UNKNOWN",
        accepted=accepted,
        checks=tuple(checks),
        evidence_ids=tuple(dict.fromkeys(used)),
        missing=missing,
        reason=(
            "static resolver, module/entry input, and downstream consumer are linked"
            if accepted
            else "; ".join(f"missing {item}" for item in missing)
        ),
    )


_PPID_ENUM_MARKERS = ("process32first", "process32next", "createtoolhelp32snapshot")
_PPID_INVENTED_MODE_TOKENS = ("process hollowing", "remote injection")


def _ppid_blob(row: Mapping[str, object]) -> str:
    value = row.get("value")
    if isinstance(value, str):
        return f"{row.get('kind', '')} {value}".casefold()
    return _row_text(row)


def _ppid_is_enumeration_row(row: Mapping[str, object]) -> bool:
    """Process32 snapshot walking must be a typed call or argument trace.

    Ghidra strings that mention Process32First next to explorer.exe, and
    import_symbol listings of Process32*, are not enumeration evidence.
    """
    kind = str(row.get("kind") or "").casefold()
    if kind not in {"function_call", "api_argument_trace"}:
        return False
    blob = _ppid_blob(row)
    return any(marker in blob for marker in _PPID_ENUM_MARKERS)


def _ppid_parent_image(row: Mapping[str, object]) -> str:
    value = row.get("value")
    if isinstance(value, Mapping):
        image = str(value.get("parent_selection") or value.get("parent") or value.get("text") or "").strip()
        if image:
            return image
    blob = _ppid_blob(row)
    match = re.search(r"explorer\.exe|[a-z0-9_\-]+\.exe", blob, re.I)
    return match.group(0) if match else ""


def _ppid_flags_from_row(row: Mapping[str, object]) -> int | None:
    parsed = _creation_flags_from_row(row)
    if parsed is not None:
        return parsed
    value = row.get("value")
    if isinstance(value, str):
        return _parse_creation_flags_value(value)
    if not isinstance(value, Mapping):
        return None
    return _parse_creation_flags_value(
        value.get("creation_flags") or value.get("flags") or value.get("value")
    )


def verify_ppid_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify PPID spoofing from an attribute chain, not a lone explorer.exe string.

    Process32 enumeration plus a parent image is required. Creation flags come
    from recovered integers / the Windows flag table, not from requiring
    0x09080008 as a specialist token. CREATE_SUSPENDED is only accepted when
    that bit is present on a typed flags integer.
    """
    rows = tuple(evidence)
    enum_ids = [str(row.get("id")) for row in rows if row.get("id") and _ppid_is_enumeration_row(row)]
    parent_ids: list[str] = []
    if enum_ids:
        parent_ids = [
            str(row.get("id"))
            for row in rows
            if row.get("id") and _ppid_parent_image(row)
        ]
    open_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            "openprocess" in _ppid_blob(row)
            or "process_create_process" in _ppid_blob(row)
            or "0x00000080" in _ppid_blob(row)
        )
    ]
    attr_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            "updateprocthreadattribute" in _ppid_blob(row)
            or "proc_thread_attribute_parent_process" in _ppid_blob(row)
            or "parent_process" in _ppid_blob(row)
        )
    ]
    create_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            "createprocessw" in _ppid_blob(row)
            or "createprocessa" in _ppid_blob(row)
            or "startupinfoex" in _ppid_blob(row)
            or "extended_startupinfo" in _ppid_blob(row)
        )
    ]
    flag_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id") and _ppid_flags_from_row(row) is not None
    ]
    if not flag_ids:
        flag_ids = [
            str(row.get("id"))
            for row in rows
            if row.get("id")
            and any(
                token in _ppid_blob(row)
                for token in ("create_no_window", "detached_process", "breakaway", "extended_startupinfo_present")
            )
        ]
    checks = (
        {"name": "process enumeration", "passed": bool(enum_ids), "evidence_ids": enum_ids[:8]},
        {"name": "parent identity", "passed": bool(parent_ids), "evidence_ids": parent_ids[:8]},
        {"name": "OpenProcess access", "passed": bool(open_ids), "evidence_ids": open_ids[:8]},
        {"name": "parent attribute", "passed": bool(attr_ids), "evidence_ids": attr_ids[:8]},
        {"name": "CreateProcess startup", "passed": bool(create_ids), "evidence_ids": create_ids[:8]},
        {"name": "creation flags", "passed": bool(flag_ids), "evidence_ids": flag_ids[:8]},
    )
    match_sets = (
        set(enum_ids),
        set(parent_ids),
        set(open_ids),
        set(attr_ids),
        set(create_ids),
        set(flag_ids),
    )
    missing = [str(item["name"]) for item in checks if not item["passed"]]
    present_sets = tuple(item for item in match_sets if item)
    coherent = (not present_sets) or _groups_share_static_path(rows, present_sets)
    checks = checks + (
        {"name": "evidence anchor coherence", "passed": coherent, "evidence_ids": []},
    )
    if not coherent:
        missing.append("evidence anchor coherence")
    used = tuple(dict.fromkeys([*enum_ids, *parent_ids, *open_ids, *attr_ids, *create_ids, *flag_ids]))
    decoded_suspended = False
    for row in rows:
        parsed = _ppid_flags_from_row(row)
        if parsed is not None and parsed & 0x00000004:
            decoded_suspended = True
    text = " ".join(_ppid_blob(row) for row in rows)
    invented = tuple(
        token
        for token in _PPID_INVENTED_MODE_TOKENS
        if token in text
    )
    if "create_suspended" in text and not decoded_suspended:
        invented = ("create_suspended", *invented)
    if "create_new_console" in text and not any(
        (parsed := _ppid_flags_from_row(row)) is not None and parsed & 0x00000010
        for row in rows
    ):
        invented = (*invented, "create_new_console")
    if invented:
        return MechanismVerification(
            "PPID_SPOOFING",
            "CONTRADICTED",
            False,
            checks,
            used,
            tuple(f"forbidden:{item}" for item in invented),
            f"negative-gold contradiction: {', '.join(invented)}",
        )
    accepted = not missing
    return MechanismVerification(
        "PPID_SPOOFING",
        "VERIFIED" if accepted else "UNKNOWN",
        accepted,
        checks,
        used,
        tuple(missing),
        (
            "PPID attribute chain recovered process enumeration, parent identity, and flags"
            if accepted
            else "; ".join(f"missing {item}" for item in missing)
        ),
    )


def verify_etw_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    # Patch bytes are a typed fact, not a label.  In particular, a row with
    # ``length=3`` or a ``patch_bytes`` field containing unrelated bytes must
    # not satisfy this verifier.
    rows = tuple(evidence)
    groups: tuple[tuple[str, set[str]], ...] = (
        (
            "EtwEventWrite identity",
            {
                str(row.get("id"))
                for row in rows
                if row.get("id") and "etweventwrite" in _link_text(row)
            },
        ),
        (
            "VirtualProtect target",
            {
                str(row.get("id"))
                for row in rows
                if row.get("id") and "virtualprotect" in _link_text(row)
            },
        ),
        (
            "patch bytes",
            {
                str(row.get("id"))
                for row in rows
                if row.get("id") and _has_etw_patch(row)
            },
        ),
        (
            "restore/flush",
            {
                str(row.get("id"))
                for row in rows
                if row.get("id") and any(
                    token in _link_text(row)
                    for token in ("flushinstructioncache", "restore", "old_protection")
                )
            },
        ),
    )
    checks = [
        {"name": name, "passed": bool(ids), "evidence_ids": sorted(ids)[:8]}
        for name, ids in groups
    ]
    match_sets = tuple(ids for _, ids in groups)
    coherent = _groups_share_static_path(rows, match_sets)
    checks.append({"name": "evidence anchor coherence", "passed": coherent, "evidence_ids": []})
    used = tuple(dict.fromkeys(item for ids in match_sets for item in ids))
    missing = tuple(item["name"] for item in checks if not item["passed"])
    return MechanismVerification(
        "ETW_PATCH",
        "VERIFIED" if not missing else "UNKNOWN",
        not missing,
        tuple(checks),
        used,
        missing,
        "all semantic verifier checks passed" if not missing else "; ".join(f"missing {item}" for item in missing),
    )


def verify_http_download_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify a statically linked WinHTTP request/response path.

    The decoded endpoint and the WinHTTP API *sequence* are recovered
    configuration and are checked by name.  The claim that a call actually
    consumes the request is not: ``request consumer`` is an object-level group,
    so a WinHTTP name sitting in decoded text can no longer confirm it.
    """
    return _verify_groups(
        "HTTP_DOWNLOAD",
        evidence,
        (
            ("https input", ("https", "http endpoint", "endpoint")),
            ("response side effect", ("winhttpreceiveresponse", "response bytes")),
        ),
        require_anchor=True,
        object_level_groups=(("request consumer", ("winhttpsendrequest", "httpsendrequest")),),
    )


def verify_shell_output_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify a static child-process pipe/output capture chain.

    ``shell/process input`` and ``pipe consumer`` are consumption claims: they
    require a *recovered call* to the process/pipe APIs.  A name sitting in
    decoded text or a plain string is configuration -- it proves the sample
    names the API, not that a call consumes the child's output.  The
    ``output capture side effect`` group stays a text check because it describes
    the observed side effect rather than binding an argument.
    """
    return _verify_groups(
        "SHELL_OUTPUT",
        evidence,
        (
            ("output capture side effect", ("output capture", "readfile", "peeknamedpipe")),
        ),
        require_anchor=True,
        object_level_groups=(
            ("shell/process input", ("createprocess", "shellexecute", "winexec")),
            ("pipe consumer", ("createpipe", "peeknamedpipe", "readfile")),
        ),
    )


_PROCESS_EXECUTION_APIS = frozenset(
    {"createprocess", "createprocessa", "createprocessw"}
)
_CRYPTOAPI_DECODE_APIS = frozenset(
    {
        "cryptdecrypt",
        "cryptencrypt",
        "cryptimportkey",
        "bcryptdecrypt",
        "bcryptencrypt",
        "bcryptimportkeypair",
    }
)
_THREAD_CALLBACK_APIS = frozenset(
    {
        "createthread",
        "createthreadex",
        "createremotethread",
        "createremotethreadex",
        "queueuserapc",
    }
)
_INVALID_CREATION_FLAGS = frozenset({0xFFFFFFFF, 0xFFFFFFFE})
_INVALID_START_SENTINELS = frozenset(
    {"0xffffffff", "0xfffffffe", "ffffffff", "fffffffe", "-1"}
)


def _typed_call_api(row: Mapping[str, object]) -> str:
    """Return a normalized API only from a call/trace row, never from imports or strings."""
    kind = str(row.get("kind", "")).casefold()
    if kind not in {"function_call", "api_argument_trace"}:
        return ""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    for key in ("api", "api_name", "target_name", "target_function"):
        name = normalize_api_symbol(value.get(key))
        if name:
            return name
    return ""


def _has_cryptoapi_decode_evidence(evidence: Iterable[Mapping[str, object]]) -> bool:
    return any(_typed_call_api(row) in _CRYPTOAPI_DECODE_APIS for row in evidence)


def _known_scalar(value: object) -> bool:
    if value in (None, "", [], {}, ()):
        return False
    return not is_unknown_or_negative(value)


def _typed_buffer_present(row: Mapping[str, object], names: tuple[str, ...]) -> bool:
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    wanted = {item.casefold() for item in names}
    folded = {str(key).casefold(): item for key, item in value.items()}
    for key in wanted:
        if _known_scalar(folded.get(key)):
            return True
    args = value.get("arguments")
    if isinstance(args, (list, tuple)):
        for item in args:
            if not isinstance(item, Mapping) or not item.get("resolved"):
                continue
            name = str(item.get("name") or "").casefold()
            if name in wanted and _known_scalar(item.get("value")):
                return True
    return False


def verify_cryptoapi_decode_mechanism(
    evidence: Iterable[Mapping[str, object]],
) -> MechanismVerification:
    """Accept DECODE_CONFIG for CryptoAPI only with typed key, cipher, algorithm, and consumer.

    XOR counter/step are not required. CryptDecrypt presence alone cannot pass.
    """
    rows = tuple(evidence)
    call_rows = [
        row
        for row in rows
        if row.get("id") and _typed_call_api(row) in _CRYPTOAPI_DECODE_APIS
    ]
    call_ids = [str(row.get("id")) for row in call_rows]
    key_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            _typed_call_api(row) in {"cryptimportkey", "bcryptimportkeypair"}
            or _typed_buffer_present(row, ("key_blob", "key", "hkey", "pbkey"))
        )
    ]
    cipher_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and _typed_call_api(row) in {"cryptdecrypt", "cryptencrypt", "bcryptdecrypt", "bcryptencrypt"}
        and _typed_buffer_present(
            row,
            ("pbdata", "data_buffer", "cipher", "encoded", "encrypted", "encrypted_buffer"),
        )
    ]
    algorithm_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            _typed_buffer_present(row, ("algorithm", "alg", "algid"))
            or (
                _typed_call_api(row) in _CRYPTOAPI_DECODE_APIS
                and any(
                    token in _row_text(row)
                    for token in ("calg_", "rc4", "aes", "des", "3des")
                )
            )
        )
    ]
    consumer_ids: list[str] = []
    for row in rows:
        row_id = str(row.get("id") or "").strip()
        if not row_id:
            continue
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        if str(value.get("relation") or "") != "output_to_consumer":
            continue
        if is_named_decode_consumer_api(
            value.get("api") or value.get("consumer") or value.get("consumer_api")
        ):
            consumer_ids.append(row_id)
    checks = (
        {"name": "CryptoAPI call", "passed": bool(call_ids), "evidence_ids": call_ids[:8]},
        {"name": "key", "passed": bool(key_ids), "evidence_ids": key_ids[:8]},
        {"name": "cipher/data", "passed": bool(cipher_ids), "evidence_ids": cipher_ids[:8]},
        {"name": "algorithm", "passed": bool(algorithm_ids), "evidence_ids": algorithm_ids[:8]},
        {"name": "consumer", "passed": bool(consumer_ids), "evidence_ids": consumer_ids[:8]},
    )
    missing = tuple(str(item["name"]) for item in checks if not item["passed"])
    used = tuple(dict.fromkeys([*call_ids, *key_ids, *cipher_ids, *algorithm_ids, *consumer_ids]))
    accepted = not missing
    return MechanismVerification(
        "DECODE_CONFIG",
        "VERIFIED" if accepted else "UNKNOWN",
        accepted,
        checks,
        used,
        missing,
        (
            "CryptoAPI decrypt/import path recovered key, cipher buffer, algorithm, and consumer"
            if accepted
            else "; ".join(f"missing {item}" for item in missing)
        ),
    )


def _parse_creation_flags_value(raw: object) -> int | None:
    """Parse a recovered dwCreationFlags integer; reject UNKNOWN and -1 soup."""
    if isinstance(raw, bool) or raw is None:
        return None
    if is_unknown_or_negative(raw):
        return None
    if isinstance(raw, int):
        flags = raw & 0xFFFFFFFF
        return None if flags in _INVALID_CREATION_FLAGS else flags
    text = str(raw).strip()
    if not text or is_unknown_or_negative(text):
        return None
    match = re.search(r"0x[0-9a-fA-F]+", text)
    token = match.group(0) if match else text
    try:
        if token.lower().startswith("0x"):
            flags = int(token, 16) & 0xFFFFFFFF
        elif token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
            flags = int(token, 0) & 0xFFFFFFFF
        else:
            return None
    except ValueError:
        return None
    if flags in _INVALID_CREATION_FLAGS:
        return None
    return flags


def _creation_flags_from_row(row: Mapping[str, object]) -> int | None:
    """Read a typed creation_flags fact that survives the credibility gate.

    G3 §7.2: a typed integer is necessary but not sufficient. A neighbouring
    timeout constant such as ``0x000f4240`` (1,000,000 ms) is not a
    ``dwCreationFlags`` argument even when it reaches us as a
    ``process_creation_flags`` row, so it must not close the process-creation
    HOW. Callers see ``None`` and keep ``UNKNOWN(creation_flags)`` instead.
    """
    parsed = _raw_creation_flags_from_row(row)
    if parsed is None:
        return None
    # Deferred import: static_analysis imports recovered_thread_start_address from
    # this module at module scope, so a top-level import here would be a cycle.
    from threat_report_agent.static.static_analysis import credible_windows_process_creation_flags

    if not credible_windows_process_creation_flags(parsed):
        return None
    return parsed


def _raw_creation_flags_from_row(row: Mapping[str, object]) -> int | None:
    """Read a typed creation_flags fact. Named CREATE_SUSPENDED without an integer is not recovered."""
    kind = str(row.get("kind", "")).casefold()
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    if kind == "process_creation_flags":
        parsed = _parse_creation_flags_value(
            value.get("creation_flags") or value.get("value") or value.get("flags")
        )
        if parsed is not None:
            return parsed
    if kind == "constant" and str(value.get("name") or "").casefold() in {
        "creation_flags",
        "dwcreationflags",
        "flags",
    }:
        parsed = _parse_creation_flags_value(
            value.get("creation_flags") or value.get("value") or value.get("flags")
        )
        if parsed is not None:
            return parsed
    for key in ("creation_flags", "dwCreationFlags", "dwcreationflags"):
        parsed = _parse_creation_flags_value(value.get(key))
        if parsed is not None:
            return parsed
    args = value.get("arguments")
    if isinstance(args, (list, tuple)):
        for item in args:
            if not isinstance(item, Mapping) or not item.get("resolved"):
                continue
            name = str(item.get("name") or "").casefold()
            if item.get("index") == 5 or "creation" in name or name in {"dwcreationflags", "flags"}:
                parsed = _parse_creation_flags_value(item.get("value"))
                if parsed is not None:
                    return parsed
    return None


def _thread_start_from_row(row: Mapping[str, object]) -> str | None:
    """Recover start_routine/entry from a thread API call or argument trace."""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    recovered = recovered_thread_start_address(value)
    if recovered:
        if recovered.casefold() in _INVALID_START_SENTINELS:
            return None
        return recovered
    for key in ("start_routine", "entry", "lpStartAddress", "start_address", "callback"):
        parsed = canonical_code_address(value.get(key))
        if parsed and parsed.casefold() not in _INVALID_START_SENTINELS:
            return parsed
    return None


def verify_process_execution_mechanism(
    evidence: Iterable[Mapping[str, object]],
) -> MechanismVerification:
    """Accept PROCESS_EXECUTION only with a CreateProcess call and recovered flags.

    Import listings, UNKNOWN/negation, 0xffffffff, and API/string co-occurrence
    cannot pass.  CREATE_SUSPENDED and explorer.exe are never invented.
    """
    rows = tuple(evidence)
    call_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id") and _typed_call_api(row) in _PROCESS_EXECUTION_APIS
    ]
    flag_ids: list[str] = []
    call_anchors = set()
    for row in rows:
        if str(row.get("id")) in call_ids:
            call_anchors.update(_row_anchor_tokens(row))
    for row in rows:
        if not row.get("id"):
            continue
        flags = _creation_flags_from_row(row)
        if flags is None:
            continue
        row_id = str(row.get("id"))
        if row_id in call_ids:
            flag_ids.append(row_id)
            continue
        if call_anchors and (_row_anchor_tokens(row) & call_anchors):
            flag_ids.append(row_id)
    checks = (
        {"name": "CreateProcess call", "passed": bool(call_ids), "evidence_ids": call_ids[:8]},
        {"name": "creation_flags", "passed": bool(flag_ids), "evidence_ids": flag_ids[:8]},
    )
    used = tuple(dict.fromkeys([*call_ids, *flag_ids]))
    if not call_ids:
        return MechanismVerification(
            "PROCESS_EXECUTION",
            "NOT_APPLICABLE",
            False,
            checks,
            used,
            ("process_api_call",),
            "no CreateProcess/CreateProcessW call evidence; not a process-execution candidate",
        )
    if not flag_ids:
        return MechanismVerification(
            "PROCESS_EXECUTION",
            "UNKNOWN",
            False,
            checks,
            used,
            ("creation_flags",),
            "missing creation_flags",
        )
    return MechanismVerification(
        "PROCESS_EXECUTION",
        "VERIFIED",
        True,
        checks,
        used,
        (),
        "CreateProcess/CreateProcessW call and recovered creation_flags are present",
    )


def verify_thread_callback_mechanism(
    evidence: Iterable[Mapping[str, object]],
) -> MechanismVerification:
    """Accept THREAD_CALLBACK only with a thread API call and recovered start routine.

    Listing CreateThread/CreateRemoteThread/QueueUserAPC without a start
    RVA/entry cannot pass.  UNKNOWN/negation and API co-occurrence cannot pass.
    """
    rows = tuple(evidence)
    call_rows = [
        row
        for row in rows
        if row.get("id") and _typed_call_api(row) in _THREAD_CALLBACK_APIS
    ]
    start_ids: list[str] = []
    for row in call_rows:
        start = _thread_start_from_row(row)
        if start:
            start_ids.append(str(row.get("id")))
    checks = (
        {
            "name": "thread API call",
            "passed": bool(call_rows),
            "evidence_ids": [str(row.get("id")) for row in call_rows][:8],
        },
        {"name": "start_routine", "passed": bool(start_ids), "evidence_ids": start_ids[:8]},
    )
    used = tuple(dict.fromkeys(start_ids or [str(row.get("id")) for row in call_rows]))
    if not start_ids:
        return MechanismVerification(
            "THREAD_CALLBACK",
            "UNKNOWN",
            False,
            checks,
            used,
            ("start_routine",),
            "missing start_routine",
        )
    return MechanismVerification(
        "THREAD_CALLBACK",
        "VERIFIED",
        True,
        checks,
        used,
        (),
        "thread API call and recovered start_routine/entry are present",
    )


_ENVIRONMENT_GUARD_PROBE_APIS = frozenset(
    {
        "gettickcount64",
        "gettickcount",
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "globalmemorystatus",
        "globalmemorystatusex",
    }
)
_ENVIRONMENT_GUARD_NON_PROBE_APIS = frozenset(
    {
        "sleep",
        "sleepex",
        "waitforsingleobject",
        "waitformultipleobjects",
        "queryperformancecounter",
        "getsystemtimeasfiletime",
        "getsystemtime",
        "strcmp",
        "wcscmp",
        "lstrcmpw",
        "lstrcmpa",
        "lstrcmpiw",
        "crt",
    }
)
_ENVIRONMENT_GUARD_THRESHOLD_NAMES = frozenset(
    {
        "threshold",
        "comparison",
        "tick_threshold",
        "memory_threshold",
        "uptime",
        "dwtotalphys",
        "ulltotalphys",
    }
)
_ENVIRONMENT_GUARD_TIMEOUT_NAMES = frozenset(
    {
        "timeout",
        "delay",
        "sleeptime",
        "dwmilliseconds",
        "milliseconds",
        "creation_flags",
        "flags",
        "dwcreationflags",
    }
)
_ENVIRONMENT_GUARD_INVALID_THRESHOLDS = frozenset({0, 0xFFFFFFFF, 0xFFFFFFFE})
_ENVIRONMENT_GUARD_FAIL_TOKENS = frozenset(
    {
        "fail",
        "failure",
        "false",
        "taken",
        "jz",
        "jbe",
        "jle",
        "jb",
        "jl",
        "exit",
        "skip",
        "abort",
        "terminate",
    }
)
_ENVIRONMENT_GUARD_GATED_TOKENS = frozenset(
    {
        "exit",
        "skip",
        "exitprocess",
        "terminateprocess",
        "terminate",
        "abort",
        "fatalexit",
        "rtlexituserprocess",
    }
)


def _parse_environment_guard_threshold(raw: object) -> str | None:
    """Parse a recovered comparison/threshold immediate. Sleep INFINITE is not a gate."""
    if isinstance(raw, bool) or raw is None:
        return None
    if is_unknown_or_negative(raw):
        return None
    if isinstance(raw, int):
        value = raw & 0xFFFFFFFF if raw >= 0 else raw
        if value in _ENVIRONMENT_GUARD_INVALID_THRESHOLDS or raw < 0:
            return None
        return f"0x{value:x}"
    text = str(raw).strip()
    if not text:
        return None
    match = re.search(r"0x[0-9a-fA-F]+", text)
    token = match.group(0) if match else text
    try:
        if token.lower().startswith("0x"):
            value = int(token, 16) & 0xFFFFFFFF
        elif token.isdigit():
            value = int(token, 10) & 0xFFFFFFFF
        else:
            return None
    except ValueError:
        return None
    if value in _ENVIRONMENT_GUARD_INVALID_THRESHOLDS:
        return None
    return f"0x{value:x}"


def _environment_guard_probe_api(row: Mapping[str, object]) -> str:
    """Return a probe API from a call/trace row. Imports and Sleep are not probes."""
    api = _typed_call_api(row)
    if api in _ENVIRONMENT_GUARD_NON_PROBE_APIS:
        return ""
    if api in _ENVIRONMENT_GUARD_PROBE_APIS:
        return api
    return ""


def _environment_guard_threshold_from_row(row: Mapping[str, object]) -> str | None:
    """Read a typed comparison/threshold constant. Timeouts and flags are not thresholds."""
    kind = str(row.get("kind", "")).casefold()
    if kind in {"import_symbol", "string"}:
        return None
    if _typed_call_api(row) in _ENVIRONMENT_GUARD_NON_PROBE_APIS:
        return None
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    name = str(value.get("name") or "").casefold()
    if name in _ENVIRONMENT_GUARD_TIMEOUT_NAMES:
        return None
    for key in ("threshold", "comparison"):
        parsed = _parse_environment_guard_threshold(value.get(key))
        if parsed is not None:
            return parsed
    if kind == "constant" and name in _ENVIRONMENT_GUARD_THRESHOLD_NAMES:
        parsed = _parse_environment_guard_threshold(
            value.get("value") or value.get("threshold") or value.get("comparison")
        )
        if parsed is not None:
            return parsed
    args = value.get("arguments")
    if isinstance(args, (list, tuple)):
        for item in args:
            if not isinstance(item, Mapping) or not item.get("resolved"):
                continue
            arg_name = str(item.get("name") or "").casefold()
            if arg_name in _ENVIRONMENT_GUARD_TIMEOUT_NAMES:
                continue
            if arg_name in _ENVIRONMENT_GUARD_THRESHOLD_NAMES:
                parsed = _parse_environment_guard_threshold(item.get("value"))
                if parsed is not None:
                    return parsed
    return None


def _environment_guard_text_tokens(raw: object) -> set[str]:
    text = str(raw or "").strip().casefold()
    if not text or is_unknown_or_negative(raw):
        return set()
    return {item for item in re.split(r"[^a-z0-9]+", text) if item}


def _environment_guard_branch_from_row(row: Mapping[str, object]) -> bool:
    """True when a typed fail/exit branch is recovered. Sleep delay is not a branch."""
    kind = str(row.get("kind", "")).casefold()
    if kind in {"import_symbol", "string"}:
        return False
    if _typed_call_api(row) in _ENVIRONMENT_GUARD_NON_PROBE_APIS:
        return False
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    for key in ("return_branch", "branch", "fail_branch", "condition_outcome"):
        if _environment_guard_text_tokens(value.get(key)) & _ENVIRONMENT_GUARD_FAIL_TOKENS:
            return True
    if kind == "cfg_block":
        for key in ("terminal", "outcome", "taken_branch", "false_branch"):
            if _environment_guard_text_tokens(value.get(key)) & _ENVIRONMENT_GUARD_FAIL_TOKENS:
                return True
    relation = str(value.get("relation") or "").casefold()
    return relation == "probe_to_branch"


def _environment_guard_gated_from_row(row: Mapping[str, object]) -> bool:
    """True when the gated capability (exit/skip) is a typed fact, not an inferred API purpose."""
    kind = str(row.get("kind", "")).casefold()
    if kind in {"import_symbol", "string"}:
        return False
    api = _typed_call_api(row)
    if api in _ENVIRONMENT_GUARD_NON_PROBE_APIS:
        return False
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    for key in ("gated_behavior", "gated_capability", "exit", "skip"):
        if not _known_scalar(value.get(key)):
            continue
        tokens = _environment_guard_text_tokens(value.get(key))
        if tokens & _ENVIRONMENT_GUARD_GATED_TOKENS or key in {"gated_behavior", "gated_capability"}:
            return True
    if api in {"exitprocess", "terminateprocess", "fatalexit", "rtlexituserprocess"}:
        return True
    if kind == "cfg_block":
        for key in ("terminal", "gated_behavior", "exit"):
            if _environment_guard_text_tokens(value.get(key)) & _ENVIRONMENT_GUARD_GATED_TOKENS:
                return True
    return False


def _environment_guard_ids_linked_to_probe(
    rows: tuple[Mapping[str, object], ...],
    probe_ids: list[str],
    candidate_ids: list[str],
) -> list[str]:
    """Keep threshold/branch/exit on the probe call or a shared function/RVA."""
    if not probe_ids:
        return []
    probe_set = set(probe_ids)
    probe_anchors: set[str] = set()
    for row in rows:
        if str(row.get("id")) in probe_set:
            probe_anchors.update(_row_anchor_tokens(row))
    linked: list[str] = []
    candidate_set = set(candidate_ids)
    for row in rows:
        row_id = str(row.get("id") or "")
        if row_id not in candidate_set:
            continue
        if row_id in probe_set:
            linked.append(row_id)
            continue
        if probe_anchors and (_row_anchor_tokens(row) & probe_anchors):
            linked.append(row_id)
    return linked


def verify_environment_guard_mechanism(
    evidence: Iterable[Mapping[str, object]],
) -> MechanismVerification:
    """Accept ENVIRONMENT_GUARD only with a probe call, threshold, and fail/exit.

    Import listings, Sleep, and CRT/timing APIs cannot prove anti-analysis.
    Missing comparison/threshold stays UNKNOWN; do not invent a gate.
    """
    rows = tuple(evidence)
    probe_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id") and _environment_guard_probe_api(row)
    ]
    threshold_ids = _environment_guard_ids_linked_to_probe(
        rows,
        probe_ids,
        [
            str(row.get("id"))
            for row in rows
            if row.get("id") and _environment_guard_threshold_from_row(row)
        ],
    )
    branch_ids = _environment_guard_ids_linked_to_probe(
        rows,
        probe_ids,
        [
            str(row.get("id"))
            for row in rows
            if row.get("id") and _environment_guard_branch_from_row(row)
        ],
    )
    gated_ids = _environment_guard_ids_linked_to_probe(
        rows,
        probe_ids,
        [
            str(row.get("id"))
            for row in rows
            if row.get("id") and _environment_guard_gated_from_row(row)
        ],
    )
    checks = (
        {"name": "probe", "passed": bool(probe_ids), "evidence_ids": probe_ids[:8]},
        {"name": "threshold", "passed": bool(threshold_ids), "evidence_ids": threshold_ids[:8]},
        {"name": "branch", "passed": bool(branch_ids), "evidence_ids": branch_ids[:8]},
        {"name": "gated behavior", "passed": bool(gated_ids), "evidence_ids": gated_ids[:8]},
    )
    used = tuple(dict.fromkeys([*probe_ids, *threshold_ids, *branch_ids, *gated_ids]))
    missing = tuple(str(item["name"]) for item in checks if not item["passed"])
    if missing:
        return MechanismVerification(
            "ENVIRONMENT_GUARD",
            "UNKNOWN",
            False,
            checks,
            used,
            missing,
            "; ".join(f"missing {item}" for item in missing),
        )
    return MechanismVerification(
        "ENVIRONMENT_GUARD",
        "VERIFIED",
        True,
        checks,
        used,
        (),
        "environment probe, recovered threshold, fail/exit branch, and gated behavior are present",
    )


def verify_mechanism(mechanism_type: str, evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Dispatch to the release verifier for a canonical mechanism type."""
    verifiers = {
        "DECODE_CONFIG": verify_xor_mechanism,
        "DYNAMIC_API_RESOLUTION": verify_dynamic_api_mechanism,
        "PPID_SPOOFING": verify_ppid_mechanism,
        "ETW_PATCH": verify_etw_mechanism,
        "HTTP_DOWNLOAD": verify_http_download_mechanism,
        "SHELL_OUTPUT": verify_shell_output_mechanism,
        "PROCESS_EXECUTION": verify_process_execution_mechanism,
        "PROCESS_CREATION": verify_process_execution_mechanism,
        "THREAD_CALLBACK": verify_thread_callback_mechanism,
        "ENVIRONMENT_GUARD": verify_environment_guard_mechanism,
    }
    name = str(mechanism_type).upper()
    if name == "DECODE_CONFIG" and _has_cryptoapi_decode_evidence(evidence):
        return verify_cryptoapi_decode_mechanism(evidence)
    verifier = verifiers.get(name)
    if verifier is None:
        return MechanismVerification(
            str(mechanism_type), "UNKNOWN", False, (), (),
            ("specialized_verifier_not_available",),
            "no specialized verifier registered for this mechanism type",
        )
    return verifier(evidence)


def mechanism_completeness_score(mechanism: Mapping[str, object]) -> int:
    """Return the single shared semantic mechanism score."""
    return _semantic_mechanism_completeness_score(mechanism)


@dataclass(frozen=True)
class HypothesisPredicate:
    """Typed proposition used when a verifier evaluates support or refutation."""

    subject: str
    predicate: str
    object: str
    scope: str
    counter_evidence_rule: str = "affirmative_or_exhaustive"


class ClaimGate:
    """Evidence threshold gate used before a hypothesis becomes a Claim."""

    @staticmethod
    def _has_derivation_provenance(row: Mapping[str, object]) -> bool:
        value = row.get('value')
        if not isinstance(value, Mapping):
            return False
        derivation = value.get('derivation')
        if not isinstance(derivation, Mapping):
            return False
        required = ('evaluator', 'input_evidence_ids', 'input_digest', 'output_digest')
        if any(not derivation.get(item) for item in required):
            return False
        source_ids = derivation.get('input_evidence_ids')
        if not isinstance(source_ids, (list, tuple)) or not all(str(item).strip() for item in source_ids):
            return False
        for digest_name in ('input_digest', 'output_digest'):
            digest = derivation.get(digest_name)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in '0123456789abcdefABCDEF' for character in digest)
            ):
                return False
        return isinstance(derivation.get('evaluator'), str) and bool(derivation['evaluator'].strip())

    def evaluate(
        self,
        evidence: Iterable[Mapping[str, object]],
        *,
        required_kinds: tuple[str, ...] = (),
        required_any_kinds: tuple[str, ...] = (),
        required_predicates: tuple[Callable[[Mapping[str, object]], bool], ...] = (),
        required_any_predicates: tuple[Callable[[Mapping[str, object]], bool], ...] = (),
        contradictory_ids: tuple[str, ...] = (),
        allowed_natures: frozenset[str] = frozenset(
            {"STATIC_OBSERVED", "STATIC_DERIVED", "STATIC_INFERRED"}
        ),
    ) -> GateDecision:
        rows = tuple(evidence)
        derived_without_provenance = tuple(
            str(row.get('id'))
            for row in rows
            if row.get('id')
            and str(row.get('nature', '')) == 'STATIC_DERIVED'
            and not self._has_derivation_provenance(row)
        )
        ids = tuple(str(row.get("id")) for row in rows if row.get("id"))
        contradictions = tuple(item for item in contradictory_ids if item in ids)
        missing: list[str] = []
        for kind in required_kinds:
            if not any(str(row.get("kind")) == kind for row in rows):
                missing.append(f"kind:{kind}")
        if required_any_kinds and not any(str(row.get("kind")) in required_any_kinds for row in rows):
            missing.append("any_kind:" + "|".join(required_any_kinds))
        for index, predicate in enumerate(required_predicates, start=1):
            if not any(predicate(row) for row in rows):
                missing.append(f"predicate:{index}")
        if required_any_predicates and not any(predicate(row) for predicate in required_any_predicates for row in rows):
            missing.append("any_predicate")
        disallowed = tuple(
            str(row.get("id"))
            for row in rows
            if row.get("id") and str(row.get("nature", "")) not in allowed_natures
        )
        if contradictions:
            return GateDecision(False, "CONTRADICTED", "contradictory evidence is present", ids, tuple(missing), contradictions)
        if derived_without_provenance:
            return GateDecision(False, 'UNKNOWN', 'STATIC_DERIVED evidence requires provenance', ids, tuple(missing), derived_without_provenance)
        if disallowed:
            return GateDecision(False, "UNKNOWN", "evidence nature is outside the claim gate", ids, tuple(missing), disallowed)
        if missing:
            return GateDecision(False, "UNKNOWN", "required evidence threshold is not met", ids, tuple(missing))
        return GateDecision(True, "SUPPORTED", "all required evidence conditions are satisfied", ids)

    def evaluate_refutation(
        self,
        predicate: HypothesisPredicate,
        *,
        affirmative_counterevidence_ids: tuple[str, ...] = (),
        exhaustive_scope_verified: bool = False,
    ) -> GateDecision:
        """Refute only with affirmative evidence or a verifier-proven finite scope.

        Absence is deliberately insufficient. A direct-import query cannot rule
        out dynamic resolution, wrappers, hashes, or indirect calls unless the
        supplied predicate explicitly limits its scope.
        """
        evidence_ids = tuple(dict.fromkeys(str(item) for item in affirmative_counterevidence_ids if item))
        if evidence_ids:
            return GateDecision(
                False,
                "REFUTED",
                f"affirmative counter-evidence refutes {predicate.predicate} within {predicate.scope}",
                evidence_ids,
                contradictions=evidence_ids,
            )
        if exhaustive_scope_verified:
            return GateDecision(
                False,
                "REFUTED",
                f"verifier completed the explicit exhaustive scope: {predicate.scope}",
                (),
            )
        return GateDecision(
            False,
            "UNKNOWN",
            "no affirmative counter-evidence or verified exhaustive scope is available",
            (),
            missing=("counter_evidence_or_exhaustive_scope",),
        )


class Investigator:
    """Propose target-aware static experiments from matching Playbooks."""

    def __init__(self, playbooks: MechanismPlaybookRegistry | None = None) -> None:
        self.playbooks = playbooks or MechanismPlaybookRegistry()
        # Per-``propose`` scan memo.  ``repr`` of an Evidence ``value`` mapping
        # is the single most expensive thing this module does (about 23 us for
        # the ~3 kB average row of a real PE corpus), and one ``propose`` pass
        # scans the same bounded corpus ~114 times looking for different terms.
        # Without memoisation the identical multi-kilobyte string was rebuilt
        # and re-case-folded for every scan of every row.  Each entry keeps a
        # strong reference to the row it describes so an ``id()`` key can never
        # be recycled onto a different row; the whole memo is dropped when the
        # pass ends.
        self._row_scan_text_memo: dict[int, tuple[object, str]] = {}
        self._row_value_text_memo: dict[int, tuple[object, str]] = {}
        self._corpus_projection_memo: dict[int, tuple[object, str, frozenset[str]]] = {}
        # Cross-iteration term-scan cache: (rows, {id(row): frozenset(matched terms)}).
        # Survives `_reset_scan_memo` on purpose - its whole value is spanning
        # iterations, and it holds strong row references so `id()` keys stay valid.
        self._term_scan_cache: tuple[
            list[Mapping[str, object]] | None, dict[int, frozenset[str]]
        ] = (None, {})

    def _reset_scan_memo(self) -> None:
        self._row_scan_text_memo.clear()
        self._row_value_text_memo.clear()
        self._corpus_projection_memo.clear()

    def _row_scan_text(self, row: Mapping[str, object]) -> str:
        """Case-folded ``kind value anchor`` haystack for one Evidence row.

        Byte-for-byte the string ``_contains`` used to receive at each call
        site, computed once per row per pass instead of once per scan.
        """
        key = id(row)
        cached = self._row_scan_text_memo.get(key)
        if cached is not None and cached[0] is row:
            return cached[1]
        text = f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()
        self._row_scan_text_memo[key] = (row, text)
        return text

    def _row_value_text(self, row: Mapping[str, object]) -> str:
        """Case-folded ``str(value)`` for one Evidence row, memoised per pass."""
        key = id(row)
        cached = self._row_value_text_memo.get(key)
        if cached is not None and cached[0] is row:
            return cached[1]
        text = str(row.get("value", "")).casefold()
        self._row_value_text_memo[key] = (row, text)
        return text

    def _corpus_projection(
        self, rows: list[Mapping[str, object]]
    ) -> tuple[str, frozenset[str]]:
        """Memoised ``(case-folded value text, case-folded kinds)`` for a row list.

        ``propose`` needs the joined value text for its own term checks and the
        Playbook registry needs exactly the same projection; deriving it twice
        walked the whole corpus twice per pass.
        """
        key = id(rows)
        cached = self._corpus_projection_memo.get(key)
        if cached is not None and cached[0] is rows:
            return cached[1], cached[2]
        text = " ".join(str(row.get("value", "")) for row in rows).casefold()
        kinds = frozenset(str(row.get("kind", "")).casefold() for row in rows)
        self._corpus_projection_memo[key] = (rows, text, kinds)
        return text, kinds

    @staticmethod
    def _first_static_target(rows: Iterable[Mapping[str, object]]) -> str:
        for row in rows:
            target = DeepMiningPlanner._function_key(row)
            if target:
                return target
        return ""

    @classmethod
    def _concrete_target(cls, rows: Iterable[Mapping[str, object]]) -> str:
        """Resolve an action selector from observed static Evidence only.

        Mechanism labels describe an investigation question, not a location in
        an artifact.  Executing an action against one of those labels creates
        an auditable but useless ``NO_NEW_EVIDENCE`` result.  Prefer a stable
        function/RVA locator, then an observed API/symbol name.
        """
        materialized = list(rows)
        target = cls._first_static_target(materialized)
        if target:
            return target
        for row in materialized:
            value = row.get("value")
            if not isinstance(value, Mapping):
                continue
            for key in ("api", "api_name", "target_name", "target_function", "name", "indicator"):
                item = value.get(key)
                if not isinstance(item, (str, int)) or not str(item).strip():
                    continue
                candidate = str(item).strip()
                # Static mechanism values use upper-snake case.  They are
                # categorization metadata, never resolvable code/data IDs.
                if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", candidate):
                    continue
                return candidate
        return ""

    @staticmethod
    def _evidence_ids(rows: Iterable[Mapping[str, object]]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                str(row.get("id"))
                for row in rows
                if isinstance(row.get("id"), (str, int)) and str(row.get("id")).strip()
            )
        )[:24]

    def _matching_rows(
        self,
        rows: Iterable[Mapping[str, object]],
        *terms: str,
        candidates: Sequence[Mapping[str, object]] | None = None,
    ) -> list[Mapping[str, object]]:
        # Fold the terms once per scan, not once per row: ``_contains`` used to
        # re-case-fold every term for every row it tested.  The row haystack is
        # resolved once per row as well, so a multi-term scan does not repeat
        # the memo lookup (and its ``id()``) for every term.
        #
        # ``candidates`` is an exact pre-filter, not a heuristic: a row can only
        # match one of ``terms`` if it matches the union those candidates were
        # built from, so passing it never changes the result.  `_propose_scanned`
        # uses it because scanning all 38,422 rows of the real corpus once per
        # profile (20 profiles, 94 terms) cost 10.7 s per `propose`, and
        # `propose` runs once per investigation-loop iteration - measured 17.8
        # minutes per 100 iterations, which is the observed stall.
        folded_terms = tuple(term.casefold() for term in terms)
        if not folded_terms:
            return []
        source = rows if candidates is None else candidates
        matched: list[Mapping[str, object]] = []
        for row in source:
            haystack = self._row_scan_text(row)
            for term in folded_terms:
                if term in haystack:
                    matched.append(row)
                    break
        return matched

    @staticmethod
    def _contains(text: str, *terms: str) -> bool:
        normalized = text.casefold()
        return any(term.casefold() in normalized for term in terms)

    @classmethod
    def _has_decode_material(cls, rows: Iterable[Mapping[str, object]]) -> bool:
        """Require an observed transform input before scheduling a decode replay.

        A function name containing ``decode`` or a broad crypto import is a
        useful lead, but it is not a replayable decode candidate.  Treating it
        as one consumed a scarce investigation action and reliably returned
        ``NO_NEW_EVIDENCE`` on ordinary PE helper functions.  The static
        extractors emit these three evidence kinds only when they have
        recovered a bounded candidate window, encoded object, or concrete
        crypto transform for inspection.
        """
        return any(
            str(row.get("kind", ""))
            in DeepMiningPlanner._DECODE_MATERIAL_KINDS
            for row in rows
        )

    def propose(
        self,
        *,
        evidence: Iterable[Mapping[str, object]],
        scheduled: set[str],
    ) -> tuple[ActionSuggestion, ...]:
        rows = list(evidence)
        result: list[ActionSuggestion] = []
        # One pass, one projection, one scan memo.  Everything below reuses the
        # same case-folded corpus text and per-row haystacks instead of
        # rebuilding them for each of the ~114 term scans this pass performs.
        #
        # A cross-iteration fold cache was tried here and REMOVED: measured
        # 9.62 s steady-state cached vs 9.54 s uncached (0.99x, i.e. nothing).
        # Folding all 38.4k rows costs only ~0.9 s of the ~10 s `propose`, so
        # caching it cannot matter.  The cost is the union scan's per-row term
        # tests, not the fold.  Do not re-add without measuring.
        self._reset_scan_memo()
        try:
            return self._propose_scanned(rows=rows, scheduled=scheduled, result=result)
        finally:
            self._reset_scan_memo()

    def _propose_scanned(
        self,
        *,
        rows: list[Mapping[str, object]],
        scheduled: set[str],
        result: list[ActionSuggestion],
    ) -> tuple[ActionSuggestion, ...]:
        text, corpus_kinds = self._corpus_projection(rows)
        target = self._concrete_target(rows)
        has_function_anchor = bool(self._first_static_target(rows))
        latch = packer_latch_active(rows)
        suppress_stub = latch and not unpack_completed(rows)
        stub_apis = stub_import_names(rows) if latch else frozenset()
        reconstructed_apis = set(reconstructed_import_names(rows)) if latch else set()
        if (
            latch
            and target
            and normalize_api_symbol(target) in stub_apis
            and (suppress_stub or normalize_api_symbol(target) not in reconstructed_apis)
        ):
            # Stub IAT names are not payload investigation selectors.
            target = ""
            if suppress_stub:
                has_function_anchor = False

        def add(
            action_type: ActionType,
            priority: int,
            reason: str,
            *,
            action_target: str = "",
            expected: tuple[str, ...] = (),
            success: str = "new_targeted_evidence",
            source_rows: Iterable[Mapping[str, object]] = (),
            plan: Mapping[str, object] | None = None,
        ) -> None:
            parameters: dict[str, object] = {"target": action_target} if action_target else {}
            suggestion = ActionSuggestion(
                action_type=action_type,
                priority=priority,
                reason=reason,
                parameters=parameters,
                expected_evidence_kinds=expected,
                success_condition=success,
                source_evidence_ids=self._evidence_ids(source_rows),
                plan=dict(plan or {}),
            )
            if not investigation_is_scheduled(
                suggestion.action_type, suggestion.parameters, suggestion.plan, scheduled
            ) and suggestion.dedupe_key not in {item.dedupe_key for item in result}:
                result.append(suggestion)

        # One Playbook scan per pass.  The profile selection below and the
        # per-profile target expansion further down both need exactly this
        # result, and a second scan would re-walk the whole corpus text.
        matched_playbooks = self.playbooks.matching(
            rows, folded_text=text, folded_kinds=corpus_kinds
        )
        profiles = {item.id for item in matched_playbooks}
        if "ppid-process-chain" in profiles:
            has_openprocess_call = any(
                str(row.get("kind")) == "function_call"
                and "openprocess" in self._row_value_text(row)
                for row in rows
            )
            has_attribute_call = any(
                str(row.get("kind")) == "function_call"
                and "updateprocthreadattribute" in self._row_value_text(row)
                for row in rows
            )
            has_parent_constant = any(
                str(row.get("kind")) == "constant"
                and any(
                    term in self._row_value_text(row)
                    for term in (
                        "proc_thread_attribute_parent_process",
                        "0x00020000",
                    )
                )
                for row in rows
            )
            if not has_openprocess_call:
                openprocess_rows = self._matching_rows(rows, "openprocess")
                add(
                    ActionType.GET_XREFS_TO,
                    10,
                    "Resolve an artifact-local OpenProcess callsite before following the process chain.",
                    action_target="OpenProcess",
                    expected=("xref", "function_context"),
                    source_rows=openprocess_rows,
                )
            elif not has_attribute_call:
                openprocess_rows = self._matching_rows(rows, "openprocess")
                add(
                    ActionType.GET_CALLEES,
                    12,
                    "Resolve the static continuation from OpenProcess to its handle consumers.",
                    action_target="OpenProcess",
                    expected=("function_call", "function_context"),
                    source_rows=openprocess_rows,
                )
            elif not has_parent_constant:
                attribute_rows = self._matching_rows(rows, "updateprocthreadattribute")
                add(
                    ActionType.EVALUATE_CONSTANT,
                    14,
                    "Evaluate the process-attribute constant at the UpdateProcThreadAttribute path.",
                    action_target="UpdateProcThreadAttribute",
                    expected=("constant", "function_call"),
                    source_rows=attribute_rows,
                )

        if "dynamic-api-resolution" in profiles and not suppress_stub:
            for api in ("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrGetProcedureAddress"):
                if api.casefold() in text:
                    api_rows = self._matching_rows(rows, api)
                    api_function_target = self._first_static_target(api_rows)
                    add(
                        ActionType.GET_XREFS_TO,
                        20,
                        f"Resolve static Xrefs to {api} before inferring dynamically resolved behavior.",
                        action_target=api,
                        expected=("xref", "function_context", "data_reference"),
                        source_rows=api_rows,
                    )
                    if api_function_target:
                        add(
                            ActionType.GET_PCODE_SLICE,
                            22,
                            f"Inspect the bounded static argument/return slice around {api}.",
                            action_target=api_function_target,
                            expected=("pcode_slice", "function_context"),
                            source_rows=api_rows,
                        )

        if "xor-config-recovery" in profiles:
            decode_rows = [
                row
                for row in rows
                if str(row.get("kind", ""))
                in DeepMiningPlanner._DECODE_MATERIAL_KINDS
            ]
            if self._has_decode_material(decode_rows):
                decode_target = self._concrete_target(decode_rows) or target or "xor"
                add(
                    ActionType.GET_DATA_REFERENCES,
                    24,
                    "Resolve data references for the statically observed decode candidate.",
                    action_target=decode_target,
                    expected=("data_reference", "function_context"),
                    source_rows=decode_rows,
                )
                add(
                    ActionType.GET_PCODE_SLICE,
                    26,
                    "Obtain a bounded P-code slice for the decode candidate.",
                    action_target=decode_target,
                    expected=("pcode_slice", "function_instruction_window"),
                    source_rows=decode_rows,
                )
                add(
                    ActionType.DECODE_CANDIDATE,
                    28,
                    "Attempt only deterministic, bounded static decode validation.",
                    action_target=decode_target,
                    expected=("decode_result", "decode_candidate"),
                    source_rows=decode_rows,
                )

        if "entrypoint-timeline" in profiles:
            entry_target = target or "entrypoint"
            if not has_function_anchor:
                add(
                    ActionType.GET_FUNCTION,
                    30,
                    "Resolve the static entrypoint function before constructing an ordered timeline.",
                    action_target=entry_target,
                    expected=("function", "function_context"),
                    source_rows=rows,
                )
            add(
                ActionType.GET_CALLEES,
                32,
                "Expand one bounded call-graph step from the static entrypoint.",
                action_target=entry_target,
                expected=("function_call", "function_context"),
                source_rows=rows,
            )
            add(
                ActionType.GET_CFG_SLICE,
                34,
                "Read a bounded CFG slice to preserve conditional timeline limits.",
                action_target=entry_target,
                expected=("cfg_block", "function_context"),
                source_rows=rows,
            )

        # Every matching v3 profile is an independent investigation question.
        # The older ``if not result`` guard silently discarded a process,
        # network, decoder or anti-analysis lead whenever a resolver playbook
        # happened to run first.  Admit a bounded, profile-local gap action
        # for each concrete target instead.  Queue deduplication still merges
        # equivalent actions, and the loop's hard budget remains authoritative.
        # This is deliberately not model reasoning: profile terms, targets and
        # Evidence citations all come from the static artifact-local corpus.
        matched_profiles = [
            item for item in matched_playbooks if item.id.startswith("v3-")
        ]

        # ``sorted`` evaluates every profile's score before the admission loop
        # starts, so the ranked top-8 below would otherwise repeat the same
        # full-corpus scan it just performed.  Memoise the scan, not the score:
        # admission still re-derives every target from the same row set.
        ranked_profile_rows: dict[str, list[Mapping[str, object]]] = {}

        # Exact pre-filter for every profile scan.  A row can only match a given
        # profile term if it matches at least one term in the union of all profile
        # terms, so scanning the union's matches is equivalent to scanning the
        # corpus - and the union hits only 1,603 of 38,422 rows (4.2%) on the real
        # sample, replacing ~20 full-corpus scans per `propose`.
        #
        # The union scan is itself built in ONE pass rather than term-by-term.
        # `_matching_rows(rows, *union_terms)` tests all 94 terms against every row,
        # which is ~2.4M Python-level substring calls and measured 3.5 s of a 10.7 s
        # `propose` - the single largest remaining item, and the live stack sat in
        # exactly that loop (`_matching_rows` inner term test) for 12+ minutes at
        # 100% CPU.  Building `{term: [rows]}` in one corpus pass and then scanning
        # each retrieved list in corpus order is exactly equivalent and turns the
        # per-row term test from `len(terms)` steps into `len(rows)+hits` total.
        union_terms = tuple(
            {term for profile in matched_profiles for term in profile.trigger_terms}
        )
        candidate_rows: list[Mapping[str, object]] | None = None
        term_row_index: dict[str, list[Mapping[str, object]]] = {}
        if union_terms:
            folded_union = {term.casefold() for term in union_terms}
            # Incremental across iterations.  The investigation loop calls `propose`
            # once per iteration and the corpus it passes grows by only the rows an
            # action produced; the ~38k static analysis rows are the SAME objects
            # every time.  Re-testing all 94 terms against all 38,407 rows costs
            # 3.05 s per pass, measured, and that is the dominant term in a ~10 s
            # `propose` - the container shape is irrelevant (setdefault / dict.get /
            # hoisted lookup all measured 2.9-3.1 s; "term tests only" measured
            # 3.05 s).  Caching each row's matched terms and re-testing only rows not
            # seen before turns the per-iteration cost into O(delta).
            #
            # This is exactly equivalent, not an approximation: a row's haystack is
            # a pure function of the row, so a row re-tested would yield the same
            # term set.  The cache is invalidated whenever the corpus is not a
            # superset of the previous one, and it holds strong references so a
            # recycled `id()` cannot alias a different row.
            previous_rows, row_terms_cache = self._term_scan_cache
            reusable = (
                previous_rows is not None
                and len(rows) >= len(previous_rows)
                and all(
                    a is b for a, b in zip(previous_rows, rows[: len(previous_rows)])
                )
            )
            if reusable:
                row_term_sets = dict(row_terms_cache)
            else:
                row_term_sets = {}
            fresh: set[int] = set()
            for row in rows:
                key = id(row)
                if key not in row_term_sets:
                    fresh.add(key)
            new_terms: dict[int, frozenset[str]] = {}
            for row in rows:
                key = id(row)
                if key not in fresh:
                    continue
                haystack = self._row_scan_text(row)
                new_terms[key] = frozenset(
                    term for term in folded_union if term in haystack
                )
            row_term_sets.update(new_terms)
            for row in rows:
                for term in row_term_sets.get(id(row), frozenset()):
                    term_row_index.setdefault(term, []).append(row)
            # Retain rows and their term sets for the next iteration.
            self._term_scan_cache = (rows, row_term_sets)

            # Preserve corpus order across the union of every term's matches.
            matched_ids = {
                id(row) for bucket in term_row_index.values() for row in bucket
            }
            candidate_rows = [row for row in rows if id(row) in matched_ids]

        def profile_scan(profile: MechanismPlaybook) -> list[Mapping[str, object]]:
            cached = ranked_profile_rows.get(profile.id)
            if cached is not None:
                return cached
            folded = tuple(term.casefold() for term in profile.trigger_terms)
            # Union of this profile's terms' buckets, in corpus order.
            allowed = {
                id(row)
                for term in folded
                for row in term_row_index.get(term, ())
            }
            found = [
                row for row in (candidate_rows or []) if id(row) in allowed
            ]
            ranked_profile_rows[profile.id] = found
            return found

        def profile_score(profile: MechanismPlaybook) -> tuple[int, int, str]:
            profile_rows = profile_scan(profile)
            # Count how many of the profile's terms appear in the rows it matched.
            # Built from the single-pass index rather than re-testing every term
            # against every row; a term is present iff its bucket is non-empty.
            matched_terms = sum(
                1
                for term in profile.trigger_terms
                if term_row_index.get(term.casefold())
            )
            return (-matched_terms, -len(profile_rows), profile.id)

        for profile_index, profile in enumerate(sorted(matched_profiles, key=profile_score)[:8]):
            profile_rows = profile_scan(profile)
            profile_target = self._concrete_target(profile_rows)
            if not profile_target:
                # A mechanism category is not an executor selector. The
                # deep-mining frontier may still find a concrete target
                # later, but this Playbook must not queue an empty probe.
                continue
            if (
                latch
                and normalize_api_symbol(profile_target) in stub_apis
                and (suppress_stub or normalize_api_symbol(profile_target) not in reconstructed_apis)
            ):
                continue
            profile_function_target = self._first_static_target(profile_rows)
            if not profile_function_target:
                # A playbook may recognize a high-risk import before a
                # callsite has been recovered.  Defer every function-only
                # probe until a bounded Xref gives it an RVA/function anchor.
                # This maintains breadth while preventing a category match
                # from turning into several duplicate import-table queries.
                add(
                    ActionType.GET_XREFS_TO,
                    35 + profile_index * 3,
                    f"Resolve a concrete static callsite for the {profile.mechanism_type} hypothesis.",
                    action_target=profile_target,
                    expected=("xref", "function_context"),
                    source_rows=profile_rows,
                    plan={
                        "playbook_id": profile.id,
                        "mechanism_type": profile.mechanism_type,
                        "question": profile.question_templates[0] if profile.question_templates else "Which static callsite anchors this mechanism?",
                        "required_evidence": list(profile.verifier_contract),
                        "stage": "resolve_function_anchor",
                    },
                )
                continue
            profile_target = profile_function_target
            # The declared playbook order encodes the evidence dependency for
            # each mechanism.  A global action-type ranking used to move
            # ``EVALUATE_CONSTANT`` ahead of the CFG probe for process
            # creation, even though no constant was yet observed.  Once a
            # function anchor exists, resolving Xrefs to that same anchor is
            # also redundant; begin with the profile's next discriminating
            # function-local observations instead.
            profile_actions = [
                action_type
                for action_type in profile.preferred_actions
                if action_type != ActionType.GET_XREFS_TO
            ][:2]
            for action_index, action_type in enumerate(profile_actions):
                add(
                    action_type,
                    35 + profile_index * 3 + action_index,
                    f"Collect discriminating evidence for the {profile.mechanism_type} hypothesis.",
                    action_target=profile_target,
                    expected=tuple(profile.required_evidence_kinds[:3]) or ("specialist_observation",),
                    source_rows=profile_rows,
                    plan={
                        "playbook_id": profile.id,
                        "mechanism_type": profile.mechanism_type,
                        "question": profile.question_templates[0] if profile.question_templates else "Which static evidence distinguishes this mechanism?",
                        "required_evidence": list(profile.verifier_contract),
                    },
                )

        # The generic fallback is intentionally evidence-seeking rather than
        # conclusion-seeking.  It gives an unfamiliar mechanism a bounded
        # target/data/call-flow investigation while leaving verification in the
        # UNKNOWN/CANDIDATE state until a specialist contract exists.
        # The generic fallback is intentionally evidence-seeking rather than
        # conclusion-seeking.  It gives an unfamiliar mechanism a bounded
        # target/data/call-flow investigation while leaving verification in the
        # UNKNOWN/CANDIDATE state until a specialist contract exists.
        if not result:
            generic_target = target or self._concrete_target(rows)
            if (
                latch
                and generic_target
                and normalize_api_symbol(generic_target) in stub_apis
                and (
                    suppress_stub
                    or normalize_api_symbol(generic_target) not in reconstructed_apis
                )
            ):
                generic_target = ""
            if generic_target:
                if has_function_anchor:
                    add(
                        ActionType.GET_CALLEES,
                        42,
                        "Follow one bounded call-flow hop from the generic mechanism target.",
                        action_target=generic_target,
                        expected=("function_call", "function_context"),
                        source_rows=rows,
                    )
                    add(
                        ActionType.GET_DATA_REFERENCES,
                        44,
                        "Follow data references to identify inputs, transformations, and consumers.",
                        action_target=generic_target,
                        expected=("data_reference", "value_flow"),
                        source_rows=rows,
                    )
                else:
                    add(
                        ActionType.GET_XREFS_TO,
                        40,
                        "Resolve a concrete static function/RVA before generic deep investigation.",
                        action_target=generic_target,
                        expected=("xref", "function_context"),
                        source_rows=rows,
                    )

        if not result and target:
            add(
                ActionType.GET_XREFS_TO,
                60,
                "Expand exact static references from the current evidence frontier.",
                action_target=target,
                expected=("xref", "function_context"),
                source_rows=rows,
            )
        # The specialist playbooks above provide fast, mechanism-specific
        # routing.  The deep-mining planner adds a bounded best-first set of
        # function-level actions so a PE with several high-value functions still
        # closes the top claim (including isolated emulation) in one pass.  Its
        # actions remain catalog-validated by the caller and are de-duplicated
        # against the already scheduled frontier.
        reserved = set(scheduled)
        for item in result:
            investigation_reserve_scheduled(
                reserved, item.action_type, item.parameters, item.plan, item.dedupe_key
            )
        deep_actions = DeepMiningPlanner.plan_actions(
            rows,
            scheduled=reserved,
            # The default investigation budget is 32. Reserve its capacity
            # for six five-facet high-value contracts instead of truncating
            # the active frontier to four before the loop begins.
            max_actions=32,
        )
        return tuple([*result, *deep_actions])


class Verifier:
    """Independent evidence verifier; only it can return a GateDecision."""

    def __init__(
        self,
        gate: ClaimGate | None = None,
        playbooks: MechanismPlaybookRegistry | None = None,
        behavior_catalog: BehaviorCatalog | None = None,
    ) -> None:
        self.gate = gate or ClaimGate()
        self.playbooks = playbooks or MechanismPlaybookRegistry()
        self.behavior_catalog = behavior_catalog or self.playbooks.behavior_catalog
        # (key, folded corpus text) for `_corpus_text`; see its docstring.
        self._corpus_text_cache: tuple[tuple[int, int, int], str] | None = None
        # {id(row): (row, str(row["value"]))} - the per-row half of the same cache.
        self._row_text_cache: dict[int, tuple[object, str]] = {}

    @staticmethod
    def _contains_api(row: Mapping[str, object], api: str) -> bool:
        value = row.get("value")
        return api.lower() in str(value).lower()

    def _evaluate_playbook(
        self,
        evidence: list[dict[str, object]],
        playbook: MechanismPlaybook,
    ) -> GateDecision:
        entry = self.playbooks.behavior_entry(playbook.id)
        if entry is None:
            # A legacy/custom playbook has no typed behaviour contract.  Its
            # trigger and token thresholds are useful for navigation only;
            # allowing them to reach ClaimGate would reintroduce the old
            # string co-occurrence bypass.  Keep the result explicitly
            # unresolved until a versioned catalogue entry is registered.
            ids = tuple(str(row.get("id")) for row in evidence if row.get("id"))
            return GateDecision(
                False,
                "UNKNOWN",
                "typed behaviour contract is unavailable; legacy thresholds cannot prove a mechanism",
                ids,
                ("typed_behavior_contract",),
            )

        # Every catalogue entry is evaluated before any specialist verifier.
        # This ordering is the Claim Gate boundary: specialist keyword/path
        # logic can add semantic checks, but it cannot promote an observation
        # whose required typed facts or object relations are missing.
        evaluation: ContractEvaluation = entry.contract.evaluate(evidence)
        if not evaluation.accepted:
            return GateDecision(
                False,
                evaluation.status,
                evaluation.reason,
                evaluation.evidence_ids,
                evaluation.missing,
                evaluation.contradictions,
            )

        # The dedicated verifier is the authoritative path for entries that
        # advertise one.  A failed verifier must not fall back to token
        # co-occurrence or a generic candidate promotion.  Typed contract
        # success above is necessary but not sufficient for specialist
        # behaviours.
        if entry.verifier_id and entry.verifier is SupportLevel.SUPPORTED:
            specialized = verify_mechanism(entry.verifier_id, evidence)
            if specialized.accepted:
                return GateDecision(
                    True,
                    "SUPPORTED",
                    specialized.reason or "specialized behaviour verifier accepted",
                    specialized.evidence_ids,
                )
            return GateDecision(
                False,
                specialized.status or "UNKNOWN",
                specialized.reason or "specialized behaviour verifier did not close the contract",
                specialized.evidence_ids,
                specialized.missing,
                tuple(specialized.missing)
                if specialized.status == "CONTRADICTED"
                else (),
            )

        # A generic typed contract is a candidate only.  It must not be
        # represented as a verified specialist until an explicit verifier has
        # been registered and invoked.
        return GateDecision(
            True,
            "CANDIDATE",
            "typed behaviour facts are present; specialized verifier is not registered",
            evaluation.evidence_ids,
            missing=("specialized_verifier",),
        )

    def evaluate_contract(
        self,
        behavior_id: str,
        evidence: Iterable[Mapping[str, object]],
    ) -> GateDecision:
        """Evaluate a versioned behaviour contract through the verifier seam."""

        evaluation = self.behavior_catalog.evaluate(behavior_id, evidence)
        return GateDecision(
            evaluation.accepted,
            evaluation.status,
            evaluation.reason,
            evaluation.evidence_ids,
            evaluation.missing,
            evaluation.contradictions,
        )

    def _corpus_text(self, evidence: Iterable[Mapping[str, object]]) -> str:
        """Case-folded join of every row's ``value``, cached per row and per list.

        Used by `Verifier.evaluate` for the PPID corpus probe and handed to
        `MechanismPlaybookRegistry.matching`/`best_match` so they do not rebuild it.

        Why this matters: the join is O(payload).  On the real sample it produces a
        **71 MB** string, and `evaluate` triggered it repeatedly - once for the ppid
        probe, once inside `matching`, and once inside `best_match`.  A live stack of
        a 20-minute stall sat in this family:

            run -> _evaluate_gate -> Verifier.evaluate -> matching

        Two layers, because the callers pass DIFFERENT lists of the SAME rows:
        `evaluate` joins `evidence` while `best_match` receives `[*evidence, question]`.
        So the join is cached by list identity, and each row's `str(value)` is cached by
        row identity.  Serialising a row is the expensive part on a 2 MB payload, and
        per-row caching makes it happen exactly once no matter how the lists are
        combined.  Both caches hold strong references, so a recycled ``id()`` cannot
        alias a different object.
        """
        rows = evidence if isinstance(evidence, list) else list(evidence)
        if not rows:
            return ""
        list_key = (id(rows), len(rows), id(rows[-1]))
        cached = self._corpus_text_cache
        if cached is not None and cached[0] == list_key:
            return cached[1]
        row_texts = self._row_text_cache
        parts: list[str] = []
        for row in rows:
            key = id(row)
            entry = row_texts.get(key)
            if entry is None or entry[0] is not row:
                entry = (row, str(row.get("value", "")))
                if len(row_texts) >= _ROW_TEXT_CACHE_LIMIT:
                    row_texts.clear()
                row_texts[key] = entry
            parts.append(entry[1])
        text = " ".join(parts).casefold()
        self._corpus_text_cache = (list_key, text)
        return text

    def evaluate(self, evidence: list[dict[str, object]], question: str, statement: str) -> GateDecision:
        text = f"{question} {statement}".lower()
        # The corpus-wide value join is only consulted when the question itself
        # does not already name the PPID mechanism.  Building it eagerly cost a
        # full ``repr``-and-lower pass over every Evidence row on calls that
        # short-circuit on ``text`` alone (a PPID thread names ppid in its
        # question on every gate check).
        named_ppid = any(
            token in text
            for token in ("ppid", "parent process", "parent-process", "explorer.exe")
        )
        # The corpus join is built at most ONCE here and reused by every callee.
        # `a or b()` already evaluated `b()` when it reached the ppid branch, so the
        # old code called `_corpus_text` a second time for the same list; and
        # `matching`/`best_match` each rebuilt their own projection from the rows.
        corpus_text: str | None = None
        ppid = named_ppid
        if not ppid:
            corpus_text = self._corpus_text(evidence)
            ppid = "updateprocthreadattribute" in corpus_text
        if ppid:
            if corpus_text is None:
                corpus_text = self._corpus_text(evidence)
            playbook = next(
                (
                    item
                    for item in self.playbooks.matching(
                        [
                            *evidence,
                            {
                                "kind": "investigation_question",
                                "value": {"question": question, "statement": statement},
                            },
                        ],
                        # Reuse the projection built above.  The appended question row
                        # cannot contribute a trigger term that matters here: the
                        # corpus text already decides the routing, and the caller's own
                        # text covers every evidence row.
                        folded_text=corpus_text,
                    )
                    if item.id == "ppid-process-chain"
                ),
                None,
            )
            if playbook is not None:
                return self._evaluate_playbook(evidence, playbook)
        profile_rows = [
            *evidence,
            {
                "id": "question-profile",
                "kind": "investigation_question",
                "nature": "STATIC_INFERRED",
                "value": {"question": question, "statement": statement},
            },
        ]
        matched = self.playbooks.best_match(
            profile_rows, folded_text=self._corpus_text(evidence)
        )
        if matched:
            return self._evaluate_playbook(evidence, matched)
        ids = tuple(str(row.get("id")) for row in evidence if row.get("id"))
        has_structure = any(str(row.get("kind")) in {"function", "function_context"} for row in evidence)
        has_flow = any(str(row.get("kind")) in {"function_call", "xref", "data_reference", "value_flow"} for row in evidence)
        if has_structure and has_flow:
            return GateDecision(
                accepted=True,
                status="CANDIDATE",
                reason="generic evidence threshold reached; specialized verification is unavailable",
                evidence_ids=ids,
                missing=("specialized_verifier",),
            )
        return GateDecision(
            accepted=False,
            status="UNKNOWN",
            reason="generic mechanism evidence threshold is not met",
            evidence_ids=ids,
            missing=("function_context_or_function", "function_call_or_flow"),
        )


@dataclass(frozen=True)
class InvestigationEvent:
    phase: str
    action_id: str | None
    state: str
    evidence_ids: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class InvestigationResult:
    thread_id: str
    artifact_id: str
    thread_state: InvestigationThreadState
    hypothesis_status: str
    evidence: tuple[dict[str, object], ...]
    events: tuple[InvestigationEvent, ...]
    actions: tuple[ActionSpec, ...]
    gate: GateDecision
    # Process coverage for admitted deep targets. This remains separate from
    # ClaimGate acceptance: a target can be fully inspected and still stay
    # UNKNOWN because static evidence did not prove its mechanism.
    coverage: Mapping[str, object] = field(default_factory=dict)


class InvestigationLoopDriver:
    """Run a bounded Hypothesis -> Action -> Evidence -> Verification loop."""

    def __init__(
        self,
        *,
        max_steps: int = 32,
        max_consecutive_no_gain: int = 2,
        catalog: ActionCatalog | None = None,
    ) -> None:
        self.max_steps = max_steps
        if max_consecutive_no_gain < 1:
            raise ValueError("max_consecutive_no_gain must be positive")
        self.max_consecutive_no_gain = max_consecutive_no_gain
        self.catalog = catalog or ActionCatalog.default()
        self.machine = ThreadStateMachine()
        self.gate = ClaimGate()
        self.investigator = Investigator()
        self.verifier = Verifier(self.gate)

    @staticmethod
    def _has_api(evidence: Iterable[Mapping[str, object]], api: str) -> bool:
        needle = api.lower()
        for row in evidence:
            value = row.get("value")
            if isinstance(value, Mapping):
                for key in ("api", "name", "target_name", "text"):
                    if needle in str(value.get(key, "")).lower():
                        return True
                for key in ("apis", "calls", "functions"):
                    nested = value.get(key)
                    if isinstance(nested, (list, tuple)) and any(needle in str(item).lower() for item in nested):
                        return True
        return False

    @staticmethod
    def _same_function_target(row: Mapping[str, object], target: object) -> bool:
        expected = str(target).strip().casefold()
        if not expected:
            return False
        recovered = DeepMiningPlanner._function_key(row).casefold()
        return recovered == expected

    @classmethod
    def _is_redundant_static_read(
        cls,
        action: ActionSpec,
        evidence: Iterable[Mapping[str, object]],
    ) -> bool:
        """Reuse already recovered function facts instead of rereading them.

        The baseline extractor may have emitted an argument trace or a
        function-call edge before the recursive thread reaches the same
        hypothesis.  Reissuing the identical read is neither an independent
        verification nor new evidence; its correct effect is to keep the
        existing observation in the evidence set and schedule the next
        discriminating action.
        """
        target = dict(action.target_selector).get("target")
        if not isinstance(target, (str, int)) or not str(target).strip():
            return False
        output_kind = {
            ActionType.TRACE_API_ARGUMENT: "api_argument_trace",
            ActionType.GET_CALLEES: "function_call",
        }.get(action.action_type)
        if output_kind is None:
            return False
        return any(
            str(row.get("kind", "")) == output_kind
            and cls._same_function_target(row, target)
            for row in evidence
        )

    @staticmethod
    def _action_target_key(action: ActionSpec) -> str:
        """Return the concrete scope used for convergence and coverage."""
        selector = dict(action.target_selector)
        for key in (
            "function_entry",
            "function",
            "entry",
            "rva",
            "address",
            "api",
            "target",
        ):
            value = selector.get(key)
            if isinstance(value, (str, int)) and str(value).strip():
                return f"{key}:{str(value).strip().casefold()}"
        return action.dedupe_key

    @classmethod
    def _evidence_matches_target(
        cls,
        row: Mapping[str, object],
        target_key: str,
    ) -> bool:
        """Keep a coverage facet artifact-local and target-specific."""
        _, _, target = target_key.partition(":")
        if not target:
            return False
        return cls._same_function_target(row, target) or target in _link_text(row)

    @staticmethod
    def _selector_values(row: Mapping[str, object]) -> set[str]:
        """Return concrete locators carried by one executor result.

        Investigation executors are intentionally supplied as a callback so
        the loop can be used by the service and by deterministic test
        harnesses.  A callback must not be able to turn a query for function
        ``0x1000`` into evidence for function ``0x2000``.  Keep this check
        deliberately small and structural: only fields that can identify a
        function, API, line, or data object are considered locators.
        """
        values: set[str] = set()
        for container_name in ("value", "anchor"):
            container = row.get(container_name)
            if not isinstance(container, Mapping):
                continue
            for key in (
                "target",
                "api",
                "api_name",
                "name",
                "target_name",
                "target_function",
                "function",
                "function_entry",
                "entry",
                "entry_rva",
                "rva",
                "address",
                "caller",
                "callee",
                "line",
                "internal_path",
            ):
                item = container.get(key)
                if isinstance(item, (str, int)) and str(item).strip():
                    values.add(str(item).strip().casefold())
        return values

    @classmethod
    def _produced_row_matches_action(
        cls,
        row: Mapping[str, object],
        action: ActionSpec,
        *,
        allow_unanchored: bool = False,
    ) -> bool:
        """Check that an executor result remains in the action's target scope.

        The service executor already performs target filtering, but this is a
        second-line invariant at the loop boundary.  It matters for model or
        plugin executors, where returning a task-wide row would otherwise be
        counted as progress and could satisfy a deep-coverage contract.  Rows
        with no locator are retained for backwards-compatible lightweight
        callbacks; once a result claims a concrete locator it must match the
        action selector exactly or in the bounded textual representation.
        """
        selector = dict(action.target_selector)
        target_values = {
            str(value).strip().casefold()
            for value in selector.values()
            if isinstance(value, (str, int)) and str(value).strip()
        }
        if not target_values:
            return False

        # An executor callback may be supplied by a model/plugin boundary,
        # rather than the database-backed service executor.  When it carries
        # an explicit artifact identity, enforce it here before considering
        # the row as progress.  Rows without the optional field remain
        # compatible with the in-memory harness and are still constrained by
        # their function/API selector below.  This prevents a same-target
        # observation from another artifact from satisfying a deep contract.
        row_artifact = row.get("artifact_id")
        if row_artifact is None:
            for container_name in ("value", "anchor"):
                container = row.get(container_name)
                if isinstance(container, Mapping) and container.get("artifact_id") is not None:
                    row_artifact = container.get("artifact_id")
                    break
        if row_artifact is not None and str(row_artifact).strip() != str(action.artifact_id).strip():
            return False

        wildcard_targets = {
            "global",
            "file",
            "strings",
            "string",
            "str",
            "file_header",
            "pe_header",
            "pe_headers_and_imports",
            "strings_and_signals",
            "functions_and_xrefs",
            "script",
            "document",
            "carrier",
            "decode",
            "network",
        }
        if target_values & wildcard_targets:
            return True

        # A few legacy callers use the loop as a pure state-machine harness
        # and return compact ``{"kind", "value"}`` rows without provenance.
        # Production Evidence always has an artifact/anchor, so this escape
        # hatch is enabled by ``run`` only when the *initial* frontier is also
        # entirely unanchored.  It keeps those callers source-compatible while
        # retaining strict target filtering for real executor output.
        if allow_unanchored and not isinstance(row.get("anchor"), Mapping):
            return True

        row_values = cls._selector_values(row)
        if row_values:
            if row_values & target_values:
                return True
            # Static exporters and model plans may use different import
            # decoration (for example ``KERNEL32.dll!CreateProcessW`` versus
            # ``CreateProcessW``).  Normalize symbols after the exact locator
            # check so a productive result is not rejected as out-of-scope.
            # ``normalize_api_symbol`` strips only module/thunk decoration;
            # it does not perform fuzzy or substring matching.
            normalized_rows = {
                normalize_api_symbol(value)
                for value in row_values
                if normalize_api_symbol(value)
            }
            normalized_targets = {
                normalize_api_symbol(value)
                for value in target_values
                if normalize_api_symbol(value)
            }
            if normalized_rows & normalized_targets:
                return True
            # A qualified symbol or a decompiler-rendered row may not expose
            # the exact selector in a dedicated field.  The rendered text is
            # still bounded to this row and is safe as a fallback, while
            # direct locator fields above prevent numeric-prefix collisions.
            rendered = _link_text(row)
            return any(
                re.search(
                    rf"(?<![A-Za-z0-9_]){re.escape(target)}(?![A-Za-z0-9_])",
                    rendered,
                    flags=re.IGNORECASE,
                )
                is not None
                for target in target_values
            )

        # An anchored production frontier cannot accept a result that carries
        # no locator at all: there is no way to prove that it belongs to this
        # action's target.  The explicit compatibility flag above is limited
        # to legacy, wholly-unanchored test/harness frontiers.
        return False

    @staticmethod
    def _no_gain_autopsy(
        action: ActionSpec,
        *,
        produced_count: int,
        rejected_count: int = 0,
    ) -> str:
        """Classify a no-gain action without treating absence as refutation."""
        if not action.target_selector:
            return "SELECTOR_ERROR"
        if action.failure_interpretation == FailureInterpretation.STATIC_BOUNDARY:
            return "STATIC_BOUNDARY"
        if rejected_count:
            return "TARGET_SCOPE_MISMATCH"
        if produced_count == 0:
            return "LOW_INFORMATION_ACTION"
        return "DUPLICATE_EVIDENCE"

    @staticmethod
    def _semantic_method_key(action: ActionSpec) -> str:
        return investigation_method_id(action.action_type, action.target_selector, action.plan)

    @classmethod
    def _stamp_method_plan(cls, action: ActionSpec) -> ActionSpec:
        plan = dict(action.plan)
        if plan.get("method_id"):
            return action
        plan.update(
            DeepMiningPlanner._method_plan_fields(
                action.action_type, action.target_selector, plan
            )
        )
        return replace(action, plan=plan)

    @classmethod
    def _apply_failure_contract(
        cls,
        actions: list[ActionSpec],
        action: ActionSpec,
        *,
        outcome: str,
        frontier_before: str,
        frontier_after: str,
        attempted_method_ids: list[str],
        error_type: str | None = None,
    ) -> ActionSpec:
        contract = DeepMiningPlanner.failure_contract(
            action,
            outcome=outcome,
            frontier_before=frontier_before,
            frontier_after=frontier_after,
            existing_method_ids=attempted_method_ids,
            error_type=error_type,
        )
        method_id = str(contract.get("method_id") or "")
        if method_id and method_id not in attempted_method_ids:
            attempted_method_ids.append(method_id)
        updated = replace(action, plan={**dict(action.plan), **contract})
        for index, item in enumerate(actions):
            if item.id == action.id:
                actions[index] = updated
                break
        return updated

    @staticmethod
    def _selector_identity(selector: Mapping[str, object] | None) -> str:
        return investigation_method_id(ActionType.GET_CALLEES, selector)

    @classmethod
    def _block_same_family(
        cls,
        queue: InvestigationQueue,
        action: ActionSpec,
        *,
        target_key: str,
        blocked_method_ids: set[str],
        scheduled: set[str],
        actions: list[ActionSpec],
    ) -> None:
        blocked_method_ids.add(cls._semantic_method_key(action))
        investigation_reserve_scheduled(
            scheduled, action.action_type, action.target_selector, action.plan, action.dedupe_key
        )
        if action.action_type not in _CALL_GRAPH_FAMILY:
            return
        action_identity = cls._selector_identity(action.target_selector)
        dropped_ids: set[str] = set()
        for queued in list(queue.pending):
            if queued.id == action.id:
                continue
            if queued.depends_on and action.id in queued.depends_on:
                continue
            if queued.action_type not in _CALL_GRAPH_FAMILY:
                continue
            if (
                cls._action_target_key(queued) != target_key
                and cls._selector_identity(queued.target_selector) != action_identity
            ):
                continue
            blocked_method_ids.add(cls._semantic_method_key(queued))
            investigation_reserve_scheduled(
                scheduled,
                queued.action_type,
                queued.target_selector,
                queued.plan,
                queued.dedupe_key,
            )
            queue.drop_pending(queued.id)
            dropped_ids.add(queued.id)
        if dropped_ids:
            actions[:] = [item for item in actions if item.id not in dropped_ids]

    @classmethod
    def _next_pending_action(
        cls,
        queue: InvestigationQueue,
        *,
        target_key: str,
        attempted_action_ids: set[str],
        last_action_type: ActionType | None = None,
        blocked_method_ids: Iterable[str] = (),
    ) -> ActionSpec | None:
        blocked = {str(item) for item in blocked_method_ids}
        preferred = ()
        if last_action_type is not None:
            next_name = investigation_next_method(last_action_type)
            if next_name != "STATIC_BOUNDARY":
                try:
                    preferred = (ActionType(next_name),)
                except ValueError:
                    preferred = ()

        def eligible(action: ActionSpec) -> bool:
            if action.id in attempted_action_ids:
                return False
            if cls._semantic_method_key(action) in blocked:
                return False
            if (
                last_action_type in _CALL_GRAPH_FAMILY
                and action.action_type in _CALL_GRAPH_FAMILY
            ):
                return False
            return True

        candidates = [
            action
            for action in queue.pending
            if eligible(action) and cls._action_target_key(action) == target_key
        ]
        if preferred:
            preferred_matches = [
                action for action in candidates if action.action_type in preferred
            ]
            if preferred_matches:
                candidates = preferred_matches
        if not candidates:
            # A dry target should not hide a still-actionable independent
            # target.  The caller records this as the next frontier step; the
            # no-gain threshold remains scoped to the original target.
            candidates = [
                action for action in queue.pending if eligible(action)
            ]
            if preferred:
                preferred_matches = [
                    action for action in candidates if action.action_type in preferred
                ]
                if preferred_matches:
                    candidates = preferred_matches
        if not candidates:
            return None
        return min(candidates, key=lambda item: (item.priority, item.id))

    @classmethod
    def _coverage_snapshot(
        cls,
        actions: Iterable[ActionSpec],
        evidence: Iterable[Mapping[str, object]],
        attempted_action_ids: set[str],
        failed_action_ids: set[str],
    ) -> dict[str, object]:
        """Measure whether each admitted deep target received its required work.

        Process coverage and Claim evidence coverage are deliberately
        separate. An action which was attempted but failed is sufficient to
        record a bounded static limitation; it must never count as evidence
        satisfying the corresponding facet or permit Claim promotion.
        """
        action_rows = tuple(actions)
        evidence_rows = tuple(evidence)
        contracts: dict[str, dict[str, object]] = {}
        for action in action_rows:
            raw = action.plan.get("deep_investigation_contract")
            if not isinstance(raw, Mapping):
                continue
            required = tuple(
                item
                for item in raw.get("required_action_types", ())
                if isinstance(item, str) and item in ActionType._value2member_map_
            )
            if not required:
                continue
            target_key = cls._action_target_key(action)
            entry = contracts.setdefault(
                target_key,
                {
                    "contract_id": str(raw.get("id", "deep-static-v1")),
                    "category": str(raw.get("category", "generic")),
                    "required_action_types": set(),
                    "evidence_kinds_by_action": {},
                    "action_ids": set(),
                },
            )
            entry["required_action_types"].update(required)
            entry["action_ids"].add(action.id)
            evidence_kinds = raw.get("evidence_kinds_by_action", {})
            if isinstance(evidence_kinds, Mapping):
                for action_type, kinds in evidence_kinds.items():
                    if not isinstance(action_type, str) or not isinstance(kinds, (list, tuple)):
                        continue
                    current = entry["evidence_kinds_by_action"].setdefault(action_type, set())
                    current.update(str(kind) for kind in kinds if str(kind).strip())

        targets: list[dict[str, object]] = []
        action_by_id = {action.id: action for action in action_rows}
        for target_key, contract in sorted(contracts.items()):
            required_types = set(contract["required_action_types"])
            attempted_types = {
                action.action_type.value
                for action in action_rows
                if action.id in attempted_action_ids
                and cls._action_target_key(action) == target_key
            }
            failed_types = {
                action.action_type.value
                for action in action_rows
                if action.id in failed_action_ids
                and cls._action_target_key(action) == target_key
            }
            observed_types: set[str] = set()
            for action_type, kinds in contract["evidence_kinds_by_action"].items():
                successful_action_ids = {
                    action.id
                    for action in action_rows
                    if action.id in attempted_action_ids
                    and action.id not in failed_action_ids
                    and action.action_type.value == str(action_type)
                    and cls._action_target_key(action) == target_key
                }
                attempted_type_ids = {
                    action.id
                    for action in action_rows
                    if action.id in attempted_action_ids
                    and action.action_type.value == str(action_type)
                    and cls._action_target_key(action) == target_key
                }
                failed_type_ids = attempted_type_ids & failed_action_ids
                if any(
                    str(row.get("kind", "")) in kinds
                    and cls._evidence_matches_target(row, target_key)
                    and (
                        # Derived rows are explicitly attributed by the
                        # driver.  Do not let a generic trace emitted by one
                        # action satisfy a different facet (for example a
                        # DECOMPILE trace counting as CFG coverage).
                        not (
                            row.get("source_action_id")
                            or (
                                isinstance(row.get("anchor"), Mapping)
                                and row.get("anchor", {}).get("investigation_action_id")
                            )
                        )
                        or (
                            str(
                                row.get("source_action_id")
                                or (
                                    row.get("anchor", {}).get("investigation_action_id")
                                    if isinstance(row.get("anchor"), Mapping)
                                    else ""
                                )
                            )
                            in successful_action_ids
                            and action_by_id.get(
                                str(
                                    row.get("source_action_id")
                                    or (
                                        row.get("anchor", {}).get("investigation_action_id")
                                        if isinstance(row.get("anchor"), Mapping)
                                        else ""
                                    )
                                )
                            )
                            is not None
                            and action_by_id[
                                str(
                                    row.get("source_action_id")
                                    or (
                                        row.get("anchor", {}).get("investigation_action_id")
                                        if isinstance(row.get("anchor"), Mapping)
                                        else ""
                                    )
                                )
                            ].action_type.value
                            == str(action_type)
                        )
                    )
                    and (
                        # Existing parser evidence may satisfy a facet when
                        # every attempt for that facet completed normally,
                        # including a legitimate no-new-evidence result.  Once
                        # an executor exception occurs, however, only evidence
                        # explicitly produced by a successful replacement
                        # action can satisfy the facet.
                        not failed_type_ids
                        or str(
                            row.get("source_action_id")
                            or (
                                row.get("anchor", {}).get("investigation_action_id")
                                if isinstance(row.get("anchor"), Mapping)
                                else ""
                            )
                        ) in successful_action_ids
                    )
                    for row in evidence_rows
                ):
                    observed_types.add(str(action_type))
            # A failed executor call is not a completed facet.  Successful
            # no-result actions remain part of the process coverage so the
            # loop can close them as a bounded static limitation, but an
            # exception must leave the facet open and ineligible for Claim
            # promotion.  Keeping failed types out of this set prevents the
            # audit projection from describing an unexecuted probe as covered.
            successful_attempted_types = attempted_types - failed_types
            process_covered_types = successful_attempted_types | observed_types
            pending_types = sorted(required_types - process_covered_types)
            missing_evidence_types = sorted(required_types - observed_types)
            evidence_complete = not missing_evidence_types and not failed_types
            # A failed executor is a method gap, not a static boundary.  M02:
            # STATIC_BOUNDARY only after S1-S3 were attempted or marked
            # N/A/unsupported.  Empty required + empty attempted is not an
            # auditable trail and must not close S4.  API names, strings, or
            # one NO_NEW_EVIDENCE result cannot close the ladder.
            all_required_attempted = not pending_types and not failed_types
            ladder = s_ladder(
                attempted_action_types=attempted_types,
                required_action_types=required_types,
                failed_action_types=failed_types,
                pending_action_types=pending_types,
            )
            if evidence_complete:
                evidence_status = "EVIDENCE_COMPLETE"
            elif (
                all_required_attempted
                and len(required_types) > 1
                and may_record_static_boundary(ladder)
            ):
                evidence_status = "STATIC_BOUNDARY"
            else:
                evidence_status = "EVIDENCE_GAP"
            targets.append(
                {
                    "target": target_key,
                    "contract_id": contract["contract_id"],
                    "category": contract["category"],
                    "required_action_types": sorted(required_types),
                    "attempted_action_types": sorted(attempted_types),
                    "failed_action_types": sorted(failed_types),
                    "observed_action_types": sorted(observed_types),
                    "pending_action_types": pending_types,
                    "missing_evidence_action_types": missing_evidence_types,
                    "s_ladder": ladder,
                    "evidence_status": evidence_status,
                    "status": "COVERED" if not pending_types else "OPEN",
                }
            )
        attempted_all = {
            action.action_type.value
            for action in action_rows
            if action.id in attempted_action_ids
        }
        failed_all = {
            action.action_type.value
            for action in action_rows
            if action.id in failed_action_ids
        }
        required_all = {
            item
            for contract in contracts.values()
            for item in contract["required_action_types"]
        }
        pending_all = {
            item
            for target in targets
            for item in target.get("pending_action_types", [])
        }
        protocol = fill_protocol(evidence_rows)
        merged_ladder = s_ladder(
            attempted_action_types=attempted_all,
            required_action_types=required_all,
            failed_action_types=failed_all,
            pending_action_types=pending_all,
        )
        return {
            # No deep-mining contract means the ordinary ClaimGate remains
            # authoritative.  An empty contract set is therefore vacuously
            # complete rather than an artificial blocker for legacy/generic
            # investigations.
            "complete": all(item["status"] == "COVERED" for item in targets),
            # A generic Candidate Gate may be true before a deep contract has
            # recovered all required facts. Only this stricter signal permits
            # a Claim-ready state for contracted targets.
            "evidence_complete": all(
                item["evidence_status"] == "EVIDENCE_COMPLETE" for item in targets
            ),
            "claim_eligible": all(
                item["evidence_status"] == "EVIDENCE_COMPLETE" for item in targets
            ),
            "target_count": len(targets),
            "targets": targets,
            "s_ladder": merged_ladder,
            "protocol": protocol,
        }

    def _next_actions(
        self,
        *,
        thread_id: str,
        hypothesis_id: str,
        artifact_id: str,
        evidence: list[dict[str, object]],
        scheduled: set[str],
        sequence: int,
        blocked_method_ids: Iterable[str] = (),
    ) -> tuple[ActionSpec, ...]:
        proposed = self.investigator.propose(evidence=evidence, scheduled=scheduled)
        blocked = {str(item) for item in blocked_method_ids}
        actions: list[ActionSpec] = []
        for offset, suggestion in enumerate(proposed):
            candidate = ActionSpec(
                id=f"{thread_id}:action:{sequence + offset}:{suggestion.action_type.value.lower()}",
                action_type=suggestion.action_type,
                thread_id=thread_id,
                hypothesis_id=hypothesis_id,
                artifact_id=artifact_id,
                priority=suggestion.priority,
                reason=suggestion.reason,
                parameters=suggestion.parameters,
                target_selector={
                    key: value
                    for key, value in suggestion.parameters.items()
                    if key in {"target", "api", "function", "function_entry", "entry", "rva", "address"}
                    and isinstance(value, (str, int))
                },
                expected_evidence_kinds=suggestion.expected_evidence_kinds,
                success_condition=suggestion.success_condition,
                failure_interpretation=suggestion.failure_interpretation,
                cost_units=self.catalog.require(suggestion.action_type).cost_units,
                source_evidence_ids=suggestion.source_evidence_ids,
                plan=dict(suggestion.plan),
            )
            # Sequence numbers restart on a fresh invocation. Include the
            # normalized work identity so a different target cannot collide
            # with a completed action from an earlier invocation.
            candidate = replace(
                candidate,
                id=f"{candidate.id}:{hashlib.sha256(candidate.dedupe_key.encode()).hexdigest()[:16]}",
            )
            candidate = self._stamp_method_plan(candidate)
            # Suggestions can arrive through both a specialist playbook and
            # the generic deep-mining frontier.  Compare the *normalized*
            # ActionSpec key rather than the pre-normalization suggestion key
            # so ``target`` / ``function_entry`` aliases cannot replay work.
            # Reason text is not part of the semantic method identity, so a
            # rewritten GET_CALLEES cannot re-enter after no-gain.
            if (
                not investigation_is_scheduled(
                    candidate.action_type, candidate.target_selector, candidate.plan, scheduled
                )
                and self._semantic_method_key(candidate) not in blocked
                and not self._is_redundant_static_read(candidate, evidence)
            ):
                actions.append(candidate)
        return tuple(actions)

    def _evaluate_gate(self, evidence: list[dict[str, object]], question: str, statement: str) -> GateDecision:
        return self.verifier.evaluate(evidence, question, statement)

    @staticmethod
    def _is_decode_config_thread(
        evidence: Iterable[Mapping[str, object]],
        question: str,
        hypothesis_statement: str,
    ) -> bool:
        blob = f"{question} {hypothesis_statement}".casefold()
        if any(token in blob for token in ("decode", "xor", "decrypt", "plaintext", "ciphertext")):
            return True
        decode_kinds = {"encoded_blob", "decode_result", "mechanism_decode_window"}
        return any(str(row.get("kind") or "").casefold() in decode_kinds for row in evidence)

    @classmethod
    def _record_join_attempt_if_needed(
        cls,
        evidence: list[dict[str, object]],
        *,
        attempted_action_types: set[ActionType],
        question: str,
        hypothesis_statement: str,
        thread_id: str,
    ) -> None:
        """Audit Join attempts that this loop actually ran; never invent action types."""
        if not cls._is_decode_config_thread(evidence, question, hypothesis_statement):
            return
        verification = verify_xor_mechanism(evidence)
        missing = {str(item) for item in verification.missing}
        if verification.status == "VERIFIED" or not missing.intersection({"join", "consumer"}):
            return
        ran = tuple(
            dict.fromkeys(
                action_type.value
                for action_type in attempted_action_types
                if action_type.value in _JOIN_ATTEMPT_ACTION_TYPES
            )
        )
        row = {
            "id": f"{thread_id}:investigation_attempt:join",
            "kind": "investigation_attempt",
            "nature": "STATIC_DERIVED",
            "value": {
                "attempted_action_types": list(ran),
                "missing": [item for item in ("join", "consumer") if item in missing],
            },
        }
        existing = next(
            (
                index
                for index, item in enumerate(evidence)
                if str(item.get("kind") or "") == "investigation_attempt"
                and str(item.get("id") or "").endswith(":investigation_attempt:join")
            ),
            None,
        )
        if existing is None:
            evidence.append(row)
        else:
            evidence[existing] = row

    def run(
        self,
        *,
        thread_id: str,
        artifact_id: str,
        question: str,
        hypothesis_id: str,
        hypothesis_statement: str,
        initial_evidence: Iterable[Mapping[str, object]] = (),
        execute: Callable[[ActionSpec], Iterable[Mapping[str, object]]] | None = None,
        proposed_actions: Iterable[ActionSpec] = (),
        initial_scheduled: Iterable[str] = (),
        initial_completed_action_ids: Iterable[str] = (),
        allow_investigator_actions: bool = True,
        should_stop: Callable[[], bool] | None = None,
        sequence_start: int = 0,
        max_steps: int | None = None,
        blocked_method_ids: set[str] | None = None,
    ) -> InvestigationResult:
        if execute is None:
            def execute(_action: ActionSpec) -> Iterable[Mapping[str, object]]:
                return ()
        step_budget = self.max_steps if max_steps is None else int(max_steps)
        if step_budget < 1:
            raise ValueError("max_steps must be positive")
        evidence = [dict(row) for row in initial_evidence]
        evidence_ids = {
            str(row.get("id")) for row in evidence if row.get("id")
        }
        legacy_unanchored_frontier = bool(evidence) and not any(
            isinstance(row.get("anchor"), Mapping)
            or row.get("artifact_id")
            for row in evidence
        )
        state = InvestigationThreadState.DISCOVERED
        events: list[InvestigationEvent] = []
        actions: list[ActionSpec] = []
        queue = InvestigationQueue(
            max_steps=step_budget, initial_completed=initial_completed_action_ids
        )
        # Persisted callers can provide the artifact-local action frontier so
        # repeated invocations/parallel seed threads do not spend their
        # bounded budget replaying identical queries.
        scheduled: set[str] = {str(item) for item in initial_scheduled if str(item).strip()}
        evidence_signatures = {
            str((row.get("kind"), row.get("value"), row.get("anchor"))) for row in evidence
        }
        no_gain_by_target: dict[str, int] = {}
        attempted_action_types: set[ActionType] = set()
        attempted_action_ids: set[str] = set()
        failed_action_ids: set[str] = set()
        blocked_method_ids = blocked_method_ids if blocked_method_ids is not None else set()
        attempted_method_ids: list[str] = []
        k02_status = ""
        # Explicitly supplied actions (for example an approved model/human
        # plan) may justify one final complementary probe after a no-gain
        # streak.  Automatically generated broad frontiers may not: otherwise
        # a dry seed burns its whole budget merely because it contains many
        # action families, which looks like depth without recovering evidence.
        explicit_action_ids: set[str] = set()
        stop_event_emitted = False

        def stop_requested() -> bool:
            """Poll cooperative cancellation at every investigation boundary."""
            nonlocal stop_event_emitted
            if should_stop is None:
                return False
            try:
                requested = bool(should_stop())
            except Exception:
                # A status probe must never turn a static investigation into
                # an unhandled failure. The next boundary can retry the probe.
                return False
            if requested and not stop_event_emitted:
                stop_event_emitted = True
                events.append(
                    InvestigationEvent(
                        "cancelled",
                        None,
                        state.value,
                        (),
                        "investigation stopped because the task was cancelled",
                    )
                )
            return requested

        def move(target: InvestigationThreadState, message: str) -> None:
            nonlocal state
            state = self.machine.transition(state, target)
            events.append(InvestigationEvent("state", None, state.value, (), message))

        move(InvestigationThreadState.PRIORITIZED, "seed ranked for investigation")
        move(InvestigationThreadState.CONTEXT_READY, "question-centric context assembled")
        move(InvestigationThreadState.HYPOTHESIZING, hypothesis_statement)
        if sequence_start < 0:
            raise ValueError("sequence_start must be non-negative")
        sequence = sequence_start
        rejected_actions: list[dict[str, object]] = []

        def admitted(candidate: ActionSpec) -> bool:
            """Whether the catalog contract admits this action, recording a rejection.

            A malformed action is a fact about THAT ACTION, not about the sample.  Measured on
            task `0291d4b1`: the unguarded `self.catalog.validate(...)` below raised
            `GET_DECOMPILE parameters must equal its target selector`, which propagated out of the
            analysis and failed the run with `report_available: false`, discarding 1,636 evidence
            rows.  One bad action must cost one action: the violation is recorded so a reviewer can
            tell a rejected method from one that was never proposed, and the loop keeps working the
            remaining frontier.
            """
            try:
                self.catalog.validate(candidate)
            except (ValueError, PermissionError) as exc:
                rejected_actions.append(
                    {
                        "action_id": candidate.id,
                        "action_type": candidate.action_type.value,
                        "reason": str(exc),
                        "target_selector": dict(candidate.target_selector),
                    }
                )
                return False
            return True

        for proposed in proposed_actions:
            if stop_requested():
                break
            stamped = self._stamp_method_plan(proposed)
            if not admitted(stamped):
                continue
            # ``initial_scheduled`` is the durable artifact-local frontier.
            # Explicit/model actions arrive through this path on replay, so
            # they must obey the same normalized de-duplication rule as
            # investigator suggestions.  Previously only the in-memory
            # queue rejected duplicate IDs; a new thread/round could replay
            # the same action with a different ID and spend its budget on a
            # known ``NO_NEW_EVIDENCE`` query.
            if investigation_is_scheduled(
                stamped.action_type, stamped.target_selector, stamped.plan, scheduled
            ):
                continue
            if self._semantic_method_key(stamped) in blocked_method_ids:
                continue
            if queue.enqueue(stamped):
                actions.append(stamped)
                scheduled.add(stamped.dedupe_key)
                explicit_action_ids.add(stamped.id)
                sequence += 1
        while state not in {InvestigationThreadState.CLAIM_READY, InvestigationThreadState.UNKNOWN}:
            if stop_requested():
                break
            if allow_investigator_actions:
                for action in self._next_actions(
                    thread_id=thread_id,
                    hypothesis_id=hypothesis_id,
                    artifact_id=artifact_id,
                    evidence=evidence,
                    scheduled=scheduled,
                    sequence=sequence,
                    blocked_method_ids=blocked_method_ids,
                ):
                    if not admitted(action):
                        continue
                    if self._semantic_method_key(action) in blocked_method_ids:
                        continue
                    if investigation_is_scheduled(
                        action.action_type, action.target_selector, action.plan, scheduled
                    ):
                        continue
                    if queue.enqueue(action):
                        actions.append(action)
                        scheduled.add(action.dedupe_key)
                        sequence += 1
            action = queue.pop()
            # A retired method must not re-execute merely because a sibling
            # mechanism scope already queued the identical query in this pass.
            # ``blocked_method_ids`` is this loop's own retirement set (a
            # method that returned no new evidence for this frontier), and the
            # executor is selector-scoped and never reads ``action.plan``, so a
            # scope-relabelled duplicate can only return
            # ``EVIDENCE_ALREADY_PRESENT``.  Measured on storm task
            # `e53de9f7`: 46 of 144 executed actions were exactly that reuse,
            # with ``gain_class=REUSED_CONTEXT`` and ``evidence_delta=0``.
            while (
                action is not None
                and self._semantic_method_key(action) in blocked_method_ids
            ):
                action = queue.pop()
            if action is None:
                gate = self._evaluate_gate(evidence, question, hypothesis_statement)
                coverage = self._coverage_snapshot(
                    actions, evidence, attempted_action_ids, failed_action_ids
                )
                if gate.accepted and coverage["claim_eligible"]:
                    if state == InvestigationThreadState.HYPOTHESIZING:
                        # Initial deterministic evidence may already satisfy
                        # the gate when the model-only executor has no valid
                        # action. Preserve the lifecycle by recording that
                        # investigation was entered before verification.
                        move(InvestigationThreadState.INVESTIGATING, "initial evidence satisfied the investigation gate")
                    move(InvestigationThreadState.VERIFYING, gate.reason)
                    move(InvestigationThreadState.MECHANISM_READY, "mechanism evidence threshold satisfied")
                    move(InvestigationThreadState.CLAIM_READY, "hypothesis is eligible for Claim upgrade")
                else:
                    if state == InvestigationThreadState.HYPOTHESIZING:
                        move(InvestigationThreadState.INVESTIGATING, "no action was available before verification")
                    if gate.accepted and coverage["target_count"]:
                        events.append(
                            InvestigationEvent(
                                "static_boundary",
                                None,
                                state.value,
                                (),
                                "claim candidate was not promoted because required deep static evidence "
                                "was incomplete or a required action reached a static boundary",
                            )
                        )
                    move(InvestigationThreadState.UNKNOWN, gate.reason)
                break
            if stop_requested():
                break
            if state == InvestigationThreadState.HYPOTHESIZING:
                move(InvestigationThreadState.INVESTIGATING, "first investigation action dequeued")
            attempted_action_types.add(action.action_type)
            attempted_action_ids.add(action.id)
            action = self._stamp_method_plan(action)
            frontier_before = investigation_frontier_fingerprint(evidence)
            try:
                raw_produced = [dict(item) for item in execute(action)]
            except Exception as exc:  # executor errors become auditable unknowns
                queue.fail(action.id)
                failed_action_ids.add(action.id)
                target_key = self._action_target_key(action)
                action = self._apply_failure_contract(
                    actions,
                    action,
                    outcome="EXECUTOR_FAILURE",
                    frontier_before=frontier_before,
                    frontier_after=investigation_frontier_fingerprint(evidence),
                    attempted_method_ids=attempted_method_ids,
                    error_type=type(exc).__name__,
                )
                self._block_same_family(
                    queue,
                    action,
                    target_key=target_key,
                    blocked_method_ids=blocked_method_ids,
                    scheduled=scheduled,
                    actions=actions,
                )
                events.append(InvestigationEvent("action_failed", action.id, state.value, (), str(exc)))
                continue
            # Enforce the target boundary at the loop seam as well as in the
            # service executor.  An unrelated row must not look like progress
            # merely because a model/plugin returned a non-empty list.
            produced = [
                row
                for row in raw_produced
                if self._produced_row_matches_action(
                    row,
                    action,
                    allow_unanchored=legacy_unanchored_frontier,
                )
            ]
            rejected_count = len(raw_produced) - len(produced)
            if rejected_count:
                events.append(
                    InvestigationEvent(
                        "action_output_rejected",
                        action.id,
                        state.value,
                        (),
                        f"rejected {rejected_count} executor result(s) outside target scope",
                    )
                )
            new_ids: list[str] = []
            novel_count = 0
            for offset, row in enumerate(produced):
                row.setdefault("id", f"{action.id}:evidence:{offset}")
                row.setdefault("nature", "STATIC_OBSERVED")
                row.setdefault("source_action_id", action.id)
                row.setdefault("source_action_type", action.action_type.value)
                signature = str((row.get("kind"), row.get("value"), row.get("anchor")))
                if signature not in evidence_signatures:
                    evidence_signatures.add(signature)
                    novel_count += 1
                # A reused row is the *same* durable observation, carrying the
                # same payload; the executor returns it with its original id
                # (``reused=True``).  Appending a second copy adds no
                # information to the frontier but does add a full payload copy
                # to every later corpus projection: one ``propose``/``evaluate``
                # pass costs ~0.12/0.22 s per MB of accumulated value text, and
                # the loop's own decompile/CFG/pcode payloads are the bulk of
                # it.  Measured on storm task `e53de9f7`, 46 of 144 executed
                # actions returned only already-present rows, and the repeated
                # scope variants re-appended the same multi-KB blobs.
                # ``run_until_converged`` already collapses the frontier by id
                # between rounds, so this only makes a round agree with the
                # frontier it hands to the next one.
                row_id = str(row["id"])
                if row_id not in evidence_ids:
                    evidence_ids.add(row_id)
                    evidence.append(row)
                new_ids.append(row_id)
            queue.complete(action.id)
            events.append(InvestigationEvent("action_completed", action.id, state.value, tuple(new_ids), action.reason))
            target_key = self._action_target_key(action)
            if novel_count:
                no_gain_by_target[target_key] = 0
            else:
                no_gain_by_target[target_key] = no_gain_by_target.get(target_key, 0) + 1
                no_gain_streak = no_gain_by_target[target_key]
                action = self._apply_failure_contract(
                    actions,
                    action,
                    outcome="NO_NEW_EVIDENCE",
                    frontier_before=frontier_before,
                    frontier_after=investigation_frontier_fingerprint(evidence),
                    attempted_method_ids=attempted_method_ids,
                )
                self._block_same_family(
                    queue,
                    action,
                    target_key=target_key,
                    blocked_method_ids=blocked_method_ids,
                    scheduled=scheduled,
                    actions=actions,
                )
                events.append(
                    InvestigationEvent(
                        "no_new_evidence",
                        action.id,
                        state.value,
                        tuple(new_ids),
                        "no novel evidence from action "
                        f"for {target_key} ({no_gain_streak}/{self.max_consecutive_no_gain})",
                    )
                )
                next_action = self._next_pending_action(
                    queue,
                    target_key=target_key,
                    attempted_action_ids=attempted_action_ids,
                    last_action_type=action.action_type,
                    blocked_method_ids=blocked_method_ids,
                )
                next_hint = (
                    f"{next_action.action_type.value}:{next_action.id}"
                    if next_action is not None
                    else "VERIFY_OR_STATIC_BOUNDARY"
                )
                events.append(
                    InvestigationEvent(
                        "no_new_evidence_autopsy",
                        action.id,
                        state.value,
                        tuple(new_ids),
                        "autopsy="
                        + self._no_gain_autopsy(
                            action,
                            produced_count=len(produced),
                            rejected_count=rejected_count,
                        )
                        + "; next_action="
                        + next_hint,
                    )
                )
                if no_gain_streak >= self.max_consecutive_no_gain:
                    coverage = self._coverage_snapshot(
                        actions, evidence, attempted_action_ids, failed_action_ids
                    )
                    contract_target = next(
                        (
                            item
                            for item in coverage["targets"]
                            if item["target"] == target_key
                        ),
                        None,
                    )
                    if contract_target is not None and contract_target["pending_action_types"]:
                        events.append(
                            InvestigationEvent(
                                "coverage_continue",
                                action.id,
                                state.value,
                                tuple(new_ids),
                                "continuing despite no new evidence because required static facets "
                                "remain: "
                                + ", ".join(contract_target["pending_action_types"]),
                            )
                        )
                        continue
                    pending_targets = sorted(
                        {
                            self._action_target_key(queued)
                            for queued in queue.pending
                            if self._action_target_key(queued) != target_key
                        }
                    )
                    if pending_targets:
                        events.append(
                            InvestigationEvent(
                                "target_continue",
                                action.id,
                                state.value,
                                tuple(new_ids),
                                "continuing despite no new evidence because independent concrete "
                                f"targets remain: {', '.join(pending_targets[:8])}",
                            )
                        )
                        continue
                    uncovered_families = sorted(
                        {
                            queued.action_type.value
                            for queued in queue.pending
                            if queued.id in explicit_action_ids
                            if queued.action_type not in attempted_action_types
                        }
                    )
                    if uncovered_families:
                        events.append(
                            InvestigationEvent(
                                "coverage_continue",
                                action.id,
                                state.value,
                                tuple(new_ids),
                                "continuing despite no new evidence because distinct static "
                                f"action families remain uncovered: {', '.join(uncovered_families)}",
                            )
                        )
                        continue
                    gate = self._evaluate_gate(evidence, question, hypothesis_statement)
                    coverage = self._coverage_snapshot(
                        actions, evidence, attempted_action_ids, failed_action_ids
                    )
                    # Existing baseline facts can already satisfy every deep
                    # facet. A later read returning no *new* rows must not
                    # erase that complete, provenance-valid evidence path.
                    if gate.accepted and coverage["claim_eligible"]:
                        move(InvestigationThreadState.VERIFYING, gate.reason)
                        move(
                            InvestigationThreadState.MECHANISM_READY,
                            "mechanism evidence threshold satisfied",
                        )
                        move(
                            InvestigationThreadState.CLAIM_READY,
                            "hypothesis is eligible for Claim upgrade",
                        )
                        break
                    if state == InvestigationThreadState.HYPOTHESIZING:
                        move(InvestigationThreadState.INVESTIGATING, "static action started")
                    last_plan = dict(action.plan)
                    next_method = str(last_plan.get("next_method") or "")
                    k02_status = (
                        "STALLED"
                        if next_method in {"", "STATIC_BOUNDARY"}
                        else "BACKTRACK_REQUIRED"
                    )
                    events.append(
                        InvestigationEvent(
                            "stalled" if k02_status == "STALLED" else "backtrack_required",
                            action.id,
                            state.value,
                            tuple(new_ids),
                            f"{k02_status} after consecutive zero-gain; same selector is not replayed",
                        )
                    )
                    events.append(
                        InvestigationEvent(
                            "static_boundary",
                            action.id,
                            state.value,
                            tuple(new_ids),
                            "all admitted static facets for the target were attempted without "
                            "enough new evidence to close the mechanism",
                        )
                    )
                    move(
                        InvestigationThreadState.UNKNOWN,
                        "NO_NEW_EVIDENCE threshold reached; absence is not refutation",
                    )
                    break
            if any(self._has_api((row,), "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS") for row in produced):
                events.append(InvestigationEvent("hypothesis_updated", action.id, state.value, tuple(new_ids), "constant supports PPID spoofing hypothesis"))
            current_gate = self._evaluate_gate(evidence, question, hypothesis_statement)
            if current_gate.accepted:
                coverage = self._coverage_snapshot(
                    actions, evidence, attempted_action_ids, failed_action_ids
                )
                if coverage["claim_eligible"]:
                    move(InvestigationThreadState.VERIFYING, current_gate.reason)
                    move(InvestigationThreadState.MECHANISM_READY, "mechanism evidence threshold satisfied")
                    move(InvestigationThreadState.CLAIM_READY, "hypothesis is eligible for Claim upgrade")
                    break
                pending = [
                    f"{item['target']}:{','.join(item['missing_evidence_action_types'])}"
                    for item in coverage["targets"]
                    if item["missing_evidence_action_types"]
                ]
                events.append(
                    InvestigationEvent(
                        "coverage_continue",
                        action.id,
                        state.value,
                        tuple(new_ids),
                        "candidate evidence is present; continuing to cover required static facets: "
                        + "; ".join(pending[:8]),
                    )
                )

        gate = self._evaluate_gate(evidence, question, hypothesis_statement)
        coverage = self._coverage_snapshot(
            actions, evidence, attempted_action_ids, failed_action_ids
        )
        if (
            state == InvestigationThreadState.INVESTIGATING
            and not stop_event_emitted
            and not coverage["complete"]
        ):
            events.append(
                InvestigationEvent(
                    "static_boundary",
                    None,
                    state.value,
                    (),
                    "investigation budget ended before all required static facets were covered",
                )
            )
            move(
                InvestigationThreadState.UNKNOWN,
                "investigation budget exhausted before deep static coverage completed",
            )
        self._record_join_attempt_if_needed(
            evidence,
            attempted_action_types=attempted_action_types,
            question=question,
            hypothesis_statement=hypothesis_statement,
            thread_id=thread_id,
        )
        coverage = dict(coverage)
        if k02_status:
            coverage["k02_status"] = k02_status
        for rejection in rejected_actions:
            # Auditable, and deliberately NOT counted as an attempted method: the catalog refused
            # it, so charging the sample for the attempt would misreport coverage. The row exists
            # so a reviewer can tell a rejected action from one that was never proposed.
            evidence.append(
                {
                    "kind": "investigation_action_rejected",
                    "nature": "STATIC_INFERRED",
                    "value": {
                        "reason": "catalog_contract_violation",
                        "detail": rejection.get("reason"),
                        "action_id": rejection.get("action_id"),
                        "action_type": rejection.get("action_type"),
                        "target_selector": rejection.get("target_selector"),
                    },
                    "anchor": {"type": "investigation_action_rejection"},
                }
            )
        return InvestigationResult(
            thread_id,
            artifact_id,
            state,
            gate.status if gate.accepted and coverage["claim_eligible"] else "UNKNOWN",
            tuple(evidence),
            tuple(events),
            tuple(actions),
            gate,
            coverage,
        )

    def run_until_converged(
        self,
        *,
        thread_id: str,
        artifact_id: str,
        question: str,
        hypothesis_id: str,
        hypothesis_statement: str,
        initial_evidence: Iterable[Mapping[str, object]] = (),
        execute: Callable[[ActionSpec], Iterable[Mapping[str, object]]] | None = None,
        proposed_actions: Iterable[ActionSpec] = (),
        initial_scheduled: Iterable[str] = (),
        initial_completed_action_ids: Iterable[str] = (),
        allow_investigator_actions: bool = True,
        should_stop: Callable[[], bool] | None = None,
        max_rounds: int = 4,
        max_total_steps: int | None = None,
    ) -> InvestigationResult:
        """Resume a bounded frontier until its deep contract is covered.

        One ``run`` invocation intentionally has a small action budget.  A
        real artifact often has more targets than fit in that budget, so this
        method carries unexecuted actions into the next round and re-plans
        from the accumulated evidence.  Only completed/failed action keys are
        marked scheduled; otherwise a pending frontier would be silently
        discarded at the round boundary.
        """
        if max_rounds < 1:
            raise ValueError("max_rounds must be positive")
        if max_total_steps is not None and max_total_steps < 1:
            raise ValueError("max_total_steps must be positive when provided")
        if execute is None:
            def execute(_action: ActionSpec) -> Iterable[Mapping[str, object]]:
                return ()
        evidence: list[dict[str, object]] = [dict(row) for row in initial_evidence]
        scheduled: set[str] = {
            str(item) for item in initial_scheduled if str(item).strip()
        }
        pending: tuple[ActionSpec, ...] = tuple(proposed_actions)
        all_actions: list[ActionSpec] = []
        all_events: list[InvestigationEvent] = []
        attempted_ids: set[str] = set()
        failed_ids: set[str] = set()
        completed_ids: set[str] = {
            str(item) for item in initial_completed_action_ids if str(item).strip()
        }
        next_sequence = 0
        total_attempted = 0
        final: InvestigationResult | None = None
        blocked_method_ids: set[str] = set()

        for round_index in range(max_rounds):
            if max_total_steps is not None and total_attempted >= max_total_steps:
                break
            round_budget = self.max_steps
            if max_total_steps is not None:
                round_budget = min(self.max_steps, max_total_steps - total_attempted)
            result = self.run(
                thread_id=thread_id,
                artifact_id=artifact_id,
                question=question,
                hypothesis_id=hypothesis_id,
                hypothesis_statement=hypothesis_statement,
                initial_evidence=evidence,
                execute=execute,
                proposed_actions=pending,
                initial_scheduled=scheduled,
                initial_completed_action_ids=completed_ids,
                allow_investigator_actions=allow_investigator_actions,
                should_stop=should_stop,
                sequence_start=next_sequence,
                max_steps=round_budget,
                blocked_method_ids=blocked_method_ids,
            )
            final = result
            all_events.extend(result.events)
            existing_ids = {item.id for item in all_actions}
            all_actions.extend(item for item in result.actions if item.id not in existing_ids)
            evidence_by_id = {
                str(item.get("id")): item
                for item in evidence
                if item.get("id")
            }
            for item in result.evidence:
                item_id = str(item.get("id", ""))
                if item_id and item_id not in evidence_by_id:
                    evidence_by_id[item_id] = dict(item)
            evidence = list(evidence_by_id.values())

            attempted_this_round = {
                event.action_id
                for event in result.events
                if event.action_id
                and event.phase
                in {
                    "action_completed",
                    "action_failed",
                    "no_new_evidence",
                    "no_new_evidence_autopsy",
                }
            }
            failed_this_round = {
                event.action_id
                for event in result.events
                if event.action_id and event.phase == "action_failed"
            }
            attempted_ids.update(item for item in attempted_this_round if item)
            failed_ids.update(item for item in failed_this_round if item)
            # Dependency edges keep their original IDs across rounds. Only
            # successful completions unlock them; failed prerequisites stay
            # blocked and prior work does not consume this round's budget.
            completed_ids.update(
                event.action_id
                for event in result.events
                if event.action_id and event.phase == "action_completed"
            )
            total_attempted += len(attempted_this_round)
            by_id = {item.id: item for item in result.actions}
            for action_id in attempted_this_round:
                action = by_id.get(action_id)
                if action is not None:
                    scheduled.add(action.dedupe_key)
            pending = tuple(
                item
                for item in result.actions
                if item.id not in attempted_this_round
                and investigation_method_id(item.action_type, item.target_selector, item.plan)
                not in blocked_method_ids
                and not investigation_is_scheduled(
                    item.action_type, item.target_selector, item.plan, scheduled
                )
            )
            next_sequence += max(len(result.actions), 1)

            if should_stop is not None:
                try:
                    if should_stop():
                        break
                except Exception:
                    pass
            # A claim-ready gate on the current evidence window is not a
            # stop while later high-value targets or pending contract facets
            # remain.  Kunglao SATURATED: unused rounds plus open work is not
            # idle completion.
            if (
                result.thread_state == InvestigationThreadState.CLAIM_READY
                and not pending
                and result.coverage.get("complete")
            ):
                break
            if result.coverage.get("complete") and not pending:
                break
            # No frontier means re-planning cannot make progress.  This is a
            # bounded static conclusion, not a claim that the behavior is
            # absent.
            if not result.actions and not pending:
                break
            if not allow_investigator_actions and not pending:
                break

        if final is None:  # pragma: no cover - max_rounds is validated above
            raise RuntimeError("investigation did not execute a round")
        if (
            max_total_steps is not None
            and total_attempted >= max_total_steps
            and pending
        ):
            all_events.append(
                InvestigationEvent(
                    "budget_exhausted",
                    None,
                    final.thread_state.value,
                    (),
                    "task-level investigation action budget exhausted; pending frontier deferred",
                )
            )
        merged_coverage = self._coverage_snapshot(
            all_actions,
            evidence,
            attempted_ids,
            failed_ids,
        )
        merged_gate = self._evaluate_gate(evidence, question, hypothesis_statement)
        merged_state = final.thread_state
        merged_hypothesis = (
            merged_gate.status
            if merged_gate.accepted and merged_coverage["claim_eligible"]
            else "UNKNOWN"
        )
        if merged_gate.accepted and merged_coverage["claim_eligible"]:
            merged_state = InvestigationThreadState.CLAIM_READY
        elif merged_state == InvestigationThreadState.CLAIM_READY:
            merged_state = InvestigationThreadState.UNKNOWN
        return replace(
            final,
            thread_state=merged_state,
            hypothesis_status=merged_hypothesis,
            evidence=tuple(evidence),
            events=tuple(all_events),
            actions=tuple(all_actions),
            gate=merged_gate,
            coverage=merged_coverage,
        )

    def run_many(
        self,
        seeds: Iterable[Mapping[str, object]],
        *,
        execute: Callable[[ActionSpec], Iterable[Mapping[str, object]]] | None = None,
        max_active_threads: int = 12,
        max_seeds: int = 50,
        evidence_by_artifact: Mapping[str, Iterable[Mapping[str, object]]] | None = None,
    ) -> tuple[InvestigationResult, ...]:
        """Investigate a bounded, priority-ordered seed frontier.

        Each seed is run through the same recursive loop as ``run``.  The
        scheduler limits active thread identities and keeps seed admission
        deterministic; this avoids the old single-seed behavior without
        introducing unbounded concurrency or model-specific side effects.
        """
        scheduler = MultiSeedInvestigationScheduler(
            max_active_threads=max_active_threads,
            max_seeds=max_seeds,
        )
        scheduler.admit(seeds)
        by_artifact = evidence_by_artifact or {}
        results: list[InvestigationResult] = []
        while True:
            seed = scheduler.next_seed()
            if seed is None:
                break
            artifact_id = str(seed["artifact_id"])
            thread_id = str(seed.get("thread_id") or f"thread:{artifact_id}:{len(results)}")
            hypothesis_id = str(seed.get("hypothesis_id") or f"hypothesis:{thread_id}")
            statement = str(
                seed.get("hypothesis_statement")
                or seed.get("statement")
                or f"Static evidence can determine the {seed.get('seed_kind', 'generic')} mechanism."
            )
            result = self.run(
                thread_id=thread_id,
                artifact_id=artifact_id,
                question=str(seed["question"]),
                hypothesis_id=hypothesis_id,
                hypothesis_statement=statement,
                initial_evidence=tuple(by_artifact.get(artifact_id, ())),
                execute=execute,
            )
            results.append(result)
            scheduler.complete(artifact_id, question=str(seed["question"]), seed_kind=str(seed.get("seed_kind", "generic")))
        return tuple(results)
