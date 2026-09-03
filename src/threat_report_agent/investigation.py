"""Evidence-driven investigation primitives.

The static parsers produce observations; this module turns those observations
into a bounded, auditable investigation loop.  It deliberately contains no
sample execution and no model-specific code.  A model may propose an action at
the service seam, but only the catalog and queue can authorize its execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import heapq
import hashlib
import re
from typing import Callable, Iterable, Mapping

from threat_report_agent.evidence_recovery import FailureInterpretation, canonical_action_key
from threat_report_agent.mechanism_completeness import mechanism_completeness_score as _semantic_mechanism_completeness_score
from threat_report_agent.semantic_predicates import normalize_api_symbol


def _link_text(row: Mapping[str, object]) -> str:
    """Render one typed static row for bounded semantic-link matching."""
    value = row.get("value")
    anchor = row.get("anchor")
    return f"{row.get('kind', '')} {value!r} {anchor!r}".casefold()


def _link_function_key(row: Mapping[str, object]) -> str:
    """Return the strongest available function/RVA identity for a row."""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
    for item in (
        anchor.get("function_entry"), anchor.get("entry"), anchor.get("rva"),
        value.get("function_entry"), value.get("entry"), value.get("entry_rva"),
        value.get("function"),
    ):
        if isinstance(item, (str, int)) and str(item).strip():
            return str(item).casefold()
    # Unanchored imports/strings are still useful as global inputs, but are
    # kept in a separate bucket and never create a function-local link alone.
    return "__global__"


def _link_api_names(rows: Iterable[Mapping[str, object]]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
        for key in ("api", "name", "target_name", "target_function", "consumer", "transport"):
            item = value.get(key)
            if item:
                names.add(normalize_api_symbol(item))
        for key in ("apis", "functions", "call_targets", "calls", "consumer_apis"):
            nested = value.get(key)
            if isinstance(nested, (list, tuple, set)):
                for item in nested:
                    if isinstance(item, Mapping):
                        for field in ("api", "name", "target_name", "target_function"):
                            if item.get(field):
                                names.add(normalize_api_symbol(item[field]))
                    elif item:
                        names.add(normalize_api_symbol(item))
    return {item for item in names if item}


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
        source_ids = [str(item["id"]) for item in bucket if item.get("id")]
        if not source_ids:
            return
        identity = {
            "kind": kind,
            "mechanism_type": mechanism_type,
            "source_evidence_ids": tuple(source_ids),
            "function_key": _link_function_key(bucket[0]),
        }
        if any(
            item.get("kind") == kind
            and tuple(item.get("value", {}).get("source_evidence_ids", ())) == tuple(source_ids)
            for item in results
        ):
            return
        results.append(
            {
                    "id": "static-link:" + mechanism_type.casefold() + ":" + hashlib.sha256(
                        repr(identity).encode("utf-8")
                    ).hexdigest()[:16],
                "kind": kind,
                "nature": "STATIC_INFERRED",
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
        has_patch = bool(re.search(r"33\s*,?\s*c0\s*,?\s*c3|patch_bytes|length\s*=\s*3", text))
        if has_etw and has_vp and has_patch and has_flush:
            required_ids = [
                *sum((ids_by_api.get(item, []) for item in ("etweventwrite", "virtualprotect", "flushinstructioncache")), []),
                *[str(row["id"]) for row in bucket if re.search(r"33\s*,?\s*c0\s*,?\s*c3|patch_bytes|length\s*=\s*3", _link_text(row))],
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
            for relation_field in ("call_targets", "calls", "references_from"):
                nested = value.get(relation_field)
                if isinstance(nested, (list, tuple)):
                    targets.extend(nested)
            for target in targets:
                if isinstance(target, Mapping):
                    candidate = target.get("to") or target.get("target_function") or target.get("target_name")
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

    def _emit_cross(
        mechanism_type: str,
        kind: str,
        path: tuple[str, ...],
        source: list[dict[str, object]],
        value: dict[str, object],
    ) -> None:
        if not source:
            return
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
            patch_rows = [row for row in source if re.search(r"33\s*,?\s*c0\s*,?\s*c3|patch_bytes|length\s*=\s*3", _link_text(row))]
            if patch_rows:
                component_ids = tuple(sorted(
                    str(row.get("id"))
                    for node in path
                    for row in buckets[node]
                    if _link_api_names((row,)) & patch_names
                    or re.search(r"33\s*,?\s*c0\s*,?\s*c3|patch_bytes|length\s*=\s*3", _link_text(row))
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
    selector_keys: tuple[str, ...] = (
        "target",
        "api",
        "function",
        "function_entry",
        "entry",
        "rva",
        "address",
    )


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

    def __post_init__(self) -> None:
        # Keep legacy deterministic callers source-compatible while making the
        # selector explicit on the immutable action contract.  Model actions
        # are normalized at the service boundary before construction.
        parameters = dict(self.parameters)
        selector = dict(self.target_selector)
        selector_keys = {
            "target", "api", "function", "function_entry", "entry", "rva", "address"
        }
        if not selector:
            selector = {
                key: value
                for key, value in parameters.items()
                if key in selector_keys and isinstance(value, (str, int)) and str(value).strip()
            }
        if not parameters and selector:
            parameters = dict(selector)
        object.__setattr__(self, "parameters", parameters)
        object.__setattr__(self, "target_selector", selector)

    @property
    def dedupe_key(self) -> str:
        return canonical_action_key(
            self.action_type.value,
            {"target_selector": dict(self.target_selector)},
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

    @property
    def dedupe_key(self) -> str:
        return canonical_action_key(self.action_type.value, self.parameters)


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

    def __init__(self, playbooks: Iterable[MechanismPlaybook] | None = None) -> None:
        self._playbooks = tuple(playbooks or self.default_playbooks())

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
                (ActionType.GET_DATA_REFERENCES, ActionType.GET_PCODE_SLICE, ActionType.READ_BYTES, ActionType.DECODE_CANDIDATE),
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

    def matching(self, evidence: Iterable[Mapping[str, object]]) -> tuple[MechanismPlaybook, ...]:
        text = " ".join(str(row.get("value", "")) for row in evidence).casefold()
        kinds = {str(row.get("kind", "")).casefold() for row in evidence}
        matches = [
            item
            for item in self._playbooks
            if any(term in text or term in kinds for term in item.trigger_terms)
        ]
        return tuple(matches)

    def fallback(self) -> MechanismPlaybook:
        """Return the generic playbook for evidence without a specialist match."""
        return next(item for item in self._playbooks if item.id == "generic-mechanism-investigation")

    def best_match(self, evidence: Iterable[Mapping[str, object]]) -> MechanismPlaybook | None:
        """Return the most specific matched playbook with deterministic ties."""
        rows = tuple(evidence)
        text = " ".join(str(row.get("value", "")) for row in rows).casefold()
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

    @property
    def digest(self) -> str:
        source = "|".join(
            f"{item.id}@{item.version}:{','.join(item.spawned_threads)}"
            for item in self._playbooks
        )
        return canonical_action_key("mechanism-playbooks", {"profiles": source})


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

    def __init__(self, *, max_steps: int = 32) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.max_steps = max_steps
        self._items: dict[str, ActionSpec] = {}
        self._heap: list[tuple[int, int, str]] = []
        self._counter = 0
        self._completed: set[str] = set()
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
        heapq.heappush(self._heap, (action.priority, self._counter, action.id))
        self._counter += 1
        return True

    def pop(self) -> ActionSpec | None:
        if self.steps >= self.max_steps:
            return None
        deferred: list[tuple[int, int, str]] = []
        selected: ActionSpec | None = None
        while self._heap:
            priority, counter, action_id = heapq.heappop(self._heap)
            action = self._items.get(action_id)
            if action is None:
                continue
            if all(dependency in self._completed for dependency in action.depends_on):
                selected = action
                break
            deferred.append((priority, counter, action_id))
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

    def as_dict(self) -> dict[str, object]:
        return {
            "mechanism_type": self.mechanism_type,
            "status": self.status,
            "accepted": self.accepted,
            "checks": [dict(item) for item in self.checks],
            "evidence_ids": list(self.evidence_ids),
            "missing": list(self.missing),
            "reason": self.reason,
        }


def _row_text(row: Mapping[str, object]) -> str:
    return f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()


def _row_anchor_tokens(row: Mapping[str, object]) -> set[str]:
    """Return normalized function/RVA identities for one Evidence row."""
    value = row.get("value") if isinstance(row.get("value"), Mapping) else {}
    anchor = row.get("anchor") if isinstance(row.get("anchor"), Mapping) else {}
    tokens: set[str] = set()
    for source in (anchor, value):
        for key in ("function_entry", "entry", "entry_rva", "rva", "address", "function"):
            item = source.get(key)
            if item is None:
                continue
            token = str(item).strip().casefold()
            if token:
                tokens.add(token)
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
        if all(source_set & ids for ids in match_ids):
            return True
    return False


def _verify_groups(
    mechanism_type: str,
    evidence: Iterable[Mapping[str, object]],
    groups: tuple[tuple[str, tuple[str, ...]], ...],
    *,
    require_anchor: bool = False,
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


def verify_xor_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    return _verify_groups(
        "DECODE_CONFIG",
        evidence,
        (
            ("cipher/data", ("cipher", "encoded", "encrypted", "data_block")),
            ("key", ("key", "key_table", "16-byte")),
            ("algorithm", ("xor", "transformation", "formula")),
            ("counter", ("counter=", "counter", "initial_counter")),
            ("step", ("step=", "counter_step", "increment")),
            # Keep this verifier sample-agnostic: concrete decoded strings are
            # evidence, but no fixture filename may be used as a proof token.
            ("plaintext", ("plaintext", "decoded", "string", "url", "path")),
            ("consumer", ("consumer", "use", "call", "downstream")),
        ),
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
        value = row_value(row)
        names: set[str] = set()
        for key in ("api", "target_name", "target_function"):
            item = value.get(key)
            if item:
                names.add(normalize_api_symbol(item))
        for key in ("apis", "functions", "call_targets"):
            nested = value.get(key)
            if isinstance(nested, (list, tuple)):
                for item in nested:
                    if isinstance(item, Mapping):
                        for field in ("api", "target_name", "target_function"):
                            if item.get(field):
                                names.add(normalize_api_symbol(item[field]))
                    elif item:
                        names.add(normalize_api_symbol(item))
        return {item for item in names if item}

    def text(row: Mapping[str, object]) -> str:
        return f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()

    resolver_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
        and (
            str(row.get("kind", "")) == "mechanism_dynamic_resolution"
            or bool(api_names(row) & {"getprocaddress", "loadlibrarya", "loadlibraryw", "ldrgetprocedureaddress"})
        )
    ]
    module_input_ids = [
        str(row.get("id"))
        for row in rows
        if row.get("id")
            and (
            any(token in text(row) for token in ("lpfilename", "module", "dll", "library", "entryname", "entry_point", "entry point"))
            and str(row.get("kind", "")) in {"function_context", "function_data_correlation", "data_reference", "function_call", "string_reference", "mechanism_dynamic_api_link"}
        )
    ]
    consumer_ids: list[str] = []
    resolver_api_names = {"loadlibrarya", "loadlibraryw", "getprocaddress", "ldrgetprocedureaddress"}
    for row in rows:
        if not row.get("id"):
            continue
        value = row_value(row)
        names = api_names(row)
        explicit_pointer = str(row.get("kind", "")) == "indirect_function_pointer_link" or bool(value.get("indirect"))
        explicit_consumer = any(
            token in text(row)
            for token in ("calling_entry_point", "calling entry point", "resolved entry", "consumer", "invoke", "indirect_call")
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
        if explicit_pointer or explicit_consumer or typed_direct_consumer:
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


def verify_ppid_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    result = _verify_groups(
        "PPID_SPOOFING",
        evidence,
        (
            ("explorer selection", ("explorer.exe", "process enumeration", "process32first")),
            ("OpenProcess access", ("openprocess", "process_create_process", "0x00000080")),
            ("parent attribute", ("updateprocthreadattribute", "parent_process", "proc_thread_attribute_parent_process")),
            ("CreateProcess startup", ("createprocessw", "startupinfoex", "extended_startupinfo")),
            ("creation flags", ("0x09080008", "create_no_window", "detached_process", "breakaway")),
        ),
    )
    forbidden = ("create_suspended", "create_new_console", "process hollowing", "remote injection")
    text = " ".join(_row_text(row) for row in evidence).casefold()
    bad = tuple(token for token in forbidden if token in text)
    if bad:
        return MechanismVerification(
            result.mechanism_type, "CONTRADICTED", False, result.checks,
            result.evidence_ids, tuple(f"forbidden:{item}" for item in bad),
            f"negative-gold contradiction: {', '.join(bad)}",
        )
    return result


def verify_etw_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    return _verify_groups(
        "ETW_PATCH",
        evidence,
        (
            ("EtwEventWrite identity", ("etweventwrite", "0x24a8d022", "ntdll.dll")),
            ("VirtualProtect target", ("virtualprotect", "protection", "target")),
            ("patch bytes", ("33 c0 c3", "33,c0,c3", "patch_bytes", "length=3")),
            ("restore/flush", ("flushinstructioncache", "restore", "old_protection")),
        ),
        require_anchor=True,
    )


def verify_http_download_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify a statically linked WinHTTP request/response path."""
    return _verify_groups(
        "HTTP_DOWNLOAD",
        evidence,
        (
            ("https input", ("https", "http endpoint", "endpoint")),
            ("request consumer", ("winhttpsendrequest",)),
            ("response side effect", ("winhttpreceiveresponse", "response bytes")),
        ),
        require_anchor=True,
    )


def verify_shell_output_mechanism(evidence: Iterable[Mapping[str, object]]) -> MechanismVerification:
    """Verify a static child-process pipe/output capture chain."""
    return _verify_groups(
        "SHELL_OUTPUT",
        evidence,
        (
            ("shell/process input", ("shell", "createprocessw", "child process")),
            ("pipe consumer", ("createpipe", "pipe")),
            ("output capture side effect", ("output capture", "readfile", "peeknamedpipe")),
        ),
        require_anchor=True,
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
    }
    verifier = verifiers.get(str(mechanism_type).upper())
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

    @staticmethod
    def _first_static_target(rows: Iterable[Mapping[str, object]]) -> str:
        for row in rows:
            anchor = row.get("anchor")
            if isinstance(anchor, Mapping):
                for key in ("function_entry", "entry", "rva", "address"):
                    value = anchor.get(key)
                    if isinstance(value, (str, int)) and str(value).strip():
                        return str(value)
            value = row.get("value")
            if isinstance(value, Mapping):
                for key in ("function_entry", "entry", "rva", "address"):
                    item = value.get(key)
                    if isinstance(item, (str, int)) and str(item).strip():
                        return str(item)
        return ""

    @staticmethod
    def _contains(text: str, *terms: str) -> bool:
        normalized = text.casefold()
        return any(term.casefold() in normalized for term in terms)

    def propose(
        self,
        *,
        evidence: Iterable[Mapping[str, object]],
        scheduled: set[str],
    ) -> tuple[ActionSuggestion, ...]:
        rows = list(evidence)
        result: list[ActionSuggestion] = []
        kinds = {str(row.get("kind", "")) for row in rows}
        text = " ".join(str(row.get("value", "")) for row in rows).casefold()
        target = self._first_static_target(rows)

        def add(
            action_type: ActionType,
            priority: int,
            reason: str,
            *,
            action_target: str = "",
            expected: tuple[str, ...] = (),
            success: str = "new_targeted_evidence",
        ) -> None:
            parameters: dict[str, object] = {"target": action_target} if action_target else {}
            suggestion = ActionSuggestion(
                action_type=action_type,
                priority=priority,
                reason=reason,
                parameters=parameters,
                expected_evidence_kinds=expected,
                success_condition=success,
            )
            if suggestion.dedupe_key not in scheduled:
                result.append(suggestion)

        profiles = {item.id for item in self.playbooks.matching(rows)}
        if "ppid-process-chain" in profiles:
            has_openprocess_call = any(
                str(row.get("kind")) == "function_call"
                and self._contains(str(row.get("value", "")), "openprocess")
                for row in rows
            )
            has_attribute_call = any(
                str(row.get("kind")) == "function_call"
                and self._contains(str(row.get("value", "")), "updateprocthreadattribute")
                for row in rows
            )
            has_parent_constant = any(
                str(row.get("kind")) == "constant"
                and self._contains(
                    str(row.get("value", "")),
                    "proc_thread_attribute_parent_process",
                    "0x00020000",
                )
                for row in rows
            )
            if not has_openprocess_call:
                add(
                    ActionType.GET_STRINGS_REFERENCED,
                    10,
                    "Trace the OpenProcess seed into a static function context.",
                    action_target="OpenProcess",
                    expected=("function_context", "function_call"),
                )
            elif not has_attribute_call:
                add(
                    ActionType.GET_CALLEES,
                    12,
                    "Resolve the static continuation from OpenProcess to its handle consumers.",
                    action_target="OpenProcess",
                    expected=("function_call", "function_context"),
                )
            elif not has_parent_constant:
                add(
                    ActionType.EVALUATE_CONSTANT,
                    14,
                    "Evaluate the process-attribute constant at the UpdateProcThreadAttribute path.",
                    action_target="UpdateProcThreadAttribute",
                    expected=("constant", "function_call"),
                )

        if "dynamic-api-resolution" in profiles:
            for api in ("GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrGetProcedureAddress"):
                if api.casefold() in text:
                    add(
                        ActionType.GET_XREFS_TO,
                        20,
                        f"Resolve static Xrefs to {api} before inferring dynamically resolved behavior.",
                        action_target=api,
                        expected=("xref", "function_context", "data_reference"),
                    )
                    add(
                        ActionType.GET_PCODE_SLICE,
                        22,
                        f"Inspect the bounded static argument/return slice around {api}.",
                        action_target=api,
                        expected=("pcode_slice", "function_context"),
                    )

        if "xor-config-recovery" in profiles:
            decode_target = target or "xor"
            add(
                ActionType.GET_DATA_REFERENCES,
                24,
                "Resolve data references for the statically observed decode candidate.",
                action_target=decode_target,
                expected=("data_reference", "function_context"),
            )
            add(
                ActionType.GET_PCODE_SLICE,
                26,
                "Obtain a bounded P-code slice for the decode candidate.",
                action_target=decode_target,
                expected=("pcode_slice", "function_instruction_window"),
            )
            add(
                ActionType.DECODE_CANDIDATE,
                28,
                "Attempt only deterministic, bounded static decode validation.",
                action_target=decode_target,
                expected=("decode_result", "decode_candidate"),
            )

        if "entrypoint-timeline" in profiles:
            entry_target = target or "entrypoint"
            add(
                ActionType.GET_FUNCTION,
                30,
                "Resolve the static entrypoint function before constructing an ordered timeline.",
                action_target=entry_target,
                expected=("function", "function_context"),
            )
            add(
                ActionType.GET_CALLEES,
                32,
                "Expand one bounded call-graph step from the static entrypoint.",
                action_target=entry_target,
                expected=("function_call", "function_context"),
            )
            add(
                ActionType.GET_CFG_SLICE,
                34,
                "Read a bounded CFG slice to preserve conditional timeline limits.",
                action_target=entry_target,
                expected=("cfg_block", "function_context"),
            )

        # v3 profiles are data-driven and may not have a bespoke branch above.
        # Materialize a small evidence-seeking frontier from their preferred
        # actions rather than silently treating a matched mechanism as generic.
        if not result:
            matched_profiles = tuple(
                item for item in self.playbooks.matching(rows)
                if item.id != "generic-mechanism-investigation"
            )
            for profile_index, profile in enumerate(matched_profiles):
                for action_index, action_type in enumerate(profile.preferred_actions[:4]):
                    add(
                        action_type,
                        35 + profile_index * 3 + action_index,
                        f"Collect discriminating evidence for the {profile.mechanism_type} hypothesis.",
                        action_target=target or profile.mechanism_type,
                        expected=tuple(profile.required_evidence_kinds[:3]) or ("specialist_observation",),
                    )

        # The generic fallback is intentionally evidence-seeking rather than
        # conclusion-seeking.  It gives an unfamiliar mechanism a bounded
        # target/data/call-flow investigation while leaving verification in the
        # UNKNOWN/CANDIDATE state until a specialist contract exists.
        if not result:
            generic_target = target or next(
                (
                    str(item.get("value", {}).get("name"))
                    for item in rows
                    if isinstance(item.get("value"), Mapping)
                    and item.get("value", {}).get("name")
                ),
                "artifact",
            )
            add(
                ActionType.GET_FUNCTION,
                40,
                "Locate the highest-value static function or anchor for the generic mechanism hypothesis.",
                action_target=generic_target,
                expected=("function", "function_context"),
            )
            add(
                ActionType.GET_CALLEES,
                42,
                "Follow one bounded call-flow hop from the generic mechanism target.",
                action_target=generic_target,
                expected=("function_call", "function_context"),
            )
            add(
                ActionType.GET_DATA_REFERENCES,
                44,
                "Follow data references to identify inputs, transformations, and consumers.",
                action_target=generic_target,
                expected=("data_reference", "value_flow"),
            )

        if not result and "function" not in kinds and target:
            add(
                ActionType.GET_FUNCTION,
                50,
                "Locate a bounded static function anchor for the open hypothesis.",
                action_target=target,
                expected=("function", "function_context"),
            )
        if not result and target:
            add(
                ActionType.GET_XREFS_TO,
                60,
                "Expand exact static references from the current evidence frontier.",
                action_target=target,
                expected=("xref", "function_context"),
            )
        return tuple(result)


class Verifier:
    """Independent evidence verifier; only it can return a GateDecision."""

    def __init__(
        self,
        gate: ClaimGate | None = None,
        playbooks: MechanismPlaybookRegistry | None = None,
    ) -> None:
        self.gate = gate or ClaimGate()
        self.playbooks = playbooks or MechanismPlaybookRegistry()

    @staticmethod
    def _contains_api(row: Mapping[str, object], api: str) -> bool:
        value = row.get("value")
        return api.lower() in str(value).lower()

    def _evaluate_playbook(
        self,
        evidence: list[dict[str, object]],
        playbook: MechanismPlaybook,
    ) -> GateDecision:
        def threshold_satisfied(tokens: tuple[str, ...]) -> bool:
            return all(
                any(
                    token.casefold()
                    in f"{row.get('kind', '')} {row.get('value', '')} {row.get('anchor', '')}".casefold()
                    for row in evidence
                )
                for token in tokens
            )

        return self.gate.evaluate(
            evidence,
            required_predicates=tuple(
                (lambda _row, tokens=tokens: threshold_satisfied(tokens))
                for tokens in playbook.evidence_thresholds
            ),
        )

    def evaluate(self, evidence: list[dict[str, object]], question: str, statement: str) -> GateDecision:
        text = f"{question} {statement}".lower()
        all_text = " ".join(str(row.get("value", "")) for row in evidence).lower()
        ppid = any(token in text for token in ("ppid", "parent process", "parent-process", "explorer.exe")) or "updateprocthreadattribute" in all_text
        if ppid:
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
                        ]
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
        matched = self.playbooks.matching(profile_rows)
        if matched:
            return self._evaluate_playbook(evidence, matched[0])
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

    def _next_actions(
        self,
        *,
        thread_id: str,
        hypothesis_id: str,
        artifact_id: str,
        evidence: list[dict[str, object]],
        scheduled: set[str],
        sequence: int,
    ) -> tuple[ActionSpec, ...]:
        proposed = self.investigator.propose(evidence=evidence, scheduled=scheduled)
        return tuple(
            ActionSpec(
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
            )
            for offset, suggestion in enumerate(proposed)
        )

    def _evaluate_gate(self, evidence: list[dict[str, object]], question: str, statement: str) -> GateDecision:
        return self.verifier.evaluate(evidence, question, statement)

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
        allow_investigator_actions: bool = True,
    ) -> InvestigationResult:
        if execute is None:
            def execute(_action: ActionSpec) -> Iterable[Mapping[str, object]]:
                return ()
        evidence = [dict(row) for row in initial_evidence]
        state = InvestigationThreadState.DISCOVERED
        events: list[InvestigationEvent] = []
        actions: list[ActionSpec] = []
        queue = InvestigationQueue(max_steps=self.max_steps)
        scheduled: set[str] = set()
        evidence_signatures = {
            str((row.get("kind"), row.get("value"), row.get("anchor"))) for row in evidence
        }
        no_gain_streak = 0

        def move(target: InvestigationThreadState, message: str) -> None:
            nonlocal state
            state = self.machine.transition(state, target)
            events.append(InvestigationEvent("state", None, state.value, (), message))

        move(InvestigationThreadState.PRIORITIZED, "seed ranked for investigation")
        move(InvestigationThreadState.CONTEXT_READY, "question-centric context assembled")
        move(InvestigationThreadState.HYPOTHESIZING, hypothesis_statement)
        sequence = 0
        for proposed in proposed_actions:
            self.catalog.validate(proposed)
            if queue.enqueue(proposed):
                actions.append(proposed)
                scheduled.add(proposed.dedupe_key)
                sequence += 1
        while state not in {InvestigationThreadState.CLAIM_READY, InvestigationThreadState.UNKNOWN}:
            if allow_investigator_actions:
                for action in self._next_actions(
                    thread_id=thread_id,
                    hypothesis_id=hypothesis_id,
                    artifact_id=artifact_id,
                    evidence=evidence,
                    scheduled=scheduled,
                    sequence=sequence,
                ):
                    self.catalog.validate(action)
                    if queue.enqueue(action):
                        actions.append(action)
                        scheduled.add(action.dedupe_key)
                        sequence += 1
            action = queue.pop()
            if action is None:
                gate = self._evaluate_gate(evidence, question, hypothesis_statement)
                if gate.accepted:
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
                    move(InvestigationThreadState.UNKNOWN, gate.reason)
                break
            if state == InvestigationThreadState.HYPOTHESIZING:
                move(InvestigationThreadState.INVESTIGATING, "first investigation action dequeued")
            try:
                produced = [dict(item) for item in execute(action)]
            except Exception as exc:  # executor errors become auditable unknowns
                queue.fail(action.id)
                events.append(InvestigationEvent("action_failed", action.id, state.value, (), str(exc)))
                continue
            new_ids: list[str] = []
            novel_count = 0
            for offset, row in enumerate(produced):
                row.setdefault("id", f"{action.id}:evidence:{offset}")
                row.setdefault("nature", "STATIC_OBSERVED")
                row.setdefault("source_action_id", action.id)
                signature = str((row.get("kind"), row.get("value"), row.get("anchor")))
                if signature not in evidence_signatures:
                    evidence_signatures.add(signature)
                    novel_count += 1
                evidence.append(row)
                new_ids.append(str(row["id"]))
            queue.complete(action.id)
            events.append(InvestigationEvent("action_completed", action.id, state.value, tuple(new_ids), action.reason))
            if novel_count:
                no_gain_streak = 0
            else:
                no_gain_streak += 1
                events.append(
                    InvestigationEvent(
                        "no_new_evidence",
                        action.id,
                        state.value,
                        tuple(new_ids),
                        f"no novel evidence from action ({no_gain_streak}/{self.max_consecutive_no_gain})",
                    )
                )
                if no_gain_streak >= self.max_consecutive_no_gain:
                    gate = self._evaluate_gate(evidence, question, hypothesis_statement)
                    if state == InvestigationThreadState.HYPOTHESIZING:
                        move(InvestigationThreadState.INVESTIGATING, "static action started")
                    move(
                        InvestigationThreadState.UNKNOWN,
                        "NO_NEW_EVIDENCE threshold reached; absence is not refutation",
                    )
                    break
            if any(self._has_api((row,), "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS") for row in produced):
                events.append(InvestigationEvent("hypothesis_updated", action.id, state.value, tuple(new_ids), "constant supports PPID spoofing hypothesis"))
            current_gate = self._evaluate_gate(evidence, question, hypothesis_statement)
            if current_gate.accepted:
                move(InvestigationThreadState.VERIFYING, current_gate.reason)
                move(InvestigationThreadState.MECHANISM_READY, "mechanism evidence threshold satisfied")
                move(InvestigationThreadState.CLAIM_READY, "hypothesis is eligible for Claim upgrade")
                break

        gate = self._evaluate_gate(evidence, question, hypothesis_statement)
        return InvestigationResult(
            thread_id,
            artifact_id,
            state,
            gate.status if gate.accepted else "UNKNOWN",
            tuple(evidence),
            tuple(events),
            tuple(actions),
            gate,
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
