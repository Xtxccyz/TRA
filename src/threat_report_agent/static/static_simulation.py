"""Safe static abstract execution for evidence-driven reverse engineering.

This module does not load, import, emulate, or execute a sample.  It walks the
ordered disassembly and call references already produced by a static tool and
maintains a deliberately small abstract state.  The result is a *prediction*
that can help an investigator decide what to inspect next; it is never a
runtime observation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable, Mapping


#: Longest chain of nested ``OP(prev,operand)`` expressions retained per register.
#:
#: ``_instruction_state`` renders a derived value as ``f"{op}({previous.value},{raw})"``.
#: Composing that over a long run of arithmetic on ONE register grows the string
#: linearly per step and quadratically in total retained bytes -- measured at 337 MB
#: of serialized evidence and a MemoryError for a single 10,000-instruction
#: function of ``ADD RAX, 1``.  The old 128-step cap hid this; it was never the
#: real cause.  Past this depth the accumulated expression is not analysable in
#: prose anyway, so the chain is cut with an explicit marker and the *current*
#: operation is still recorded in the step inputs.  This bounds a representation,
#: it does not skip analysis: every step is still visited and emitted.
MAX_ABSTRACT_EXPRESSION_DEPTH = 8


@dataclass(frozen=True)
class AbstractValue:
    """A bounded value in the abstract state."""

    kind: str
    value: object
    source: str | None = None
    depth: int = 0

    def as_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "value": self.value, "source": self.source}


@dataclass
class AbstractRegisterState:
    registers: dict[str, AbstractValue] = field(default_factory=dict)

    def set(self, register: str, value: AbstractValue) -> None:
        self.registers[register.upper()] = value

    def get(self, register: str) -> AbstractValue | None:
        return self.registers.get(register.upper())

    def as_dict(self) -> dict[str, object]:
        return {name: value.as_dict() for name, value in sorted(self.registers.items())}


@dataclass
class AbstractMemoryState:
    values: dict[str, AbstractValue] = field(default_factory=dict)

    def set(self, address: str, value: AbstractValue) -> None:
        if len(self.values) < 256:
            self.values[address] = value

    def as_dict(self) -> dict[str, object]:
        return {key: value.as_dict() for key, value in sorted(self.values.items())}


@dataclass(frozen=True)
class PathCondition:
    expression: str
    source: str
    resolved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "expression": self.expression,
            "source": self.source,
            "resolved": self.resolved,
        }


@dataclass(frozen=True)
class SimulationTraceStep:
    index: int
    operation: str
    api: str | None
    inputs: dict[str, object]
    outputs: dict[str, object]
    path_condition: str | None
    source_anchor: dict[str, object]
    confidence: str = "MEDIUM"

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "operation": self.operation,
            "api": self.api,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "path_condition": self.path_condition,
            "source_anchor": self.source_anchor,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class StaticSimulationResult:
    function: str
    entry: str
    steps: tuple[SimulationTraceStep, ...]
    path_conditions: tuple[PathCondition, ...]
    register_state: dict[str, object]
    memory_state: dict[str, object]
    mechanism_candidates: tuple[dict[str, object], ...]
    unknowns: tuple[str, ...]
    limitations: tuple[str, ...]
    confidence: str

    @property
    def runtime_observed(self) -> bool:
        return False

    def as_dict(self) -> dict[str, object]:
        raw_steps = [item.as_dict() for item in self.steps]
        steps, anchor_base = _hoist_constant_anchor_fields(raw_steps)
        payload: dict[str, object] = {
            "simulation_kind": "static_abstract_execution",
            "runtime_observed": False,
            "predicted": True,
            "function": self.function,
            "entry": self.entry,
            "confidence": self.confidence,
            "steps": steps,
            "path_conditions": [item.as_dict() for item in self.path_conditions],
            "register_state": self.register_state,
            "memory_state": self.memory_state,
            "mechanism_candidates": list(self.mechanism_candidates),
            "unknowns": list(self.unknowns),
            "limitations": list(self.limitations),
        }
        if anchor_base:
            payload["source_anchor_base"] = anchor_base
        return payload


def _hoist_constant_anchor_fields(
    steps: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Move anchor fields that are identical in EVERY step up to the payload.

    MEASURED R4 DEFECT, fixed at the producer.  Each step's ``source_anchor`` was built from
    a fresh dict holding ``function``, ``entry`` and ``list(source_evidence_ids)[:24]``.  For
    the 551KB Rust PE's ``entry`` function the trace holds 65,536 steps, so that 24-UUID list
    - about 1,000 bytes, the same 24 ids every time - was copied 65,536 times:

        one payload, serialized          83,853,859 chars
        steps[].source_anchor            83,827,376   (99.97%)
        distinct anchor values           65,535 of 65,536  (only `instruction_index` varies)

    Hoisting the constant fields and keeping the varying ones per step introduces a new key
    while every existing reader keeps working, because the step anchors are written back in
    their original complete form - the payload still carries each step's full anchor.

    Only fields whose value is equal (``==``, which is value equality on the nested id list)
    in every step are hoisted, so a trace whose anchors genuinely differ keeps every
    distinction.  Returns ``({}, base)`` unchanged when there is one step or none: hoisting a
    single step saves nothing and would only add a key.
    """
    if len(steps) < 2:
        return steps, {}
    anchors = [step.get("source_anchor") for step in steps]
    if not all(isinstance(anchor, dict) for anchor in anchors):
        return steps, {}
    first = anchors[0]
    assert isinstance(first, dict)
    shared = {
        key: value
        for key, value in first.items()
        if all(anchor.get(key) == value for anchor in anchors[1:])
    }
    if not shared:
        return steps, {}
    hoisted: list[dict[str, object]] = []
    for step, anchor in zip(steps, anchors):
        assert isinstance(anchor, dict)
        trimmed = {key: value for key, value in anchor.items() if key not in shared}
        rebuilt = dict(step)
        if trimmed:
            rebuilt["source_anchor"] = trimmed
        else:
            # Every anchor field was shared, so the base alone describes this step.
            rebuilt.pop("source_anchor", None)
        hoisted.append(rebuilt)
    return hoisted, shared


def merged_path_condition(payload: Mapping[str, object], step: Mapping[str, object]) -> str | None:
    """The complete ``path_condition`` for one step of a trace payload.

    Reverses the path-condition hoist, the same way :func:`merged_source_anchor` reverses the anchor hoist.

    MEASURED R4 COST, task `50673002`, one `abstract_execution_trace` row of 65,536 steps: the payload is
    16,482,793 bytes and `path_condition` is its largest single field - 25.2% of the per-step bytes with
    only **62 distinct values across 400 steps** (`.scratch/measure-trace-step-cost.py`). Round 66 hoisted
    the constant anchor fields (83.8 MB -> 16.5 MB) and this is the same treatment for the next-largest
    repeated field: the distinct conditions are stored once in `path_condition_table` and each step keeps a
    small index.

    THE ONE WAY THIS DIFFERS FROM THE ANCHOR HOIST. For an anchor, "field absent" unambiguously means
    "identical to the base". For a condition it does not: a step with no condition recorded is `None`, and
    `None` must stay distinguishable from "the same condition as an earlier step", because a reader counting
    gates would otherwise see a carried-over gate where the run recorded none. So a step carries
    `path_condition_index` (a table offset) when it HAS a condition, and nothing when it does not -
    "absent" means `None`, never "repeat".

    Readers must use this rather than `step.get("path_condition")` for a hoisted payload. A payload written
    before the hoist has no table and its steps carry the condition inline, so it is returned verbatim; a
    payload that still has both returns the inline value, which is what the producer writes back for
    compatibility.
    """
    inline = step.get("path_condition")
    if isinstance(inline, str):
        return inline
    index = step.get("path_condition_index")
    table = payload.get("path_condition_table")
    if isinstance(index, int) and not isinstance(index, bool) and isinstance(table, (list, tuple)):
        if 0 <= index < len(table):
            candidate = table[index]
            if isinstance(candidate, str):
                return candidate
    # A corrupt or out-of-range index yields None rather than raising: a report build must not fail on one
    # malformed step, and inventing a condition would be worse than reporting none.
    return None


def merged_source_anchor(payload: Mapping[str, object], step: Mapping[str, object]) -> dict[str, object]:
    """The complete ``source_anchor`` for one step of a trace payload.

    Reverses :func:`_hoist_constant_anchor_fields`.  Readers that need a step's anchor must
    use this rather than ``step.get("source_anchor")``, which after hoisting holds only the
    fields that vary.  A payload written before hoisting has no ``source_anchor_base`` and is
    returned exactly as stored, so old and new rows both read correctly.
    """
    base = payload.get("source_anchor_base")
    anchor = step.get("source_anchor")
    merged: dict[str, object] = {}
    if isinstance(base, Mapping):
        merged.update(base)
    if isinstance(anchor, Mapping):
        merged.update(anchor)
    return merged


_REGISTER = r"(?:r(?:[abcd]x|[sd]i|[sb]p|ip)|e?[abcd]x|e?[sd]i|e?[sb]p|[abcd][lh])"
_IMM_RE = re.compile(r"(?:0x[0-9a-f]+|[-+]?\d+)", re.I)
_JUMP_RE = re.compile(r"\b(?:J[A-Z]{1,3}|LOOP[A-Z]*)\b", re.I)

# The record budget is a degenerate-input guard, not an analysis quota.  The
# Ghidra exporter stops one function at 10_000 instruction rows
# (ExportStaticFacts.java) and only call-typed references become extra records,
# so no function the pipeline can deliver is truncated here.  Mirrors
# ``Settings.static_abstract_execution_max_steps`` (STATIC_ABSTRACT_EXECUTION_MAX_STEPS).
DEFAULT_MAX_STEPS = 65_536


def _configured_max_steps() -> int:
    """Resolve the operator-tunable static-analysis record budget.

    ``config.Settings`` stays the single source of truth for the default so the
    guard can be retuned without a code change.  A minimal install, or an
    ambient environment that fails unrelated validation, falls back to the
    module default instead of failing an otherwise valid static analysis; the
    service call sites always pass ``self.settings`` explicitly.
    """
    try:
        from threat_report_agent.config import Settings
    except ImportError:  # pragma: no cover - defensive for minimal installs
        return DEFAULT_MAX_STEPS
    try:
        return int(Settings.from_environment().static_abstract_execution_max_steps)
    except ValueError:  # pragma: no cover - ambient environment is invalid
        return DEFAULT_MAX_STEPS


class StaticAbstractExecutor:
    """Walk bounded static facts and infer likely API/data-flow stages."""

    _API_HINTS = (
        "alloc", "protect", "writeprocessmemory", "memcpy", "memmove",
        "createthread", "remote", "queueuserapc", "setthreadcontext",
        "opentoolhelp", "process32", "openprocess", "updateprocthreadattribute",
        "createprocess", "winhttp", "wininet", "internet", "httpsend", "socket",
        "connect", "dnsquery", "urlmon", "loadlibrary", "getprocaddress",
        "ldrload", "createfile", "readfile", "writefile", "regopen", "regquery",
        "shellexecute", "winexec", "createfile", "virtualquery",
    )

    def __init__(self, *, max_steps: int = DEFAULT_MAX_STEPS, max_paths: int = 4) -> None:
        if max_steps < 1 or max_paths < 1:
            raise ValueError("max_steps and max_paths must be positive")
        self.max_steps = max_steps
        self.max_paths = max_paths

    @staticmethod
    def _call_name(row: Mapping[str, object]) -> str:
        return str(
            row.get("target_name")
            or row.get("target_function")
            or row.get("api")
            or row.get("callee")
            or row.get("target")
            or ""
        ).strip()

    @staticmethod
    def _is_navigation_target(name: str) -> bool:
        """Reject exporter labels that are addresses/data, not call targets."""
        return bool(
            re.match(r"^(?:PTR_)?(?:LAB|DAT)_", name, re.IGNORECASE)
            or re.match(r"^PTR_", name, re.IGNORECASE)
            or re.match(r"^[su]_", name)
            or re.match(r"^EXTERNAL:\s*\d+$", name, re.IGNORECASE)
        )

    @classmethod
    def _looks_like_api_name(cls, name: str) -> bool:
        """Recognize an API-shaped symbol in a type-less legacy row."""
        normalized = name.rsplit("!", 1)[-1].casefold()
        return any(hint in normalized for hint in cls._API_HINTS)

    @classmethod
    def _is_call_reference(
        cls,
        row: Mapping[str, object],
        *,
        source_key: str,
    ) -> bool:
        """Classify one exporter row without requiring a specific schema version.

        Ghidra's authoritative ``references_from`` rows carry a reference type,
        while older persisted ``function_context`` projections expose the same
        edges as ``call_targets`` without that field.  The latter is a bounded
        compatibility path: only rows with a callable symbol are accepted and
        navigation/data labels are explicitly rejected.
        """
        has_explicit_marker = any(
            row.get(key) is not None
            for key in ("type", "reference_type", "is_call", "call")
        )
        if has_explicit_marker:
            reference_type = str(row.get("type") or row.get("reference_type") or "").casefold()
            if "call" in reference_type:
                return True
            for key in ("is_call", "call"):
                flag = row.get(key)
                if flag is True:
                    return True
                if isinstance(flag, str) and flag.strip().casefold() in {"1", "true", "yes", "y"}:
                    return True
            return False

        name = cls._call_name(row)
        if not name or cls._is_navigation_target(name):
            return False
        # ``call_targets`` is a legacy projection whose contract is already
        # "call edge".  Type-less ``references_from`` rows normally need a
        # source/target location, but some old exports retained only the API
        # symbol.  Allow that narrow compatibility path for API-shaped names;
        # arbitrary data symbols remain excluded.
        if source_key == "call_targets":
            return True
        if row.get("from") or row.get("address"):
            return bool(
                row.get("to")
                or row.get("target_function")
                or row.get("target_name")
                or row.get("api")
                or row.get("callee")
                or row.get("target")
            )
        return cls._looks_like_api_name(name)

    @staticmethod
    def _parse_int(value: str) -> int | None:
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 10)
            except ValueError:
                return None

    @classmethod
    def _address_int(cls, row: Mapping[str, object], *keys: str) -> int | None:
        for key in keys:
            raw = row.get(key)
            if raw is None:
                continue
            text = str(raw).strip()
            value = cls._parse_int(text)
            if value is not None:
                return value
            # Ghidra address fields may be bare hexadecimal, but arbitrary
            # labels such as ``FUN_face`` must never be coerced into an
            # address. Require a complete numeric token with at least one
            # decimal digit and no embedded punctuation.
            match = re.fullmatch(r"(?:0x)?(?=[0-9A-Fa-f]*\d)[0-9A-Fa-f]+", text)
            if match:
                try:
                    return int(text, 16) if text.casefold().startswith("0x") else int(text, 16)
                except ValueError:
                    continue
        return None

    @classmethod
    def _instruction_state(
        cls,
        text: str,
        registers: AbstractRegisterState,
        memory: AbstractMemoryState,
        conditions: list[PathCondition],
        index: int,
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        upper = text.upper().strip()
        inputs: dict[str, object] = {}
        outputs: dict[str, object] = {}
        mov = re.search(rf"\bMOV\s+({_REGISTER})\s*,\s*([^,;]+)", upper, re.I)
        if mov:
            register, raw = mov.groups()
            raw = raw.strip()
            value = cls._parse_int(raw)
            abstract = AbstractValue("constant", value if value is not None else raw, f"instruction:{index}")
            registers.set(register, abstract)
            outputs[register] = abstract.as_dict()
            inputs["source"] = raw
            return "assign", inputs, outputs
        arithmetic = re.search(rf"\b(XOR|ADD|SUB|SHL|SHR)\s+({_REGISTER})\s*,\s*([^,;]+)", upper, re.I)
        if arithmetic:
            op, register, raw = arithmetic.groups()
            value = cls._parse_int(raw)
            previous = registers.get(register)
            inputs.update({"register": register, "operator": op, "operand": value if value is not None else raw})
            if op == "XOR" and value == 0 and previous is not None:
                registers.set(register, previous)
            else:
                operand = value if value is not None else raw
                previous_depth = previous.depth if previous is not None else 0
                if previous is not None and previous_depth >= MAX_ABSTRACT_EXPRESSION_DEPTH:
                    # Cut the chain: keep the operation visible, stop the growth.
                    registers.set(
                        register,
                        AbstractValue(
                            "derived",
                            f"{op}(<expr depth {previous_depth}>,{operand})",
                            f"instruction:{index}",
                            previous_depth + 1,
                        ),
                    )
                else:
                    registers.set(
                        register,
                        AbstractValue(
                            "derived",
                            f"{op}({previous.value if previous else '?'},{operand})",
                            f"instruction:{index}",
                            previous_depth + 1,
                        ),
                    )
            outputs[register] = registers.get(register).as_dict() if registers.get(register) else {}
            return "arithmetic", inputs, outputs
        compare = re.search(r"\b(CMP|TEST)\s+([^,;]+)(?:\s*,\s*([^,;]+))?", upper)
        if compare:
            op, left, right = compare.groups()
            left = left.strip()
            right = (right or "").strip()
            # Intel ``CMP dst, src`` derives the flags from ``dst - src`` and
            # ``TEST dst, src`` from ``dst & src``: the FIRST operand is the one the
            # comparison is about, so it stays first and the derivation is written
            # out.  A bare ``dst cmp src`` left the direction to the reader, which is
            # why a recovered anti-sandbox gate (``CMP RAX,0x493e1`` after
            # ``GetTickCount64``) could not be stated as "RAX is below the threshold"
            # even though the constant was present in the trace.
            if right:
                derived = f"{left} - {right}" if op == "CMP" else f"{left} & {right}"
                expression = f"{left} {op.lower()} {right} ({derived})"
            else:
                # No second operand recovered: keep the non-committal wording
                # instead of inventing a self-subtraction the instruction never had.
                expression = f"{left} {op.lower()} nonzero"
            conditions.append(PathCondition(expression, f"instruction:{index}", False))
            return "branch_condition", {"operator": op, "left": left, "right": right or None}, {}
        if _JUMP_RE.search(upper):
            expression = f"branch at instruction {index} unresolved"
            conditions.append(PathCondition(expression, f"instruction:{index}", False))
            return "conditional_branch", {}, {}
        return "instruction", {}, {}

    def analyze(
        self,
        function: Mapping[str, object],
        *,
        source_evidence_ids: Iterable[str] = (),
    ) -> StaticSimulationResult:
        name = str(function.get("name") or "unknown")
        entry = str(function.get("entry") or function.get("entry_rva") or "")
        registers = AbstractRegisterState()
        memory = AbstractMemoryState()
        conditions: list[PathCondition] = []
        steps: list[SimulationTraceStep] = []
        unknowns: list[str] = []
        limitations = [
            "static abstract execution only; no sample loading or runtime observation",
            "indirect calls, opaque predicates, and unresolved memory aliases remain unknown",
        ]
        instruction_rows = function.get("instructions", [])
        instructions = [row for row in instruction_rows if isinstance(row, Mapping)] if isinstance(instruction_rows, list) else []
        calls: list[Mapping[str, object]] = []
        seen_call_keys: set[tuple[str, str, str]] = set()
        for source_key in ("references_from", "call_targets"):
            rows = function.get(source_key, [])
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, Mapping) or not self._is_call_reference(row, source_key=source_key):
                    continue
                name_key = self._call_name(row).casefold()
                from_key = str(row.get("from") or row.get("address") or "").casefold()
                to_key = str(row.get("to") or row.get("target") or "").casefold()
                # A context row and its call_targets projection often carry
                # the same callsite. Keep one semantic step while preserving
                # repeated calls that have distinct source addresses.
                key = (name_key, from_key, to_key)
                if from_key and key in seen_call_keys:
                    continue
                if from_key:
                    seen_call_keys.add(key)
                calls.append(row)
        total_records = len(instructions) + len(calls)
        if total_records > self.max_steps:
            unknowns.append(f"instruction budget exhausted after {self.max_steps} records")
        ordered: list[tuple[str, Mapping[str, object], int]] = []
        records: list[tuple[str, Mapping[str, object], int, int | None]] = []
        for index, row in enumerate(instructions):
            records.append(("instruction", row, index, self._address_int(row, "address", "offset")))
        for offset, row in enumerate(calls):
            records.append(("call", row, offset, self._address_int(row, "from", "address")))
        if records and any(address is not None for _, _, _, address in records):
            # Ghidra exports both instruction addresses and call reference
            # source addresses.  Sorting by those addresses restores a useful
            # sequence; records without an address stay after known records.
            records.sort(key=lambda item: (item[3] is None, item[3] if item[3] is not None else item[2]))
        for position, (kind, row, _, _) in enumerate(records[: self.max_steps]):
            ordered.append((kind, row, position))
        # Exporters may provide calls without instruction ordering.  Preserve
        # their order and mark this limitation instead of fabricating offsets.
        if calls and not instructions:
            limitations.append("call references were available without instruction-level ordering")
        elif calls and not any(self._address_int(row, "from", "address") is not None for row in calls):
            limitations.append("call references had no source addresses; API order is exporter order")
        for kind, row, index in ordered:
            if len(steps) >= self.max_steps:
                unknowns.append("instruction budget exhausted")
                break
            if kind == "instruction":
                text = str(row.get("text") or row.get("mnemonic") or "")
                operation, inputs, outputs = self._instruction_state(text, registers, memory, conditions, index)
                steps.append(SimulationTraceStep(index, operation, None, inputs, outputs, conditions[-1].expression if conditions else None, {"function": name, "entry": entry, "instruction_index": index, "source_evidence_ids": list(source_evidence_ids)[:24]}))
                continue
            api = self._call_name(row)
            if not api:
                unknowns.append(f"unresolved call at {row.get('from', index)}")
                continue
            lowered = api.lower()
            operation = "api_call"
            inputs = {"reference": row.get("from"), "target": row.get("to")}
            outputs: dict[str, object] = {}
            if any(token in lowered for token in ("virtualalloc", "heapalloc", "alloc", "allocvirtual")):
                operation = "allocate_memory"
                outputs["memory"] = "allocated_buffer"
                memory.set("abstract_alloc", AbstractValue("pointer", "allocated_buffer", f"call:{index}"))
            elif any(token in lowered for token in ("writeprocessmemory", "memcpy", "memmove", "rtlmovememory", "writefile")):
                operation = "write_memory"
                inputs["source"] = registers.get("RCX").as_dict() if registers.get("RCX") else "unknown"
                outputs["memory"] = "buffer_mutated"
            elif any(token in lowered for token in ("virtualprotect", "virtualprotectex", "protectmemory")):
                operation = "change_memory_protection"
                outputs["protection"] = "executable_or_writable_candidate"
            elif any(token in lowered for token in ("createthread", "createremotethread", "queueuserapc", "setthreadcontext")):
                operation = "start_thread_or_inject"
                outputs["runtime_effect"] = "thread_start_candidate"
            elif any(token in lowered for token in ("opentoolhelp", "process32first", "process32next", "openprocess", "updateprocthreadattribute", "createprocess")):
                operation = "process_discovery_or_creation"
                outputs["process_effect"] = "process_chain_candidate"
            elif any(token in lowered for token in ("winhttp", "wininet", "internetopen", "httpsend", "socket", "connect", "dnsquery", "urlmon")):
                operation = "network_operation"
                outputs["network_effect"] = "endpoint_or_transport_candidate"
            elif any(token in lowered for token in ("loadlibrary", "getprocaddress", "ldrload")):
                operation = "dynamic_resolution"
                outputs["resolved_symbol"] = "runtime_symbol_candidate"
            else:
                unknowns.append(f"semantics unresolved for {api}")
                operation = "unresolved_api_call"
            steps.append(SimulationTraceStep(index, operation, api, inputs, outputs, conditions[-1].expression if conditions else None, {"function": name, "entry": entry, "call_site": row.get("from"), "source_evidence_ids": list(source_evidence_ids)[:24]}))

        operations = [item.operation for item in steps]
        candidates: list[dict[str, object]] = []
        def candidate(kind: str, required: tuple[str, ...], attack: str | None = None) -> None:
            positions = [operations.index(item) for item in required if item in operations]
            if len(positions) == len(required) and positions == sorted(positions):
                row: dict[str, object] = {
                    "kind": kind,
                    "operations": list(required),
                    "api_sequence": [steps[index].api for index in positions if steps[index].api],
                    "static_only": True,
                }
                if attack:
                    row["attack_technique"] = attack
                candidates.append(row)
        candidate("memory_loader", ("allocate_memory", "write_memory", "change_memory_protection"), "T1055")
        candidate("memory_execution", ("change_memory_protection", "start_thread_or_inject"), "T1055")
        ppid_steps = [
            step for step in steps
            if step.api and any(
                token in step.api.lower()
                for token in ("openprocess", "updateprocthreadattribute", "createprocess")
            )
        ]
        ppid_names = {str(step.api).lower() for step in ppid_steps}
        if (
            any("openprocess" in name for name in ppid_names)
            and any("updateprocthreadattribute" in name for name in ppid_names)
            and any("createprocess" in name for name in ppid_names)
        ):
            candidates.append(
                {
                    "kind": "ppid_spoofing",
                    "api_sequence": [step.api for step in ppid_steps],
                    "static_only": True,
                    "attack_technique": "T1134.004",
                }
            )
        candidate("network_staging", ("network_operation", "write_memory"), "T1071")
        candidate("dynamic_loader", ("dynamic_resolution", "start_thread_or_inject"), "T1129")
        confidence = "HIGH" if candidates and not unknowns else "MEDIUM" if candidates else "LOW"
        if not steps:
            unknowns.append("no ordered instructions or call references available")
        return StaticSimulationResult(name, entry, tuple(steps), tuple(conditions[: self.max_paths]), registers.as_dict(), memory.as_dict(), tuple(candidates), tuple(dict.fromkeys(unknowns)), tuple(dict.fromkeys(limitations)), confidence)


def simulation_evidence_from_function(
    function: Mapping[str, object],
    *,
    source_evidence_ids: Iterable[str] = (),
    max_steps: int | None = None,
) -> dict[str, object]:
    """Return an Evidence-ready value without executing untrusted input.

    ``max_steps`` defaults to the configured guard
    (``STATIC_ABSTRACT_EXECUTION_MAX_STEPS``) so a caller cannot silently
    reintroduce a small analysis quota by omitting the argument.
    """
    budget = int(max_steps) if max_steps is not None else _configured_max_steps()
    if budget < 1:
        raise ValueError("max_steps must be positive")
    value = StaticAbstractExecutor(max_steps=budget).analyze(
        function, source_evidence_ids=source_evidence_ids
    ).as_dict()
    # Keep the abstract execution trace and a compact semantic slice together.
    # This gives the investigator source/sink/condition context without
    # flooding the model with every raw instruction.  The slice uses the same
    # configured budget as the trace instead of a second, smaller cap; the
    # exporter bounds native P-code rows independently.
    try:
        from threat_report_agent.static.static_analysis import build_pcode_slice

        value["pcode_slice"] = build_pcode_slice(
            function, source_evidence_ids=source_evidence_ids, max_operations=budget
        )
        from threat_report_agent.static.static_analysis import track_indirect_function_pointers

        value["indirect_function_pointer_links"] = list(
            track_indirect_function_pointers(function)
        )
    except ImportError:  # pragma: no cover - defensive for minimal installs
        value["pcode_slice"] = {"kind": "pcode_slice", "static_only": True, "operations": []}
    return value
