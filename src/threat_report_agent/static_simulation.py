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


@dataclass(frozen=True)
class AbstractValue:
    """A bounded value in the abstract state."""

    kind: str
    value: object
    source: str | None = None

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
        return {
            "simulation_kind": "static_abstract_execution",
            "runtime_observed": False,
            "predicted": True,
            "function": self.function,
            "entry": self.entry,
            "confidence": self.confidence,
            "steps": [item.as_dict() for item in self.steps],
            "path_conditions": [item.as_dict() for item in self.path_conditions],
            "register_state": self.register_state,
            "memory_state": self.memory_state,
            "mechanism_candidates": list(self.mechanism_candidates),
            "unknowns": list(self.unknowns),
            "limitations": list(self.limitations),
        }


_REGISTER = r"(?:r(?:[abcd]x|[sd]i|[sb]p|ip)|e?[abcd]x|e?[sd]i|e?[sb]p|[abcd][lh])"
_IMM_RE = re.compile(r"(?:0x[0-9a-f]+|[-+]?\d+)", re.I)
_JUMP_RE = re.compile(r"\b(?:J[A-Z]{1,3}|LOOP[A-Z]*)\b", re.I)


class StaticAbstractExecutor:
    """Walk bounded static facts and infer likely API/data-flow stages."""

    def __init__(self, *, max_steps: int = 256, max_paths: int = 4) -> None:
        if max_steps < 1 or max_paths < 1:
            raise ValueError("max_steps and max_paths must be positive")
        self.max_steps = max_steps
        self.max_paths = max_paths

    @staticmethod
    def _call_name(row: Mapping[str, object]) -> str:
        return str(row.get("target_name") or row.get("target_function") or row.get("api") or "").strip()

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
                registers.set(register, AbstractValue("derived", f"{op}({previous.value if previous else '?'},{value if value is not None else raw})", f"instruction:{index}"))
            outputs[register] = registers.get(register).as_dict() if registers.get(register) else {}
            return "arithmetic", inputs, outputs
        compare = re.search(r"\b(CMP|TEST)\s+([^,;]+)(?:\s*,\s*([^,;]+))?", upper)
        if compare:
            op, left, right = compare.groups()
            expression = f"{left.strip()} {op.lower()} {right.strip() if right else 'nonzero'}"
            conditions.append(PathCondition(expression, f"instruction:{index}", False))
            return "branch_condition", {"operator": op, "left": left.strip(), "right": right}, {}
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
        call_rows = function.get("references_from", [])
        calls = [row for row in call_rows if isinstance(row, Mapping) and "call" in str(row.get("type", "")).lower()] if isinstance(call_rows, list) else []
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


def simulation_evidence_from_function(function: Mapping[str, object], *, source_evidence_ids: Iterable[str] = (), max_steps: int = 256) -> dict[str, object]:
    """Return an Evidence-ready value without executing untrusted input."""
    value = StaticAbstractExecutor(max_steps=max_steps).analyze(
        function, source_evidence_ids=source_evidence_ids
    ).as_dict()
    # Keep the abstract execution trace and a compact semantic slice together.
    # This gives the investigator source/sink/condition context without
    # flooding the model with every raw instruction.
    try:
        from threat_report_agent.static_analysis import build_pcode_slice

        value["pcode_slice"] = build_pcode_slice(
            function, source_evidence_ids=source_evidence_ids, max_operations=min(max_steps, 128)
        )
        from threat_report_agent.static_analysis import track_indirect_function_pointers

        value["indirect_function_pointer_links"] = list(
            track_indirect_function_pointers(function)
        )
    except ImportError:  # pragma: no cover - defensive for minimal installs
        value["pcode_slice"] = {"kind": "pcode_slice", "static_only": True, "operations": []}
    return value
