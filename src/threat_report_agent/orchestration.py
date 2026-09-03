from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import pairwise
from operator import add
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

from threat_report_agent.contracts import (
    ActionProposal,
    FourChannelInput,
    Hypothesis,
    InvestigationThread as ContractInvestigationThread,
    Mechanism,
)
from threat_report_agent.policy import PolicyDecision, PolicyRegistry


class InvestigationState(TypedDict):
    manifest: FourChannelInput
    stages: Annotated[list[str], add]


@dataclass(frozen=True)
class InvestigationPlan:
    stages: tuple[str, ...]
    analysis_modules: tuple[str, ...]
    action_proposals: tuple[ActionProposal, ...]
    policy_decisions: tuple[PolicyDecision, ...]
    preset_catalog_digest: str
    investigation_threads: tuple[ContractInvestigationThread, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    mechanisms: tuple[Mechanism, ...] = ()
    seed_rankings: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True)
class InvestigationSeed:
    """Deterministic priority seed used before any model turn."""

    artifact_id: str
    priority: int
    question: str
    rationale: str
    expected_tools: tuple[str, ...]


@dataclass(frozen=True)
class AtomicInvestigationQuestion:
    """A bounded, mechanism-oriented question produced from a case goal."""

    thread_type: str
    question: str
    target_anchors: tuple[str, ...]
    required_evidence_kinds: tuple[str, ...]
    success_requirements: tuple[str, ...]
    stop_conditions: tuple[str, ...]


class QuestionCompiler:
    """Compile broad case goals into deterministic, auditable thread questions.

    This is deliberately conservative. It recognizes explicit analyst anchors
    (function names/addresses and API names) and otherwise emits a fixed set of
    mechanism questions appropriate for the detected artifact type. No Gold
    answers or sample-specific strings are consulted.
    """

    _PE_PROFILES = (
        (
            "TRACE_DYNAMIC_API_RESOLUTION",
            "Which APIs are resolved dynamically by the identified resolver and where are they consumed?",
            ("function", "decompile", "pcode", "data_reference", "call", "value_flow"),
            ("resolver identified", "at least one API identity recovered", "consumer identified"),
        ),
        (
            "TRACE_DECODE_CONFIGURATION",
            "How does the candidate decoder transform its input bytes and where is the decoded value consumed?",
            ("decompile", "pcode", "data_reference", "decoded_string", "value_flow"),
            ("decoder identified", "transformation or constants recovered", "decoded consumer identified"),
        ),
        (
            "TRACE_PROCESS_CREATION",
            "What process-creation inputs and attributes reach the child-process API?",
            ("function", "call", "constant", "value_flow", "decompile"),
            ("process API identified", "creation flags or attributes evaluated", "source value traced"),
        ),
        (
            "TRACE_NETWORK_CONSUMER",
            "Which statically observed endpoint or transport APIs are consumed by a concrete call path?",
            ("string", "import_symbol", "function", "call", "value_flow"),
            ("endpoint or transport identified", "call path linked", "consumer function identified"),
        ),
        (
            "TRACE_ENTRY_TIMELINE",
            "What ordered static call path leaves the entrypoint and reaches high-value behavior?",
            ("pe_structure", "function", "call", "cfg_block", "xref"),
            ("entrypoint resolved", "ordered calls recovered", "terminal behavior classified"),
        ),
    )

    _SCRIPT_PROFILE = (
        "TRACE_SCRIPT_BEHAVIOR",
        "Which script lines and imported calls form a decode, network, or execution chain?",
        ("script_line", "script_import", "script_call", "decoded_string", "value_flow"),
        ("relevant lines identified", "call chain linked", "behavioral consumer identified"),
    )

    _DOCUMENT_PROFILE = (
        "TRACE_CARRIER_CONTENT",
        "Which embedded object or active-content path is statically recoverable from this carrier?",
        ("document_metadata", "embedded_object", "document_url", "content_manifest"),
        ("carrier feature identified", "embedded object classified", "recursive analysis scope decided"),
    )

    _PE_ANTI_PROFILE = (
        "TRACE_ANTI_ANALYSIS",
        "Which environment, debugger, or service checks gate the recovered behavior path?",
        ("function", "call", "constant", "value_flow", "decompile"),
        ("check identified", "gated branch located", "security meaning bounded"),
    )

    def compile(
        self,
        case_goal: str,
        *,
        artifact_id: str,
        detected_type: str,
        evidence_kinds: tuple[str, ...] = (),
        target_anchors: tuple[str, ...] = (),
    ) -> tuple[AtomicInvestigationQuestion, ...]:
        goal = str(case_goal or "").strip()
        # Explicit function/address/API anchors make a single question more
        # useful than emitting unrelated generic threads.
        import re

        anchors = list(target_anchors)
        for token in re.findall(r"\b(?:FUN_[0-9A-Fa-f]+|0x[0-9A-Fa-f]+|[A-Za-z]+(?:Process|Thread|WinHttp|EtwEventWrite|GetProcAddress))\b", goal):
            if token not in anchors:
                anchors.append(token)
        lowered = goal.casefold()
        broad_terms = sum(
            term in lowered for term in ("loading", "decode", "execution", "network", "evasion")
        )
        if broad_terms >= 3 and not anchors:
            return tuple(
                self._make(profile, artifact_id, [label], "")
                for profile, label in zip(
                    self._PE_PROFILES,
                    ("loading", "decode", "execution", "network", "entrypoint"),
                    strict=True,
                )
            )
        if "resolved" in lowered or "dynamic api" in lowered or "getprocaddress" in lowered:
            profile = self._PE_PROFILES[0]
            return (self._make(profile, artifact_id, anchors or ["resolver"] , goal),)
        if "decode" in lowered or "xor" in lowered or "decrypt" in lowered:
            profile = self._PE_PROFILES[1]
            return (self._make(profile, artifact_id, anchors or ["decoder"], goal),)
        if "process" in lowered or "ppid" in lowered or "createprocess" in lowered:
            profile = self._PE_PROFILES[2]
            return (self._make(profile, artifact_id, anchors or ["process_creation"], goal),)
        if "network" in lowered or "http" in lowered or "endpoint" in lowered:
            profile = self._PE_PROFILES[3]
            return (self._make(profile, artifact_id, anchors or ["network_consumer"], goal),)
        if "entrypoint" in lowered or "timeline" in lowered:
            profile = self._PE_PROFILES[4]
            return (self._make(profile, artifact_id, anchors or ["entrypoint"], goal),)

        detected = detected_type.casefold()
        if detected == "pe":
            # Once baseline evidence exists, compile only the questions
            # justified by observed signal classes. This avoids sending every
            # PE through the same dynamic-resolver playbook.
            kinds = {str(item).casefold() for item in evidence_kinds}
            signal_profiles: list[tuple[tuple[object, ...], str]] = []
            if any(token in kind for kind in kinds for token in ("decode", "decrypt", "crypto", "resource", "encoded", "compression")):
                signal_profiles.append((self._PE_PROFILES[1], "decode"))
            if any(token in kind for kind in kinds for token in ("network", "endpoint", "socket", "http", "url", "dns", "c2")):
                signal_profiles.append((self._PE_PROFILES[3], "network"))
            if any(token in kind for kind in kinds for token in ("process", "execution", "injection", "thread", "ppid")):
                signal_profiles.append((self._PE_PROFILES[2], "execution"))
            if any(token in kind for kind in kinds for token in ("anti", "environment", "service", "debug")):
                signal_profiles.append((self._PE_ANTI_PROFILE, "anti-analysis"))
            if any(token in kind for kind in kinds for token in ("dynamic", "resolver", "getprocaddress", "function_pointer")):
                signal_profiles.append((self._PE_PROFILES[0], "resolver"))
            if not signal_profiles:
                signal_profiles.append((self._PE_PROFILES[4], "entrypoint"))
            return tuple(
                self._make(profile, artifact_id, anchors or [label], "")
                for profile, label in signal_profiles
            )
        if detected == "script":
            return (self._make(self._SCRIPT_PROFILE, artifact_id, anchors or ["script_entry"], goal),)
        if detected in {"pdf", "ole", "ooxml"}:
            return (self._make(self._DOCUMENT_PROFILE, artifact_id, anchors or ["carrier"], goal),)
        # Unknown mechanisms still receive atomic, evidence-oriented questions.
        # They are deliberately generic and cannot produce a verified critical
        # finding without a specialist verifier.
        generic = (
            "GENERIC_MECHANISM_INVESTIGATION",
            "What input reaches the target, what transformation or condition is applied, what consumes the output, and which evidence is still missing?",
            ("function_context", "function_call", "data_reference", "value_flow", "decompile", "pcode_slice"),
            ("target identified", "input or source traced", "transformation/condition assessed", "consumer or missing evidence recorded"),
        )
        return (self._make(generic, artifact_id, anchors or ["artifact"], goal),)

    @staticmethod
    def _make(profile: tuple[str, str, tuple[str, ...], tuple[str, ...]], artifact_id: str, anchors: list[str], goal: str) -> AtomicInvestigationQuestion:
        thread_type, template, kinds, success = profile
        anchor_text = ", ".join(anchors)
        question = goal if goal and len(goal) <= 1000 and not any(token in goal.casefold() for token in ("what malicious things", "analyze execution/network/evasion")) else template
        if goal and question == goal and anchor_text and not any(anchor.casefold() in question.casefold() for anchor in anchors):
            question = f"{template} Target: {anchor_text}."
        elif question == template and anchor_text:
            question = f"{template} Target: {anchor_text}."
        return AtomicInvestigationQuestion(
            thread_type=thread_type,
            question=question,
            target_anchors=tuple(dict.fromkeys(anchors)),
            required_evidence_kinds=kinds,
            success_requirements=success,
            stop_conditions=("CONFIRMED", "STATIC_BOUNDARY", "NO_NEW_EVIDENCE"),
        )


class DeterministicSeedRanker:
    """Rank investigation work from observable type and evidence only.

    The ranker is intentionally model-independent: a provider outage cannot
    remove baseline coverage or leave the scheduler without a question.
    """

    _TYPE_WEIGHTS = {"pe": 10, "script": 20, "ole": 25, "ooxml": 25, "pdf": 25, "zip": 30}

    def rank(self, artifacts: list[dict[str, object]]) -> tuple[InvestigationSeed, ...]:
        seeds: list[InvestigationSeed] = []
        for index, artifact in enumerate(artifacts):
            artifact_id = str(artifact.get("artifact_id", ""))
            if not artifact_id:
                continue
            detected_type = str(artifact.get("detected_type", "unknown")).lower()
            evidence_kinds = {
                str(item)
                for item in artifact.get("evidence_kinds", [])
                if isinstance(item, str)
            }
            if detected_type == "pe":
                question = "Which ordered call/data paths explain loading, decode, execution, network, or evasion?"
                tools = ("pe-parser", "ghidra-headless")
            elif detected_type == "script":
                question = "Which script lines and imports form a decode, network, or execution chain?"
                tools = ("script-parser",)
            elif detected_type in {"pdf", "ooxml", "ole"}:
                question = "Does the carrier contain an embedded object or active content requiring recursive analysis?"
                tools = ("document-carrier-parser",)
            else:
                question = "What deterministic static observations can explain this artifact's role?"
                tools = ("builtin-static-analyzer",)
            signal_bonus = -min(8, len(evidence_kinds))
            seeds.append(
                InvestigationSeed(
                    artifact_id=artifact_id,
                    priority=self._TYPE_WEIGHTS.get(detected_type, 40) + index + signal_bonus,
                    question=question,
                    rationale=f"type={detected_type}; evidence_kinds={sorted(evidence_kinds)[:8]}",
                    expected_tools=tools,
                )
            )
        return tuple(sorted(seeds, key=lambda item: (item.priority, item.artifact_id)))


class QuestionCentricContextBuilder:
    """Build a bounded context packet for a single investigation question."""

    def __init__(self, max_bytes: int = 2_000_000) -> None:
        self.max_bytes = max(1024, max_bytes)

    def build(
        self,
        *,
        question: str,
        artifact: dict[str, object],
        evidence: list[dict[str, object]],
        hypotheses: list[dict[str, object]] | None = None,
        call_graph: dict[str, object] | None = None,
        contradictions: list[dict[str, object]] | None = None,
        open_unknowns: list[str] | None = None,
        action_history: list[dict[str, object]] | None = None,
        pcode_slice: list[dict[str, object]] | None = None,
        allowed_actions: list[str] | None = None,
        evidence_budget: int | None = None,
        mechanism_requirements: list[str] | None = None,
        forbidden_inferences: list[str] | None = None,
    ) -> dict[str, object]:
        packet: dict[str, object] = {
            "question": question,
            "artifact": artifact,
            "hypotheses": list(hypotheses or []),
            "call_graph": dict(call_graph or {}),
            "pcode_slice": list(pcode_slice or []),
            "contradictions": list(contradictions or []),
            "open_unknowns": list(open_unknowns or []),
            "action_history": list(action_history or []),
            "allowed_actions": list(allowed_actions or []),
            "evidence_budget": evidence_budget if evidence_budget is not None else len(evidence),
            "mechanism_requirements": list(mechanism_requirements or []),
            "forbidden_inferences": list(forbidden_inferences or [
                "do not treat an import or string alone as proof of execution",
                "do not infer runtime behavior from static absence",
            ]),
            "evidence": [],
            "omitted_evidence_count": 0,
        }
        selected: list[dict[str, object]] = []
        for row in evidence:
            candidate = {
                "evidence_id": row.get("evidence_id"),
                "kind": row.get("kind"),
                "nature": row.get("nature"),
                "value": row.get("value"),
                "anchor": row.get("anchor"),
            }
            trial = {**packet, "evidence": [*selected, candidate]}
            size = len(str(trial).encode("utf-8"))
            if size > self.max_bytes:
                break
            selected.append(candidate)
        packet["evidence"] = selected
        packet["omitted_evidence_count"] = max(0, len(evidence) - len(selected))
        return packet


def _stage(name: str):
    def node(_: InvestigationState) -> dict[str, list[str]]:
        return {"stages": [name]}

    return node


class StaticInvestigationOrchestrator:
    def __init__(self, policy: PolicyRegistry) -> None:
        self.policy = policy
        builder = StateGraph(InvestigationState)
        stages = (
            "validate_inputs",
            "schedule_intake",
            "schedule_triage",
            "schedule_static_modules",
            "finalize",
        )
        for stage in stages:
            builder.add_node(stage, _stage(stage))
        builder.add_edge(START, stages[0])
        for current, target in pairwise(stages):
            builder.add_edge(current, target)
        builder.add_edge(stages[-1], END)
        self.graph = builder.compile()

    def plan(
        self,
        manifest: FourChannelInput,
        *,
        target_artifact_id: str,
    ) -> InvestigationPlan:
        preset = self.policy.require_preset(manifest.task_request.preset_id)
        ranked_seeds = DeterministicSeedRanker().rank(
            [
                {
                    "artifact_id": target_artifact_id,
                    "detected_type": manifest.sample_package.source_kind,
                    "evidence_kinds": (),
                }
            ]
        )
        detected_type = manifest.sample_package.source_kind
        compiled_questions = QuestionCompiler().compile(
            "",
            artifact_id=target_artifact_id,
            detected_type=detected_type,
        )
        primary_question = compiled_questions[0]
        result = self.graph.invoke({"manifest": manifest, "stages": []})
        def make_thread(question: AtomicInvestigationQuestion) -> tuple[ContractInvestigationThread, Hypothesis, Mechanism]:
            thread_id = self._stable_id("thread", target_artifact_id, manifest.task_request.preset_id, question.thread_type)
            return (
                ContractInvestigationThread(
                    id=thread_id, artifact_id=target_artifact_id, state="PRIORITIZED",
                    question=question.question, seed_kind=question.thread_type,
                ),
                Hypothesis(
                    id=self._stable_id("hypothesis", thread_id, "mechanism"), thread_id=thread_id,
                    statement=f"Static evidence can determine whether the {question.thread_type.lower()} question is supported.",
                    dimension=question.thread_type.lower(),
                ),
                Mechanism(
                    id=self._stable_id("mechanism", thread_id, "static"), thread_id=thread_id,
                    dimension=question.thread_type.lower(), type=question.thread_type,
                    status="UNKNOWN",
                    limitations=("No runtime execution or network access is permitted in this phase.",),
                ),
            )

        thread_parts = tuple(make_thread(item) for item in compiled_questions)
        threads = tuple(item[0] for item in thread_parts)
        hypotheses = tuple(item[1] for item in thread_parts)
        mechanisms = tuple(item[2] for item in thread_parts)
        thread = threads[0]
        proposals = tuple(
            ActionProposal(
                tool_name=tool_name,
                target_artifact_id=target_artifact_id,
                reason=f"Execute preset {preset.id} for investigation question",
                expected_evidence=self._expected_evidence(tool_name),
                cpu_seconds=300 if tool_name == "ghidra-headless" else 60,
                memory_mb=4096 if tool_name == "ghidra-headless" else 512,
                investigation_thread_id=thread.id,
                hypothesis_id=hypotheses[0].id,
                question=thread.question,
                analysis_focus=(*self._analysis_focus(tool_name), *primary_question.required_evidence_kinds[:3]),
            )
            for tool_name in preset.tool_names
        )
        decisions = tuple(self.policy.authorize(proposal) for proposal in proposals)
        denied = [
            f"{proposal.tool_name}:{decision.reason}"
            for proposal, decision in zip(proposals, decisions, strict=True)
            if not decision.allowed
        ]
        if denied:
            raise PermissionError("; ".join(denied))
        return InvestigationPlan(
            stages=tuple(result["stages"]),
            analysis_modules=preset.analysis_modules,
            action_proposals=proposals,
            policy_decisions=decisions,
            preset_catalog_digest=self.policy.catalog_digest,
            investigation_threads=threads,
            hypotheses=hypotheses,
            mechanisms=mechanisms,
            seed_rankings=tuple(
                {
                    "artifact_id": seed.artifact_id,
                    "priority": seed.priority,
                    "seed_kind": primary_question.thread_type,
                    "question": seed.question,
                    "rationale": seed.rationale,
                    "expected_tools": list(seed.expected_tools),
                    "required_evidence_kinds": list(primary_question.required_evidence_kinds),
                    "success_requirements": list(primary_question.success_requirements),
                    "stop_conditions": list(primary_question.stop_conditions),
                }
                for seed in ranked_seeds
            ),
        )

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:20]
        return f"{prefix}-{digest}"

    @staticmethod
    def _expected_evidence(tool_name: str) -> tuple[str, ...]:
        return {
            "python-zipfile-safe-reader": ("archive_member", "content_manifest"),
            "pe-parser": ("pe_structure", "import_symbol", "string", "resource_inventory"),
            "script-parser": ("script_import", "script_call", "script_line"),
            "document-carrier-parser": ("document_metadata", "embedded_object", "document_url"),
            "builtin-static-analyzer": ("file_identity", "string", "indicator"),
            "ghidra-headless": ("function", "xref", "cfg_block", "function_mechanism"),
        }.get(tool_name, ("specialist_observation",))

    @staticmethod
    def _analysis_focus(tool_name: str) -> tuple[str, ...]:
        return {
            "pe-parser": ("identity", "imports", "sections", "resources"),
            "ghidra-headless": ("call_graph", "rva", "cfg", "mechanism_chain"),
            "script-parser": ("line_evidence", "imports", "calls"),
            "document-carrier-parser": ("carrier", "embedded_objects", "urls"),
            "python-zipfile-safe-reader": ("recursive_inventory", "password_gate"),
        }.get(tool_name, ("static_observation",))
