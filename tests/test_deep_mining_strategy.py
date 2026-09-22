from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    Investigator,
    DeepMiningPlanner,
    InvestigationLoopDriver,
    investigation_next_method,
    completed_investigation_methods,
)
from threat_report_agent.evidence_recovery import canonical_action_key
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService


def _function(entry: str, name: str, *apis: str) -> dict[str, object]:
    return {
        "id": f"ctx-{entry}",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {
            "name": name,
            "entry": entry,
            "call_targets": [{"target_name": api, "from": entry} for api in apis],
            "data_references": [{"to": f"data-{entry}"}],
        },
        "anchor": {"function_entry": entry},
    }


def test_deep_mining_frontier_ranks_and_covers_each_high_value_function() -> None:
    rows = [
        _function("0x1000", "entry_orchestrator", "GetProcAddress", "CreateProcessW"),
        _function("0x2000", "decode_config", "VirtualProtect"),
        {"id": "i1", "kind": "import_symbol", "nature": "STATIC_OBSERVED", "value": {"name": "GetProcAddress"}, "anchor": {}},
        {"id": "i2", "kind": "import_symbol", "nature": "STATIC_OBSERVED", "value": {"name": "CreateProcessW"}, "anchor": {}},
        {"id": "s1", "kind": "string", "nature": "STATIC_OBSERVED", "value": {"text": "https://example.invalid/gate"}, "anchor": {"function_entry": "0x2000"}},
    ]

    planner = DeepMiningPlanner()
    frontier = planner.build_frontier(rows)
    targets = {item.selector["function_entry"] for item in frontier if "function_entry" in item.selector}

    assert {"0x1000", "0x2000"} <= targets
    assert frontier[0].priority < frontier[-1].priority
    planned = planner.plan_actions(rows, scheduled=set(), max_actions=32)
    assert any(item.action_type == ActionType.GET_DECOMPILE and item.parameters.get("target") == "0x1000" for item in planned)
    assert any(item.action_type == ActionType.GET_PCODE_SLICE and item.parameters.get("target") == "0x2000" for item in planned)
    assert all(item.plan.get("missing_evidence") for item in planned)


def test_recovered_createthread_start_routine_becomes_its_own_frontier_target() -> None:
    """A CreateThread listing is not closed; recovered lpStartAddress must be investigated."""
    caller = _function("0x401000", "spawn_worker", "CreateThread")
    trace = {
        "id": "trace-createthread",
        "kind": "api_argument_trace",
        "nature": "STATIC_DERIVED",
        "value": {
            "api": "CreateThread",
            "function_entry": "0x401000",
            "arguments": [
                {"index": 0, "register": "RCX", "value": "0x0", "resolved": True},
                {"index": 1, "register": "RDX", "value": "0x0", "resolved": True},
                {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
            ],
        },
        "anchor": {"function_entry": "0x401000"},
    }
    frontier = DeepMiningPlanner.build_frontier([caller, trace], max_targets=32)
    start_targets = [
        item
        for item in frontier
        if item.selector.get("function_entry") == "0x401500"
        and item.category == "thread_start_routine"
    ]
    assert start_targets, frontier
    assert start_targets[0].priority <= 12
    assert "0x401500" in start_targets[0].question

    planned = DeepMiningPlanner.plan_actions([caller, trace], scheduled=set(), max_actions=24)
    start_actions = [
        item for item in planned if item.parameters.get("target") == "0x401500"
    ]
    assert start_actions
    assert start_actions[0].action_type == ActionType.GET_DECOMPILE
    required = start_actions[0].plan["deep_investigation_contract"]["required_action_types"]
    assert ActionType.GET_DECOMPILE.value in required
    assert ActionType.GET_CFG_SLICE.value in required
    assert ActionType.GET_CALLEES.value in required


def test_same_process_createthread_is_unique_thread_not_injection() -> None:
    rows = [
        _function("0x9000", "spawn_worker", "CreateThread"),
        _function(
            "0x9100",
            "remote_inject",
            "OpenProcess",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ),
    ]
    frontier = DeepMiningPlanner.build_frontier(rows, max_targets=32)
    by_entry = {}
    for item in frontier:
        entry = str(item.selector.get("function_entry") or "")
        by_entry.setdefault(entry, set()).add(item.category)
    assert "thread" in by_entry["0x9000"]
    assert "injection" not in by_entry["0x9000"]
    assert "injection" in by_entry["0x9100"]
    thread_actions = DeepMiningPlanner.plan_actions(
        [rows[0]], scheduled=set(), max_actions=16
    )
    required = thread_actions[0].plan["deep_investigation_contract"]["required_action_types"]
    assert ActionType.TRACE_API_ARGUMENT.value in required
    assert ActionType.GET_DECOMPILE.value in required
    assert ActionType.READ_BYTES.value in required
    assert thread_actions[0].action_type == ActionType.TRACE_API_ARGUMENT
    assert any("start" in item.reason.casefold() or "lpstart" in item.reason.casefold() for item in thread_actions)


def test_deep_mining_frontier_keeps_independent_mechanisms_on_one_function() -> None:
    """A multi-capability function receives one target per mechanism dimension."""
    rows = [
        _function(
            "0x7000",
            "resolve_decode_spawn",
            "GetProcAddress",
            "CreateProcessW",
            "WinHttpSendRequest",
        ),
        {
            "id": "decode-window-7000",
            "kind": "mechanism_decode_window",
            "nature": "STATIC_DERIVED",
            "value": {"function_entry": "0x7000", "transformation": "xor"},
            "anchor": {"function_entry": "0x7000"},
        },
    ]

    frontier = DeepMiningPlanner.build_frontier(rows, max_targets=32)
    categories = {
        item.category
        for item in frontier
        if item.selector.get("function_entry") == "0x7000"
    }
    assert {"decode", "network", "loader", "process"} <= categories

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=32)
    more = DeepMiningPlanner.plan_actions(
        rows,
        scheduled={item.dedupe_key for item in actions},
        max_actions=32,
    )
    scoped_actions = {
        str(item.plan["deep_investigation_contract"]["category"])
        for item in (*actions, *more)
        if item.parameters.get("target") == "0x7000"
        and isinstance(item.plan.get("deep_investigation_contract"), dict)
    }
    assert {"decode", "network", "loader", "process"} <= scoped_actions


def test_action_dedupe_scope_does_not_cross_mechanism_questions() -> None:
    """Same action and RVA may run for independent mechanism contracts."""
    def action(scope: str) -> ActionSpec:
        return ActionSpec(
            id=f"{scope}-trace",
            action_type=ActionType.TRACE_API_ARGUMENT,
            thread_id=scope,
            hypothesis_id=f"h-{scope}",
            artifact_id="artifact",
            parameters={"target": "0x7000"},
            target_selector={"target": "0x7000"},
            expected_evidence_kinds=("api_argument_trace",),
            plan={"deep_investigation_contract": {"category": scope}},
        )

    process = action("process")
    network = action("network")
    assert process.dedupe_key != network.dedupe_key


def test_deep_mining_actions_preserve_their_function_evidence_anchor() -> None:
    """A function investigation must retain the evidence that selected it."""
    rows = [
        _function("0x1000", "entry_orchestrator", "GetProcAddress"),
        _function("0x2000", "network_worker", "WinHttpSendRequest"),
    ]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=16)
    function_action = next(
        item
        for item in actions
        if item.action_type == ActionType.GET_DECOMPILE
        and item.parameters.get("target") == "0x1000"
    )

    assert function_action.source_evidence_ids == ("ctx-0x1000",)


def test_admitted_deep_targets_fit_their_required_static_coverage_budget() -> None:
    """The planner must not admit more targets than it can inspect deeply."""
    rows = [
        _function(f"0x{0x1000 + index * 0x100:x}", f"spawn_{index}", "CreateProcessW")
        for index in range(6)
    ]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=24)
    contracts: dict[str, set[str]] = {}
    admitted: dict[str, set[str]] = {}
    for action in actions:
        target = str(action.parameters.get("target", ""))
        contract = action.plan.get("deep_investigation_contract", {})
        if not target or not isinstance(contract, dict):
            continue
        contracts.setdefault(target, set()).update(
            str(item) for item in contract.get("required_action_types", [])
        )
        admitted.setdefault(target, set()).add(action.action_type.value)

    assert contracts
    assert all(contracts[target] <= admitted[target] for target in contracts)
    assert len(actions) <= 24
    top = str(actions[0].parameters.get("target"))
    assert ActionType.CONTROLLED_EMULATE.value in admitted[top]


def test_deep_mining_advances_to_unserved_targets_before_optional_reads() -> None:
    """A second planning pass cannot keep spending depth on the first window."""
    rows = [
        _function(f"0x{0x1000 + index * 0x100:x}", f"spawn_{index}", "CreateProcessW")
        for index in range(8)
    ]

    first = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=24)
    second = DeepMiningPlanner.plan_actions(
        rows,
        scheduled={item.dedupe_key for item in first},
        max_actions=24,
    )

    first_targets = {str(item.parameters.get("target")) for item in first}
    second_targets = {str(item.parameters.get("target")) for item in second}
    assert first_targets
    assert second_targets
    assert not first_targets & second_targets
    assert ActionType.CONTROLLED_EMULATE in {
        item.action_type for item in first if item.parameters.get("target") == "0x1000"
    }

    for target in first_targets:
        target_actions = [item for item in first if item.parameters.get("target") == target]
        required = set(target_actions[0].plan["deep_investigation_contract"]["required_action_types"])
        assert required <= {item.action_type.value for item in target_actions}


def test_best_first_queues_emulation_before_spreading_across_functions() -> None:
    """Kunglao priority_ratio: one conversation pass must reach CONTROLLED_EMULATE."""
    rows = [
        _function(f"0x{0x1000 + index * 0x100:x}", f"spawn_{index}", "CreateProcessW")
        for index in range(12)
    ]
    planned = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=24)
    assert ActionType.CONTROLLED_EMULATE in {item.action_type for item in planned}
    first_target = str(planned[0].parameters.get("target"))
    first_types = {item.action_type for item in planned if item.parameters.get("target") == first_target}
    assert ActionType.CONTROLLED_EMULATE in first_types


def test_investigation_next_method_reaches_emulation_before_static_boundary() -> None:
    """Two dry static methods are not a boundary until CONTROLLED_EMULATE."""
    assert (
        investigation_next_method(
            ActionType.GET_XREFS_FROM,
            ["GET_XREFS_TO", "GET_XREFS_FROM"],
        )
        == ActionType.GET_DECOMPILE.value
    )
    assert (
        investigation_next_method(
            ActionType.GET_DECOMPILE,
            ["GET_XREFS_TO:prior", "GET_XREFS_FROM:alt", "GET_DECOMPILE:entry"],
        )
        == ActionType.CONTROLLED_EMULATE.value
    )
    assert (
        investigation_next_method(
            ActionType.CONTROLLED_EMULATE,
            ["GET_DECOMPILE", "CONTROLLED_EMULATE"],
        )
        == "STATIC_BOUNDARY"
    )


def test_placeholder_emulate_is_not_a_completed_method() -> None:
    """A DEFERRED_TO_WORKER row must not stamp STATIC_BOUNDARY."""
    actions = [
        SimpleNamespace(action_type=ActionType.GET_DECOMPILE),
        SimpleNamespace(action_type=ActionType.CONTROLLED_EMULATE),
    ]
    placeholder = [
        {
            "kind": "simulation_result",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        }
    ]
    names = completed_investigation_methods(actions, placeholder)
    assert "CONTROLLED_EMULATE" not in names
    assert (
        investigation_next_method(ActionType.CONTROLLED_EMULATE, names)
        == ActionType.CONTROLLED_EMULATE.value
    )
    failed = [
        {
            "kind": "simulation_result",
            "value": {"status": "FAILED", "simulator": "unicorn", "function_entry": "0x401000"},
        }
    ]
    assert "CONTROLLED_EMULATE" in completed_investigation_methods(actions, failed)
    assert (
        investigation_next_method(
            ActionType.CONTROLLED_EMULATE,
            completed_investigation_methods(actions, failed),
        )
        == "STATIC_BOUNDARY"
    )


def test_deep_mining_contract_completes_required_static_facets_before_claim_ready() -> None:
    """A generic candidate gate cannot truncate a high-risk function investigation.

    The first argument trace already makes the generic ClaimGate eligible.  A
    process-creation lead still needs the bounded P-code, data, CFG and
    downstream-call facets before the thread can be marked claim-ready.
    """
    initial = _function("0x401000", "spawn_worker", "CreateProcessW")
    executed: list[ActionSpec] = []
    produced_kind = {
        ActionType.TRACE_API_ARGUMENT: "api_argument_trace",
        ActionType.GET_PCODE_SLICE: "pcode_slice",
        ActionType.GET_DATA_REFERENCES: "data_reference",
        ActionType.GET_CFG_SLICE: "cfg_block",
        ActionType.GET_CALLEES: "function_call",
    }

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action)
        kind = produced_kind.get(action.action_type)
        if kind is None:
            return []
        return [
            {
                "id": f"fact-{action.action_type.value}",
                "kind": kind,
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "0x401000", "api": "CreateProcessW"},
                "anchor": {"function_entry": "0x401000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=8).run(
        thread_id="deep-contract",
        artifact_id="artifact",
        question="Which process creation path is statically recoverable?",
        hypothesis_id="hypothesis",
        hypothesis_statement="A function prepares a child process using CreateProcessW.",
        initial_evidence=(initial,),
        execute=execute,
    )

    assert {
        ActionType.TRACE_API_ARGUMENT,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_DATA_REFERENCES,
        ActionType.GET_CFG_SLICE,
        ActionType.GET_CALLEES,
    } <= {item.action_type for item in executed}
    # The synthetic rows do not satisfy the process-execution verifier, which
    # is correct: exhaustive static probing is not permission to overclaim.
    assert result.thread_state.value == "UNKNOWN"
    assert result.coverage["complete"] is True
    assert result.coverage["targets"][0]["status"] == "COVERED"


def test_deep_mining_records_static_boundary_after_exhausting_required_facets() -> None:
    """A dry high-risk target must be a bounded static limitation, not a shortcut.

    Every required static facet is attempted once before the thread becomes
    UNKNOWN.  This prevents two dry probes from silently hiding an otherwise
    important process-creation target.
    """
    executed: list[ActionSpec] = []
    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=1).run(
        thread_id="deep-boundary",
        artifact_id="artifact",
        question="Which process creation path is statically recoverable?",
        hypothesis_id="hypothesis",
        hypothesis_statement="A function prepares a child process using CreateProcessW.",
        initial_evidence=(_function("0x401000", "spawn_worker", "CreateProcessW"),),
        execute=lambda action: executed.append(action) or (),
    )

    assert {
        ActionType.TRACE_API_ARGUMENT,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_DATA_REFERENCES,
        ActionType.GET_CFG_SLICE,
        ActionType.GET_CALLEES,
    } <= {item.action_type for item in executed}
    assert result.thread_state.value == "UNKNOWN"
    assert result.coverage["complete"] is True
    assert any(event.phase == "static_boundary" for event in result.events)


def test_failed_required_facets_cannot_promote_a_candidate_claim() -> None:
    """A failed probe is a boundary, never evidence satisfying its facet.

    The baseline structure and call edge intentionally satisfy the generic
    candidate gate.  Every contract action then fails.  The loop must retain
    the attempt history for auditability but cannot turn it into an
    evidence-backed Claim-ready state.
    """
    initial = (
        _function("0x401000", "worker"),
        {
            "id": "baseline-call",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"function_entry": "0x401000", "api": "helper"},
            "anchor": {"function_entry": "0x401000"},
        },
    )

    def fail(_action: ActionSpec) -> list[dict[str, object]]:
        raise RuntimeError("bounded static tool failure")

    result = InvestigationLoopDriver(max_steps=8).run(
        thread_id="failed-facets",
        artifact_id="artifact",
        question="Which artifact-local behavior path is statically recoverable?",
        hypothesis_id="hypothesis",
        hypothesis_statement="A concrete function participates in a recoverable behavior path.",
        initial_evidence=initial,
        execute=fail,
    )

    assert result.gate.accepted is True
    assert result.thread_state.value == "UNKNOWN"
    # An executor exception leaves every required facet unresolved.  The
    # attempt remains visible in the audit trail, but it is not coverage.
    assert result.coverage["complete"] is False
    assert result.coverage["evidence_complete"] is False
    assert result.coverage["claim_eligible"] is False
    assert result.coverage["targets"][0]["failed_action_types"]
    assert any(event.phase == "static_boundary" for event in result.events)


def test_investigator_never_uses_a_mechanism_label_as_a_static_target() -> None:
    """A capability label cannot substitute for a function/API/RVA anchor."""
    rows = [
        {
            "id": "import-create-process",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        }
    ]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())
    targets = {str(item.parameters.get("target", "")) for item in suggestions}

    assert "PROCESS_EXECUTION" not in targets
    assert "CreateProcessW" in targets


def test_unanchored_api_is_resolved_before_expensive_deep_mining() -> None:
    """An import name is a lead, not a function-level analysis location.

    The first action is intentionally limited to Xref resolution.  Scheduling
    P-code, argument or data-flow work against an unanchored import only
    rediscoveres existing import evidence and consumes the depth budget.
    """
    rows = [
        {
            "id": "import-resolver",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "GetProcAddress", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        }
    ]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=16)

    assert [item.action_type for item in actions] == [ActionType.GET_XREFS_TO]
    assert actions[0].parameters["target"] == "GetProcAddress"


def test_unanchored_api_never_falls_back_to_function_lookup_when_xref_is_pending() -> None:
    """A queued API Xref is progress, not a reason to locate an API as code."""
    lead = {
        "id": "import-virtual-protect",
        "kind": "import_symbol",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "VirtualProtect", "library": "KERNEL32.dll"},
        "anchor": {"type": "pe_import"},
    }
    xref_key = canonical_action_key(
        ActionType.GET_XREFS_TO.value,
        {"target": "VirtualProtect"},
    )

    suggestions = Investigator().propose(evidence=[lead], scheduled={xref_key})

    assert ActionType.GET_FUNCTION not in {item.action_type for item in suggestions}


def test_deep_mining_never_treats_a_pe_header_entry_rva_as_a_function_anchor() -> None:
    """A PE header is a navigation lead, never function-local evidence.

    The historical failure used ``pe_structure.entry_rva`` as if it were a
    Ghidra function context. That scheduled P-code and argument actions on a
    decimal header value rather than on the function recovered at that RVA.
    """
    rows = [
        {
            "id": "pe-header",
            "kind": "pe_structure",
            "nature": "STATIC_OBSERVED",
            "value": {"entry_rva": 5152, "machine": "AMD64"},
            "anchor": {"type": "pe_header"},
        },
        {
            "id": "import-process",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
    ]

    frontier = DeepMiningPlanner.build_frontier(rows)
    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=8)

    assert not any(item.selector.get("function_entry") == "5152" for item in frontier)
    assert all(item.parameters.get("target") != "5152" for item in actions)
    assert [item.action_type for item in actions] == [ActionType.GET_XREFS_TO]


def test_investigator_defers_profile_probes_until_api_has_function_anchor() -> None:
    """Mechanism profiles must not execute function-only probes on an import."""
    rows = [
        {
            "id": "import-process",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        }
    ]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())

    assert suggestions
    assert {item.action_type for item in suggestions} == {ActionType.GET_XREFS_TO}
    assert all(item.parameters["target"] == "CreateProcessW" for item in suggestions)


def test_investigator_does_not_relocate_an_already_recovered_function() -> None:
    """A function context is an anchor, not a reason to query it again.

    Re-running ``GET_FUNCTION`` against a concrete RVA only rediscovered the
    same Ghidra record on real samples. The first useful follow-up must instead
    examine its arguments, control flow, data, or call graph.
    """
    rows = [_function("0x401000", "artifact_local_helper")]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())
    anchored = [item for item in suggestions if item.parameters.get("target") == "0x401000"]

    assert anchored
    assert all(item.action_type != ActionType.GET_FUNCTION for item in anchored)
    assert any(
        item.action_type
        in {
            ActionType.TRACE_API_ARGUMENT,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DATA_REFERENCES,
            ActionType.GET_CFG_SLICE,
            ActionType.GET_CALLEES,
        }
        for item in anchored
    )


def test_ppid_import_lead_starts_with_xref_not_string_enumeration() -> None:
    """A PPID candidate needs a callsite before semantic follow-up actions."""
    rows = [
        {
            "id": "openprocess-import",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "OpenProcess", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "parent-attribute-import",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "UpdateProcThreadAttribute", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "parent-process-string",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"},
            "anchor": {"file_offset": 512},
        },
    ]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())
    openprocess_actions = [item for item in suggestions if item.parameters.get("target") == "OpenProcess"]

    assert openprocess_actions
    assert openprocess_actions[0].action_type == ActionType.GET_XREFS_TO
    assert all(item.action_type != ActionType.GET_STRINGS_REFERENCED for item in openprocess_actions)


def test_import_lead_becomes_function_targeted_deep_mining_after_xref() -> None:
    """The second step must use the concrete callsite recovered by the first.

    This is the smallest end-to-end guard against the historical failure mode:
    repeatedly querying a broad import table while never inspecting the function
    that actually calls the API.
    """
    initial = {
        "id": "import-create-process",
        "kind": "import_symbol",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "CreateProcessW", "library": "KERNEL32.dll"},
        "anchor": {"type": "pe_import"},
    }
    executed: list[ActionSpec] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action)
        if action.action_type == ActionType.GET_XREFS_TO:
            return [
                {
                    "id": "spawn-callsite",
                    "kind": "function_context",
                    "nature": "STATIC_OBSERVED",
                    "value": {
                        "name": "spawn_worker",
                        "entry": "0x401000",
                        "call_targets": [
                            {"target_name": "CreateProcessW", "from": "0x401020"}
                        ],
                    },
                    "anchor": {"function_entry": "0x401000"},
                }
            ]
        if action.target_selector.get("target") == "0x401000":
            return [
                {
                    "id": f"deep-{action.action_type.value}",
                    "kind": "api_argument_trace",
                    "nature": "STATIC_DERIVED",
                    "value": {"api": "CreateProcessW", "function_entry": "0x401000"},
                    "anchor": {"function_entry": "0x401000"},
                }
            ]
        return []

    InvestigationLoopDriver(max_steps=4, max_consecutive_no_gain=2).run(
        thread_id="staged-import",
        artifact_id="artifact",
        question="Which static process-creation path is present?",
        hypothesis_id="staged-hypothesis",
        hypothesis_statement="A concrete CreateProcessW callsite may reveal its arguments and branch.",
        initial_evidence=(initial,),
        execute=execute,
    )

    assert executed[0].action_type == ActionType.GET_XREFS_TO
    assert executed[0].target_selector == {"target": "CreateProcessW"}
    assert any(
        item.action_type in {
            ActionType.TRACE_API_ARGUMENT,
            ActionType.GET_PCODE_SLICE,
            ActionType.GET_DATA_REFERENCES,
            ActionType.GET_CFG_SLICE,
        }
        and item.target_selector == {"target": "0x401000"}
        for item in executed[1:]
    )


def test_xref_provenance_recovers_the_enclosing_function_target() -> None:
    """A derived Xref must promote its cited caller into a function target.

    Ghidra's Xref facts preserve the enclosing function in ``source_anchors``.
    Treating that record as an API-only fact caused the investigation loop to
    schedule ``GET_FUNCTION(CreateProcessW)`` instead of inspecting the
    recovered caller.  The caller provenance is a static, artifact-local
    anchor and is therefore admissible for a bounded deep-mining action.
    """
    derived_xref = {
        "id": "xref-create-process",
        "kind": "function_call",
        "nature": "STATIC_DERIVED",
        "value": {"api": "CreateProcessW", "caller": "FUN_140007a00"},
        "anchor": {
            "type": "investigation_action",
            "source_anchors": [
                {"type": "function_context", "entry": "0x140007a00", "rva": 31232}
            ],
        },
    }

    actions = DeepMiningPlanner.plan_actions([derived_xref], scheduled=set(), max_actions=8)

    assert any(
        item.action_type == ActionType.TRACE_API_ARGUMENT
        and item.parameters.get("target") == "0x140007a00"
        and item.source_evidence_ids == ("xref-create-process",)
        for item in actions
    )


def test_investigator_adds_deep_actions_without_drowning_specialist_targets() -> None:
    rows = [
        _function("0x1000", "resolve_and_dispatch", "GetProcAddress", "WinHttpSendRequest"),
        {"id": "i1", "kind": "import_symbol", "nature": "STATIC_OBSERVED", "value": {"name": "GetProcAddress"}, "anchor": {}},
        {"id": "i2", "kind": "import_symbol", "nature": "STATIC_OBSERVED", "value": {"name": "WinHttpSendRequest"}, "anchor": {}},
    ]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())
    assert any(item.action_type == ActionType.GET_DECOMPILE and item.parameters.get("target") == "0x1000" for item in suggestions)
    assert any(item.action_type == ActionType.GET_XREFS_TO and item.parameters.get("target") == "GetProcAddress" for item in suggestions)
    assert len({item.dedupe_key for item in suggestions}) == len(suggestions)


def test_deep_mining_prioritizes_mechanism_discriminating_actions() -> None:
    """A process seed must recover arguments/data before broad enumeration."""
    rows = [_function("0x1000", "spawn_worker", "CreateProcessW", "OpenProcess")]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=8)
    process_actions = [item for item in actions if item.parameters.get("target") == "0x1000"]

    assert [item.action_type for item in process_actions[:4]] == [
        ActionType.TRACE_API_ARGUMENT,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_DATA_REFERENCES,
        ActionType.GET_CFG_SLICE,
    ]
    assert all(item.source_evidence_ids == ("ctx-0x1000",) for item in process_actions)


def test_run_until_converged_continues_pending_facets_without_duplicate_action_ids() -> None:
    """A bounded round must resume its frontier until the contract is covered."""
    initial = _function("0x401000", "plain_worker")
    executed: list[ActionSpec] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action)
        kind = {
            ActionType.GET_DECOMPILE: "abstract_execution_trace",
            ActionType.GET_PCODE_SLICE: "pcode_slice",
            ActionType.GET_DATA_REFERENCES: "data_reference",
            ActionType.GET_CFG_SLICE: "cfg_block",
            ActionType.GET_CALLEES: "function_call",
        }.get(action.action_type, "investigation_observation")
        return [
            {
                "id": f"{action.id}:result",
                "kind": kind,
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "0x401000", "target": "0x401000"},
                "anchor": {"function_entry": "0x401000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=2).run_until_converged(
        thread_id="continuation-thread",
        artifact_id="artifact-1",
        question="What does this worker do?",
        hypothesis_id="continuation-hypothesis",
        hypothesis_statement="The worker has a statically recoverable call and data-flow path.",
        initial_evidence=(initial,),
        execute=execute,
        max_rounds=4,
    )

    required = {
        ActionType.GET_DECOMPILE,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_DATA_REFERENCES,
        ActionType.GET_CFG_SLICE,
        ActionType.GET_CALLEES,
    }
    assert required <= {action.action_type for action in executed}
    assert len({action.id for action in executed}) == len(executed)
    assert result.coverage["complete"] is True


def test_deep_mining_only_requests_function_strings_when_the_anchor_has_textual_evidence() -> None:
    """A function without textual provenance must not spend a step on strings."""
    function = _function("0x401000", "network_worker", "WinHttpSendRequest")
    without_strings = DeepMiningPlanner.plan_actions([function], scheduled=set(), max_actions=16)
    with_strings = DeepMiningPlanner.plan_actions(
        [
            function,
            {
                "id": "function-url",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "https://example.invalid/path"},
                "anchor": {"function_entry": "0x401000"},
            },
        ],
        scheduled=set(),
        max_actions=16,
    )

    assert not any(
        item.action_type == ActionType.GET_STRINGS_REFERENCED
        and item.parameters.get("target") == "0x401000"
        for item in without_strings
    )
    assert any(
        item.action_type == ActionType.GET_STRINGS_REFERENCED
        and item.parameters.get("target") == "0x401000"
        for item in with_strings
    )


def test_decode_playbook_requires_observed_decode_material() -> None:
    """A decoder-like name is a lead, not a byte-replay authorization."""
    lead_only = [_function("0x401000", "xor_decode_config_helper")]
    candidate = {
        "id": "decode-window",
        "kind": "mechanism_decode_window",
        "nature": "STATIC_DERIVED",
        "value": {"function_entry": "0x401000", "transformation": "xor"},
        "anchor": {"function_entry": "0x401000"},
    }

    without_material = Investigator().propose(evidence=lead_only, scheduled=set())
    with_material = Investigator().propose(evidence=[*lead_only, candidate], scheduled=set())

    assert ActionType.DECODE_CANDIDATE not in {
        item.action_type for item in without_material
    }
    assert any(
        item.action_type == ActionType.DECODE_CANDIDATE
        and item.parameters.get("target") == "0x401000"
        and item.source_evidence_ids == ("decode-window",)
        for item in with_material
    )


def test_decode_playbook_accepts_normalized_decryption_material() -> None:
    """Parser-specific decryption facts must enter the same deep-mining path."""
    rows = [
        _function("0x401000", "xor_decode_config_helper"),
        {
            "id": "decryption-material",
            "kind": "mechanism_decryption",
            "nature": "STATIC_DERIVED",
            "value": {"function_entry": "0x401000", "transformation": "xor"},
            "anchor": {"function_entry": "0x401000"},
        },
    ]

    actions = Investigator().propose(evidence=rows, scheduled=set())

    assert any(
        item.action_type == ActionType.DECODE_CANDIDATE
        and item.parameters.get("target") == "0x401000"
        and item.source_evidence_ids == ("decryption-material",)
        for item in actions
    )


def test_process_profile_preserves_dependency_order_after_function_recovery() -> None:
    """Do not evaluate constants before recovering process arguments/branches."""
    rows = [_function("0x401000", "spawn_worker", "CreateProcessW")]

    actions = Investigator().propose(evidence=rows, scheduled=set())
    process_actions = [
        item
        for item in actions
        if item.parameters.get("target") == "0x401000"
        and item.plan.get("playbook_id") == "v3-process-creation"
    ]

    assert [item.action_type for item in process_actions[:2]] == [
        ActionType.TRACE_API_ARGUMENT,
        ActionType.GET_CFG_SLICE,
    ]
    assert ActionType.EVALUATE_CONSTANT not in {
        item.action_type for item in process_actions[:2]
    }


def test_deep_mining_normalizes_qualified_apis_and_covers_security_relevant_surfaces() -> None:
    """DLL-qualified API facts must not silently fall back to generic probing.

    This regression represents the common Ghidra/PE mismatch: the same API
    can arrive as a qualified import, a thunk name or a plain call target. The
    planner must assign each security-relevant function a question whose first
    action recovers inputs and conditions, rather than merely listing code.
    """
    rows = [
        _function("0x1000", "autorun_writer", "ADVAPI32.DLL!RegSetValueExW"),
        _function("0x2000", "remote_worker", "KERNEL32.dll!CreateRemoteThread"),
        _function("0x3000", "dns_transport", "WS2_32!getaddrinfo"),
        _function("0x4000", "telemetry_gate", "NTDLL!NtQueryInformationProcess"),
    ]

    frontier = DeepMiningPlanner.build_frontier(rows)
    categories = {
        str(item.selector.get("function_entry")): set()
        for item in frontier
        if item.selector.get("function_entry")
    }
    for item in frontier:
        target = str(item.selector.get("function_entry", ""))
        if target in categories:
            categories[target].add(item.category)
    assert "persistence" in categories["0x1000"]
    assert "injection" in categories["0x2000"]
    assert "network" in categories["0x3000"]
    assert "anti_analysis" in categories["0x4000"]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=48)
    for target in categories:
        target_actions = [item for item in actions if item.parameters.get("target") == target]
        assert target_actions
        assert target_actions[0].action_type == ActionType.TRACE_API_ARGUMENT
        assert target_actions[0].plan["question"]
        assert target_actions[0].plan["alternatives"]


def test_investigator_does_not_skip_independent_matching_mechanisms() -> None:
    """One resolver hit must not hide a separate process/network hypothesis."""
    rows = [
        _function("0x1000", "resolve_then_spawn", "GetProcAddress", "CreateProcessW"),
        _function("0x2000", "transport_worker", "WinHttpOpen", "WinHttpSendRequest"),
    ]

    suggestions = Investigator().propose(evidence=rows, scheduled=set())
    profile_ids = {
        str(item.plan.get("playbook_id"))
        for item in suggestions
        if item.plan.get("playbook_id")
    }

    assert {"v3-process-creation", "v3-network-transport"} <= profile_ids
    assert any(
        item.action_type == ActionType.TRACE_API_ARGUMENT
        and item.parameters.get("target") == "0x1000"
        and item.plan.get("playbook_id") == "v3-process-creation"
        and item.source_evidence_ids == ("ctx-0x1000",)
        for item in suggestions
    )
    assert any(
        item.action_type == ActionType.TRACE_API_ARGUMENT
        and item.parameters.get("target") == "0x2000"
        and item.plan.get("playbook_id") == "v3-network-transport"
        and item.source_evidence_ids == ("ctx-0x2000",)
        for item in suggestions
    )


def test_deep_mining_keeps_script_and_carrier_surfaces_in_the_frontier() -> None:
    rows = [
        {"id": "line-1", "kind": "script_line", "nature": "STATIC_OBSERVED", "value": {"line": "powershell -enc ..."}, "anchor": {"line": 7}},
        {"id": "call-1", "kind": "script_call", "nature": "STATIC_OBSERVED", "value": {"name": "Invoke-WebRequest"}, "anchor": {"line": 7}},
        {"id": "embed-1", "kind": "document_embedded_object", "nature": "STATIC_OBSERVED", "value": {"internal_path": "word/embeddings/oleObject1.bin"}, "anchor": {"internal_path": "word/embeddings/oleObject1.bin"}},
    ]
    frontier = DeepMiningPlanner.build_frontier(rows)
    categories = {item.category for item in frontier}
    assert {"script", "carrier"} <= categories
    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=8)
    assert any(item.action_type == ActionType.GET_CALLEES for item in actions)
    assert any(item.action_type == ActionType.GET_XREFS_TO for item in actions)


def test_deep_mining_tracks_resource_payload_and_decode_chain() -> None:
    """Resource payloads must remain actionable through extraction/decode stages."""
    rows = [
        {
            "id": "resource-inventory-1",
            "kind": "resource_inventory",
            "nature": "STATIC_OBSERVED",
            "value": {"count": 1, "entries": [{"type": "RT_RCDATA", "size": 4096}]},
            "anchor": {"type": "pe_resource_directory"},
        },
        {
            "id": "resource-payload-1",
            "kind": "mechanism_resource_payload",
            "nature": "STATIC_INFERRED",
            "value": {"resource_type": "RT_RCDATA", "high_entropy": True},
            "anchor": {"type": "pe_resource_directory"},
        },
        {
            "id": "resource-bytes-1",
            "kind": "pe_resource",
            "nature": "STATIC_OBSERVED",
            "value": {"resource_type": "RT_RCDATA", "size": 4096, "offset": 8192},
            "anchor": {"type": "pe_resource", "offset": 8192},
        },
        {
            "id": "resource-decompress-1",
            "kind": "mechanism_decompression",
            "nature": "STATIC_INFERRED",
            "value": {"api": "RtlDecompressBuffer", "compression_format": "LZNT1 candidate"},
            "anchor": {"type": "api_call_chain"},
        },
    ]

    frontier = DeepMiningPlanner.build_frontier(rows, max_targets=32)
    assert "resource" in {item.category for item in frontier}
    assert "decode" in {item.category for item in frontier}

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=32)
    resource_actions = [item for item in actions if item.parameters.get("target") in {"resource", "decode"}]
    assert resource_actions
    cited = {evidence_id for item in resource_actions for evidence_id in item.source_evidence_ids}
    assert {"resource-payload-1", "resource-bytes-1", "resource-decompress-1"} <= cited
    assert any(item.action_type == ActionType.GET_DATA_REFERENCES for item in resource_actions)
    assert any(item.action_type == ActionType.DECODE_CANDIDATE for item in resource_actions)


def test_deep_mining_tracks_embedded_artifact_staging_chain() -> None:
    """Embedded and archive children must create a bounded staging question."""
    rows = [
        {
            "id": "embedded-child-1",
            "kind": "embedded_artifact",
            "nature": "STATIC_OBSERVED",
            "value": {"logical_path": "word/embeddings/oleObject1.bin", "detected_type": "pe"},
            "anchor": {"internal_path": "word/embeddings/oleObject1.bin"},
        },
        {
            "id": "archive-member-1",
            "kind": "archive_member",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "payload.bin", "size": 2048},
            "anchor": {"member": "payload.bin"},
        },
        {
            "id": "document-embed-1",
            "kind": "document_embedded_file",
            "nature": "STATIC_OBSERVED",
            "value": {"internal_path": "word/embeddings/oleObject1.bin"},
            "anchor": {"internal_path": "word/embeddings/oleObject1.bin"},
        },
    ]

    frontier = DeepMiningPlanner.build_frontier(rows, max_targets=32)
    assert "staging" in {item.category for item in frontier}
    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=32)
    staging_actions = [item for item in actions if item.parameters.get("target") == "staging"]
    assert staging_actions
    cited = {evidence_id for item in staging_actions for evidence_id in item.source_evidence_ids}
    assert {"embedded-child-1", "archive-member-1", "document-embed-1"} <= cited
    assert any(item.action_type == ActionType.GET_DATA_REFERENCES for item in staging_actions)


def test_static_executor_keeps_resource_and_embedded_actions_productive(test_settings) -> None:
    """Resource actions must yield auditable observations instead of false no-gain results."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="resource-executor",
            artifact_id="artifact-resource",
            kind="pe_resource",
            value={"resource_type": "RT_RCDATA", "offset": 4, "size": 8},
            anchor={"type": "pe_resource", "offset": 4},
        ),
        SimpleNamespace(
            id="resource-decompress-executor",
            artifact_id="artifact-resource",
            kind="mechanism_decompression",
            value={"api": "RtlDecompressBuffer", "call_sites": [{"api": "RtlDecompressBuffer"}]},
            anchor={"type": "api_call_chain"},
        ),
        SimpleNamespace(
            id="embedded-executor",
            artifact_id="artifact-resource",
            kind="embedded_artifact",
            value={"logical_path": "payload.bin", "detected_type": "pe"},
            anchor={"internal_path": "payload.bin"},
        ),
    ]

    def action(action_type: ActionType) -> ActionSpec:
        return ActionSpec(
            id=f"resource-{action_type.value}",
            action_type=action_type,
            thread_id="resource-thread",
            hypothesis_id="resource-hypothesis",
            artifact_id="artifact-resource",
            target_selector={"target": "resource"},
        )

    data = service._derive_investigation_observations(rows, action(ActionType.GET_DATA_REFERENCES))
    xrefs = service._derive_investigation_observations(rows, action(ActionType.GET_XREFS_TO))
    callees = service._derive_investigation_observations(rows, action(ActionType.GET_CALLEES))

    assert data and any(item["kind"] == "data_reference" for item in data)
    assert xrefs and any(item["kind"] == "embedded_object" for item in xrefs)
    assert callees and any(item["kind"] == "resource_consumer" for item in callees)
    assert all(
        source_id in {"resource-executor", "resource-decompress-executor", "embedded-executor"}
        for observation in (*data, *xrefs, *callees)
        for source_id in observation["value"]["source_evidence_ids"]
    )


def test_loop_honors_persisted_frontier_keys_before_scheduling_followups() -> None:
    action = ActionSpec(
        id="already-run",
        action_type=ActionType.GET_FUNCTION,
        thread_id="t",
        hypothesis_id="h",
        artifact_id="a",
        parameters={"target": "0x1000"},
        target_selector={"target": "0x1000"},
        expected_evidence_kinds=("function",),
    )
    executed: list[str] = []
    result = InvestigationLoopDriver(max_steps=4).run(
        thread_id="t",
        artifact_id="a",
        question="What does the function do?",
        hypothesis_id="h",
        hypothesis_statement="A static mechanism may be present.",
        initial_evidence=(_function("0x1000", "entry_orchestrator", "CreateProcessW"),),
        initial_scheduled=(action.dedupe_key,),
        execute=lambda item: executed.append(item.id) or (),
    )
    assert not any(item.action_type == ActionType.GET_FUNCTION for item in result.actions)
    assert result.thread_state.value in {"UNKNOWN", "CLAIM_READY"}


def test_loop_reuses_existing_function_trace_and_call_edge_before_planning_more_reads() -> None:
    """The recursive loop must advance from baseline facts instead of rereading them."""
    driver = InvestigationLoopDriver(max_steps=4)
    context = _function("0x401000", "spawn_worker", "CreateProcessW")
    trace = {
        "id": "existing-trace",
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {"function_entry": "0x401000", "api": "CreateProcessW"},
        "anchor": {"function_entry": "0x401000"},
    }
    call = {
        "id": "existing-call",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"caller": "spawn_worker", "api": "CreateProcessW"},
        "anchor": {"function_entry": "0x401000"},
    }

    actions = driver._next_actions(
        thread_id="reuse-thread",
        hypothesis_id="reuse-hypothesis",
        artifact_id="artifact",
        evidence=[context, trace, call],
        scheduled=set(),
        sequence=0,
    )

    assert not any(item.action_type == ActionType.TRACE_API_ARGUMENT for item in actions)
    assert not any(item.action_type == ActionType.GET_CALLEES for item in actions)
    assert any(item.action_type == ActionType.GET_PCODE_SLICE for item in actions)


def test_loop_does_not_stop_a_second_concrete_target_after_first_target_is_dry() -> None:
    """A no-result resolver probe cannot suppress an independent mechanism lead."""
    proposed = [
        ActionSpec(
            id=f"a-{index}",
            action_type=action_type,
            thread_id="t",
            hypothesis_id="h",
            artifact_id="a",
            parameters={"target": target},
            target_selector={"target": target},
            expected_evidence_kinds=("function_context",),
        )
        for index, (action_type, target) in enumerate(
            (
                (ActionType.GET_XREFS_TO, "GetProcAddress"),
                (ActionType.GET_PCODE_SLICE, "GetProcAddress"),
                (ActionType.GET_XREFS_TO, "CreateProcessW"),
            ),
            start=1,
        )
    ]
    attempted: list[str] = []

    result = InvestigationLoopDriver(max_steps=4, max_consecutive_no_gain=2).run(
        thread_id="t",
        artifact_id="a",
        question="Which independent static mechanisms remain open?",
        hypothesis_id="h",
        hypothesis_statement="Independent concrete targets require independent static checks.",
        proposed_actions=proposed,
        allow_investigator_actions=False,
        execute=lambda action: attempted.append(str(action.target_selector["target"])) or (),
    )

    assert attempted == ["GetProcAddress", "GetProcAddress", "CreateProcessW"]
    assert result.thread_state.value == "UNKNOWN"


def test_loop_keeps_dispatching_after_first_planner_window_is_claim_ready() -> None:
    """A claim-ready gate on the first window is not permission to idle.

    Kunglao's SATURATED rule forbids stopping while independent high-value
    questions remain.  The planner admits twelve targets at a time; later
    functions must still receive required static facets in continuation
    rounds instead of remaining report-only.
    """
    rows = [
        _function(f"0x{0x1000 * index:x}", f"fn_{index}", "CreateProcessW")
        for index in range(1, 16)
    ]
    attempted_targets: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        target = str(action.target_selector.get("target") or action.parameters.get("target") or "")
        attempted_targets.append(target)
        return [
            {
                "id": f"{action.id}:row",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "CreateProcessW", "function_entry": target},
                "anchor": {"function_entry": target},
            }
        ]

    InvestigationLoopDriver(max_steps=32).run_until_converged(
        thread_id="saturated-thread",
        artifact_id="saturated-artifact",
        question="Which high-value function paths are used?",
        hypothesis_id="saturated-hypothesis",
        hypothesis_statement="Independent high-value functions require independent static checks.",
        initial_evidence=rows,
        execute=execute,
        allow_investigator_actions=True,
        max_rounds=8,
        max_total_steps=96,
    )

    unique_functions = {
        target for target in attempted_targets if target.lower().startswith("0x")
    }
    expected = {f"0x{0x1000 * index:x}" for index in range(1, 16)}
    assert expected <= unique_functions


def test_action_key_merges_function_rva_aliases_but_keeps_api_scope_distinct() -> None:
    old_key = canonical_action_key(
        "GET_DECOMPILE", {"target_selector": {"function_entry": "0x140001000"}}
    )
    deep_mining_key = canonical_action_key(
        "GET_DECOMPILE", {"target_selector": {"target": "0x140001000"}}
    )
    api_key = canonical_action_key(
        "GET_DECOMPILE", {"target_selector": {"api": "0x140001000"}}
    )

    assert old_key == deep_mining_key
    assert api_key != deep_mining_key


def test_deep_mining_planner_paginates_six_targets_without_dropping_contracts() -> None:
    """Successive planner turns eventually expose every admitted target."""
    rows = [
        _function(f"0x{0x1000 + index * 0x100:x}", f"worker_{index}", "CreateProcessW")
        for index in range(6)
    ]
    first = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=24)
    second = DeepMiningPlanner.plan_actions(
        rows,
        scheduled={item.dedupe_key for item in first},
        max_actions=24,
    )
    third = DeepMiningPlanner.plan_actions(
        rows,
        scheduled={item.dedupe_key for item in (*first, *second)},
        max_actions=24,
    )

    seen_targets = {
        str(item.parameters["target"])
        for item in (*first, *second, *third)
        if item.parameters.get("target")
    }
    expected_targets = {f"0x{0x1000 + index * 0x100:x}" for index in range(6)}
    assert expected_targets <= seen_targets
    for target in expected_targets:
        target_actions = [
            item
            for item in (*first, *second, *third)
            if item.parameters.get("target") == target
        ]
        required = set(
            target_actions[0].plan["deep_investigation_contract"]["required_action_types"]
        )
        assert required <= {item.action_type.value for item in target_actions}


def test_deep_mining_planner_reaches_targets_beyond_first_128_after_paging() -> None:
    """Scheduled-frontier paging must not make late functions unreachable.

    The planner's admission budget is intentionally small, but discovery must
    happen before that budget is applied.  This reproduces the large-binary
    case where the first 128 ranked targets have already been scheduled and
    verifies that later targets are eventually admitted on subsequent turns.
    """
    rows = [
        {
            "id": f"ctx-{index}",
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": f"helper_{index}",
                "entry": f"0x{0x1000 + index * 0x10:x}",
                "call_targets": [{"target_name": "internal_helper"}],
                "data_references": [{"to": f"data-{index}"}],
            },
            "anchor": {"function_entry": f"0x{0x1000 + index * 0x10:x}"},
        }
        for index in range(130)
    ]
    scheduled: set[str] = set()
    seen_targets: set[str] = set()
    for _ in range(32):
        page = DeepMiningPlanner.plan_actions(
            rows,
            scheduled=scheduled,
            max_actions=48,
        )
        if not page:
            break
        seen_targets.update(
            str(item.parameters["target"])
            for item in page
            if item.parameters.get("target")
        )
        scheduled.update(item.dedupe_key for item in page)

    expected_targets = {
        f"0x{0x1000 + index * 0x10:x}" for index in range(130)
    }
    assert expected_targets <= seen_targets


def test_loop_rejects_executor_evidence_from_another_function_scope() -> None:
    """Cross-target output cannot satisfy a function's deep contract."""
    initial = _function("0x401000", "spawn_worker", "CreateProcessW")

    def execute(_action: ActionSpec) -> list[dict[str, object]]:
        return [
            {
                "id": "wrong-function",
                "kind": "function_call",
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "0x402000", "api": "Unrelated"},
                "anchor": {"function_entry": "0x402000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=1).run(
        thread_id="target-boundary",
        artifact_id="artifact",
        question="Which process path is statically recoverable?",
        hypothesis_id="h-target-boundary",
        hypothesis_statement="The 0x401000 function may create a child process.",
        initial_evidence=(initial,),
        execute=execute,
    )

    assert all(row.get("id") != "wrong-function" for row in result.evidence)
    assert any(event.phase == "action_output_rejected" for event in result.events)
    assert result.coverage["evidence_complete"] is False


def test_loop_rejects_executor_evidence_from_another_artifact_scope() -> None:
    """A same-target row from another artifact cannot satisfy this thread."""
    initial = _function("0x401000", "spawn_worker", "CreateProcessW")

    def execute(_action: ActionSpec) -> list[dict[str, object]]:
        return [
            {
                "id": "wrong-artifact",
                "artifact_id": "artifact-other",
                "kind": "function_call",
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "0x401000", "api": "CreateProcessW"},
                "anchor": {"function_entry": "0x401000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=1).run(
        thread_id="artifact-boundary",
        artifact_id="artifact-local",
        question="Which process path is statically recoverable?",
        hypothesis_id="h-artifact-boundary",
        hypothesis_statement="The local function may create a child process.",
        initial_evidence=(initial,),
        execute=execute,
    )

    assert all(row.get("id") != "wrong-artifact" for row in result.evidence)
    assert any(event.phase == "action_output_rejected" for event in result.events)
    assert result.coverage["evidence_complete"] is False


def test_no_gain_emits_autopsy_and_high_information_next_action() -> None:
    initial = _function("0x401000", "spawn_worker", "CreateProcessW")
    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=1).run(
        thread_id="autopsy",
        artifact_id="artifact",
        question="Which process path is statically recoverable?",
        hypothesis_id="h-autopsy",
        hypothesis_statement="The function may create a child process.",
        initial_evidence=(initial,),
        execute=lambda _action: (),
    )

    autopsies = [item for item in result.events if item.phase == "no_new_evidence_autopsy"]
    assert autopsies
    assert "autopsy=LOW_INFORMATION_ACTION" in autopsies[0].message
    assert "next_action=" in autopsies[0].message
    assert any(item.phase == "static_boundary" for item in result.events)


def test_high_rank_decode_closes_emulation_before_import_only_admission() -> None:
    """A modest budget must finish one HOW claim, including isolated emulation.

    Import-only leads are cheaper than a decode contract.  If they occupy the
    first window, the high-rank transform never reaches CONTROLLED_EMULATE and
    the leftover slots become empty UNKNOWN threads.
    """
    decode = _function("0x1000", "xor_decode_config")
    decode_window = {
        "id": "decode-window-1000",
        "kind": "mechanism_decode_window",
        "nature": "STATIC_DERIVED",
        "value": {"function_entry": "0x1000", "transformation": "xor"},
        "anchor": {"function_entry": "0x1000"},
    }
    helpers = [
        _function(f"0x{0x2000 + index * 0x100:x}", f"helper_{index}", "CreateFileW")
        for index in range(20)
    ]
    imports = [
        {
            "id": f"imp-{name}",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": name},
            "anchor": {},
        }
        for name in ("LoadLibraryA", "VirtualAlloc", "WinHttpOpen", "RegSetValueExW")
    ]

    planned = DeepMiningPlanner.plan_actions(
        [decode, decode_window, *helpers, *imports],
        scheduled=set(),
        max_actions=24,
    )
    decode_actions = [
        item for item in planned if item.parameters.get("target") == "0x1000"
    ]
    decode_types = {item.action_type for item in decode_actions}
    required = set(decode_actions[0].plan["deep_investigation_contract"]["required_action_types"])
    import_names = {"LoadLibraryA", "VirtualAlloc", "WinHttpOpen", "RegSetValueExW"}
    import_actions = [
        item for item in planned if item.parameters.get("target") in import_names
    ]

    assert decode_actions, planned
    assert required <= {item.action_type.value for item in decode_actions}
    assert ActionType.CONTROLLED_EMULATE in decode_types
    leftover = 24 - len(planned)
    if leftover < 1:
        assert not import_actions
    for action in import_actions:
        contract = action.plan.get("deep_investigation_contract", {})
        depth = len(set(contract.get("required_action_types", ())))
        # An import-only lead may join only when the leftover budget can
        # finish its own contract; truncated API xrefs must stay unadmitted.
        assert depth <= leftover + len(
            [item for item in import_actions if item.parameters.get("target") == action.parameters.get("target")]
        )


def _function_action(
    action_id: str,
    action_type: ActionType,
    *,
    priority: int,
    reason: str,
    category: str | None = None,
    required: tuple[str, ...] = (),
) -> ActionSpec:
    contract = {
        "id": f"deep-static-v1:{category or 'function'}",
        "category": category or "function",
        "required_action_types": list(required),
        "evidence_kinds_by_action": {},
        "completion_rule": "all_required_facets_attempted_or_static_boundary",
    }
    plan: dict[str, object] = {
        "why": reason,
        "deep_investigation_contract": contract,
    }
    return ActionSpec(
        id=action_id,
        action_type=action_type,
        thread_id="k01-thread",
        hypothesis_id="k01-hypothesis",
        artifact_id="artifact",
        priority=priority,
        reason=reason,
        parameters={"target": "0x401000"},
        target_selector={"target": "0x401000"},
        expected_evidence_kinds=("function_context",),
        plan=plan,
    )


def test_callees_or_function_no_gain_switches_to_decompile_then_emulate() -> None:
    """K01: a failed call-graph method must change family, not rewrite the reason."""
    required = (
        ActionType.GET_CALLEES.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.CONTROLLED_EMULATE.value,
    )
    proposed = [
        _function_action(
            "callees-playbook",
            ActionType.GET_CALLEES,
            priority=10,
            reason="Follow one bounded call-flow hop from the generic mechanism target.",
            category="process",
            required=required,
        ),
        _function_action(
            "callees-rewrite",
            ActionType.GET_CALLEES,
            priority=11,
            reason="Find consumers reached after the transform returns.",
            category="decode",
            required=required,
        ),
        _function_action(
            "function-fallback",
            ActionType.GET_FUNCTION,
            priority=12,
            reason="Resolve the static function before constructing an ordered timeline.",
            category="process",
            required=required,
        ),
        _function_action(
            "decompile",
            ActionType.GET_DECOMPILE,
            priority=20,
            reason="Recover a bounded semantic view after call-graph methods stall.",
            category="process",
            required=required,
        ),
        _function_action(
            "emulate",
            ActionType.CONTROLLED_EMULATE,
            priority=21,
            reason="When static recovery stalls, emulate granted function bytes in the isolated worker.",
            category="process",
            required=required,
        ),
    ]
    executed: list[ActionType] = []

    result = InvestigationLoopDriver(max_steps=6, max_consecutive_no_gain=1).run(
        thread_id="k01-thread",
        artifact_id="artifact",
        question="What consumes the recovered buffer?",
        hypothesis_id="k01-hypothesis",
        hypothesis_statement="The function may decode and consume a buffer.",
        initial_evidence=(_function("0x401000", "xor_decode_config", "CreateProcessW"),),
        proposed_actions=proposed,
        allow_investigator_actions=False,
        execute=lambda action: executed.append(action.action_type) or (),
    )

    assert executed[0] in {ActionType.GET_CALLEES, ActionType.GET_FUNCTION}
    assert ActionType.GET_DECOMPILE in executed
    callees_index = next(
        index
        for index, action_type in enumerate(executed)
        if action_type in {ActionType.GET_CALLEES, ActionType.GET_FUNCTION}
    )
    after_call_graph = executed[callees_index + 1 :]
    assert after_call_graph
    assert after_call_graph[0] == ActionType.GET_DECOMPILE
    assert ActionType.GET_CALLEES not in after_call_graph
    assert ActionType.GET_FUNCTION not in after_call_graph
    assert ActionType.CONTROLLED_EMULATE in after_call_graph
    failed = next(
        action
        for action in result.actions
        if action.action_type in {ActionType.GET_CALLEES, ActionType.GET_FUNCTION}
    )
    plan = failed.plan
    assert plan.get("method_id")
    assert plan.get("method_assumption")
    assert plan.get("assumption_validity") == "not_justified"
    assert plan.get("next_method") in {ActionType.GET_DECOMPILE.value, "GET_DECOMPILE"}
    assert plan.get("gain_class") == "NO_NEW_EVIDENCE"
    assert plan.get("frontier_fingerprint_before")
    assert plan.get("frontier_fingerprint_after")


def test_optional_navigation_does_not_starve_active_claim_required_facets() -> None:
    """GET_CALLERS / unanchored strings cannot delay CONTROLLED_EMULATE."""
    caller = _function("0x401000", "spawn_worker", "CreateThread")
    trace = {
        "id": "trace-createthread",
        "kind": "api_argument_trace",
        "nature": "STATIC_DERIVED",
        "value": {
            "api": "CreateThread",
            "function_entry": "0x401000",
            "arguments": [
                {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
            ],
        },
        "anchor": {"function_entry": "0x401000"},
    }
    planned = DeepMiningPlanner.plan_actions(
        [caller, trace],
        scheduled=set(),
        max_actions=24,
    )
    start_actions = [
        item for item in planned if item.parameters.get("target") == "0x401500"
    ]
    start_types = [item.action_type for item in start_actions]
    required = set(start_actions[0].plan["deep_investigation_contract"]["required_action_types"])

    assert ActionType.CONTROLLED_EMULATE in start_types
    assert required <= {item.value for item in start_types}
    assert ActionType.GET_STRINGS_REFERENCED not in start_types
    if ActionType.GET_CALLERS in start_types:
        assert start_types.index(ActionType.CONTROLLED_EMULATE) < start_types.index(
            ActionType.GET_CALLERS
        )
    for action in start_actions:
        assert action.plan.get("method_id")
        assert action.plan.get("method_assumption")
        assert action.plan.get("next_method")
        assert action.plan.get("gain_class") == "UNTESTED"
        assert action.plan.get("assumption_validity") == "untested"

    tight = DeepMiningPlanner.plan_actions(
        [caller, trace],
        scheduled=set(),
        max_actions=len(required),
    )
    tight_start = [
        item for item in tight if item.parameters.get("target") == "0x401500"
    ]
    tight_types = {item.action_type for item in tight_start}
    assert ActionType.CONTROLLED_EMULATE in tight_types
    assert ActionType.GET_CALLERS not in tight_types
    assert ActionType.GET_STRINGS_REFERENCED not in tight_types
