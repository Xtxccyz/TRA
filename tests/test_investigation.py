from __future__ import annotations

import pytest

from threat_report_agent.dataflow import catalog_output_consumer_relation
from threat_report_agent.investigation import (
    ActionCatalog,
    ActionSpec,
    ActionType,
    ClaimGate,
    InvestigationLoopDriver,
    InvestigationQueue,
    InvestigationThreadState,
    HypothesisPredicate,
    Investigator,
    ThreadStateMachine,
    Verifier,
    MultiSeedInvestigationScheduler,
    MechanismPlaybookRegistry,
    _xor_row_is_object_consumer,
    is_process_command_text_decode_consumer,
    verify_mechanism,
    verify_process_execution_mechanism,
    verify_xor_mechanism,
)
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService
from threat_report_agent.simulation_adapters import IsolatedSimulationRunner
from threat_report_agent.emulation.policy import SimulationRequest
from threat_report_agent.orchestration import QuestionCentricContextBuilder


def test_action_catalog_exposes_bounded_static_actions() -> None:
    catalog = ActionCatalog.default()

    assert len(catalog.names()) >= 15
    assert catalog.require(ActionType.GET_CALLERS).sample_execution is False
    assert catalog.require(ActionType.READ_BYTES).network_access is False


def test_v3_playbook_catalog_covers_generic_mechanism_matrix() -> None:
    expected = {
        "CONFIG_DECODER", "STRING_DECODER", "API_HASH_RESOLVER",
        "DYNAMIC_API_RESOLUTION", "NETWORK_TRANSPORT", "DOWNLOAD_DROP",
        "PROCESS_CREATION", "PPID_SPOOF", "COMMAND_EXECUTION",
        "MEMORY_PERMISSION_CHANGE", "MANUAL_PE_LOAD", "REGISTRY_CONFIGURATION",
        "REGISTRY_PERSISTENCE", "SCHEDULED_TASK", "SERVICE",
        "ENVIRONMENT_GUARD", "ETW_AMSI_PATCH", "PLUGIN_LOAD", "IPC",
        "COMMAND_DISPATCH", "CLEANUP_SELF_DELETE",
    }
    actual = {item.mechanism_type for item in MechanismPlaybookRegistry.default_playbooks()}
    assert expected <= actual
    assert all(item.question_templates and item.verifier_contract for item in MechanismPlaybookRegistry.default_playbooks())


def test_multi_seed_scheduler_keeps_priority_and_active_bound() -> None:
    scheduler = MultiSeedInvestigationScheduler(max_active_threads=2, max_seeds=4)
    seeds = [
        {"artifact_id": "a1", "priority": 20, "question": "q1", "seed_kind": "network"},
        {"artifact_id": "a2", "priority": 5, "question": "q2", "seed_kind": "decode"},
        {"artifact_id": "a3", "priority": 10, "question": "q3", "seed_kind": "execution"},
    ]
    admitted = scheduler.admit(seeds)
    assert [item["artifact_id"] for item in admitted] == ["a2", "a3", "a1"]
    assert scheduler.active_threads == ("a2", "a3")
    assert scheduler.next_seed()["artifact_id"] == "a2"
    scheduler.complete("a2")
    assert scheduler.active_threads == ("a3", "a1")


def test_loop_run_many_executes_each_admitted_seed_in_priority_order() -> None:
    order: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        order.append(action.artifact_id)
        return []

    results = InvestigationLoopDriver(max_steps=1, max_consecutive_no_gain=1).run_many(
        [
            {"artifact_id": "slow", "priority": 20, "question": "q-slow", "seed_kind": "entry"},
            {"artifact_id": "fast", "priority": 1, "question": "q-fast", "seed_kind": "decode"},
        ],
        execute=execute,
        max_active_threads=1,
    )
    assert len(results) == 2
    assert [item.artifact_id for item in results] == ["fast", "slow"]


def test_action_catalog_rejects_an_unanchored_or_semantically_incomplete_experiment() -> None:
    catalog = ActionCatalog.default()
    incomplete = ActionSpec(
        id="bad-action",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
    )

    try:
        catalog.validate(incomplete)
    except ValueError as exc:
        assert "target selector" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("unanchored Action was accepted")

    incomplete = ActionSpec(
        id="bad-semantics",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "GetProcAddress"},
    )
    try:
        catalog.validate(incomplete)
    except ValueError as exc:
        assert "expected evidence" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("Action without expected evidence was accepted")


def test_action_contract_freezes_selector_and_catalog_cost() -> None:
    catalog = ActionCatalog.default()
    action = ActionSpec(
        id="targeted-xref",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "GetProcAddress"},
        expected_evidence_kinds=("xref",),
    )

    assert action.target_selector == {"target": "GetProcAddress"}
    assert action.cost_units is None
    catalog.validate(action)

    mismatched = ActionSpec(
        id="mismatched-xref",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        parameters={"target": "GetProcAddress"},
        target_selector={"target": "LoadLibraryA"},
        expected_evidence_kinds=("xref",),
    )
    try:
        catalog.validate(mismatched)
    except ValueError as exc:
        assert "parameters must equal" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("mismatched target selector was accepted")


def test_queue_respects_dependencies_deduplicates_and_stops_at_budget() -> None:
    queue = InvestigationQueue(max_steps=2)
    first = ActionSpec(
        id="a1",
        action_type=ActionType.GET_FUNCTION,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="a",
        priority=20,
    )
    second = ActionSpec(
        id="a2",
        action_type=ActionType.GET_CALLEES,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="a",
        priority=10,
        depends_on=("a1",),
    )
    queue.enqueue(second)
    queue.enqueue(first)
    queue.enqueue(first)

    assert queue.pop().id == "a1"
    queue.complete("a1")
    assert queue.pop().id == "a2"
    queue.complete("a2")
    assert queue.pop() is None


def test_queue_prioritizes_required_deep_facet_over_optional_navigation() -> None:
    """A contracted target must spend its budget on discriminating facets first."""
    contract = {
        "id": "deep-static-v1:process",
        "category": "process",
        "required_action_types": [ActionType.TRACE_API_ARGUMENT.value],
    }
    optional = ActionSpec(
        id="optional-callers",
        action_type=ActionType.GET_CALLERS,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="a",
        priority=1,
        parameters={"target": "0x401000"},
        target_selector={"target": "0x401000"},
        plan={"deep_investigation_contract": contract},
    )
    required = ActionSpec(
        id="required-arguments",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="a",
        priority=80,
        parameters={"target": "0x401000"},
        target_selector={"target": "0x401000"},
        plan={"deep_investigation_contract": contract},
    )
    queue = InvestigationQueue(max_steps=2)
    assert queue.enqueue(optional)
    assert queue.enqueue(required)
    assert queue.pop().id == "required-arguments"


def test_loop_skips_explicit_action_already_in_durable_frontier() -> None:
    """A replayed action ID must not bypass selector-level de-duplication."""
    action = ActionSpec(
        id="new-thread-action-id",
        action_type=ActionType.GET_CALLERS,
        thread_id="new-thread",
        hypothesis_id="h1",
        artifact_id="artifact-1",
        parameters={"target": "0x401000"},
        target_selector={"target": "0x401000"},
        expected_evidence_kinds=("function_call",),
    )
    calls: list[str] = []
    result = InvestigationLoopDriver(max_steps=2).run(
        thread_id="new-thread",
        artifact_id="artifact-1",
        question="What calls this function?",
        hypothesis_id="h1",
        hypothesis_statement="The function may have a caller.",
        initial_scheduled=(action.dedupe_key,),
        proposed_actions=(action,),
        execute=lambda item: calls.append(item.id) or (),
        allow_investigator_actions=False,
    )

    assert result.actions == ()
    assert calls == []
    assert result.thread_state == InvestigationThreadState.UNKNOWN


def test_thread_state_machine_rejects_illegal_transition() -> None:
    machine = ThreadStateMachine()
    assert machine.transition(
        InvestigationThreadState.DISCOVERED,
        InvestigationThreadState.PRIORITIZED,
    ) == InvestigationThreadState.PRIORITIZED
    try:
        machine.transition(
            InvestigationThreadState.DISCOVERED,
            InvestigationThreadState.CLAIM_READY,
        )
    except ValueError as exc:
        assert "illegal investigation transition" in str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("illegal transition was accepted")


def test_claim_gate_requires_all_evidence_and_rejects_contradiction() -> None:
    gate = ClaimGate()
    evidence = [
        {"id": "e1", "kind": "function_call", "nature": "STATIC_OBSERVED", "value": {"api": "OpenProcess"}},
        {"id": "e2", "kind": "function_call", "nature": "STATIC_OBSERVED", "value": {"api": "UpdateProcThreadAttribute"}},
    ]
    accepted = gate.evaluate(
        evidence,
        required_kinds=("function_call",),
        required_predicates=(lambda row: row["value"].get("api") == "OpenProcess",),
    )
    assert accepted.accepted is True
    rejected = gate.evaluate(
        evidence,
        required_kinds=("function_call",),
        required_predicates=(lambda row: row["value"].get("api") == "CreateRemoteThread",),
        contradictory_ids=("e2",),
    )
    assert rejected.accepted is False
    assert rejected.status == "CONTRADICTED"
    either = gate.evaluate(
        evidence,
        required_any_kinds=("constant", "function_call"),
    )
    assert either.accepted is True


def test_claim_gate_requires_provenance_for_static_derived_evidence() -> None:
    gate = ClaimGate()
    invalid = gate.evaluate(
        [{'id': 'derived-without-provenance', 'kind': 'constant', 'nature': 'STATIC_DERIVED', 'value': {'name': 'FLAG'}}],
        required_kinds=('constant',),
    )
    assert invalid.accepted is False
    assert invalid.status == 'UNKNOWN'
    assert 'provenance' in invalid.reason

    valid = gate.evaluate(
        [{
            'id': 'derived-with-provenance',
            'kind': 'constant',
            'nature': 'STATIC_DERIVED',
            'value': {'name': 'FLAG', 'derivation': {
                'evaluator': 'test-v1',
                'input_evidence_ids': ['source-1'],
                'input_digest': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'output_digest': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            }},
        }],
        required_kinds=('constant',),
    )
    assert valid.accepted is True


def test_claim_gate_rejects_malformed_derived_digest() -> None:
    decision = ClaimGate().evaluate(
        [{
            "id": "derived-bad-digest",
            "kind": "constant",
            "nature": "STATIC_DERIVED",
            "value": {"derivation": {
                "evaluator": "test-v1",
                "input_evidence_ids": ["source-1"],
                "input_digest": "short",
                "output_digest": "b" * 64,
            }},
        }],
        required_kinds=("constant",),
    )

    assert decision.accepted is False
    assert decision.status == "UNKNOWN"


def test_verifier_enforces_playbook_specific_evidence_thresholds() -> None:
    verifier = Verifier()
    incomplete = verifier.evaluate(
        [
            {
                "id": "resolver-context",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {"call_targets": ["GetProcAddress"]},
            }
        ],
        "Does the sample dynamically resolve APIs?",
        "The sample may dynamically resolve APIs.",
    )
    assert incomplete.accepted is False

    complete = verifier.evaluate(
        [
            {
                "id": "resolver-context",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "GetProcAddress",
                    "module_input": "kernel32.dll",
                    "api_identity": "VirtualAlloc",
                    "resolver": "GetProcAddress",
                    "consumer": "resolved_pointer",
                    "resolved_pointer": {
                        "artifact_id": "artifact-1",
                        "address_space": "artifact-1",
                        "address": 4096,
                        "length": 8,
                    },
                },
                "anchor": {"function_entry": "0x1000"},
            },
            {
                "id": "resolver-xref",
                "kind": "function_data_correlation",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "module_input": "kernel32.dll",
                    "api_identity": "VirtualAlloc",
                    "resolver": "GetProcAddress",
                },
                "anchor": {"function_entry": "0x1000"},
            },
            {
                "id": "resolver-consumer",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "VirtualAlloc",
                    "consumer": True,
                    "consumer_pointer": {
                        "artifact_id": "artifact-1",
                        "address_space": "artifact-1",
                        "address": 4096,
                        "length": 8,
                    },
                    "input_buffer": {
                        "artifact_id": "artifact-1",
                        "address_space": "artifact-1",
                        "address": 4096,
                        "length": 8,
                    },
                },
                "anchor": {"function_entry": "0x1000"},
            },
            {
                "id": "resolver-relation",
                "kind": "value_flow",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "relation": "resolved_pointer_to_call",
                    "source_evidence_ids": ["resolver-context"],
                    "target_evidence_ids": ["resolver-consumer"],
                    "source_object": "resolved-pointer",
                    "target_object": "resolved-pointer",
                },
                "anchor": {"function_entry": "0x1000"},
            },
        ],
        "Does the sample dynamically resolve APIs?",
        "The sample may dynamically resolve APIs.",
    )
    assert complete.accepted is True


def test_specialist_verifier_rejects_cross_function_token_cooccurrence() -> None:
    """A mechanism must be linked by one static path, not global token counts."""
    evidence = [
        {"id": "explorer", "kind": "string", "value": "explorer.exe Process32First", "anchor": {"function_entry": "0x1000"}},
        {"id": "open", "kind": "function_call", "value": "OpenProcess(PROCESS_CREATE_PROCESS)", "anchor": {"function_entry": "0x2000"}},
        {"id": "parent", "kind": "function_call", "value": "UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "anchor": {"function_entry": "0x3000"}},
        {"id": "create", "kind": "function_call", "value": "CreateProcessW STARTUPINFOEX", "anchor": {"function_entry": "0x4000"}},
        {"id": "flags", "kind": "constant", "value": "0x09080008 CREATE_NO_WINDOW DETACHED_PROCESS", "anchor": {"function_entry": "0x5000"}},
    ]

    result = verify_mechanism("PPID_SPOOFING", evidence)

    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert "evidence anchor coherence" in result.missing


def test_specialist_verifier_accepts_same_function_or_explicit_provenance_bridge() -> None:
    rows = [
        {"id": "enum", "kind": "function_call", "value": {"api": "Process32FirstW"}, "anchor": {"function_entry": "0x1000"}},
        {"id": "explorer", "kind": "string", "value": "explorer.exe", "anchor": {"function_entry": "0x1000"}},
        {"id": "open", "kind": "function_call", "value": "OpenProcess(PROCESS_CREATE_PROCESS)", "anchor": {"function_entry": "0x1000"}},
        {"id": "parent", "kind": "function_call", "value": "UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "anchor": {"function_entry": "0x1000"}},
        {"id": "create", "kind": "function_call", "value": "CreateProcessW STARTUPINFOEX", "anchor": {"function_entry": "0x1000"}},
        {"id": "flags", "kind": "constant", "value": "0x09080008 CREATE_NO_WINDOW DETACHED_PROCESS", "anchor": {"function_entry": "0x1000"}},
    ]
    same_function = verify_mechanism("PPID_SPOOFING", rows)
    assert same_function.accepted is True

    split_rows = [
        {**row, "anchor": {"function_entry": f"0x{index + 2:04x}"}}
        for index, row in enumerate(rows)
    ]
    split_rows.append({
        "id": "bridge",
        "kind": "mechanism_chain",
        "value": {"source_evidence_ids": [row["id"] for row in rows], "relationship": "explicit static provenance bridge"},
        "anchor": {"type": "derived_mechanism"},
    })
    bridged = verify_mechanism("PPID_SPOOFING", split_rows)
    assert bridged.accepted is True


def test_refutation_requires_positive_counterevidence_or_explicit_exhaustive_scope() -> None:
    gate = ClaimGate()
    predicate = HypothesisPredicate(
        subject="sample.exe",
        predicate="uses_network_capability",
        object="WinHTTP",
        scope="runtime use including dynamically resolved APIs",
    )

    absent_iat = gate.evaluate_refutation(predicate)
    assert absent_iat.status == "UNKNOWN"
    refuted = gate.evaluate_refutation(predicate, affirmative_counterevidence_ids=("counter-1",))
    assert refuted.status == "REFUTED"
    direct_import_only = gate.evaluate_refutation(
        HypothesisPredicate(
            subject="sample.exe",
            predicate="has_direct_iat_import",
            object="WinHTTP",
            scope="complete direct IAT enumeration",
        ),
        exhaustive_scope_verified=True,
    )
    assert direct_import_only.status == "REFUTED"


def test_dynamic_api_playbook_keeps_distinct_targets_as_distinct_experiments() -> None:
    extra_imports = [
        {
            "id": f"import-extra-{index}",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": name},
        }
        for index, name in enumerate(
            (
                "CreateFileW",
                "ReadFile",
                "WriteFile",
                "CloseHandle",
                "RegSetValueExW",
                "WinHttpOpen",
                "WinHttpConnect",
                "CreateProcessW",
                "VirtualAlloc",
            ),
            start=3,
        )
    ]
    suggestions = Investigator().propose(
        evidence=[
            {
                "id": "import-1",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "GetProcAddress"},
            },
            {
                "id": "import-2",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "LoadLibraryA"},
            },
            *extra_imports,
        ],
        scheduled=set(),
    )
    xref_targets = {
        str(item.parameters.get("target"))
        for item in suggestions
        if item.action_type == ActionType.GET_XREFS_TO
    }
    assert {"GetProcAddress", "LoadLibraryA"} <= xref_targets
    assert all(item.expected_evidence_kinds for item in suggestions)


def test_loop_marks_no_new_evidence_after_bounded_consecutive_no_gain() -> None:
    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=2).run(
        thread_id="entry-thread",
        artifact_id="artifact-1",
        question="What static timeline starts at the entrypoint?",
        hypothesis_id="entry-hypothesis",
        hypothesis_statement="The entrypoint may expose an ordered static timeline.",
        initial_evidence=(
            {
                "id": "entry-1",
                "kind": "pe_structure",
                "nature": "STATIC_OBSERVED",
                "value": {"entrypoint": "0x1000"},
                "anchor": {"function_entry": "0x1000"},
            },
        ),
        execute=lambda _action: (),
    )

    assert result.thread_state == InvestigationThreadState.UNKNOWN
    no_gain_events = [item for item in result.events if item.phase == "no_new_evidence"]
    # A concrete entrypoint is a deep target. Two dry probes are insufficient
    # to suppress its remaining bounded semantic/data-flow facets; the loop
    # records a static boundary only after that contract is exhausted.
    assert len(no_gain_events) >= 2
    assert result.coverage["complete"] is True
    assert any(item.phase == "coverage_continue" for item in result.events)
    assert any(item.phase == "static_boundary" for item in result.events)
    assert "NO_NEW_EVIDENCE" in result.events[-1].message


def test_context_builder_keeps_graph_contradictions_unknowns_and_history() -> None:
    packet = QuestionCentricContextBuilder(50_000).build(
        question="What does this function do?",
        artifact={"artifact_id": "a1"},
        evidence=[],
        call_graph={"callers": ["f1"], "callees": ["f2"]},
        pcode_slice=[{"op": "CALL"}],
        contradictions=[{"evidence_id": "e2", "reason": "conflict"}],
        open_unknowns=["runtime target"],
        action_history=[{"action_type": "GET_CALLEES", "status": "SUCCEEDED"}],
    )
    assert packet["call_graph"]["callees"] == ["f2"]
    assert packet["contradictions"]
    assert packet["open_unknowns"] == ["runtime target"]
    assert packet["action_history"]


def test_loop_recursively_updates_hypothesis_and_reaches_claim_ready() -> None:
    initial = {
        "id": "e0",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"text": "explorer.exe", "parent_selection": "explorer.exe"},
        "anchor": {"function_entry": "0x1000"},
    }
    calls: list[ActionType] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        calls.append(action.action_type)
        if action.action_type == ActionType.GET_XREFS_TO:
            return [{
                "id": "e-open",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "OpenProcess",
                    "access_mask": "PROCESS_CREATE_PROCESS",
                    "parent_handle": {"artifact_id": "artifact-1", "handle_id": "h-parent"},
                },
                "anchor": {"function_entry": "0x1000"},
            }]
        if action.action_type == ActionType.GET_CALLEES:
            return [{
                "id": "e-enum",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "Process32FirstW", "parent_selection": "explorer.exe"},
                "anchor": {"function_entry": "0x1000"},
            }, {
                "id": "e-attribute",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "UpdateProcThreadAttribute",
                    "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                    "startup_info": "STARTUPINFOEX",
                    "attribute_handle": {"artifact_id": "artifact-1", "handle_id": "h-attribute"},
                },
                "anchor": {"function_entry": "0x1000"},
            }, {
                "id": "e-create",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "CreateProcessW", "startupinfo": "STARTUPINFOEX"},
                "anchor": {"function_entry": "0x1000"},
            }, {
                "id": "e-relation",
                "kind": "value_flow",
                "nature": "STATIC_DERIVED",
                "value": {
                    "name": "UpdateProcThreadAttribute",
                    "relation": "parent_handle_to_attribute",
                    "source_evidence_ids": ["e-open"],
                    "target_evidence_ids": ["e-attribute"],
                    "parent_handle": {"artifact_id": "artifact-1", "handle_id": "h-parent"},
                    "attribute_handle": {"artifact_id": "artifact-1", "handle_id": "h-attribute"},
                },
                "anchor": {"function_entry": "0x1000"},
            }]
        if action.action_type == ActionType.EVALUATE_CONSTANT:
            return [{
                "id": "e-flags",
                "kind": "constant",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                    "creation_flags": "0x09080008",
                },
                "anchor": {"function_entry": "0x1000"},
            }]
        return []

    actions = (
        ActionSpec(
            id="ppid-open",
            action_type=ActionType.GET_XREFS_TO,
            thread_id="t1",
            hypothesis_id="h1",
            artifact_id="artifact-1",
                priority=1,
                parameters={"target": "OpenProcess"},
                target_selector={"target": "OpenProcess"},
            expected_evidence_kinds=("function_call",),
        ),
        ActionSpec(
            id="ppid-attribute",
            action_type=ActionType.GET_CALLEES,
            thread_id="t1",
            hypothesis_id="h1",
            artifact_id="artifact-1",
            priority=2,
                parameters={"target": "0x1000"},
                target_selector={"target": "0x1000"},
            expected_evidence_kinds=("function_call", "value_flow"),
            depends_on=("ppid-open",),
        ),
        ActionSpec(
            id="ppid-flags",
            action_type=ActionType.EVALUATE_CONSTANT,
            thread_id="t1",
            hypothesis_id="h1",
            artifact_id="artifact-1",
            priority=3,
                parameters={"target": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"},
                target_selector={"target": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"},
            expected_evidence_kinds=("constant",),
            depends_on=("ppid-attribute",),
        ),
    )
    result = InvestigationLoopDriver(max_steps=8).run(
        thread_id="t1",
        artifact_id="artifact-1",
        question="Can the sample spoof its parent process?",
        hypothesis_id="h1",
        hypothesis_statement="The sample may implement PPID spoofing.",
        initial_evidence=(initial,),
        execute=execute,
        proposed_actions=actions,
        allow_investigator_actions=False,
    )

    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    assert result.hypothesis_status == "SUPPORTED"
    assert calls[0] == ActionType.GET_XREFS_TO
    assert ActionType.EVALUATE_CONSTANT in calls
    assert len(result.events) >= 3


def test_loop_total_action_budget_leaves_pending_frontier_auditable() -> None:
    initial = {
        "id": "e0",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "entry", "entry": "0x1000"},
        "anchor": {"function_entry": "0x1000"},
    }
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.id)
        return [{
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": action.action_type.value},
            "anchor": {"function_entry": "0x1000"},
        }]

    result = InvestigationLoopDriver(max_steps=4).run_until_converged(
        thread_id="budget-thread",
        artifact_id="budget-artifact",
        question="Which static path is present?",
        hypothesis_id="budget-hypothesis",
        hypothesis_statement="The artifact may expose a static mechanism.",
        initial_evidence=(initial,),
        execute=execute,
        max_rounds=4,
        max_total_steps=2,
    )

    attempted = {
        event.action_id
        for event in result.events
        if event.action_id and event.phase == "action_completed"
    }
    assert len(executed) <= 2
    assert len(attempted) <= 2
    assert any(event.phase == "budget_exhausted" for event in result.events)
    assert len(result.actions) > len(attempted)


@pytest.mark.parametrize("prerequisite_fails", [False, True])
def test_loop_continuation_keeps_successful_dependencies(prerequisite_fails: bool) -> None:
    actions = (
        ActionSpec(
            id="dependency-parent",
            action_type=ActionType.GET_FUNCTION,
            thread_id="dependency-thread",
            hypothesis_id="dependency-hypothesis",
            artifact_id="dependency-artifact",
            parameters={"target": "0x1000"},
            expected_evidence_kinds=("function_context",),
        ),
        ActionSpec(
            id="dependency-child",
            action_type=ActionType.GET_CALLEES,
            thread_id="dependency-thread",
            hypothesis_id="dependency-hypothesis",
            artifact_id="dependency-artifact",
            parameters={"target": "0x1000"},
            expected_evidence_kinds=("function_call",),
            depends_on=("dependency-parent",),
        ),
    )
    executed: list[str] = []

    def execute(action: ActionSpec) -> tuple[()]:
        executed.append(action.id)
        if prerequisite_fails and action.id == "dependency-parent":
            raise RuntimeError("static prerequisite failed")
        return ()

    result = InvestigationLoopDriver(max_steps=1).run_until_converged(
        thread_id="dependency-thread",
        artifact_id="dependency-artifact",
        question="Which static calls are present?",
        hypothesis_id="dependency-hypothesis",
        hypothesis_statement="The function may expose a static call path.",
        proposed_actions=actions,
        execute=execute,
        allow_investigator_actions=False,
        max_rounds=2,
        max_total_steps=2,
    )

    assert executed == (
        ["dependency-parent"]
        if prerequisite_fails
        else ["dependency-parent", "dependency-child"]
    )
    assert next(action for action in result.actions if action.id == "dependency-child").depends_on == (
        "dependency-parent",
    )


def test_resumed_frontier_does_not_reuse_completed_ids_for_new_selectors() -> None:
    evidence = [
        {
            "id": f"function-{index}", "kind": "function_context", "nature": "STATIC_OBSERVED",
            "value": {"name": f"function_{index}", "entry": hex(index * 4096)},
            "anchor": {"function_entry": hex(index * 4096)},
        }
        for index in range(1, 6)
    ]
    executed: dict[str, ActionSpec] = {}
    scheduled: set[str] = set()

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed[action.id] = action
        return [{"id": f"result-{action.id}", "kind": "static_observation",
                 "value": {"source": action.id}}]

    for source in evidence:
        InvestigationLoopDriver(max_steps=2).run_until_converged(
            thread_id="resume-thread", artifact_id="resume-artifact", question="Explain the mechanism",
            hypothesis_id="resume-hypothesis", hypothesis_statement="An ordered static path is present",
            initial_evidence=[source], initial_scheduled=scheduled,
            initial_completed_action_ids=tuple(executed), execute=execute,
            max_rounds=4, max_total_steps=8,
        )
        scheduled.update(action.dedupe_key for action in executed.values())
    targets = {(action.target_selector.get("target"), action.action_type) for action in executed.values()}
    for index in range(1, 6):
        assert (hex(index * 4096), ActionType.GET_DATA_REFERENCES) in targets
        assert (hex(index * 4096), ActionType.GET_CFG_SLICE) in targets


def test_service_persists_investigation_actions_and_claim_gate(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("investigation service")
    result = service.analyze_submission(
        case_id=case.id,
        filename="ppid.py",
        content=(
            b"OpenProcess UpdateProcThreadAttribute "
            b"PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
        ),
    )

    view = service.task_view(result.task_id)
    assert view["investigation"]["threads"]
    assert view["investigation"]["actions"]
    assert all(item["status"] in {"SUCCEEDED", "FAILED"} for item in view["investigation"]["actions"])
    # A token-only script fixture must not be promoted to an execution/PPID
    # mechanism.  The strict typed contract keeps the investigation auditable
    # while still persisting its seed/action frontier.
    assert not any(item["module"] == "execution" for item in view["claims"])
    assert any(item["module"] == "static_triage" for item in view["claims"])
    trace = service.analysis_trace(result.task_id)
    assert trace["investigation"]["private_chain_of_thought"] is False
    assert any(event["phase"] == "action_completed" for event in trace["investigation"]["runtime"]["events"])
    report = service.get_report_revision(result.report_revision_id)
    assert "PERSISTED_INVESTIGATION" not in report["markdown"]
    assert "分析结论" in report["markdown"]


def test_dynamic_simulation_requires_isolated_worker_and_explicit_policy() -> None:
    runner = IsolatedSimulationRunner()
    denied = runner.run(SimulationRequest("qiling", "sample.exe"))
    assert denied.status == "DISABLED_BY_POLICY"
    rejected = runner.run(SimulationRequest("qiling", "sample.exe", allow_execution=True))
    assert rejected.status == "REJECTED"
    unavailable = runner.run(
        SimulationRequest("qiling", "sample.exe", allow_execution=True, worker_isolated=True)
    )
    # Request-side isolation is only an untrusted assertion.  A server-owned
    # policy with a pinned worker identity and image digest is required before
    # the runner may even probe an adapter.
    assert unavailable.status == "REJECTED"
    assert unavailable.stop_reason == "POLICY_DENIED"


def _xor_transform_rows() -> list[dict[str, object]]:
    return [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "http://69.48.228.74/miaom-c.pdf",
                "plaintext": "http://69.48.228.74/miaom-c.pdf",
            },
            "anchor": {"entry": "140004605"},
        },
    ]


def test_verify_xor_mechanism_keeps_transform_when_consumer_is_missing() -> None:
    verification = verify_xor_mechanism(_xor_transform_rows())
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    assert "consumer" in verification.missing
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["cipher/data"] is True
    assert passed["key"] is True
    assert passed["plaintext"] is True
    assert passed["consumer"] is False
    assert passed["join"] is True
    assert "join" not in verification.missing
    assert verification.attempted_action_types == ()


def test_verify_xor_mechanism_rejects_filename_as_plaintext_proof() -> None:
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
        },
        {
            "id": "key-1",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"key_table": [1, 2, 3, 4], "formula": "xor", "counter_initial": 0, "counter_step": 1},
        },
        {
            "id": "name-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"string": "Resume.pdf.exe"},
        },
    ]
    verification = verify_xor_mechanism(rows)
    assert verification.accepted is False
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["plaintext"] is False
    assert verify_mechanism("DECODE_CONFIG", rows).accepted is False


def test_verify_xor_mechanism_rejects_call_token_as_consumer() -> None:
    rows = [
        *_xor_transform_rows(),
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "lstrlenA"},
            "anchor": {"entry": "140004605"},
        },
    ]
    verification = verify_xor_mechanism(rows)
    assert verification.accepted is False
    assert "consumer" in verification.missing


def test_verify_xor_mechanism_keeps_recovered_payload_exe_as_plaintext() -> None:
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "FoxitPDFReader.exe",
                "plaintext": "FoxitPDFReader.exe",
            },
            "anchor": {"entry": "140004605"},
        },
    ]
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["plaintext"] is True
    assert passed["consumer"] is False
    assert verification.accepted is False


def test_cryptoapi_decode_does_not_treat_xor_plaintext_as_consumer() -> None:
    rows = [
        {
            "id": "decrypt",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CryptDecrypt"},
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "decoded_text": "http://example.invalid/gate",
                "plaintext": "http://example.invalid/gate",
                "output_buffer": {"address": 0x18000B000, "length": 24},
            },
            "anchor": {"function_entry": "0x180001000"},
        },
    ]
    verification = verify_mechanism("DECODE_CONFIG", rows)
    assert verification.accepted is False
    assert "consumer" in verification.missing
    assert "counter" not in verification.missing


def test_verify_ppid_rejects_explorer_string_without_process_enumeration() -> None:
    rows = [
        {
            "id": "attr-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "open-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "OpenProcess", "access": "PROCESS_CREATE_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "create-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "flags-1",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "creation_flags", "creation_flags": "0x000f4240"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "name-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    verification = verify_mechanism("PPID_SPOOFING", rows)
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    names = " ".join(verification.missing)
    assert "enumeration" in names or "parent" in names


def test_verify_ppid_string_mentioning_process32_is_not_enumeration() -> None:
    """A Ghidra string that names Process32FirstW is not a snapshot-enum call."""
    rows = [
        {
            "id": "attr-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "open-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "OpenProcess", "access": "PROCESS_CREATE_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "create-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "flags-1",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "creation_flags", "creation_flags": "0x000f4240"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "name-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "Process32FirstW explorer.exe"},
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    verification = verify_mechanism("PPID_SPOOFING", rows)
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    names = " ".join(verification.missing)
    assert "enumeration" in names


def test_verify_ppid_accepts_process32_and_table_decoded_flags() -> None:
    rows = [
        {
            "id": "enum-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "Process32FirstW"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "name-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "open-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "OpenProcess", "access": "PROCESS_CREATE_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "attr-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            },
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "create-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW", "startupinfo": "STARTUPINFOEX"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "flags-1",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "creation_flags", "creation_flags": "0x000f4240"},
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    verification = verify_mechanism("PPID_SPOOFING", rows)
    assert verification.accepted is True
    assert verification.status == "VERIFIED"
    assert "0x09080008" not in verification.reason
    assert "create_suspended" not in verification.reason.casefold()


def test_verify_ppid_import_symbol_process32_is_not_enumeration() -> None:
    """An IAT listing of Process32FirstW is not a matching snapshot-enum chain."""
    rows = [
        {
            "id": "enum-1",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "Process32FirstW"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "name-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "open-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "OpenProcess", "access": "PROCESS_CREATE_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "attr-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            },
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "create-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW", "startupinfo": "STARTUPINFOEX"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "flags-1",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "creation_flags", "creation_flags": "0x000f4240"},
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    verification = verify_mechanism("PPID_SPOOFING", rows)
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    names = " ".join(verification.missing)
    assert "enumeration" in names


def _c3_process_call_and_flags() -> list[dict[str, object]]:
    """CreateProcess call with a credible dwCreationFlags immediate.

    G3 §7.2: the value must survive the credibility gate. ``0x000f4240``
    (1,000,000 ms, a WaitForSingleObject timeout) no longer closes the process
    HOW, so the fixture uses EXTENDED_STARTUPINFO_PRESENT instead.
    """
    return [
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateProcessW",
                "command": "FoxitPDFReader.exe",
                "creation_flags": "0x00080000",
            },
            "anchor": {"function_entry": "0x140004605"},
        },
    ]


def test_process_verifier_does_not_require_decode_join() -> None:
    """Call + recovered flags can VERIFIED; Join is a separate slot."""
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "FoxitPDFReader.exe",
                "plaintext": "FoxitPDFReader.exe",
            },
            "anchor": {"entry": "140004605"},
        },
        *_c3_process_call_and_flags(),
    ]
    verification = verify_process_execution_mechanism(rows)
    assert verification.accepted is True
    assert verification.status == "VERIFIED"
    check_names = [str(item["name"]) for item in verification.checks]
    assert check_names == ["CreateProcess call", "creation_flags"]
    assert "join" not in " ".join(check_names).casefold()
    assert "consumer" not in " ".join(check_names).casefold()
    assert verify_mechanism("PROCESS_EXECUTION", rows).accepted is True


def test_xor_matching_command_string_is_not_a_consumer() -> None:
    """Equal plaintext and CreateProcess command text is co-occurrence, not a Join."""
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "FoxitPDFReader.exe",
                "plaintext": "FoxitPDFReader.exe",
            },
            "anchor": {"entry": "140004605"},
        },
        *_c3_process_call_and_flags(),
    ]
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["plaintext"] is True
    assert passed["consumer"] is False
    assert passed["join"] is False
    assert "consumer" in verification.missing
    assert "join" in verification.missing
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    process = verify_process_execution_mechanism(rows)
    assert process.accepted is True
    assert process.status == "VERIFIED"


def test_xor_string_match_output_to_consumer_is_not_a_join() -> None:
    """A claimed consumer that only repeats the command string is not object-level."""
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "FoxitPDFReader.exe",
                "plaintext": "FoxitPDFReader.exe",
            },
            "anchor": {"entry": "140004605"},
        },
        *_c3_process_call_and_flags(),
        {
            "id": "join-1",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "output_to_consumer",
                "api": "CreateProcessW",
                "consumer": "CreateProcessW",
                "plaintext": "FoxitPDFReader.exe",
                "command": "FoxitPDFReader.exe",
                "source_evidence_ids": ["decode-1"],
                "target_evidence_ids": ["call-1"],
            },
            "anchor": {"entry": "140004605"},
        },
    ]
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["consumer"] is False
    assert passed["join"] is False
    assert "consumer" in verification.missing
    assert "join" in verification.missing
    assert verification.accepted is False
    assert verify_process_execution_mechanism(rows).accepted is True


def test_http_retry_is_not_c2_tasking() -> None:
    """Ordinary WinHTTP retry/Sleep is not command-and-control tasking."""
    rows = [
        {
            "id": "send-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "WinHttpSendRequest"},
            "anchor": {"function_entry": "0x140031f00"},
        },
        {
            "id": "sleep-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "Sleep", "timeout": 5000},
            "anchor": {"function_entry": "0x140031f00"},
        },
        {
            "id": "retry-1",
            "kind": "cfg_block",
            "nature": "STATIC_OBSERVED",
            "value": {"back_edge": True, "handler": "retry"},
            "anchor": {"function_entry": "0x140031f00"},
        },
    ]
    http = verify_mechanism("HTTP_DOWNLOAD", rows)
    assert http.accepted is False
    assert http.status != "VERIFIED"
    guard = verify_mechanism("ENVIRONMENT_GUARD", rows)
    assert guard.accepted is False
    assert guard.status != "VERIFIED"
    loop = verify_mechanism("COMMUNICATION_LOOP", rows)
    assert loop.accepted is False
    assert loop.status != "VERIFIED"


def test_crt_strcmp_is_not_command_dispatch() -> None:
    """A CRT strcmp of command-like text is not a dispatcher."""
    rows = [
        {
            "id": "cmp-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "strcmp", "arguments": ["command", "help"]},
            "anchor": {"function_entry": "0x401100"},
        },
        {
            "id": "str-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "command"},
            "anchor": {"function_entry": "0x401100"},
        },
    ]
    result = verify_mechanism("COMMAND_DISPATCH", rows)
    assert result.accepted is False
    assert result.status != "VERIFIED"
    assert "specialized_verifier_not_available" in result.missing


def test_xor_decode_join_string_match_with_different_buffers_is_not_consumer() -> None:
    """decode_output_to_process_command is a Join only when buffers share identity."""
    same = {
        "artifact_id": "artifact-1",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 24,
    }
    other = {
        "artifact_id": "artifact-1",
        "address_space": "image",
        "address": 0x140010000,
        "length": 24,
    }
    assert is_process_command_text_decode_consumer(
        "FoxitPDFReader.exe",
        "FoxitPDFReader.exe",
        output_buffer=same,
        command_buffer=other,
    ) is False
    assert is_process_command_text_decode_consumer(
        "FoxitPDFReader.exe",
        "FoxitPDFReader.exe",
        output_buffer=same,
        command_buffer=dict(same),
    ) is True
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "FoxitPDFReader.exe",
                "plaintext": "FoxitPDFReader.exe",
                "output_buffer": same,
            },
            "anchor": {"entry": "140004605"},
        },
        *_c3_process_call_and_flags(),
        {
            "id": "join-1",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "decode_output_to_process_command",
                "api": "CreateProcessW",
                "plaintext": "FoxitPDFReader.exe",
                "command": "FoxitPDFReader.exe",
                "output_buffer": same,
                "command_buffer": other,
                "source_evidence_ids": ["decode-1"],
                "target_evidence_ids": ["call-1"],
            },
            "anchor": {"entry": "140004605"},
        },
    ]
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["consumer"] is False
    assert passed["join"] is False
    assert "consumer" in verification.missing
    assert "join" in verification.missing
    assert verification.accepted is False
    assert verify_process_execution_mechanism(rows).accepted is True


def _c3_xor_url_rows(*, extra: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
    rows = [
        {
            "id": "blob-1",
            "kind": "encoded_blob",
            "nature": "STATIC_OBSERVED",
            "value": {"label": "encoded config block", "cipher": "xor-block"},
            "anchor": {"entry": "140004605"},
        },
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "formula": "key_table_modulo_xor_counter",
                "key_table": [182, 144, 1, 106],
                "counter_initial": 3,
                "counter_step": 7,
                "decoded_text": "http://69.48.228.74/miaom-c.pdf",
                "plaintext": "http://69.48.228.74/miaom-c.pdf",
            },
            "anchor": {"entry": "140004605"},
        },
    ]
    if extra:
        rows.extend(extra)
    return rows


def test_xor_url_string_match_without_buffer_identity_is_not_a_winhttp_join() -> None:
    """Matching URL text plus a named WinHttp* API is co-occurrence, not a Join."""
    rows = _c3_xor_url_rows(
        extra=[
            {
                "id": "join-string",
                "kind": "value_flow",
                "nature": "STATIC_DERIVED",
                "value": {
                    "relation": "output_to_consumer",
                    "api": "WinHttpOpen",
                    "consumer": "WinHttpOpen",
                    "plaintext": "http://69.48.228.74/miaom-c.pdf",
                    "url": "http://69.48.228.74/miaom-c.pdf",
                    "source_evidence_ids": ["decode-1"],
                    "target_evidence_ids": ["http-1"],
                },
                "anchor": {"entry": "140004605"},
            },
            {
                "id": "http-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "WinHttpOpen"},
                "anchor": {"function_entry": "0x140031f00"},
            },
        ]
    )
    assert _xor_row_is_object_consumer(rows[-2]) is False
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["plaintext"] is True
    assert passed["consumer"] is False
    assert passed["join"] is False
    assert "consumer" in verification.missing
    assert "join" in verification.missing
    assert verification.accepted is False
    assert verification.status != "VERIFIED"
    attempted = getattr(verification, "attempted_action_types", ())
    assert set(attempted) <= set()
    for invented in ("GET_DECOMPILE", "TRACE_API_ARGUMENT", "CONTROLLED_EMULATE"):
        assert invented not in attempted


def test_xor_same_buffer_winhttp_output_is_a_join() -> None:
    """Object-level same-buffer WinHTTP output_to_consumer is a Join."""
    buffer = {
        "artifact_id": "artifact-1",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 31,
    }
    rows = _c3_xor_url_rows(
        extra=[
            {
                "id": "join-obj",
                "kind": "value_flow",
                "nature": "STATIC_DERIVED",
                "value": {
                    "relation": "output_to_consumer",
                    "api": "WinHttpOpen",
                    "consumer": "WinHttpOpen",
                    "output_buffer": buffer,
                    "input_buffer": buffer,
                    "source_evidence_ids": ["decode-1"],
                    "target_evidence_ids": ["http-1"],
                },
                "anchor": {"entry": "140004605"},
            },
            {
                "id": "http-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "WinHttpOpen", "input_buffer": buffer},
                "anchor": {"entry": "140004605"},
            },
        ]
    )
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["join"] is True
    assert passed["consumer"] is True
    assert "join" not in verification.missing
    assert verification.attempted_action_types == ()


def test_xor_same_buffer_loadlibrary_consumer_does_not_require_resume_join() -> None:
    """Lite XOR floor: named same-buffer LoadLibrary is VERIFIED without a Resume sink."""
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 31,
    }
    rows = _xor_transform_rows()
    rows[1]["value"]["output_buffer"] = dict(buffer)
    rows.extend(
        [
            {
                "id": "api-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "LoadLibraryW"},
                "anchor": {"entry": "140004605"},
            },
            {
                "id": "flow-1",
                "kind": "value_flow",
                "nature": "STATIC_INFERRED",
                "value": catalog_output_consumer_relation(
                    producer_id="decode-1",
                    consumer_id="api-1",
                    output_buffer=dict(buffer),
                    consumer_api="LoadLibraryW",
                ),
                "anchor": {"entry": "140004605"},
            },
        ]
    )
    verification = verify_xor_mechanism(rows)
    passed = {str(item["name"]): bool(item["passed"]) for item in verification.checks}
    assert passed["consumer"] is True
    assert passed["join"] is True
    assert verification.accepted is True
    assert verification.status == "VERIFIED"


def test_xor_join_attempt_types_come_from_evidence_never_invented() -> None:
    rows = _xor_transform_rows()
    rows.append(
        {
            "id": "attempt-1",
            "kind": "investigation_attempt",
            "nature": "STATIC_DERIVED",
            "value": {"attempted_action_types": ["GET_DECOMPILE"]},
        }
    )
    verification = verify_xor_mechanism(rows)
    assert verification.attempted_action_types == ("GET_DECOMPILE",)
    assert "TRACE_API_ARGUMENT" not in verification.attempted_action_types
    assert "CONTROLLED_EMULATE" not in verification.attempted_action_types
    assert "consumer" in verification.missing
    assert verification.status != "VERIFIED"


def _join_loop_action(action_id: str, action_type: ActionType, *, priority: int = 10) -> ActionSpec:
    return ActionSpec(
        id=action_id,
        action_type=action_type,
        thread_id="decode-thread",
        hypothesis_id="decode-h",
        artifact_id="artifact-1",
        priority=priority,
        reason="recover decode consumer join",
        parameters={"target": "0x140004605"},
        target_selector={"target": "0x140004605"},
        expected_evidence_kinds=("function_context",),
    )


def test_decode_loop_unknown_join_records_only_actions_this_loop_ran() -> None:
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type.value)
        return []

    result = InvestigationLoopDriver(max_steps=4, max_consecutive_no_gain=2).run(
        thread_id="decode-thread",
        artifact_id="artifact-1",
        question="What consumes the recovered XOR plaintext?",
        hypothesis_id="decode-h",
        hypothesis_statement="The function xor-decodes a config block for a later consumer.",
        initial_evidence=_xor_transform_rows(),
        proposed_actions=(
            _join_loop_action("a-decompile", ActionType.GET_DECOMPILE, priority=10),
            _join_loop_action("a-trace", ActionType.TRACE_API_ARGUMENT, priority=20),
        ),
        execute=execute,
        allow_investigator_actions=False,
    )
    attempts = [row for row in result.evidence if row.get("kind") == "investigation_attempt"]
    assert len(attempts) == 1
    listed = list(attempts[0]["value"]["attempted_action_types"])
    assert set(listed) <= set(executed)
    assert "GET_DECOMPILE" in listed
    assert "CONTROLLED_EMULATE" not in listed
    xor = verify_xor_mechanism(result.evidence)
    assert xor.status != "VERIFIED"
    assert "consumer" in xor.missing
    assert set(xor.attempted_action_types) == set(listed)


def test_decode_loop_omits_join_actions_this_loop_did_not_run() -> None:
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type.value)
        return []

    result = InvestigationLoopDriver(max_steps=2, max_consecutive_no_gain=2).run(
        thread_id="decode-thread",
        artifact_id="artifact-1",
        question="What consumes the recovered XOR plaintext?",
        hypothesis_id="decode-h",
        hypothesis_statement="The function xor-decodes a config block for a later consumer.",
        initial_evidence=_xor_transform_rows(),
        proposed_actions=(_join_loop_action("a-function", ActionType.GET_FUNCTION),),
        execute=execute,
        allow_investigator_actions=False,
    )
    assert executed == ["GET_FUNCTION"]
    attempts = [row for row in result.evidence if row.get("kind") == "investigation_attempt"]
    assert len(attempts) == 1
    listed = list(attempts[0]["value"]["attempted_action_types"])
    assert listed == []
    xor = verify_xor_mechanism(result.evidence)
    assert xor.attempted_action_types == ()
    for invented in ("GET_DECOMPILE", "TRACE_API_ARGUMENT", "CONTROLLED_EMULATE"):
        assert invented not in xor.attempted_action_types


def test_one_loop_run_executes_multiple_actions_for_one_request() -> None:
    executed: list[ActionType] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type)
        return [
            {
                "kind": "function_context",
                "value": {"name": action.action_type.value, "function_entry": "0x1000", "target": "0x1000"},
                "anchor": {"function_entry": "0x1000", "target": "0x1000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=8).run(
        thread_id="multi-thread",
        artifact_id="artifact-1",
        question="What does this function do?",
        hypothesis_id="h1",
        hypothesis_statement="The function may expose ordered callees.",
        initial_evidence=(
            {
                "id": "fn-1",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "FUN_1000", "function_entry": "0x1000"},
                "anchor": {"function_entry": "0x1000"},
            },
        ),
        proposed_actions=(
            ActionSpec(
                id="a-fn",
                action_type=ActionType.GET_FUNCTION,
                thread_id="multi-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=10,
                parameters={"target": "0x1000"},
                target_selector={"target": "0x1000"},
                expected_evidence_kinds=("function_context",),
            ),
            ActionSpec(
                id="a-callees",
                action_type=ActionType.GET_CALLEES,
                thread_id="multi-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=20,
                parameters={"target": "0x1000"},
                target_selector={"target": "0x1000"},
                expected_evidence_kinds=("function_context",),
            ),
        ),
        execute=execute,
        allow_investigator_actions=False,
    )
    assert len(executed) >= 2
    assert ActionType.GET_FUNCTION in executed
    assert ActionType.GET_CALLEES in executed
    assert len(result.actions) >= 2


def test_no_new_evidence_records_method_fields_and_retries_one_different_family() -> None:
    executed: list[ActionType] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type)
        return []

    result = InvestigationLoopDriver(max_steps=6, max_consecutive_no_gain=2).run(
        thread_id="k01-thread",
        artifact_id="artifact-1",
        question="What consumes the recovered buffer?",
        hypothesis_id="h1",
        hypothesis_statement="The function may decode a buffer.",
        initial_evidence=(
            {
                "id": "fn-1",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "xor_decode_config", "function_entry": "0x401000"},
                "anchor": {"function_entry": "0x401000"},
            },
        ),
        proposed_actions=(
            ActionSpec(
                id="a-callees",
                action_type=ActionType.GET_CALLEES,
                thread_id="k01-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=10,
                parameters={"target": "0x401000"},
                target_selector={"target": "0x401000"},
                expected_evidence_kinds=("function_context",),
            ),
            ActionSpec(
                id="a-function",
                action_type=ActionType.GET_FUNCTION,
                thread_id="k01-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=11,
                parameters={"target": "0x401000"},
                target_selector={"target": "0x401000"},
                expected_evidence_kinds=("function_context",),
            ),
            ActionSpec(
                id="a-decompile",
                action_type=ActionType.GET_DECOMPILE,
                thread_id="k01-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=20,
                parameters={"target": "0x401000"},
                target_selector={"target": "0x401000"},
                expected_evidence_kinds=("function_context",),
            ),
        ),
        execute=execute,
        allow_investigator_actions=False,
    )
    assert ActionType.GET_CALLEES in executed
    assert ActionType.GET_FUNCTION not in executed
    assert ActionType.GET_DECOMPILE in executed
    failed = next(action for action in result.actions if action.action_type == ActionType.GET_CALLEES)
    plan = failed.plan
    assert plan.get("method_assumption")
    assert plan.get("next_method")
    assert plan.get("frontier_fingerprint_before")
    assert plan.get("frontier_fingerprint_after")
    assert plan.get("gain_class") == "NO_NEW_EVIDENCE"


def test_consecutive_zero_gain_stalls_without_same_selector_replay() -> None:
    executed_keys: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        selector = tuple(sorted((str(key), str(value)) for key, value in dict(action.target_selector).items()))
        executed_keys.append((action.action_type.value, selector))
        return []

    result = InvestigationLoopDriver(max_steps=8, max_consecutive_no_gain=2).run(
        thread_id="stall-thread",
        artifact_id="artifact-1",
        question="What does this function do?",
        hypothesis_id="h1",
        hypothesis_statement="The function may expose a static path.",
        initial_evidence=(
            {
                "id": "fn-1",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "FUN_401000", "function_entry": "0x401000"},
                "anchor": {"function_entry": "0x401000"},
            },
        ),
        proposed_actions=(
            ActionSpec(
                id="a-decompile",
                action_type=ActionType.GET_DECOMPILE,
                thread_id="stall-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=10,
                parameters={"target": "0x401000"},
                target_selector={"target": "0x401000"},
                expected_evidence_kinds=("function_context",),
            ),
            ActionSpec(
                id="a-trace",
                action_type=ActionType.TRACE_API_ARGUMENT,
                thread_id="stall-thread",
                hypothesis_id="h1",
                artifact_id="artifact-1",
                priority=20,
                parameters={"target": "0x401000"},
                target_selector={"target": "0x401000"},
                expected_evidence_kinds=("api_argument_trace",),
            ),
        ),
        execute=execute,
        allow_investigator_actions=False,
    )
    assert result.coverage.get("k02_status") in {"STALLED", "BACKTRACK_REQUIRED"}
    assert any(item.phase in {"stalled", "backtrack_required"} for item in result.events)
    assert len(executed_keys) == len(set(executed_keys))
    assert result.thread_state == InvestigationThreadState.UNKNOWN

