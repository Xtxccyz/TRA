from __future__ import annotations

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
)
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService
from threat_report_agent.simulation_adapters import IsolatedSimulationRunner, SimulationRequest
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
                "value": {"call_targets": ["GetProcAddress"]},
            },
            {
                "id": "resolver-xref",
                "kind": "xref",
                "nature": "STATIC_OBSERVED",
                "value": {"target_name": "GetProcAddress"},
            },
            {
                "id": "resolver-data",
                "kind": "data_reference",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "encoded API name"},
            },
        ],
        "Does the sample dynamically resolve APIs?",
        "The sample may dynamically resolve APIs.",
    )
    assert complete.accepted is True


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
        ],
        scheduled=set(),
    )

    xref_targets = {
        str(item.parameters.get("target"))
        for item in suggestions
        if item.action_type == ActionType.GET_XREFS_TO
    }
    assert xref_targets == {"GetProcAddress", "LoadLibraryA"}
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
    assert len(no_gain_events) == 2
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
        "value": {"text": "explorer.exe"},
    }
    calls: list[ActionType] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        calls.append(action.action_type)
        if action.action_type == ActionType.GET_STRINGS_REFERENCED:
            return [{"kind": "function_call", "value": {"api": "OpenProcess"}}]
        if action.action_type == ActionType.GET_CALLEES:
            return [{"kind": "function_call", "value": {"api": "UpdateProcThreadAttribute"}}]
        if action.action_type == ActionType.EVALUATE_CONSTANT:
            return [{"kind": "constant", "value": {"name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"}}]
        return []

    result = InvestigationLoopDriver(max_steps=8).run(
        thread_id="t1",
        artifact_id="artifact-1",
        question="Can the sample spoof its parent process?",
        hypothesis_id="h1",
        hypothesis_statement="The sample may implement PPID spoofing.",
        initial_evidence=(initial,),
        execute=execute,
    )

    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    assert result.hypothesis_status == "SUPPORTED"
    assert ActionType.GET_STRINGS_REFERENCED in calls
    assert ActionType.EVALUATE_CONSTANT in calls
    assert len(result.events) >= 3


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
    assert any(item["module"] == "execution" for item in view["claims"])
    trace = service.analysis_trace(result.task_id)
    assert trace["investigation"]["private_chain_of_thought"] is False
    assert any(event["phase"] == "action_completed" for event in trace["investigation"]["runtime"]["events"])
    report = service.get_report_revision(result.report_revision_id)
    assert "PERSISTED_INVESTIGATION" in report["markdown"]


def test_dynamic_simulation_requires_isolated_worker_and_explicit_policy() -> None:
    runner = IsolatedSimulationRunner()
    denied = runner.run(SimulationRequest("qiling", "sample.exe"))
    assert denied.status == "DISABLED_BY_POLICY"
    rejected = runner.run(SimulationRequest("qiling", "sample.exe", allow_execution=True))
    assert rejected.status == "REJECTED"
    unavailable = runner.run(
        SimulationRequest("qiling", "sample.exe", allow_execution=True, worker_isolated=True)
    )
    assert unavailable.status in {"READY", "UNAVAILABLE"}
