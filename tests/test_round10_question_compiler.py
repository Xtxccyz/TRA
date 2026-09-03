from threat_report_agent.orchestration import QuestionCompiler
from threat_report_agent.contracts import Mechanism
from threat_report_agent.investigation import verify_mechanism
from benchmarks.evidence_funnel import build_evidence_funnel
from threat_report_agent.orchestration import QuestionCentricContextBuilder


def test_question_compiler_splits_case_goal_into_atomic_threads() -> None:
    compiler = QuestionCompiler()
    questions = compiler.compile(
        "Explain loading, decode, execution, network, and evasion for this PE",
        artifact_id="artifact-1",
        detected_type="pe",
        evidence_kinds=("import_symbol", "string", "function"),
    )

    assert len(questions) >= 4
    assert all(q.target_anchors for q in questions)
    assert all(q.required_evidence_kinds for q in questions)
    assert all(q.success_requirements for q in questions)
    assert all(q.stop_conditions for q in questions)
    assert all("What malicious things" not in q.question for q in questions)


def test_question_compiler_preserves_specific_anchor() -> None:
    questions = QuestionCompiler().compile(
        "Which APIs are resolved by FUN_14000C520?",
        artifact_id="artifact-2",
        detected_type="pe",
        evidence_kinds=("function",),
    )
    assert len(questions) == 1
    assert questions[0].thread_type == "TRACE_DYNAMIC_API_RESOLUTION"
    assert "FUN_14000C520" in questions[0].question
    assert "FUN_14000C520" in questions[0].target_anchors


def test_mechanism_contract_has_typed_recovery_fields_and_score() -> None:
    mechanism = Mechanism(
        id="m1", thread_id="t1", dimension="network", type="HTTP_DOWNLOAD",
        target="endpoint", inputs=("host",),
        transformation_or_control=("WinHttpOpen -> WinHttpSendRequest",),
        conditions=("decoded host is non-empty",), outputs=("response bytes",),
        side_effects=("network request candidate",), consumers=("loader",),
        evidence_ids=("e1",), status="CONFIRMED",
    )
    assert mechanism.completeness_score == 100


def test_ppid_verifier_requires_semantic_chain_and_rejects_negative_gold() -> None:
    evidence = [
        {"id": "e1", "kind": "function_call", "value": "explorer.exe Process32First"},
        {"id": "e2", "kind": "function_call", "value": "OpenProcess(PROCESS_CREATE_PROCESS)"},
        {"id": "e3", "kind": "function_call", "value": "UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"},
        {"id": "e4", "kind": "function_call", "value": "CreateProcessW STARTUPINFOEX"},
        {"id": "e5", "kind": "constant", "value": "0x09080008 CREATE_NO_WINDOW DETACHED_PROCESS"},
    ]
    result = verify_mechanism("PPID_SPOOFING", evidence)
    assert result.status == "VERIFIED"
    bad = verify_mechanism("PPID_SPOOFING", [*evidence, {"id": "e6", "kind": "constant", "value": "CREATE_SUSPENDED"}])
    assert bad.status == "CONTRADICTED"


def test_round10_funnel_excludes_explained_loss_from_silent_loss_and_reports_rates() -> None:
    score = build_evidence_funnel(
        {
            "id": "metric-fixture",
            "evidence": [{"id": "e1", "value": "OpenProcess", "anchor": {}}],
            "evidence_delivery": {"records": [{"evidence_id": "e1", "stage": "CANDIDATE", "exclusion_reason": "out_of_thread_scope"}]},
            "claims": [], "claim_evidence": [],
            "investigation": {"threads": [], "actions": [{"outcome": "INVALID"}, {"outcome": "PRODUCTIVE", "critical": True, "result_evidence_ids": ["e1"]}]},
            "limitations": [],
        },
        {"version": "metric-v2", "evaluator_only": True, "mechanisms": [{"id": "m", "components": {"chain": ["OpenProcess"]}}]},
    )
    assert score["summary"]["silent_evidence_loss"] == 0
    assert score["summary"]["invalid_action_rate"] == 0.5
    assert "invalid_action_rate" in score["gate"]["failures"]


def test_context_builder_exposes_round10_control_fields() -> None:
    packet = QuestionCentricContextBuilder().build(
        question="Which APIs are resolved?", artifact={"id": "a1"}, evidence=[],
        allowed_actions=["GET_XREFS_TO"], evidence_budget=12,
        mechanism_requirements=["resolver identified"],
    )
    assert packet["allowed_actions"] == ["GET_XREFS_TO"]
    assert packet["evidence_budget"] == 12
    assert packet["mechanism_requirements"] == ["resolver identified"]
    assert packet["forbidden_inferences"]


def test_question_compiler_is_sample_adaptive_from_observed_signals() -> None:
    questions = QuestionCompiler().compile(
        "", artifact_id="artifact-net", detected_type="pe",
        evidence_kinds=("function", "function_ioc", "network_indicator"),
    )
    assert len(questions) == 1
    assert questions[0].thread_type == "TRACE_NETWORK_CONSUMER"
    assert "network" in questions[0].question.casefold()


def test_question_compiler_does_not_default_to_dynamic_resolver_without_signals() -> None:
    questions = QuestionCompiler().compile(
        "", artifact_id="artifact-plain", detected_type="pe",
        evidence_kinds=("function", "cfg_block"),
    )
    assert questions[0].thread_type == "TRACE_ENTRY_TIMELINE"
    assert "resolved dynamically" not in questions[0].question.casefold()
