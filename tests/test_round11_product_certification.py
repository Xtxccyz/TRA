from threat_report_agent.product_certification import (
    AnalysisResultClass,
    aggregate_result_class,
    analysis_coverage,
    classify_artifact_result,
    release_gate,
    static_wording_violations,
    supported_artifact_matrix,
    validate_corpus_split,
)
from threat_report_agent.report.analyst_report import compose_official_markdown
from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    render_ledger_markdown,
    report_v3_quality_violations,
)


def test_analysis_result_class_distinguishes_failure_from_static_boundary() -> None:
    assert classify_artifact_result("pe", tool_runs=[]) is AnalysisResultClass.FAILED_ANALYSIS
    assert classify_artifact_result(
        "pe", tool_runs=[{"status": "SUCCEEDED"}], limitations=["packed PE; static boundary"]
    ) is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    assert classify_artifact_result(
        "script",
        tool_runs=[{"status": "SUCCEEDED"}],
        limitations=["The actual behavior cannot be determined from static evidence alone."],
    ) is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    assert classify_artifact_result(
        "script",
        tool_runs=[{"status": "SUCCEEDED"}],
        limitations=["Actual malicious behavior is impossible to determine without dynamic analysis."],
    ) is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    assert classify_artifact_result("elf", tool_runs=[{"status": "SUCCEEDED"}]) is AnalysisResultClass.UNSUPPORTED_ARTIFACT
    assert classify_artifact_result("pe", tool_runs=[{"status": "SUCCEEDED"}]) is AnalysisResultClass.FULL_STATIC_ANALYSIS


def test_analysis_class_release_examples_are_explicit_and_non_overlapping() -> None:
    # Analyzer failure is a product failure, not a static limitation.
    assert classify_artifact_result(
        "pe", tool_runs=[{"status": "FAILED", "error": "worker unavailable"}]
    ) is AnalysisResultClass.FAILED_ANALYSIS
    # Packing/runtime-only semantics are a truthful static boundary after a
    # successful parser run.
    assert classify_artifact_result(
        "pe", tool_runs=[{"status": "SUCCEEDED"}], metadata={"packing": "probable packed PE"}
    ) is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    # Formats outside the release matrix stay unsupported even if a generic
    # tool happened to return a successful result.
    assert classify_artifact_result("elf", tool_runs=[{"status": "SUCCEEDED"}]) is AnalysisResultClass.UNSUPPORTED_ARTIFACT
    # A benign/control PE remains a complete static analysis; no malicious
    # mechanism is not the same as an analysis failure.
    assert classify_artifact_result(
        "pe", tool_runs=[{"status": "SUCCEEDED"}], metadata={"control": "benign"}
    ) is AnalysisResultClass.FULL_STATIC_ANALYSIS
    # Runtime uncertainty alone is not a structural static boundary when the
    # caller supplies the new explicit classification channel.
    assert classify_artifact_result(
        "pe",
        tool_runs=[{"status": "SUCCEEDED"}],
        limitations=["dynamic execution is unavailable"],
        structural_limitations=[],
    ) is AnalysisResultClass.FULL_STATIC_ANALYSIS


def test_aggregate_result_class_is_strict_and_truthful() -> None:
    assert aggregate_result_class(["FULL_STATIC_ANALYSIS", "BOUNDED_STATIC_ANALYSIS"]) is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    assert aggregate_result_class(["UNSUPPORTED_ARTIFACT"]) is AnalysisResultClass.UNSUPPORTED_ARTIFACT
    assert aggregate_result_class(["UNSUPPORTED_ARTIFACT", "FAILED_ANALYSIS"]) is AnalysisResultClass.FAILED_ANALYSIS


def test_static_wording_guard_allows_qualified_static_language() -> None:
    assert static_wording_violations("The sample would attempt a network connection if executed.") == []
    assert static_wording_violations("No sample code was executed during this review.") == []
    assert static_wording_violations("The sample was never executed by the analyzer.") == []
    assert static_wording_violations("The sample would be executed if run in a sandbox.") == []
    assert static_wording_violations("The sample connected to the C2 server.")
    assert static_wording_violations("DYNAMIC_OBSERVED evidence was recorded.")
    assert static_wording_violations("The sample was executed successfully.")
    # Qualification is scoped to one clause; a later unqualified assertion
    # must still be rejected.
    assert static_wording_violations(
        "No sample code was executed during this review; the sample was executed successfully."
    ) == [r"\bexecuted\b"]
    # Markdown/JSON detail strings may contain punctuation in their key or
    # value.  The quoted value must be evaluated as one semantic clause.
    assert static_wording_violations(
        '- detail: "No dynamic execution evidence is available to confirm '
        'if or how the embedded payload.bin is loaded or executed by the host application."'
    ) == []
    assert static_wording_violations('- detail: "The sample executed successfully."') == [
        r"\bexecuted\b"
    ]
    assert static_wording_violations(
        "- detail: 'No dynamic execution evidence can confirm whether the payload was executed.'"
    ) == []
    assert static_wording_violations("- detail: 'The sample executed successfully.'") == [
        r"\bexecuted\b"
    ]
    assert static_wording_violations("The sample can't be executed by this analyzer.") == []


def test_coverage_is_bounded_and_exposes_gaps() -> None:
    coverage = analysis_coverage(
        artifact_parse=1.5,
        code_recovery=-1,
        function_coverage=.5,
        data_reference_coverage=.25,
        mechanism_investigation=.75,
        verifier_coverage=1,
        report_synthesis=1,
        gaps=["packed child", "packed child"],
    )
    assert coverage["score"] == 64.29
    assert coverage["dimensions"]["artifact_parse"] == 1
    assert coverage["dimensions"]["code_recovery"] == 0
    assert coverage["gaps"] == ["packed child"]


def test_support_matrix_is_public_and_corpus_validation_is_strict() -> None:
    matrix = supported_artifact_matrix()
    assert any(item["artifact_class"] == "pe32_x86_exe" for item in matrix)
    errors = validate_corpus_split(
        [{"sample_id": "one", "sha256": "bad", "category": "malware", "split": "development"}]
    )
    assert any("15 malware" in item for item in errors)
    assert any("lowercase SHA-256" in item for item in errors)


def test_release_gate_never_passes_missing_external_metrics() -> None:
    result = release_gate({}, external_blockers=["Docker unavailable"])
    assert result["status"] == "BLOCKED"
    assert result["blocker_count"] >= 20
    assert "Docker unavailable" in result["blockers"]


def test_release_gate_accepts_only_a_complete_certification_scorecard() -> None:
    minimums = {
        "evidence_retrieval_recall": 0.90,
        "evidence_delivery_recall": 0.90,
        "critical_mechanism_delivery_recall": 0.95,
        "model_utilization": 0.70,
        "thread_discovery_recall": 0.70,
        "critical_thread_discovery_recall": 0.85,
        "case_productivity": 0.50,
        "critical_thread_productivity": 0.60,
        "context_precision": 0.70,
        "critical_mechanism_precision": 0.95,
        "critical_mechanism_recall": 0.80,
        "mechanism_completeness": 0.80,
        "boundary_classification_precision": 0.95,
        "full_report_quality_pass_rate": 0.80,
        "unknown_calibration": 0.85,
        "core_finding_mechanism_coverage": 1.0,
        "traceability": 1.0,
        "analysis_completion_rate": 0.95,
    }
    maximums = {
        "invalid_action_rate": 0.02,
        "duplicate_action_rate": 0.05,
        "failed_analysis_rate": 0.05,
        "report_bloat_violation_rate": 0.0,
        "benign_critical_false_positive_rate": 0.0,
    }
    metrics = {
        **minimums,
        **maximums,
        "critical_unsupported_claims": 0,
        "negative_gold_violations": 0,
        "false_refuted_from_absence": 0,
        **{key: True for key in (
            "security_audit_pass", "browser_e2e_pass", "restart_recovery_pass",
            "concurrency_pass", "soak_pass", "independent_review_pass",
            "dsh_core_diff_zero", "dangerous_tool_exposure_zero",
            "sample_execution_zero", "sample_network_zero",
            "cross_case_isolation_pass",
        )},
    }
    assert release_gate(metrics)["status"] == "PASS"


def test_report_v3_contract_survives_module_projection() -> None:
    """Hidden modules remain analyzable while the projection may be selective."""
    document = {
        "report_version": "3.0",
        "analysis_class": "FULL_STATIC_ANALYSIS",
        "analysis_coverage": {"score": 100},
        "case_id": "case-1",
        "task_id": "task-1",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "selected_modules": ["loader"],
        "modules": [{"id": "loader", "rows": []}],
    }
    assert report_v3_quality_violations(document) == []


def test_report_projection_preserves_static_boundary_statement() -> None:
    """The static boundary must be stated on the path the reader actually gets.

    MEASURED at the P2-R step-5 retirement (`.scratch/p2r5-boundary-statement.py`): this test used to assert the
    module SUMMARY sentence `"No sample code was executed during this review."`, which appeared ONLY in the pre-V3
    renderer that the retirement deleted. Neither surviving producer prints module summaries - and production never
    called that renderer, so the requirement was pinned on dead code.

    The live requirement is not lost: the OFFICIAL body states the boundary in its own banner, and that banner had
    NO test at all before this change. So this now pins the live wording (a stronger, load-bearing assertion) and
    separately keeps the ledger's boundary SECTION, instead of the retired renderer's phrasing.
    """
    document = {
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [
            {
                "id": "limitations",
                "title": "Unknowns / Static Boundaries",
                "summary": "No sample code was executed during this review.",
                "rows": [],
            }
        ],
    }

    official = compose_official_markdown(document)
    assert "This is not sandbox/dynamic analysis (full sample execution)." in official, (
        "the official body no longer states that the analysis was not full sample execution; that is the "
        "analyst-facing static boundary and it is what this test now pins"
    )

    ledger = render_ledger_markdown(document)
    assert "Unknowns / Static Boundaries" in ledger, (
        "the ledger projection dropped the static-boundary section entirely"
    )


def test_report_v3_projection_is_analyst_facing_and_not_an_evidence_dump() -> None:
    document = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-v3",
        "task_id": "task-v3",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {
            "score": 48.0,
            "dimensions": {"artifact_parse": 1.0, "mechanism_investigation": 0.2},
            "pipeline_completion": {"score": 100.0},
            "gaps": ["missing dependency blocks consumer resolution"],
        },
        "modules": [
            {"id": "executive_summary", "title": "执行摘要", "summary": "Static assessment: suspicious static indicators.", "rows": [
                {"type": "analyst_assessment", "summary": "Static assessment: suspicious static indicators.", "findings": [
                    {"type": "analytical_claim", "module": "loader", "claim_id": "c1", "finding": "A buffer is prepared for a secondary component.", "mechanism": "resource -> decode -> memory", "condition": "static evidence only", "confidence": "MEDIUM", "evidence_ids": ["e1"]}
                ]}
            ]},
            {"id": "artifact_inventory", "title": "样本与组件清单", "summary": "", "rows": [
                {"artifact_id": "a1", "path": "sample.exe", "type": "pe", "role": "EXECUTABLE", "sha256": "a" * 64}
            ]},
            {"id": "evidence_ledger", "title": "证据账本", "summary": "", "rows": [
                {"type": "evidence_group", "kind": "string", "count": 5000, "evidence_ids": ["e1", "e2", "e3", "e4", "e5"]}
            ]},
        ],
        "trace": {"evidence_ids": [f"e{i}" for i in range(100)], "claim_ids": ["c1"], "tool_run_ids": ["t1"]},
    }
    rendered = render_ledger_markdown(document)
    assert "## 3. Key Static Findings" in rendered
    assert "A buffer is prepared" in rendered
    assert "5000" not in rendered
    assert "e2" not in rendered
    assert len(rendered.encode("utf-8")) < 20_000
