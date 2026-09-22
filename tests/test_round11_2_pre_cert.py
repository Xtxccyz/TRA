from threat_report_agent.product_certification import analysis_coverage, semantic_flow_metrics
from threat_report_agent.report.reporting import render_ledger_markdown


def _closed_mechanism() -> dict[str, object]:
    return {
        "status": "VERIFIED",
        "target": "sample.exe",
        "inputs": ["module name and entry-point name data"],
        "transformation_or_control": [
            "LoadLibrary resolves the module; GetProcAddress resolves its entry point"
        ],
        "conditions": ["static call/data-flow ordering is recovered"],
        "outputs": ["resolved function address"],
        "consumers": ["resolved entry-point consumer"],
        "side_effects": ["loads a secondary module and prepares a resolved entry point"],
        "evidence_ids": ["e1", "e2"],
        "verifier": {"status": "VERIFIED"},
    }


def test_semantic_flow_metrics_count_only_closed_high_level_nodes() -> None:
    metrics = semantic_flow_metrics([_closed_mechanism()])
    assert metrics == {
        "semantic_flow_nodes": 4,
        "semantic_flow_edges": 3,
        "eligible_mechanisms": 1,
        "participating_mechanisms": 1,
        "relation_flow_coverage": 1.0,
        "coverage_applicable": True,
        "behavior_flow_present": True,
    }


def test_semantic_flow_metrics_is_not_applicable_without_closed_mechanisms() -> None:
    metrics = semantic_flow_metrics([{"status": "CANDIDATE", "inputs": ["x"]}])
    assert metrics["semantic_flow_nodes"] == 0
    assert metrics["semantic_flow_edges"] == 0
    assert metrics["relation_flow_coverage"] == 0.0
    assert metrics["coverage_applicable"] is False
    assert metrics["behavior_flow_present"] is False


def test_analysis_coverage_exposes_flow_contract_without_changing_score_dimensions() -> None:
    coverage = analysis_coverage(
        artifact_parse=1.0,
        code_recovery=1.0,
        function_coverage=1.0,
        data_reference_coverage=1.0,
        mechanism_investigation=1.0,
        verifier_coverage=1.0,
        report_synthesis=1.0,
        verified_mechanism_coverage=1.0,
        relation_flow_coverage=1.0,
        semantic_flow_nodes=4,
        semantic_flow_edges=3,
        behavior_flow_present=True,
        coverage_applicable=True,
    )
    assert coverage["semantic_flow_nodes"] == 4
    assert coverage["semantic_flow_edges"] == 3
    assert coverage["behavior_flow_present"] is True
    assert coverage["coverage_applicable"] is True
    assert "semantic_flow_nodes" not in coverage["dimensions"]


def test_report_distinguishes_task_outcome_from_analysis_class() -> None:
    markdown = render_ledger_markdown(
        {
            "report_version": "3.0",
            "report_sections": ["Executive Assessment"],
            "case_id": "case-1",
            "task_id": "task-1",
            "analysis_outcome": "PARTIAL",
            "analysis_class": "FULL_STATIC_ANALYSIS",
            "analysis_coverage": {},
            "modules": [],
            "trace": {},
        }
    )
    assert "Task Outcome" in markdown
    assert "Analysis Class" in markdown
    assert "Legacy task-completion field" in markdown
