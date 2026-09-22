from types import SimpleNamespace

import pytest

from threat_report_agent.investigation import mechanism_completeness_score
from threat_report_agent.investigation import MechanismPlaybookRegistry, verify_dynamic_api_mechanism
from threat_report_agent.product_certification import AnalysisResultClass, classify_artifact_result
from threat_report_agent.product_certification import analysis_coverage, mechanism_coverage_metrics
from threat_report_agent.report.reporting import build_mechanism_projections, render_ledger_markdown
from threat_report_agent.service import AnalysisService
from threat_report_agent.static_analysis import derive_function_mechanism_facts


@pytest.mark.parametrize(
    "api",
    [
        "GetSystemTime",
        "GetSystemTimeAsFileTime",
        "SystemTimeToFileTime",
        "QueryPerformanceCounter",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetTickCount",
        "memset",
        "memcpy",
        "malloc",
        "free",
    ],
)
def test_non_execution_api_never_becomes_execution_mechanism(api: str) -> None:
    facts = derive_function_mechanism_facts(
        {
            "name": "helper",
            "entry": "0x1000",
            "references_from": [{"type": "CALL", "target_name": api, "from": "0x1001"}],
        }
    )
    assert all(
        not (
            fact.kind == "mechanism_chain"
            and "execution" in fact.value.get("categories", [])
        )
        for fact in facts
    )


@pytest.mark.parametrize(
    "api",
    ["CreateProcessA", "CreateProcessW", "CreateProcessAsUserW", "WinExec", "ShellExecuteW", "system", "_popen"],
)
def test_explicit_execution_api_remains_execution_mechanism(api: str) -> None:
    facts = derive_function_mechanism_facts(
        {
            "name": "launcher",
            "entry": "0x1000",
            "references_from": [
                {"type": "CALL", "target_name": api, "from": "0x1001"},
                {"type": "CALL", "target_name": "OpenProcess", "from": "0x1002"},
            ],
        }
    )
    assert any(
        fact.kind == "mechanism_chain" and "execution" in fact.value.get("categories", [])
        for fact in facts
    )


def test_unknown_mandatory_fields_do_not_score_as_complete() -> None:
    mechanism = {
        "target": "loader",
        "inputs": ["UNKNOWN(input)"],
        "transformation_or_control": ["xor decode"],
        "conditions": ["static evidence only"],
        "outputs": ["UNKNOWN(output)"],
        "consumers": ["UNKNOWN(consumer)"],
        "side_effects": ["UNKNOWN(side_effect)"],
        "evidence_ids": ["e1"],
    }
    assert mechanism_completeness_score(mechanism) <= 60


def test_dynamic_resolution_template_fields_do_not_score_as_concrete() -> None:
    """Generic resolver/consumer labels must not masquerade as recovered values."""
    mechanism = {
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "target": "FUN_14000a2c0@14000a2c0",
        "inputs": ["module name and exported entry-point name"],
        "transformation_or_control": ["LoadLibrary -> GetProcAddress"],
        "conditions": ["static evidence only"],
        "outputs": ["resolved function pointer"],
        "consumers": ["indirect call/jump consumer"],
        "side_effects": ["may hide imports"],
        "evidence_ids": ["e1", "e2"],
    }
    assert mechanism_completeness_score(mechanism) <= 60


@pytest.mark.parametrize(
    "claim_type,action",
    [
        ("FUNCTION_REVIEW_PRIORITY", "prioritizes"),
        ("CROSS_FUNCTION_MECHANISM", "exhibits_cross_function_chain"),
        ("FALLBACK_CODE_CALL_GRAPH", "contains_rva_level_call_sites"),
    ],
)
def test_navigation_claims_do_not_materialize_as_mechanism_candidates(
    claim_type: str,
    action: str,
) -> None:
    """Navigation Claims stay auditable without diluting mechanism closure."""
    claim = SimpleNamespace(
        id=f"c-{claim_type}",
        claim_type=claim_type,
        subject="sample.exe",
        action=action,
        object="function@0x1000",
        mechanism="xref/cfg prominence",
        condition="static evidence only",
        status="CANDIDATE",
    )
    evidence = {
        "e1": SimpleNamespace(id="e1", kind="function", value={"name": "f"})
    }
    assert build_mechanism_projections([claim], {claim.id: ["e1"]}, evidence) == []


def test_navigation_only_claim_is_not_a_core_finding() -> None:
    markdown = render_ledger_markdown(
        {
            "report_version": "3.0",
            "report_sections": [
                "Executive Assessment",
                "Artifact Summary",
                "Key Static Findings",
                "Verified Mechanisms",
                "Reconstructed Static Behavior Flow",
                "IOC / Indicators",
                "Detection / Hunting Opportunities",
                "ATT&CK Reference",
                "Unknowns / Static Boundaries",
                "Analysis Coverage",
            ],
            "case_id": "case-1",
            "task_id": "task-1",
            "analysis_outcome": "PARTIAL",
            "analysis_class": "BOUNDED_STATIC_ANALYSIS",
            "analysis_coverage": {"score": 50, "dimensions": {}},
            "modules": [
                {
                    "id": "executive_summary",
                    "rows": [
                        {
                            "type": "analytical_claim",
                            "claim_id": "c1",
                            "finding": "Prioritize function review at RVA 0x1000.",
                            "action": "contains_rva_level_call_sites",
                            "mechanism": "xref/cfg/instruction prominence",
                            "evidence_ids": ["e1"],
                            "confidence": "MEDIUM",
                        }
                    ],
                }
            ],
            "trace": {},
        }
    )
    assert "Prioritize function review" not in markdown


def test_semantic_coverage_is_required_for_full_classification() -> None:
    result = classify_artifact_result(
        "pe",
        tool_runs=[{"status": "SUCCEEDED"}],
        semantic_coverage={
            "verified_mechanism_coverage": 0.0,
            "relation_flow_coverage": 0.0,
        },
    )
    assert result is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS


def test_semantic_coverage_hard_caps_without_verified_mechanism_or_flow() -> None:
    coverage = analysis_coverage(
        artifact_parse=1.0,
        code_recovery=1.0,
        function_coverage=1.0,
        data_reference_coverage=1.0,
        mechanism_investigation=1.0,
        verifier_coverage=1.0,
        report_synthesis=1.0,
        verified_mechanism_coverage=0.0,
        relation_flow_coverage=0.0,
    )
    assert coverage["score"] <= 60.0


def test_verified_mechanism_coverage_is_not_inflated_by_artifact_count() -> None:
    mechanisms = [
        {
            "status": "VERIFIED",
            "target": "sample.exe",
            "inputs": ["config"],
            "transformation_or_control": ["decode"],
            "outputs": ["payload"],
            "consumers": ["loader"],
            "side_effects": ["prepares payload"],
            "evidence_ids": ["e1", "e2"],
            "verifier": {"status": "VERIFIED"},
        },
        {
            "status": "CANDIDATE",
            "target": "sample.exe",
            "inputs": ["UNKNOWN(input)"],
            "transformation_or_control": ["UNKNOWN(transformation_or_control)"],
            "outputs": ["UNKNOWN(output)"],
            "consumers": ["UNKNOWN(consumer)"],
            "side_effects": ["UNKNOWN(side_effect)"],
            "evidence_ids": ["e3"],
            "verifier": {"status": "CANDIDATE"},
        },
    ]
    metrics = mechanism_coverage_metrics(mechanisms)
    assert metrics["mechanism_count"] == 2
    assert metrics["verified_mechanism_count"] == 1
    assert metrics["verified_mechanism_coverage"] == 0.5


def test_empty_static_condition_is_not_semantic_mechanism_condition() -> None:
    assert mechanism_completeness_score({
        "target": "x", "inputs": ["buffer"],
        "transformation_or_control": ["xor decode"],
        "conditions": ["static evidence only"],
        "outputs": ["decoded buffer"], "consumers": ["LoadLibraryA"],
        "side_effects": ["prepares decoded payload"], "evidence_ids": ["e1", "e2"],
    }) == 90


def test_missing_external_component_is_a_structural_static_boundary() -> None:
    result = classify_artifact_result(
        "pe",
        tool_runs=[{"status": "SUCCEEDED"}],
        structural_limitations=["missing custom DLL trch-1.dll"],
        semantic_coverage={
            "verified_mechanism_coverage": 0.0,
            "relation_flow_coverage": 0.0,
        },
    )
    assert result is AnalysisResultClass.BOUNDED_STATIC_ANALYSIS


def test_model_runtime_assertion_is_rendered_as_static_conditional() -> None:
    markdown = render_ledger_markdown(
        {
            "report_version": "3.0",
            "report_sections": ["Executive Assessment", "Key Static Findings"],
            "case_id": "case-1",
            "task_id": "task-1",
            "analysis_outcome": "PARTIAL",
            "analysis_class": "BOUNDED_STATIC_ANALYSIS",
            "analysis_coverage": {"score": 40, "dimensions": {}},
            "modules": [
                {
                    "id": "executive_summary",
                    "rows": [
                        {
                            "type": "analyst_assessment",
                            "summary": "The sample connected to a remote endpoint.",
                            "findings": [],
                        }
                    ],
                }
            ],
            "trace": {},
        }
    )
    assert "connected to" not in markdown
    assert "would connect to" in markdown


def test_dynamic_resolution_playbook_wins_over_generic_plugin_noise() -> None:
    evidence = [
        {"kind": "mechanism_dynamic_resolution", "value": {"apis": ["LoadLibrary", "GetProcAddress"]}},
        {"kind": "function_context", "value": {"name": "FUN_00401750", "call_targets": [
            {"target_name": "LoadLibraryA", "type": "COMPUTED_CALL"},
            {"target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
            {"target_name": "FreeLibrary", "type": "COMPUTED_CALL"},
        ], "data_references": [
            {"target_name": "s_LPFilename"},
            {"target_name": "s_LPEntryName"},
            {"target_name": "plugin.dll"},
        ]}},
    ]
    assert MechanismPlaybookRegistry().best_match(evidence).id == "dynamic-api-resolution"


def test_dynamic_resolution_verifier_accepts_static_loader_consumer_chain() -> None:
    evidence = [
        {"id": "e1", "kind": "mechanism_dynamic_resolution", "value": {"apis": ["LoadLibrary", "GetProcAddress"]}, "anchor": {"function_entry": "00401750"}},
        {"id": "e2", "kind": "function_context", "value": {"name": "FUN_00401750", "call_targets": [
            {"target_name": "LoadLibraryA", "type": "COMPUTED_CALL"},
            {"target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
        ], "data_references": [{"target_name": "s_LPFilename"}, {"target_name": "s_LPEntryName"}]}, "anchor": {"function_entry": "00401750"}},
        {"id": "e3", "kind": "function_call", "value": {"api": "LoadLibraryA", "argument_trace": "static module-name data reference", "function": "FUN_00401750"}, "anchor": {"function_entry": "00401750"}},
        {"id": "e4", "kind": "function_call", "value": {"api": "GetProcAddress", "argument_trace": "static entry-name data reference", "function": "FUN_00401750"}, "anchor": {"function_entry": "00401750"}},
        {"id": "e5", "kind": "function_call", "value": {"api": "FreeLibrary", "consumer": "resolved module lifecycle", "function": "FUN_00401750"}, "anchor": {"function_entry": "00401750"}},
    ]
    result = verify_dynamic_api_mechanism(evidence)
    assert result.accepted is True
    assert result.status == "VERIFIED"


def test_dynamic_resolution_verifier_accepts_provenance_backed_link() -> None:
    """A derived link is usable only when its cited static rows are present."""
    evidence = [
        {
            "id": "resolver-context",
            "kind": "function_context",
            "value": {
                "name": "FUN_00402000",
                "entry": "00402000",
                "call_targets": [
                    {"target_name": "LoadLibraryA"},
                    {"target_name": "GetProcAddress"},
                ],
                "data_references": [{"target_name": "plugin.dll"}],
            },
            "anchor": {"function_entry": "00402000"},
        },
        {
            "id": "pointer-consumer",
            "kind": "indirect_function_pointer_link",
            "value": {
                "resolver": "GetProcAddress",
                "consumer": "CALL RAX",
                "indirect": True,
            },
            "anchor": {"function_entry": "00402000"},
        },
        {
            "id": "derived-link",
            "kind": "mechanism_dynamic_api_link",
            "nature": "STATIC_DERIVED",
            "value": {
                "apis": ["getprocaddress", "loadlibrarya"],
                "module": "dynamically loaded module",
                "function_pointer": "resolved function pointer",
                "consumer": ["indirect function-pointer consumer"],
                "source_evidence_ids": ["resolver-context", "pointer-consumer"],
            },
            "anchor": {"function_entry": "00402000"},
        },
    ]
    result = verify_dynamic_api_mechanism(evidence)
    assert result.accepted is True
    assert result.status == "VERIFIED"


def test_dynamic_resolution_link_without_bridge_is_not_self_authenticating() -> None:
    """A copied link label cannot satisfy the verifier without its sources."""
    result = verify_dynamic_api_mechanism(
        [
            {
                "id": "unbacked-link",
                "kind": "mechanism_dynamic_api_link",
                "value": {
                    "apis": ["getprocaddress", "loadlibrarya"],
                    "module": "dynamically loaded module",
                    "function_pointer": "resolved function pointer",
                    "consumer": ["indirect function-pointer consumer"],
                    "source_evidence_ids": ["missing-source"],
                },
                "anchor": {"function_entry": "00402000"},
            }
        ]
    )
    assert result.accepted is False


def test_verified_specialist_fields_are_not_overwritten_by_generic_projection() -> None:
    existing = {
        "claim_id": "c1",
        "status": "VERIFIED",
        "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        "target": "sample.exe",
        "inputs": ["module name and entry-point name data"],
        "transformation_or_control": ["LoadLibrary resolves the module; GetProcAddress resolves its entry point"],
        "conditions": ["static call/data-flow ordering is recovered; runtime reachability is not observed"],
        "outputs": ["resolved function address"],
        "consumers": ["resolved entry-point consumer"],
        "side_effects": ["loads a secondary module and prepares a resolved entry point"],
        "evidence_ids": ["e1", "e2"],
        "completeness": 100,
    }
    generic = {
        "claim_id": "c1",
        "status": "CANDIDATE",
        "target": "sample.exe",
        "inputs": ["UNKNOWN(input)"],
        "transformation_or_control": ["multiple independent static observations correlated by investigation actions"],
        "conditions": ["static evidence threshold satisfied; runtime execution not proven"],
        "outputs": ["ordered static behavior indicators"],
        "consumers": ["atoi"],
        "side_effects": ["UNKNOWN(side_effect)"],
        "evidence_ids": ["e3"],
        "completeness": 50,
    }
    merged = AnalysisService._merge_mechanism_projection(existing, generic)
    assert merged["status"] == "VERIFIED"
    assert merged["verifier"]["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
    assert merged["inputs"] == existing["inputs"]
    assert merged["transformation_or_control"] == existing["transformation_or_control"]
    assert merged["evidence_ids"] == existing["evidence_ids"]
    assert merged["completeness"] == 100


def test_nested_verified_flow_is_rendered_in_primary_report() -> None:
    markdown = render_ledger_markdown({
        "report_version": "3.0",
        "report_sections": ["Executive Assessment", "Key Static Findings", "Verified Mechanisms", "Reconstructed Static Behavior Flow"],
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "FULL_STATIC_ANALYSIS",
        "analysis_coverage": {"score": 90, "dimensions": {"verified_mechanism_coverage": 1.0}},
        "modules": [{"id": "executive_summary", "rows": [{
            "type": "analyst_assessment",
            "summary": "Static chain recovered.",
            "findings": [{
                "type": "mechanism_chain",
                "rendered": "input -> decode -> resolved entry point",
                "status": "confirmed",
            }],
        }]}],
    })
    assert "input -> decode -> resolved entry point" in markdown


def test_production_snapshot_with_unclosed_mechanisms_has_no_semantic_flow() -> None:
    markdown = render_ledger_markdown({
        "report_version": "3.0",
        "report_sections": ["Executive Assessment", "Reconstructed Static Behavior Flow"],
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"score": 60, "dimensions": {"verified_mechanism_coverage": 0.0}},
        "mechanisms": [],
        "modules": [{"id": "executive_summary", "rows": [{
            "type": "analyst_assessment",
            "summary": "Candidate API observations.",
            "findings": [{
                "type": "analytical_claim",
                "claim_id": "c1",
                "module": "loader",
                "action": "may_load_or_prepare_memory",
                "object": "secondary module",
                "statement": "Static loader candidate.",
                "evidence_ids": ["e1"],
            }],
        }]}],
    })
    assert "未恢复出有序的静态行为链" in markdown
