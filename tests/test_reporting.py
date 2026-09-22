from types import SimpleNamespace

from threat_report_agent.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    build_report_document,
    build_observed_mechanism_projections,
    build_decode_result_projections,
    document_to_markdown,
    markdown_to_docx,
    report_analytical_violations,
    report_one_round_readiness_violations,
    _build_assessment,
    _format_function_location,
    _select_mechanism_projections,
)


def test_function_location_does_not_repeat_an_existing_entry_suffix() -> None:
    assert _format_function_location("FUN_14000a2c0", "14000a2c0") == "FUN_14000a2c0@14000a2c0"
    assert _format_function_location("FUN_14000a2c0@14000a2c0@14000a2c0", "0x14000a2c0") == "FUN_14000a2c0@0x14000a2c0"
    assert _format_function_location("launch_stage", "0x401000") == "launch_stage@0x401000"
    assert _format_function_location(
        "FUN_fallback_region@0x7000@fallback_region@0x7000",
        "fallback_region@0x7000",
    ) == "FUN_fallback_region@0x7000"
    assert _format_function_location(
        "fallback_region@0x7000", "fallback_region@0x7000"
    ) == "fallback_region@0x7000"


def test_decode_projections_include_recovered_child_artifact() -> None:
    evidence = {
        "e-child": SimpleNamespace(
            id="e-child",
            artifact_id="artifact-parent",
            kind="decoded_artifact",
            nature="STATIC_DERIVED",
            value={
                "child_artifact_id": "child-1",
                "sha256": "ab" * 32,
                "size": 64,
                "source": "xor",
            },
            anchor={"type": "decoded_artifact"},
        )
    }
    rows = build_decode_result_projections(evidence)
    assert rows[0]["verification_status"] == "RECOVERED_CHILD"
    assert rows[0]["child_artifact_id"] == "child-1"
    assert rows[0]["sha256"] == "ab" * 32
    assert rows[0]["plaintext_recovered"] is False


def test_assessment_normalizes_preformatted_mechanism_locator_once() -> None:
    task = SimpleNamespace(id="task-locator", outcome="PARTIAL", limitations=[])
    mechanism = {
        "mechanism_id": "mechanism-locator",
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "status": "SUPPORTED",
        "target": "FUN_14000a2c0@14000a2c0@14000a2c0",
        "function": "FUN_14000a2c0@14000a2c0@14000a2c0",
        "function_entry": "0x14000a2c0",
        "inputs": ["module name"],
        "transformation_or_control": ["LoadLibrary -> GetProcAddress"],
        "conditions": ["static call path"],
        "outputs": ["resolved function pointer"],
        "consumers": ["indirect CALL"],
        "side_effects": ["may hide imports"],
        "evidence_ids": ["evidence-locator"],
        "verifier": {"status": "VERIFIED"},
    }
    summary, _ = _build_assessment(
        task=task,
        artifacts=[],
        claims=[],
        links_by_claim={},
        evidence_by_id={"evidence-locator": object()},
        model_calls=[],
        mechanisms=[mechanism],
        mechanism_projections=[],
    )

    assert "FUN_14000a2c0@0x14000a2c0@0x14000a2c0" not in summary
    assert "FUN_14000a2c0@0x14000a2c0" in summary


def test_v3_markdown_uses_semantic_flow_coverage_as_source_of_truth() -> None:
    markdown = document_to_markdown(
        {
            "report_version": "3.0",
            "report_sections": ["Executive Assessment"],
            "case_id": "case-flow",
            "task_id": "task-flow",
            "analysis_outcome": "PARTIAL",
            "analysis_class": "BOUNDED_STATIC_ANALYSIS",
            "analysis_coverage": {
                "semantic_flow_nodes": 4,
                "semantic_flow_edges": 3,
                "behavior_flow_present": True,
                "dimensions": {"relation_flow_coverage": 1.0},
            },
            "modules": [],
            "trace": {},
        }
    )
    assert "nodes=4, edges=3, present=True" in markdown


def test_report_analytical_gate_requires_verified_mechanism_provenance() -> None:
    invalid = {"modules": [{"rows": [{"type": "security_finding", "mechanism_id": "m1", "claim_id": "c1", "evidence_ids": ["e1"], "what": "x", "how": "y", "security_meaning": "z", "boundary": "static", "verifier": {"status": "CANDIDATE"}}]}]}
    assert any("not backed" in item for item in report_analytical_violations(invalid))
    valid = {"modules": [{"rows": [{"type": "security_finding", "mechanism_id": "m1", "claim_id": "c1", "evidence_ids": ["e1"], "what": "x", "how": "y", "security_meaning": "z", "boundary": "static", "verifier": {"status": "VERIFIED"}}]}]}
    assert report_analytical_violations(valid) == []


def test_report_projects_seed_map_evidence_from_any_module_and_renders_details() -> None:
    """The analyst view must retain the scheduler's question/provenance map."""
    evidence = SimpleNamespace(
        id="seed-map-1",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="investigation",
        kind="investigation_seed_map",
        nature="STATIC_INFERRED",
        value={
            "cluster_count": 2,
            "high_value_cluster_count": 1,
            "clusters": [{
                "id": "cluster-loader",
                "category": "loader",
                "priority": 90,
                "question": "Which module is resolved and where is the pointer consumed?",
                "hypotheses": [
                    "A dynamically resolved loader path exists.",
                    "The import is unused compatibility code.",
                ],
                "evidence_ids": ["e-api", "e-xref"],
            }],
        },
        anchor={"type": "investigation_seed_map"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-seed"),
        task=SimpleNamespace(
            id="task-seed", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], selected_modules=["static_triage"],
    )

    static_rows = document["modules"][0]["rows"]
    seed_row = next(row for row in static_rows if row.get("type") == "investigation_seed_map")
    assert seed_row["cluster_count"] == 2
    assert seed_row["clusters"][0]["question"].startswith("Which module")
    assert seed_row["clusters"][0]["hypotheses"]
    assert seed_row["clusters"][0]["evidence_ids"] == ["e-api", "e-xref"]

    markdown = document_to_markdown(document)
    assert "Investigation Seed Map" in markdown
    assert "2 clusters" in markdown
    assert "Which module is resolved" in markdown
    assert "competing hypotheses" in markdown
    assert "e-api" in markdown and "e-xref" in markdown


def test_report_renders_function_semantic_summary_as_analysis_not_field_dump() -> None:
    evidence = SimpleNamespace(
        id="semantic-1",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_INFERRED",
        value={
            "function": "launch_stage",
            "function_entry": "0x401000",
            "call_sequence": [{
                "api": "CreateProcessW",
                "callsite": "0x40100a",
                "category": "execution",
                "arguments": [{"argument_index": 1, "source_kind": "constant", "value": "0x08000000"}],
                "recovered_argument_count": 1,
            }],
            "inputs": [{"api": "CreateProcessW", "value": "0x08000000", "source_kind": "constant"}],
            "conditions": [{"address": "0x401012", "text": "JZ 0x401030"}],
            "consumers": [{"api": "ReadFile", "callsite": "0x401018", "role": "downstream_static_call"}],
            "recovered_argument_count": 1,
            "confidence": "HIGH",
            "unknowns": ["branch outcome is unobserved"],
            "boundary": "Static evidence only; runtime execution is unobserved.",
            "static_only": True,
        },
        anchor={"type": "function_semantic_summary", "function_entry": "0x401000"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-semantic"),
        task=SimpleNamespace(
            id="task-semantic", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], selected_modules=["static_triage"],
    )

    markdown = document_to_markdown(document)
    assert "Function-Level Semantic Recovery" in markdown
    assert "CreateProcessW @ 0x40100a [execution]" in markdown
    assert "0x08000000 [constant]" in markdown
    assert "branch outcome is unobserved" in markdown


def test_official_markdown_title_does_not_assume_malice() -> None:
    markdown = document_to_markdown({
        "report_version": "3.0",
        "report_sections": [],
        "case_id": "case-benign",
        "task_id": "task-benign",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [],
    })
    assert markdown.splitlines()[0] == "# 静态分析报告"
    assert "恶意样本" not in markdown.splitlines()[0]


def test_report_omits_navigation_call_noise_but_keeps_semantic_calls() -> None:
    markdown = document_to_markdown({
        "case_id": "case-call-noise",
        "task_id": "task-call-noise",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "function_semantic_summary",
                "function": "spawn_worker",
                "function_entry": "0x401000",
                "call_sequence": [
                    {"api": "LAB_401010", "category": "unclassified_call", "arguments": []},
                    {"api": "CreateProcessW", "category": "execution", "arguments": []},
                    {"api": "DAT_401020", "category": "unclassified_call", "arguments": []},
                ],
                "conditions": [],
                "consumers": [],
                "confidence": "MEDIUM",
                "unknowns": [],
                "boundary": "Static only",
            }],
        }],
    })

    assert "CreateProcessW @" in markdown
    assert "LAB_401010" not in markdown
    assert "DAT_401020" not in markdown
    assert "omitted_low_information_calls: 2" in markdown


def test_report_omits_legacy_label_calls_even_when_they_have_arguments() -> None:
    """Stale LAB/DAT rows cannot become visible calls through argument data."""
    markdown = document_to_markdown({
        "case_id": "case-call-label-args",
        "task_id": "task-call-label-args",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "function_semantic_summary",
                "function": "loader",
                "function_entry": "0x401000",
                "call_sequence": [
                    {
                        "api": "LAB_401010",
                        "category": "unclassified_call",
                        "arguments": [{"value": "0x1", "source_kind": "constant"}],
                    },
                    {
                        "api": "CreateProcessW",
                        "category": "execution",
                        "arguments": [],
                    },
                ],
                "conditions": [],
                "consumers": [],
                "confidence": "MEDIUM",
                "unknowns": [],
                "boundary": "Static only",
            }],
        }],
    })

    assert "CreateProcessW @" in markdown
    assert "LAB_401010" not in markdown
    assert "omitted_low_information_calls: 1" in markdown


def test_report_omits_unresolved_internal_targets_but_keeps_parameter_clues() -> None:
    """Unresolved internal dispatch labels stay in the ledger, not call lists."""
    markdown = document_to_markdown({
        "case_id": "case-internal-targets",
        "task_id": "task-internal-targets",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "function_semantic_summary",
                "function": "loader",
                "function_entry": "0x401000",
                "call_sequence": [
                    {
                        "api": "FUN_401100",
                        "category": "unclassified_call",
                        "arguments": [{
                            "argument_index": 0,
                            "value": "0x401200",
                            "source_kind": "constant",
                        }],
                    },
                    {
                        "api": "PTR_FUN_402000",
                        "category": "unclassified_call",
                        "arguments": [],
                    },
                    {
                        "api": "PTR_PTR_403000",
                        "category": "unclassified_call",
                        "arguments": [{
                            "argument_index": 1,
                            "value": "cmd.exe",
                            "source_kind": "string",
                        }],
                    },
                    {
                        "api": "CreateProcessW",
                        "category": "execution",
                        "arguments": [],
                    },
                ],
                "conditions": [],
                "consumers": [],
                "confidence": "MEDIUM",
                "unknowns": [],
                "boundary": "Static only",
            }],
        }],
    })

    assert "CreateProcessW @" in markdown
    assert "FUN_401100" not in markdown
    assert "PTR_FUN_402000" not in markdown
    assert "PTR_PTR_403000" not in markdown
    assert "omitted_unresolved_internal_calls: 3" in markdown
    assert '"0x401200" [constant]' in markdown
    assert '"cmd.exe" [string]' in markdown


def test_report_deduplicates_api_aliases_at_same_callsite() -> None:
    """Imported and pointer/case aliases describe one static callsite."""
    markdown = document_to_markdown({
        "case_id": "case-api-aliases",
        "task_id": "task-api-aliases",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "function_semantic_summary",
                "function": "loader",
                "function_entry": "0x401000",
                "call_sequence": [
                    {"api": "virtualquery", "callsite": "0x401020", "category": "environment_query", "arguments": []},
                    {"api": "VirtualQuery", "callsite": "0x401020", "category": "environment_query", "arguments": []},
                    {"api": "VirtualQuery", "callsite": "0x401030", "category": "environment_query", "arguments": []},
                ],
                "conditions": [], "consumers": [], "confidence": "HIGH", "unknowns": [],
                "boundary": "Static evidence only",
            }],
        }],
    })

    assert markdown.count("VirtualQuery @ 0x401020") == 1
    assert markdown.count("VirtualQuery @ 0x401030") == 1
    assert "virtualquery @ 0x401020" not in markdown


def test_report_compacts_unresolved_register_arguments_and_keeps_recovered_values() -> None:
    """Unknown ABI slots are summarized instead of rendered as field noise."""
    markdown = document_to_markdown({
        "case_id": "case-unknown-args",
        "task_id": "task-unknown-args",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [
                {
                    "type": "api_argument_recovery",
                    "evidence_id": "trace-unknown",
                    "api": "CreateProcessW",
                    "function": "spawn_worker",
                    "function_entry": "0x401000",
                    "callsite": "0x401020",
                    "recovered_argument_count": 1,
                        "arguments": [
                            {"index": 0, "register": "RBX", "value": "RBX", "source_kind": "unknown"},
                            {"index": 1, "register": "RBP", "value": "RBP", "source_kind": "unknown"},
                            {"index": 2, "register": "RDI", "value": "RBX/RBP/RDI/RSI", "source_kind": "register_or_expression"},
                            {"index": 3, "register": "RCX", "value": "cmd.exe", "source_kind": "string"},
                    ],
                },
                {
                    "type": "function_semantic_summary",
                    "evidence_id": "summary-unknown",
                    "function": "spawn_worker",
                    "function_entry": "0x401000",
                    "recovered_argument_count": 1,
                    "call_sequence": [{
                        "api": "CreateProcessW",
                        "callsite": "0x401020",
                        "category": "execution",
                            "arguments": [
                                {"argument_index": 0, "register": "RBX", "value": "RBX", "source_kind": "unknown"},
                                {"argument_index": 1, "register": "RBP", "value": "RBP", "source_kind": "unknown"},
                            {"argument_index": 2, "register": "RDI", "value": "RBX/RBP/RDI/RSI", "source_kind": "register_or_expression"},
                            {"argument_index": 3, "register": "RCX", "value": "cmd.exe", "source_kind": "string"},
                        ],
                    }],
                },
            ],
        }],
        "trace": {},
    })

    assert "arg0 (RBX): RBX [unknown]" not in markdown
    assert "arg1 (RBP): RBP [unknown]" not in markdown
    assert "arg0: RBX [unknown]" not in markdown
    assert "arg1: RBP [unknown]" not in markdown
    assert "unresolved_argument_slots: 3" in markdown
    assert "unresolved argument slots: 3" in markdown
    assert 'arg3 (RCX): "cmd.exe" [string]' in markdown
    assert 'arg3: "cmd.exe" [string]' in markdown


def test_report_compacts_unresolved_register_slots_in_v3_projection() -> None:
    """Unknown ABI placeholders must not drown out recovered call evidence."""
    document = {
        "report_version": "3.0",
        "report_sections": ["static_triage"],
        "modules": [{
            "id": "static_triage",
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "function_semantic_summary",
                "evidence_id": "semantic-noise",
                "function": "FUN_14000a2c0",
                "function_entry": "0xA2C0",
                "confidence": "MEDIUM",
                "recovered_argument_count": 1,
                "call_sequence": [{
                    "api": "CreateProcessW",
                    "callsite": "0xAEEC",
                    "category": "execution",
                    "arguments": [
                        {"argument_index": 0, "register": "RCX", "value": "RBX", "source_kind": "unknown"},
                        {"argument_index": 1, "register": "RDX", "value": "0x08000000", "source_kind": "constant"},
                        {"argument_index": 2, "register": "R8", "value": None, "source_kind": "unknown"},
                    ],
                }],
                "conditions": [],
                "consumers": [],
                "unknowns": [],
                "boundary": "Static evidence only.",
            }],
        }],
    }

    markdown = document_to_markdown(document)

    assert "0x08000000 [constant]" in markdown
    assert "unresolved argument slots: 2" in markdown
    assert "arg0: RBX [unknown]" not in markdown
    assert "arg2: None [unknown]" not in markdown


def test_legacy_report_compacts_unresolved_argument_rows() -> None:
    document = {
        "case_id": "case-legacy",
        "task_id": "task-legacy",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [{
            "title": "Static Triage",
            "summary": "",
            "rows": [{
                "type": "api_argument_recovery",
                "evidence_id": "trace-legacy",
                "api": "OpenProcess",
                "function": "FUN_1000",
                "function_entry": "0x1000",
                "callsite": "0x1010",
                "consumer": "UpdateProcThreadAttribute",
                "recovered_argument_count": 1,
                "arguments": [
                    {"index": 0, "register": "RBX", "value": "RBX", "source_kind": "unknown"},
                    {"index": 1, "register": "RDX", "value": "0x80000", "source_kind": "constant"},
                ],
            }],
        }],
    }

    markdown = document_to_markdown(document)

    assert "0x80000" in markdown and "[constant]" in markdown
    assert "- unresolved_argument_slots: 1" in markdown
    assert "arg0 (RBX): RBX [unknown]" not in markdown


def test_verified_mechanism_is_projected_as_security_finding() -> None:
    claim = SimpleNamespace(id="c1", statement="ETW is patched", mechanism="VirtualProtect -> write")
    evidence = {"e1": SimpleNamespace(id="e1", value="patch", kind="patch_bytes", anchor={})}
    from threat_report_agent.reporting import build_verified_security_findings
    findings = build_verified_security_findings(
        [{"id": "m1", "status": "VERIFIED", "claim_id": "c1", "evidence_ids": ["e1"], "target": "EtwEventWrite", "verifier": {"status": "VERIFIED"}}],
        [claim], evidence,
    )
    assert findings[0]["critical"] is True
    assert findings[0]["mechanism_id"] == "m1"


def test_verified_deduplicated_mechanism_uses_claim_ids_and_preserves_shape() -> None:
    from threat_report_agent.reporting import build_verified_security_findings

    claim = SimpleNamespace(
        id="c2",
        statement="A resolved API pointer reaches a memory permission change.",
        mechanism="resolver -> function pointer -> VirtualProtect",
        module="loader",
        confidence="HIGH",
    )
    evidence = {"e2": SimpleNamespace(id="e2", value={"api": "VirtualProtect"}, kind="function_call", anchor={})}
    findings = build_verified_security_findings(
        [{
            "id": "m2",
            "status": "VERIFIED",
            "claim_id": None,
            "claim_ids": ["c2"],
            "evidence_ids": ["e2"],
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "target": "sample!FUN_1000",
            "inputs": ["module name"],
            "transformation_or_control": ["LoadLibrary -> GetProcAddress"],
            "conditions": ["static path"],
            "outputs": ["function pointer"],
            "consumers": ["VirtualProtect"],
            "side_effects": ["prepares resolved call"],
            "completeness": 100,
            "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        }],
        [claim],
        evidence,
    )
    assert len(findings) == 1
    assert findings[0]["claim_id"] == "c2"
    assert findings[0]["claim_ids"] == ["c2"]
    assert findings[0]["inputs"] == ["module name"]
    assert findings[0]["consumers"] == ["VirtualProtect"]


def test_verified_static_mechanism_prioritizes_attack_mapping_and_hunting() -> None:
    claim = SimpleNamespace(
        id="static-link-claim",
        module="investigation",
        claim_type="STATIC_MECHANISM_LINK",
        subject="sample.exe",
        action="resolves_dynamic_api",
        object="resolved API entry point",
        mechanism="LoadLibrary/GetProcAddress -> function pointer -> VirtualProtect",
        condition="specialist static verifier accepted the evidence path",
        statement="Static analysis recovered a verified dynamic API resolution mechanism.",
        nature="STATIC_INFERRED",
        status="SUPPORTED",
        confidence="MEDIUM",
        attack_mapping={
            "status": "candidate",
            "mappings": [{
                "technique_id": "T1027.007",
                "technique_name": "Obfuscated Files or Information: Dynamic API Resolution",
                "status": "candidate",
            }],
        },
        model_call_id=None,
    )
    evidence = SimpleNamespace(
        id="static-link-evidence",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="investigation",
        kind="mechanism_dynamic_api_link",
        nature="STATIC_DERIVED",
        value={"relationship": "LoadLibrary/GetProcAddress -> function pointer -> VirtualProtect"},
        anchor={"function_entry": "0x1000"},
    )
    mechanism = {
        "id": "verified-static-link",
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "status": "VERIFIED",
        "claim_id": claim.id,
        "claim_ids": [claim.id],
        "target": "sample.exe",
        "inputs": ["module name and entry-point name data"],
        "transformation_or_control": ["LoadLibrary/GetProcAddress -> function pointer -> VirtualProtect"],
        "conditions": ["static linked evidence only; runtime reachability is unobserved"],
        "outputs": ["resolved function pointer"],
        "consumers": ["VirtualProtect"],
        "side_effects": ["prepares a resolved API entry point"],
        "evidence_ids": [evidence.id],
        "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
    }
    document = build_report_document(
        case=SimpleNamespace(id="case-static-link"),
        task=SimpleNamespace(
            id="task-static-link", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only analysis"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id=claim.id, evidence_id=evidence.id, stance="SUPPORTS")],
        relations=[], gates=[], mechanisms=[mechanism],
        selected_modules=["behavior_attack", "c2_network"],
    )
    modules = {item["id"]: item for item in document["modules"]}
    behavior_rows = modules["behavior_attack"]["rows"]
    claim_row = next(row for row in behavior_rows if row.get("claim_id") == claim.id)
    assert claim_row["attack_techniques"][0]["technique_id"] == "T1027.007"
    assert any(row.get("type") == "security_finding" for row in behavior_rows)
    hunting = modules["c2_network"]["rows"]
    assert any("indirect module/API resolution" in row.get("statement", "") for row in hunting)


def test_equivalent_verified_mechanisms_merge_hunting_guidance() -> None:
    claim = SimpleNamespace(
        id="resolver-claim",
        module="investigation",
        claim_type="STATIC_MECHANISM_LINK",
        subject="sample.exe",
        action="resolves_dynamic_api",
        object="resolved entry point",
        mechanism="LoadLibrary -> GetProcAddress -> consumer",
        condition="static-only",
        statement="Static resolver path recovered.",
        nature="STATIC_INFERRED",
        status="SUPPORTED",
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
    )
    evidence = SimpleNamespace(
        id="resolver-evidence",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="investigation",
        kind="mechanism_dynamic_api_link",
        nature="STATIC_DERIVED",
        value={},
        anchor={},
    )
    mechanism = {
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "status": "VERIFIED",
        "claim_id": claim.id,
        "target": "sample.exe",
        "inputs": ["module and export data"],
        "transformation_or_control": ["LoadLibrary -> GetProcAddress -> consumer"],
        "conditions": ["static linked evidence"],
        "outputs": ["function pointer"],
        "consumers": ["consumer"],
        "side_effects": ["indirect API use"],
        "evidence_ids": [evidence.id],
        "completeness": 100,
        "verifier": {"status": "VERIFIED"},
    }
    document = build_report_document(
        case=SimpleNamespace(id="case-duplicate-hunt"),
        task=SimpleNamespace(
            id="task-duplicate-hunt", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only analysis"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id=claim.id, evidence_id=evidence.id, stance="SUPPORTS")],
        relations=[], gates=[], mechanisms=[
            {**mechanism, "id": "resolver-a"},
            {**mechanism, "id": "resolver-b"},
        ],
        selected_modules=["c2_network"],
    )
    hunting = [
        row for row in document["modules"][0]["rows"]
        if row.get("type") == "hunting_opportunity"
    ]
    assert len(hunting) == 1
    assert "indirect module/API resolution" in hunting[0]["statement"]


def test_claim_is_materialized_as_structured_candidate_mechanism() -> None:
    from threat_report_agent.reporting import build_mechanism_projections

    claim = SimpleNamespace(
        id="c-mech", module="loader", subject="sample.exe",
        action="may_load_or_prepare_memory", object="secondary payload",
        mechanism="resource -> decode -> VirtualAlloc", condition="static evidence only",
        status="CANDIDATE",
    )
    evidence = {
        "e1": SimpleNamespace(id="e1", kind="mechanism_resource_payload", value={"text": "encoded resource payload"}),
        "e2": SimpleNamespace(id="e2", kind="function_call", value={"api": "VirtualAlloc"}),
    }
    rows = build_mechanism_projections([claim], {"c-mech": ["e1", "e2"]}, evidence)
    assert rows[0]["status"] == "CANDIDATE"
    assert rows[0]["inputs"]
    assert rows[0]["transformation_or_control"]
    assert rows[0]["outputs"] == ["secondary payload"]
    assert rows[0]["evidence_ids"] == ["e1", "e2"]


def test_large_evidence_sets_keep_full_trace_with_bounded_report_rows() -> None:
    evidence = [
        SimpleNamespace(
            id=f"evidence-{index}",
            artifact_id="artifact-1",
            tool_run_id="tool-run-1",
            module="static_triage",
            kind="cfg_block",
            nature="STATIC_OBSERVED",
            value={"payload": "x" * 2_000},
            anchor={"block": index},
        )
        for index in range(1_000)
    ]
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="COMPLETE",
            target_breadth="B0",
            target_depth="D2",
            actual_granularity={},
            request_snapshot={},
            limitations=[],
        ),
        artifacts=[],
        tool_runs=[],
        evidence=evidence,
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        selected_modules=["static_triage", "evidence_ledger"],
    )

    modules = {item["id"]: item for item in document["modules"]}
    assert len(modules["static_triage"]["rows"]) == 1
    assert len(modules["evidence_ledger"]["rows"]) == 1
    assert modules["evidence_ledger"]["rows"][0]["count"] == 1_000
    assert len(document["trace"]["evidence_ids"]) == 1_000

    markdown = document_to_markdown(document)
    assert len(markdown) < 100_000
    assert markdown_to_docx(markdown).startswith(b"PK")


def test_report_puts_evidence_backed_assessment_before_raw_evidence() -> None:
    claim = SimpleNamespace(
        id="claim-1",
        module="loader",
        statement="sample references VirtualAlloc and LoadLibrary consistently with a loader.",
        subject="sample.exe",
        action="may_load_or_inject",
        object="secondary component",
        mechanism="memory-management and loader APIs",
        condition="static evidence only",
        status="CANDIDATE",
        confidence="MEDIUM",
        attack_mapping={"technique_id": "T1055"},
        model_call_id=None,
    )
    evidence = SimpleNamespace(
        id="evidence-1",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="loader_indicator",
        nature="STATIC_OBSERVED",
        value={"name": "VirtualAlloc"},
        anchor={"offset": 10},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D2", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="sha256",
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )], tool_runs=[],
        evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id="claim-1", evidence_id="evidence-1", stance="SUPPORTS")],
        relations=[], gates=[], model_calls=[], selected_modules=["executive_summary", "static_triage"],
    )
    modules = {item["id"]: item for item in document["modules"]}
    summary_row = modules["executive_summary"]["rows"][0]
    assert summary_row["type"] == "analyst_assessment"
    assert summary_row["findings"][1]["finding"].startswith("sample references")
    assert summary_row["findings"][1]["evidence_samples"][0]["value"] == {"name": "VirtualAlloc"}
    assert modules["static_triage"]["rows"][0]["type"] == "analytical_claim"
    markdown = document_to_markdown(document)
    assert "Static assessment:" in markdown
    assert "sample references VirtualAlloc" in markdown


def test_report_assessment_exposes_mechanism_chain_before_evidence_ledger() -> None:
    claims = []
    evidence = []
    links = []
    for index, (module, action, object_name, mechanism) in enumerate(
        (
            ("decryption", "may_decode_or_decrypt", "embedded resource", "resource -> decompression"),
            ("loader", "may_load_or_prepare_memory", "secondary component", "extract -> resolve -> prepare memory"),
            ("anti_analysis", "may_detect_analysis", "service state", "environment/service checks"),
        ),
        start=1,
    ):
        claim_id = f"claim-{index}"
        evidence_id = f"evidence-{index}"
        claims.append(
            SimpleNamespace(
                id=claim_id,
                module=module,
                statement=f"sample {action} {object_name}",
                subject="sample.exe",
                action=action,
                object=object_name,
                mechanism=mechanism,
                condition="static only",
                status="CANDIDATE",
                confidence="HIGH",
                attack_mapping={},
                model_call_id=None,
            )
        )
        evidence.append(
            SimpleNamespace(
                id=evidence_id,
                artifact_id="artifact-1",
                tool_run_id="tool-1",
                module=module,
                kind=f"mechanism_{module}",
                nature="STATIC_OBSERVED",
                value={"module": module},
                anchor={"type": "test"},
            )
        )
        links.append(SimpleNamespace(claim_id=claim_id, evidence_id=evidence_id, stance="SUPPORTS"))

    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="sha256",
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=evidence, claims=claims, claim_evidence=links,
        relations=[], gates=[], model_calls=[], selected_modules=["executive_summary"],
    )

    findings = document["modules"][0]["rows"][0]["findings"]
    chain = next(item for item in findings if item.get("type") == "mechanism_chain")
    assert chain["status"] == "inferred"
    assert chain["rendered"] == (
        "resource -> decompress/decode/integrity-check -> "
        "extract/resolve payload -> prepare memory -> check environment/service state"
    )


def test_report_keeps_specialist_link_visible_ahead_of_generic_candidates() -> None:
    source = SimpleNamespace(
        id="source-resolver",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"target_function": "GetProcAddress"},
        anchor={"function_entry": "0x1000"},
    )
    link = SimpleNamespace(
        id="link-resolver",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="investigation",
        kind="mechanism_dynamic_api_link",
        nature="STATIC_DERIVED",
        value={
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "resolver": ["getprocaddress"],
            "consumer": ["winhttpopen"],
            "module": "winhttp.dll",
            "function_pointer": "resolved pointer",
            "relationship": "resolver -> consumer",
            "source_evidence_ids": ["source-resolver"],
        },
        anchor={"type": "static_mechanism_link"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="sha256",
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[source, link], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], mechanisms=[],
        selected_modules=["behavior_attack"],
    )
    rows = document["modules"][0]["rows"]
    specialist = next(row for row in rows if row.get("type") == "mechanism_link")
    assert specialist["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
    assert specialist["status"] == "CANDIDATE"
    assert specialist["evidence_ids"] == ["link-resolver", "source-resolver"]


def test_static_link_projection_recovers_function_and_resolver_consumer_callsites() -> None:
    """Cross-function links retain the anchors needed for an analyst-grade HOW."""
    from threat_report_agent.reporting import build_static_link_mechanism_projections

    pointer = SimpleNamespace(
        id="pointer-1", artifact_id="artifact-1", kind="indirect_function_pointer_link",
        nature="STATIC_OBSERVED", module="loader",
        value={
            "resolver": "GetProcAddress",
            "resolver_callsite": "14000aeec",
            "consumer_callsite": "14000aefe",
            "consumer": "CALL R12",
            "storage": "RSP + 0x70",
        },
        anchor={"type": "indirect_function_pointer", "function_entry": "14000a2c0", "rva": 41664},
    )
    link = SimpleNamespace(
        id="link-1", artifact_id="artifact-1", kind="mechanism_dynamic_api_link",
        nature="STATIC_DERIVED", module="investigation",
        value={
            "resolver": ["getprocaddress"],
            "consumer": ["indirect function-pointer consumer"],
            "relationship": "LoadLibrary/GetProcAddress -> function pointer -> consumer",
            "source_evidence_ids": ["pointer-1"],
        },
        anchor={"type": "static_mechanism_link", "function_entry": "14000a2c0"},
    )

    rows = build_static_link_mechanism_projections({"link-1": link, "pointer-1": pointer})
    row = rows[0]
    assert row["function_entry"] == "14000a2c0"
    assert row["rva"] == 41664
    assert row["target"] == "FUN_14000a2c0@14000a2c0"
    assert row["resolver_callsites"] == ["14000aeec"]
    assert row["consumer_callsites"] == ["14000aefe"]
    assert "resolver callsite=14000aeec" in row["transformation_or_control"]
    assert "consumer callsite=14000aefe" in row["transformation_or_control"]


def test_static_link_projection_keeps_transport_shell_and_patch_callsite_maps() -> None:
    """C2-C4 derived links expose their typed call sequence in the report."""
    from threat_report_agent.reporting import build_static_link_mechanism_projections

    cases = (
        (
            "mechanism_http_transport_link", "HTTP_DOWNLOAD", "0x1100", 4352,
            ("WinHttpOpen", "WinHttpSendRequest", "WinHttpReceiveResponse"),
        ),
        (
            "mechanism_shell_output_link", "SHELL_OUTPUT", "0x2200", 8704,
            ("CreateProcessW", "CreatePipe", "ReadFile"),
        ),
        (
            "mechanism_etw_patch_link", "ETW_PATCH", "0x3300", 13056,
            ("EtwEventWrite", "VirtualProtect", "FlushInstructionCache"),
        ),
    )
    evidence: dict[str, object] = {}
    for index, (kind, mechanism_type, entry, rva, apis) in enumerate(cases, start=1):
        source_id = f"source-{index}"
        link_id = f"link-{index}"
        evidence[source_id] = SimpleNamespace(
            id=source_id, artifact_id="artifact-1", kind="function_context",
            nature="STATIC_OBSERVED", module="static_triage",
            value={
                "name": f"FUN_{entry}", "entry": entry, "entry_rva": rva,
                "call_targets": [
                    {"target_name": api, "from": f"{int(entry, 16) + offset:x}"}
                    for offset, api in enumerate(apis, start=1)
                ],
            },
            anchor={"type": "function_context", "function_entry": entry, "rva": rva},
        )
        evidence[link_id] = SimpleNamespace(
            id=link_id, artifact_id="artifact-1", kind=kind,
            nature="STATIC_DERIVED", module="investigation",
            value={
                "apis": list(apis),
                "relationship": " -> ".join(apis),
                "source_evidence_ids": [source_id],
                **({"entry": "EtwEventWrite", "condition": "VirtualProtect", "patch_bytes": "33 C0 C3", "flush": "FlushInstructionCache"} if mechanism_type == "ETW_PATCH" else {}),
            },
            anchor={"type": "static_mechanism_link", "function_entry": entry},
        )

    rows = build_static_link_mechanism_projections(evidence)
    assert {row["mechanism_type"] for row in rows} == {item[1] for item in cases}
    for row in rows:
        assert row["function_entry"]
        assert row["rva"]
        assert row["target"].startswith("FUN_")
        assert any(item.startswith("static callsites=") for item in row["transformation_or_control"])


def test_report_projects_observed_static_chains_into_analyst_mechanisms() -> None:
    """High-value observed chains must be readable even when no Claim is closed."""
    from threat_report_agent.reporting import build_report_document

    evidence = [
        SimpleNamespace(
            id="chain-1", artifact_id="artifact-1", tool_run_id="ghidra-1",
            module="static_triage", kind="mechanism_chain", nature="STATIC_OBSERVED",
            value={
                "chain_type": "dynamic_loader", "function": "FUN_14000a2c0",
                "entry": "14000a2c0", "entry_rva": 41664,
                "steps": [
                    {"category": "file_io", "name": "CreateFileA", "address": "14000adff"},
                    {"category": "file_io", "name": "WriteFile", "address": "14000ae37"},
                    {"category": "dynamic_resolution", "name": "LoadLibraryA", "address": "14000ae5b"},
                    {"category": "dynamic_resolution", "name": "GetProcAddress", "address": "14000aead"},
                    {"category": "file_io", "name": "DeleteFileA", "address": "14000afe2"},
                ],
                "static_only": True,
            },
            anchor={"type": "function_mechanism_chain", "function_entry": "14000a2c0", "rva": 41664},
        ),
        SimpleNamespace(
            id="decode-1", artifact_id="artifact-1", tool_run_id="ghidra-1",
            module="static_triage", kind="mechanism_decode_window", nature="STATIC_OBSERVED",
            value={
                "algorithm": "xor_loop_candidate", "confidence": "MEDIUM",
                "xor_count": 24, "loop_branch_count": 64,
                "key_candidates": [14, 1073741824], "counter_initial": 8,
                "counter_step": 248,
                "semantic_requirements": {"input_output_buffers": True, "consumer": False},
                "verification": "structural_only; decoded output not observed",
            },
            anchor={"type": "function_instruction_window", "function_entry": "14000a2c0", "rva": 41664},
        ),
    ]
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="ComHost.exe.VIR", content_sha256="sha",
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED", parent_artifact_id=None,
        )],
        tool_runs=[], evidence=evidence, claims=[], claim_evidence=[], relations=[], gates=[],
        mechanisms=[], selected_modules=["executive_summary", "behavior_attack"],
    )
    rows = [
        row for module in document["modules"] for row in module["rows"]
        if row.get("type") == "mechanism_observation"
    ]
    assert len(rows) == 2
    chain = next(row for row in rows if row["mechanism_type"] == "DYNAMIC_LOADER")
    assert chain["function"] == "FUN_14000a2c0"
    assert "CreateFileA" in chain["transformation_or_control"][0]
    assert "GetProcAddress" in chain["transformation_or_control"][0]
    assert chain["status"] == "CANDIDATE"
    markdown = document_to_markdown(document)
    assert "FUN_14000a2c0" in markdown
    assert "xor_loop_candidate" in markdown
    assert "decoded output not observed" in markdown


def test_verified_specialist_suppresses_duplicate_observation_for_same_artifact() -> None:
    """Only an exact, fully closed evidence path is suppressed from the body."""
    def evidence(
        evidence_id: str,
        artifact_id: str,
        kind: str,
        *,
        function_entry: str = "0x1000",
        resolver_callsite: str | None = None,
    ) -> SimpleNamespace:
        value = (
            {"apis": ["LoadLibraryA", "GetProcAddress"]}
            if kind == "mechanism_dynamic_resolution"
            else {"algorithm": "xor_loop_candidate"}
        )
        if resolver_callsite:
            value["resolver_callsite"] = resolver_callsite
        return SimpleNamespace(
            id=evidence_id,
            artifact_id=artifact_id,
            tool_run_id="tool-1",
            module="loader",
            kind=kind,
            nature="STATIC_OBSERVED",
            value=value,
            anchor={"function_entry": function_entry},
        )

    verified_edge = evidence("verified-edge", "artifact-1", "function_call")
    duplicate = evidence(
        "duplicate-dynamic", "artifact-1", "mechanism_dynamic_resolution",
        resolver_callsite="0x1010",
    )
    different_function = evidence(
        "other-function-dynamic", "artifact-1", "mechanism_dynamic_resolution",
        function_entry="0x2000", resolver_callsite="0x2010",
    )
    different_artifact = evidence(
        "other-artifact-dynamic", "artifact-2", "mechanism_dynamic_resolution",
    )
    different_type = evidence("different-type", "artifact-1", "mechanism_decode_window")
    document = build_report_document(
        case=SimpleNamespace(id="case-suppression"),
        task=SimpleNamespace(
            id="task-suppression", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[], tool_runs=[],
        evidence=[
            verified_edge, duplicate, different_function,
            different_artifact, different_type,
        ],
        claims=[], claim_evidence=[], relations=[], gates=[],
        mechanisms=[{
            "id": "verified-dynamic",
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "status": "VERIFIED",
            "artifact_id": "artifact-1",
            "evidence_ids": ["verified-edge", "duplicate-dynamic"],
            "target": "sample.exe!FUN_1000",
            "inputs": ["module and exported entry-point name"],
            "transformation_or_control": ["LoadLibraryA -> GetProcAddress -> indirect consumer"],
            "conditions": ["static evidence path"],
            "outputs": ["resolved function pointer"],
            "consumers": ["indirect API consumer"],
            "side_effects": ["prepares an indirect API dispatch"],
            "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        }],
        selected_modules=["behavior_attack", "evidence_ledger"],
    )

    behavior_rows = document["modules"][0]["rows"]
    observation_ids = {
        row["mechanism_id"]
        for row in behavior_rows
        if row.get("type") == "mechanism_observation"
    }
    assert "observed-mechanism:duplicate-dynamic" not in observation_ids
    assert "observed-mechanism:other-function-dynamic" in observation_ids
    assert "observed-mechanism:other-artifact-dynamic" in observation_ids
    assert "observed-mechanism:different-type" in observation_ids

    # Suppression is an analyst-view projection only; the immutable ledger
    # must still retain every source evidence row for replay and audit.
    ledger_rows = document["modules"][1]["rows"]
    ledger_evidence_ids = {
        evidence_id
        for row in ledger_rows
        if row.get("type") == "evidence_group"
        for evidence_id in row.get("evidence_ids", [])
    }
    assert {
        "verified-edge", "duplicate-dynamic", "other-function-dynamic",
        "other-artifact-dynamic", "different-type",
    } <= ledger_evidence_ids
    suppressed = document["trace"]["suppressed_mechanism_projections"]
    assert len(suppressed) == 1
    assert suppressed[0]["projection_id"] == "observed-mechanism:duplicate-dynamic"
    assert suppressed[0]["suppressed_by_mechanism_id"] == "verified-dynamic"
    assert suppressed[0]["evidence_ids"] == ["duplicate-dynamic"]


def test_specialist_suppression_requires_complete_verifier_and_exact_evidence() -> None:
    """Incomplete/shared-path records must never hide independent observations."""
    def row(evidence_id: str, function_entry: str, *, callsite: str) -> SimpleNamespace:
        return SimpleNamespace(
            id=evidence_id,
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="loader",
            kind="mechanism_dynamic_resolution",
            nature="STATIC_OBSERVED",
            value={
                "apis": ["LoadLibraryA", "GetProcAddress"],
                "resolver_callsite": callsite,
            },
            anchor={"function_entry": function_entry},
        )

    evidence = [
        row("candidate-a", "0x3000", callsite="0x3010"),
        row("candidate-b", "0x4000", callsite="0x4010"),
    ]
    # Same type/artifact and a shared source ID is insufficient; the
    # mechanism is incomplete and cannot act as a suppressor.
    incomplete = {
        "id": "incomplete",
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "status": "VERIFIED",
        "artifact_id": "artifact-1",
        "evidence_ids": ["candidate-a", "candidate-b"],
        "target": "sample.exe",
        "inputs": ["module"],
        "transformation_or_control": ["resolver"],
        "conditions": ["static path"],
        "outputs": ["pointer"],
        "consumers": ["indirect call"],
        # Missing side_effects keeps mechanism_is_critical_ready false.
        "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
    }
    document = build_report_document(
        case=SimpleNamespace(id="case-incomplete-suppression"),
        task=SimpleNamespace(
            id="task-incomplete-suppression", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[], tool_runs=[], evidence=evidence, claims=[], claim_evidence=[],
        relations=[], gates=[], mechanisms=[incomplete],
        selected_modules=["behavior_attack"],
    )
    visible = [
        item for item in document["modules"][0]["rows"]
        if item.get("type") == "mechanism_observation"
    ]
    assert {item["mechanism_id"] for item in visible} == {
        "observed-mechanism:candidate-a", "observed-mechanism:candidate-b",
    }
    assert document["trace"]["suppressed_mechanism_projections"] == []


def test_specialist_suppression_rejects_cross_artifact_and_non_static_evidence() -> None:
    """A suppressor must be fully backed by same-artifact static Evidence."""
    def evidence(evidence_id: str, artifact_id: str, nature: str) -> SimpleNamespace:
        return SimpleNamespace(
            id=evidence_id,
            artifact_id=artifact_id,
            tool_run_id="tool-1",
            module="loader",
            kind="mechanism_dynamic_resolution",
            nature=nature,
            value={"apis": ["LoadLibraryA", "GetProcAddress"], "resolver_callsite": "0x1010"},
            anchor={"function_entry": "0x1000"},
        )

    candidate = evidence("candidate", "artifact-1", "STATIC_OBSERVED")
    cross_artifact = evidence("cross-artifact", "artifact-2", "STATIC_OBSERVED")
    non_static = evidence("non-static", "artifact-1", "DYNAMIC_OBSERVED")

    def suppressor(evidence_ids: list[str]) -> dict[str, object]:
        return {
            "id": "verified-dynamic",
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "status": "VERIFIED",
            "artifact_id": "artifact-1",
            "evidence_ids": evidence_ids,
            "target": "sample.exe!FUN_1000",
            "inputs": ["module and exported entry-point name"],
            "transformation_or_control": ["LoadLibraryA -> GetProcAddress -> indirect consumer"],
            "conditions": ["static evidence path"],
            "outputs": ["resolved function pointer"],
            "consumers": ["indirect API consumer"],
            "side_effects": ["prepares an indirect API dispatch"],
            "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        }

    def render(evidence_rows: list[SimpleNamespace], mechanism: dict[str, object]) -> dict[str, object]:
        return build_report_document(
            case=SimpleNamespace(id="case-evidence-boundary"),
            task=SimpleNamespace(
                id="task-evidence-boundary", lifecycle="SUCCEEDED", outcome="PARTIAL",
                target_breadth="B0", target_depth="D3", actual_granularity={},
                request_snapshot={}, limitations=["static only"],
            ),
            artifacts=[], tool_runs=[], evidence=evidence_rows, claims=[], claim_evidence=[],
            relations=[], gates=[], mechanisms=[mechanism], selected_modules=["behavior_attack"],
        )

    cross_document = render([candidate, cross_artifact], suppressor(["candidate", "cross-artifact"]))
    assert cross_document["trace"]["suppressed_mechanism_projections"] == []
    assert any(
        row.get("mechanism_id") == "observed-mechanism:candidate"
        for row in cross_document["modules"][0]["rows"]
    )

    dynamic_document = render([candidate, non_static], suppressor(["candidate", "non-static"]))
    assert dynamic_document["trace"]["suppressed_mechanism_projections"] == []
    assert any(
        row.get("mechanism_id") == "observed-mechanism:candidate"
        for row in dynamic_document["modules"][0]["rows"]
    )


def test_specialist_suppression_rejects_unknown_evidence_nature_and_missing_id() -> None:
    """Only named static natures and stable mechanism IDs can suppress rows."""
    evidence = SimpleNamespace(
        id="candidate", artifact_id="artifact-1", tool_run_id="tool-1",
        module="loader", kind="mechanism_dynamic_resolution",
        nature="STATIC_FABRICATED",
        value={"apis": ["LoadLibraryA", "GetProcAddress"]},
        anchor={"function_entry": "0x1000"},
    )
    base = {
        "mechanism_type": "DYNAMIC_API_RESOLUTION", "status": "VERIFIED",
        "artifact_id": "artifact-1", "evidence_ids": ["candidate"],
        "target": "sample.exe!FUN_1000", "inputs": ["module"],
        "transformation_or_control": ["LoadLibraryA -> GetProcAddress -> indirect consumer"],
        "conditions": ["static path"], "outputs": ["pointer"],
        "consumers": ["indirect consumer"],
        "side_effects": ["prepares dispatch"],
        "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
    }

    def render(mechanism: dict[str, object]) -> dict[str, object]:
        return build_report_document(
            case=SimpleNamespace(id="case-nature"),
            task=SimpleNamespace(
                id="task-nature", lifecycle="SUCCEEDED", outcome="PARTIAL",
                target_breadth="B0", target_depth="D3", actual_granularity={},
                request_snapshot={}, limitations=["static only"],
            ),
            artifacts=[], tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[],
            relations=[], gates=[], mechanisms=[mechanism], selected_modules=["behavior_attack"],
        )

    assert render({**base, "id": "valid-id"})["trace"]["suppressed_mechanism_projections"] == []
    assert render({**base, "id": ""})["trace"]["suppressed_mechanism_projections"] == []


def test_specialist_suppression_keeps_same_function_independent_callsite() -> None:
    """A function can contain multiple resolver callsites with distinct paths."""
    def evidence(evidence_id: str, callsite: str) -> SimpleNamespace:
        return SimpleNamespace(
            id=evidence_id, artifact_id="artifact-1", tool_run_id="tool-1",
            module="loader", kind="mechanism_dynamic_resolution", nature="STATIC_OBSERVED",
            value={
                "apis": ["LoadLibraryA", "GetProcAddress"],
                "resolver_callsite": callsite,
            },
            anchor={"function_entry": "0x1000"},
        )

    first = evidence("e-a", "0x1010")
    second = evidence("e-b", "0x1020")
    document = build_report_document(
        case=SimpleNamespace(id="case-callsite-scope"),
        task=SimpleNamespace(
            id="task-callsite-scope", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[], tool_runs=[], evidence=[first, second], claims=[], claim_evidence=[],
        relations=[], gates=[], mechanisms=[{
            "id": "verified-callsite-b",
            "mechanism_type": "DYNAMIC_API_RESOLUTION", "status": "VERIFIED",
            # The verifier's evidence closure contains both observations, but
            # its accepted mechanism scope is explicitly callsite-a.  The
            # independent callsite-b path must remain visible.
                "artifact_id": "artifact-1", "evidence_ids": ["e-a", "e-b"],
            "callsites": ["0x1010"],
            "function": "FUN_0x1000", "function_entry": "0x1000",
            "target": "sample.exe!FUN_0x1000",
            "inputs": ["module and entry-point"],
            "transformation_or_control": ["resolver -> pointer -> indirect call"],
            "conditions": ["static path"], "outputs": ["function pointer"],
            "consumers": ["indirect call"], "side_effects": ["prepares dispatch"],
            "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        }], selected_modules=["behavior_attack"],
    )

    visible_ids = {
        row.get("mechanism_id")
        for row in document["modules"][0]["rows"]
        if row.get("type") == "mechanism_observation"
    }
    assert "observed-mechanism:e-a" not in visible_ids
    assert "observed-mechanism:e-b" in visible_ids
    assert document["trace"]["suppressed_mechanism_projections"][0]["evidence_ids"] == ["e-a"]


def test_report_projects_recovered_dynamic_api_into_mechanism() -> None:
    from threat_report_agent.reporting import build_observed_mechanism_projections

    evidence = SimpleNamespace(
        id="resolved-1", artifact_id="artifact-1", kind="resolved_api",
        nature="STATIC_DERIVED", module="loader",
        value={
            "resolver": "GetProcAddress", "api_name": "WinHttpOpen",
            "resolver_callsite": "0x1010", "consumer_callsite": "0x1020",
            "consumer": "CALL [resolved_slot]", "string_address": "0x2000",
            "confidence": "HIGH", "static_only": True,
        },
        anchor={"function_entry": "0x1000", "rva": 4096},
    )
    rows = build_observed_mechanism_projections({"resolved-1": evidence})
    row = rows[0]
    assert row["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
    assert "WinHttpOpen" in row["transformation_or_control"][0]
    assert "0x1020" in row["transformation_or_control"][0]
    assert row["resolver_callsites"] == ["0x1010"]
    assert row["consumer_callsites"] == ["0x1020"]
    assert "resolved_api" == row["provenance"]["source_kind"]


def test_observed_mechanism_dedup_preserves_all_evidence_and_callsites() -> None:
    """Projection deduplication must not erase corroborating source rows."""
    from threat_report_agent.reporting import build_observed_mechanism_projections

    def evidence(evidence_id: str, resolver: str, consumer: str) -> SimpleNamespace:
        return SimpleNamespace(
            id=evidence_id,
            artifact_id="artifact-1",
            module="loader",
            kind="resolved_api",
            nature="STATIC_DERIVED",
            value={
                "resolver": "GetProcAddress",
                "api_name": "WinHttpOpen",
                "resolver_callsite": resolver,
                "consumer_callsite": consumer,
                "consumer": "CALL [resolved_slot]",
                "confidence": "HIGH",
                "static_only": True,
            },
            anchor={"function": "FUN_1000", "function_entry": "0x1000"},
        )

    rows = build_observed_mechanism_projections({
        "resolved-1": evidence("resolved-1", "0x1010", "0x1020"),
        # Same semantic observation from a second evidence edge.  The
        # analyst projection should stay one row while retaining both ids.
        "resolved-2": evidence("resolved-2", "0x1010", "0x1020"),
    })

    assert len(rows) == 1
    row = rows[0]
    assert set(row["evidence_ids"]) == {"resolved-1", "resolved-2"}
    assert row["resolver_callsites"] == ["0x1010"]
    assert row["consumer_callsites"] == ["0x1020"]
    assert set(row["provenance"]["merged_observation_evidence_ids"]) == {"resolved-1", "resolved-2"}


def test_observed_resolver_recovers_function_and_pointer_sites_from_sources() -> None:
    """A file-level resolver observation must still render its concrete path."""
    from threat_report_agent.reporting import build_observed_mechanism_projections

    source = SimpleNamespace(
        id="pointer-source", artifact_id="artifact-1", module="loader",
        kind="indirect_function_pointer_link", nature="STATIC_OBSERVED",
        value={
            "resolver": "GetProcAddress",
            "resolver_callsite": "0x401120",
            "consumer_callsite": "0x401180",
            "consumer": "CALL R12",
        },
        anchor={"type": "indirect_function_pointer", "function_entry": "0x401000", "rva": 4096},
    )
    observation = SimpleNamespace(
        id="resolver-observation", artifact_id="artifact-1", module="loader",
        kind="mechanism_dynamic_resolution", nature="STATIC_DERIVED",
        value={
            "apis": ["LoadLibraryA", "GetProcAddress"],
            "source_evidence_ids": ["pointer-source"],
        },
        anchor={"type": "api_call_chain", "artifact_id": "artifact-1"},
    )

    rows = build_observed_mechanism_projections({
        "resolver-observation": observation,
        "pointer-source": source,
    })
    row = next(row for row in rows if row["mechanism_id"] == "observed-mechanism:resolver-observation")
    assert row["target"] == "FUN_0x401000@0x401000"
    assert row["function_entry"] == "0x401000"
    assert row["rva"] == 4096
    assert row["resolver_callsites"] == ["0x401120"]
    assert row["consumer_callsites"] == ["0x401180"]
    assert "resolver callsite=0x401120" in row["transformation_or_control"][0]
    assert "consumer callsite=0x401180" in row["transformation_or_control"][0]


def test_report_projects_cross_function_chain_as_ordered_static_flow() -> None:
    evidence = SimpleNamespace(
        id="cross-chain-1", artifact_id="artifact-1", tool_run_id="tool-1",
        module="static_triage", kind="cross_function_chain",
        nature="STATIC_OBSERVED",
        value={
            "functions": ["FUN_1000", "FUN_2000", "FUN_3000"],
            "categories": ["loader", "dynamic_resolution", "execution"],
            "edge_provenance": [{"from": "FUN_1000", "to": "FUN_2000"}],
            "static_only": True,
        },
        anchor={"type": "call_graph_path", "function_entries": ["FUN_1000", "FUN_2000", "FUN_3000"]},
    )
    rows = build_observed_mechanism_projections({"cross-chain-1": evidence})
    assert len(rows) == 1
    row = rows[0]
    assert row["mechanism_type"] == "CROSS_FUNCTION_CHAIN"
    assert row["ordered"] is True
    assert row["function"] == "FUN_1000 -> FUN_2000 -> FUN_3000"
    assert "loader -> dynamic_resolution -> execution" in row["transformation_or_control"][0]
    assert row["consumers"] == ["FUN_3000"]


def test_generic_dynamic_resolution_does_not_claim_full_completeness() -> None:
    evidence = SimpleNamespace(
        id="generic-resolution", artifact_id="artifact-1", tool_run_id="tool-1",
        module="loader", kind="mechanism_dynamic_resolution",
        nature="STATIC_OBSERVED", value={}, anchor={"function_entry": "0x4000"},
    )
    rows = build_observed_mechanism_projections({"generic-resolution": evidence})
    assert len(rows) == 1
    assert rows[0]["completeness"] < 80
    assert rows[0]["inputs"] == ["UNKNOWN(module name and exported entry-point name)"]
    assert rows[0]["consumers"] == ["UNKNOWN(indirect call/jump consumer)"]


def test_report_projects_decode_result_with_verification_and_consumer() -> None:
    """A recovered decode must be visible as an analyst result, not a raw row."""
    from threat_report_agent.reporting import build_report_document, document_to_markdown

    evidence = SimpleNamespace(
        id="decode-result-1", artifact_id="artifact-1", tool_run_id="tool-1",
        module="static_triage", kind="decode_result", nature="STATIC_DERIVED",
        value={
            "source_kind": "mechanism_decode_window",
            "verification": {
                "status": "VERIFIED_STATIC_DATA",
                "file_offset": 512,
                "virtual_address": "0x140003000",
                "formula": "single_key_plus_step",
                "length": 32,
                "printable_ratio": 0.9688,
                "markers": ["http"],
                "decoded_preview": "https://example.invalid/config",
                "decoded_strings": ["https://example.invalid/config"],
            },
            "verification_status": "VERIFIED_STATIC_DATA",
            "consumer_status": "LINKED_STATIC",
            "consumer_candidates": [
                {"evidence_id": "consumer-1", "kind": "function_call", "api": "LoadLibraryW", "function_entry": "0x140003000"}
            ],
            "consumer_evidence_ids": ["consumer-1"],
            "static_only": True,
        },
        anchor={"type": "investigation_action", "function_entry": "0x140003000", "rva": 12288},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL", target_breadth="B0",
            target_depth="D3", actual_granularity={}, request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="sha", detected_type="pe",
            role="EXECUTABLE", obligation="REQUIRED", parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[], relations=[], gates=[],
        model_calls=[], mechanisms=[], selected_modules=["decryption"],
    )
    module = document["modules"][0]
    row = next(row for row in module["rows"] if row.get("type") == "decode_result")
    assert row["verification_status"] == "VERIFIED_STATIC_DATA"
    assert row["consumer_status"] == "LINKED_STATIC"
    assert row["consumer_evidence_ids"] == ["consumer-1"]
    assert row["decoded_preview"] == "https://example.invalid/config"
    markdown = document_to_markdown(document)
    assert "Static Decode Result" in markdown
    assert "VERIFIED_STATIC_DATA" in markdown
    assert "LoadLibraryW" in markdown
    assert "runtime execution is unobserved" in markdown


def test_network_download_projection_respects_typed_categories() -> None:
    network = SimpleNamespace(
        id="network-1", artifact_id="a1", kind="mechanism_chain", nature="STATIC_OBSERVED",
        value={
            "chain_type": "network_download",
            "categories": ["network", "file_io"],
            "steps": [
                {"category": "network", "name": "WinHttpSendRequest"},
                {"category": "file_io", "name": "WriteFile"},
            ],
        }, anchor={"function_entry": "0x1000"},
    )
    pipe = SimpleNamespace(
        id="pipe-1", artifact_id="a1", kind="mechanism_chain", nature="STATIC_OBSERVED",
        value={
            "chain_type": "network_download",
            "categories": ["execution", "file_io"],
            "steps": [
                {"category": "execution", "name": "CreateProcessW"},
                {"category": "file_io", "name": "ReadFile"},
            ],
        }, anchor={"function_entry": "0x2000"},
    )
    rows = build_observed_mechanism_projections({"network-1": network, "pipe-1": pipe})
    network_row = next(row for row in rows if row["provenance"]["observation_evidence_id"] == "network-1")
    pipe_row = next(row for row in rows if row["provenance"]["observation_evidence_id"] == "pipe-1")
    assert network_row["mechanism_type"] == "NETWORK_DOWNLOAD"
    assert "network request inputs" in network_row["inputs"][0]
    assert pipe_row["mechanism_type"] == "SHELL_OUTPUT"
    assert "captured stdout/stderr" in pipe_row["outputs"][0]


def test_candidate_projection_selection_preserves_high_value_types() -> None:
    rows = [
        {"mechanism_id": f"decode-{index}", "mechanism_type": "DECODE_TRANSFORM"}
        for index in range(20)
    ] + [
        {"mechanism_id": "dyn", "mechanism_type": "DYNAMIC_API_RESOLUTION"},
        {"mechanism_id": "memory", "mechanism_type": "MEMORY_PERMISSION_CHANGE"},
        {"mechanism_id": "env", "mechanism_type": "ENVIRONMENT_CHECK"},
    ]
    selected = _select_mechanism_projections(rows, limit=8)
    selected_types = {row["mechanism_type"] for row in selected}
    assert {"DYNAMIC_API_RESOLUTION", "MEMORY_PERMISSION_CHANGE", "ENVIRONMENT_CHECK"} <= selected_types


def test_candidate_projection_selection_keeps_persist_how_process_and_decode() -> None:
    rows = [
        {"mechanism_id": f"dyn-{index}", "mechanism_type": "DYNAMIC_API_RESOLUTION"}
        for index in range(20)
    ] + [
        {
            "mechanism_id": "process-1",
            "mechanism_type": "PROCESS_EXECUTION",
            "inputs": ["cmd.exe /c FoxitPDFReader.exe"],
            "transformation_or_control": ["CreateProcessW creation_flags=0x000f4240"],
            "consumers": ["cmd.exe /c FoxitPDFReader.exe"],
        },
        {
            "mechanism_id": "decode-1",
            "mechanism_type": "DECODE_CONFIG",
            "inputs": ["encoded buffer"],
            "transformation_or_control": ["key_table_modulo_xor_counter"],
            "consumers": ["FUN_140004605"],
        },
    ]
    selected = _select_mechanism_projections(rows, limit=8)
    selected_types = {row["mechanism_type"] for row in selected}
    assert "PROCESS_EXECUTION" in selected_types
    assert "DECODE_CONFIG" in selected_types
    from threat_report_agent.reporting import _is_actionable_candidate_mechanism

    process = next(row for row in rows if row["mechanism_id"] == "process-1")
    decode = next(row for row in rows if row["mechanism_id"] == "decode-1")
    assert _is_actionable_candidate_mechanism(
        {**process, "status": "CANDIDATE", "evidence_ids": ["trace-1"]}
    )
    assert _is_actionable_candidate_mechanism(
        {**decode, "status": "CANDIDATE", "evidence_ids": ["decode-1"]}
    )
    assert not _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["trace-specialist"],
            "mechanism_type": "PROCESS_EXECUTION",
            "inputs": [],
            "transformation_or_control": ["CreateProcessW creation_flags=0x09080008"],
            "consumers": [],
        }
    )


def test_named_api_consumer_is_actionable_without_module_input() -> None:
    """One-round report must print named API + JMP even without GetProcAddress in the row."""
    from threat_report_agent.reporting import _is_actionable_candidate_mechanism

    assert _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["resolved-1"],
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "inputs": ["SetThreadDescription"],
            "transformation_or_control": ["GetProcAddress", "SetThreadDescription", "JMP R8"],
            "consumers": ["JMP R8"],
        }
    )
    assert _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["resolved-2"],
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "inputs": ["SetThreadDescription"],
            "transformation_or_control": ["SetThreadDescription"],
            "consumers": ["JMP R8"],
        }
    )
    assert not _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["iat-1"],
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "inputs": ["GetProcAddress"],
            "transformation_or_control": ["GetProcAddress"],
            "consumers": [],
        }
    )


def test_unique_thread_start_is_actionable_candidate_mechanism() -> None:
    """Recovered lpStartAddress is one-round HOW, not TRACE bait."""
    from threat_report_agent.reporting import _is_actionable_candidate_mechanism

    assert _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["trace-thread"],
            "mechanism_type": "THREAD_CALLBACK",
            "inputs": ["0x14004d100"],
            "transformation_or_control": [
                "CreateThread lpStartAddress=0x14000a100; lpParameter=0x14004d100"
            ],
            "outputs": ["0x14000a100"],
            "consumers": ["0x14000a100"],
        }
    )
    assert not _is_actionable_candidate_mechanism(
        {
            "status": "CANDIDATE",
            "evidence_ids": ["trace-unknown"],
            "mechanism_type": "THREAD_CALLBACK",
            "inputs": ["UNKNOWN(parameter)"],
            "transformation_or_control": ["CreateThread lpStartAddress=UNKNOWN(start_routine)"],
            "outputs": ["UNKNOWN(start_routine)"],
            "consumers": [],
        }
    )


def test_ppid_chain_without_specialist_token_is_not_actionable() -> None:
    """Resume OpenProcess/UpdateProcThreadAttribute/CreateProcess is not PPID HOW."""
    from threat_report_agent.reporting import _is_actionable_candidate_mechanism

    chain = {
        "status": "CANDIDATE",
        "evidence_ids": ["trace-ppid"],
        "mechanism_type": "PPID_SPOOFING",
        "inputs": ["UNKNOWN(parent)"],
        "transformation_or_control": [
            "OpenProcess -> UpdateProcThreadAttribute -> CreateProcessW"
        ],
        "consumers": ["CreateProcessW"],
        "unknowns": ["0x09080008 not recovered"],
    }
    assert not _is_actionable_candidate_mechanism(chain)
    assert _is_actionable_candidate_mechanism(
        {
            **chain,
            "transformation_or_control": [
                "OpenProcess -> UpdateProcThreadAttribute -> CreateProcessW; 0x09080008"
            ],
        }
    )


def test_persist_how_unique_thread_claim_survives_resolver_flood_in_markdown() -> None:
    """One-round report must print recovered CreateThread start, not only GetProcAddress."""
    thread_claim = SimpleNamespace(
        id="claim-thread",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a same-process OS thread: "
            "`CreateThread` start `0x14000a100` parameter `0x14004d100`; "
            "runtime start is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_start_os_thread",
        object="0x14000a100",
        mechanism="CreateThread lpStartAddress=0x14000a100; lpParameter=0x14004d100",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    thread_trace = SimpleNamespace(
        id="trace-thread",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateThread",
            "arguments": [
                {
                    "index": 2,
                    "name": "lpStartAddress",
                    "value": "0x14000a100",
                    "resolved": True,
                },
                {
                    "index": 3,
                    "name": "lpParameter",
                    "value": "0x14004d100",
                    "resolved": True,
                },
            ],
        },
        anchor={"function_entry": "140001000"},
    )
    thread_body = SimpleNamespace(
        id="body-thread",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "FUN_14000a100",
            "call_targets": [
                {"target_name": "WaitForSingleObject"},
                {"target_name": "ExitThread"},
            ],
            "data_references": [{"text": "work_item"}],
        },
        anchor={},
    )
    noise = [
        SimpleNamespace(
            id=f"resolved-{index}",
            artifact_id="artifact-1",
            tool_run_id="ghidra-1",
            module="static_triage",
            kind="resolved_api",
            nature="STATIC_DERIVED",
            value={
                "resolver": "GetProcAddress",
                "api_name": f"Export{index}",
                "module_input": "kernel32.dll",
                "consumer": "JMP R8",
            },
            anchor={"function_entry": f"14003{index:04x}"},
        )
        for index in range(20)
    ]
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[thread_trace, thread_body, *noise],
        claims=[thread_claim],
        claim_evidence=[
            SimpleNamespace(
                claim_id="claim-thread",
                evidence_id="trace-thread",
                stance="SUPPORTS",
            )
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assert "0x14000a100" in markdown
    assert "CreateThread" in markdown
    assert "lpStartAddress" in markdown
    assert "thread-and-callback" in markdown
    assert "Phase 7" in markdown
    assert "0x14000a100" in markdown.split("Phase 7", 1)[-1].split("Phase 8", 1)[0]
    unique_block = markdown.split("Unique OS threads / callbacks", 1)[-1].split("#### ", 1)[0]
    assert "WaitForSingleObject" in unique_block
    assert "ExitThread" in unique_block
    assert "UNKNOWN(loop)" not in unique_block
    assert "UNKNOWN(exit)" not in unique_block


def test_persist_how_process_claim_survives_resolver_flood_in_markdown() -> None:
    """One-round report must print recovered command/flags, not only GetProcAddress."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `cmd.exe /c FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="cmd.exe /c FoxitPDFReader.exe",
        mechanism="CreateProcessW command=cmd.exe /c FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={"technique_id": "T1059", "name": "Command and Scripting Interpreter", "status": "candidate"},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "cmd.exe /c FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "140004605"},
    )
    noise = [
        SimpleNamespace(
            id=f"resolved-{index}",
            artifact_id="artifact-1",
            tool_run_id="ghidra-1",
            module="static_triage",
            kind="resolved_api",
            nature="STATIC_DERIVED",
            value={
                "resolver": "GetProcAddress",
                "api_name": f"Export{index}",
                "module_input": "kernel32.dll",
                "consumer": "JMP R8",
            },
            anchor={"function_entry": f"14003{index:04x}"},
        )
        for index in range(20)
    ]
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace, *noise],
        claims=[process_claim],
        claim_evidence=[
            SimpleNamespace(
                claim_id="claim-process",
                evidence_id="trace-process",
                stance="SUPPORTS",
            )
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assert "FoxitPDFReader.exe" in markdown
    assert "0x000f4240" in markdown
    assert "CreateProcessW" in markdown
    assert "  - input:" in markdown
    assert "  - condition:" in markdown
    assert "HTTP transport API not recovered" in markdown
    assert "parent-process spoofing" in markdown.casefold() or "PPID specialist token" in markdown
    assert "process-creation" in markdown
    assert "Phase 5" in markdown
    assert "FoxitPDFReader.exe" in markdown.split("Phase 5", 1)[-1].split("Phase 6", 1)[0]
    assert "UNKNOWN(phase" not in markdown.split("Phase 5", 1)[-1].split("Phase 6", 1)[0]
    summary = document["modules"][0]["rows"][0]["summary"]
    assert "FoxitPDFReader.exe" in summary
    assert "the implementation path was not recovered" not in summary


def test_executive_how_leads_with_process_command_not_decoded_url() -> None:
    """Decoded C2 URLs must not prepend-starve persist CreateProcess HOW on the front page."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "140004605"},
    )
    decode = SimpleNamespace(
        id="decode-1",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="decryption",
        kind="decode_result",
        nature="STATIC_OBSERVED",
        value={
            "status": "VERIFIED_STATIC_DATA",
            "decoded_text": "http://69.48.228.74/ComHost.exe",
            "decoded_preview": "http://69.48.228.74/ComHost.exe",
            "formula": "key_table_modulo_xor_counter",
        },
        anchor={},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace, decode],
        claims=[process_claim],
        claim_evidence=[
            SimpleNamespace(
                claim_id="claim-process",
                evidence_id="trace-process",
                stance="SUPPORTS",
            )
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assessment = markdown.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0]
    how_line = next(line for line in assessment.splitlines() if "How:" in line)
    foxit_at = how_line.find("FoxitPDFReader.exe")
    url_at = how_line.find("http://69.48.228.74/ComHost.exe")
    assert foxit_at != -1
    assert foxit_at < url_at or url_at == -1
    summary = document["modules"][0]["rows"][0]["summary"]
    assert "FoxitPDFReader.exe" in summary.split("How:", 1)[-1].split("Key unknowns:", 1)[0]


def test_executive_how_keeps_persist_process_not_shellexecute_dump() -> None:
    """HOW11 Executive How concatenated ShellExecute/env-string decompile over Foxit flags."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={"api": "CreateProcessW", "command": "FoxitPDFReader.exe", "creation_flags": "0x000f4240"},
        anchor={"function_entry": "140004605"},
    )
    semantic_claim = SimpleNamespace(
        id="claim-sem",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement="process-creation FUN_140003885",
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="Resume.pdf.exe",
        mechanism=(
            "FUN_140003885@140003885: ShellExecuteW(qword ptr [0x140049008]); "
            "consumer=ShellExecuteW; FUN_14003c550: GetEnvironmentStringsW -> CreateProcessW"
        ),
        condition="abstract_execution_trace",
        status="CANDIDATE",
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    semantic_row = SimpleNamespace(
        id="sem-1",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="investigation",
        kind="function_semantic_summary",
        nature="STATIC_DERIVED",
        value={
            "function": "FUN_140003885",
            "function_entry": "140003885",
            "call_sequence": [{"api": "ShellExecuteW"}, {"api": "GetEnvironmentStringsW"}],
        },
        anchor={"function_entry": "140003885"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace, semantic_row],
        claims=[process_claim, semantic_claim],
        claim_evidence=[
            SimpleNamespace(claim_id="claim-process", evidence_id="trace-process", stance="SUPPORTS"),
            SimpleNamespace(claim_id="claim-sem", evidence_id="sem-1", stance="SUPPORTS"),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assessment = markdown.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0]
    how_line = next(line for line in assessment.splitlines() if line.startswith("What:") or "How:" in line)
    how_block = assessment.split("How:", 1)[-1].split("Key unknowns:", 1)[0]
    assert "FoxitPDFReader.exe" in how_block
    assert "0x000f4240" in how_block
    assert "ShellExecuteW" not in how_block
    assert "GetEnvironmentStringsW" not in how_block
    assert how_line  # keep assessment parse from going unused


def test_executive_how_leads_with_process_command_not_ppid() -> None:
    """HOW6: recovered UpdateProcThreadAttribute must not beat Foxit command on the front page."""
    ppid_claim = SimpleNamespace(
        id="claim-ppid",
        module="identity",
        claim_type="INVESTIGATED_MECHANISM",
        statement="parent-process-spoofing via UpdateProcThreadAttribute on Resume.pdf.exe",
        subject="Resume.pdf.exe",
        action="may_spoof_parent_process",
        object="explorer.exe",
        mechanism="OpenProcess -> UpdateProcThreadAttribute -> CreateProcessW",
        condition="specialist token 0x09080008 not recovered",
        status="CANDIDATE",
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    ppid_trace = SimpleNamespace(
        id="trace-ppid",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "UpdateProcThreadAttribute",
            "parent_selection": "explorer.exe",
            "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        },
        anchor={"function_entry": "FUN_140004605"},
    )
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "140004605"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[ppid_trace, process_trace],
        claims=[ppid_claim, process_claim],
        claim_evidence=[
            SimpleNamespace(
                claim_id="claim-ppid",
                evidence_id="trace-ppid",
                stance="SUPPORTS",
            ),
            SimpleNamespace(
                claim_id="claim-process",
                evidence_id="trace-process",
                stance="SUPPORTS",
            ),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assessment = markdown.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0]
    how_line = next(line for line in assessment.splitlines() if "How:" in line)
    foxit_at = how_line.find("FoxitPDFReader.exe")
    ppid_at = how_line.find("UpdateProcThreadAttribute")
    assert foxit_at != -1
    assert foxit_at < ppid_at or ppid_at == -1
    summary = document["modules"][0]["rows"][0]["summary"]
    how_text = summary.split("How:", 1)[-1].split("Key unknowns:", 1)[0]
    assert "FoxitPDFReader.exe" in how_text
    assert how_text.find("FoxitPDFReader.exe") < how_text.find("UpdateProcThreadAttribute") or (
        "UpdateProcThreadAttribute" not in how_text
    )


def test_executive_how_drops_fun_dump_after_persist_process() -> None:
    """Gate leftover concatenated FUN_140004605 GetConsoleWindow dump after Foxit How."""
    fun_dump = (
        "FUN_140004605@140004605: GetConsoleWindow -> GetTickCount64 -> GetSystemInfo -> "
        "memcpy -> memcmp -> OpenProcess -> InitializeProcThreadAttributeList -> "
        "UpdateProcThreadAttribute -> CreateProcessW -> MoveFileExW -> CopyFileExW; "
        "Attribute=0x20000"
    )
    ppid_claim = SimpleNamespace(
        id="claim-ppid",
        module="identity",
        claim_type="INVESTIGATED_MECHANISM",
        statement="parent-process-spoofing via UpdateProcThreadAttribute on Resume.pdf.exe",
        subject="Resume.pdf.exe",
        action="may_spoof_parent_process",
        object="UNKNOWN(parent identity)",
        mechanism=fun_dump,
        condition="parent identity not recovered",
        status="CANDIDATE",
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    ppid_trace = SimpleNamespace(
        id="trace-ppid",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "UpdateProcThreadAttribute",
            "attribute": "0x00020000",
        },
        anchor={"function_entry": "FUN_140004605"},
    )
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "140004605"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[ppid_trace, process_trace],
        claims=[ppid_claim, process_claim],
        claim_evidence=[
            SimpleNamespace(claim_id="claim-ppid", evidence_id="trace-ppid", stance="SUPPORTS"),
            SimpleNamespace(claim_id="claim-process", evidence_id="trace-process", stance="SUPPORTS"),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assessment = markdown.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0]
    how_line = next(line for line in assessment.splitlines() if "How:" in line)
    assert "FoxitPDFReader.exe" in how_line
    assert "0x000f4240" in how_line
    assert "GetConsoleWindow" not in how_line
    assert how_line.count(" -> ") < 6
    summary = document["modules"][0]["rows"][0]["summary"]
    how_text = summary.split("How:", 1)[-1].split("Key unknowns:", 1)[0]
    assert "FoxitPDFReader.exe" in how_text
    assert "GetConsoleWindow" not in how_text
    catalog = next(
        row
        for module in document["modules"]
        for row in module.get("rows") or []
        if isinstance(row, dict) and row.get("type") == "catalog_behavior_matrix"
    )
    ppid_row = next(
        item
        for item in catalog["discovered"]
        if item.get("catalog_id") == "parent-process-spoofing"
    )
    assert "FUN_140004605" not in str(ppid_row.get("how") or "")
    assert "GetConsoleWindow" not in str(ppid_row.get("how") or "")
    assert "GetConsoleWindow" not in assessment
    chain = assessment.split("Mechanism chain:", 1)[-1] if "Mechanism chain:" in assessment else ""
    assert "FUN_140004605@" not in chain.split("Interpretation", 1)[0]
    interp = assessment.split("Interpretation:", 1)[-1] if "Interpretation:" in assessment else ""
    assert "FUN_140004605@" not in interp


def test_executive_how_keeps_persist_command_when_semantic_decompile_exists() -> None:
    """HOW7: catalog ShellExecute decompile must not replace persist Foxit command on How."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "140004605"},
    )
    semantic = SimpleNamespace(
        id="sem-shellexecute",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_DERIVED",
        value={
            "function": "FUN_140003885",
            "function_entry": "140003885",
            "call_sequence": [
                {
                    "api": "ShellExecuteW",
                    "callsite": "1400038df",
                    "arguments": [],
                    "consumers": [{"api": "ShellExecuteW"}],
                }
            ],
        },
        anchor={"function_entry": "140003885"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace, semantic],
        claims=[process_claim],
        claim_evidence=[
            SimpleNamespace(
                claim_id="claim-process",
                evidence_id="trace-process",
                stance="SUPPORTS",
            )
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    assessment = markdown.split("## 1. Executive Assessment", 1)[1].split("## 2.", 1)[0]
    how_line = next(line for line in assessment.splitlines() if "How:" in line)
    foxit_at = how_line.find("FoxitPDFReader.exe")
    shell_at = how_line.find("ShellExecuteW")
    assert foxit_at != -1
    assert foxit_at < shell_at or shell_at == -1
    summary = document["modules"][0]["rows"][0]["summary"]
    how_text = summary.split("How:", 1)[-1].split("Key unknowns:", 1)[0]
    assert "FoxitPDFReader.exe" in how_text
    assert how_text.find("FoxitPDFReader.exe") < how_text.find("ShellExecuteW") or (
        "ShellExecuteW" not in how_text
    )


def test_behavior_overview_ranks_process_how_ahead_of_named_api_claim_flood() -> None:
    """Kunglao leftover remainder: named-API claims must not slice Foxit off the first 8 HOW rows."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `cmd.exe /c FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="cmd.exe /c FoxitPDFReader.exe",
        mechanism="CreateProcessW command=cmd.exe /c FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "cmd.exe /c FoxitPDFReader.exe",
            "creation_flags": "0x000f4240",
        },
        anchor={"function_entry": "FUN_140004605"},
    )
    named_claims = []
    named_evidence = []
    named_links = []
    for index in range(20):
        claim_id = f"claim-api-{index}"
        evidence_id = f"resolved-{index}"
        named_claims.append(
            SimpleNamespace(
                id=claim_id,
                module="loader",
                claim_type="INVESTIGATED_MECHANISM",
                statement=f"named API Export{index} consumer JMP R8",
                subject="Resume.pdf.exe",
                action="may_resolve_api_dynamically",
                object=f"Export{index}",
                mechanism=f"GetProcAddress api=Export{index} consumer=JMP R8",
                condition="static evidence threshold satisfied; runtime execution not proven",
                status="CANDIDATE",
                confidence="HIGH",
                attack_mapping={},
                model_call_id=None,
                nature="STATIC_INFERRED",
            )
        )
        named_evidence.append(
            SimpleNamespace(
                id=evidence_id,
                artifact_id="artifact-1",
                tool_run_id="ghidra-1",
                module="static_triage",
                kind="resolved_api",
                nature="STATIC_DERIVED",
                value={
                    "resolver": "GetProcAddress",
                    "api_name": f"Export{index}",
                    "module_input": "kernel32.dll",
                    "consumer": "JMP R8",
                },
                anchor={"function_entry": f"14003{index:04x}"},
            )
        )
        named_links.append(
            SimpleNamespace(claim_id=claim_id, evidence_id=evidence_id, stance="SUPPORTS")
        )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace, *named_evidence],
        claims=[*named_claims, process_claim],
        claim_evidence=[
            *named_links,
            SimpleNamespace(
                claim_id="claim-process",
                evidence_id="trace-process",
                stance="SUPPORTS",
            ),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    markdown = document_to_markdown(document)
    overview = markdown.split("### Behavior Overview", 1)[-1].split("## 3.", 1)[0]
    assert "FoxitPDFReader.exe" in overview
    assert "CreateProcessW" in overview
    assert "0x000f4240" in overview
    summary = document["modules"][0]["rows"][0]["summary"]
    assert "FoxitPDFReader.exe" in summary


def test_production_assessment_does_not_join_independent_function_paths() -> None:
    evidence = []
    for index, function_entry in enumerate(("0x1000", "0x2000"), start=1):
        evidence.append(SimpleNamespace(
            id=f"chain-{index}", artifact_id="a1", tool_run_id="t1",
            module="static_triage", kind="mechanism_chain", nature="STATIC_OBSERVED",
            value={
                "chain_type": "dynamic_loader", "function": f"FUN_{function_entry}",
                "entry": function_entry, "steps": [
                    {"category": "dynamic_resolution", "name": "LoadLibraryA"},
                    {"category": "dynamic_resolution", "name": "GetProcAddress"},
                ],
            }, anchor={"function_entry": function_entry},
        ))
    document = build_report_document(
        case=SimpleNamespace(id="c1"),
        task=SimpleNamespace(id="t1", lifecycle="SUCCEEDED", outcome="PARTIAL", target_breadth="B0", target_depth="D3", actual_granularity={}, request_snapshot={}, limitations=["static"]),
        artifacts=[SimpleNamespace(id="a1", logical_path="sample.exe", content_sha256="sha", detected_type="pe", role="EXECUTABLE", obligation="REQUIRED", parent_artifact_id=None)],
        tool_runs=[], evidence=evidence, claims=[], claim_evidence=[], relations=[], gates=[], mechanisms=[],
        selected_modules=["executive_summary"],
    )
    assessment = document["modules"][0]["rows"][0]["findings"]
    chain = next(row for row in assessment if row.get("type") == "mechanism_chain")
    assert chain["rendered"] == ""
    assert len(chain["independent_paths"]) == 2
    assessment_summary = document["modules"][0]["rows"][0]["summary"]
    assert "Interpretation:" in assessment_summary
    assert "loader path" in assessment_summary
    markdown = document_to_markdown(document)
    assert "未恢复出跨函数有序因果链" in markdown
    assert "FUN_0x1000" in markdown and "FUN_0x2000" in markdown


def test_v3_markdown_exposes_static_execution_boundary_pipeline_and_empty_model_state() -> None:
    markdown = document_to_markdown(
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
            "analysis_coverage": {
                "score": 80.0,
                "dimensions": {"artifact_parse": 1.0},
                "pipeline_completion": {
                    "score": 100.0,
                    "dimensions": {"artifact_parse": 1.0, "report_synthesis": 1.0},
                },
                "gaps": ["static only"],
            },
            "modules": [],
            "trace": {"evidence_ids": [], "claim_ids": [], "tool_run_ids": []},
        }
    )
    assert "- Sample execution: **false**" in markdown
    assert "- Sandbox/dynamic analysis: **false**" in markdown
    assert "isolated Unicorn/Speakeasy/Qiling" in markdown
    assert "### Model-Synthesized Candidates" in markdown
    assert "No model-synthesized candidate was accepted" in markdown
    assert "- pipeline score: 100.0" in markdown
    assert "- pipeline report_synthesis: 1.0" in markdown


def test_report_renders_attack_technique_identifiers_as_compact_findings() -> None:
    claim = SimpleNamespace(
        id="claim-attack",
        module="decryption",
        statement="sample may decode a resource",
        subject="sample.exe",
        action="may_decode_or_decrypt",
        object="embedded resource",
        mechanism="resource decode",
        condition="static only",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={
            "mappings": [
                {
                    "technique_id": "T1140",
                    "technique_name": "Deobfuscate/Decode Files or Information",
                    "status": "candidate",
                    "confidence": "HIGH",
                    "evidence_ids": ["evidence-attack"],
                }
            ]
        },
        model_call_id=None,
    )
    evidence = SimpleNamespace(
        id="evidence-attack",
        artifact_id="artifact-attack",
        tool_run_id="tool-attack",
        module="decryption",
        kind="mechanism_decode",
        nature="STATIC_OBSERVED",
        value={"indicator": "decode"},
        anchor={"type": "file_offset", "offset": 10},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-attack"),
        task=SimpleNamespace(
            id="task-attack", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-attack", logical_path="sample.exe", content_sha256="sha256",
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(
            claim_id="claim-attack", evidence_id="evidence-attack", stance="SUPPORTS"
        )],
        relations=[], gates=[], model_calls=[], selected_modules=["behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert "T1140" in markdown
    assert "Deobfuscate/Decode Files or Information" in markdown
    behavior_rows = document["modules"][0]["rows"]
    claim_row = next(row for row in behavior_rows if row.get("claim_id") == "claim-attack")
    assert claim_row["attack_techniques"][0]["technique_id"] == "T1140"


def test_report_exposes_ghidra_scale_summary() -> None:
    run = SimpleNamespace(
        id="ghidra-run",
        tool_name="ghidra-headless",
        tool_version="12.1.2",
        artifact_id="artifact-pe",
        status="SUCCEEDED",
        error=None,
        output={
            "function_count": 1228,
            "xref_count": 3809,
            "cfg_block_count": 9683,
            "symbol_count": 6678,
        },
        output_sha256="a" * 64,
        output_storage_key="aa/output.json",
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-ghidra"),
        task=SimpleNamespace(
            id="task-ghidra", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B1", target_depth="D3", actual_granularity={"depth": "D3"},
            request_snapshot={}, limitations=["one unsupported payload"],
        ),
        artifacts=[], tool_runs=[run], evidence=[], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], selected_modules=["static_triage"],
    )
    summary = next(
        row for row in document["modules"][0]["rows"] if row.get("type") == "tool_summary"
    )
    assert summary["function_count"] == 1228
    assert summary["xref_count"] == 3809
    assert summary["cfg_block_count"] == 9683
    assert summary["symbol_count"] == 6678


def test_report_renders_static_abstract_execution_prediction() -> None:
    evidence = SimpleNamespace(
        id="simulation-evidence",
        artifact_id="artifact-pe",
        tool_run_id="ghidra-run",
        module="static_triage",
        kind="abstract_execution_trace",
        nature="STATIC_OBSERVED",
        value={
            "simulation_kind": "static_abstract_execution",
            "runtime_observed": False,
            "predicted": True,
            "function": "FUN_loader",
            "entry": "0x401000",
            "confidence": "HIGH",
            "steps": [
                {"index": 1, "operation": "allocate_memory", "api": "VirtualAlloc", "outputs": {"memory": "allocated_buffer"}, "source_anchor": {}},
                {"index": 2, "operation": "change_memory_protection", "api": "VirtualProtect", "outputs": {"protection": "executable_or_writable_candidate"}, "source_anchor": {}},
            ],
            "mechanism_candidates": [{"kind": "memory_loader", "attack_technique": "T1055"}],
            "path_conditions": [{"expression": "RCX cmp 0", "source": "instruction:3"}],
            "unknowns": [],
            "limitations": ["static abstract execution only"],
        },
        anchor={"type": "abstract_execution_trace"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-simulation"),
        task=SimpleNamespace(
            id="task-simulation", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static only"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[], claim_evidence=[],
        relations=[], gates=[], model_calls=[], selected_modules=["static_triage"],
    )
    row = next(item for item in document["modules"][0]["rows"] if item.get("type") == "static_simulation_prediction")
    assert row["runtime_observed"] is False
    assert row["mechanism_candidates"][0]["kind"] == "memory_loader"
    markdown = document_to_markdown(document)
    assert "Static Abstract Execution Prediction" in markdown
    assert "VirtualAlloc" in markdown


def test_static_indicator_projection_exposes_high_value_pivots_with_provenance() -> None:
    from threat_report_agent.reporting import build_static_indicator_projections

    evidence = {
        "e-url": SimpleNamespace(
            id="e-url", module="c2_network", kind="string", value={
                "text": "http://203.0.113.10/payload.exe",
            }, anchor={"function_entry": "0x401000"},
        ),
        "e-reg": SimpleNamespace(
            id="e-reg", module="loader", kind="function_call", value={
                "api": "RegSetValueExW",
                "path": r"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\SpyNet",
            }, anchor={"rva": 4096},
        ),
        "e-task": SimpleNamespace(
            id="e-task", module="execution", kind="string", value={
                "text": "schtasks /create /sc once /run /delete",
            }, anchor={"offset": 12},
        ),
    }
    rows = build_static_indicator_projections(
        evidence,
        [SimpleNamespace(content_sha256="a" * 64)],
    )
    by_category = {row["category"]: row for row in rows}
    assert by_category["url"]["value"] == "http://203.0.113.10/payload.exe"
    assert by_category["url"]["classification"] == "STATIC_DERIVED"
    assert by_category["url"]["evidence_ids"] == ["e-url"]
    assert "registry" in by_category
    assert "scheduled_task" in by_category
    assert by_category["sha256"]["value"] == "a" * 64


def test_static_attack_candidates_require_multi_signal_conjunctions() -> None:
    from threat_report_agent.reporting import build_static_attack_candidates

    evidence = {
        "e-defender": SimpleNamespace(
            id="e-defender", value={"text": "Windows Defender SpyNet MAPSReporting"}
        ),
        "e-reg": SimpleNamespace(
            id="e-reg", value={"api": "RegSetValueExW", "text": "registry write"}
        ),
        "e-parent": SimpleNamespace(
            id="e-parent", value={
                "api": "UpdateProcThreadAttribute",
                "text": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS explorer.exe",
            }
        ),
        "e-open": SimpleNamespace(id="e-open", value={"api": "OpenProcess"}),
        "e-task": SimpleNamespace(
            id="e-task", value={"text": "schtasks /create /sc once /run /delete"}
        ),
        "e-network": SimpleNamespace(
            id="e-network", value={"api": "WinHttpSendRequest", "text": "http://203.0.113.10/x"}
        ),
        "e-decode": SimpleNamespace(
            id="e-decode", kind="mechanism_decode_window", value={"algorithm": "xor_loop_candidate"}
        ),
    }
    mappings = build_static_attack_candidates(evidence)
    techniques = {
        row["attack_techniques"][0]["technique_id"]
        for row in mappings
    }
    assert {"T1112", "T1562.001", "T1134.004", "T1053.005", "T1105", "T1140"} <= techniques
    # A lone process-creation API must not create a command-interpreter claim.
    assert "T1059" not in techniques


def test_static_attack_candidates_use_typed_evidence_kind_for_decode_mapping() -> None:
    """A typed decode observation maps even when its payload details are opaque."""
    from threat_report_agent.reporting import build_static_attack_candidates

    mappings = build_static_attack_candidates({
        "decode-window": SimpleNamespace(
            id="decode-window",
            module="static_triage",
            kind="mechanism_decode_window",
            value={"algorithm": "single_key_plus_step", "length": 128},
        )
    })

    assert [
        technique["technique_id"]
        for row in mappings
        for technique in row["attack_techniques"]
    ] == ["T1140"]


def test_v3_markdown_renders_ioc_classification_and_provenance() -> None:
    markdown = document_to_markdown({
        "report_version": "3.0",
        "report_sections": [
            "Executive Assessment", "Artifact Summary", "Key Static Findings",
            "Verified Mechanisms", "Reconstructed Static Behavior Flow",
            "IOC / Indicators", "Detection / Hunting Opportunities",
            "ATT&CK Reference", "Unknowns / Static Boundaries", "Analysis Coverage",
        ],
        "case_id": "case-ioc", "task_id": "task-ioc",
        "analysis_outcome": "PARTIAL", "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{
            "id": "c2_network",
            "rows": [{
                "type": "ioc", "category": "url", "value": "http://203.0.113.10/x",
                "classification": "STATIC_DERIVED", "confidence": "HIGH",
                "evidence_ids": ["e-url"], "source": "c2_network/string",
                "boundary": "Static value; runtime contact is unobserved.",
            }],
        }],
        "trace": {"evidence_ids": ["e-url"], "claim_ids": [], "tool_run_ids": []},
    })
    assert "`url` **http://203.0.113.10/x**" in markdown
    assert "classification=STATIC_DERIVED, confidence=HIGH" in markdown
    assert "Evidence: ['e-url']" in markdown
    assert "runtime contact is unobserved" in markdown


def test_v3_markdown_turns_high_signal_candidates_into_concrete_static_findings() -> None:
    """Analyst-facing reports explain a recovered path instead of naming a type."""
    markdown = document_to_markdown({
        "report_version": "3.0",
        "report_sections": [
            "Executive Assessment", "Artifact Summary", "Key Static Findings",
            "Verified Mechanisms", "Reconstructed Static Behavior Flow",
            "IOC / Indicators", "Detection / Hunting Opportunities",
            "ATT&CK Reference", "Unknowns / Static Boundaries", "Analysis Coverage",
        ],
        "case_id": "case-candidate", "task_id": "task-candidate",
        "analysis_outcome": "PARTIAL", "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [
            {"id": "behavior_attack", "rows": [
                {
                    "type": "mechanism_observation",
                    "mechanism_id": "loader-path", "mechanism_type": "DYNAMIC_LOADER",
                    "target": "FUN_14000a2c0@0xA2C0", "function": "FUN_14000a2c0",
                    "function_entry": "0xA2C0", "status": "CANDIDATE", "confidence": "HIGH",
                    "inputs": ["%TEMP%\\od_%08x.tmp"],
                    "transformation_or_control": [
                        "CreateFileA -> WriteFile -> LoadLibraryA -> DeleteFileA"
                    ],
                    "outputs": ["local module candidate"], "consumers": ["LoadLibraryA"],
                    "side_effects": ["local file materialization candidate"],
                    "evidence_ids": ["e-loader"], "completeness": 100,
                },
                {
                    "type": "mechanism_observation",
                    "mechanism_id": "xor-noise", "mechanism_type": "DECODE_TRANSFORM",
                    "target": "FUN_140012340", "status": "CANDIDATE", "confidence": "LOW",
                    "inputs": ["unknown"],
                    "transformation_or_control": ["xor_loop_candidate (3 indicators)"],
                    "outputs": ["transformed buffer candidate"],
                    "consumers": ["downstream consumer not recovered"],
                    "evidence_ids": ["e-xor"], "completeness": 50,
                },
            ]},
            {"id": "c2_network", "rows": [
                {
                    "type": "ioc", "category": "url", "value": "http://203.0.113.10/payload.exe",
                    "classification": "STATIC_DERIVED", "confidence": "HIGH",
                    "evidence_ids": ["e-url"], "source": "decode_result",
                    "boundary": "Static value; runtime contact is unobserved.",
                },
                {
                    "type": "hunting_opportunity",
                    "statement": "Hunt DNS/HTTP telemetry for the statically recovered URL.",
                    "evidence_ids": ["e-url"],
                },
            ]},
        ],
        "trace": {"evidence_ids": ["e-loader", "e-xor", "e-url"], "claim_ids": [], "tool_run_ids": []},
    })

    assert "links file materialization, dynamic module loading, and cleanup" in markdown
    assert "http://203.0.113.10/payload.exe" in markdown
    assert "Hunt DNS/HTTP telemetry" in markdown
    assert "xor-noise" not in markdown


def test_one_round_readiness_stamped_on_partial_document() -> None:
    """Readiness is stamped on analysis_quality; PARTIAL reports still emit."""
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement=(
            "Resume.pdf.exe statically recovers a child-process construction: "
            "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`; "
            "runtime execution is unverified."
        ),
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism="CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        condition="static evidence threshold satisfied; runtime execution not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={"api": "CreateProcessW", "command": "FoxitPDFReader.exe", "creation_flags": "0x000f4240"},
        anchor={"function_entry": "140004605"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[process_trace],
        claims=[process_claim],
        claim_evidence=[
            SimpleNamespace(claim_id="claim-process", evidence_id="trace-process", stance="SUPPORTS"),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    readiness = document["analysis_quality"]["one_round_readiness"]
    assert "complete" in readiness
    assert isinstance(readiness["violations"], list)
    markdown = document_to_markdown(document)
    assert "FoxitPDFReader.exe" in markdown
    assert document["analysis_quality"]["one_round_readiness"]["violations"] == (
        report_one_round_readiness_violations(document, markdown)
    )
    quality_violations = report_analytical_violations(document)
    assert not any("one_round_readiness" in item for item in quality_violations)


def test_join_and_consumer_slots_survive_into_official_get() -> None:
    """C3: persist HOW join/consumer tokens must remain visible in official GET."""
    from threat_report_agent.analyst_report import (
        ANALYST_CONCLUSION_HEADING,
        primary_analyst_violations,
        render_official_markdown,
    )

    xor_claim = SimpleNamespace(
        id="claim-xor",
        module="decryption",
        claim_type="INVESTIGATED_MECHANISM",
        statement="XOR recovered a URL without a linked consumer.",
        subject="Resume.pdf.exe",
        action="may_decode_configuration",
        object="http://example.invalid/gate",
        mechanism=(
            "key_table_modulo_xor_counter plaintext=`http://example.invalid/gate` "
            "consumer=UNKNOWN(consumer)"
        ),
        condition="static decode; consumer not joined",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    process_claim = SimpleNamespace(
        id="claim-process",
        module="execution",
        claim_type="INVESTIGATED_MECHANISM",
        statement="CreateProcessW command without a decode join.",
        subject="Resume.pdf.exe",
        action="may_create_process",
        object="FoxitPDFReader.exe",
        mechanism=(
            "CreateProcessW command=`FoxitPDFReader.exe` "
            "creation_flags=0x000f4240 join=UNKNOWN(join)"
        ),
        condition="static evidence; join not proven",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    xor_trace = SimpleNamespace(
        id="trace-xor",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="decode_result",
        nature="STATIC_DERIVED",
        value={"formula": "key_table_modulo_xor_counter", "decoded_text": "http://example.invalid/gate"},
        anchor={"function_entry": "140001000"},
    )
    process_trace = SimpleNamespace(
        id="trace-process",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={"api": "CreateProcessW", "command": "FoxitPDFReader.exe", "creation_flags": "0x000f4240"},
        anchor={"function_entry": "140004605"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-c3-join"),
        task=SimpleNamespace(
            id="task-c3-join",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[xor_trace, process_trace],
        claims=[xor_claim, process_claim],
        claim_evidence=[
            SimpleNamespace(claim_id="claim-xor", evidence_id="trace-xor", stance="SUPPORTS"),
            SimpleNamespace(claim_id="claim-process", evidence_id="trace-process", stance="SUPPORTS"),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    official = render_official_markdown(document)
    assert ANALYST_CONCLUSION_HEADING in official
    assert "UNKNOWN(consumer)" in official
    assert "UNKNOWN(join)" in official
    assert "JOINED_STATIC" not in official
    assert "PERSISTED_INVESTIGATION" not in official
    assert "FUN_" not in official
    assert primary_analyst_violations(official) == []


def test_official_get_from_report_document_projects_slots_and_revision() -> None:
    """C7: build_report_document → official GET keeps CANDIDATE, ten-question slots, revision."""
    from threat_report_agent.analyst_report import (
        ANALYST_CONCLUSION_HEADING,
        compact_analyst_context,
        primary_analyst_violations,
        render_official_markdown,
    )

    claim = SimpleNamespace(
        id="claim-xor",
        module="decryption",
        claim_type="INVESTIGATED_MECHANISM",
        statement="XOR recovered a URL without a linked consumer.",
        subject="Resume.pdf.exe",
        action="may_decode_configuration",
        object="http://example.invalid/gate",
        mechanism=(
            "key_table_modulo_xor_counter plaintext=`http://example.invalid/gate` "
            "consumer=UNKNOWN(consumer)"
        ),
        condition="static decode; consumer not joined",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
        nature="STATIC_INFERRED",
    )
    evidence = SimpleNamespace(
        id="trace-xor",
        artifact_id="artifact-1",
        tool_run_id="ghidra-1",
        module="static_triage",
        kind="decode_result",
        nature="STATIC_DERIVED",
        value={"formula": "key_table_modulo_xor_counter", "decoded_text": "http://example.invalid/gate"},
        anchor={"function_entry": "140001000"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-c7-slots"),
        task=SimpleNamespace(
            id="task-c7-slots",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
            authoritative_revision_id="rev-c7-report",
        ),
        artifacts=[
            SimpleNamespace(
                id="artifact-1",
                logical_path="Resume.pdf.exe",
                content_sha256="sha256",
                detected_type="pe",
                role="EXECUTABLE",
                obligation="REQUIRED",
                parent_artifact_id=None,
            )
        ],
        tool_runs=[],
        evidence=[evidence],
        claims=[claim],
        claim_evidence=[
            SimpleNamespace(claim_id="claim-xor", evidence_id="trace-xor", stance="SUPPORTS"),
        ],
        relations=[],
        gates=[],
        mechanisms=[],
        selected_modules=["executive_summary", "static_triage"],
    )
    official = render_official_markdown(document)
    context = compact_analyst_context(document)
    assert document["authoritative_revision_id"] == "rev-c7-report"
    assert context["authoritative_revision_id"] == "rev-c7-report"
    assert "`rev-c7-report`" in official
    assert ANALYST_CONCLUSION_HEADING in official
    assert "- What:" in official
    assert "- How:" in official
    assert "- Consumer:" in official
    assert "UNKNOWN(consumer)" in official
    assert "CANDIDATE" in official
    assert "不是活 C2" in official
    assert "APT29" not in official
    assert primary_analyst_violations(official) == []


def test_v3_markdown_omits_unknown_empty_runtime_phase_shells() -> None:
    """C4: ledger markdown must not invent Phase 1–8 empty shells."""
    document = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-c4-phases",
        "task_id": "task-c4-phases",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [
            {
                "id": "executive_summary",
                "title": "Executive Assessment",
                "summary": "bounded static",
                "rows": [
                    {
                        "type": "runtime_sequence",
                        "phases": [
                            {
                                "id": "startup",
                                "title": "Phase 1 — startup / loader",
                                "status": "CANDIDATE",
                                "how": "PE AddressOfEntryPoint=0x1460",
                            },
                            {
                                "id": "anti_analysis",
                                "title": "Phase 2 — environment / anti-analysis",
                                "status": "UNKNOWN",
                                "how": "UNKNOWN(phase not recovered statically)",
                            },
                            {
                                "id": "process",
                                "title": "Phase 5 — process creation / PPID",
                                "status": "CANDIDATE",
                                "how": "CreateProcessW creation_flags=UNKNOWN(creation_flags)",
                            },
                            {
                                "id": "loop",
                                "title": "Phase 8 — loop / repeat",
                                "status": "UNKNOWN",
                                "how": "UNKNOWN(phase not recovered statically)",
                            },
                        ],
                    }
                ],
            }
        ],
    }
    markdown = document_to_markdown(document)
    assert "Phase 1 — startup / loader" in markdown
    assert "Phase 5 — process creation / PPID" in markdown
    assert "Phase 2 — environment / anti-analysis" not in markdown
    assert "Phase 8 — loop / repeat" not in markdown
    assert "UNKNOWN(phase not recovered statically)" not in markdown

