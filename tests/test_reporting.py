from types import SimpleNamespace

from threat_report_agent.reporting import (
    build_report_document,
    build_observed_mechanism_projections,
    document_to_markdown,
    markdown_to_docx,
    report_analytical_violations,
    _select_mechanism_projections,
)


def test_report_analytical_gate_requires_verified_mechanism_provenance() -> None:
    invalid = {"modules": [{"rows": [{"type": "security_finding", "mechanism_id": "m1", "claim_id": "c1", "evidence_ids": ["e1"], "what": "x", "how": "y", "security_meaning": "z", "boundary": "static", "verifier": {"status": "CANDIDATE"}}]}]}
    assert any("not backed" in item for item in report_analytical_violations(invalid))
    valid = {"modules": [{"rows": [{"type": "security_finding", "mechanism_id": "m1", "claim_id": "c1", "evidence_ids": ["e1"], "what": "x", "how": "y", "security_meaning": "z", "boundary": "static", "verifier": {"status": "VERIFIED"}}]}]}
    assert report_analytical_violations(valid) == []


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
