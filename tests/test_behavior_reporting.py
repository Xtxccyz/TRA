from types import SimpleNamespace

from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH,
    _build_assessment,
    build_behavior_findings,
    build_behavior_relations,
    build_catalog_behavior_matrix,
    build_process_flag_projections,
    build_pe_entry_projection,
    build_report_document,
    build_runtime_sequence,
    build_unique_execution_threads,
    document_to_markdown,
    report_one_round_readiness_violations,
    report_v3_quality_violations,
)


def _evidence(evidence_id: str, artifact_id: str = "artifact-1", nature: str = "STATIC_OBSERVED"):
    return SimpleNamespace(
        id=evidence_id,
        artifact_id=artifact_id,
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature=nature,
        value={"api": "LoadLibraryW"},
        anchor={"function_entry": "0x401000"},
    )


def _claim(claim_id: str, module: str = "loader", status: str = "CANDIDATE"):
    return SimpleNamespace(
        id=claim_id,
        module=module,
        claim_type="BEHAVIOR",
        subject="sample.exe",
        action="may_load_or_prepare_memory",
        object="secondary module",
        mechanism="resource -> resolve -> LoadLibraryW",
        condition="static evidence only",
        statement="The sample may prepare and load a secondary module.",
        status=status,
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
    )


def test_behavior_finding_preserves_candidate_status_and_explicit_unknowns() -> None:
    evidence = {"e1": _evidence("e1")}
    finding = build_behavior_findings(
        [_claim("c1")],
        links_by_claim={"c1": ["e1"]},
        evidence_by_id=evidence,
    )[0]

    assert finding["type"] == "behavior_finding"
    assert finding["finding_status"] == "CANDIDATE"
    assert finding["status"] == "CANDIDATE"
    assert finding["claim_ids"] == ["c1"]
    assert finding["supporting_evidence_ids"] == ["e1"]
    assert "runtime execution and intent are not observed" in finding["unknowns"]
    assert finding["maliciousness_assessment"] == "candidate_security_relevant_behavior"
    assert finding["ten_question_protocol"]["loop"]["status"] == "UNKNOWN"
    assert finding["ten_question_protocol"]["loop"]["reason"]


def test_queueuserapc_finding_without_cross_process_is_not_verified_injection() -> None:
    evidence = {"e-apc": _evidence("e-apc")}
    finding = build_behavior_findings(
        [],
        mechanism_projections=[{
            "type": "behavior_finding",
            "finding_id": "apc-queue",
            "claim_id": "c-apc",
            "status": "SUPPORTED",
            "what": "QueueUserAPC",
            "how": "same-process APC queued without a remote thread handle",
            "target": "current thread",
            "inputs": ["APC routine"],
            "transformation_or_control": ["QueueUserAPC"],
            "conditions": ["alertable wait"],
            "outputs": ["queued APC"],
            "consumers": ["current thread"],
            "evidence_ids": ["e-apc"],
            "artifact_id": "artifact-1",
        }],
        links_by_claim={"c-apc": ["e-apc"]},
        evidence_by_id=evidence,
    )[0]

    assert finding["status"] in {"CANDIDATE", "UNKNOWN"}
    assert finding["finding_status"] in {"CANDIDATE", "UNKNOWN"}
    assert finding["status"] not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
    assert str(finding.get("severity") or "").upper() != "HIGH"
    assert finding["adversarial_downgrade"] is True


def test_assessment_does_not_turn_three_candidate_modules_into_high_risk() -> None:
    claims = [_claim(f"c{i}", module) for i, module in enumerate(("loader", "decryption", "c2_network"), start=1)]
    links = {claim.id: [f"e{i}"] for i, claim in enumerate(claims, start=1)}
    summary, rows = _build_assessment(
        task=SimpleNamespace(id="task-1", outcome="PARTIAL", limitations=[]),
        artifacts=[],
        claims=claims,
        links_by_claim=links,
        evidence_by_id={f"e{i}": _evidence(f"e{i}") for i in range(1, 4)},
        model_calls=[],
        mechanisms=[],
        mechanism_projections=[],
        behavior_findings=build_behavior_findings(
            claims,
            links_by_claim=links,
            evidence_by_id={f"e{i}": _evidence(f"e{i}") for i in range(1, 4)},
        ),
    )

    assessment = rows[0]
    assert assessment["risk"] != "HIGH"
    assert assessment["severity"] == "UNASSESSED"
    assert assessment["conclusion_confidence"] == "LOW"
    assert "Evidence confidence: LOW" in summary
    assert "module count" not in assessment["confidence_basis"]


def test_behavior_relation_requires_real_support_and_keeps_artifact_scope() -> None:
    evidence = {"e1": _evidence("e1", "artifact-1")}
    findings = [
        {"finding_id": "bf-source", "artifact_id": "artifact-1", "claim_ids": ["c1"]},
        {"finding_id": "bf-target", "artifact_id": "artifact-2", "claim_ids": ["c2"]},
    ]
    relations = [
        SimpleNamespace(
            id="r1",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-2",
            relation_type="DROPS",
            evidence_id="e1",
            claim_id=None,
            status="OBSERVED",
        ),
        # An unbacked relation must not become a graph edge merely because its
        # artifact endpoints happen to exist.
        SimpleNamespace(
            id="r2",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-2",
            relation_type="EXECUTES",
            evidence_id=None,
            claim_id=None,
            status="CONFIRMED",
        ),
    ]

    projected = build_behavior_relations(
        relations,
        findings,
        evidence_by_id=evidence,
    )

    assert [row["relation_id"] for row in projected] == ["r1"]
    assert projected[0]["type"] == "behavior_relation"
    assert projected[0]["validation_status"] == "OBSERVED"
    assert projected[0]["source_finding_id"] == "bf-source"
    assert projected[0]["target_finding_id"] == "bf-target"
    assert projected[0]["evidence_ids"] == ["e1"]


def test_behavior_relation_drops_dangling_claim_only_edge() -> None:
    findings = [
        {"finding_id": "bf-source", "artifact_id": "artifact-1", "claim_ids": ["c1"]},
        {"finding_id": "bf-target", "artifact_id": "artifact-2", "claim_ids": ["c2"]},
    ]
    relation = SimpleNamespace(
        id="dangling",
        source_artifact_id="artifact-1",
        target_artifact_id="artifact-2",
        relation_type="EXECUTES",
        evidence_id=None,
        claim_id="missing-claim",
        status="CONFIRMED",
    )
    assert build_behavior_relations([relation], findings, evidence_by_id={}) == []


def test_same_artifact_injects_is_not_closed_injection_behavior() -> None:
    evidence = {"e1": _evidence("e1", "artifact-1")}
    findings = [
        {"finding_id": "bf-same", "artifact_id": "artifact-1", "claim_ids": ["c1"]},
    ]
    relations = [
        SimpleNamespace(
            id="r-self-inject",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-1",
            relation_type="INJECTS",
            evidence_id="e1",
            claim_id="c1",
            status="INFERRED",
        ),
        SimpleNamespace(
            id="r-cross-drops",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-2",
            relation_type="DROPS",
            evidence_id="e1",
            claim_id=None,
            status="OBSERVED",
        ),
    ]
    projected = build_behavior_relations(relations, findings, evidence_by_id=evidence)
    injects = [row for row in projected if str(row.get("relation_type") or "").upper() == "INJECTS"]
    assert injects, "self-loop remains auditable but must not be a closed injection"
    row = injects[0]
    assert row["source_artifact_id"] == row["target_artifact_id"] == "artifact-1"
    assert str(row.get("status") or "").upper() in {"CANDIDATE", "UNKNOWN"}
    assert str(row.get("validation_status") or "").upper() in {"CANDIDATE", "UNKNOWN"}
    assert str(row.get("status") or "").upper() not in {"VERIFIED", "SUPPORTED", "CONFIRMED", "INFERRED"}
    assert row.get("is_behavior_edge") is not True
    assert row.get("adversarial_downgrade") is True
    drops = [row for row in projected if str(row.get("relation_type") or "").upper() == "DROPS"]
    assert drops and drops[0]["validation_status"] == "OBSERVED"


def test_distinct_artifact_injects_remains_when_cross_process() -> None:
    evidence = {"e1": _evidence("e1", "artifact-1")}
    findings = [
        {"finding_id": "bf-source", "artifact_id": "artifact-1", "claim_ids": ["c1"]},
        {"finding_id": "bf-target", "artifact_id": "artifact-2", "claim_ids": ["c2"]},
    ]
    projected = build_behavior_relations(
        [SimpleNamespace(
            id="r-cross-inject",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-2",
            relation_type="INJECTS",
            evidence_id="e1",
            claim_id="c1",
            status="INFERRED",
        )],
        findings,
        evidence_by_id=evidence,
    )
    assert len(projected) == 1
    assert projected[0]["relation_type"] == "INJECTS"
    assert projected[0]["status"] == "INFERRED"
    assert projected[0].get("adversarial_downgrade") is not True
    assert projected[0]["is_behavior_edge"] is True


def test_report_markdown_does_not_present_same_artifact_injects_as_injection() -> None:
    evidence = _evidence("e1", "artifact-1")
    claim = _claim("c1")
    document = build_report_document(
        case=SimpleNamespace(id="case-inject"),
        task=SimpleNamespace(
            id="task-inject", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
            analysis_class="BOUNDED_STATIC_ANALYSIS", coverage={},
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.dll", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id="c1", evidence_id="e1", stance="SUPPORTS")],
        relations=[SimpleNamespace(
            id="r-self-inject",
            source_artifact_id="artifact-1",
            target_artifact_id="artifact-1",
            relation_type="INJECTS",
            evidence_id="e1",
            claim_id="c1",
            status="INFERRED",
        )],
        gates=[], model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )

    markdown = document_to_markdown(document)
    assert "INJECTS; INFERRED" not in markdown
    assert not any(
        "INJECTS" in line and "-->" in line and line.count("`sample.dll`") >= 2
        for line in markdown.splitlines()
    )
    relation_rows = [
        row for module in document["modules"]
        for row in module.get("rows", [])
        if isinstance(row, dict) and (
            row.get("type") == "behavior_relation"
            or str(row.get("relation") or "").upper() == "INJECTS"
        )
    ]
    for row in relation_rows:
        status = str(row.get("status") or row.get("validation_status") or row.get("state") or "").upper()
        assert status not in {"VERIFIED", "SUPPORTED", "CONFIRMED", "INFERRED"}
    critic = document["analysis_quality"]["critic"]
    assert any(item.get("rule_id") == "INJECTS_SELF_LOOP" for item in critic.get("overclaim_checks", []))


def test_report_v3_quality_gate_requires_behavior_template_fields() -> None:
    document = {
        "report_version": "3.0",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "case_id": "case-1",
        "task_id": "task-1",
        "report_sections": [
            "Executive Assessment", "Artifact Summary", "Key Static Findings",
            "Verified Mechanisms", "Reconstructed Static Behavior Flow",
            "IOC / Indicators", "Detection / Hunting Opportunities",
            "ATT&CK Reference", "Unknowns / Static Boundaries", "Analysis Coverage",
        ],
        "modules": [{"id": "behavior_attack", "rows": [{
            "type": "behavior_finding",
            "finding_id": "bf-incomplete",
            "what": "candidate",
            "finding_status": "CANDIDATE",
            "evidence_ids": ["e1"],
        }]}],
    }
    violations = report_v3_quality_violations(document)
    assert any("behavior finding" in item and "missing how" in item for item in violations)
    assert any("behavior finding" in item and "missing unknowns" in item for item in violations)


def test_report_v3_m06_gate_rejects_complete_report_with_blocked_quality() -> None:
    document = {
        "report_version": "3.0",
        "analysis_class": "FULL_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "COMPLETE",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "analysis_quality": {
            "readiness": "READY_FOR_REPORT",
            "critic": {"status": "BLOCKED", "overclaim_checks": []},
            "s4_orchestration": [{"thread_id": "thread-1", "status": "BLOCKED"}],
        },
        "modules": [],
    }

    violations = report_v3_quality_violations(document)

    assert any("blocked S4" in item for item in violations)
    assert any("critic is BLOCKED" in item for item in violations)


def test_report_v3_m06_gate_allows_explicitly_bounded_quality() -> None:
    document = {
        "report_version": "3.0",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "analysis_quality": {
            "readiness": "BOUNDED_WITH_LIMITATIONS",
            "critic": {
                "status": "BLOCKED",
                "overclaim_checks": [{"row_id": "candidate-1", "status": "BLOCKED"}],
            },
            "s4_orchestration": [{"thread_id": "thread-1", "status": "BLOCKED"}],
        },
        "modules": [],
    }

    assert report_v3_quality_violations(document) == []


def test_report_v3_m06_gate_rejects_closed_finding_flagged_by_critic() -> None:
    document = {
        "report_version": "3.0",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "analysis_quality": {
            "readiness": "BOUNDED_WITH_LIMITATIONS",
            "critic": {
                "status": "BLOCKED",
                "overclaim_checks": [{"row_id": "mechanism-1", "status": "BLOCKED"}],
            },
            "s4_orchestration": [],
        },
        "modules": [{"id": "static_triage", "rows": [{
            "type": "security_finding",
            "mechanism_id": "mechanism-1",
            "claim_id": "claim-1",
            "evidence_ids": ["e1"],
            "status": "VERIFIED",
        }]}],
    }

    violations = report_v3_quality_violations(document)

    assert any("overclaim checks on closed findings" in item for item in violations)


def test_report_quality_preserves_thread_inputs_for_s4_orchestration() -> None:
    document = build_report_document(
        case=SimpleNamespace(id="case-s4"),
        task=SimpleNamespace(
            id="task-s4", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
            analysis_class="BOUNDED_STATIC_ANALYSIS", coverage={},
        ),
        artifacts=[], tool_runs=[], evidence=[_evidence("e1")], claims=[],
        claim_evidence=[], relations=[], gates=[], model_calls=[],
        investigation_threads=[SimpleNamespace(
            id="thread-closed", state="CLAIM_READY", question="Who consumes the decoded buffer?",
            action_ids=["action-1"], evidence_ids=["e1"],
        )],
        investigation_actions=[SimpleNamespace(
            id="action-1", action_type="GET_CALLEES", reason="resolve consumer",
            parameters={}, status="SUCCEEDED", result_evidence_ids=["e1"],
        )],
        selected_modules=["executive_summary"],
    )

    s4 = document["analysis_quality"]["s4_orchestration"]
    assert s4 == [{
        "thread_id": "thread-closed",
        "state": "CLAIM_READY",
        "status": "CLOSED",
        "question": "Who consumes the decoded buffer?",
        "action_ids": ["action-1"],
        "evidence_ids": ["e1"],
        "reason": "thread reached a verifier-ready state with recorded actions and evidence",
    }]


def test_report_exposes_behavior_projection_without_attribution_summary() -> None:
    evidence = _evidence("e1")
    claim = _claim("c1")
    attribution = SimpleNamespace(
        id="c-attribution",
        module="attribution",
        claim_type="BEHAVIOR",
        subject="sample.exe",
        action="matches",
        object="APT29",
        mechanism="family resemblance",
        condition="static only",
        statement="The sample is attributed to APT29.",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-1"),
        task=SimpleNamespace(
            id="task-1", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[evidence], claims=[claim, attribution],
        claim_evidence=[SimpleNamespace(claim_id="c1", evidence_id="e1", stance="SUPPORTS")],
        relations=[], gates=[], model_calls=[], selected_modules=["executive_summary", "behavior_attack"],
    )

    behavior_rows = document["modules"][1]["rows"]
    finding = next(row for row in behavior_rows if row.get("type") == "behavior_finding")
    assert finding["finding_status"] == "CANDIDATE"
    summary = document["modules"][0]["rows"][0]["summary"]
    assert "APT29" not in summary
    markdown = document_to_markdown(document)
    assert "Behavior Overview" in markdown
    assert "CANDIDATE" in markdown


def test_behavior_finding_materializes_unknown_fields_without_treating_markers_as_facts() -> None:
    """Missing semantic fields stay explicit unknowns in the analyst view."""
    evidence = {"e1": _evidence("e1")}
    claim = SimpleNamespace(
        id="c-unknown",
        module="loader",
        claim_type="BEHAVIOR",
        subject="UNKNOWN(subject)",
        action="may_load_or_prepare_memory",
        object="UNKNOWN(object)",
        mechanism="UNKNOWN(mechanism)",
        condition="NOT_IDENTIFIED(condition)",
        statement="A loader-related path is a candidate.",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
    )

    finding = build_behavior_findings(
        [claim],
        links_by_claim={"c-unknown": ["e1"]},
        evidence_by_id=evidence,
    )[0]

    for field in ("target", "condition", "output", "consumer"):
        values = finding[field]
        assert values, field
        assert any(str(value).startswith("UNKNOWN(") for value in values), field
    assert any("not recovered" in item for item in finding["unknowns"])
    assert finding["finding_status"] == "CANDIDATE"


def test_attribution_claim_is_not_projected_as_behavior_finding_or_assessment_text() -> None:
    evidence = {"e1": _evidence("e1")}
    attribution = SimpleNamespace(
        id="c-attr",
        module="attribution",
        claim_type="ATTRIBUTION",
        subject="sample.exe",
        action="associated_with",
        object="APT29",
        mechanism="family resemblance",
        condition="static only",
        statement="The sample is associated with APT29.",
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
    )

    findings = build_behavior_findings(
        [attribution],
        links_by_claim={"c-attr": ["e1"]},
        evidence_by_id=evidence,
    )
    assert findings == []

    summary, rows = _build_assessment(
        task=SimpleNamespace(id="task-attr", outcome="PARTIAL", limitations=[]),
        artifacts=[],
        claims=[attribution],
        links_by_claim={"c-attr": ["e1"]},
        evidence_by_id=evidence,
        model_calls=[],
        mechanisms=[],
        mechanism_projections=[],
        behavior_findings=[],
    )
    assert "APT29" not in summary
    assert rows[0]["finding_count"] == 0


def test_behavior_overview_renders_condition_output_consumer_and_evidence() -> None:
    evidence = _evidence("e1")
    claim = _claim("c-full")
    document = build_report_document(
        case=SimpleNamespace(id="case-full"),
        task=SimpleNamespace(
            id="task-full", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[], tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id="c-full", evidence_id="e1", stance="SUPPORTS")],
        relations=[], gates=[], model_calls=[], selected_modules=["executive_summary"],
    )
    markdown = document_to_markdown(document)
    assert "Condition:" in markdown
    assert "Output:" in markdown
    assert "Consumer:" in markdown
    assert "Evidence:" in markdown


def test_assessment_leads_with_what_how_unknowns_not_claim_inventory() -> None:
    evidence = {"e1": _evidence("e1")}
    claim = _claim("c-summary")
    findings = build_behavior_findings(
        [claim],
        links_by_claim={"c-summary": ["e1"]},
        evidence_by_id=evidence,
    )
    summary, rows = _build_assessment(
        task=SimpleNamespace(id="task-summary", outcome="PARTIAL", limitations=[]),
        artifacts=[SimpleNamespace(id="artifact-1")],
        claims=[claim],
        links_by_claim={"c-summary": ["e1"]},
        evidence_by_id=evidence,
        model_calls=[],
        mechanisms=[],
        mechanism_projections=[],
        behavior_findings=findings,
    )
    assert summary.startswith("What:")
    assert "How:" in summary
    assert "Key unknowns:" in summary
    assert "The task produced" not in summary
    assert rows[0]["what"]
    assert rows[0]["how"]


def test_catalog_matrix_lists_only_discovered_behaviors() -> None:
    thread_evidence = SimpleNamespace(
        id="e-thread",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "CreateThread", "target_name": "CreateThread"},
        anchor={"function_entry": "0x401000"},
    )
    load_evidence = _evidence("e-load")
    thread_finding = {
        "type": "behavior_finding",
        "finding_id": "bf-thread",
        "catalog_id": "thread-and-callback",
        "what": "Creates an OS worker thread",
        "how": "CreateThread start routine is not yet recovered",
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-thread"],
        "supporting_evidence_ids": ["e-thread"],
    }
    matrix = build_catalog_behavior_matrix(
        [thread_finding],
        evidence_by_id={"e-thread": thread_evidence, "e-load": load_evidence},
    )
    discovered_ids = [row["catalog_id"] for row in matrix["discovered"]]
    assert discovered_ids == ["thread-and-callback"]
    assert "lateral-movement" not in discovered_ids
    assert "impact-and-resource-abuse" not in discovered_ids
    assert "file-operations" not in discovered_ids

    unclosed = build_catalog_behavior_matrix(
        [],
        evidence_by_id={"e-thread": thread_evidence},
    )
    assert unclosed["discovered"] == []
    assert any(item["catalog_id"] == "thread-and-callback" for item in unclosed["unclosed_high_value"])
    assert any(item["catalog_id"] == "network-transport" for item in unclosed["unclosed_high_value"])
    assert any(
        "transport API not recovered" in str(item.get("reason") or "")
        for item in unclosed["unclosed_high_value"]
        if item.get("catalog_id") == "network-transport"
    )
    assert any(item["catalog_id"] == "parent-process-spoofing" for item in unclosed["unclosed_high_value"])
    assert any(
        "chain not recovered" in str(item.get("reason") or "")
        for item in unclosed["unclosed_high_value"]
        if item.get("catalog_id") == "parent-process-spoofing"
    )

    chain_evidence = SimpleNamespace(
        id="e-ppid",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value={"relation": "parent_handle_to_attribute", "api": "UpdateProcThreadAttribute"},
        anchor={"function_entry": "0x140004605"},
    )
    chain_matrix = build_catalog_behavior_matrix(
        [],
        evidence_by_id={"e-ppid": chain_evidence},
    )
    assert any(
        "PPID specialist token 0x09080008 not recovered" in str(item.get("reason") or "")
        for item in chain_matrix["unclosed_high_value"]
        if item.get("catalog_id") == "parent-process-spoofing"
    )


def test_catalog_matrix_records_process_and_loader_remainder() -> None:
    """Kunglao leftover remainder: seeded process/loader HOW cannot vanish from Unknowns."""
    process_evidence = SimpleNamespace(
        id="e-process",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "CreateProcessW", "target_name": "CreateProcessW"},
        anchor={"function_entry": "FUN_140004605"},
    )
    loader_evidence = SimpleNamespace(
        id="e-loader",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "GetProcAddress", "target_name": "GetProcAddress"},
        anchor={"function_entry": "140038dd0"},
    )
    matrix = build_catalog_behavior_matrix(
        [],
        evidence_by_id={"e-process": process_evidence, "e-loader": loader_evidence},
    )
    unclosed_ids = {item["catalog_id"] for item in matrix["unclosed_high_value"]}
    assert "process-creation" in unclosed_ids
    assert "loader-and-api-resolution" in unclosed_ids
    assert matrix["discovered"] == []
    process_row = next(item for item in matrix["unclosed_high_value"] if item["catalog_id"] == "process-creation")
    loader_row = next(item for item in matrix["unclosed_high_value"] if item["catalog_id"] == "loader-and-api-resolution")
    assert process_row["status"] == "UNKNOWN"
    assert "UNKNOWN(creation_flags)" in str(process_row.get("reason") or "")
    assert "open investigation gap" not in str(process_row.get("reason") or "").casefold()
    assert loader_row["status"] == "UNKNOWN"
    assert str(loader_row.get("reason") or "").startswith("UNKNOWN(what/how):")
    assert "open investigation gap" not in str(loader_row.get("reason") or "").casefold()


def test_unclosed_high_value_slots_are_unknown_not_open_gap() -> None:
    thread_evidence = SimpleNamespace(
        id="e-thread",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "CreateThread", "target_name": "CreateThread"},
        anchor={"function_entry": "0x401000"},
    )
    matrix = build_catalog_behavior_matrix(
        [],
        evidence_by_id={"e-thread": thread_evidence},
    )
    thread_row = next(
        item for item in matrix["unclosed_high_value"]
        if item["catalog_id"] == "thread-and-callback"
    )
    assert thread_row["status"] == "UNKNOWN"
    assert "UNKNOWN(start_routine)" in thread_row["reason"]
    assert "open investigation gap" not in thread_row["reason"].casefold()


def test_recovered_unique_os_closes_thread_and_callback_catalog() -> None:
    evidence = {
        "e-call": SimpleNamespace(
            id="e-call",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateThread", "target_name": "CreateThread"},
            anchor={"function_entry": "0x401000"},
        ),
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
    }
    matrix = build_catalog_behavior_matrix([], evidence_by_id=evidence)
    discovered = next(
        row for row in matrix["discovered"] if row["catalog_id"] == "thread-and-callback"
    )
    assert "start=0x401500" in str(discovered["how"])
    assert discovered["status"] == "CANDIDATE"
    assert not any(
        item["catalog_id"] == "thread-and-callback"
        for item in matrix["unclosed_high_value"]
    )


def test_cover_findings_drop_fun_dump_and_unknown_behavior_when_named_catalog_exists() -> None:
    persist = {
        "type": "behavior_finding",
        "finding_id": "bf-ppid-persist",
        "catalog_id": "parent-process-spoofing",
        "what": (
            "Resume.pdf.exe.VIR statically recovers a parent-process attribute chain "
            "attribute=0x00020000; parent=UNKNOWN(parent identity)"
        ),
        "how": (
            "UpdateProcThreadAttribute -> CreateToolhelp32Snapshot -> Process32FirstW; "
            "attribute=0x00020000; parent=UNKNOWN(parent identity)"
        ),
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-ppid"],
        "supporting_evidence_ids": ["e-ppid"],
        "target": "Resume.pdf.exe.VIR",
    }
    dump = {
        "type": "behavior_finding",
        "finding_id": "bf-ppid-dump",
        "catalog_id": "parent-process-spoofing",
        "what": "parent-process-spoofing Resume.pdf.exe.VIR",
        "how": (
            "FUN_140004605@140004605: GetConsoleWindow(0x14004cb10) -> GetTickCount64 -> "
            "OpenProcess -> UpdateProcThreadAttribute(Attribute=0x20000) -> CreateProcessW"
        ),
        "transformation_or_control": [
            "FUN_140004605@140004605: GetConsoleWindow(0x14004cb10) -> GetTickCount64 -> "
            "OpenProcess -> UpdateProcThreadAttribute(Attribute=0x20000) -> CreateProcessW"
        ],
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-ppid"],
        "supporting_evidence_ids": ["e-ppid"],
        "target": "Resume.pdf.exe.VIR",
    }
    noise = {
        "type": "behavior_finding",
        "finding_id": "bf-unknown",
        "catalog_id": "unknown_behavior",
        "what": "process_execution candidate",
        "how": (
            "FUN_140004605@140004605: GetConsoleWindow -> ShowWindow -> GetTickCount64"
        ),
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-ppid"],
        "supporting_evidence_ids": ["e-ppid"],
        "target": "FUN_140004605@140004605",
    }
    document = {
        "report_version": "3.0",
        "report_sections": ["Executive Assessment"],
        "case_id": "case-cover",
        "task_id": "task-cover",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [
            {
                "id": "executive_summary",
                "title": "执行摘要",
                "summary": "cover noise regression",
                "rows": [
                    persist,
                    dump,
                    noise,
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {
                                "catalog_id": "parent-process-spoofing",
                                "category": "identity",
                                "status": "CANDIDATE",
                                "what": persist["what"],
                                "how": persist["how"],
                                "evidence_ids": ["e-ppid"],
                            }
                        ],
                        "unclosed_high_value": [],
                    },
                ],
            }
        ],
        "analysis_quality": {},
        "analysis_coverage": {},
    }
    markdown = document_to_markdown(document)
    overview = markdown.split("### Behavior Overview", 1)[-1].split("## 3.", 1)[0]
    findings = markdown.split("## 3. Key Static Findings", 1)[-1].split("## 4.", 1)[0]
    cover = overview + findings
    assert "attribute=0x00020000" in cover
    assert "GetConsoleWindow" not in cover
    assert "unknown_behavior" not in cover
    assert "process_execution candidate" not in cover


def test_unique_execution_threads_are_projected_separately_from_injection() -> None:
    evidence = {
        "e-thread": SimpleNamespace(
            id="e-thread",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateThread", "target_name": "CreateThread"},
            anchor={"function_entry": "0x401000", "rva": 4096},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="UNKNOWN",
            value={"status": "DISABLED_BY_POLICY", "simulator": "unicorn"},
            anchor={"type": "unique_thread_emulation", "function_entry": "0x401000"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["api"] == "CreateThread"
    assert rows[0]["function_entry"] == "0x401000"
    assert rows[0]["emulator_status"] == "DISABLED_BY_POLICY"


def test_unique_execution_threads_use_recovered_lpstartaddress() -> None:
    evidence = {
        "e-call": SimpleNamespace(
            id="e-call",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateThread", "target_name": "CreateThread"},
            anchor={"function_entry": "0x401000"},
        ),
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["start_routine"] == "0x401500"
    assert rows[0]["parameter"] == "0x40a000"
    assert rows[0]["start_routine"] != "UNKNOWN(start_routine)"


def test_runtime_sequence_orders_recovered_phases_and_keeps_unknown_fallbacks() -> None:
    findings = [
        {
            "catalog_id": "loader-and-api-resolution",
            "finding_status": "SUPPORTED",
            "what": "resolves WinHttp APIs",
            "how": "GetProcAddress consumer=WinHttpOpen",
            "ten_question_protocol": {
                "consumer": {"status": "ANSWERED", "value": "WinHttpSendRequest"},
                "failure_fallback": {"status": "ANSWERED", "value": "schtasks /Create fallback"},
            },
        },
        {
            "catalog_id": "parent-process-spoofing",
            "finding_status": "CANDIDATE",
            "what": "PPID spoof via UpdateProcThreadAttribute",
            "how": "attribute=PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        },
        {
            "catalog_id": "network-transport",
            "finding_status": "CANDIDATE",
            "what": "WinHttp download",
            "how": "WinHttpSendRequest",
        },
    ]
    phases = build_runtime_sequence(findings)
    ids = [item["id"] for item in phases]
    assert ids == [
        "startup",
        "anti_analysis",
        "decode",
        "network",
        "process",
        "fallback",
        "thread",
        "loop",
    ]
    by_id = {item["id"]: item for item in phases}
    assert by_id["startup"]["status"] == "SUPPORTED"
    assert by_id["process"]["status"] == "CANDIDATE"
    assert "PPID" in by_id["process"]["how"]
    assert by_id["network"]["status"] == "CANDIDATE"
    assert by_id["anti_analysis"]["status"] == "UNKNOWN"
    assert "schtasks" in by_id["fallback"]["how"]
    assert by_id["loop"]["status"] == "UNKNOWN"


def test_unique_thread_body_reads_start_routine_loop_and_exit() -> None:
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "entry": "0x401500",
                "loop": "poll until named event",
                "exit": "return when event is signaled",
                "shared_state": "work item at lpParameter",
            },
            anchor={"function_entry": "0x401500"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x401500"
    assert rows[0]["loop"] == "poll until named event"
    assert rows[0]["exit"] == "return when event is signaled"
    assert rows[0]["shared_state"] == "work item at lpParameter"


def test_unique_thread_emulator_status_matches_normalized_start_address() -> None:
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="UNKNOWN",
            value={"status": "SUCCEEDED", "simulator": "unicorn"},
            anchor={"function_entry": "0x000401500"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["emulator_status"] == "SUCCEEDED"


def test_unique_thread_emulator_status_prefers_worker_over_deferred_placeholder() -> None:
    """Kunglao leftover dump: DEFERRED_TO_WORKER must not hide Unicorn SUCCEEDED."""
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "FUN_1400040b9",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x140038ae0", "resolved": True},
                ],
            },
            anchor={"function_entry": "FUN_1400040b9"},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-emu",
            module="static_triage",
            kind="simulation_result",
            nature="EMULATION_OBSERVED",
            value={"status": "SUCCEEDED", "simulator": "unicorn", "function_entry": "0x140038ae0"},
            anchor={"function_entry": "FUN_140038ae0"},
        ),
        "e-deferred": SimpleNamespace(
            id="e-deferred",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="STATIC_INFERRED",
            value={
                "status": "DEFERRED_TO_WORKER",
                "simulator": "unicorn",
                "stop_reason": "DEFERRED_TO_WORKER",
                "function_entry": "0x140038ae0",
            },
            anchor={"function_entry": "0x140038ae0"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x140038ae0"
    assert rows[0]["emulator_status"] == "SUCCEEDED"


def test_unique_thread_emulator_status_skips_placeholder_when_worker_succeeded_elsewhere() -> None:
    """HOW6: SUPERSEDED keyed to start VA must not hide overall Unicorn SUCCEEDED."""
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "FUN_1400040b9",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x140038ae0", "resolved": True},
                ],
            },
            anchor={"function_entry": "FUN_1400040b9"},
        ),
        "e-placeholder": SimpleNamespace(
            id="e-placeholder",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="STATIC_INFERRED",
            value={
                "status": "SUPERSEDED_BY_WORKER",
                "simulator": "unicorn",
                "function_entry": "0x140038ae0",
            },
            anchor={"function_entry": "0x140038ae0"},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-emu",
            module="controlled-emulator",
            kind="simulation_result",
            nature="EMULATION_OBSERVED",
            value={"status": "SUCCEEDED", "simulator": "unicorn"},
            anchor={},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x140038ae0"
    assert rows[0]["emulator_status"] == "OVERALL_SUCCEEDED"
    assert rows[0]["emulator_status"] != "SUPERSEDED_BY_WORKER"


def test_unique_thread_body_uses_start_routine_call_targets() -> None:
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "entry": "0x401500",
                "call_targets": [
                    {"target_name": "WaitForSingleObject"},
                    {"target_name": "WinHttpSendRequest"},
                    {"target_name": "ExitThread"},
                ],
                "data_references": [{"text": "work_item at lpParameter"}],
            },
            anchor={"function_entry": "0x401500"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x401500"
    assert "WaitForSingleObject" in rows[0]["loop"]
    assert "WinHttpSendRequest" in rows[0]["loop"]
    assert "schtasks" not in rows[0]["loop"].casefold()
    assert "ExitThread" in rows[0]["exit"]
    assert "work_item" in rows[0]["shared_state"]


def test_unique_thread_body_joins_ghidra_fun_label_to_hex_start() -> None:
    """Kunglao leftover remainder: persist FUN_* body must join recovered lpStartAddress."""
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "1400440b9",
                "arguments": [
                    {
                        "index": 2,
                        "name": "lpStartAddress",
                        "value": "0x140038ae0",
                        "resolved": True,
                    },
                    {
                        "index": 3,
                        "name": "lpParameter",
                        "value": "0x8",
                        "resolved": True,
                    },
                ],
            },
            anchor={"function_entry": "1400440b9"},
        ),
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "FUN_140038ae0",
                "entry": "FUN_140038ae0",
                "call_targets": [
                    {"target_name": "WaitForSingleObject"},
                    {"target_name": "ExitThread"},
                ],
                "data_references": [{"text": "work_item"}],
            },
            anchor={"function_entry": "FUN_140038ae0"},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="STATIC_INFERRED",
            value={"status": "SUCCEEDED", "simulator": "unicorn", "stop_reason": "UNMAPPED_DATA"},
            anchor={"function_entry": "FUN_140038ae0"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x140038ae0"
    assert "WaitForSingleObject" in rows[0]["loop"]
    assert "ExitThread" in rows[0]["exit"]
    assert "work_item" in rows[0]["shared_state"]
    assert rows[0]["emulator_status"] == "SUCCEEDED"


def test_unique_thread_body_joins_name_only_fun_label_to_hex_start() -> None:
    """Ghidra persist may store FUN_* in name without a numeric entry field."""
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "arguments": [
                    {
                        "index": 2,
                        "name": "lpStartAddress",
                        "value": "0x140038ae0",
                        "resolved": True,
                    },
                ],
            },
            anchor={"function_entry": "1400440b9"},
        ),
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "FUN_140038ae0",
                "loop": "poll until named event",
                "exit": "return when event is signaled",
                "shared_state": "work item at lpParameter",
            },
            anchor={},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x140038ae0"
    assert rows[0]["loop"] == "poll until named event"
    assert rows[0]["exit"] == "return when event is signaled"
    assert rows[0]["shared_state"] == "work item at lpParameter"


def test_unique_thread_body_uses_ghidra_semantic_summary_not_invented_fallback() -> None:
    evidence = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        "e-summary": SimpleNamespace(
            id="e-summary",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "start_routine",
                "function_entry": "0x401500",
                "call_sequence": [
                    {"api": "WaitForSingleObject"},
                    {"api": "WinHttpSendRequest"},
                    {"api": "ExitThread"},
                ],
                "consumers": [{"api": "WinHttpSendRequest"}],
            },
            anchor={"function_entry": "0x401500"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows[0]["start_routine"] == "0x401500"
    assert "WaitForSingleObject" in rows[0]["loop"]
    assert "WinHttpSendRequest" in rows[0]["loop"]
    assert "schtasks" not in rows[0]["loop"].casefold()
    assert "ExitThread" in rows[0]["exit"]


def test_unique_thread_exit_from_start_routine_ret_and_one_hop_callee() -> None:
    """HOW11 Unique OS recovered TLS loop but left exit=UNKNOWN(exit)."""
    ret_only = {
        "e-trace": SimpleNamespace(
            id="e-trace",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={
                "api": "CreateThread",
                "arguments": [
                    {"index": 2, "name": "lpStartAddress", "value": "0x140038ae0", "resolved": True},
                ],
            },
            anchor={"function_entry": "1400440b9"},
        ),
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_instruction_window",
            nature="STATIC_OBSERVED",
            value={
                "entry": "0x140038ae0",
                "call_targets": [{"target_name": "TlsGetValue"}, {"target_name": "FUN_1400165e0"}],
                "instructions": [
                    {"text": "CALL TlsGetValue"},
                    {"text": "RET"},
                ],
            },
            anchor={"function_entry": "0x140038ae0"},
        ),
    }
    ret_rows = build_unique_execution_threads(ret_only)
    assert "TlsGetValue" in ret_rows[0]["loop"]
    assert "UNKNOWN(exit)" not in ret_rows[0]["exit"]
    assert "return" in ret_rows[0]["exit"].casefold()

    hop = {
        **ret_only,
        "e-body": SimpleNamespace(
            id="e-body",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_semantic_summary",
            nature="STATIC_DERIVED",
            value={
                "function_entry": "0x140038ae0",
                "call_sequence": [
                    {"api": "TlsGetValue"},
                    {"api": "FUN_1400165e0"},
                    {"api": "TlsSetValue"},
                ],
            },
            anchor={"function_entry": "FUN_140038ae0"},
        ),
        "e-callee": SimpleNamespace(
            id="e-callee",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_semantic_summary",
            nature="STATIC_DERIVED",
            value={
                "function_entry": "FUN_1400165e0",
                "call_sequence": [
                    {"api": "WaitOnAddress"},
                    {"api": "ExitThread"},
                ],
            },
            anchor={"function_entry": "FUN_1400165e0"},
        ),
    }
    hop_rows = build_unique_execution_threads(hop)
    assert "TlsGetValue" in hop_rows[0]["loop"]
    assert "ExitThread" in hop_rows[0]["exit"]
    assert "UNKNOWN(exit)" not in hop_rows[0]["exit"]


def test_catalog_matrix_drops_unique_or_unknown_when_named_behaviors_exist() -> None:
    """HOW11 leftover drowned named HOW under unique-or-unknown FUN_* flood."""
    named = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "CreateProcessW FoxitPDFReader.exe",
        "how": "command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-process"],
    }
    unknown = {
        "type": "behavior_finding",
        "catalog_id": "unique-or-unknown",
        "what": "unique-or-unknown FUN_140046090@140046090",
        "how": "CreateWaitableTimerExW",
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-unknown"],
    }
    matrix = build_catalog_behavior_matrix([named, unknown], evidence_by_id={})
    discovered_ids = [row["catalog_id"] for row in matrix["discovered"]]
    assert "process-creation" in discovered_ids
    assert "unique-or-unknown" not in discovered_ids


def test_catalog_matrix_keeps_persist_process_how_over_semantic_flood() -> None:
    """HOW11 process-creation How was ShellExecuteW/env-string dump over Foxit flags."""
    persist = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`",
        "how": "CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-process", "e-sem"],
    }
    evidence = {
        "e-process": SimpleNamespace(
            id="e-process",
            artifact_id="artifact-1",
            tool_run_id="ghidra-1",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_DERIVED",
            value={"api": "CreateProcessW", "command": "FoxitPDFReader.exe", "creation_flags": "0x000f4240"},
            anchor={"function_entry": "140004605"},
        ),
        "e-sem": SimpleNamespace(
            id="e-sem",
            artifact_id="artifact-1",
            tool_run_id="ghidra-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_DERIVED",
            value={
                "function": "FUN_140003885",
                "function_entry": "140003885",
                "call_sequence": [
                    {"api": "ShellExecuteW"},
                    {"api": "GetEnvironmentStringsW"},
                    {"api": "CreateProcessW"},
                ],
            },
            anchor={"function_entry": "140003885"},
        ),
    }
    matrix = build_catalog_behavior_matrix([persist], evidence_by_id=evidence)
    how = str(matrix["discovered"][0]["how"])
    assert "FoxitPDFReader.exe" in how
    assert "creation_flags=0x000f4240" in how
    assert "ShellExecuteW" not in how
    assert "GetEnvironmentStringsW" not in how


def test_catalog_matrix_does_not_append_shellexecute_over_persist_how() -> None:
    """HOW12 merged a second process-creation finding and drowned Foxit flags."""
    persist = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`",
        "how": "CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-process"],
    }
    flood = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "process-creation FUN_140003885@140003885",
        "how": (
            "FUN_140003885@140003885: ShellExecuteW(qword ptr [0x140049008]); "
            "consumer=ShellExecuteW; FUN_14003c550: GetEnvironmentStringsW -> CreateProcessW"
        ),
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-sem"],
    }
    matrix = build_catalog_behavior_matrix([persist, flood], evidence_by_id={})
    how = str(matrix["discovered"][0]["how"])
    assert "FoxitPDFReader.exe" in how
    assert "0x000f4240" in how
    assert "ShellExecuteW" not in how
    assert "GetEnvironmentStringsW" not in how


def test_behavior_how_includes_recovered_call_arguments_and_predicates() -> None:
    evidence = {
        "e-crypto": SimpleNamespace(
            id="e-crypto",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "FUN_18003be48",
                "function_entry": "0x18003be48",
                "call_sequence": [
                    {
                        "api": "CryptImportKey",
                        "arguments": [
                            {
                                "argument_index": 1,
                                "value": "0x6801",
                                "source_kind": "constant",
                            }
                        ],
                    },
                    {
                        "api": "CryptDecrypt",
                        "arguments": [
                            {
                                "argument_index": 2,
                                "name": "Final",
                                "value": "1",
                                "source_kind": "constant",
                            }
                        ],
                    },
                ],
                "conditions": [
                    {"text": "TEST RAX, RAX"},
                    {"text": "CMP EAX, 0x103"},
                ],
            },
            anchor={"function_entry": "0x18003be48"},
        )
    }
    finding = build_behavior_findings(
        [_claim("c-crypto")],
        links_by_claim={"c-crypto": ["e-crypto"]},
        evidence_by_id=evidence,
    )[0]
    how = finding["how"]
    how_text = "; ".join(str(item) for item in how) if isinstance(how, list) else str(how)
    assert "CryptImportKey" in how_text
    assert "0x6801" in how_text
    assert "CALG_RC4" in how_text
    assert "CryptDecrypt" in how_text
    assert "0x103" in how_text
    finding["catalog_id"] = "config-and-crypto"
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id=evidence)
    discovered_how = " ".join(str(row.get("how") or "") for row in matrix["discovered"])
    assert "0x6801" in discovered_how


def test_unique_execution_threads_use_semantic_call_sequence_start() -> None:
    evidence = {
        "e-call": SimpleNamespace(
            id="e-call",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateThread", "target_name": "CreateThread"},
            anchor={"function_entry": "0x401000"},
        ),
        "e-sem": SimpleNamespace(
            id="e-sem",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "FUN_401000",
                "function_entry": "0x401000",
                "call_sequence": [
                    {
                        "api": "CreateThread",
                        "callsite": "0x401040",
                        "arguments": [
                            {
                                "argument_index": 2,
                                "register": "R8",
                                "value": "0x401500",
                                "source_kind": "constant",
                            },
                            {
                                "argument_index": 3,
                                "register": "R9",
                                "value": "0x40a000",
                                "source_kind": "constant",
                            },
                        ],
                    }
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["start_routine"] == "0x401500"
    assert rows[0]["parameter"] == "0x40a000"


def test_catalog_how_includes_same_artifact_semantic_summary() -> None:
    evidence = {
        "e-call": SimpleNamespace(
            id="e-call",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CryptDecrypt", "target_name": "CryptDecrypt"},
            anchor={"function_entry": "0x18003be48"},
        ),
        "e-sem": SimpleNamespace(
            id="e-sem",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "FUN_18003be48",
                "function_entry": "0x18003be48",
                "call_sequence": [
                    {
                        "api": "CryptImportKey",
                        "arguments": [
                            {
                                "argument_index": 1,
                                "value": "0x6801",
                                "source_kind": "constant",
                            }
                        ],
                    },
                    {"api": "CryptDecrypt"},
                ],
            },
            anchor={"function_entry": "0x18003be48"},
        ),
    }
    claim = _claim("c-crypto")
    claim.catalog_id = "config-and-crypto"
    finding = build_behavior_findings(
        [claim],
        links_by_claim={"c-crypto": ["e-call"]},
        evidence_by_id=evidence,
    )[0]
    how_text = "; ".join(str(item) for item in finding["how"]) if isinstance(finding["how"], list) else str(finding["how"])
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id=evidence)
    discovered_how = " ".join(str(row.get("how") or "") for row in matrix["discovered"])
    assert "0x6801" in how_text or "0x6801" in discovered_how
    assert "CALG_RC4" in how_text or "CALG_RC4" in discovered_how


def test_unique_execution_threads_ignore_short_constants_as_start() -> None:
    evidence = {
        "e-sem": SimpleNamespace(
            id="e-sem",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "FUN_401000",
                "function_entry": "0x401000",
                "call_sequence": [
                    {
                        "api": "CreateThread",
                        "arguments": [
                            {
                                "argument_index": 2,
                                "value": "0x6801",
                                "source_kind": "constant",
                            }
                        ],
                    }
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert rows
    assert rows[0]["start_routine"] == "UNKNOWN(start_routine)"


def test_behavior_how_uses_ghidra_semantic_call_sequence() -> None:
    evidence = {
        "e-summary": SimpleNamespace(
            id="e-summary",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="investigation",
            kind="function_semantic_summary",
            nature="STATIC_INFERRED",
            value={
                "function": "download_worker",
                "function_entry": "0x401500",
                "call_sequence": [
                    {"api": "WinHttpOpen"},
                    {"api": "WinHttpSendRequest"},
                    {"api": "WinHttpReadData"},
                ],
            },
            anchor={"function_entry": "0x401500"},
        )
    }
    finding = build_behavior_findings(
        [_claim("c1")],
        links_by_claim={"c1": ["e-summary"]},
        evidence_by_id=evidence,
    )[0]
    how = finding["how"]
    how_text = "; ".join(str(item) for item in how) if isinstance(how, list) else str(how)
    assert "WinHttpOpen" in how_text
    assert "WinHttpSendRequest" in how_text
    assert "schtasks" not in how_text.casefold()
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id=evidence)
    discovered_how = " ".join(str(row.get("how") or "") for row in matrix["discovered"])
    if discovered_how:
        assert "WinHttpOpen" in discovered_how


def test_closed_finding_labels_static_behavior_not_capability() -> None:
    finding = build_behavior_findings(
        [_claim("c1", status="VERIFIED")],
        links_by_claim={"c1": ["e1"]},
        evidence_by_id={"e1": _evidence("e1")},
    )[0]
    assert finding["maliciousness_assessment"] == "security_relevant_static_behavior"
    assert "capability" not in finding["maliciousness_assessment"]


def test_tlssetvalue_without_start_routine_is_not_a_unique_thread_body() -> None:
    evidence = {
        "e-tls": SimpleNamespace(
            id="e-tls",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "TlsSetValue", "target_name": "TlsSetValue"},
            anchor={"function_entry": ""},
        ),
    }
    assert build_unique_execution_threads(evidence) == []


def test_iat_pointer_create_thread_merges_into_recovered_start() -> None:
    evidence = {
        "e-ptr": SimpleNamespace(
            id="e-ptr",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "PTR_CreateThread_180063188", "target_name": "PTR_CreateThread_180063188"},
            anchor={"function_entry": "0x180001e10"},
        ),
        "e-call": SimpleNamespace(
            id="e-call",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateThread", "lpStartAddress": "0x180001b54"},
            anchor={"function_entry": "0x180001e10"},
        ),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="controlled-emulator",
            kind="simulation_result",
            nature="EMULATION_OBSERVED",
            value={"status": "SUCCEEDED", "simulator": "speakeasy", "entry_address": "0x1000000"},
            anchor={},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["api"] == "CreateThread"
    assert rows[0]["start_routine"] == "0x180001b54"
    assert rows[0]["emulator_status"] == "OVERALL_SUCCEEDED"


def test_imported_createthread_without_start_is_explicit_unknown_thread() -> None:
    evidence = {
        "e-pe": SimpleNamespace(
            id="e-pe",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="pe_structure",
            nature="STATIC_OBSERVED",
            value={
                "entry_rva": "0x1420",
                "image_base": "0x140000000",
                "imports": [{"dll": "KERNEL32.dll", "functions": ["CreateThread", "VirtualProtect"]}],
            },
            anchor={},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["api"] == "CreateThread"
    assert rows[0]["start_routine"] == "UNKNOWN(start_routine)"


def test_pe_without_createthread_still_emits_unknown_unique_thread() -> None:
    evidence = {
        "e-pe": SimpleNamespace(
            id="e-pe",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="pe_structure",
            nature="STATIC_OBSERVED",
            value={
                "entry_rva": "0x1000",
                "image_base": "0x140000000",
                "imports": [{"dll": "KERNEL32.dll", "functions": ["CreateProcessW", "CreatePipe"]}],
            },
            anchor={},
        ),
    }
    rows = build_unique_execution_threads(evidence)
    assert len(rows) == 1
    assert rows[0]["api"] == "UNKNOWN(thread_api)"
    assert rows[0]["start_routine"] == "UNKNOWN(start_routine)"


def test_runtime_sequence_uses_verified_decode_config() -> None:
    phases = build_runtime_sequence(
        [],
        decoded_configs=[
            {
                "verification_status": "VERIFIED_STATIC_DATA",
                "decoded_preview": "http://203.0.113.9/payload.exe",
                "decoded_strings": ["http://203.0.113.9/payload.exe"],
                "formula": "key_table_modulo_xor_counter",
            }
        ],
    )
    by_id = {item["id"]: item for item in phases}
    assert by_id["decode"]["status"] == "SUPPORTED"
    assert "http://203.0.113.9/payload.exe" in by_id["decode"]["how"]
    assert by_id["network"]["status"] == "UNKNOWN"
    assert "http://" not in str(by_id["network"]["how"]).casefold() or by_id["network"]["how"].startswith("UNKNOWN")


def test_runtime_sequence_projects_process_flags_without_inventing_suspended() -> None:
    evidence = {
        "e-flags": SimpleNamespace(
            id="e-flags",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="execution",
            kind="process_creation_flags",
            nature="STATIC_DERIVED",
            value={
                "function": "CreateProcessW",
                "flags": [
                    {
                        "value": "0x09080008",
                        "set_flags": [
                            "DETACHED_PROCESS",
                            "EXTENDED_STARTUPINFO_PRESENT",
                            "CREATE_NO_WINDOW",
                        ],
                        "contains_create_suspended": False,
                        "contains_create_new_console": False,
                        "interpretation": (
                            "extended startup information is present; "
                            "parent-process attributes may be supplied"
                        ),
                        "runtime_effect_proven": False,
                    }
                ],
                "runtime_effect_proven": False,
            },
            anchor={"function_entry": "0x140004605"},
        ),
    }
    phases = build_runtime_sequence(
        [],
        process_flags=build_process_flag_projections(evidence),
    )
    by_id = {item["id"]: item for item in phases}
    assert by_id["process"]["status"] == "CANDIDATE"
    assert "0x09080008" in by_id["process"]["how"]
    assert "EXTENDED_STARTUPINFO_PRESENT" in by_id["process"]["how"]
    assert "CREATE_SUSPENDED" not in by_id["process"]["how"]
    assert "CREATE_NEW_CONSOLE" not in by_id["process"]["how"]


def test_runtime_sequence_projects_pe_entry_without_inventing_crt() -> None:
    evidence = {
        "e-pe": SimpleNamespace(
            id="e-pe",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="pe_structure",
            nature="STATIC_OBSERVED",
            value={"entry_rva": 0x1420, "image_base": 0x140000000},
            anchor={"type": "file_offset", "offset": 0x80},
        ),
    }
    phases = build_runtime_sequence([], pe_entry=build_pe_entry_projection(evidence))
    by_id = {item["id"]: item for item in phases}
    assert by_id["startup"]["status"] == "CANDIDATE"
    assert "0x1420" in by_id["startup"]["how"]
    assert "0x140001420" in by_id["startup"]["how"]
    assert "crt" not in by_id["startup"]["how"].casefold()


def test_runtime_sequence_projects_decoded_failure_string_as_fallback() -> None:
    phases = build_runtime_sequence(
        [],
        decoded_configs=[
            {
                "verification_status": "VERIFIED_STATIC_DATA",
                "decoded_preview": "download failed",
            }
        ],
    )
    by_id = {item["id"]: item for item in phases}
    assert by_id["fallback"]["status"] == "CANDIDATE"
    assert "download failed" in by_id["fallback"]["how"]
    assert "schtasks" not in by_id["fallback"]["how"].casefold()


def test_assessment_does_not_tell_analyst_to_leave_for_a_sandbox() -> None:
    evidence = {
        "e1": _evidence("e1"),
        "e-emu": SimpleNamespace(
            id="e-emu",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="simulation_result",
            nature="EMULATION_OBSERVED",
            value={"status": "SUCCEEDED", "simulator": "unicorn"},
            anchor={"function_entry": "0x401500"},
        ),
    }
    _, rows = _build_assessment(
        task=SimpleNamespace(id="task-1", outcome="PARTIAL", limitations=["static boundary on AES"]),
        artifacts=[],
        claims=[_claim("c1")],
        links_by_claim={"c1": ["e1"]},
        evidence_by_id=evidence,
        model_calls=[],
        mechanisms=[],
        mechanism_projections=[],
        behavior_findings=[],
    )
    next_steps = [row for row in rows if row.get("type") == "next_step"]
    assert next_steps
    text = " ".join(str(row.get("action") or "") for row in next_steps).casefold()
    assert "sandbox" not in text
    assert "go to" not in text
    assert "emulator" in text


def test_report_markdown_renders_catalog_table_and_unique_threads_without_empty_categories() -> None:
    evidence = SimpleNamespace(
        id="e-thread",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "CreateThread", "target_name": "CreateThread"},
        anchor={"function_entry": "0x401000"},
    )
    claim = SimpleNamespace(
        id="c-thread",
        module="behavior_attack",
        claim_type="BEHAVIOR",
        subject="sample.exe",
        action="creates_worker_thread",
        object="worker start routine",
        mechanism="CreateThread -> UNKNOWN(start routine)",
        condition="static evidence only",
        statement="The sample creates an OS thread whose start routine is not recovered.",
        status="CANDIDATE",
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
        catalog_id="thread-and-callback",
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-thread"),
        task=SimpleNamespace(
            id="task-thread", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[], evidence=[evidence], claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id="c-thread", evidence_id="e-thread", stance="SUPPORTS")],
        relations=[], gates=[], model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert "Discovered catalog behaviors" in markdown
    assert "thread-and-callback" in markdown
    assert "lateral-movement" not in markdown
    assert "Unique OS threads / callbacks" in markdown
    assert "CreateThread" in markdown
    assert "Runtime sequence (static reconstruction)" in markdown
    assert "Phase 7" in markdown
    assert "Phase 1 — startup / loader" not in markdown
    assert summary_leads_with_what(markdown)


def summary_leads_with_what(markdown: str) -> bool:
    assessment = markdown.split("## 1. Executive Assessment", 1)[1]
    body = assessment.split("## 2.", 1)[0]
    return "What:" in body and "The task produced" not in body


def test_report_projects_gold_like_sequence_constants_and_emu_status() -> None:
    """Session-shaped semantic evidence must appear in the authoritative markdown."""
    pe = SimpleNamespace(
        id="e-pe",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="pe_structure",
        nature="STATIC_OBSERVED",
        value={
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": 0x1420,
            "image_base": 0x140000000,
            "subsystem": 3,
            "sections": [{"name": ".text"}, {"name": ".rdata"}],
            "imports": [{"dll": "advapi32", "functions": ["CryptAcquireContextW"]}],
        },
        anchor={},
    )
    semantic = SimpleNamespace(
        id="e-semantic",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_INFERRED",
        value={
            "function": "FUN_140009da0",
            "function_entry": "0x140009da0",
            "call_sequence": [
                {
                    "api": "CryptAcquireContextW",
                    "callsite": "0x140009e10",
                    "category": "crypto",
                    "arguments": [
                        {"argument_index": 4, "name": "Algid", "value": "0x6801", "source_kind": "immediate"},
                    ],
                },
                {
                    "api": "CreateThread",
                    "callsite": "0x140009f00",
                    "category": "thread",
                    "arguments": [
                        {"argument_index": 2, "name": "lpStartAddress", "value": "0x14000a100", "source_kind": "immediate"},
                    ],
                },
            ],
            "consumers": ["CryptEncrypt"],
            "unknowns": ["runtime branch outcome"],
        },
        anchor={"function_entry": "0x140009da0"},
    )
    emu = SimpleNamespace(
        id="e-emu",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="simulation_result",
        nature="STATIC_INFERRED",
        value={
            "status": "DEFERRED_TO_WORKER",
            "simulator": "unicorn",
            "stop_reason": "DEFERRED_TO_WORKER",
            "function_entry": "0x14000a100",
            "limitations": ["isolated emu-worker"],
        },
        anchor={"function_entry": "0x14000a100"},
    )
    claim = _claim("c-crypto", module="decryption")
    document = build_report_document(
        case=SimpleNamespace(id="case-gold"),
        task=SimpleNamespace(
            id="task-gold", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[],
        evidence=[pe, semantic, emu],
        claims=[claim],
        claim_evidence=[SimpleNamespace(claim_id="c-crypto", evidence_id="e-semantic", stance="SUPPORTS")],
        relations=[], gates=[], model_calls=[],
        selected_modules=["executive_summary", "static_triage", "behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert "PE basics (static header)" in markdown
    assert "0x1420" in markdown or "0x140001420" in markdown
    assert "Ordered static call sequence (reconstructed)" in markdown
    assert "CALG_RC4" in markdown
    assert "CryptAcquireContextW" in markdown
    assert "Controlled emulation (isolated worker, not host execution)" in markdown
    assert "DEFERRED_TO_WORKER" in markdown
    assert "UNKNOWN(start)" not in markdown or "0x14000a100" in markdown


def test_ordered_flow_prefers_crypto_over_low_address_noise() -> None:
    from threat_report_agent.report.reporting import build_ordered_static_call_flow

    evidence = {}
    for index in range(20):
        evidence[f"noise-{index}"] = SimpleNamespace(
            id=f"e-noise-{index}",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_semantic_summary",
            nature="STATIC_OBSERVED",
            value={
                "function": f"FUN_{index:08x}",
                "function_entry": f"0x18000{index:04x}",
                "call_sequence": [{"api": "Sleep", "arguments": [{"name": "dwMilliseconds", "value": "1", "source_kind": "immediate"}]}],
            },
            anchor={"function_entry": f"0x18000{index:04x}"},
        )
    evidence["crypto"] = SimpleNamespace(
        id="e-crypto",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_OBSERVED",
        value={
            "function": "FUN_180038af8",
            "function_entry": "0x180038af8",
            "call_sequence": [
                {
                    "api": "CryptAcquireContextW",
                    "arguments": [
                        {"name": "Algid", "value": "0x6801", "source_kind": "immediate"},
                    ],
                }
            ],
        },
        anchor={"function_entry": "0x180038af8"},
    )
    steps = build_ordered_static_call_flow(evidence)
    assert any("CryptAcquireContextW" in str(step.get("calls")) for step in steps[:16])
    assert any("CALG_RC4" in str(step.get("calls")) or "CALG_RC4" in str(step.get("how")) for step in steps[:16])


def test_ordered_flow_keeps_persist_createprocess_ahead_of_getprocaddress_flood() -> None:
    """Kunglao leftover remainder: prologue GetProcAddress must not hide Foxit HOW."""
    from threat_report_agent.report.reporting import build_ordered_static_call_flow

    evidence: dict[str, object] = {}
    for index in range(20):
        evidence[f"resolver-{index}"] = SimpleNamespace(
            id=f"e-resolver-{index}",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_semantic_summary",
            nature="STATIC_OBSERVED",
            value={
                "function": f"FUN_14003{index:04x}",
                "function_entry": f"0x14003{index:04x}",
                "call_sequence": [
                    {"api": "GetProcAddress", "arguments": [{"name": "lpProcName", "value": f"Export{index}"}]}
                ],
            },
            anchor={"function_entry": f"0x14003{index:04x}"},
        )
    evidence["prologue"] = SimpleNamespace(
        id="e-prologue",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_OBSERVED",
        value={
            "function": "FUN_140004605",
            "function_entry": "140004605",
            "call_sequence": [
                {"api": "GetConsoleWindow"},
                {"api": "GetTickCount64"},
                {"api": "GetSystemInfo"},
            ],
        },
        anchor={"function_entry": "140004605"},
    )
    evidence["process"] = SimpleNamespace(
        id="e-process",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
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
    steps = build_ordered_static_call_flow(evidence)
    blob = " ".join(
        f"{step.get('how')} {' '.join(str(call) for call in (step.get('calls') or []))}"
        for step in steps[:8]
    )
    assert "FoxitPDFReader.exe" in blob
    assert "CreateProcessW" in blob
    assert "0x000f4240" in blob
    assert steps[0]["function_entry"] in {"140004605", "FUN_140004605", "0x140004605"}


def test_ordered_flow_decodes_algid_from_same_function_instruction_window() -> None:
    from threat_report_agent.report.reporting import build_ordered_static_call_flow

    evidence = {
        "sem": SimpleNamespace(
            id="e-crypto-reg",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_semantic_summary",
            nature="STATIC_OBSERVED",
            value={
                "function": "FUN_180038af8",
                "function_entry": "0x180038af8",
                "call_sequence": [
                    {
                        "api": "CryptGenKey",
                        "arguments": [
                            {"name": "Algid", "value": "R15 + 0x1", "source_kind": "register"},
                        ],
                    }
                ],
            },
            anchor={"function_entry": "0x180038af8"},
        ),
        "imm": SimpleNamespace(
            id="e-imm-6801",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="static_triage",
            kind="function_instruction_window",
            nature="STATIC_OBSERVED",
            value={
                "function_entry": "0x180038af8",
                "instructions": ["MOV EDX,0x6801", "CMP EAX,0x6801"],
            },
            anchor={"function_entry": "0x180038af8"},
        ),
    }
    steps = build_ordered_static_call_flow(evidence)
    blob = " ".join(
        f"{step.get('how')} {' '.join(str(call) for call in (step.get('calls') or []))}"
        for step in steps[:16]
    )
    assert "CALG_RC4" in blob


def test_gold_flow_survives_large_finding_volume() -> None:
    findings = [
        {
            "type": "security_finding",
            "finding_id": f"finding-{index}",
            "what": "candidate " * 40,
            "how": "LoadLibraryA(lpLibFileName=buffer) " * 20,
            "verdict": "CANDIDATE",
            "confidence": "LOW",
            "evidence_ids": [f"e{index}"],
        }
        for index in range(80)
    ]
    document = {
        "report_version": "3.0",
        "report_sections": ["Executive Assessment", "IOC / Indicators"],
        "case_id": "case-volume",
        "task_id": "task-volume",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {"type": "analyst_assessment", "summary": "Static candidate paths only.", "findings": []},
                    {
                        "type": "pe_basics",
                        "format": "PE32+",
                        "machine": "x64",
                        "image_base": "0x180000000",
                        "entry_rva": "0x1000",
                    },
                    {
                        "type": "ordered_static_call_flow",
                        "steps": [
                            {
                                "function": "entry",
                                "function_entry": "0x180001000",
                                "how": "CryptAcquireContextW(Algid=0x6801 (CALG_RC4))",
                                "calls": ["CryptAcquireContextW(Algid=0x6801 (CALG_RC4))"],
                            }
                        ],
                    },
                    {
                        "type": "emulation_status",
                        "overall": "NOT_ATTEMPTED",
                        "attempted": False,
                        "next_step": "Isolated CONTROLLED_EMULATE after static stalls.",
                    },
                    {
                        "type": "runtime_sequence",
                        "phases": [{"title": "Phase 1", "status": "CANDIDATE", "how": "static reconstruction"}],
                    },
                    {"type": "ioc", "category": "hash", "value": "aa" * 32, "classification": "STATIC_DERIVED"},
                    *findings,
                ],
            }
        ],
    }
    markdown = document_to_markdown(document)
    assert "PE basics (static header)" in markdown
    assert "Ordered static call sequence (reconstructed)" in markdown
    assert "Controlled emulation (isolated worker, not host execution)" in markdown
    assert "NOT_ATTEMPTED" in markdown
    assert "## 6. IOC / Indicators" in markdown


def test_unclassified_calls_do_not_crash_report_compose() -> None:
    semantic = SimpleNamespace(
        id="e-semantic",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind="function_semantic_summary",
        nature="STATIC_OBSERVED",
        value={
            "function": "FUN_180001000",
            "function_entry": "0x180001000",
            "call_sequence": [
                {"api": "FUN_180038af8", "category": "unclassified_call", "arguments": []},
                {"api": "FUN_180038b00", "category": "unclassified_call", "arguments": []},
                {"api": "LoadLibraryA", "category": "dynamic_resolution", "arguments": []},
            ],
        },
        anchor={"function_entry": "0x180001000"},
    )
    document = build_report_document(
        case=SimpleNamespace(id="case-unclassified"),
        task=SimpleNamespace(
            id="task-unclassified", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.dll", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[],
        evidence=[semantic],
        claims=[],
        claim_evidence=[],
        relations=[], gates=[], model_calls=[],
        selected_modules=["executive_summary", "static_triage", "behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert "LoadLibraryA" in markdown
    assert "Ordered static call sequence (reconstructed)" in markdown


def test_stack_frame_spills_are_omitted_from_semantic_how() -> None:
    from threat_report_agent.report.reporting import _format_semantic_call

    rendered = _format_semantic_call(
        {
            "api": "LoadLibraryA",
            "arguments": [
                {"argument_index": 0, "name": "lpLibFileName", "value": "RSP + 0x30", "source_kind": "stack_local"},
                {"argument_index": 0, "name": "lpLibFileName", "value": "0x18006de38", "source_kind": "constant"},
            ],
        }
    )
    assert "RSP" not in rendered
    assert "LoadLibraryA(lpLibFileName=0x18006de38)" == rendered


def test_recovered_function_parameter_consumer_renders_concrete_how() -> None:
    markdown = document_to_markdown(
        {
            "case_id": "case-how",
            "task_id": "task-how",
            "report_version": "3.0",
            "report_sections": ["static_triage"],
            "analysis_outcome": "PARTIAL",
            "analysis_class": "BOUNDED_STATIC_ANALYSIS",
            "modules": [
                {
                    "id": "static_triage",
                    "title": "Static Triage",
                    "summary": "semantic evidence",
                    "rows": [
                        {
                            "type": "behavior_finding",
                            "finding_id": "thread-worker",
                            "catalog_id": "thread-and-callback",
                            "finding_status": "CANDIDATE",
                            "what": "starts a worker thread",
                            "how": "UNKNOWN(start_routine)",
                            "function": "FUN_140009da0",
                            "function_entry": "0x140009da0",
                            "target": "0x140009da0",
                            "consumer": "CryptEncrypt",
                            "ten_question_protocol": {
                                "input": {
                                    "status": "ANSWERED",
                                    "value": "lpParameter=0x14000a000",
                                },
                                "consumer": {
                                    "status": "ANSWERED",
                                    "value": "CryptEncrypt",
                                },
                                "failure_fallback": {
                                    "status": "ANSWERED",
                                    "value": "retry with cached provider",
                                },
                            },
                            "evidence_ids": ["ev-thread"],
                        },
                    ],
                }
            ],
        }
    )
    how_lines = [
        line.strip() for line in markdown.splitlines() if line.strip().startswith("- How:")
        or line.strip().startswith("- How:") or "  - How:" in line
    ]
    assert how_lines, markdown
    how_text = "\n".join(how_lines)
    assert "UNKNOWN(" not in how_text
    assert "FUN_140009da0" in how_text or "0x140009da0" in how_text
    assert "0x14000a000" in how_text or "lpParameter" in how_text
    assert "CryptEncrypt" in how_text
    assert "Deferred unanswered behavior leads" not in markdown


def test_name_only_api_seeds_stay_candidate_and_omit_overclaimed_attack() -> None:
    seeds = (
        ("c-thread", "e-thread", "CreateThread", "T1055", "Process Injection"),
        ("c-apc", "e-apc", "QueueUserAPC", "T1055", "Process Injection"),
        ("c-http", "e-http", "WinHttpSendRequest", "T1071", "Application Layer Protocol"),
        ("c-task", "e-task", "schtasks", "T1547", "Boot or Logon Autostart Execution"),
        ("c-ppid", "e-ppid", "UpdateProcThreadAttribute", "T1055", "Process Injection"),
        ("c-import", "e-import", "LoadLibraryW", "T1055", "Process Injection"),
    )
    evidence = {
        evidence_id: SimpleNamespace(
            id=evidence_id,
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="loader",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": api},
            anchor={},
        )
        for _, evidence_id, api, _, _ in seeds
    }
    claims = []
    links = []
    projections = []
    for claim_id, evidence_id, api, technique_id, technique_name in seeds:
        claims.append(
            SimpleNamespace(
                id=claim_id,
                module="behavior_attack",
                claim_type="BEHAVIOR",
                subject="sample.exe",
                action=api,
                object=api,
                mechanism=api,
                condition="",
                statement=api,
                status="SUPPORTED",
                confidence="HIGH",
                attack_mapping={
                    "mappings": [{
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "status": "confirmed",
                    }],
                },
                model_call_id=None,
            )
        )
        links.append(SimpleNamespace(claim_id=claim_id, evidence_id=evidence_id, stance="SUPPORTS"))
        projections.append({
            "type": "behavior_finding",
            "finding_id": claim_id,
            "claim_id": claim_id,
            "status": "SUPPORTED",
            "what": api,
            "how": api,
            "target": api,
            "inputs": [api],
            "transformation_or_control": [api],
            "conditions": [api],
            "outputs": [api],
            "consumers": [api],
            "evidence_ids": [evidence_id],
            "artifact_id": "artifact-1",
            "attack_techniques": [{"technique_id": technique_id, "name": technique_name}],
        })
    findings = build_behavior_findings(
        claims,
        mechanism_projections=projections,
        links_by_claim={claim.id: [link.evidence_id] for claim, link in zip(claims, links)},
        claim_evidence=links,
        evidence_by_id=evidence,
    )
    assert findings
    for finding in findings:
        assert finding["status"] in {"CANDIDATE", "UNKNOWN"}
        assert finding["finding_status"] in {"CANDIDATE", "UNKNOWN"}
        assert finding["status"] not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
    document = build_report_document(
        case=SimpleNamespace(id="case-m06"),
        task=SimpleNamespace(
            id="task-m06", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
        ),
        artifacts=[SimpleNamespace(
            id="artifact-1", logical_path="sample.exe", content_sha256="a" * 64,
            detected_type="pe", role="EXECUTABLE", obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[],
        evidence=list(evidence.values()),
        claims=claims,
        claim_evidence=links,
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert "`T1055`" not in markdown
    assert "`T1071`" not in markdown
    assert "`T1547`" not in markdown
    attack_ids = {
        str(technique.get("technique_id"))
        for module in document["modules"]
        for row in module.get("rows", [])
        for technique in (
            row.get("attack_techniques") if isinstance(row.get("attack_techniques"), list) else []
        )
        if isinstance(technique, dict)
    }
    nested_ids = {
        str(technique.get("technique_id"))
        for module in document["modules"]
        for row in module.get("rows", [])
        if isinstance(row, dict)
        for finding in (row.get("findings") if isinstance(row.get("findings"), list) else [])
        if isinstance(finding, dict)
        for technique in (
            finding.get("attack_techniques") if isinstance(finding.get("attack_techniques"), list) else []
        )
        if isinstance(technique, dict)
    }
    assert not ({"T1055", "T1071", "T1547"} & (attack_ids | nested_ids))


def test_s4_closed_empty_attempts_renders_blocked_not_static_boundary() -> None:
    document = build_report_document(
        case=SimpleNamespace(id="case-s4-vacuous"),
        task=SimpleNamespace(
            id="task-s4-vacuous", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
            analysis_class="BOUNDED_STATIC_ANALYSIS", coverage={},
        ),
        artifacts=[], tool_runs=[], evidence=[_evidence("e1")], claims=[],
        claim_evidence=[], relations=[], gates=[], model_calls=[],
        investigation_threads=[SimpleNamespace(
            id="thread-vacuous",
            state="STATIC_BOUNDARY",
            question="Who consumes the decoded buffer?",
            action_ids=[],
            evidence_ids=[],
            s_ladder={
                "s1_context": "NOT_APPLICABLE",
                "s2_dataflow": "NOT_APPLICABLE",
                "s3_consumer": "NOT_APPLICABLE",
                "s4_orchestration": "CLOSED",
                "attempted_action_types": [],
                "required_action_types": [],
            },
        )],
        investigation_actions=[],
        selected_modules=["executive_summary"],
    )
    s4 = {item["thread_id"]: item for item in document["analysis_quality"]["s4_orchestration"]}
    assert s4["thread-vacuous"]["status"] in {"BLOCKED", "PARTIAL"}
    assert s4["thread-vacuous"]["status"] != "CLOSED"
    markdown = document_to_markdown(document)
    assert "S4 orchestration" in markdown
    assert "thread-vacuous" in markdown
    assert "status=**BLOCKED**" in markdown or "status=**PARTIAL**" in markdown
    assert "empty attempts" in markdown.casefold()
    assert "status=**CLOSED**" not in markdown
    assert "STATIC_BOUNDARY" not in markdown or "not STATIC_BOUNDARY" in markdown


def test_persist_claim_ready_without_trace_renders_closed_not_blocked() -> None:
    """One-round persist HOW skip must not print S4 BLOCKED and ask 再深入."""
    document = build_report_document(
        case=SimpleNamespace(id="case-s4-persist"),
        task=SimpleNamespace(
            id="task-s4-persist", lifecycle="SUCCEEDED", outcome="PARTIAL",
            target_breadth="B0", target_depth="D3", actual_granularity={},
            request_snapshot={}, limitations=["static-only"],
            analysis_class="BOUNDED_STATIC_ANALYSIS", coverage={},
        ),
        artifacts=[], tool_runs=[], evidence=[_evidence("e-process")], claims=[],
        claim_evidence=[], relations=[], gates=[], model_calls=[],
        investigation_threads=[SimpleNamespace(
            id="thread-process",
            state="CLAIM_READY",
            question="How does CreateProcess start Foxit?",
            action_ids=[],
            evidence_ids=["e-process"],
        )],
        investigation_actions=[],
        selected_modules=["executive_summary"],
    )
    s4 = {item["thread_id"]: item for item in document["analysis_quality"]["s4_orchestration"]}
    assert s4["thread-process"]["status"] == "CLOSED"
    markdown = document_to_markdown(document)
    assert "thread-process" in markdown
    assert "status=**CLOSED**" in markdown
    assert "status=**BLOCKED**" not in markdown
    assert "leftover remainder" in markdown.casefold() or "persist" in markdown.casefold()


def test_compose_control_workers_inherit_simulation_profile() -> None:
    from pathlib import Path

    text = Path("docker-compose.yml").read_text(encoding="utf-8")
    anchor = text.split("x-static-worker-environment:")[1].split("services:")[0]
    assert "SIMULATION_PROFILE: static-first-controlled-emulation" in anchor


def test_catalog_how_prefers_persist_what_not_shellexecute_finding_how() -> None:
    """Catalog How must use persist What, not a ShellExecuteW decompile body."""
    finding = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`",
        "how": (
            "FUN_140003885@140003885: ShellExecuteW(qword ptr [0x140049008]); "
            "consumer=ShellExecuteW"
        ),
        "finding_status": "CANDIDATE",
        "evidence_ids": ["e-sem"],
    }
    evidence = {
        "e-sem": SimpleNamespace(
            id="e-sem",
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
        ),
    }
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id=evidence)
    how = str(matrix["discovered"][0]["how"])
    assert "FoxitPDFReader.exe" in how
    assert "0x000f4240" in how
    assert "ShellExecuteW" not in how
    assert "GetEnvironmentStringsW" not in how


def test_catalog_how_does_not_use_twelve_call_fun_dump() -> None:
    finding = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "what": "process-creation FUN_140004605@140004605",
        "how": (
            "FUN_140004605@140004605: GetConsoleWindow -> GetTickCount64 -> GetSystemInfo -> "
            "memcpy -> memcmp -> OpenProcess -> InitializeProcThreadAttributeList -> "
            "UpdateProcThreadAttribute -> CreateProcessW -> MoveFileExW -> CopyFileExW"
        ),
        "finding_status": "CANDIDATE",
        "evidence_ids": [],
    }
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id={})
    how = str(matrix["discovered"][0]["how"])
    assert "FUN_140004605" not in how
    assert how.count(" -> ") < 6
    assert how == "not recovered"


_FUN_PPID_DUMP = (
    "FUN_140004605@140004605: GetConsoleWindow -> GetTickCount64 -> GetSystemInfo -> "
    "memcpy -> memcmp -> OpenProcess -> InitializeProcThreadAttributeList -> "
    "UpdateProcThreadAttribute -> CreateProcessW -> MoveFileExW -> CopyFileExW; "
    "Attribute=0x20000"
)


def test_catalog_how_prefers_ppid_persist_not_fun_dump() -> None:
    """Gate leftover: PPID How was a FUN_* dump even after persist attribute/parent."""
    finding = {
        "type": "behavior_finding",
        "catalog_id": "parent-process-spoofing",
        "what": "UpdateProcThreadAttribute; attribute=0x00020000; parent=UNKNOWN(parent identity)",
        "how": _FUN_PPID_DUMP,
        "finding_status": "CANDIDATE",
        "evidence_ids": [],
    }
    matrix = build_catalog_behavior_matrix([finding], evidence_by_id={})
    how = str(matrix["discovered"][0]["how"])
    assert "attribute=0x00020000" in how.casefold()
    assert "parent=UNKNOWN(parent identity)" in how
    assert "FUN_140004605" not in how
    assert how.count(" -> ") < 6


def test_catalog_loader_how_prefers_named_api_not_fun_resolver() -> None:
    """TypedHow leftover: loader How mixed GetTempPath2W persist with FUN GetModuleHandle dumps."""
    findings = [
        {
            "type": "behavior_finding",
            "catalog_id": "loader-and-api-resolution",
            "what": "kernel32.dll!GetTempPath2W consumed by JMP R8",
            "how": (
                "FUN_140046000@140046000: GetModuleHandleA(0x140054d58) -> "
                "GetProcAddress(lpProcName=0x140054f7c); consumer=GetProcAddress"
            ),
            "finding_status": "VERIFIED",
            "evidence_ids": [],
        },
        {
            "type": "behavior_finding",
            "catalog_id": "loader-and-api-resolution",
            "what": "loader-and-api-resolution FUN_140038dd0@140038dd0",
            "how": "GetProcAddress@140046878; predicate=JMP qword ptr [0x14005e688]",
            "finding_status": "CANDIDATE",
            "evidence_ids": [],
        },
    ]
    matrix = build_catalog_behavior_matrix(findings, evidence_by_id={})
    row = matrix["discovered"][0]
    how = str(row["how"])
    what = str(row["what"])
    assert "GetTempPath2W" in how or "consumed by" in how.casefold()
    assert "FUN_140046000" not in how
    assert "GetModuleHandleA" not in how
    assert "FUN_140038dd0" not in what


def test_one_round_readiness_flags_fun_dump_on_executive_and_ppid() -> None:
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "assessment",
                        "summary": (
                            "What: CreateProcessW command=FoxitPDFReader.exe. "
                            f"How: command=FoxitPDFReader.exe; creation_flags=0x000f4240; {_FUN_PPID_DUMP}. "
                            "Key unknowns: runtime CreateProcess."
                        ),
                    },
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {
                                "catalog_id": "process-creation",
                                "what": "command=FoxitPDFReader.exe; creation_flags=0x000f4240",
                                "how": "CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
                            },
                            {
                                "catalog_id": "parent-process-spoofing",
                                "what": "attribute=0x00020000; parent=UNKNOWN(parent identity)",
                                "how": _FUN_PPID_DUMP,
                            },
                        ],
                    },
                ],
            }
        ],
        "analysis_quality": {},
    }
    violations = report_one_round_readiness_violations(document)
    assert any("parent-process-spoofing" in item for item in violations)
    assert any("executive" in item for item in violations)
    from threat_report_agent.report.reporting import _stamp_one_round_readiness

    _stamp_one_round_readiness(document)
    assert document["analysis_quality"]["one_round_readiness"]["complete"] is False


def test_one_round_readiness_flags_shellexecute_over_persist_what() -> None:
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {
                                "catalog_id": "process-creation",
                                "what": "command `FoxitPDFReader.exe` with creation_flags `0x000f4240`",
                                "how": (
                                    "FUN_140003885@140003885: ShellExecuteW; "
                                    "GetEnvironmentStringsW -> CreateProcessW"
                                ),
                            }
                        ],
                    }
                ],
            }
        ],
        "analysis_quality": {},
    }
    violations = report_one_round_readiness_violations(document)
    assert any("ShellExecuteW" in item or "GetEnvironmentStringsW" in item for item in violations)


def test_one_round_readiness_flags_executive_mechanism_chain_dump() -> None:
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "assessment",
                        "summary": (
                            "What: command=FoxitPDFReader.exe. "
                            "How: CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240. "
                            "Key unknowns: runtime. "
                            "Mechanism chain: FUN_140004605@140004605: GetConsoleWindow -> CreateProcessW."
                        ),
                    }
                ],
            }
        ],
        "analysis_quality": {},
    }
    violations = report_one_round_readiness_violations(document)
    assert any("executive cover" in item for item in violations)


def test_one_round_readiness_allows_fun_location_citation_on_typed_cover() -> None:
    """Exec-clean leftover one_round=False because Interpretation cited (FUN_*@rva)."""
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "assessment",
                        "summary": (
                            "What: command=FoxitPDFReader.exe. "
                            "How: CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240. "
                            "Key unknowns: UNKNOWN(parent identity). "
                            "Mechanism chain: typed How above; function-level call sequences "
                            "are in Evidence Explorer. "
                            "Interpretation: a child-process path (FUN_140004605@140004605)."
                        ),
                    },
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {
                                "catalog_id": "process-creation",
                                "what": "command=FoxitPDFReader.exe",
                                "how": "CreateProcessW command=FoxitPDFReader.exe; creation_flags=0x000f4240",
                            },
                            {
                                "catalog_id": "parent-process-spoofing",
                                "what": "attribute=0x00020000",
                                "how": "attribute=0x00020000; parent=UNKNOWN(parent identity)",
                            },
                        ],
                    },
                ],
            }
        ],
        "analysis_quality": {},
    }
    assert report_one_round_readiness_violations(document) == []


def test_one_round_readiness_flags_unique_or_unknown_with_named_catalog() -> None:
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {"catalog_id": "process-creation", "what": "CreateProcessW", "how": "command=cmd.exe"},
                            {"catalog_id": "unique-or-unknown", "what": "FUN_140046090", "how": "CreateWaitableTimerExW"},
                        ],
                    }
                ],
            }
        ],
        "analysis_quality": {},
    }
    violations = report_one_round_readiness_violations(document)
    assert any("unique-or-unknown" in item for item in violations)


def test_one_round_readiness_empty_how_is_note_not_hard_violation() -> None:
    document = {
        "modules": [
            {
                "id": "executive_summary",
                "rows": [
                    {
                        "type": "catalog_behavior_matrix",
                        "discovered": [
                            {
                                "catalog_id": "network-transport",
                                "what": "HTTP transport candidate",
                                "how": "not recovered",
                            }
                        ],
                    },
                    {
                        "type": "assessment",
                        "summary": "What: candidate. How: not recovered. Key unknowns: transport API.",
                        "key_unknowns": ["HTTP transport API not recovered"],
                    },
                ],
            }
        ],
        "analysis_quality": {},
    }
    markdown = "What: candidate. How: not recovered. Key unknowns: transport API."
    violations = report_one_round_readiness_violations(document, markdown)
    assert violations == []
    from threat_report_agent.report.reporting import _stamp_one_round_readiness

    _stamp_one_round_readiness(document, markdown)
    readiness = document["analysis_quality"]["one_round_readiness"]
    assert readiness["complete"] is True
    assert readiness["violations"] == []
    assert any("network-transport" in note for note in readiness.get("notes") or [])


def _plan_report_task(strategy_snapshot: dict | None = None, **overrides):
    payload = dict(
        id="task-plan",
        lifecycle="SUCCEEDED",
        outcome="PARTIAL",
        target_breadth="B0",
        target_depth="D3",
        actual_granularity={},
        request_snapshot={},
        limitations=["static-only"],
        analysis_class="BOUNDED_STATIC_ANALYSIS",
        coverage={},
        strategy_snapshot=strategy_snapshot if strategy_snapshot is not None else {},
    )
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _plan_report_artifact():
    return SimpleNamespace(
        id="artifact-1",
        logical_path="sample.exe",
        content_sha256="a" * 64,
        detected_type="pe",
        role="EXECUTABLE",
        obligation="REQUIRED",
        parent_artifact_id=None,
    )


def test_packed_stub_iat_does_not_appear_as_verified_how() -> None:
    evidence = {
        "e-ll": SimpleNamespace(
            id="e-ll",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="loader",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "LoadLibraryA"},
            anchor={"function_entry": "FUN_401000"},
        ),
        "e-gpa": SimpleNamespace(
            id="e-gpa",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="loader",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "GetProcAddress"},
            anchor={"function_entry": "FUN_401000"},
        ),
    }
    claims = [
        SimpleNamespace(
            id="c-stub",
            module="loader",
            claim_type="BEHAVIOR",
            subject="sample.exe",
            action="LoadLibraryA",
            object="GetProcAddress",
            mechanism="FUN_401000@401000 LoadLibraryA -> GetProcAddress",
            condition="",
            statement="FUN_401000@401000 LoadLibraryA -> GetProcAddress",
            status="SUPPORTED",
            confidence="HIGH",
            attack_mapping={},
            model_call_id=None,
        )
    ]
    document = build_report_document(
        case=SimpleNamespace(id="case-packer"),
        task=_plan_report_task(
            {
                "investigation": {
                    "static_analysis_plan": {
                        "schema_version": "1",
                        "packer_latch": True,
                        "items": [
                            {
                                "id": "unpack",
                                "title": "Identify packer and unpack before treating IAT as payload",
                                "status": "BLOCKED",
                                "unknowns": ["oep"],
                                "next_method": "locate OEP then rebuild IAT",
                                "kind": "unpack",
                            }
                        ],
                    }
                }
            }
        ),
        artifacts=[_plan_report_artifact()],
        tool_runs=[],
        evidence=list(evidence.values()),
        claims=claims,
        claim_evidence=[SimpleNamespace(claim_id="c-stub", evidence_id="e-ll", stance="SUPPORTS")],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
        mechanisms=[
            {
                "id": "mech-stub",
                "claim_id": "c-stub",
                "status": "VERIFIED",
                "target": "FUN_401000",
                "inputs": ["LoadLibraryA"],
                "transformation_or_control": ["FUN_401000@401000 LoadLibraryA -> GetProcAddress"],
                "conditions": [],
                "outputs": ["GetProcAddress"],
                "consumers": ["LoadLibraryA"],
                "evidence_ids": ["e-ll", "e-gpa"],
                "verifier": {"status": "VERIFIED", "mechanism_type": "DYNAMIC_LOADER"},
            }
        ],
    )
    markdown = document_to_markdown(document)
    assert "Static analysis plan" in markdown
    assert STATIC_ANALYSIS_PLAN_SNAPSHOT_PATH in markdown
    assert "unpack" in markdown
    assert "packer_latch" in markdown.casefold()
    verified_block = markdown.split("## 4. Verified Mechanisms", 1)[1].split("### Candidate Mechanisms", 1)[0].split("## 5.", 1)[0]
    assert "LoadLibraryA -> GetProcAddress" not in verified_block
    assert "FUN_401000@401000 LoadLibraryA" not in verified_block
    assert "当前没有通过验证门限的完整机制" in verified_block
    how_lines = [line for line in markdown.splitlines() if line.strip().startswith("- How:")]
    assert not any("FUN_401000@401000 LoadLibraryA -> GetProcAddress" in line for line in how_lines)
    assert not any(
        "How:" in line and "LoadLibraryA -> GetProcAddress" in line and "FUN_" in line
        for line in markdown.splitlines()
    )


def test_missing_creation_flags_renders_named_unknown() -> None:
    evidence = {
        "e-process": SimpleNamespace(
            id="e-process",
            artifact_id="artifact-1",
            tool_run_id="tool-1",
            module="loader",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateProcessW", "target_name": "CreateProcessW"},
            anchor={"function_entry": "0x401000"},
        )
    }
    document = build_report_document(
        case=SimpleNamespace(id="case-flags"),
        task=_plan_report_task(
            {
                "investigation": {
                    "static_analysis_plan": {
                        "items": [
                            {
                                "id": "process-creation",
                                "title": "Recover CreateProcess construction",
                                "status": "UNKNOWN",
                                "unknowns": ["creation_flags", "parent identity"],
                                "next_method": "TRACE dwCreationFlags and parent attribute",
                            }
                        ]
                    }
                }
            }
        ),
        artifacts=[_plan_report_artifact()],
        tool_runs=[],
        evidence=list(evidence.values()),
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary"],
    )
    markdown = document_to_markdown(document)
    assert "UNKNOWN(creation_flags)" in markdown
    assert "UNKNOWN(parent_identity)" in markdown
    assert "open investigation gap" not in markdown.casefold()
    assert "explorer.exe" not in markdown.casefold()
    matrix = next(
        row
        for module in document["modules"]
        for row in module.get("rows", [])
        if row.get("type") == "catalog_behavior_matrix"
    )
    process_row = next(
        item for item in matrix["unclosed_high_value"] if item["catalog_id"] == "process-creation"
    )
    assert "UNKNOWN(creation_flags)" in process_row["reason"]


def test_missing_static_analysis_plan_key_still_builds_report() -> None:
    document = build_report_document(
        case=SimpleNamespace(id="case-old"),
        task=_plan_report_task({"investigation": {"threads": []}}),
        artifacts=[_plan_report_artifact()],
        tool_runs=[],
        evidence=[_evidence("e1")],
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )
    markdown = document_to_markdown(document)
    assert document["case_id"] == "case-old"
    assert document["task_id"] == "task-plan"
    assert "Static analysis plan" not in markdown
    assert "# 静态分析报告" in markdown
    task_no_snapshot = _plan_report_task()
    delattr(task_no_snapshot, "strategy_snapshot")
    document_legacy = build_report_document(
        case=SimpleNamespace(id="case-legacy"),
        task=task_no_snapshot,
        artifacts=[],
        tool_runs=[],
        evidence=[],
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary"],
    )
    assert document_to_markdown(document_legacy)
    assert "Static analysis plan" not in document_to_markdown(document_legacy)


def test_plan_completion_does_not_verify_how_or_weaken_readiness() -> None:
    document = build_report_document(
        case=SimpleNamespace(id="case-gold"),
        task=_plan_report_task(
            {
                "investigation": {
                    "static_analysis_plan": {
                        "packer_latch": True,
                        "items": [
                            {
                                "id": "unpack",
                                "title": "Unpack completed in planner",
                                "status": "COMPLETED",
                                "unknowns": [],
                                "next_method": "",
                            }
                        ],
                    }
                }
            }
        ),
        artifacts=[_plan_report_artifact()],
        tool_runs=[],
        evidence=[_evidence("e1")],
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary"],
    )
    markdown = document_to_markdown(document)
    assert "status=**COMPLETED**" in markdown
    assert "not verified HOW closure" in markdown
    verified_block = markdown.split("## 4. Verified Mechanisms", 1)[1].split("## 5.", 1)[0]
    assert "当前没有通过验证门限的完整机制" in verified_block
    readiness = document["analysis_quality"]["one_round_readiness"]
    assert "complete" in readiness
    assert report_one_round_readiness_violations(document, markdown) == list(
        readiness.get("violations") or []
    )

