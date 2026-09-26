"""B05 / M04 / M06: the report readiness gate and the adversarial self-check artefact.

Three obligations are pinned here, each on the PUBLISHED surface rather than on a helper:

* **M04** — every core Finding must carry What / How / Target / Condition / Output /
  Consumer / Evidence / Unknown.  A slot may be genuinely not applicable, but then the
  row must SAY so; an empty or bare-marker slot is an unmet requirement rather than a
  value, and an unmet gate must be published as PARTIAL/BOUNDED, never as a silently
  complete report.
* **M06** — before a high-value conclusion enters a report revision the adversarial
  over-claim check must exist as a structured artefact covering the six named
  evidence-to-behaviour leaps, and a conclusion that fails it must be downgraded
  (status AND severity) instead of being reported as established behaviour.
* **B05** — the compose gate must not accept a draft that keeps the operational
  limitation HEADING while dropping every bullet under it.  The heading is the marker
  that is supposed to prove the information survived; keeping it while deleting the
  content is the same loss the rule exists to prevent.

FAILS BEFORE THE FIX: `behavior_report_readiness_gate` did not exist, no gate verdict
was stamped on a document, a failing high-severity finding kept `HIGH`, and
`compose_gate_violations(DRAFT_KEEPING_HEADING_ONLY, FRAGMENTS)` returned `[]`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.report.analyst_report import (  # noqa: E402
    OPERATIONAL_LIMITATIONS_HEADING,
    compose_gate_violations,
    compact_analyst_context,
    render_official_markdown,
)
from threat_report_agent.report.reporting import (  # noqa: E402
    M06_SELF_CHECK_RULES,
    behavior_report_readiness_gate,
    build_report_document,
    markdown_to_docx,
    report_v3_quality_violations,
)

#: A pipeline operational limitation, in the exact shape the renderer writes it.
LIMITATION = "[pipeline] Tool run controlled-emulator ended CANCELLED: TOOL_ACTIVITY_CANCELLED."

_OPERATIONAL_BLOCK = f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- {LIMITATION}\n"
_FRAGMENTS = f"# 静态分析报告\n\n## 分析结论\n\n确定性正文。\n\n{_OPERATIONAL_BLOCK}"


def _evidence(evidence_id: str = "e1") -> SimpleNamespace:
    return SimpleNamespace(
        id=evidence_id,
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="loader",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "LoadLibraryW"},
        anchor={"function_entry": "0x401000"},
    )


def _artifact() -> SimpleNamespace:
    return SimpleNamespace(
        id="artifact-1",
        logical_path="sample.exe",
        content_sha256="a" * 64,
        detected_type="pe",
        role="EXECUTABLE",
        obligation="REQUIRED",
        parent_artifact_id=None,
    )


def _task(**overrides: object) -> SimpleNamespace:
    base = dict(
        id="task-b05",
        lifecycle="SUCCEEDED",
        outcome="PARTIAL",
        target_breadth="B0",
        target_depth="D3",
        actual_granularity={},
        request_snapshot={},
        limitations=["static-only"],
        analysis_class="BOUNDED_STATIC_ANALYSIS",
        coverage={},
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _claim(
    claim_id: str = "c1",
    *,
    statement: str = "The sample may prepare and load a secondary module.",
    mechanism: str = "resource -> resolve -> LoadLibraryW",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=claim_id,
        module="loader",
        claim_type="BEHAVIOR",
        subject="sample.exe",
        action="may_load_or_prepare_memory",
        object="secondary module",
        mechanism=mechanism,
        condition="static evidence only",
        statement=statement,
        status="CANDIDATE",
        confidence="HIGH",
        attack_mapping={},
        model_call_id=None,
    )


def _finding(**overrides: object) -> dict[str, object]:
    """A minimal behavior finding row, not yet projected by the pipeline."""
    base: dict[str, object] = {
        "type": "behavior_finding",
        "finding_id": "bf-1",
        "what": "The sample loads a secondary module",
        "how": "resource -> resolve -> LoadLibraryW",
        "target": "secondary module",
        "condition": "static evidence only",
        "output": "loaded module handle",
        "consumer": "GetProcAddress",
        "evidence_ids": ["e1"],
        "unknowns": ["runtime execution and intent are not observed"],
        "finding_status": "CANDIDATE",
        "status": "CANDIDATE",
    }
    base.update(overrides)
    return base


def _document(rows: list[dict[str, object]], *, quality: dict[str, object] | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "report_version": "3.0",
        "case_id": "case-1",
        "task_id": "task-1",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{"id": "behavior_attack", "rows": rows}],
    }
    if quality is not None:
        document["analysis_quality"] = quality
    return document


# ---------------------------------------------------------------------------
# M04 — the readiness gate
# ---------------------------------------------------------------------------


def test_silently_empty_template_slot_fails_the_readiness_gate() -> None:
    """A core finding whose `condition` is empty and unexplained is PARTIAL."""
    document = _document([_finding(condition="", conditions="")])

    gate = behavior_report_readiness_gate(document)

    assert gate["status"] == "PARTIAL", gate
    assert gate["complete"] is False
    entry = next(item for item in gate["core_findings_incomplete"] if item["finding_id"] == "bf-1")
    # `what/how/...` are present, so ONLY the empty slot is named.
    assert entry["missing_slots"] == ["condition"], entry
    assert "bf-1" in gate["unexplained_core_findings"]


def test_slot_with_a_recorded_reason_is_not_an_unexplained_hole() -> None:
    """The honest form is accepted: the row states the slot and why it is open."""
    document = _document([
        _finding(
            condition="",
            conditions="",
            unknowns=[
                "condition not recovered from available static evidence",
                "runtime execution and intent are not observed",
            ],
        )
    ])

    gate = behavior_report_readiness_gate(document)

    assert gate["status"] in {"READY", "BOUNDED"}, gate
    assert gate["unexplained_core_findings"] == []


def test_a_generic_unknown_does_not_explain_every_slot() -> None:
    """A blanket 'runtime execution is not observed' may not silence a slot."""
    document = _document([
        _finding(
            condition="",
            conditions="",
            unknowns=["runtime execution and intent are not observed"],
        )
    ])

    gate = behavior_report_readiness_gate(document)

    assert gate["status"] == "PARTIAL", gate
    assert gate["core_findings_incomplete"][0]["missing_slots"] == ["condition"]


def test_an_unmet_gate_cannot_be_published_as_a_complete_report() -> None:
    """The gate owns the completeness claim, whatever stamped the outcome."""
    document = _document(
        [_finding(condition="", conditions="")],
        quality={"readiness": "READY_FOR_REPORT", "readiness_gate": {"status": "PARTIAL"}},
    )
    document["analysis_outcome"] = "COMPLETE"

    violations = report_v3_quality_violations(document)

    assert any("M04 readiness gate is PARTIAL" in item for item in violations), violations


def test_build_report_document_stamps_the_gate() -> None:
    """The assembled revision always carries its own M04 verdict."""
    document = build_report_document(
        case=SimpleNamespace(id="case-gate"),
        task=_task(outcome="COMPLETE", analysis_class="FULL_STATIC_ANALYSIS"),
        artifacts=[_artifact()],
        tool_runs=[],
        evidence=[_evidence("e1")],
        claims=[_claim("c1")],
        claim_evidence=[SimpleNamespace(claim_id="c1", evidence_id="e1", stance="SUPPORTS")],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )

    gate = document["analysis_quality"]["readiness_gate"]
    assert gate["requirement"] == "M04"
    assert gate["core_findings_checked"] >= 1
    assert gate["status"] in {"READY", "BOUNDED", "PARTIAL"}
    assert gate["complete"] is (gate["status"] == "READY")
    # The verdict rides on the analysis_quality module row too, so a reader of
    # the module projection sees the same gate the document carries.
    quality_rows = [
        row
        for module in document["modules"]
        for row in module.get("rows", [])
        if row.get("type") == "analysis_quality"
    ]
    assert quality_rows, "no analysis_quality row in the projected modules"
    assert quality_rows[0]["readiness_gate"]["status"] == gate["status"]


def test_an_unmet_gate_degrades_a_complete_outcome_to_partial() -> None:
    """M04: an unmet gate is explicit PARTIAL, not a silently complete report."""
    from threat_report_agent.report.reporting import _stamp_behavior_readiness

    document = _document([_finding(condition="", conditions="")], quality={"readiness": "READY_FOR_REPORT"})
    document["analysis_outcome"] = "COMPLETE"

    gate = _stamp_behavior_readiness(document)

    assert gate["status"] == "PARTIAL", gate
    assert document["analysis_outcome"] == "PARTIAL", document["analysis_outcome"]
    assert document["analysis_quality"]["readiness"] == "BOUNDED_WITH_LIMITATIONS"


def test_a_core_finding_from_the_real_projection_is_not_silently_incomplete() -> None:
    """The projector's own UNKNOWN markers explain the slot they emptied.

    This is the NEGATIVE CONTROL for the gate: the pipeline's honest output must
    not be re-flagged as an unexplained hole, or the gate would fire on every
    real revision and be ignored.
    """
    document = build_report_document(
        case=SimpleNamespace(id="case-projection"),
        task=_task(),
        artifacts=[_artifact()],
        tool_runs=[],
        evidence=[_evidence("e1")],
        claims=[_claim("c1", statement="UNKNOWN(statement)", mechanism="UNKNOWN(mechanism)")],
        claim_evidence=[SimpleNamespace(claim_id="c1", evidence_id="e1", stance="SUPPORTS")],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )

    gate = document["analysis_quality"]["readiness_gate"]
    assert gate["core_findings_checked"] >= 1, gate
    assert gate["unexplained_core_findings"] == [], gate["core_findings_incomplete"]


def test_high_value_conclusion_needs_its_s4_state_recorded() -> None:
    """M06: a HIGH finding with no S4 orchestration row is BOUNDED, not READY."""
    document = _document(
        [_finding(finding_status="VERIFIED", status="VERIFIED", severity="HIGH")],
        quality={"s4_orchestration": []},
    )

    gate = behavior_report_readiness_gate(document)

    assert gate["s4_orchestration_recorded"] is False
    assert gate["status"] == "BOUNDED", gate


# ---------------------------------------------------------------------------
# M06 — the adversarial self-check gate
# ---------------------------------------------------------------------------


def test_self_check_artefact_covers_the_six_named_leaps() -> None:
    document = _document([_finding()], quality={})

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)
    artefact = document["analysis_quality"]["m06_self_check"]

    assert artefact["traceable"] is True
    assert artefact["status"] == "PASS"
    assert set(artefact["rules_covered"]) == {rule["rule_id"] for rule in M06_SELF_CHECK_RULES}
    assert len(artefact["rules_covered"]) == 6
    assert artefact["checks"], "every rule needs a recorded verdict, including the quiet ones"
    assert all(item["status"] in {"CHECKED", "BLOCKED"} for item in artefact["checks"])


def test_network_endpoint_as_active_c2_is_downgraded_from_high() -> None:
    """API/string level evidence may not be published as live C2, let alone HIGH."""
    document = _document(
        [
            _finding(
                what="The sample beacons to its active C2 endpoint",
                how="WinHttpOpen to the recovered host",
                severity="HIGH",
                finding_status="VERIFIED",
                status="VERIFIED",
                unknowns=[],
            )
        ],
        quality={},
    )

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)
    row = document["modules"][0]["rows"][0]
    artefact = document["analysis_quality"]["m06_self_check"]

    assert row["status"] == "CANDIDATE", row
    assert row["finding_status"] == "CANDIDATE"
    assert row["severity"] == "UNASSESSED", row
    assert artefact["status"] == "BLOCKED"
    assert artefact["downgraded"] and artefact["downgraded"][0]["rules"] == ["NETWORK_IS_C2"]
    assert artefact["downgraded"][0]["previous_status"] == "VERIFIED"
    blocked = next(item for item in artefact["checks"] if item["rule_id"] == "NETWORK_IS_C2")
    assert blocked["status"] == "BLOCKED"
    assert blocked["hits"] == ["bf-1"]


def test_api_name_alone_is_not_high_severity_behavior() -> None:
    """A bare API name is a seed, not a behaviour with a severity."""
    document = _document(
        [
            _finding(
                what="CreateFileW",
                how="",
                condition="",
                output="",
                consumer="",
                severity="CRITICAL",
                finding_status="VERIFIED",
                status="VERIFIED",
                unknowns=[],
            )
        ],
        quality={},
    )

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)
    row = document["modules"][0]["rows"][0]

    assert row["severity"] == "UNASSESSED"
    assert row["status"] == "CANDIDATE"
    rules = {
        hit["rule_id"] for hit in document["analysis_quality"]["m06_self_check"]["hits"]
    }
    assert "API_IS_BEHAVIOR" in rules


def test_collection_without_a_network_sink_is_not_exfiltration() -> None:
    document = _document(
        [
            _finding(
                what="The sample collects browser profile files",
                how="FindFirstFileW over the profile directory",
                statement="Collection of browser profile files into the temp directory",
                security_meaning="exfiltration of browser credentials",
                severity="HIGH",
                finding_status="VERIFIED",
                status="VERIFIED",
                unknowns=[],
            )
        ],
        quality={},
    )

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)
    row = document["modules"][0]["rows"][0]
    artefact = document["analysis_quality"]["m06_self_check"]

    assert "COLLECTION_IS_EXFILTRATION" in {
        hit["rule_id"] for hit in artefact["hits"]
    }
    assert row["severity"] == "UNASSESSED"


def test_emulation_observed_is_not_rewritten_as_unobserved_runtime() -> None:
    """A row with EMULATION_OBSERVED provenance is not failing the runtime rule."""
    document = _document(
        [
            _finding(
                what="The decoder was executed in an isolated worker",
                statement="runtime observed in isolated emulation: decoded buffer recovered",
                evidence_natures=["EMULATION_OBSERVED"],
                unknowns=[],
            )
        ],
        quality={},
    )

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)

    rules = {
        hit["rule_id"] for hit in document["analysis_quality"]["m06_self_check"]["hits"]
    }
    assert "SIMULATION_IS_RUNTIME" not in rules


def test_static_report_saying_the_sample_did_not_run_is_not_an_overclaim() -> None:
    """The honest boundary statement must not be policed as a runtime claim."""
    document = _document(
        [_finding(statement="样本未运行，运行时行为仅作静态推断。", unknowns=[])],
        quality={},
    )

    from threat_report_agent.report.reporting import _write_m06_self_check

    _write_m06_self_check(document)

    rules = {
        hit["rule_id"] for hit in document["analysis_quality"]["m06_self_check"]["hits"]
    }
    assert "SIMULATION_IS_RUNTIME" not in rules


def test_self_check_that_blocks_without_downgrading_is_a_violation() -> None:
    document = _document(
        [],
        quality={
            "readiness": "BOUNDED_WITH_LIMITATIONS",
            "m06_self_check": {"status": "BLOCKED", "downgraded": []},
        },
    )

    violations = report_v3_quality_violations(document)

    assert any("no conclusion was downgraded" in item for item in violations), violations


def test_the_official_body_states_partial_when_the_gate_is_unmet() -> None:
    """M04: the reader's surface says PARTIAL, not a complete-looking report."""
    document = _document(
        [_finding(condition="", conditions="")],
        quality={"readiness": "BOUNDED_WITH_LIMITATIONS", "readiness_gate": {"status": "PARTIAL"}},
    )
    document["analysis_outcome"] = "COMPLETE"

    official = render_official_markdown(document)

    assert "- 任务结果：**PARTIAL**" in official, official[:400]
    task_line = next(line for line in official.splitlines() if line.startswith("- 任务结果："))
    assert "COMPLETE" not in task_line
    assert "M04 报告就绪门：**PARTIAL**" in official


def test_a_ready_gate_does_not_rewrite_the_task_outcome() -> None:
    """NEGATIVE CONTROL: a satisfied gate leaves the declared outcome alone."""
    document = _document(
        [_finding()],
        quality={"readiness": "READY_FOR_REPORT", "readiness_gate": {"status": "READY"}},
    )
    document["analysis_outcome"] = "COMPLETE"

    official = render_official_markdown(document)

    assert "- 任务结果：**COMPLETE**" in official, official[:400]


# ---------------------------------------------------------------------------
# B05 — the compose gate may not accept a heading without its content
# ---------------------------------------------------------------------------


def test_draft_keeping_the_limitations_heading_but_dropping_every_bullet_is_rejected() -> None:
    """The heading is the marker that proves the content survived; it cannot be a substitute."""
    draft = (
        "# 静态分析报告\n\n## 分析结论\n\n模型润色后的正文。\n\n"
        f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n"
    )

    violations = compose_gate_violations(draft, _FRAGMENTS)

    assert any("keeps the operational-limitations heading but drops" in item for item in violations), (
        "a draft kept the heading and deleted the limitation it marks; the reader would see the marker "
        f"with nothing under it. violations={violations}"
    )


def test_the_previous_heading_only_rule_would_have_accepted_that_draft() -> None:
    """Records WHY the test above is a red-to-green change, not a style preference.

    The pre-fix rule was exactly this one line (an in-test copy of it), so the
    hole is reproduced here rather than asserted from memory.
    """
    draft = (
        "# 静态分析报告\n\n## 分析结论\n\n模型润色后的正文。\n\n"
        f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n"
    )

    def old_rule(text: str, source: str) -> list[str]:
        if OPERATIONAL_LIMITATIONS_HEADING in source and OPERATIONAL_LIMITATIONS_HEADING not in text:
            return ["draft omits the pipeline's operational limitations"]
        return []

    assert old_rule(draft, _FRAGMENTS) == [], (
        "the old rule did not fire on a heading-only draft, so the strengthened rule is a real change"
    )
    assert compose_gate_violations(draft, _FRAGMENTS), "the strengthened rule must fire on it"


def test_draft_carrying_the_bullets_still_passes_that_rule() -> None:
    """NEGATIVE CONTROL: the strengthened rule must not reject a compliant draft."""
    draft = "# 静态分析报告\n\n## 分析结论\n\n模型润色后的正文。\n\n" + _OPERATIONAL_BLOCK

    violations = compose_gate_violations(draft, _FRAGMENTS)

    assert not any("operational-limitations heading" in item for item in violations), violations


def test_the_plan_named_probe_reading_is_now_non_empty() -> None:
    """The same reading `scripts/structure_behavior_probe.py` freezes as a known gap.

    That probe records `violations_for_heading_kept_bullets_dropped` and labels it
    "PLAN-NAMED FALSE-GREEN, RECORDED NOT FIXED"; the reading is reproduced here so the
    fix is visible in the suite as well as in the probe output.
    """
    block = f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- [pipeline] Tool run x ended TIMED_OUT: T.\n"
    fragments = f"# 静态分析报告\n\n## 分析结论\n\n正文。\n\n{block}"
    draft_without = "# 静态分析报告\n\n## 分析结论\n\n模型润色正文。\n"
    draft_heading_only = f"{draft_without}\n{OPERATIONAL_LIMITATIONS_HEADING}\n"

    assert compose_gate_violations(draft_heading_only, fragments), (
        "the probe's known gap must now be non-empty"
    )
    assert compose_gate_violations(draft_without, fragments), "omitting the block stays a violation"


def test_dropping_one_of_two_limitation_bullets_is_reported_as_a_partial_drop() -> None:
    """The gate counts bullets, so a partial drop is not rounded up to 'present'."""
    second = "[pipeline] Ghidra tool run ended TIMED_OUT: ANALYSIS_TIMEOUT."
    fragments = (
        "# 静态分析报告\n\n## 分析结论\n\n正文。\n\n"
        f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- {LIMITATION}\n- {second}\n"
    )
    draft = (
        "# 静态分析报告\n\n## 分析结论\n\n模型润色正文。\n\n"
        f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- {LIMITATION}\n"
    )

    violations = compose_gate_violations(draft, fragments)

    assert any("drops 1 of 2 limitation bullets" in item for item in violations), violations


# ---------------------------------------------------------------------------
# B05 — every graph edge states its basis, and no string becomes a behaviour
# ---------------------------------------------------------------------------


def test_every_projected_edge_states_a_basis() -> None:
    """B05: an edge with no Evidence/Claim/typed basis is labelled UNSTATED."""
    document = _document([
        {
            "type": "behavior_relation",
            "relation_id": "rel-with-evidence",
            "relation_type": "LOADS",
            "source_finding_id": "bf-1",
            "target_finding_id": "bf-2",
            "evidence_ids": ["e1"],
        },
        {
            "type": "behavior_relation",
            "relation_id": "rel-claim-only",
            "relation_type": "DECRYPTS",
            "claim_id": "c1",
        },
        {
            "type": "behavior_relation",
            "relation_id": "rel-unbacked",
            "relation_type": "INJECTS",
            "source_artifact_id": "artifact-1",
            "target_artifact_id": "artifact-2",
        },
    ])

    from threat_report_agent.report.reporting import behavior_report_edge_gate, _write_edge_gate

    gate = behavior_report_edge_gate(document)

    basis = {edge["relation_id"]: edge["basis"] for edge in gate["edges"]}
    assert basis == {
        "rel-with-evidence": "EVIDENCE",
        "rel-claim-only": "CLAIM",
        "rel-unbacked": "UNSTATED",
    }, basis
    assert gate["edges_without_basis"] == ["rel-unbacked"]
    assert gate["status"] == "BOUNDED"

    _write_edge_gate(document)
    rows = document["modules"][0]["rows"]
    assert next(row for row in rows if row["relation_id"] == "rel-unbacked")["basis"] == "UNSTATED"


def test_a_string_fact_in_the_summary_is_recorded_as_a_violation() -> None:
    """B05: an API/string seed may not become the summary's answer to 'what does it do'."""
    from threat_report_agent.report.reporting import _string_fact_summary_check

    document = _document([])
    document["modules"][0]["id"] = "executive_summary"
    document["modules"][0]["summary"] = "The sample calls WinHttpOpen to reach its endpoint."
    document["string_facts"] = {"facts": [{"value": "WinHttpOpen", "fact_class": "network_api"}]}

    check = _string_fact_summary_check(document)

    assert check["status"] == "BLOCKED", check
    assert check["summary_only_facts"] == ["WinHttpOpen"]


def test_a_string_fact_used_as_corroboration_is_not_a_violation() -> None:
    """NEGATIVE CONTROL: quoting a recovered string is not presenting it as behaviour."""
    from threat_report_agent.report.reporting import _string_fact_summary_check

    document = _document([])
    document["modules"][0]["id"] = "executive_summary"
    document["modules"][0]["summary"] = (
        "The loader resolves APIs at runtime; the recovered string table is listed under Indicators."
    )
    document["string_facts"] = {"facts": [{"value": "WinHttpOpen", "fact_class": "network_api"}]}

    check = _string_fact_summary_check(document)

    assert check["status"] == "PASS", check


# ---------------------------------------------------------------------------
# B05 — chat / report / export render the same revision
# ---------------------------------------------------------------------------


def test_chat_report_and_export_share_one_revision() -> None:
    """B05: the chat context, the report body and the export render ONE revision.

    The DOCX is a ZIP, so the assertion unzips `word/document.xml` and compares
    the SEMANTIC tokens it carries against the markdown body's - a byte grep for
    the revision string would only prove the zip stored it uncompressed.
    """
    import io
    import zipfile

    from threat_report_agent.report.analyst_report import official_revision_semantic_tokens

    document = build_report_document(
        case=SimpleNamespace(id="case-rev"),
        task=_task(authoritative_revision_id="rev-shared-1"),
        artifacts=[_artifact()],
        tool_runs=[],
        evidence=[_evidence("e1")],
        claims=[_claim("c1")],
        claim_evidence=[SimpleNamespace(claim_id="c1", evidence_id="e1", stance="SUPPORTS")],
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "behavior_attack"],
    )

    official = render_official_markdown(document)
    chat = compact_analyst_context(document)
    docx = markdown_to_docx(official)
    with zipfile.ZipFile(io.BytesIO(docx)) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")

    assert document["authoritative_revision_id"] == "rev-shared-1"
    assert document["report_revision_id"] == "rev-shared-1"
    assert chat["authoritative_revision_id"] == "rev-shared-1"
    assert "`rev-shared-1`" in official
    assert "rev-shared-1" in xml, "the export dropped the revision it was rendered from"

    body_tokens = official_revision_semantic_tokens(official)
    export_tokens = official_revision_semantic_tokens(xml)
    assert export_tokens, "the exported body carries no semantic tokens"
    assert export_tokens <= body_tokens, (
        "the export carries facts the report body does not, so they are not one revision; "
        f"extra={sorted(export_tokens - body_tokens)[:8]}"
    )
