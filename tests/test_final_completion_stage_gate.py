from __future__ import annotations

import json

import pytest

from scripts.final_completion_stage_gate import FORMAL_GATE_FIELDS, _git, build_gate, validate_gate_schema


def _write(path, value) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_final_gate_has_plan_schema_projection_and_preserves_blockers(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    task = tmp_path / "task.json"
    _write(
        baseline,
        {
            "results": [
                {
                    "task_id": "task-1",
                    "lifecycle": "SUCCEEDED",
                    "outcome": "PARTIAL",
                    "analysis_class": "BOUNDED_STATIC_ANALYSIS",
                    "evidence_count": 2,
                    "claims": 1,
                    "tool_runs": 1,
                }
            ]
        },
    )
    _write(
        semantic,
        {
            "summary": {"supported": 1, "unknown": 10},
            "mechanisms": [
                {"mechanism_id": "comhost-dynamic-api", "status": "SUPPORTED"},
                {"mechanism_id": "comhost-c2-transport", "status": "UNKNOWN"},
                {"mechanism_id": "comhost-shell", "status": "SUPPORTED"},
                {"mechanism_id": "comhost-etw-patch", "status": "UNKNOWN"},
            ],
        },
    )
    _write(sbom, {"status": "PASS"})
    _write(cve, {"status": "BLOCKED"})
    _write(
        task,
        {
            "id": "task-1",
            "case_id": "case-1",
            "request_snapshot": {"sample_package": {"content_sha256": "a" * 64}},
        },
    )

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        task_view_path=task,
    )

    required = {
        "open_p0",
        "open_p1",
        "agentic_mechanism_effectiveness",
        "comhost_c1_c4",
        "analysis_depth_gate",
        "report_depth_gate",
        "browser_e2e",
        "generalization",
        "recovery",
        "concurrency",
        "soak_24h",
        "production_hardening",
        "independent_reviews",
    }
    assert required <= gate.keys()
    assert gate["status"] == "BLOCKED"
    assert gate["production_ready"] is False
    assert gate["comhost_c1_c4"] == "BLOCKED"
    assert gate["release_identity"]["fresh_task_id"] == "task-1"
    assert gate["release_identity"]["fresh_case_id"] == "case-1"
    assert len(gate["artifact_manifest"]) == 6
    assert all(isinstance(item, dict) for item in gate["artifact_manifest"])
    assert any("CVE" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


def test_final_gate_recognizes_valid_cyclonedx_sbom_without_status(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"bomFormat": "CycloneDX", "components": []}),
        (cve, {"status": "BLOCKED"}),
    ):
        _write(path, value)

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
    )

    assert gate["verification"]["sbom"] == "PASS"
    assert not any("SBOM evidence" in item for item in gate["blockers"])


def test_final_gate_uses_current_pytest_summary_and_rejects_stale_identity(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    summary = tmp_path / "pytest.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "PASS"}),
        (cve, {"status": "BLOCKED"}),
    ):
        _write(path, value)
    _write(
        summary,
        {
            "summary": "457 passed, 2 skipped (2026-09-04)",
            "git_commit": "stale",
            "git_tree": "stale",
        },
    )

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        pytest_summary_path=summary,
    )

    assert gate["verification"]["pytest"] == "457 passed, 2 skipped (2026-09-04)"
    assert gate["gates"]["unit_and_integration_tests"] == "BLOCKED (457 passed, 2 skipped (2026-09-04))"
    assert any("Pytest summary evidence" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])
    assert any(item["path"].endswith("pytest.json") for item in gate["artifact_manifest"])


def test_final_gate_rejects_blocked_payload_without_blockers() -> None:
    payload = {
        "status": "BLOCKED",
        "production_ready": False,
        **{field: "BLOCKED" for field in FORMAL_GATE_FIELDS},
        "blockers": [],
    }

    with pytest.raises(ValueError, match="must name at least one blocker"):
        validate_gate_schema(payload)


def test_final_gate_uses_frozen_baseline_manifest_when_run_artifact_has_no_identity(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    manifest = tmp_path / "manifest.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    _write(baseline, {"results": [{}]})
    _write(semantic, {"summary": {}, "mechanisms": []})
    _write(sbom, {"status": "PASS"})
    _write(cve, {"status": "BLOCKED"})
    _write(manifest, {"repository": {"backend_commit": "stale", "backend_tree": "stale"}})

    gate = build_gate(
        baseline_path=baseline,
        baseline_manifest_path=manifest,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
    )

    assert gate["release_identity"]["baseline_manifest"].endswith("manifest.json")
    assert gate["release_identity"]["baseline_identity_match"] is False


def test_final_gate_fails_closed_when_verification_evidence_is_missing(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "BLOCKED"}),
        (cve, {"status": "BLOCKED"}),
    ):
        _write(path, value)

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
    )

    assert gate["verification"]["sbom"] == "BLOCKED"
    assert gate["verification"]["ruff"] == "NOT_PROVEN"
    assert gate["verification"]["compileall"] == "NOT_PROVEN"
    assert any("SBOM evidence" in item for item in gate["blockers"])
    assert any("Ruff lint evidence" in item for item in gate["blockers"])
    assert any("compileall evidence" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


def test_final_gate_fails_closed_when_format_debt_identity_is_missing(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    format_debt = tmp_path / "format-debt.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "PASS"}),
        (cve, {"status": "BLOCKED"}),
        (format_debt, {"status": "PASS"}),
    ):
        _write(path, value)

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        format_debt_path=format_debt,
    )

    assert gate["verification"]["ruff_format_debt"] == "BLOCKED"
    assert any("Ruff format-debt evidence is missing" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


def test_final_gate_fails_closed_when_ruff_or_compileall_tree_is_stale(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    ruff = tmp_path / "ruff.json"
    compileall = tmp_path / "compileall.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "PASS"}),
        (cve, {"status": "BLOCKED"}),
        (ruff, {"status": "PASS", "git_commit": "stale", "git_tree": "stale"}),
        (compileall, {"status": "PASS", "git_commit": "stale", "git_tree": "stale"}),
    ):
        _write(path, value)

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        ruff_path=ruff,
        compileall_path=compileall,
    )

    assert gate["verification"]["ruff"] == "BLOCKED"
    assert gate["verification"]["compileall"] == "BLOCKED"
    assert any("Ruff evidence identity does not match" in item for item in gate["blockers"])
    assert any("compileall evidence identity does not match" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


def test_final_gate_consumes_bound_wave_evidence(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    seeded = tmp_path / "seeded.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "PASS"}),
        (cve, {"status": "BLOCKED"}),
    ):
        _write(path, value)
    _write(
        seeded,
        {
            "status": "PASS",
            "evidence_level": "L1",
            "git_commit": _git("rev-parse", "HEAD"),
            "git_tree": _git("rev-parse", "HEAD^{tree}"),
        },
    )

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        seeded_gate_path=seeded,
    )

    assert gate["gates"]["seeded_c1_c4_l1"] == "PASS"
    assert any(item["path"].endswith("seeded.json") for item in gate["artifact_manifest"])


def test_final_gate_rejects_unbound_wave_evidence(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    semantic = tmp_path / "semantic.json"
    sbom = tmp_path / "sbom.json"
    cve = tmp_path / "cve.json"
    seeded = tmp_path / "seeded.json"
    for path, value in (
        (baseline, {"results": [{}]}),
        (semantic, {"summary": {}, "mechanisms": []}),
        (sbom, {"status": "PASS"}),
        (cve, {"status": "BLOCKED"}),
        (seeded, {"status": "PASS"}),
    ):
        _write(path, value)

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        seeded_gate_path=seeded,
    )

    assert gate["gates"]["seeded_c1_c4_l1"] == "BLOCKED"
    assert any("Seeded C1-C4 evidence is missing git_commit" in item for item in gate["blockers"])
