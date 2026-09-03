from __future__ import annotations

import json

import pytest

from scripts.final_completion_stage_gate import FORMAL_GATE_FIELDS, build_gate, validate_gate_schema


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
    assert len(gate["artifact_manifest"]) == 5
    assert all(isinstance(item, dict) for item in gate["artifact_manifest"])
    assert any("CVE" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


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
    _write(summary, {"summary": "457 passed, 2 skipped (2026-09-04)", "git_commit": "stale"})

    gate = build_gate(
        baseline_path=baseline,
        semantic_path=semantic,
        sbom_path=sbom,
        cve_path=cve,
        pytest_summary_path=summary,
    )

    assert gate["verification"]["pytest"] == "457 passed, 2 skipped (2026-09-04)"
    assert gate["gates"]["unit_and_integration_tests"] == "PASS (457 passed, 2 skipped (2026-09-04))"
    assert any("Pytest summary identity" in item for item in gate["blockers"])
    assert gate["blocker_count"] == len(gate["blockers"])


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
