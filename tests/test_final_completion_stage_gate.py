from __future__ import annotations

import json

from scripts.final_completion_stage_gate import build_gate


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
    assert len(gate["artifact_manifest"]) == 4
    assert any("CVE" in item for item in gate["blockers"])

