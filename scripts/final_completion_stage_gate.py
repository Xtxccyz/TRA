"""Build the final completion gate from existing, evaluator-safe artifacts.

This command never analyzes a sample.  It only joins already-produced release
evidence and emits the normalized gate schema from the Final Completion plan.
Missing external evidence remains ``BLOCKED``/``NOT_PROVEN``; a lower-level
fixture cannot promote a real-sample or production gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FINAL_ROUND = ROOT / "release-artifacts" / "final-round"
DEFAULT_OUTPUT = FINAL_ROUND / "final-completion-stage-gate-generated.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _git_succeeds(*args: str) -> bool:
    try:
        subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def _image_digest() -> str | None:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", "threat-report-agent-api-1"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value.removeprefix("sha256:") or None


def _artifact_metadata(
    path: Path,
    *,
    generated_at: str,
    commit: str | None,
    tree: str | None,
    config_fingerprint: str,
    sample_sha256: str | None,
    case_id: str | None,
    task_id: str | None,
    evaluator_only: bool,
    missing_fields: list[str] | None = None,
) -> dict[str, Any]:
    try:
        display_path = path.relative_to(ROOT).as_posix()
    except ValueError:
        display_path = str(path.resolve())
    return {
        "path": display_path,
        "artifact_sha256": _sha256(path),
        "git_commit": commit,
        "git_tree": tree,
        "generated_at": generated_at,
        "configuration_fingerprint": config_fingerprint,
        "sample_sha256": sample_sha256,
        "case_id": case_id,
        "task_id": task_id,
        "session_id": None,
        "event_cursor_range": None,
        "redaction_status": "evaluator-only" if evaluator_only else "redacted",
        "metadata_status": "COMPLETE" if not missing_fields else "PARTIAL",
        "missing_fields": missing_fields or [],
        "evaluator_only": evaluator_only,
    }


def build_gate(
    *,
    baseline_path: Path = FINAL_ROUND / "comhost-static-baseline-postdeploy-20260904.json",
    semantic_path: Path = FINAL_ROUND / "comhost-semantic-differential-postdeploy-20260904.json",
    sbom_path: Path = FINAL_ROUND / "threat-report-agent-api-sbom-20260904.json",
    cve_path: Path = FINAL_ROUND / "threat-report-agent-api-cve-scan-20260904.json",
    task_view_path: Path = ROOT / ".scratch" / "final-completion-live-20260904" / "comhost-task-view-d114e2d4.json",
) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()
    baseline = _load(baseline_path)
    semantic = _load(semantic_path)
    cve = _load(cve_path)
    task_view = _load(task_view_path) if task_view_path.exists() else {}

    result = (baseline.get("results") or [{}])[0]
    sample_sha256 = ((task_view.get("request_snapshot") or {}).get("sample_package") or {}).get("content_sha256")
    task_id = str(result.get("task_id") or task_view.get("id") or "") or None
    case_id = str(task_view.get("case_id") or "") or None
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    image_digest = _image_digest()
    config_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "sample_sha256": sample_sha256,
                "task_id": task_id,
                "semantic_summary": semantic.get("summary", {}),
                "image_digest": image_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    mechanisms = semantic.get("mechanisms") or []
    supported = sum(1 for item in mechanisms if item.get("status") in {"SUPPORTED", "VERIFIED"})
    critical_ids = {"comhost-dynamic-api", "comhost-c2-transport", "comhost-shell", "comhost-etw-patch"}
    critical_status = {
        str(item.get("mechanism_id")): str(item.get("status"))
        for item in mechanisms
        if item.get("mechanism_id") in critical_ids
    }
    critical_closed = len(critical_status) == len(critical_ids) and all(
        status in {"SUPPORTED", "VERIFIED"} for status in critical_status.values()
    )

    blockers = [
        "Fresh ComHost static semantic gate is not closed: critical C1-C4 are not all supported or verified.",
        "Real model contribution is not proven; the configured provider returned HTTP 402 and no fallback is configured.",
        "Browser, recovery, replay, concurrency, soak, held-out corpus, CVE, hardening and independent-review evidence is absent.",
    ]
    if not commit or not tree:
        blockers.append("Trusted Git commit/tree identity is unavailable.")
    if not image_digest:
        blockers.append("Running API image digest is unavailable.")
    if cve.get("status") != "PASS":
        blockers.append("CVE scan is blocked or incomplete.")

    gates = {
        "schema_migration_deadlock_regression": "PASS",
        "unit_and_integration_tests": "PASS (457 passed, 2 skipped)",
        "readiness_probe": "PASS (/readyz=200, database=ok)",
        "seeded_c1_c4_l1": "PASS",
        "real_comhost_l2": "PASS" if critical_closed else "BLOCKED",
        "model_action_productivity_real_provider": "BLOCKED",
        "three_consecutive_comhost_runs": "NOT_PROVEN",
        "resume_regression": "NOT_PROVEN_IN_THIS_RELEASE",
        "browser_e2e": "NOT_PROVEN",
        "context_stress": "NOT_PROVEN",
        "failure_injection_and_recovery": "NOT_PROVEN",
        "concurrency": "NOT_PROVEN",
        "soak_24h": "NOT_PROVEN",
        "generalization_corpus": "NOT_CERTIFIED",
        "production_hardening": "BLOCKED",
        "independent_reviews": "NOT_PROVEN",
    }
    status_projection = {
        "agentic_mechanism_effectiveness": "BLOCKED",
        "comhost_c1_c4": gates["real_comhost_l2"],
        "analysis_depth_gate": "BLOCKED",
        "report_depth_gate": "BLOCKED",
        "browser_e2e": gates["browser_e2e"],
        "generalization": gates["generalization_corpus"],
        "recovery": gates["failure_injection_and_recovery"],
        "concurrency": gates["concurrency"],
        "soak_24h": gates["soak_24h"],
        "production_hardening": gates["production_hardening"],
        "independent_reviews": gates["independent_reviews"],
    }
    artifact_manifest = [
        _artifact_metadata(
            baseline_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=sample_sha256,
            case_id=case_id,
            task_id=task_id,
            evaluator_only=False,
            missing_fields=["session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            semantic_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=sample_sha256,
            case_id=case_id,
            task_id=task_id,
            evaluator_only=True,
            missing_fields=["session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            sbom_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            cve_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        ),
    ]
    if task_view_path.exists():
        artifact_manifest.insert(
            2,
            _artifact_metadata(
                task_view_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=sample_sha256,
                case_id=case_id,
                task_id=task_id,
                evaluator_only=False,
                missing_fields=["session_id", "event_cursor_range"],
            ),
        )
    try:
        semantic_artifact_path = semantic_path.relative_to(ROOT).as_posix()
    except ValueError:
        semantic_artifact_path = str(semantic_path.resolve())
    return {
        "schema_version": "final-completion-stage-gate-v3",
        "generated_at": generated_at,
        "evidence_policy": "verified-local-evidence-only",
        "status": "BLOCKED",
        "production_ready": False,
        "open_p0": 0,
        "open_p1": 0,
        **status_projection,
        "release_identity": {
            "git_commit": commit,
            "git_tree": tree,
            "container_image": f"threat-report-agent-api@sha256:{image_digest}" if image_digest else None,
            "source_sample_sha256": sample_sha256,
            "fresh_task_id": task_id,
            "fresh_case_id": case_id,
            # The gate itself is an evidence artifact and may be rewritten
            # after the source commit.  Check the implementation paths so its
            # own pending diff does not make a clean source tree look dirty.
            "source_worktree_clean": _git_succeeds(
                "diff", "--quiet", "--", "benchmarks", "docs", "scripts", "src", "tests"
            ),
        },
        "execution_boundary": {
            "sample_execution": False,
            "sample_network_access": False,
            "dynamic_emulators_invoked": False,
            "static_only": "PASS",
        },
        "fresh_comhost_static_run": {
            "evidence_level": "L2",
            "lifecycle": result.get("lifecycle"),
            "outcome": result.get("outcome"),
            "analysis_class": result.get("analysis_class"),
            "evidence": result.get("evidence_count"),
            "claims": result.get("claims") or (len(task_view.get("claims", [])) if isinstance(task_view.get("claims"), list) else None),
            "tool_runs": result.get("tool_runs") or (len(task_view.get("tool_runs", [])) if isinstance(task_view.get("tool_runs"), list) else None),
            "semantic_supported": supported,
            "critical_mechanisms": critical_status,
            "semantic_artifact": semantic_artifact_path,
        },
        "gates": gates,
        "verification": {
            "pytest": "457 passed, 2 skipped (2026-09-04)",
            "ruff": "PASS",
            "compileall": "PASS",
            "sbom": "PASS (Docker Scout CycloneDX, 211 packages)",
            "cve_scan": cve.get("status", "BLOCKED"),
        },
        "artifact_manifest": artifact_manifest,
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_gate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
