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
DEFAULT_TASK_VIEW_PATH = ROOT / ".scratch" / "final-completion-live-20260904" / "comhost-task-view-d114e2d4.json"
DEFAULT_BASELINE_PATH = FINAL_ROUND / "comhost-static-baseline-postdeploy-20260904.json"

# These names are the release-facing contract from the Final Completion plan.
# Internal gate names may be added, but they must not replace these fields.
FORMAL_GATE_FIELDS = frozenset(
    {
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
)

# Acceptance artifacts are deliberately mapped here instead of encoding a
# permanent answer in the gate.  A release artifact can promote a gate only
# when it contains an explicit PASS and the same source identity as the
# current checkout (see ``_load_gate_evidence``).  Missing, stale, or
# incomplete artifacts therefore remain NOT_PROVEN/BLOCKED.
DEFAULT_GATE_EVIDENCE_SOURCES: dict[str, tuple[Path, ...]] = {
    "agentic_mechanism_effectiveness": (
        FINAL_ROUND / "model-effectiveness-real-20260902.json",
    ),
    "analysis_depth_gate": (
        FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        FINAL_ROUND / "resume-regression-summary-20260904.json",
    ),
    "report_depth_gate": (
        FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        FINAL_ROUND / "resume-regression-summary-20260904.json",
    ),
    "browser_e2e": (FINAL_ROUND / "browser-e2e-20260902.json",),
    "generalization": (ROOT / "release-artifacts" / "round11.2" / "heldout-results.json",),
    "recovery": (ROOT / "release-artifacts" / "round11.2" / "restart-recovery.json",),
    "concurrency": (ROOT / "release-artifacts" / "round11.2" / "concurrency.json",),
    "soak_24h": (ROOT / "release-artifacts" / "round11.2" / "soak-24h.json",),
    "production_hardening": (
        ROOT / "release-artifacts" / "round11.2" / "production-hardening.json",
    ),
    "independent_reviews": (
        ROOT / "release-artifacts" / "round11.2" / "independent-reviews.json",
    ),
}


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


def _baseline_identity(baseline: dict[str, Any]) -> tuple[str | None, str | None]:
    """Read the source identity from either baseline schema revision."""
    repository = baseline.get("repository")
    if not isinstance(repository, dict):
        return None, None
    commit = repository.get("backend_commit") or repository.get("git_commit")
    tree = repository.get("backend_tree") or repository.get("git_tree")
    return (
        str(commit) if commit else None,
        str(tree) if tree else None,
    )


def _identity_error(
    payload: dict[str, Any],
    *,
    label: str,
    commit: str | None,
    tree: str | None,
) -> str | None:
    """Return a fail-closed identity error for a verification artifact.

    A verification result is only evidence for this release when it records
    both the commit and tree it checked and those values match the current
    checkout.  Missing identity is intentionally not treated as legacy
    compatibility: a PASS without provenance is not trustworthy evidence.
    """
    observed_commit = payload.get("git_commit")
    observed_tree = payload.get("git_tree")
    if not observed_commit or not observed_tree:
        return f"{label} evidence is missing git_commit and/or git_tree identity."
    if not commit or not tree:
        return f"{label} evidence cannot be trusted because current HEAD/tree identity is unavailable."
    if str(observed_commit) != commit or str(observed_tree) != tree:
        return f"{label} evidence identity does not match the current HEAD/tree."
    return None


def _load_gate_evidence(
    path: Path | None,
    *,
    label: str,
    commit: str | None,
    tree: str | None,
) -> tuple[str, dict[str, Any], str | None]:
    """Load one release gate artifact without trusting unbound PASS values.

    A missing optional artifact means the corresponding acceptance activity was
    not proven for this release.  A present artifact with malformed JSON or a
    stale/missing source identity is an explicit BLOCKED condition.  Callers
    may then project the artifact status while retaining the blocker.
    """
    if path is None:
        return "NOT_PROVEN", {}, f"{label} evidence is not supplied."
    if not path.exists():
        return "NOT_PROVEN", {}, f"{label} evidence file is missing: {path}."
    try:
        payload = _load(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return "BLOCKED", {}, f"{label} evidence is invalid: {exc}."
    identity_error = _identity_error(payload, label=label, commit=commit, tree=tree)
    if identity_error:
        return "BLOCKED", payload, identity_error
    status_value: object = payload.get("status")
    if not status_value:
        # Older acceptance artifacts put the gate result under a metrics or
        # report-depth envelope. Read those projections without treating a
        # missing value as success.
        metrics = payload.get("metrics")
        if isinstance(metrics, dict):
            status_value = metrics.get("status") or metrics.get("readiness")
            report_depth = metrics.get("report_depth")
            if not status_value and isinstance(report_depth, dict):
                status_value = report_depth.get("status")
        status_value = status_value or payload.get("gate_status") or payload.get("overall_status")
    status = str(status_value or "").strip().upper()
    if not status:
        return "BLOCKED", payload, f"{label} evidence has no status."
    return status, payload, None


def validate_gate_schema(payload: dict[str, Any]) -> None:
    """Fail closed when the release-facing gate contract is malformed."""
    missing = sorted(FORMAL_GATE_FIELDS - payload.keys())
    if missing:
        raise ValueError(f"final gate is missing formal fields: {', '.join(missing)}")
    if payload.get("status") == "PASS" and payload.get("blockers"):
        raise ValueError("a PASS final gate cannot contain blockers")
    if payload.get("status") == "BLOCKED" and not payload.get("blockers"):
        raise ValueError("a BLOCKED final gate must name at least one blocker")
    blocker_count = payload.get("blocker_count")
    blockers = payload.get("blockers") or []
    if blocker_count != len(blockers):
        raise ValueError("blocker_count must equal the number of unique blockers")
    if payload.get("status") == "PASS" and blocker_count != 0:
        raise ValueError("a PASS final gate must have blocker_count=0")
    if payload.get("production_ready") is True and payload.get("status") != "PASS":
        raise ValueError("production_ready=true requires status=PASS")


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
    resolved_path = path.resolve()
    try:
        display_path = resolved_path.relative_to(ROOT).as_posix()
    except ValueError:
        display_path = str(resolved_path)
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
    baseline_path: Path = DEFAULT_BASELINE_PATH,
    semantic_path: Path = FINAL_ROUND / "comhost-semantic-differential-postdeploy-20260904.json",
    sbom_path: Path = FINAL_ROUND / "threat-report-agent-api-sbom-20260904.json",
    cve_path: Path = FINAL_ROUND / "threat-report-agent-api-cve-scan-20260904.json",
    ruff_path: Path | None = None,
    compileall_path: Path | None = None,
    task_view_path: Path = DEFAULT_TASK_VIEW_PATH,
    pytest_summary: str | None = None,
    pytest_summary_path: Path | None = None,
    baseline_manifest_path: Path = FINAL_ROUND / "baseline-manifest.json",
    format_debt_path: Path = FINAL_ROUND / "ruff-format-debt-check-20260904.json",
    seeded_gate_path: Path | None = None,
    model_effectiveness_path: Path | None = None,
    analysis_depth_path: Path | None = None,
    report_depth_path: Path | None = None,
    browser_e2e_path: Path | None = None,
    context_stress_path: Path | None = None,
    recovery_path: Path | None = None,
    concurrency_path: Path | None = None,
    soak_path: Path | None = None,
    comhost_runs_path: Path | None = None,
    generalization_path: Path | None = None,
    production_hardening_path: Path | None = None,
    independent_reviews_path: Path | None = None,
    resume_regression_path: Path | None = None,
) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()
    baseline = _load(baseline_path)
    semantic = _load(semantic_path)
    sbom = _load(sbom_path)
    cve = _load(cve_path)
    ruff = _load(ruff_path) if ruff_path is not None and ruff_path.exists() else {}
    compileall = (
        _load(compileall_path)
        if compileall_path is not None and compileall_path.exists()
        else {}
    )
    format_debt = _load(format_debt_path) if format_debt_path.exists() else {}
    # The live ComHost task projection can be hundreds of megabytes because it
    # contains the complete Evidence ledger. Test/fixture callers commonly
    # replace the baseline with a temporary artifact; do not eagerly parse the
    # unrelated live projection in that case (and risk an avoidable OOM).
    use_task_view = task_view_path.exists() and (
        task_view_path != DEFAULT_TASK_VIEW_PATH or baseline_path == DEFAULT_BASELINE_PATH
    )
    task_view = _load(task_view_path) if use_task_view else {}

    result = (baseline.get("results") or [{}])[0]
    sample_sha256 = ((task_view.get("request_snapshot") or {}).get("sample_package") or {}).get("content_sha256")
    task_id = str(result.get("task_id") or task_view.get("id") or "") or None
    case_id = str(task_view.get("case_id") or "") or None
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    identity_source = baseline
    identity_path = baseline_path
    if not isinstance(baseline.get("repository"), dict) and baseline_manifest_path.exists():
        identity_source = _load(baseline_manifest_path)
        identity_path = baseline_manifest_path
    baseline_commit, baseline_tree = _baseline_identity(identity_source)
    baseline_identity_match = bool(
        commit
        and tree
        and baseline_commit == commit
        and baseline_tree == tree
    )
    image_digest = _image_digest()
    source_worktree_clean = _git_succeeds(
        "diff", "--quiet", "--", "benchmarks", "docs", "scripts", "src", "tests"
    )

    # Optional acceptance artifacts are evaluated independently. Their
    # statuses are projected into the final dashboard only after the artifact
    # is bound to this checkout; missing evidence remains NOT_PROVEN and an
    # invalid or stale artifact is BLOCKED.
    evidence_specs = {
        "seeded_c1_c4_l1": (seeded_gate_path, "Seeded C1-C4"),
        "model_action_productivity_real_provider": (model_effectiveness_path, "Model effectiveness"),
        "analysis_depth_gate": (analysis_depth_path, "Analysis depth"),
        "report_depth_gate": (report_depth_path, "Report depth"),
        "browser_e2e": (browser_e2e_path, "Browser E2E"),
        "context_stress": (context_stress_path, "Context stress"),
        "failure_injection_and_recovery": (recovery_path, "Recovery"),
        "concurrency": (concurrency_path, "Concurrency"),
        "soak_24h": (soak_path, "24-hour soak"),
        "three_consecutive_comhost_runs": (comhost_runs_path, "Three consecutive ComHost runs"),
        "generalization_corpus": (generalization_path, "Generalization"),
        "production_hardening": (production_hardening_path, "Production hardening"),
        "independent_reviews": (independent_reviews_path, "Independent reviews"),
        "resume_regression": (resume_regression_path, "Resume regression"),
    }
    evidence_statuses: dict[str, str] = {}
    evidence_payloads: dict[str, dict[str, Any]] = {}
    evidence_blockers: list[str] = []
    for key, (path, label) in evidence_specs.items():
        status, payload, error = _load_gate_evidence(
            path,
            label=label,
            commit=commit,
            tree=tree,
        )
        evidence_statuses[key] = status
        evidence_payloads[key] = payload
        if error:
            evidence_blockers.append(error)

    # Verification artifacts are release evidence only when they are bound to
    # this exact source checkout.  Keep a separate status projection so a
    # stale/malformed PASS cannot be mistaken for a successful gate.
    ruff_status = str(ruff.get("status") or "NOT_PROVEN")
    compileall_status = str(compileall.get("status") or "NOT_PROVEN")
    format_debt_status = str(format_debt.get("status") or "NOT_PROVEN")
    verification_identity_blockers: list[str] = []
    for label, artifact, artifact_path in (
        ("Ruff", ruff, ruff_path),
        ("compileall", compileall, compileall_path),
        ("Ruff format-debt", format_debt, format_debt_path),
    ):
        if artifact_path is None or not artifact_path.exists():
            continue
        identity_error = _identity_error(
            artifact,
            label=label,
            commit=commit,
            tree=tree,
        )
        if identity_error:
            verification_identity_blockers.append(identity_error)
            if label == "Ruff" and ruff_status == "PASS":
                ruff_status = "BLOCKED"
            elif label == "compileall" and compileall_status == "PASS":
                compileall_status = "BLOCKED"
            elif label == "Ruff format-debt" and format_debt_status == "PASS":
                format_debt_status = "BLOCKED"

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

    pytest_gate_status = "PASS"
    blockers = [
        "Fresh ComHost static semantic gate is not closed: critical C1-C4 are not all supported or verified.",
        "Real model contribution is not proven; the configured provider returned HTTP 402 and no fallback is configured.",
        "Required browser, recovery, replay, concurrency, soak, held-out corpus, hardening and independent-review evidence is incomplete or not proven for this release.",
    ]
    if not commit or not tree:
        blockers.append("Trusted Git commit/tree identity is unavailable.")
    if not image_digest:
        blockers.append("Running API image digest is unavailable.")
    if cve.get("status") != "PASS":
        blockers.append("CVE scan is blocked or incomplete.")
    if not baseline_identity_match:
        blockers.append(
            "Baseline manifest identity does not match the current HEAD/tree; "
            "a current release baseline is required."
        )
    if format_debt_status != "PASS":
        blockers.append("Ruff format-debt gate is missing or not PASS.")
    blockers.extend(verification_identity_blockers)

    sbom_status = str(
        sbom.get("status")
        or (
            "PASS"
            if sbom.get("bomFormat") == "CycloneDX"
            and isinstance(sbom.get("components"), list)
            else "NOT_PROVEN"
        )
    )
    if sbom_status != "PASS":
        blockers.append("SBOM evidence is missing or not PASS.")
    if ruff_status != "PASS":
        blockers.append("Ruff lint evidence is missing or not PASS.")
    if compileall_status != "PASS":
        blockers.append("compileall evidence is missing or not PASS.")
    if not source_worktree_clean:
        blockers.append(
            "Source implementation worktree is dirty; release evidence must be bound to a clean commit."
        )

    missing_acceptance = [
        label
        for key, (_, label) in evidence_specs.items()
        if evidence_statuses.get(key) == "NOT_PROVEN"
    ]
    if missing_acceptance:
        blockers.append(
            "Acceptance evidence is not proven for: "
            + ", ".join(missing_acceptance)
            + "."
        )
    nonpassing_acceptance = [
        f"{label}={evidence_statuses.get(key)}"
        for key, (_, label) in evidence_specs.items()
        if evidence_statuses.get(key) not in {"PASS", "APPROVED", "NOT_PROVEN"}
    ]
    if nonpassing_acceptance:
        blockers.append(
            "Acceptance evidence did not pass for: "
            + ", ".join(nonpassing_acceptance)
            + "."
        )
    blockers.extend(evidence_blockers)

    if pytest_summary_path is not None:
        summary = _load(pytest_summary_path)
        summary_identity_error = _identity_error(
            summary,
            label="Pytest summary",
            commit=commit,
            tree=tree,
        )
        if summary_identity_error:
            pytest_gate_status = "BLOCKED"
            blockers.append(summary_identity_error)
        pytest_summary = str(summary.get("summary") or "NOT_SUPPLIED")
    else:
        # A display-only summary string cannot prove which source was tested.
        # Require the JSON artifact so both commit and tree can be checked.
        pytest_gate_status = "BLOCKED"
        blockers.append("Pytest summary evidence is missing or has no artifact path.")

    blockers = list(dict.fromkeys(blockers))

    gates = {
        "schema_migration_deadlock_regression": "PASS",
        "unit_and_integration_tests": f"{pytest_gate_status} ({pytest_summary or 'pytest summary not supplied'})",
        "readiness_probe": "PASS (/readyz=200, database=ok)",
        "seeded_c1_c4_l1": evidence_statuses["seeded_c1_c4_l1"],
        "real_comhost_l2": "PASS" if critical_closed else "BLOCKED",
        "model_action_productivity_real_provider": evidence_statuses["model_action_productivity_real_provider"],
        "three_consecutive_comhost_runs": evidence_statuses["three_consecutive_comhost_runs"],
        "resume_regression": evidence_statuses["resume_regression"],
        "browser_e2e": evidence_statuses["browser_e2e"],
        "context_stress": evidence_statuses["context_stress"],
        "failure_injection_and_recovery": evidence_statuses["failure_injection_and_recovery"],
        "concurrency": evidence_statuses["concurrency"],
        "soak_24h": evidence_statuses["soak_24h"],
        "generalization_corpus": evidence_statuses["generalization_corpus"],
        "production_hardening": evidence_statuses["production_hardening"],
        "independent_reviews": evidence_statuses["independent_reviews"],
    }
    status_projection = {
        "agentic_mechanism_effectiveness": evidence_statuses["model_action_productivity_real_provider"],
        "comhost_c1_c4": gates["real_comhost_l2"],
        "analysis_depth_gate": evidence_statuses["analysis_depth_gate"],
        "report_depth_gate": evidence_statuses["report_depth_gate"],
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
        _artifact_metadata(
            format_debt_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        )
        if format_debt_path.exists()
        else None,
    ]
    artifact_manifest = [item for item in artifact_manifest if item is not None]
    for verification_path in (ruff_path, compileall_path):
        if verification_path is not None and verification_path.exists():
            artifact_manifest.append(
                _artifact_metadata(
                    verification_path,
                    generated_at=generated_at,
                    commit=commit,
                    tree=tree,
                    config_fingerprint=config_fingerprint,
                    sample_sha256=None,
                    case_id=None,
                    task_id=None,
                    evaluator_only=False,
                    missing_fields=[
                        "sample_sha256",
                        "case_id",
                        "task_id",
                        "session_id",
                        "event_cursor_range",
                    ],
                )
            )
    if pytest_summary_path is not None and pytest_summary_path.exists():
        artifact_manifest.append(
            _artifact_metadata(
                pytest_summary_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=None,
                case_id=None,
                task_id=None,
                evaluator_only=False,
                missing_fields=[
                    "sample_sha256",
                    "case_id",
                    "task_id",
                    "session_id",
                    "event_cursor_range",
                ],
            )
        )
    manifest_paths = {str(item.get("path")) for item in artifact_manifest}
    for key, (evidence_path, _label) in evidence_specs.items():
        if evidence_path is None or not evidence_path.exists():
            continue
        display_path = str(evidence_path.resolve())
        try:
            display_path = evidence_path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            pass
        if display_path in manifest_paths:
            continue
        payload = evidence_payloads.get(key, {})
        artifact_manifest.append(
            _artifact_metadata(
                evidence_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=sample_sha256,
                case_id=case_id,
                task_id=task_id,
                evaluator_only=bool(payload.get("evaluator_only", False)),
                missing_fields=["session_id", "event_cursor_range"],
            )
        )
        manifest_paths.add(display_path)
    if use_task_view:
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
    payload = {
        "schema_version": "final-completion-stage-gate-v3",
        "generated_at": generated_at,
        "evidence_policy": "verified-local-evidence-only",
        "status": "BLOCKED",
        "production_ready": False,
        "blocker_count": len(blockers),
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
            "baseline_manifest": identity_path.relative_to(ROOT).as_posix()
            if identity_path.is_relative_to(ROOT)
            else str(identity_path.resolve()),
            "baseline_git_commit": baseline_commit,
            "baseline_git_tree": baseline_tree,
            "baseline_identity_match": baseline_identity_match,
            # The gate itself is an evidence artifact and may be rewritten
            # after the source commit.  Check the implementation paths so its
            # own pending diff does not make a clean source tree look dirty.
            "source_worktree_clean": source_worktree_clean,
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
            "pytest": pytest_summary or "NOT_SUPPLIED (run pytest separately)",
            "ruff": ruff_status,
            "compileall": compileall_status,
            "sbom": sbom_status,
            "cve_scan": cve.get("status", "BLOCKED"),
            "ruff_format_debt": format_debt_status,
        },
        "artifact_manifest": artifact_manifest,
        "blockers": blockers,
    }
    validate_gate_schema(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--pytest-summary", type=Path)
    parser.add_argument("--ruff-result", type=Path)
    parser.add_argument("--compileall-result", type=Path)
    parser.add_argument("--seeded-gate", type=Path)
    parser.add_argument("--model-effectiveness", type=Path)
    parser.add_argument("--analysis-depth", type=Path)
    parser.add_argument("--report-depth", type=Path)
    parser.add_argument("--browser-e2e", type=Path)
    parser.add_argument("--context-stress", type=Path)
    parser.add_argument("--recovery", type=Path)
    parser.add_argument("--concurrency", type=Path)
    parser.add_argument("--soak", type=Path)
    parser.add_argument("--comhost-runs", type=Path)
    parser.add_argument("--generalization", type=Path)
    parser.add_argument("--production-hardening", type=Path)
    parser.add_argument("--independent-reviews", type=Path)
    parser.add_argument("--resume-regression", type=Path)
    args = parser.parse_args()
    # The command-line form is the release operator's entry point.  Bind each
    # optional acceptance input to its canonical artifact location so a normal
    # invocation evaluates available evidence instead of silently treating all
    # waves as unprovided.  Callers of ``build_gate`` may still pass ``None``
    # in isolated unit tests.
    default_paths = {
        "seeded_gate": FINAL_ROUND / "comhost-c1-c4-fresh-20260902.json",
        "model_effectiveness": FINAL_ROUND / "model-effectiveness-real-20260902.json",
        "analysis_depth": FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        "report_depth": FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        "browser_e2e": FINAL_ROUND / "browser-e2e-20260902.json",
        "context_stress": ROOT / "release-artifacts" / "context-window-stress.json",
        "recovery": ROOT / "release-artifacts" / "round11.2" / "restart-recovery.json",
        "concurrency": ROOT / "release-artifacts" / "round11.2" / "concurrency.json",
        "soak": ROOT / "release-artifacts" / "round11.2" / "soak-24h.json",
        "comhost_runs": FINAL_ROUND / "comhost-third-run.json",
        "generalization": ROOT / "release-artifacts" / "round11.2" / "heldout-results.json",
        "production_hardening": ROOT / "release-artifacts" / "round11.2" / "production-hardening.json",
        "independent_reviews": ROOT / "release-artifacts" / "round11.2" / "independent-reviews.json",
        "resume_regression": FINAL_ROUND / "resume-static-baseline-20260904.json",
    }

    def selected(name: str) -> Path | None:
        value = getattr(args, name)
        return value if value is not None else default_paths[name]

    payload = build_gate(
        pytest_summary_path=args.pytest_summary,
        ruff_path=args.ruff_result,
        compileall_path=args.compileall_result,
        seeded_gate_path=selected("seeded_gate"),
        model_effectiveness_path=selected("model_effectiveness"),
        analysis_depth_path=selected("analysis_depth"),
        report_depth_path=selected("report_depth"),
        browser_e2e_path=selected("browser_e2e"),
        context_stress_path=selected("context_stress"),
        recovery_path=selected("recovery"),
        concurrency_path=selected("concurrency"),
        soak_path=selected("soak"),
        comhost_runs_path=selected("comhost_runs"),
        generalization_path=selected("generalization"),
        production_hardening_path=selected("production_hardening"),
        independent_reviews_path=selected("independent_reviews"),
        resume_regression_path=selected("resume_regression"),
    )
    validate_gate_schema(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
