"""Generate a provenance-bound P0/P1 release issue register.

The final completion gate treats the issue register as release evidence.  This
small command records only verifiable local facts (the current Git identity and
the named evidence artifacts); it does not infer that an unavailable external
run passed.  Operators can close an issue in a later snapshot by supplying a
status override, but a missing override deliberately leaves the issue OPEN.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "release-artifacts" / "final-round" / "issue-register-20260905.json"

# These are release-level blockers observed in the current final-stage gate.
# They are intentionally evidence references, not sample-derived findings.
DEFAULT_ISSUES: tuple[dict[str, Any], ...] = (
    {
        "id": "FC-P0-001",
        "severity": "P0",
        "status": "OPEN",
        "title": "Fresh ComHost C1-C4 semantic closure is not proven",
        "gate": "comhost_c1_c4",
        "evidence_level": "L2",
        "source_artifacts": [
            "release-artifacts/final-round/comhost-semantic-differential-current-20260905.json",
            "release-artifacts/final-round/comhost-static-baseline-current-20260905.json",
        ],
        "reason": "Only the shell mechanism is SUPPORTED; dynamic API, C2 transport and ETW patch remain UNKNOWN.",
        "required_action": "Run a fresh static ComHost investigation and bind each C1-C4 component to anchored Evidence.",
    },
    {
        "id": "FC-P0-002",
        "severity": "P0",
        "status": "OPEN",
        "title": "Real model contribution is not attributable",
        "gate": "agentic_mechanism_effectiveness",
        "evidence_level": "L2",
        "source_artifacts": [
            "release-artifacts/final-round/model-effectiveness-real-20260902.json",
            "release-artifacts/final-round/model-health-probe-20260904-rerun.json",
        ],
        "reason": "Sample-sized requests returned HTTP 402 and accepted_model_actions is zero; fallback output cannot receive model credit.",
        "required_action": "Use a funded provider and capture attributable model-origin actions plus consumed Evidence.",
    },
    {
        "id": "FC-P0-003",
        "severity": "P0",
        "status": "OPEN",
        "title": "Analyst-grade analysis and report depth thresholds are not met",
        "gate": "analysis_depth_gate/report_depth_gate",
        "evidence_level": "L2",
        "source_artifacts": [
            "release-artifacts/final-round/report-depth-comhost-current-20260905.json",
            ".scratch/final-completion-live-20260904/comhost-report-current-r2.json",
        ],
        "reason": "Critical mechanism completeness and required HOW fields are below the release thresholds.",
        "required_action": "Produce a fresh report with complete Input/Transformation/Condition/Output/Consumer, provenance and alternatives for five core findings.",
    },
    {
        "id": "FC-P1-001",
        "severity": "P1",
        "status": "OPEN",
        "title": "Browser/DSH product path has no current captured acceptance run",
        "gate": "browser_e2e",
        "evidence_level": "L3",
        "source_artifacts": ["release-artifacts/final-round/browser-e2e-20260902.json"],
        "reason": "A fresh New Session -> Upload -> Chat -> Evidence -> Mechanism -> Report capture is unavailable.",
        "required_action": "Capture the user path on the pinned product profile with session and cursor provenance.",
    },
    {
        "id": "FC-P1-002",
        "severity": "P1",
        "status": "OPEN",
        "title": "Held-out generalization corpus is not certified",
        "gate": "generalization",
        "evidence_level": "L2",
        "source_artifacts": [
            "release-artifacts/round11.2/heldout-results.json",
            "release-artifacts/round11.2/gold-manifest.json",
        ],
        "reason": "Evaluator-owned malware/benign Gold and the required held-out corpus are not present.",
        "required_action": "Obtain the evaluator-labelled corpus and Gold, then run the development and held-out gates without exposing Gold to runtime.",
    },
    {
        "id": "FC-P1-003",
        "severity": "P1",
        "status": "OPEN",
        "title": "Recovery, replay, concurrency and 24-hour soak are not proven",
        "gate": "recovery/concurrency/soak_24h",
        "evidence_level": "L4",
        "source_artifacts": [
            "release-artifacts/round11.2/restart-recovery.json",
            "release-artifacts/round11.2/concurrency.json",
            "release-artifacts/round11.2/soak-24h.json",
        ],
        "reason": "The available records explicitly state that the drills were not executed.",
        "required_action": "Run fresh timestamped fault, replay, concurrent-analysis and soak scenarios with no lost/duplicate events.",
    },
    {
        "id": "FC-P1-004",
        "severity": "P1",
        "status": "OPEN",
        "title": "Production hardening and independent approvals are incomplete",
        "gate": "production_hardening/independent_reviews",
        "evidence_level": "L4",
        "source_artifacts": [
            "release-artifacts/round11.2/production-hardening.md",
            "release-artifacts/round11.2/production-security-probe.json",
            "release-artifacts/round11.2/malware-analyst-review.md",
            "release-artifacts/round11.2/security-review.md",
        ],
        "reason": "CVE scan, backup/restore, secret rotation and required independent approvals are not all proven.",
        "required_action": "Complete hardening evidence and record APPROVED/BLOCKED decisions from each required reviewer.",
    },
    {
        "id": "FC-P1-005",
        "severity": "P1",
        "status": "OPEN",
        "title": "Resume regression and provenance metadata are incomplete",
        "gate": "resume_regression/artifact_metadata",
        "evidence_level": "L2",
        "source_artifacts": [
            "release-artifacts/final-round/resume-static-baseline-20260904.json",
            "release-artifacts/final-round/baseline-manifest.json",
        ],
        "reason": "The current evidence does not prove a fresh Resume regression with session/cursor provenance at this release identity.",
        "required_action": "Run a fresh static Resume regression and record sample, case, task, session and event-cursor bindings.",
    },
)


def _git(*args: str) -> str | None:
    """Return a Git value, or None when this checkout has no usable Git."""
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


def _normalise_status(value: object) -> str:
    status = str(value or "OPEN").strip().upper()
    if status not in {"OPEN", "IN_PROGRESS", "BLOCKED", "CLOSED"}:
        raise ValueError(f"unsupported issue status: {value!r}")
    return status


def _count_open(issues: Iterable[dict[str, Any]], severity: str) -> int:
    return sum(
        1
        for issue in issues
        if str(issue.get("severity", "")).upper() == severity
        and _normalise_status(issue.get("status")) != "CLOSED"
    )


def build_issue_register(
    *,
    commit: str | None = None,
    tree: str | None = None,
    generated_at: str | None = None,
    issues: Iterable[dict[str, Any]] = DEFAULT_ISSUES,
) -> dict[str, Any]:
    """Build a release register bound to one source identity."""
    materialized: list[dict[str, Any]] = []
    for source in issues:
        issue = dict(source)
        issue["status"] = _normalise_status(issue.get("status"))
        materialized.append(issue)
    open_p0 = _count_open(materialized, "P0")
    open_p1 = _count_open(materialized, "P1")
    return {
        "schema_version": "p0-p1-issue-register-v1",
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "evidence_policy": "verified-local-evidence-only",
        "git_commit": commit if commit is not None else _git("rev-parse", "HEAD"),
        "git_tree": tree if tree is not None else _git("rev-parse", "HEAD^{tree}"),
        "status": "CLEAR" if open_p0 == 0 and open_p1 == 0 else "BLOCKED",
        "open_p0": open_p0,
        "open_p1": open_p1,
        "issues": materialized,
        "notes": [
            "OPEN records are release blockers, not claims about sample behavior.",
            "Unavailable real-provider, browser, corpus and production evidence remains OPEN until a fresh bound artifact is supplied.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = build_issue_register()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
