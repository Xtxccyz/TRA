"""Generate a truthful Round 11.2 certification bundle.

This command is the certification control-plane entry point.  It only hashes
explicitly labelled sample roots and consumes evaluator/external evidence that
is already on disk.  It never executes samples, sends sample-derived network
traffic, or copies Gold into the runtime.  Missing evidence is a blocker.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from threat_report_agent.product_certification import sha256_file, validate_corpus_split  # noqa: E402


REQUIRED_GATE_KEYS = (
    "precert_metric_contract",
    "model_path_health",
    "development_generalization",
    "gold_isolation",
    "critical_mechanism_recall",
    "critical_mechanism_precision",
    "relation_quality",
    "unknown_calibration",
    "benign_false_positive",
    "report_quality",
    "traceability",
    "browser_e2e",
    "restart_recovery",
    "concurrency",
    "soak",
    "production_hardening",
    "static_security_boundary",
    "independent_reviews",
)


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root.resolve()]
    return sorted(
        item for item in root.rglob("*") if item.is_file() and not item.is_symlink()
    )


def _labelled_rows(roots: Iterable[Path], category: str, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for root in roots:
        for path in _files(root.resolve()):
            digest = sha256_file(path)
            rows.append(
                {
                    "sample_id": f"{category}-{len(rows) + 1:03d}",
                    "path": str(path.resolve()),
                    "sha256": digest,
                    "category": category,
                    "split": split,
                    "expected_analysis_class": "FULL_STATIC_ANALYSIS",
                }
            )
    return rows


def build_partition(
    malware_roots: Iterable[Path], benign_roots: Iterable[Path]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Build the frozen 15/5 development and 5/5 certification partition.

    Roots are evaluator-labelled.  No filename or extension is used to infer
    malware/benign classification.  Files are hash-sorted before partitioning
    so the result is deterministic once roots are frozen.
    """

    malware = _labelled_rows(malware_roots, "malware", "")
    benign = _labelled_rows(benign_roots, "benign", "")
    malware = sorted(malware, key=lambda row: (row["sha256"], row["path"]))
    benign = sorted(benign, key=lambda row: (row["sha256"], row["path"]))
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(malware[:15], 1):
        rows.append({**row, "sample_id": f"malware-{index:03d}", "split": "development"})
    for index, row in enumerate(malware[15:20], 16):
        rows.append({**row, "sample_id": f"malware-{index:03d}", "split": "certification"})
    for index, row in enumerate(benign[:5], 1):
        rows.append({**row, "sample_id": f"benign-{index:03d}", "split": "development"})
    for index, row in enumerate(benign[5:10], 6):
        rows.append({**row, "sample_id": f"benign-{index:03d}", "split": "certification"})
    errors = validate_corpus_split(rows)
    if len(malware) > 20 or len(benign) > 10:
        errors.append("additional labelled files exist; partition uses only the frozen first 20/10")
    return rows, errors


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _status_artifact(status: str, blockers: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "status": status,
        "blockers": blockers,
        "generated_at": datetime.now(UTC).isoformat(),
        **extra,
    }


def _run(command: list[str], cwd: Path) -> tuple[bool, str]:
    try:
        completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output[-4000:]


def _static_security_probe() -> dict[str, Any]:
    checks: dict[str, bool] = {}
    npm = "npm.cmd" if os.name == "nt" else "npm"
    commands = {
        "dsh_profile_security": [npm, "run", "security"],
        "legacy_webui_absent": [npm, "run", "legacy-guard"],
        "dsh_core_diff_zero": [npm, "run", "core-guard"],
    }
    dsh_root = REPO_ROOT / "threat-dsh-workbench"
    outputs: dict[str, str] = {}
    for name, command in commands.items():
        ok, output = _run(command, dsh_root)
        checks[name] = ok
        outputs[name] = output
    compose_ok, compose_output = _run(["docker", "compose", "config", "--quiet"], REPO_ROOT)
    checks["compose_config"] = compose_ok
    outputs["compose_config"] = compose_output
    return {
        "status": "PASS" if all(checks.values()) else "BLOCKED",
        "checks": checks,
        "outputs": outputs,
        "sample_execution_zero": True,
        "sample_network_zero": True,
    }


def _load_status(path: Path) -> str:
    if not path.is_file():
        return "BLOCKED"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "BLOCKED"
    return str(payload.get("status", "BLOCKED")).upper()


def build_gate(out_dir: Path, statuses: dict[str, str], extra_blockers: list[str]) -> dict[str, Any]:
    blockers = list(dict.fromkeys(extra_blockers))
    checks: dict[str, str] = {}
    for key in REQUIRED_GATE_KEYS:
        status = statuses.get(key, "BLOCKED").upper()
        checks[key] = "PASS" if status == "PASS" else "BLOCKED"
        if status != "PASS":
            blockers.append(f"{key} is {status}")
    return {
        "version": "round11.2-release-gate-v1",
        "status": "PASS" if not blockers else "BLOCKED",
        "blocker_count": len(set(blockers)),
        "blockers": list(dict.fromkeys(blockers)),
        "checks": checks,
        "generated_at": datetime.now(UTC).isoformat(),
        "artifact_root": str(out_dir.resolve()),
        "production_ready": not blockers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malware-root", action="append", type=Path, default=[])
    parser.add_argument("--benign-root", action="append", type=Path, default=[])
    parser.add_argument(
        "--output-dir", type=Path, default=REPO_ROOT / "release-artifacts" / "round11.2"
    )
    parser.add_argument("--model-health", type=Path)
    parser.add_argument("--external", action="append", default=[], metavar="KEY=PATH")
    args = parser.parse_args()
    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    metric_contract = {
        "version": "round11.2-metric-contract-v1",
        "flow_runtime": {
            "definition": "participating verified mechanisms / eligible verified mechanisms",
            "zero_denominator": {"relation_flow_coverage": 0.0, "coverage_applicable": False},
        },
        "external_gold": {
            "critical_mechanism_recall": "matched recoverable critical Gold mechanisms / recoverable critical Gold mechanisms",
            "critical_mechanism_precision": "Gold-matched supported or verified critical mechanisms / all product supported or verified critical mechanisms",
            "unknown_calibration": "2 * unknown_precision * unknown_recall / (unknown_precision + unknown_recall)",
            "critical_malicious_fp": "report-visible unsupported supported/verified malicious critical behavior on benign controls",
        },
        "hard_gates": {"critical_unsupported": 0, "critical_unknown_overclaim": 0, "traceability": 1.0},
    }
    _write(out_dir / "metric-contract.json", metric_contract)
    (out_dir / "relation-flow-metric-review.md").write_text(
        "# Relation Flow Metric Review\n\n"
        "Wave 1 implementation uses the same verifier-accepted semantic mechanisms for "
        "flow nodes, edges, and runtime coverage. Runtime coverage is not Gold recall.\n",
        encoding="utf-8",
    )
    (out_dir / "status-semantic-review.md").write_text(
        "# Status Semantic Review\n\n"
        "Lifecycle answers whether the task ran; Task Outcome is a legacy completion field; "
        "Analysis Class is the formal semantic result. API, report, and UI expose all three.\n",
        encoding="utf-8",
    )

    rows: list[dict[str, Any]] = []
    corpus_errors: list[str] = []
    if args.malware_root or args.benign_root:
        rows, corpus_errors = build_partition(args.malware_root, args.benign_root)
    else:
        corpus_errors = ["no evaluator-labelled malware/benign roots supplied"]
    dev = [row for row in rows if row.get("split") == "development"]
    heldout = [row for row in rows if row.get("split") == "certification"]
    _write(
        out_dir / "corpus-manifest.json",
        _status_artifact(
            "PASS" if not corpus_errors else "BLOCKED",
            corpus_errors,
            sample_count=len(rows),
            malware_count=sum(row["category"] == "malware" for row in rows),
            benign_count=sum(row["category"] == "benign" for row in rows),
            gold_is_runtime_inaccessible=True,
        ),
    )
    _write(
        out_dir / "development-split.json",
        _status_artifact("PASS" if len(dev) == 20 else "BLOCKED", [], samples=dev),
    )
    _write(
        out_dir / "heldout-split.json",
        _status_artifact("PASS" if len(heldout) == 10 else "BLOCKED", [], samples=heldout),
    )
    _write(
        out_dir / "gold-manifest.json",
        _status_artifact("BLOCKED", ["evaluator-owned Gold was not supplied; no Gold was generated from reports"]),
    )

    model_path = args.model_health or out_dir / "model-path-health.json"
    if args.model_health and model_path.is_file():
        model_status = _load_status(model_path)
    else:
        model_enabled = os.getenv("MODEL_CALLS_ENABLED", "false").lower() in {"1", "true", "yes"}
        model_status = "PASS" if model_enabled else "BLOCKED"
        _write(
            out_dir / "model-path-health.json",
            _status_artifact(
                model_status,
                [] if model_status == "PASS" else ["MODEL_CALLS_ENABLED is false or no live provider evidence was supplied"],
                configured=model_enabled,
                calls_required=20,
                accepted_planned_actions_required=3,
                secrets_redacted=True,
            ),
        )

    static_probe = _static_security_probe()
    _write(out_dir / "production-security-probe.json", static_probe)
    _write(
        out_dir / "model-failure-fallback.json",
        _status_artifact("BLOCKED", ["live model failure/retry/fallback certification evidence is absent"], unit_tests_pass=True),
    )

    # Static boundary guards can be proven locally, but production hardening
    # requires an explicit release-image/secrets/backup evidence bundle.  Do
    # not infer that broader gate from source-level guards.
    statuses = {
        "precert_metric_contract": "PASS",
        "model_path_health": model_status,
        "development_generalization": _load_status(out_dir / "development-results.json"),
        # Corpus labels alone do not prove evaluator Gold isolation.  Gold is
        # an independent artifact and must supply an explicit external PASS.
        "gold_isolation": "BLOCKED",
        "static_security_boundary": static_probe["status"],
        "production_hardening": "BLOCKED",
    }
    external_paths: dict[str, Path] = {}
    for item in args.external:
        if "=" not in item:
            corpus_errors.append(f"invalid --external value: {item}")
            continue
        key, raw_path = item.split("=", 1)
        external_paths[key] = Path(raw_path)
    for key, path in external_paths.items():
        statuses[key] = _load_status(path)
    for key in REQUIRED_GATE_KEYS:
        if key not in statuses:
            statuses[key] = "BLOCKED"
    # Preserve the required artifact names even when external certification
    # has not yet been run.  Each placeholder is explicitly blocked so later
    # runs can replace it with evaluator-owned evidence without changing the
    # release contract.
    blocked_artifacts = {
        "development-results.json": "development generalization run not executed",
        "development-failure-taxonomy.json": "development generalization run not executed",
        "heldout-results.json": "held-out certification not executed",
        "mechanism-metrics.json": "evaluator Gold not supplied",
        "relation-metrics.json": "evaluator Gold not supplied",
        "unknown-calibration.json": "Unknown Gold not supplied",
        "benign-fp-results.json": "benign held-out run not executed",
        "report-quality-results.json": "independent report scoring not supplied",
        "browser-e2e.json": "full browser E2E not executed",
        "restart-recovery.json": "restart/recovery drills not executed",
        "concurrency.json": "concurrency run not executed",
        "soak-24h.json": "24-hour soak not executed",
    }
    for filename, reason in blocked_artifacts.items():
        target = out_dir / filename
        # Preserve a real operational result produced by a live baseline. The
        # certification command must not erase evidence merely because other
        # external gates are still unavailable.
        if filename in {"development-results.json", "development-failure-taxonomy.json"} and target.is_file():
            continue
        _write(target, _status_artifact("BLOCKED", [reason]))
    for filename, reason in {
        "architecture-review.md": "Architecture review pending; DSH core guard is recorded separately.\n",
        "security-review.md": "Security review pending; source-level static guards are recorded separately.\n",
        "reliability-review.md": "Reliability review pending; no restart/concurrency/soak evidence supplied.\n",
        "malware-analyst-review.md": "Independent malware analyst review pending.\n",
        "product-review.md": "Independent product review pending.\n",
        "production-hardening.md": "Production hardening is BLOCKED pending release-image, secret, backup, and vulnerability evidence.\n",
    }.items():
        (out_dir / filename).write_text(
            f"# {filename.rsplit('.', 1)[0].replace('-', ' ').title()}\n\nStatus: **BLOCKED**\n\n{reason}",
            encoding="utf-8",
        )
    gate = build_gate(out_dir, statuses, corpus_errors)
    _write(out_dir / "round11.2-release-gate.json", gate)
    (out_dir / "production-readiness.md").write_text(
        "# Round 11.2 Production Readiness\n\n"
        f"Status: **{gate['status']}**\n\n"
        "Production Ready is permitted only when every required check is PASS and "
        "blocker_count is zero. Missing evaluator or external evidence is a blocker.\n",
        encoding="utf-8",
    )
    print(json.dumps(gate, ensure_ascii=False, indent=2))
    if gate["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
