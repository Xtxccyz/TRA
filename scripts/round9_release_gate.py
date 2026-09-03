"""Run the reproducible Round 9 release checks and write a status ledger.

The gate is intentionally conservative: a missing Docker daemon is a release
blocker, not a pass. Static checks still run so the output distinguishes code
failures from unavailable infrastructure.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKBENCH = ROOT / "threat-dsh-workbench"
DSH_ROOT = Path(os.environ.get("DSH_HARNESS_ROOT", r"C:\Users\王宪韬\Desktop\deepseek-harness"))
EXPECTED_DSH_SHA = "47f943859bef60e4160492346772ded9b24f765a"


def run(name: str, command: list[str], cwd: Path, *, timeout: int = 180) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"name": name, "status": "ERROR", "detail": str(exc)}
    return {
        "name": name,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[-4000:],
        "stderr": (completed.stderr or "")[-4000:],
    }


def main() -> int:
    checks: list[dict[str, object]] = []
    if DSH_ROOT.is_dir() and (DSH_ROOT / ".git").exists():
        checks.append(run("dsh_lock", ["git", "rev-parse", "HEAD"], DSH_ROOT))
        checks[-1]["expected"] = EXPECTED_DSH_SHA
        if checks[-1].get("status") == "PASS" and checks[-1].get("stdout", "").strip() != EXPECTED_DSH_SHA:
            checks[-1]["status"] = "FAIL"
            checks[-1]["detail"] = "pinned commit mismatch"
        checks.append(run("dsh_clean", ["git", "status", "--porcelain"], DSH_ROOT))
        if checks[-1].get("status") == "PASS" and checks[-1].get("stdout", "").strip():
            checks[-1]["status"] = "FAIL"
            checks[-1]["detail"] = "upstream worktree is dirty"
    else:
        checks.append({"name": "dsh_lock", "status": "FAIL", "detail": f"missing DSH checkout: {DSH_ROOT}"})

    manifest = ROOT / ".scratch" / "backend-source-manifest.sha256"
    lock_doc = ROOT / "docs" / "dsh-upstream-lock.md"
    if manifest.exists() and lock_doc.exists():
        actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
        lock_text = lock_doc.read_text(encoding="utf-8")
        expected_match = re.search(r"^backend_source_manifest:\s*([0-9a-f]{64})$", lock_text, re.MULTILINE)
        expected = expected_match.group(1) if expected_match else ""
        checks.append(
            {
                "name": "backend_manifest_lock",
                "status": "PASS" if actual == expected else "FAIL",
                "expected": expected,
                "actual": actual,
            }
        )
    else:
        checks.append({"name": "backend_manifest_lock", "status": "FAIL", "detail": "manifest or lock document missing"})

    checks.extend(
        [
            run("workbench_typecheck", ["npm.cmd", "run", "typecheck"], WORKBENCH),
            run("workbench_tests", ["npm.cmd", "test"], WORKBENCH),
            run("workbench_runtime", ["npm.cmd", "run", "test:runtime"], WORKBENCH),
            run("workbench_manifest", ["npm.cmd", "run", "manifest"], WORKBENCH),
            run("workbench_security", ["npm.cmd", "run", "security"], WORKBENCH),
            run("workbench_legacy_guard", ["npm.cmd", "run", "legacy-guard"], WORKBENCH),
            run("workbench_core_guard", ["npm.cmd", "run", "core-guard"], WORKBENCH),
            run("workbench_smoke", ["npm.cmd", "run", "smoke:dsh"], WORKBENCH, timeout=120),
        ]
    )

    docker = run("docker_daemon", ["docker", "info", "--format", "{{json .ServerVersion}}"], ROOT, timeout=15)
    if docker["status"] != "PASS":
        docker["status"] = "BLOCKED"
        docker["detail"] = "Docker Desktop Linux engine is unavailable; Compose E2E cannot run."
    checks.append(docker)

    historical = ROOT / ".scratch" / "round8-resume-comhost-docker-report-v3.md"
    if historical.exists():
        size = historical.stat().st_size
        checks.append(
            {
                "name": "historical_report_antibloat",
                "status": "INFO" if size > 40 * 1024 else "PASS",
                "bytes": size,
                "detail": "historical Docker artifact predates/does not satisfy current Report V2 budget"
                if size > 40 * 1024
                else "within budget",
            }
        )
    else:
        checks.append({"name": "historical_report_antibloat", "status": "INFO", "detail": "artifact absent"})

    # A release cannot pass on unit tests alone. These evaluator-facing files
    # are deliberately required to be replaced by fresh Resume/ComHost runs.
    for sample in ("Resume", "ComHost"):
        benchmark = ROOT / "release-artifacts" / f"{sample}-benchmark.json"
        try:
            record = json.loads(benchmark.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            checks.append({"name": f"{sample.lower()}_benchmark", "status": "BLOCKED", "detail": str(exc)})
            continue
        benchmark_status = str(record.get("status", "NOT_RUN")).upper()
        checks.append(
            {
                "name": f"{sample.lower()}_benchmark",
                "status": "PASS" if benchmark_status == "PASS" else "BLOCKED",
                "detail": record.get("reason", "benchmark status is not PASS"),
            }
        )

    blockers = [item for item in checks if item.get("status") in {"FAIL", "BLOCKED", "ERROR"}]
    status = "PASS" if not blockers else "BLOCKED" if all(item.get("status") == "BLOCKED" for item in blockers) else "FAIL"
    payload = {
        "schema_version": 1,
        "gate": "ROUND9_RELEASE",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "blocker_count": len(blockers),
        "checks": checks,
    }
    output = ROOT / ".scratch" / "round9-release-gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "blocker_count": len(blockers), "output": str(output)}, ensure_ascii=False))
    return 0 if status == "PASS" else 2 if status == "BLOCKED" else 1


if __name__ == "__main__":
    sys.exit(main())
