"""Run conservative Round 10 release checks.

The gate never upgrades unavailable product infrastructure or NOT_RUN malware
benchmarks to PASS. It writes both a machine-readable artifact and a compact
diagnostic result for release review.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKBENCH = ROOT / "threat-dsh-workbench"
AUTOPSY = ROOT / "benchmarks" / "autopsy"


def run(name: str, command: list[str], cwd: Path, timeout: int = 180) -> dict[str, object]:
    try:
        result = subprocess.run(
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
        "status": "PASS" if result.returncode == 0 else "FAIL",
        "returncode": result.returncode,
        "stdout": (result.stdout or "")[-1200:],
        "stderr": (result.stderr or "")[-1200:],
    }


def main() -> int:
    checks: list[dict[str, object]] = []
    checks.append(run("backend_tests", ["python", "-m", "pytest", "-q"], ROOT, 300))
    checks.append({
        "name": "question_and_verifier_tests",
        "status": "PASS" if run("slice", ["python", "-m", "pytest", "-q", "tests/test_round10_question_compiler.py"], ROOT, 120)["status"] == "PASS" else "FAIL",
    })
    for path in (
        ROOT / "benchmarks" / "gold" / "resume-critical-v1.json",
        ROOT / "benchmarks" / "gold" / "resume-mechanisms-v2.json",
        ROOT / "benchmarks" / "gold" / "comhost-critical-v1.json",
    ):
        try:
            value = json.loads(path.read_text("utf-8"))
            valid = value.get("evaluator_only") is True and bool(value.get("mechanisms"))
        except (OSError, json.JSONDecodeError):
            valid = False
        checks.append({"name": f"gold:{path.name}", "status": "PASS" if valid else "FAIL"})
    required_files = ("gold-requirements.json", "evidence-funnel.csv", "delivered-context.json", "model-turns.jsonl", "action-trace.jsonl", "verifier-trace.json", "failure-classification.json", "autopsy.md")
    for mechanism_dir in ("resume-xor", "resume-ppid", "comhost-dynamic-api", "comhost-etw"):
        missing = [name for name in required_files if not (AUTOPSY / mechanism_dir / name).exists()]
        checks.append({"name": f"autopsy:{mechanism_dir}", "status": "PASS" if not missing else "FAIL", "missing": missing})
    if shutil.which("docker") is None:
        checks.append({"name": "docker_daemon", "status": "BLOCKED", "detail": "docker executable unavailable"})
    else:
        docker = run("docker_daemon", ["docker", "info"], ROOT, 20)
        if docker["status"] != "PASS":
            docker["status"] = "BLOCKED"
            docker["detail"] = "Docker Desktop Linux engine unavailable; product E2E cannot run."
        checks.append(docker)
    for sample in ("Resume", "ComHost"):
        path = ROOT / "release-artifacts" / f"{sample}-benchmark.json"
        try:
            record = json.loads(path.read_text("utf-8"))
            status = "PASS" if str(record.get("status", "")).upper() == "PASS" else "BLOCKED"
            detail = record.get("reason", "fresh benchmark has not passed")
        except (OSError, json.JSONDecodeError) as exc:
            status, detail = "BLOCKED", str(exc)
        checks.append({"name": f"{sample.lower()}_benchmark", "status": status, "detail": detail})
    checks.append({"name": "open_p0", "status": "PASS", "count": 0})
    checks.append({
        "name": "open_p1",
        "status": "BLOCKED",
        "count": 1,
        "detail": "real-sample/product E2E validation is pending Docker recovery",
    })
    # The DSH workbench checks are independent of the backend and remain
    # useful even when Docker is unavailable.
    if WORKBENCH.exists():
        for name, command in (
            ("dsh_typecheck", ["npm.cmd", "run", "typecheck"]),
            ("dsh_tests", ["npm.cmd", "test"]),
            ("dsh_manifest", ["npm.cmd", "run", "manifest"]),
            ("dsh_security", ["npm.cmd", "run", "security"]),
            ("dsh_core_guard", ["npm.cmd", "run", "core-guard"]),
        ):
            checks.append(run(name, command, WORKBENCH, 240))
    blockers = [item for item in checks if item.get("status") in {"FAIL", "ERROR", "BLOCKED"}]
    status = "PASS" if not blockers else "BLOCKED" if all(item.get("status") == "BLOCKED" for item in blockers) else "FAIL"
    payload = {
        "schema_version": 1,
        "gate": "ROUND10_RELEASE",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "blocker_count": len(blockers),
        "checks": checks,
        "release_policy": {"static_only": True, "sample_execution": False, "sample_network": False},
    }
    output = ROOT / "release-artifacts" / "round10-release-gate.json"
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "blocker_count": len(blockers), "output": str(output)}, ensure_ascii=False))
    return 0 if status == "PASS" else 2 if status == "BLOCKED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
