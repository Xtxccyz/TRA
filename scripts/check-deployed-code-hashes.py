"""Deployment source manifest + strict gate. TRACKED and runnable from a fresh clone.

Replaces the gitignored `.scratch/check-deployed-code-hashes.py`, which named a fixed list of 12 modules out of
58 and therefore could not notice a moved or newly added implementation - a shim satisfies it by module name.
Plan section 4.4 requires: coverage of `src/threat_report_agent/**`, of every service that imports backend code,
and a hard failure when a container's source does not equal the tree.

Design decisions, each because the old gate got it wrong:

* **Coverage is ENUMERATED, never listed.** Every file under `src/threat_report_agent/` (any extension, so
  `ghidra_scripts/*.java`, `prompts/*.md` and `policies/*.json` are included) is in the manifest. Adding
  `facts/`, `report/` or any new path therefore needs no edit here.
* **One `sha256sum` call per container**, not one per file: 58 files x 8 services would be ~460 execs.
* **A missing file in the container is a MISMATCH, not a skip.** The old gate could not see a module that the
  image simply does not ship.
* **Docker unavailable is `BLOCKED`, never a pass.** Plan section 4.4: "镜像不存在、Docker 不可用、源码 hash
  不等于当前 HEAD、容器 import 失败，都算 BLOCKED，不是本机 pytest 已绿".

Usage:

    python scripts/check-deployed-code-hashes.py                      # report, exit 0 unless --strict
    python scripts/check-deployed-code-hashes.py --self-check         # environment + manifest sanity
    python scripts/check-deployed-code-hashes.py --strict --services api,emu-worker,ghidra-worker
    python scripts/check-deployed-code-hashes.py --strict --import-smoke
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "threat_report_agent"

#: Relative to the repository root. The prefix a container ships the source under.
CONTAINER_ROOT = "/app/src/threat_report_agent"

#: Services that actually import backend code. ghidra-worker is listed DELIBERATELY: the plan (section 14.4)
#: forbids skipping it, and it is the one worker whose compose service has no `build:` stanza.
DEFAULT_SERVICES = (
    "api",
    "intake-worker",
    "document-worker",
    "parser-worker",
    "script-worker",
    "control-worker",
    "emu-worker",
    "ghidra-worker",
)

#: Imported in every container by --import-smoke. Chosen because they are the packages the structural plan
#: creates; a container that cannot import them is running a stale image.
SMOKE_MODULES = "threat_report_agent.facts"


def container_name(service: str) -> str:
    return f"threat-report-agent-{service}-1"


def manifest() -> list[str]:
    """Every production source file, as paths relative to the source root. Enumerated, never listed."""
    if not SOURCE.is_dir():
        return []
    return sorted(
        path.relative_to(SOURCE).as_posix()
        for path in SOURCE.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )


def host_hashes(files: list[str]) -> dict[str, str]:
    digests: dict[str, str] = {}
    for name in files:
        digest = hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
        digests[name] = digest
    return digests


def run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    done = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def docker_available() -> tuple[bool, str]:
    try:
        code, output = run(["docker", "ps", "--format", "{{.Names}}"])
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return code == 0, output


def container_hashes(service: str, files: list[str]) -> tuple[dict[str, str] | None, str]:
    """One exec per container. Returns (hashes, detail); hashes is None only when NOTHING could be parsed.

    `sha256sum` exits 1 when ANY argument is unreadable while still printing the hashes it did compute, so a
    non-zero exit must NOT be treated as an unusable container: doing that discards exactly the evidence this
    gate exists to produce and reports "docker exec failed" instead of naming the file the image lacks.
    MEASURED: the first version did that, and the truncated detail hid which path was missing.
    """
    name = container_name(service)
    quoted = " ".join(f"'{CONTAINER_ROOT}/{item}'" for item in files)
    code, output = run(["docker", "exec", name, "sh", "-c", f"sha256sum {quoted}"], timeout=300)
    digests: dict[str, str] = {}
    unreadable: list[str] = []
    prefix = CONTAINER_ROOT + "/"
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("sha256sum:"):
            # e.g. "sha256sum: /app/src/.../x.py: No such file or directory"
            target = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
            unreadable.append(target.replace(prefix, "").rsplit(":", 1)[0])
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2 and parts[1].strip().startswith(prefix):
            digests[parts[1].strip()[len(prefix):]] = parts[0]
    if not digests:
        return None, f"no hashes parsed (exit {code}): {output.strip()[:200]}"
    note = f"{len(digests)} hashed"
    if unreadable:
        note += f", {len(unreadable)} UNREADABLE"
    if code != 0 and not unreadable:
        note += f" (exit {code})"
    return digests, note


def import_smoke(service: str) -> tuple[bool, str]:
    code, output = run(["docker", "exec", container_name(service), "python", "-c", f"import {SMOKE_MODULES}"])
    if code == 0:
        return True, f"import {SMOKE_MODULES} OK"
    return False, f"import {SMOKE_MODULES} FAILED: {output.strip()[:200]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--services", default="", help="comma-separated service names; default is all")
    parser.add_argument("--strict", action="store_true", help="any mismatch or missing file fails")
    parser.add_argument("--self-check", action="store_true", help="validate environment and manifest only")
    parser.add_argument("--import-smoke", action="store_true", help="also import the target packages in-container")
    args = parser.parse_args()

    files = manifest()
    services = [item.strip() for item in args.services.split(",") if item.strip()] or list(DEFAULT_SERVICES)

    print(f"source root : {SOURCE}")
    print(f"manifest    : {len(files)} file(s), enumerated from disk (not a fixed list)")
    print(f"services    : {', '.join(services)}")

    problems: list[str] = []
    if not files:
        problems.append("manifest is EMPTY - the source root is wrong or missing")
    available, detail = docker_available()
    print(f"docker      : {'available' if available else 'UNAVAILABLE'} ({detail.strip()[:80]})")
    if not available:
        problems.append("Docker is unavailable, so deployment consistency CANNOT be checked")
    else:
        for service in services:
            present = f"threat-report-agent-{service}-1" in detail
            if not present:
                problems.append(f"{service}: container not running")

    if args.self_check:
        print()
        if problems:
            print("SELF-CHECK FAILED:")
            for item in problems:
                print(f"  - {item}")
            return 2
        print("SELF-CHECK OK: manifest non-empty, Docker reachable, every listed service is running")
        return 0

    if not available:
        # Plan 4.4: Docker unavailable is BLOCKED, never a pass.
        print("\nBLOCKED: deployment consistency not verifiable (Docker unavailable)")
        return 2

    expected = host_hashes(files)
    mismatched: list[str] = []
    missing: list[str] = []
    for service in services:
        if f"threat-report-agent-{service}-1" not in detail:
            continue
        actual, note = container_hashes(service, files)
        if actual is None:
            mismatched.append(f"{service}: {note}")
            continue
        only_host = sorted(set(files) - set(actual))
        differing = sorted(name for name in files if name in actual and actual[name] != expected[name])
        print(f"  {service:18} {note:24} missing={len(only_host)} differing={len(differing)}")
        missing.extend(f"{service}:{name}" for name in only_host)
        mismatched.extend(f"{service}:{name}" for name in differing)
        if args.import_smoke:
            ok, smoke_note = import_smoke(service)
            print(f"  {service:18} {smoke_note}")
            if not ok:
                mismatched.append(f"{service}:{smoke_note}")

    print()
    print(f"checked {len(files)} file(s) across {len(services)} service(s)")
    if missing:
        print(f"MISSING IN CONTAINER ({len(missing)}): " + ", ".join(missing[:8]))
    if mismatched:
        print(f"DIFFERING ({len(mismatched)}): " + ", ".join(mismatched[:8]))

    if missing or mismatched:
        if args.strict:
            print("\nSTRICT: deployment does NOT match the tree")
            return 1
        print("\n(not strict: report only)")
        return 0
    print("ALL DEPLOYED MODULES MATCH src/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
