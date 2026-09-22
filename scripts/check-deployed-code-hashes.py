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
* **The path hashed is the path the container IMPORTS**, discovered per service, not a hard-coded `/app/src`.
  MEASURED by the r1 audit: this gate hashed `/app/src/threat_report_agent` while the container's `sys.path`
  contains only site-packages and the running package is
  `/usr/local/lib/python3.12/site-packages/threat_report_agent` - a separate inode. Content matched that day, so
  the gate was right by luck; the copy being executed was never the copy being hashed.
* **Files present in the container but absent from the tree are reported**, so "every tree file matches" is not
  mistaken for "the container equals the tree" - a moved implementation leaves the old module behind.
* **Docker unavailable is `BLOCKED`, never a pass.** Plan section 4.4: "镜像不存在、Docker 不可用、源码 hash
  不等于当前 HEAD、容器 import 失败，都算 BLOCKED，不是本机 pytest 已绿".
* **`--self-check` proves PRECONDITIONS ONLY and says so.** MEASURED by the r1 audit: it printed
  `SELF-CHECK OK` and exited 0 while every container was missing two files, so a reader could take a green
  self-check for a deployment result. It now names what it did not check.

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

#: Relative to the repository root. Kept as the documented fallback; the path actually hashed comes from
#: `loaded_root()`, because a container may import the package from site-packages instead of from `/app/src`.
CONTAINER_ROOT = "/app/src/threat_report_agent"

#: One-shot, container-side, stdlib-only. Prints the directory the container IMPORTS the package from.
LOADED_ROOT_EXPR = (
    "import os, threat_report_agent as m; print(os.path.dirname(m.__file__))"
)

#: One-shot, container-side listing of every file under a root, so container-only leftovers are visible.
LISTING_EXPR = (
    "import os, sys; root = sys.argv[1]; "
    "print('\\n'.join(sorted(os.path.relpath(os.path.join(d, f), root).replace(os.sep, '/') "
    "for d, _, fs in os.walk(root) for f in fs if '__pycache__' not in d)))"
)

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

def plan_packages() -> tuple[str, ...]:
    """The packages the structural plan has created, ENUMERATED from disk.

    The rule, so it is checkable rather than a matter of memory: a child directory of the package root is a plan
    package when it holds an `__init__.py` AND at least one other `.py` file. That excludes the DATA directories,
    which have no `__init__.py` (`prompts/`, `policies/`, `knowledge/`, `assets/`, `ghidra_scripts/`) and so are
    covered by the file manifest instead.

    MEASURED GAP this closes (P2-M): until round 79 this was a hand-written tuple of six names. `model/` was moved
    into place and NOT added to it, so `--import-smoke` would have reported `import smoke OK` while never importing
    a single model module - the same "lagged the packages the plan created" defect the comment below used to
    describe, one level up. Deriving the list means a package created by a later step (P2-T `tools/`, P2-TK
    `task/`) is smoked the moment it exists.
    """
    packages = []
    for directory in sorted(SOURCE.iterdir()):
        if not directory.is_dir() or directory.name == "__pycache__":
            continue
        if not (directory / "__init__.py").is_file():
            continue
        if not any(p.name != "__init__.py" for p in directory.glob("*.py")):
            continue
        packages.append(directory.name)
    return tuple(packages)


#: Modules imported in every container by --import-smoke. These are the packages the structural plan created; a
#: container that cannot import one is running a stale image. Derived, never hand-edited - see `plan_packages()`.
SMOKE_PACKAGES: tuple[str, ...] = plan_packages()

#: Always smoked, whether or not the package has modules yet.
SMOKE_ALWAYS: tuple[str, ...] = ("threat_report_agent.facts",)

#: ROOT-level modules that a container's entry point imports, so they need an explicit entry: `plan_packages()`
#: only covers package DIRECTORIES, and a new root module is therefore invisible to that enumeration.
#:
#: MEASURED GAP this closes (P2-T.0): `control_activities.py` was created as a root module and crash-looped the
#: control worker with `NameError: name 'StaticToolRunWorkflow' is not defined`. The hash gate found it as
#: `control-worker: NOT RUNNING`, while the import smoke stayed silent - it never imported the new module at all.
SMOKE_MODULES: tuple[str, ...] = (
    "threat_report_agent.control_activities",
    "threat_report_agent.tool_execution",
    "threat_report_agent.cli",
)


def smoke_modules() -> tuple[str, ...]:
    """Every module inside the plan's new packages, plus the fixed and root-level entries."""
    names = [*SMOKE_ALWAYS, *SMOKE_MODULES]
    for package in SMOKE_PACKAGES:
        directory = SOURCE / package
        if not directory.is_dir():
            continue
        names.append(f"threat_report_agent.{package}")
        for path in sorted(directory.rglob("*.py")):
            if "__pycache__" in path.parts or path.name == "__init__.py":
                continue
            relative = path.relative_to(SOURCE).with_suffix("")
            names.append("threat_report_agent." + ".".join(relative.parts))
    return tuple(dict.fromkeys(names))


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


def loaded_root(service: str) -> tuple[str, str]:
    """The directory the container ACTUALLY imports `threat_report_agent` from.

    MEASURED (r1 audit): the container's `sys.path` holds site-packages, and the running package lives at
    `/usr/local/lib/python3.12/site-packages/threat_report_agent` - a different inode from `/app/src/...`.
    Hashing `/app/src` while Python loads site-packages compares the wrong copy, and hashing a file on disk says
    nothing about a process that is already running either way; this at least removes the first gap.
    """
    code, output = run(
        ["docker", "exec", container_name(service), "python", "-c", LOADED_ROOT_EXPR]
    )
    path = output.strip().splitlines()[-1].strip() if output.strip() else ""
    if code != 0 or not path.startswith("/"):
        return "", f"cannot locate the imported package (exit {code}): {output.strip()[:160]}"
    return path, f"imports from {path}"


def container_listing(service: str, root: str) -> list[str]:
    """Every file under `root` in the container, relative to it. Used to see container-only leftovers."""
    code, output = run(
        ["docker", "exec", container_name(service), "python", "-c", LISTING_EXPR, root], timeout=120
    )
    if code != 0:
        return []
    return [line.strip() for line in output.splitlines() if line.strip()]


def container_hashes(service: str, files: list[str], root: str) -> tuple[dict[str, str] | None, str]:
    """One exec per container. Returns (hashes, detail); hashes is None only when NOTHING could be parsed.

    `sha256sum` exits 1 when ANY argument is unreadable while still printing the hashes it did compute, so a
    non-zero exit must NOT be treated as an unusable container: doing that discards exactly the evidence this
    gate exists to produce and reports "docker exec failed" instead of naming the file the image lacks.
    MEASURED: the first version did that, and the truncated detail hid which path was missing.
    """
    name = container_name(service)
    quoted = " ".join(f"'{root}/{item}'" for item in files)
    code, output = run(["docker", "exec", name, "sh", "-c", f"sha256sum {quoted}"], timeout=300)
    digests: dict[str, str] = {}
    unreadable: list[str] = []
    prefix = root + "/"
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("sha256sum:"):
            # e.g. "sha256sum: /app/src/.../x.py: No such file or directory"
            target = stripped.split(":", 1)[1].strip() if ":" in stripped else stripped
            unreadable.append(target.replace(prefix, "").rsplit(":", 1)[0])
            continue
        # `sha256sum` separates digest and path with two spaces; a path is taken verbatim so a filename
        # containing a space is not split into a false mismatch.
        digest, separator, path = stripped.partition("  ")
        if separator and not digest.startswith("sha256sum:") and path.startswith(prefix):
            digests[path[len(prefix):]] = digest.split()[0]
    if not digests:
        return None, f"no hashes parsed (exit {code}): {output.strip()[:200]}"
    note = f"{len(digests)} hashed"
    if unreadable:
        note += f", {len(unreadable)} UNREADABLE"
    if code != 0 and not unreadable:
        note += f" (exit {code})"
    return digests, note


def import_smoke(service: str) -> tuple[bool, str]:
    """Every package the plan has created, in ONE exec, so the result names the module that failed."""
    modules = smoke_modules()
    expression = "; ".join(f"import {name}" for name in modules)
    code, output = run(["docker", "exec", container_name(service), "python", "-c", expression])
    if code == 0:
        return True, f"import smoke OK ({len(modules)} module(s), enumerated)"
    return False, f"import smoke FAILED: {output.strip()[:200]}"


def git_state() -> tuple[str, str]:
    """The current HEAD and whether `src/` is dirty.

    Plan section 4.4 lists "源码 hash 不等于当前 HEAD" among the BLOCKED conditions, and the docstring claimed a
    HEAD comparison that did not exist. This gate compares the WORKING TREE against the containers, so a dirty
    tree is reported rather than silently used: the comparison is still meaningful, but it is against the tree,
    not against HEAD.
    """

    def git(*args: str) -> tuple[int, str]:
        try:
            done = subprocess.run(
                ["git", *args], cwd=ROOT, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return 1, f"{type(exc).__name__}: {exc}"
        return done.returncode, (done.stdout or "") + (done.stderr or "")

    code, head = git("rev-parse", "HEAD")
    head_sha = head.strip().splitlines()[0] if code == 0 and head.strip() else "UNKNOWN"
    code, status = git("status", "--porcelain", "--", "src")
    dirty = [line for line in status.splitlines() if line.strip()]
    if dirty:
        note = f"src/ DIRTY ({len(dirty)} path(s)) - compared against the WORKING TREE, not against HEAD"
    else:
        note = "src/ clean, so the tree IS HEAD"
    return head_sha, note


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
    head_sha, head_note = git_state()
    print(f"head        : {head_sha[:12]} ({head_note})")

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
        print("SELF-CHECK OK - PRECONDITIONS ONLY: manifest non-empty, Docker reachable, every listed service running.")
        print("  This does NOT prove that any file is deployed, and it does NOT compare a single hash.")
        print("  MEASURED: this line printed OK while every container was missing two files. Run without")
        print("  --self-check (add --strict) for the deployment result.")
        return 0

    if not available:
        # Plan 4.4: Docker unavailable is BLOCKED, never a pass.
        print("\nBLOCKED: deployment consistency not verifiable (Docker unavailable)")
        return 2

    expected = host_hashes(files)
    mismatched: list[str] = []
    missing: list[str] = []
    extra: list[str] = []
    for service in services:
        if f"threat-report-agent-{service}-1" not in detail:
            # A service that is NOT RUNNING must never be silently skipped.
            #
            # MEASURED BUG: `docker ps` lists only RUNNING containers, and `continue` here meant no file was
            # compared for that service while the summary still printed "ALL DEPLOYED MODULES MATCH src/".
            # ghidra-worker was `Exited (1)` and the gate reported a full match - absence read as a clean
            # result, inside the instrument built to catch exactly that. The `problems` list did catch it, but
            # `problems` is only consulted in --self-check mode, so the normal path ignored it.
            mismatched.append(f"{service}: NOT RUNNING - no file could be compared")
            print(f"  {service:18} NOT RUNNING - not compared")
            continue
        root, root_note = loaded_root(service)
        if not root:
            mismatched.append(f"{service}: {root_note}")
            print(f"  {service:18} {root_note}")
            continue
        actual, note = container_hashes(service, files, root)
        if actual is None:
            mismatched.append(f"{service}: {note}")
            print(f"  {service:18} {note}")
            continue
        only_host = sorted(set(files) - set(actual))
        differing = sorted(name for name in files if name in actual and actual[name] != expected[name])
        leftover = sorted(set(container_listing(service, root)) - set(files))
        print(f"  {service:18} {note:24} missing={len(only_host)} differing={len(differing)}"
              f" container-only={len(leftover)}")
        print(f"  {'':18} {root_note}")
        missing.extend(f"{service}:{name}" for name in only_host)
        mismatched.extend(f"{service}:{name}" for name in differing)
        extra.extend(f"{service}:{name}" for name in leftover)
        if args.import_smoke:
            ok, smoke_note = import_smoke(service)
            print(f"  {service:18} {smoke_note}")
            if not ok:
                mismatched.append(f"{service}:{smoke_note}")

    print()
    print(f"checked {len(files)} file(s) across {len(services)} service(s) against HEAD {head_sha[:12]}")
    if missing:
        print(f"MISSING IN CONTAINER ({len(missing)}): " + ", ".join(missing[:8]))
    if mismatched:
        print(f"DIFFERING ({len(mismatched)}): " + ", ".join(mismatched[:8]))
    if extra:
        # The tree does not have these, so the container is NOT equal to the tree even if every tree file
        # matches: a moved implementation leaves its old module behind.
        print(f"CONTAINER-ONLY ({len(extra)}): " + ", ".join(extra[:8]))

    if missing or mismatched or extra:
        if args.strict:
            print("\nSTRICT: deployment does NOT match the tree")
            return 1
        print("\n(not strict: report only)")
        return 0
    print("ALL DEPLOYED MODULES MATCH src/ (no tree file missing or differing, no container-only file)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
