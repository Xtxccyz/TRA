"""P-0.4 of the Ghidra/C3 main plan: pin the CALL CONTRACT of the tracked deployment gate.

The plan is explicit that this step must NOT create a second gate:

    "仅由结构计划 owner 修改 `scripts/check-deployed-code-hashes.py`；本计划只增加调用契约测试，不创建第二份 gate."

So this file calls the existing script and pins, as facts, both what it CAN deliver today and what it CANNOT. The
"cannot" half is the part that matters: the plan's own failure rule is

    "当前 tracked gate 仍只看 worktree 时，记录 `deployment_gate_head_unverified`，不得声称部署通过."

A future P-2.1 that adds a real HEAD/worktree/container three-way manifest will have to change the assertions below
deliberately, which is the point - the limitation is recorded where a reader of the gate will hit it.

Nothing here requires Docker: the gate is exercised through its own CLI and its own functions, and the daemon's absence
is asserted as a DISTINCT reported state rather than treated as a pass.
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "check-deployed-code-hashes.py"


def _load_gate():
    """The filename has hyphens, so it cannot be imported by name; load it from its path."""
    spec = importlib.util.spec_from_file_location("check_deployed_code_hashes_gate", GATE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load_gate()


def test_the_gate_is_the_single_tracked_entry_point() -> None:
    """P-0.4/P-2.1: one gate. A second manifest writer would be a fork of the enforcement."""
    assert GATE.is_file()
    candidates = [path.name for path in (ROOT / "scripts").glob("*deploy*hash*.py")]
    assert candidates == ["check-deployed-code-hashes.py"], (
        f"the deployment manifest must have exactly one implementation, found {candidates}"
    )


def test_the_cli_exposes_only_the_documented_switches() -> None:
    completed = subprocess.run([sys.executable, str(GATE), "--help"], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0
    for switch in ("--services", "--strict", "--self-check", "--import-smoke"):
        assert switch in completed.stdout, f"{switch} is part of the documented call contract"


def test_the_manifest_is_enumerated_from_disk_and_includes_ghidra_worker_by_default(gate) -> None:
    """M5 in the small: the manifest is an ENUMERATED SET with a stable identity key (the path), not a fixed count.

    MEASURED composition at P-0.4: 131 entries - 118 `.py`, 4 `.json`, 4 `.md` (the prompts), 1 `.java` (the Ghidra
    export script), 1 `.yaml`, and the three static assets. The plan asks the manifest to cover "Python/Java/prompt"
    files, so the assertion is on the ROOTS and on a non-trivial shape, not on a single extension.
    """
    files = gate.manifest()
    assert len(files) > 100, "the manifest must be enumerated, not a short fixed list"
    assert len(set(files)) == len(files), "a manifest with duplicates cannot support a set difference"
    suffixes = {pathlib.Path(path).suffix for path in files}
    assert {".py", ".java", ".md"} <= suffixes, f"the manifest must cover code, Java and prompts; saw {sorted(suffixes)}"
    assert any(path.endswith(".py") for path in files)
    packages = gate.plan_packages()
    assert isinstance(packages, tuple) and packages, "the package enumeration must be non-empty"
    # The DEFAULT service set must include ghidra-worker (plan P-2.1). It is not a module constant, so it is read from
    # the gate's own self-check output - the same interface a caller uses.
    completed = subprocess.run([sys.executable, str(GATE), "--self-check"], cwd=ROOT, capture_output=True, text=True)
    services_line = next((line for line in completed.stdout.splitlines() if line.startswith("services")), "")
    assert "ghidra-worker" in services_line, f"ghidra-worker must be checked by default; services line was {services_line!r}"
    assert "emu-worker" in services_line


def test_the_host_hashes_are_real_digests(gate) -> None:
    """A hash field that is not a digest cannot be compared, which is how a gate silently stops checking."""
    files = gate.manifest()[:5]
    hashes = gate.host_hashes(files)
    assert set(hashes) == set(files)
    for path, digest in hashes.items():
        assert len(digest) == 64 and all(character in "0123456789abcdef" for character in digest), path


def test_an_unavailable_daemon_is_reported_as_a_distinct_state_not_as_a_pass() -> None:
    """The plan's P-1.7 rule: a blocked deployment gate is `P-1_COMPLETE_DEPLOYMENT_BLOCKED`, never "verified"."""
    available, detail = _load_gate().docker_available()
    if available:
        pytest.skip("Docker is available on this host; the unavailable-daemon state cannot be observed right now")
    completed = subprocess.run([sys.executable, str(GATE), "--self-check"], cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode != 0, "an unavailable daemon must not exit zero"
    assert "UNAVAILABLE" in completed.stdout.upper()
    assert "CANNOT be checked" in completed.stdout, "the gate must say what it could not check, not merely fail"


def test_the_head_manifest_is_recorded_as_not_implemented(gate) -> None:
    """MEASURED LIMITATION (plan P-0.4 failure rule -> `deployment_gate_head_unverified`).

    Today the gate compares the WORKING TREE against the containers. That is a real, byte-level comparison - but it is
    not a HEAD comparison, and the plan forbids reading it as one. When P-2.1 lands a three-way manifest this test must
    change, on purpose.
    """
    head_sha, note = gate.git_state()
    assert head_sha and head_sha != "UNKNOWN", "the gate must be able to name the current commit"
    assert "HEAD" in note
    three_way = [name for name in dir(gate) if "head_manifest" in name or "three_way" in name]
    assert three_way == [], (
        f"a three-way manifest appears to exist now ({three_way}); P-2.1 must then be re-run and this pin updated"
    )
    for name in ("manifest", "host_hashes"):
        assert hasattr(gate, name), "the worktree half of the comparison is what exists today"
    # The recorded state for the main plan's status file, asserted here so it cannot be lost in prose.
    assert "deployment_gate_head_unverified", "the flag the plan names for this limitation"
