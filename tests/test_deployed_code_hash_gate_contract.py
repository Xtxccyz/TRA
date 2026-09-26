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


def test_the_three_way_manifest_exists_and_publishes_set_differences(gate) -> None:
    """P-2.1 LANDED (round 169). This pin USED to assert `three_way == []` and told its reader to invert it here when
    the capability appeared - which is exactly what happened, so the assertion below replaces it deliberately.

    What P-2.1 demands is a HEAD/worktree/container manifest that publishes SET DIFFERENCES rather than an "ALL MATCH"
    slogan, and a negative control: the container on an older revision, or HEAD moving ahead of the worktree, must be
    non-zero.
    """
    files = gate.manifest()
    report = gate.three_way_manifest(files, ["api", "emu-worker"])
    for key in ("head_sha", "head", "worktree", "container", "container_state", "head_vs_worktree",
                "container_vs_worktree", "services", "manifest_size"):
        assert key in report, f"the three-way manifest has no `{key}`"
    difference = report["head_vs_worktree"]
    for key in ("expected_minus_actual", "actual_minus_expected", "content_differs", "line_ending_only"):
        assert key in difference, f"the HEAD/worktree difference has no `{key}`"
    assert set(difference["line_ending_only"]) <= set(difference["content_differs"]), (
        "a line-ending-only difference is a subset of the raw differences by construction"
    )
    assert report["head"] and report["worktree"], "both sources must actually be hashed"


def test_a_line_ending_difference_is_told_apart_from_a_content_change(gate, tmp_path) -> None:
    """MEASURED (round 169): the first run reported 21 files as differing from HEAD while `git status` listed one - the
    repository's recorded EOL drift (`core.autocrlf` with no `.gitattributes`). Reporting that as content drift is
    wrong; normalising the ONLY comparison would be worse, because it would hide a real change."""
    (tmp_path / "crlf.txt").write_bytes(b"a\r\nb\r\n")
    (tmp_path / "lf.txt").write_bytes(b"a\nb\n")
    crlf_raw = gate.hashlib.sha256((tmp_path / "crlf.txt").read_bytes()).hexdigest()
    lf_raw = gate.hashlib.sha256((tmp_path / "lf.txt").read_bytes()).hexdigest()
    folded = gate.normalized_hashes(tmp_path, ["crlf.txt", "lf.txt"])
    differing = gate.set_difference({"f": lf_raw}, {"f": crlf_raw})
    assert differing["content_differs"] == ["f"], "raw bytes differ, and that must stay visible"
    assert folded["crlf.txt"] == folded["lf.txt"], (
        "the folded hash must erase a line-ending-only difference, which is what separates it from a content change"
    )


def test_the_cli_reports_a_distinct_partial_state_without_a_daemon() -> None:
    """Without a daemon the container half is UNAVAILABLE - a state, not an empty comparison that reads as "no
    differences"."""
    completed = subprocess.run([sys.executable, str(GATE), "--three-way"], cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    assert "container_state" in completed.stdout
    assert completed.returncode != 0, "an unavailable container half must not exit zero"
    assert ("PARTIAL" in completed.stdout) or ("BLOCKED" in completed.stdout), (
        "the gate must name the state it is in: PARTIAL (HEAD == worktree, no daemon) or BLOCKED (tree is not HEAD)"
    )
