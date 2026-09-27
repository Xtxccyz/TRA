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


def test_the_cli_names_its_container_state_and_only_a_matched_gate_exits_zero() -> None:
    """The CLI must always NAME its state, and only a MATCHED_TO_HEAD manifest may exit zero.

    MEASURED (P-2.1, the first full-suite run with the containers up): the previous form of this test asserted a
    non-zero exit unconditionally, because on the day it was written the daemon was unreachable and the command could
    only report PARTIAL. With the three images rebuilt and the stack running, the SAME command exits 0 and prints
    MATCHED_TO_HEAD, so that assertion had been measuring the HOST rather than the gate - it went red with not one line
    of product code changed. The contract that holds in both worlds is pinned here instead: the gate names one of its
    three states, and the exit code agrees with the state. That keeps the plan's own rule - a blocked deployment gate
    is never a pass - checkable on a day when the gate IS matched.
    """
    completed = subprocess.run([sys.executable, str(GATE), "--three-way"], cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    assert "container_state" in completed.stdout
    state = next((name for name in ("MATCHED_TO_HEAD", "PARTIAL", "BLOCKED") if name in completed.stdout), "")
    assert state, f"the gate must name one of its three states; stdout ended with {completed.stdout[-400:]!r}"
    expected_zero_for_a_matched_manifest = state == "MATCHED_TO_HEAD"
    assert (completed.returncode == 0) == expected_zero_for_a_matched_manifest, (
        f"only a MATCHED_TO_HEAD manifest may exit zero; state={state!r} exit={completed.returncode}")


def test_a_file_present_only_in_the_tree_is_reported_as_expected_minus_actual(gate) -> None:
    """P-2.1's control (b) in the small: because the manifest is ENUMERATED from disk, a production file the container
    does not have can only ever appear on the EXPECTED side. MEASURED (this step, with a real extra file in `src/`):
    the strict gate exits 1 with it under `missing`, and `--three-way` publishes it under `expected_minus_actual` for
    every service."""
    difference = gate.set_difference({"a.py": "1", "new.py": "2"}, {"a.py": "1"})
    assert difference["expected_minus_actual"] == ["new.py"]
    assert difference["actual_minus_expected"] == []
    assert difference["content_differs"] == []


def test_a_file_present_only_in_the_container_is_reported_as_actual_minus_expected(gate) -> None:
    """The reverse direction, which the three-way comparison cannot see BY CONSTRUCTION: its retrieved mapping is the
    manifest's own path list hashed inside the container, so a container-only path is never one of its keys. MEASURED
    (P-2.1): against the nine-day-old `threat-report-agent-emu-worker:fixed` image the gate reported
    `container-only=5`, and those five are visible only through its `container_listing()` helper."""
    difference = gate.set_difference({"a.py": "1"}, {"a.py": "1", "leftover.py": "3"})
    assert difference["actual_minus_expected"] == ["leftover.py"]
    assert difference["expected_minus_actual"] == []
    assert difference["content_differs"] == []


def test_the_manifest_is_enumerated_from_disk_so_a_new_production_file_appears(gate, monkeypatch, tmp_path) -> None:
    """P-2.1 asks for the ACTUAL production Python/Java/prompt files; a fixed list is how the old gate could not see a
    moved or added implementation. The rule pinned here: whatever is under the source root is in the manifest, whatever
    its extension, and no `__pycache__` entry ever is."""
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "system.md").write_text("# prompt\n", encoding="utf-8")
    (tmp_path / "ghidra_scripts").mkdir()
    (tmp_path / "ghidra_scripts" / "Export.java").write_text("class Export {}\n", encoding="utf-8")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "module.cpython-312.pyc").write_bytes(b"\x00\x01")
    monkeypatch.setattr(gate, "SOURCE", tmp_path)
    files = gate.manifest()
    assert files == ["ghidra_scripts/Export.java", "module.py", "prompts/system.md"], files


def test_the_head_manifest_omits_a_path_with_no_blob_at_head(gate) -> None:
    """MEASURED (P-2.1): a file that exists only in the working tree has NO blob at HEAD, and hashing that absence as
    an empty blob would turn "absent from the commit" into a value with a digest. It is omitted instead, which is what
    makes the strict half of the plan's control (b) report the new file as present in the tree and absent from the
    container rather than as an unchanged empty string."""
    is_empty, folded, head_sha = gate.head_hashes(["__p2_1_no_such_path__.py"])
    assert is_empty == {} and folded == {}
    assert head_sha != "UNKNOWN", "the HEAD manifest must still report the commit it read"
    present, present_folded, _ = gate.head_hashes(["contracts.py"])
    assert set(present) == {"contracts.py"}
    assert set(present_folded) == {"contracts.py"}
