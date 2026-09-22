"""P1.3 / P1.4 contract: the structure-diff gate rejects what the plan says it must.

The plan's success criteria are both about the GATE, not about the tree:

  * P1.3: "纯搬家 diff 通过；加入一个故意违规的 fixture 时 gate 失败，移除 fixture 后恢复" - a pure move passes, an
    injected violation fails, removing it restores.
  * P1.4: "纯重命名/移动通过；故意改 UNKNOWN 为 CANDIDATE、删除 limitation、放宽 compose gate 的 fixture 被拒绝".

The injected-violation half is measured end to end, against a COPY of the package, by the untracked harness
`.scratch/check-structure-diff-canfail.py` (10 cases, including a real module move inside the copy). This file
pins the parts that must hold in a normal test run, because a gate whose can-fail evidence lives only in a
gitignored scratch script is a gate nobody re-runs.

    python -m pytest -q tests/test_structure_diff_gate.py
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-structure-diff.py"
SURFACE = ROOT / "docs" / "structure-surface.json"
POLICY = ROOT / "docs" / "import-policy.json"


def load_gate_module():
    """The script's filename has dashes, so it cannot be imported by name. Load it by path."""
    spec = importlib.util.spec_from_file_location("check_structure_diff", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def run_gate(*args: str) -> tuple[int, str]:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900,
    )
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def test_the_real_tree_passes_the_structure_gate() -> None:
    """P1.3's "a pure move passes" applied to the tree as it is: no NEW structural violation."""
    code, output = run_gate("--structure", "--strict")
    assert code == 0, f"the structure gate fails on the current tree:\n{output[-1500:]}"
    assert "no new structural violation" in output


def test_the_surface_file_is_current() -> None:
    """P1.4's gate: the recorded behaviour surfaces must equal the ones extracted now.

    So that a structural step that silently edits a state vocabulary, a threshold, a budget constant, a prompt or
    the sample-execution strategy fails HERE rather than in review.
    """
    code, output = run_gate("--surface", "--strict")
    assert code == 0, (
        "the behaviour surface changed; if the change is intended it must be recorded deliberately with "
        f"`--record-surface` and stated in the step record:\n{output[-1500:]}"
    )


def test_the_three_named_behaviour_changes_are_rejected() -> None:
    """The plan's three fixtures, run against the REAL compose gate."""
    gate = load_gate_module()
    verdicts = gate.fixture_verdicts()

    required = {name: item for name, item in verdicts.items() if item["required"] == "REJECTED"}
    assert len(required) == 3, f"P1.4 names three required rejections, found {sorted(required)}"
    for name, item in required.items():
        assert item["rejected"], (
            f"fixture {name!r} was ACCEPTED by the compose gate, so the gate no longer rejects the behaviour "
            f"change P1.4 names as forbidden. Violations returned: {item['violations']}"
        )


def test_the_narrow_limitation_case_is_recorded_as_accepted_and_that_is_the_known_gap() -> None:
    """P0.5-r2 measured that the plan's NARROWER case is NOT caught: a draft keeping the heading and dropping every
    bullet passes clean, because the check at analyst_report.py:6123 is a heading substring test.

    This test asserts the gap is still EXACTLY that, so it cannot be quietly widened and cannot be quietly
    closed without updating the record. Closing it is a behaviour fix and belongs to its own work item.
    """
    gate = load_gate_module()
    verdicts = gate.fixture_verdicts()
    narrow = verdicts["narrow_case_heading_kept_bullets_dropped"]
    assert narrow["rejected"] is False, (
        "the narrow case is now rejected - good news, but the P0.5-r2 known_behavior_gap and the "
        "structure-surface reading must be updated deliberately in the same commit"
    )
    assert narrow["violations"] == []


def test_the_policy_records_what_the_gate_measures() -> None:
    """An allowlist entry must say what it is. A bare identifier is how a recorded defect becomes an approval."""
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    for key in ("known_duplicate_implementations", "known_private_reach"):
        assert key in policy, f"{key} must be recorded, even when empty, so the gate has something to compare"
    for item in policy["known_duplicate_implementations"]:
        assert len(str(item.get("note", ""))) > 80, f"{item.get('name')} has no explanation"
    for item in policy["known_private_reach"]:
        assert len(str(item.get("note", ""))) > 80, f"{item.get('expr')} has no explanation"
    for item in policy["legacy_path_imports"]:
        assert item.get("new"), f"{item} does not name the canonical module the old path now points at"
    assert len(str(policy.get("_legacy_path_imports_note", ""))) > 80


def test_the_surface_file_records_all_eight_surfaces() -> None:
    """Six named by P1.4, plus the compose-gate verdicts (so a relaxation shows up as a DIFF) and the test-side
    `getsource` count (recorded for P3.7's progress, not gated)."""
    recorded = json.loads(SURFACE.read_text(encoding="utf-8"))
    expected = {
        "report_schema",
        "validator_thresholds",
        "state_enums",
        "prompt_semantics",
        "budget_constants",
        "sample_execution_strategy",
        "compose_gate_fixture_verdicts",
        "test_getsource_count",
    }
    assert set(recorded) == expected, f"recorded surfaces are {sorted(recorded)}"
    assert recorded["compose_gate_fixture_verdicts"]["unknown_restated_as_verified"] is True
    assert recorded["compose_gate_fixture_verdicts"]["narrow_case_heading_kept_bullets_dropped"] is False
    # A state vocabulary must record VALUES, not only member names: a status string is persisted and compared.
    assert "CANDIDATE = 'CANDIDATE'" in recorded["state_enums"]["ClaimStatus"][0], (
        "the state-enum surface no longer records member values, so an edit to a status STRING would be invisible"
    )
