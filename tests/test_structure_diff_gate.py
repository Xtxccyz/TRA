"""P1.3 / P1.4 contract: the structure-diff gate rejects what the plan says it must.

The plan's success criteria are both about the GATE, not about the tree:

  * P1.3: "纯搬家 diff 通过；加入一个故意违规的 fixture 时 gate 失败，移除 fixture 后恢复" - a pure move passes, an
    injected violation fails, removing it restores.
  * P1.4: "纯重命名/移动通过；故意改 UNKNOWN 为 CANDIDATE、删除 limitation、放宽 compose gate 的 fixture 被拒绝".

The injected-violation half is measured end to end, against a COPY of the package, by the untracked harness
`.scratch/check-structure-diff-canfail.py` (19 cases, including a real module move inside the copy, a changed
comparison operator, an unguarded enum, and an `importlib` old-path reach). This file pins the parts that must
hold in a normal test run, because a gate whose can-fail evidence lives only in a gitignored scratch script is a
gate nobody re-runs - a standards review of this change said exactly that, so the two cheapest cases now exist
here as well (`test_a_pure_move_passes_the_surface_gate`, `test_a_dropped_surface_is_a_problem...

    python -m pytest -q tests/test_structure_diff_gate.py
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

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


def test_a_pure_move_passes_the_surface_gate(tmp_path) -> None:
    """P1.4's "纯重命名/移动通过", measured HERE and not only in the gitignored can-fail harness.

    WHY THIS TEST EXISTS IN THE TRACKED SUITE (a standards review of this commit raised it): the end-to-end
    can-fail evidence for "a pure move passes" lived only in `.scratch/check-structure-diff-canfail.py`, which is
    gitignored - the same "a gate nobody re-runs" failure mode this repository already recorded once. This is the
    cheap half: copy the package, move one module into a new sub-package, leave a `sys.modules` shim exactly as
    plan section 7.1 step 4 prescribes, and require every surface to be byte-identical.
    """
    module = load_gate_module()
    real = ROOT / "src" / "threat_report_agent"
    copy = tmp_path / "threat_report_agent"
    shutil.copytree(real, copy, ignore=shutil.ignore_patterns("__pycache__"))
    (copy / "task").mkdir()
    (copy / "task" / "__init__.py").write_text("", encoding="utf-8")
    shutil.move(str(copy / "status.py"), str(copy / "task" / "status.py"))
    (copy / "status.py").write_text(
        '"""Compatibility shim left by the move; the implementation is threat_report_agent.task.status."""\n'
        "import sys\n"
        "from threat_report_agent.task import status as _real\n"
        "sys.modules[__name__] = _real\n",
        encoding="utf-8",
    )

    recorded = json.loads(SURFACE.read_text(encoding="utf-8"))
    module.set_source(str(copy))
    try:
        now = module.compute_surfaces_resilient()
    finally:
        module.set_source(str(real))

    for key, value in recorded.items():
        if key == "compose_gate_fixture_verdicts":
            assert "extraction_failed" not in now[key], f"the gate could not be imported from the copy: {now[key]}"
            continue
        assert json.dumps(now[key], sort_keys=True, ensure_ascii=False) == json.dumps(
            value, sort_keys=True, ensure_ascii=False
        ), (
            f"a PURE MOVE changed the surface {key}; the extraction is keyed by something that a move alters, so "
            "P1.4's success criterion cannot hold"
        )


def test_a_vanished_state_vocabulary_is_a_problem_not_an_absence(tmp_path) -> None:
    """The presence guard: a surface that stops extracting must not read as "no change"."""
    module = load_gate_module()
    real = ROOT / "src" / "threat_report_agent"
    copy = tmp_path / "threat_report_agent"
    shutil.copytree(real, copy, ignore=shutil.ignore_patterns("__pycache__"))
    # Remove every definition of one vocabulary, leaving the rest of the tree intact.
    status = copy / "status.py"
    status.write_text(
        status.read_text(encoding="utf-8").replace("class ClaimStatus(StrEnum):", "class ClaimStatusRenamed(StrEnum):"),
        encoding="utf-8",
    )
    module.set_source(str(copy))
    try:
        problems, current = module.surface_findings()
    finally:
        module.set_source(str(real))

    assert "ClaimStatus" not in current["state_enums"], "the fixture did not remove the vocabulary"
    assert any("ClaimStatus" in item for item in problems), (
        f"a vanished state vocabulary produced no problem, so it would read as 'unchanged': {problems}"
    )


def test_a_dropped_surface_is_a_problem_not_a_shorter_comparison() -> None:
    """The adversarial review's F5, closed and pinned.

    MEASURED evasion before the fix: deleting one line from `compute_surfaces()` removed that surface from the
    comparison entirely, because the comparison walked the CURRENT keys only - so a structural step could stop
    measuring `budget_constants` and still be told "no behaviour-surface change". Two guards now exist: the
    extraction refuses to return without every declared surface, and the comparison requires the recorded key set
    to match.
    """
    module = load_gate_module()
    with pytest.raises(RuntimeError, match="omitted"):
        module._require_every_surface({"report_schema": {"headings": ["# x"]}})

    recorded = json.loads(SURFACE.read_text(encoding="utf-8"))
    pruned = {key: value for key, value in recorded.items() if key != "budget_constants"}
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(module, "compute_surfaces_resilient", lambda: pruned)
        problems, _ = module.surface_findings()
    finally:
        monkey.undo()
    assert any("budget_constants" in item and "no longer measured" in item for item in problems), (
        f"a dropped surface was not reported as a regression: {problems}"
    )


def test_a_preregistered_violation_is_not_pre_approved(tmp_path) -> None:
    """The adversarial review's F4, closed and pinned.

    MEASURED evasion before the fix: `count > recorded` was the guard, so writing the SAME expression into the
    policy with a huge count pre-approved unlimited occurrences and `--strict` still returned 0 with only a
    non-failing note. An allowlist the policed step can widen in its own commit is not an allowlist, so the record
    must now match the measurement EXACTLY.
    """
    module = load_gate_module()
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    policy["known_private_reach"] = [
        {"module": item["module"], "expr": item["expr"], "count": 999999, "note": item["note"]}
        for item in policy["known_private_reach"]
    ] or [{"module": "threat_report_agent.service", "expr": "getattr(self, '_wait_cursors')", "count": 999999,
           "note": "preregistered with an absurd count, to prove the guard is exact rather than >="}]
    scratch_policy = tmp_path / "policy.json"
    scratch_policy.write_text(json.dumps(policy), encoding="utf-8")

    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(module, "POLICY_PATH", scratch_policy)
        problems, _, _ = module.structure_findings()
    finally:
        monkey.undo()
    assert any("must match exactly" in item for item in problems), (
        f"a pre-registered private reach with count 999999 was accepted: {problems}"
    )


def test_the_policy_records_what_the_gate_measures() -> None:
    """An allowlist entry must say what it is. A bare identifier is how a recorded defect becomes an approval."""
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    for key in ("known_duplicate_implementations", "known_private_reach"):
        assert key in policy, f"{key} must be recorded, even when empty, so the gate has something to compare"
    for item in policy["known_duplicate_implementations"]:
        assert len(str(item.get("note", ""))) > 80, f"{item.get('name')} has no explanation"
        assert item.get("body_sha256"), (
            f"{item.get('name')} records no body hash, so the entry would keep passing after the duplication "
            "disappeared or its body changed"
        )
    for item in policy["known_private_reach"]:
        assert len(str(item.get("note", ""))) > 80, f"{item.get('expr')} has no explanation"
    for item in policy["legacy_path_imports"]:
        assert item.get("new"), f"{item} does not name the canonical module the old path now points at"
    assert len(str(policy.get("_legacy_path_imports_note", ""))) > 80


def test_the_surface_file_records_every_declared_surface() -> None:
    """The declared surfaces, plus the compose-gate verdicts and the test-side `getsource` count.

    The key set is asserted against the GATE's own `REQUIRED_SURFACES`, not against a second hand-written list
    here: a surface added to the gate but not recorded (or recorded but no longer measured) must fail, and two
    independent lists would drift apart silently.
    """
    recorded = json.loads(SURFACE.read_text(encoding="utf-8"))
    module = load_gate_module()
    assert set(recorded) == set(module.REQUIRED_SURFACES), (
        f"recorded {sorted(recorded)} but the gate declares {sorted(module.REQUIRED_SURFACES)}"
    )
    # A surface that extracted nothing must never look healthy.
    assert recorded["state_enums"].get("ToolRunStatus"), (
        "ToolRunStatus is a persisted status vocabulary and is missing from the state surface - a hand-written "
        "symbol list let it through once; the enum half must stay automatic"
    )
    assert recorded["threshold_comparisons"]["count"] > 0, (
        "the comparison surface is empty, so a changed comparison OPERATOR would be invisible"
    )
    assert recorded["compose_gate_fixture_verdicts"]["unknown_restated_as_verified"] is True
    assert recorded["compose_gate_fixture_verdicts"]["narrow_case_heading_kept_bullets_dropped"] is False
    # A state vocabulary must record VALUES, not only member names: a status string is persisted and compared.
    assert "CANDIDATE = 'CANDIDATE'" in recorded["state_enums"]["ClaimStatus"][0], (
        "the state-enum surface no longer records member values, so an edit to a status STRING would be invisible"
    )
