"""Tests for the capability acceptance gate (plan §4.1/§4.3/§4.4).

The gate is the new authority on whether a CAPABILITY is finished, so it has to be held to the same standard as the
things it checks: it must reject fake completion for the RIGHT reason (not merely non-zero), and it must admit an honest
card - a gate that rejects everything protects nothing.

These tests import the gate by path (its filename has a dash) and drive the real rule functions plus the `--self-test`
suite, which is the same code the executor runs.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "capability-acceptance-gate.py"
SELFTEST = ROOT / "scripts" / "capability_gate_selftest.py"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _gate():
    return _load("capability_gate_under_test", GATE)


def _selftest():
    return _load("capability_gate_selftest_under_test", SELFTEST)


def _honest_card() -> dict:
    return _selftest().honest_card(ROOT)


def test_the_gate_self_test_rejects_all_six_fakes_and_admits_the_honest_card() -> None:
    completed = subprocess.run([sys.executable, str(GATE), "--self-test"], cwd=str(ROOT), capture_output=True, text=True)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "six fakes rejected, honest card admitted" in completed.stdout


def test_the_gate_admits_an_honest_partial_card() -> None:
    gate = _gate()
    violations = gate.check_card(_honest_card(), replay_controls=True)
    assert violations.rows == [], violations.codes()


def test_the_current_t3_artifact_is_rejected_for_the_right_reasons() -> None:
    gate = _gate()
    card = json.loads((ROOT / ".scratch" / "ghidra-c3" / "preflight" / "T3-artifact.json").read_text(encoding="utf-8"))
    codes = set(gate.check_card(card).codes())
    # The plan's §4.4 first fake: an artifact that claims completion with no capability schema, no status, a source_sha
    # that is not HEAD, and no independent binding.
    assert {"CARD_SHAPE", "STATUS_ENUM", "SOURCE_SHA_NOT_HEAD"} <= codes, sorted(codes)


def test_a_changed_file_outside_allowed_files_is_a_scope_escape() -> None:
    gate = _gate()
    card = _honest_card()
    card["allowed_files"] = []
    card["changed_files"] = ["src/threat_report_agent/contracts.py"]
    assert "SCOPE_ESCAPE" in gate.check_card(card).codes()


def test_a_changed_file_in_no_ownership_lock_is_unlisted() -> None:
    gate = _gate()
    card = _honest_card()
    card["allowed_files"] = ["src/threat_report_agent/not_in_any_lock.py"]
    card["changed_files"] = ["src/threat_report_agent/not_in_any_lock.py"]
    assert "OWNERSHIP_UNLISTED" in gate.check_card(card).codes()


def test_set_differences_that_do_not_recompute_are_rejected() -> None:
    """G-12 regression: a block whose recorded differences disagree with the sets it publishes."""
    gate = _gate()
    card = _honest_card()
    card["set_differences"] = [{
        "name": "the_g12_shape",
        "identity_key": "identity",
        "enumerated_set": ["alpha", "beta"],
        "retrieved_set": ["alpha", "beta"],
        "expected_minus_actual": ["alpha"],
        "actual_minus_expected": ["beta"],
    }]
    codes = gate.check_card(card).codes()
    assert codes.count("SET_DIFF_MISMATCH") == 2, codes


def test_a_cited_capture_that_is_not_on_disk_is_rejected() -> None:
    """G-1/G-14 regression: a field must agree with the file it names."""
    gate = _gate()
    card = _honest_card()
    card["object_dumps"][0]["field_values"]["capture"] = {
        "repr": ".scratch/capability-evidence/does-not-exist/capture.txt", "source": "mapping"}
    assert "CITED_FILE_MISSING" in gate.check_card(card).codes()


def test_a_negative_control_that_did_not_fail_is_rejected() -> None:
    gate = _gate()
    card = _honest_card()
    card["negative_controls"] = [dict(card["negative_controls"][0], exit_code=0)]
    assert "CONTROL_DID_NOT_FAIL" in gate.check_card(card).codes()


def test_accepted_with_a_non_final_token_is_rejected() -> None:
    gate = _gate()
    card = _honest_card()
    card["status"] = "ACCEPTED"
    card["known_limitations"] = ["the gap is RECORDED but not fixed"]
    assert "ACCEPTED_WITH_NON_FINAL_TOKEN" in gate.check_card(card).codes()


def test_a_contract_card_may_declare_that_it_makes_no_run_assertion() -> None:
    """§4.3's DB-binding rule targets RUN assertions. A contract card must say so explicitly, with a reason."""
    gate = _gate()
    card = _honest_card()
    card["makes_run_assertions"] = False
    card["no_run_assertion_reason"] = "this card asserts source-level contract equality only; it runs no analysis task"
    card["task_revision_content_records"] = []
    assert "NO_DB_BINDING" not in gate.check_card(card).codes()

    unexplained = _honest_card()
    unexplained["makes_run_assertions"] = False
    unexplained["task_revision_content_records"] = []
    assert "NO_RUN_ASSERTION_UNEXPLAINED" in gate.check_card(unexplained).codes()


def test_a_harness_mediated_control_is_replayed_through_its_harness() -> None:
    """Some controls are applied BY a harness that restores the bytes and fails itself if the target test passes."""
    gate = _gate()
    card = _honest_card()
    card["negative_controls"] = [{
        "name": "a_harness_mediated_control",
        "command": "py scripts/capability-acceptance-gate.py --self-test",
        "exit_code": 1,
        "harness_mediated": True,
        "expect_output": ["SELF-TEST: PASS"],
        "evidence": "the harness applies the tamper, requires the target test to fail and restores the bytes",
    }]
    assert gate.check_card(card, replay_controls=True).rows == [], gate.check_card(card).codes()

    mislabelled = _honest_card()
    mislabelled["negative_controls"] = [dict(card["negative_controls"][0], expect_output=[])]
    assert "CONTROL_NO_EXPECTATION" in gate.check_card(mislabelled).codes()


def test_accepted_while_docker_is_unavailable_is_rejected() -> None:
    """Plan §8: with no daemon there is no three-way manifest, so no capability can be ACCEPTED."""
    gate = _gate()
    card = _honest_card()
    card["status"] = "ACCEPTED"
    codes = gate.check_card(card).codes()
    assert "DEPLOYMENT_WORKTREE_ONLY" in codes or "DEPLOYMENT_UNVERIFIABLE_ACCEPTED" in codes, codes
