"""Tests for `scripts/ghidra-plan-preflight.py` (Ghidra/C3 main plan, step P-0.3).

WHY THESE EXIST RATHER THAN A BIGGER FIXTURE: the preflight's `--self-test` tampers with a REAL generated artifact and
requires the real executable to exit non-zero. That is the strongest form of the check, but it can only break a block
the artifact actually contains - and P-0.3 introduces no product symbol, so there is no M4 block to disconnect. The plan
therefore requires the remaining mechanism to be covered by a named unit test, and `_check_mechanism_coverage()` reads
THIS file and fails the artifact if any of these function names is missing.

Every test below asserts that the validator REFUSES (non-empty violations), never that it accepts. A test that only
proved "a good artifact passes" would not be evidence that the hook blocks anything.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("ghidra_plan_preflight_under_test",
                                                  ROOT / "scripts" / "ghidra-plan-preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = _load()
STATUS = {"revision": PREFLIGHT.PLAN_REVISION, "plan_sha256": PREFLIGHT.sha256_file(PREFLIGHT.PLAN),
          "steps": [{"step": step, "decision": "complete"} for step in
                    PREFLIGHT.STEPS[:PREFLIGHT.STEPS.index("P-0.3")]],
          "deployment": {"gate_state": "BLOCKED"}}
OWNERSHIP = {"overlap": [], "overlap_verdict": "NO OVERLAP", "structure_plan_conflicts": [],
             "files": [{"file": "scripts/ghidra-plan-preflight.py", "state": "AVAILABLE_PENDING_LOCK"}]}


def _codes(violations) -> set[str]:
    return {str(item).split(":", 1)[0] for item in violations}


def _base_artifact(**overrides) -> dict:
    artifact = {
        "step": "P-0.3",
        "source_sha": "0" * 40,
        "worktree_manifest_sha": "1" * 64,
        "allowed_files": ["scripts/ghidra-plan-preflight.py"],
        "changed_files": ["scripts/ghidra-plan-preflight.py"],
        "commands": ["py -m pytest -q tests/test_ghidra_plan_preflight.py"],
        "focused_failure_nodes_after": [],
        "full_failure_nodes_after": [],
        # A step that REPORTS a failure set must name the capture it came from (round 275 hardening), so the fixture
        # points at the plan's own recorded 0-node baseline rather than being exempted from the rule. The gate
        # re-parses this file and requires it to agree with `full_failure_nodes_after`, so the fixture cannot drift
        # from the artifact it claims to describe.
        "full_suite_capture": ".scratch/ghidra-c3/baseline/pytest-r170-failures.txt",
        "negative_controls": [{"name": "a_control_that_fails", "exit_code": 1, "evidence": "assertion failed"}],
        "edit_hashes": [{"path": "scripts/ghidra-plan-preflight.py", "created": True, "sha256_before": "(absent)",
                         "sha256_after": "2" * 64, "method": "whole-file write",
                         "compile_or_typecheck": "py -m compileall -q scripts/ghidra-plan-preflight.py"}],
        "py_compile_or_typecheck": "pass",
        "deployment_manifest": {"gate_state": "BLOCKED"},
        "skill_audit": {"skill": "improve-codebase-architecture", "method": "denial-based",
                        "findings": [{"id": "X", "severity": "LOW", "status": "RECORDED", "finding": "base fixture"}]},
        "decision": "complete",
        "mechanisms_exercised": ["M1", "M2", "M3", "M4", "M5", "M6"],
        "object_dumps": [{"name": "probe", "type": "Path", "has_dict": False,
                          "field_values": {"exists()": {"repr": "True", "source": "measured_return"}},
                          "signature": "(self, *args)", "return_type": "Path"}],
    }
    artifact.update(overrides)
    return artifact


def _validate(artifact: dict):
    return PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, list(artifact.get("changed_files") or []))


def test_a_complete_artifact_has_no_violations() -> None:
    """The negative tests below only mean something if the base artifact is otherwise acceptable."""
    assert list(_validate(_base_artifact())) == [], "the base artifact itself must be clean"


def test_m1_blocks_a_dump_without_a_real_value() -> None:
    artifact = _base_artifact(object_dumps=[{"name": "probe", "type": "Path", "has_dict": False,
                                             "field_values": {}, "signature": "(self)"}])
    codes = _codes(_validate(artifact))
    assert "M1_NO_VALUE" in codes
    assert "M1_SURFACE" not in codes, "the dump does have a signature; only the measured value is missing"


def test_m1_blocks_a_getattr_template() -> None:
    """The plan's own failure example: `getattr(x, f, None)` dressed up as path evidence."""
    artifact = _base_artifact(object_dumps=[{"name": "probe", "type": "Worker", "has_dict": True, "field_values": {},
                                             "vars": {}, "signature": "",
                                             "note": "getattr(worker, 'isolated', None)"}])
    codes = _codes(_validate(artifact))
    assert "M1_SURFACE" in codes and "M1_NO_VALUE" in codes


def test_m1_accepts_a_mapping_dump_with_real_values_and_blocks_an_empty_one() -> None:
    """P-2.1's M1 dumps are parsed JSON Mappings, not Python objects: a `dict` has no `vars()` and no signature, so
    the rule has to stand on the measured field values alone. MEASURED: `record_object` on a Mapping records no `vars`
    and no `signature` at all, so a validator that demanded a surface would reject every JSON document a step dumps -
    and one that accepted an empty `field_values` would accept a dump that carries no value, which is the shape M1
    exists to reject."""
    mapping = PREFLIGHT.record_object({"head_sha": "d0bc17fc6f44", "manifest_size": 131},
                                      name="three_way_manifest", fields=["head_sha", "manifest_size"])
    assert mapping["has_dict"] is False
    assert "vars" not in mapping and "signature" not in mapping
    assert "M1_SURFACE" not in _codes(_validate(_base_artifact(object_dumps=[mapping])))
    codes = _codes(_validate(_base_artifact(object_dumps=[dict(mapping, field_values={})])))
    assert "M1_NO_VALUE" in codes and "M1_SURFACE" in codes


def test_m2_blocks_a_header_only_anchor() -> None:
    artifact = _base_artifact(edit_hashes=[{
        "path": "scripts/ghidra-plan-preflight.py", "sha256_before": "a" * 64, "sha256_after": "b" * 64,
        "method": "anchor insert", "anchor": "def main(argv):", "compile_or_typecheck": "pass"}])
    assert "M2_ORPHAN_ANCHOR" in _codes(_validate(artifact))


def test_m2_blocks_a_non_digest_hash() -> None:
    """MEASURED (P-0.3): copying `sha256_before` into `sha256_after` on a created file slipped through, because
    "(absent)" was accepted as a hash. A digest field that accepts a non-digest is not a check."""
    artifact = _base_artifact(edit_hashes=[{"path": "scripts/ghidra-plan-preflight.py", "created": True,
                                            "sha256_before": "(absent)", "sha256_after": "(absent)",
                                            "method": "whole-file write", "compile_or_typecheck": "pass"}])
    assert "M2_AFTER_NOT_A_HASH" in _codes(_validate(artifact))


def test_m2_blocks_a_git_checkout_restore() -> None:
    artifact = _base_artifact(edit_hashes=[{
        "path": "scripts/ghidra-plan-preflight.py", "sha256_before": "a" * 64, "sha256_after": "b" * 64,
        "method": "whole-file write", "restore": "git checkout", "compile_or_typecheck": "pass"}])
    assert "M2_RESTORE" in _codes(_validate(artifact))


def test_m3_blocks_a_runtime_claim_without_sql_metadata() -> None:
    artifact = _base_artifact(claims_runtime_fact=True, task_revision_content_records=[
        {"task_id": "", "revision_id": "rev", "content_sha256": "c" * 64, "started_at": "t0", "finished_at": "t1",
         "exit_code": 0, "rows": [["row"]]}])
    codes = _codes(_validate(artifact))
    assert "M3_COLUMNS" in codes
    assert "M3_PROVENANCE" in codes, "a hand-typed task id is not SQL evidence"
    assert "M3_NEGATIVE" in codes, "no wrong-sample/wrong-revision control was recorded"


def test_m3_blocks_a_query_that_did_not_succeed() -> None:
    artifact = _base_artifact(claims_runtime_fact=True, task_revision_content_records=[
        {"task_id": "t", "revision_id": "r", "content_sha256": "c" * 64, "started_at": "t0", "finished_at": "t1",
         "sql_text": "SELECT 1", "connection": "sqlite3 probe", "schema_query": "SELECT name FROM sqlite_master",
         "exit_code": 1, "rows": []}],
        wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1})
    codes = _codes(_validate(artifact))
    assert "M3_EXIT" in codes and "M3_ROWS" in codes


def test_m3_blocks_a_content_hash_that_does_not_match_its_source() -> None:
    """MEASURED (P-0.3): 64 zeros passed while only presence was required. The digest must be recomputed from a named
    source, otherwise the field is decoration."""
    artifact = _base_artifact(claims_runtime_fact=True, task_revision_content_records=[
        {"task_id": "t", "revision_id": "r", "content_sha256": "0" * 64, "started_at": "t0", "finished_at": "t1",
         "sql_text": "SELECT 1", "connection": "sqlite3 probe", "schema_query": "SELECT name FROM sqlite_master",
         "content_source": "scripts/ghidra-plan-preflight.py", "exit_code": 0, "rows": [["row"]]}],
        wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1})
    assert "M3_CONTENT_MISMATCH" in _codes(_validate(artifact))


def test_m3_blocks_a_content_hash_with_no_named_source() -> None:
    artifact = _base_artifact(claims_runtime_fact=True, task_revision_content_records=[
        {"task_id": "t", "revision_id": "r", "content_sha256": "0" * 64, "started_at": "t0", "finished_at": "t1",
         "sql_text": "SELECT 1", "connection": "sqlite3 probe", "schema_query": "SELECT name FROM sqlite_master",
         "exit_code": 0, "rows": [["row"]]}],
        wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1})
    assert "M3_CONTENT_SOURCE" in _codes(_validate(artifact))


def test_m4_blocks_a_symbol_without_a_render_proof() -> None:
    assert "M4_MISSING" in _codes(_validate(_base_artifact(introduces_symbol=True)))


def test_m4_blocks_a_json_only_proof_and_a_dangling_control() -> None:
    artifact = _base_artifact(
        introduces_symbol=True,
        producer_consumer_render_proof=[{"symbol": "stop_reason", "producer": "writer", "consumer": "renderer",
                                         "rendered_markdown_contains": "TIMED_OUT", "renderer": "compose_official",
                                         "read_from_json_only": True,
                                         "consumer_disconnect_control": "not_a_recorded_control"}])
    codes = _codes(_validate(artifact))
    assert "M4_JSON_ONLY" in codes, "reading the value from JSON is not the re-rendered official Markdown"
    assert "M4_CONTROL_MISSING" in codes, "the disconnect control must be a real recorded negative control"


def test_m5_blocks_a_count_only_publication() -> None:
    artifact = _base_artifact(publishes_collection=True, set_differences=[
        {"name": "ghidra_functions", "identity_key": "entry", "count_only": True}])
    codes = _codes(_validate(artifact))
    assert "M5_FIELD" in codes and "M5_COUNT_ONLY" in codes


def test_m5_blocks_a_missing_reverse_difference() -> None:
    artifact = _base_artifact(publishes_collection=True, set_differences=[
        {"name": "ghidra_functions", "identity_key": "entry", "enumerated_set": ["a"], "retrieved_set": ["a"],
         "expected_minus_actual": []}])
    assert "M5_FIELD" in _codes(_validate(artifact))


def test_m6_blocks_a_negative_control_that_did_not_fail() -> None:
    artifact = _base_artifact(negative_controls=[{"name": "never_failed", "exit_code": 0, "evidence": "passed"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_EXIT" in codes


def test_m6_blocks_a_collection_error_recorded_as_a_negative_control() -> None:
    """MEASURED (P-1.3): a can-fail harness reported `ALL_CONTROLS_FAILED_AS_REQUIRED` while every control was a
    pytest COLLECTION error (`exit_code: 4`, `ERROR tests/...`) caused by the test file being written at that
    moment. Non-zero is not the same claim as "the assertion failed", and a gate that accepts any non-zero exit
    accepts a run in which no tamper was ever exercised."""
    artifact = _base_artifact(negative_controls=[
        {"name": "collection_error", "exit_code": 4, "evidence": "ERROR tests/test_analyst_report_acceptance.py"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_NO_TEST_RAN" in codes, "a collection error was accepted as a failing negative control"
    assert "NEGATIVE_EXIT" not in codes, "the exit code is non-zero; the rejection must name the real reason"


def test_a_step_must_name_the_capture_its_failure_set_comes_from() -> None:
    """MEASURED (round 275): `full_suite_capture` was optional, so an artifact that omitted it switched OFF the
    recomputation of `full_failure_nodes_after` - the declared set was taken on trust, and a step could report an
    empty failure set for a run that had failures. Eight recorded steps predate the field (they are listed in
    `LEGACY_WITHOUT_SUITE_CAPTURE` with their measured reason); every later step must name one."""
    artifact = _base_artifact(step="P-6", full_failure_nodes_after=[])
    artifact.pop("full_suite_capture", None)
    assert "CAPTURE_NOT_NAMED" in _codes(_validate(artifact))

    legacy = _base_artifact(step="P-1.4", full_failure_nodes_after=[])
    legacy.pop("full_suite_capture", None)
    assert "CAPTURE_NOT_NAMED" not in _codes(_validate(legacy)), (
        "the measured historical exemption was lost, so an accepted step would now be reported as a violation"
    )


def test_the_recorded_evidence_triggers_each_check_even_when_the_boolean_says_no() -> None:
    """MEASURED (round 274, the plan's standing hardening item): `claims_runtime_fact`, `introduces_symbol` and
    `publishes_collection` were SWITCHES, so an artifact that recorded the evidence while declaring the boolean
    false skipped the very check that exists because of it. The boolean may still turn a check ON; it may no longer
    turn it OFF once the evidence is present.

    Each case below is broken in a way the corresponding check must catch, with the boolean set false:
      * M3: a SQL row missing its task id and content hash, `claims_runtime_fact: false`;
      * M4: a proof without a `renderer`, `introduces_symbol: false`;
      * M5: a count-only set block, `publishes_collection: false`."""
    m3 = _base_artifact(claims_runtime_fact=False, task_revision_content_records=[
        {"revision_id": "r", "sql_text": "select 1", "connection": "sqlite://x", "schema_query": "pragma",
         "exit_code": 0, "rows": [{"n": 1}]}])
    assert "M3_COLUMNS" in _codes(_validate(m3)), "a recorded SQL row was not checked once the boolean was false"

    m4 = _base_artifact(introduces_symbol=False, producer_consumer_render_proof=[
        {"symbol": "s", "producer": "p", "consumer": "c", "rendered_markdown_contains": "x",
         "consumer_disconnect_control": "control_x"}],
        negative_controls=[{"name": "control_x", "exit_code": 1, "evidence": "the naive claim is false"}])
    assert "M4_FIELD" in _codes(_validate(m4)), "a recorded render proof was not checked once the boolean was false"

    m5 = _base_artifact(publishes_collection=False, set_differences=[
        {"name": "s", "identity_key": "entry", "enumerated_set": ["a"], "retrieved_set": [], "count_only": True,
         "actual_minus_expected": []}])
    assert "M5_FIELD" in _codes(_validate(m5)) and "M5_COUNT_ONLY" in _codes(_validate(m5)), (
        "a recorded set difference was not checked once the boolean was false"
    )


def test_m6_blocks_a_control_that_died_in_its_own_harness() -> None:
    """MEASURED (round 273, in P-6's container acceptance): a control recorded `exit_code: 1` whose `evidence` was a
    Python traceback ending in `NameError: name 'SAMPLE' is not defined` raised INSIDE the control script. The
    product was never exercised, and a rule that reads only the exit code counts it as "failed as required".

    The rule is deliberately a CONJUNCTION (traceback AND a harness-level exception name): P-1.4 and P-2.2 carry
    real captured tracebacks with none of those names, and P-4.1/P-5 carry the names with no traceback, so neither
    half alone can be used without producing false findings against already-accepted steps."""
    artifact = _base_artifact(negative_controls=[
        {"name": "broken_java_script_still_runs", "exit_code": 1, "observed": {},
         "evidence": "Traceback (most recent call last):\n"
                     '  File "/work/tmp/p6acc/p6_acc_controls.py", line 225, in main\n'
                     '    ["/opt/ghidra/support/analyzeHeadless", str(project), "broken", "-import", str(SAMPLE),\n'
                     "NameError: name 'SAMPLE' is not defined"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_HARNESS_ERROR" in codes, "a harness traceback was accepted as a failing control"
    assert "NEGATIVE_NO_OBSERVATION" in codes, "an empty `observed` block was accepted as an observation"


def test_m6_accepts_a_control_that_records_what_it_observed() -> None:
    """The positive half, so the two rules above cannot be satisfied by rejecting every control: a script control
    that observed the product refusing, and recorded that observation, is accepted."""
    artifact = _base_artifact(negative_controls=[
        {"name": "reset_is_reported_as_down", "exit_code": 1,
         "observed": {"query": {"kind": "reset", "status": "BLOCKED", "code": "GHIDRA_RESIDENT_CLOSED_MID_ANSWER"}},
         "evidence": "the naive claim 'a resident that accepts and then RESETS is reported as down' is false"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_HARNESS_ERROR" not in codes and "NEGATIVE_NO_OBSERVATION" not in codes


def test_m6_does_not_fire_on_a_real_captured_traceback_without_a_harness_exception() -> None:
    """BACKWARD COMPATIBILITY, measured against the recorded artifacts: a control may legitimately quote a traceback
    the PRODUCT produced (P-1.4 and P-2.2 do). Only a harness-level exception name together with the traceback is a
    harness failure."""
    artifact = _base_artifact(negative_controls=[
        {"name": "product_crashed", "exit_code": 1,
         "evidence": "Traceback (most recent call last):\n"
                     '  File "/app/src/threat_report_agent/report/reporting.py", line 10, in render\n'
                     "ValueError: the projection produced no body"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_HARNESS_ERROR" not in codes


def test_m6_blocks_a_pytest_failure_reported_with_a_non_failure_exit_code() -> None:
    """The narrower half of the same rule: the run DID report a failing assertion, so the exit code must be
    pytest's failure code. An abort (3) or a usage error (4) after a `FAILED` line is an inconsistent record."""
    artifact = _base_artifact(negative_controls=[
        {"name": "aborted_after_failing", "exit_code": 3,
         "evidence": "FAILED tests/test_x.py::test_y - AssertionError: the boundary never reached the body"}])
    assert "NEGATIVE_NOT_A_TEST_FAILURE" in _codes(_validate(artifact))


def test_m6_blocks_a_control_whose_named_node_did_not_fail() -> None:
    """A control may not NAME one node and record the failure of another: the node must appear as FAILED."""
    artifact = _base_artifact(negative_controls=[
        {"name": "wrong_node", "exit_code": 1, "node": "tests/test_x.py::test_the_intended_one",
         "evidence": "FAILED tests/test_x.py::test_a_different_one - AssertionError: x"}])
    assert "NEGATIVE_NODE_NOT_FAILED" in _codes(_validate(artifact))


def test_m6_accepts_a_script_control_with_its_own_non_zero_convention() -> None:
    """BACKWARD COMPATIBILITY, measured against the recorded artifacts: not every control is pytest. P-0.4's
    deployment-gate control exits 2 and P-1.1's wrong-revision SQL probe exits 3, both by their own convention.
    Tightening the rule must not invalidate a real control of that shape."""
    artifact = _base_artifact(negative_controls=[
        {"name": "deployment_gate_exits_non_zero_when_docker_is_unavailable", "exit_code": 2,
         "evidence": "- Docker is unavailable, so deployment consistency CANNOT be checked"},
        {"name": "wrong_revision_returns_no_row_for_the_same_sql", "exit_code": 3,
         "evidence": "WRONG-REVISION CONTROL: 0 rows for a revision id absent from 32 tables; exit non-zero"},
    ])
    assert _codes(_validate(artifact)) == set(), "a genuine script-shaped control was rejected by the new rule"


def test_m6_accepts_a_script_control_whose_prose_says_failed() -> None:
    """MEASURED (P-1.7): a script control whose evidence read "the deployment gate FAILED as required" and exited 2
    was rejected as `NEGATIVE_NOT_A_TEST_FAILURE`, because the rule fired on the bare substring `failed `. That is a
    false positive against the control's OWN documented convention: the rule exists to catch pytest output, so it
    now requires the node shape (`FAILED <file>::<test>`) or an AssertionError, not the English word."""
    artifact = _base_artifact(negative_controls=[
        {"name": "the_deployment_gate_really_is_blocked", "kind": "script", "exit_code": 2,
         "evidence": "the deployment gate FAILED as required: BLOCKED - deployment consistency not verifiable"},
    ])
    assert "NEGATIVE_NOT_A_TEST_FAILURE" not in _codes(_validate(artifact)), (
        "a script control was judged by pytest's exit-code convention it does not use"
    )


def test_m6_still_blocks_a_real_pytest_failure_with_a_non_failure_exit_code() -> None:
    """The other half: a NODE-SHAPED pytest failure must still carry exit 1."""
    artifact = _base_artifact(negative_controls=[
        {"name": "aborted", "exit_code": 3,
         "evidence": "FAILED tests/test_x.py::test_y - AssertionError: the boundary never reached the body"}])
    assert "NEGATIVE_NOT_A_TEST_FAILURE" in _codes(_validate(artifact))


def test_m6_blocks_a_control_that_restored_a_different_file() -> None:
    """MEASURED (P-1.3, finding F4): a restore raised `OSError [Errno 22]` and left a mutation ON DISK while the
    control still read as a pass. A control that edits a product file must show it returned to its exact bytes."""
    artifact = _base_artifact(negative_controls=[
        {"name": "restore_failed", "exit_code": 1, "file": "src/threat_report_agent/report/reporting.py",
         "sha256_before": "0" * 64, "sha256_restored": "f" * 64, "restore_is_byte_identical": False,
         "evidence": "FAILED tests/test_x.py::test_y - AssertionError: z"}])
    codes = _codes(_validate(artifact))
    assert "NEGATIVE_RESTORE_NOT_PROVEN" in codes, "an unrestored tamper was accepted as a negative control"


def test_m6_blocks_a_tampered_file_with_no_restore_digests() -> None:
    """Naming the file but recording no before/after digest is the same gap stated less loudly."""
    artifact = _base_artifact(negative_controls=[
        {"name": "no_digests", "exit_code": 1, "file": "src/threat_report_agent/report/reporting.py",
         "evidence": "FAILED tests/test_x.py::test_y - AssertionError: z"}])
    assert "NEGATIVE_RESTORE_NOT_PROVEN" in _codes(_validate(artifact))


def test_m6_accepts_a_control_that_proves_its_restore() -> None:
    """POSITIVE CONTROL: the shape P-1.3's fixed harness produces must pass."""
    artifact = _base_artifact(negative_controls=[
        {"name": "properly_restored", "exit_code": 1, "file": "src/threat_report_agent/report/reporting.py",
         "sha256_before": "a" * 64, "sha256_restored": "a" * 64, "restore_is_byte_identical": True,
         "evidence": "FAILED tests/test_x.py::test_y - AssertionError: z"}])
    assert _codes(_validate(artifact)) == set(), "a properly restored control was rejected"


def test_m2_blocks_a_partial_edit_ledger(tmp_path) -> None:
    """MEASURED (P-0.4): `changed_files` named three files and `edit_hashes` recorded two. The old rule fired only
    when the ledger was ENTIRELY empty, so a partial record passed - a partial record read as complete, which is the
    plan's M5 defect applied to the edit ledger itself."""
    first = tmp_path / "one.py"
    second = tmp_path / "two.py"
    first.write_text("x = 1\n", encoding="utf-8")
    second.write_text("y = 2\n", encoding="utf-8")
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    entry = {"path": str(first), "sha256_before": digest, "sha256_after": digest,
             "method": "m", "compile_or_typecheck": "py -m py_compile one.py", "changed": True}
    artifact = _base_artifact(changed_files=[str(first), str(second)], allowed_files=[str(first), str(second)],
                              edit_hashes=[entry])
    assert "M2_COVERAGE" in _codes(PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, [str(first), str(second)]))


def test_m2_accepts_a_ledger_that_covers_every_changed_file(tmp_path) -> None:
    """POSITIVE CONTROL: the same artifact with both entries must pass, so the rule cannot reject a real record."""
    first = tmp_path / "one.py"
    second = tmp_path / "two.py"
    first.write_text("x = 1\n", encoding="utf-8")
    second.write_text("y = 2\n", encoding="utf-8")
    entries = []
    for path in (first, second):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"path": str(path), "sha256_before": digest, "sha256_after": digest,
                        "method": "m", "compile_or_typecheck": f"py -m py_compile {path.name}", "changed": True})
    artifact = _base_artifact(changed_files=[str(first), str(second)], allowed_files=[str(first), str(second)],
                              edit_hashes=entries)
    codes = _codes(PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, [str(first), str(second)]))
    assert "M2_COVERAGE" not in codes, "a complete edit ledger was rejected"


def test_m2_blocks_a_changed_file_that_is_not_utf8(tmp_path) -> None:
    """MEASURED (P-1.4): an edit replaced the five Chinese lines of a P-1.2 test file with double-encoded text - UTF-8
    bytes read as CP936 and written back as UTF-8. The suite stayed GREEN, because the corrupted constant then held a
    string the product can never print, so the assertion built on it became vacuously true. A silently weakened
    assertion is worse than a failing one, and no hash check can see it: the bytes are different but valid."""
    victim = tmp_path / "victim.py"
    victim.write_bytes(b'HEADING = "# \xe5\x88\x86\xe6\x9e\x90\xe7\xbb\x93\xe8\xae\xba"\n')
    artifact = _base_artifact(changed_files=[str(victim)], allowed_files=[str(victim)])
    assert "M2_ENCODING_ARTEFACT" not in _codes(
        PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, [str(victim)])
    ), "an intact UTF-8 file was rejected"
    # The same file after a decode/re-encode round trip: the private-use characters are the signature.
    victim.write_bytes('HEADING = "# \u701b\u6e03\ue0c1\u6d2b"\n'.encode("utf-8"))
    assert "M2_ENCODING_ARTEFACT" in _codes(
        PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, [str(victim)])
    ), "a re-encoded file passed the edit check"


def test_m2_blocks_a_changed_file_that_cannot_be_decoded(tmp_path) -> None:
    victim = tmp_path / "binary.py"
    victim.write_bytes(b"x = '\xff\xfe\x00\x81'\n")
    artifact = _base_artifact(changed_files=[str(victim)], allowed_files=[str(victim)])
    assert "M2_NOT_UTF8" in _codes(PREFLIGHT.validate("P-0.3", STATUS, OWNERSHIP, artifact, [str(victim)]))


def test_m6_blocks_an_ownership_overlap() -> None:
    ownership = json.loads(json.dumps(OWNERSHIP))
    ownership["overlap"] = [{"file": "src/threat_report_agent/service.py", "claimed_by": ["root", "T1/T2"]}]
    ownership["overlap_verdict"] = "OVERLAP - P-0.2 MUST NOT RUN"
    violations = PREFLIGHT.validate("P-0.3", STATUS, ownership, _base_artifact(), ["scripts/ghidra-plan-preflight.py"])
    assert "OWNERSHIP_OVERLAP" in _codes(violations) and "OWNERSHIP_VERDICT" in _codes(violations)


def test_m6_blocks_a_file_locked_by_another_track() -> None:
    ownership = json.loads(json.dumps(OWNERSHIP))
    ownership["files"] = [{"file": "src/threat_report_agent/report/reporting.py",
                           "state": "LOCKED_BY_ACTIVE_TRACK:behavior_reporting"}]
    artifact = _base_artifact(allowed_files=["src/threat_report_agent/report/reporting.py"],
                              changed_files=["src/threat_report_agent/report/reporting.py"])
    assert "OWNERSHIP_LOCKED" in _codes(PREFLIGHT.validate("P-0.3", STATUS, ownership, artifact,
                                                           ["src/threat_report_agent/report/reporting.py"]))


def test_m6_blocks_a_scope_escape() -> None:
    artifact = _base_artifact(changed_files=["scripts/ghidra-plan-preflight.py",
                                             "src/threat_report_agent/service.py"])
    assert "SCOPE" in _codes(_validate(artifact))


def test_a_completed_step_can_always_be_re_validated() -> None:
    """MEASURED: after the status advanced to P-1.1, `--step P-0.4` reported STEP_NOT_ALLOWED, so already-accepted
    artifacts could not be re-checked. Re-reading evidence is not advancing the state."""
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = ["P-1.1"]
    status["steps"] = [{"step": "P-0.1", "decision": "complete"}, {"step": "P-0.2", "decision": "complete"},
                       {"step": "P-0.3", "decision": "complete"}, {"step": "P-0.4", "decision": "complete"}]
    assert "STEP_NOT_ALLOWED" not in _codes(PREFLIGHT.validate("P-0.4", status, OWNERSHIP,
                                                               _base_artifact(step="P-0.4"), []))


def test_a_phase_step_is_not_gated_by_the_per_sub_step_allow_list() -> None:
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = ["P-1.1"]
    status["steps"] = [{"step": sub, "decision": "complete"} for sub in PREFLIGHT.sub_steps_of("P-1")]
    assert "STEP_NOT_ALLOWED" not in _codes(PREFLIGHT.validate("P-1", status, OWNERSHIP,
                                                               _base_artifact(step="P-1"), []))


def test_a_phase_step_requires_every_sub_step_to_be_complete() -> None:
    """The plan's P-1.7 gate is literally `--step P-1`: naming a phase must not skip the sub-steps it contains."""
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    status["steps"] = [{"step": "P-1.1", "decision": "complete"}]
    violations = PREFLIGHT.validate("P-1", status, OWNERSHIP, _base_artifact(step="P-1"), [])
    codes = _codes(violations)
    assert "PHASE_INCOMPLETE" in codes
    assert "P-1.7" in " ".join(str(item) for item in violations), "the missing sub-steps must be named"


def test_a_phase_step_passes_once_every_sub_step_is_complete() -> None:
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    status["steps"] = [{"step": sub, "decision": "complete"} for sub in PREFLIGHT.sub_steps_of("P-1")]
    assert "PHASE_INCOMPLETE" not in _codes(PREFLIGHT.validate("P-1", status, OWNERSHIP,
                                                               _base_artifact(step="P-1"), []))


def test_an_unknown_step_name_is_still_rejected() -> None:
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    assert "STEP_UNKNOWN" in _codes(PREFLIGHT.validate("P-99", status, OWNERSHIP, _base_artifact(step="P-99"), []))


def test_a_phase_may_only_be_recorded_complete_when_the_gate_is_matched() -> None:
    """P-1.7's own words: with the deployment gate blocked the state is `P-1_COMPLETE_DEPLOYMENT_BLOCKED`.

    The state machine - not a sentence in a report - has to make 'locally green' impossible to read as 'deployed'.
    """
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    status["steps"] = [{"step": sub, "decision": "complete"} for sub in PREFLIGHT.sub_steps_of("P-1")]
    status["deployment"] = {"gate_state": "BLOCKED"}
    complete = _base_artifact(step="P-1", decision="complete")
    assert "PHASE_DEPLOYMENT_OVERCLAIM" in _codes(PREFLIGHT.validate("P-1", status, OWNERSHIP, complete, []))
    named = _base_artifact(step="P-1", decision="P-1_COMPLETE_DEPLOYMENT_BLOCKED")
    assert list(PREFLIGHT.validate("P-1", status, OWNERSHIP, named, [])) == [], (
        "the plan's own name for this state must be accepted"
    )


def test_a_matched_gate_requires_the_phase_to_be_recorded_complete() -> None:
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    status["steps"] = [{"step": sub, "decision": "complete"} for sub in PREFLIGHT.sub_steps_of("P-1")]
    status["deployment"] = {"gate_state": "MATCHED_TO_HEAD"}
    blocked = _base_artifact(step="P-1", decision="P-1_COMPLETE_DEPLOYMENT_BLOCKED")
    violations = PREFLIGHT.validate("P-1", status, OWNERSHIP, blocked, [])
    assert "PHASE_DECISION" in _codes(violations)


def test_a_status_that_claims_a_phase_complete_on_a_blocked_gate_is_rejected() -> None:
    status = json.loads(json.dumps(STATUS))
    status["allowed_steps"] = None
    status["deployment"] = {"gate_state": "BLOCKED"}
    status["steps"] = [*status["steps"], {"step": "P-1", "decision": "complete"}]
    assert "PHASE_OVERCLAIM" in _codes(PREFLIGHT.validate("P-1.7", status, OWNERSHIP,
                                                          _base_artifact(step="P-1.7"), []))


def test_m6_blocks_a_step_whose_dependency_is_not_complete() -> None:
    status = json.loads(json.dumps(STATUS))
    status["steps"] = []
    violations = PREFLIGHT.validate("P-0.3", status, OWNERSHIP, _base_artifact(), [])
    assert "STEP_DEPENDENCY" in _codes(violations)


def test_m6_blocks_a_deployment_dependent_step_while_the_gate_is_blocked() -> None:
    status = json.loads(json.dumps(STATUS))
    status["steps"] = [{"step": step, "decision": "complete"} for step in PREFLIGHT.STEPS
                       if PREFLIGHT.STEPS.index(step) < PREFLIGHT.STEPS.index("T1")]
    violations = PREFLIGHT.validate("T1", status, OWNERSHIP, _base_artifact(step="T1"), [])
    assert "DEPLOYMENT_NOT_MATCHED" in _codes(violations), (
        "a local pytest run must never be able to stand in for the deployment gate"
    )


def test_mechanism_coverage_requires_a_named_test_that_exists() -> None:
    artifact = _base_artifact(mechanisms_exercised=["M1", "M2", "M3", "M5", "M6"],
                              mechanism_unit_tests={"M4": "tests/test_ghidra_plan_preflight.py::"
                                                         "a_test_that_does_not_exist"})
    assert "MECHANISM_TEST_ABSENT" in _codes(_validate(artifact))


def test_mechanism_coverage_blocks_a_silently_skipped_mechanism() -> None:
    artifact = _base_artifact(mechanisms_exercised=["M1", "M2", "M3", "M5", "M6"], mechanism_unit_tests={})
    assert "MECHANISM_UNCOVERED" in _codes(_validate(artifact))


def test_the_scope_escape_tamper_picks_a_path_the_step_does_not_own() -> None:
    """MEASURED (P-1.1): the tamper appended `service.py` unconditionally, which is ALLOWED for a step that owns the
    service, so it produced no violation and the self-test recorded a control that did not fail while its evidence
    claimed a rejection. The tamper must escape by a path the artifact does not allow."""
    artifact = _base_artifact(allowed_files=["scripts/ghidra-plan-preflight.py",
                                             "src/threat_report_agent/service.py"],
                              changed_files=["scripts/ghidra-plan-preflight.py",
                                             "src/threat_report_agent/service.py"])
    PREFLIGHT._tamper("scope_escape", {}, {}, artifact)
    escaped = [item for item in artifact["changed_files"] if item not in artifact["allowed_files"]]
    assert escaped, "the tamper did not actually escape `allowed_files`"
    assert "SCOPE" in _codes(PREFLIGHT.validate("P-1.1", STATUS, OWNERSHIP, artifact,
                                                artifact["changed_files"]))


def test_the_scope_escape_tamper_declares_itself_inapplicable_when_nothing_can_escape() -> None:
    artifact = _base_artifact(allowed_files=[*PREFLIGHT._scope_escape_candidates()],
                              changed_files=["scripts/ghidra-plan-preflight.py"])
    with pytest.raises(PREFLIGHT.NotApplicable):
        PREFLIGHT._tamper("scope_escape", {}, {}, artifact)


def test_an_empty_self_review_is_rejected() -> None:
    """MEASURED (P-1.2): the artifact carried `"skill_audit": {}` and the gate accepted it, because only the KEY's
    presence was checked. A present-but-empty self-review reads as evidence and carries none - the same family of hole
    as a tamper that breaks nothing."""
    assert "SKILL_AUDIT_SHAPE" in _codes(_validate(_base_artifact(skill_audit=[])))
    assert "SKILL_AUDIT_SKILL" in _codes(_validate(_base_artifact(skill_audit={"skill": "pending", "findings": []})))
    assert "SKILL_AUDIT_EMPTY" in _codes(_validate(_base_artifact(
        skill_audit={"skill": "analysis-verification", "findings": []})))
    explained = _base_artifact(skill_audit={"skill": "analysis-verification", "findings": [],
                                            "why_no_findings": "every claim survived the attacks, listed in `commands`"})
    assert "SKILL_AUDIT_EMPTY" not in _codes(_validate(explained))
    vague = _base_artifact(skill_audit={"skill": "analysis-verification",
                                        "findings": [{"id": "F", "severity": "LOW", "finding": "no status"}]})
    assert "SKILL_AUDIT_FINDING" in _codes(_validate(vague))


def test_a_new_failure_node_outside_every_baseline_is_a_regression() -> None:
    """P-1.7: "全量失败节点集合不得新增" - compared as a SET, which is why a count can never satisfy it."""
    status = json.loads(json.dumps(STATUS))
    status["baseline_failure_nodes"] = ["tests/test_a.py::test_one"]
    status["baseline_failure_nodes_original_p0_2"] = ["tests/test_a.py::test_one", "tests/test_b.py::test_two"]
    artifact = _base_artifact(full_failure_nodes_after=["tests/test_a.py::test_one", "tests/test_b.py::test_two"])
    assert "REGRESSION_NEW_FAILURES" not in _codes(PREFLIGHT.validate("P-0.3", status, OWNERSHIP, artifact, []))
    artifact["full_failure_nodes_after"] = ["tests/test_c.py::test_three"]
    violations = PREFLIGHT.validate("P-0.3", status, OWNERSHIP, artifact, [])
    assert "REGRESSION_NEW_FAILURES" in _codes(violations)


def test_a_focused_run_that_gains_a_failure_is_rejected() -> None:
    artifact = _base_artifact(focused_failure_nodes_before=["tests/test_a.py::test_one"],
                              focused_failure_nodes_after=["tests/test_a.py::test_one", "tests/test_b.py::test_two"])
    assert "FOCUSED_NEW_FAILURES" in _codes(_validate(artifact))


def test_an_artifact_that_disagrees_with_its_own_capture_is_rejected() -> None:
    """The artifact must report the set of the file it points at, otherwise the capture proves nothing."""
    completed = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests/test_ghidra_plan_preflight.py",
                                "-k", "no_such_test_exists", "-p", "no:randomly"], cwd=ROOT, capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
    capture = ROOT / ".scratch" / "ghidra-c3" / "preflight" / "selftest-capture-control.txt"
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_text(completed.stdout, encoding="utf-8")
    clean = _base_artifact(full_suite_capture=".scratch/ghidra-c3/preflight/selftest-capture-control.txt",
                           full_failure_nodes_after=[])
    assert "CAPTURE_MISMATCH" not in _codes(_validate(clean)), "an empty capture and an empty claim agree"
    lying = _base_artifact(full_suite_capture=".scratch/ghidra-c3/preflight/selftest-capture-control.txt",
                           full_failure_nodes_after=["tests/test_a.py::test_one"])
    assert "CAPTURE_MISMATCH" in _codes(_validate(lying))
    missing = _base_artifact(full_suite_capture=".scratch/ghidra-c3/preflight/does-not-exist.txt")
    assert "CAPTURE_MISSING" in _codes(_validate(missing))


def test_a_content_hash_may_match_its_source_at_a_named_commit() -> None:
    """MEASURED: P-0.3 hashed the preflight script itself, so every later edit broke a strict re-check of an ALREADY
    ACCEPTED step. A historical match is accepted only when the record NAMES the commit; without the name it stays a
    violation, so "the file moved on" is never a blanket excuse."""
    import hashlib
    import subprocess as sp

    source = "scripts/ghidra-plan-preflight.py"
    old_commit = sp.run(["git", "rev-parse", "b5e0c66795a2"], cwd=ROOT, capture_output=True, text=True,
                        check=True).stdout.strip()
    blob = sp.run(["git", "show", f"{old_commit}:{source}"], cwd=ROOT, capture_output=True).stdout
    old_digest = hashlib.sha256(blob).hexdigest()
    record = {"task_id": "t", "revision_id": "r", "content_sha256": old_digest, "started_at": "t0",
              "finished_at": "t1", "sql_text": "SELECT 1", "connection": "sqlite3 probe",
              "schema_query": "SELECT name FROM sqlite_master", "content_source": source,
              "exit_code": 0, "rows": [["row"]]}
    status = json.loads(json.dumps(STATUS))
    unnamed = _base_artifact(claims_runtime_fact=True, task_revision_content_records=[dict(record)],
                             wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1})
    assert "M3_CONTENT_MISMATCH" in _codes(PREFLIGHT.validate("P-0.3", status, OWNERSHIP, unnamed, []))
    named = _base_artifact(claims_runtime_fact=True,
                           task_revision_content_records=[dict(record, content_source_at_commit=old_commit)],
                           wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1})
    assert "M3_CONTENT_MISMATCH" not in _codes(PREFLIGHT.validate("P-0.3", status, OWNERSHIP, named, []))


def test_the_self_test_refuses_and_returns_non_zero_for_an_invalid_base() -> None:
    """MEASURED (round 167): the tamper loop ran unconditionally, so on an invalid artifact every tamper "failed" for a
    reason unrelated to the tamper - and the plan's own `--step P-1 --self-test` would have reported 13 rejections while
    proving nothing. A self-test whose base case is broken measures nothing.

    MEASURED (P-2.1, once the deployment gate became MATCHED_TO_HEAD): this fixture used to take its invalidity from
    the AMBIENT status file - `step="P-1"` with `decision="complete"` is a `PHASE_DEPLOYMENT_OVERCLAIM` only while the
    gate is blocked. `run_self_test` loads the real status file from disk, so as soon as the gate reported
    MATCHED_TO_HEAD the "invalid" base validated, the tamper loop ran for real and this node failed with
    `assert 0 == 1`. An invalid base must be invalid for a reason NO file on disk can remove: a required field is
    absent, which `_check_artifact_fields` reports in every state of the plan. The state-dependent rule keeps its own
    tests (`test_a_phase_may_only_be_recorded_complete_when_the_gate_is_matched` and its two companions).
    """
    invalid = _base_artifact(step="P-1", decision="complete")  # 'complete' is not allowed for a phase on a blocked gate
    invalid.pop("skill_audit")
    with tempfile.TemporaryDirectory(prefix="selftest-refusal-") as raw:
        capture = pathlib.Path(raw) / "results.json"
        code = PREFLIGHT.run_self_test("P-1", invalid, capture)
        assert code == 1, "an invalid base artifact must make the self-test refuse"
        payload = json.loads(capture.read_text(encoding="utf-8"))
        assert payload["verdict"] == "BASE_ARTIFACT_INVALID" and payload["violations"]


@pytest.mark.parametrize("tamper", [name for name, _ in PREFLIGHT.TAMPERS])
def test_every_declared_tamper_actually_does_something(tamper: str) -> None:
    """A tamper listed in `TAMPERS` that neither mutates nor declares itself inapplicable is a fake rejection.

    `_tamper` raises `SystemExit` for an unknown name, so a typo cannot pass; a tamper whose precondition is absent must
    say so with `NotApplicable` (and then `_check_mechanism_coverage` forces a unit test to cover the mechanism); every
    other tamper MUST change the inputs it was given.
    """
    status, ownership = {"x": 1}, {"y": 2}
    artifact = _base_artifact(claims_runtime_fact=True, publishes_collection=True, introduces_symbol=True,
                              task_revision_content_records=[{"task_id": "t"}],
                              wrong_sample_or_revision_control={"name": "wrong_revision", "exit_code": 1},
                              set_differences=[{"name": "s", "identity_key": "k", "expected_minus_actual": []}],
                              producer_consumer_render_proof=[{"symbol": "s"}],
                              negative_controls=[{"name": "wrong_revision_returns_no_row", "exit_code": 1,
                                                  "evidence": "0 rows"}])
    before = json.dumps([status, ownership, artifact], sort_keys=True)
    try:
        PREFLIGHT._tamper(tamper, status, ownership, artifact)
    except PREFLIGHT.NotApplicable:
        return
    after = json.dumps([status, ownership, artifact], sort_keys=True)
    assert before != after, f"tamper {tamper} neither mutated anything nor declared itself inapplicable"
