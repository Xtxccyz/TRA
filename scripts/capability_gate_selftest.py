"""Self-test for `capability-acceptance-gate.py`: the plan's §4.4 fakes must all be REJECTED.

WHY A SEPARATE MODULE. A gate that rejects everything is as useless as one that accepts everything, so the self-test has
two halves: the six fakes of plan §4.4 must each be rejected WITH the expected violation code (not merely non-zero), and
an honest card for the current tree must be admitted. The honest card is `PARTIAL` on purpose - the Docker daemon is
unavailable, so no deployment claim can be accepted today (plan §8), and a gate that demanded ACCEPTED here would be
demanding something the plan forbids.

    py scripts/capability-acceptance-gate.py --self-test
"""
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys


def _head() -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _manifest(root: pathlib.Path) -> str:
    done = subprocess.run([sys.executable, str(root / ".scratch" / "ghidra-worktree-manifest.py")],
                          capture_output=True, text=True)
    import re
    match = re.search(r"worktree_manifest_sha\s+([0-9a-f]{64})", done.stdout)
    return match.group(1) if match else ""


def honest_card(root: pathlib.Path) -> dict:
    """A card for THIS tree that must be admissible: PARTIAL, honestly limited, every citation real."""
    control_script = root / ".scratch" / "capability-evidence" / "selftest" / "always_exit_3.py"
    control_script.parent.mkdir(parents=True, exist_ok=True)
    if not control_script.is_file():
        control_script.write_text(
            '"""Self-test control: a command that really fails, used to prove the gate re-runs controls."""\n'
            "import sys\n\nsys.stderr.write('self-test control: this command exists to fail\\n')\nraise SystemExit(3)\n",
            encoding="utf-8", newline="\n")
    return {
        "capability_id": "SELFTEST-honest-partial",
        "requirement_ids": ["B00"],
        "source_sha": _head(),
        "worktree_manifest_sha": _manifest(root),
        "allowed_files": [],
        "changed_files": [],
        "producer": ["scripts/capability-acceptance-gate.py"],
        "consumer": ["scripts/capability-acceptance-gate.py"],
        "official_renderer": "src/threat_report_agent/report/analyst_report.py::render_official_markdown",
        "task_revision_content_records": [{
            "task_id": "selftest-task",
            "revision_id": "selftest-revision",
            "content_sha256": "0" * 64,
            "started_at": "2026-01-01 00:00:00.000000",
            "finished_at": "2026-01-01 00:00:01.000000",
            "wrong_row_control": {"what": "the same statement against an absent task returns zero rows",
                                  "absent_task_rows": []},
        }],
        "object_dumps": [{
            "name": "the self-test card itself",
            "type": "dict",
            "field_values": {"capability_id": {"repr": "'SELFTEST-honest-partial'", "source": "mapping"}},
        }],
        "set_differences": [{
            "name": "selftest_a_minus_b",
            "identity_key": "the fixture's own identity",
            "enumerated_set": ["alpha", "beta"],
            "retrieved_set": ["beta", "gamma"],
            "expected_minus_actual": ["alpha"],
            "actual_minus_expected": ["gamma"],
        }],
        "negative_controls": [{
            "name": "the_selftest_control_must_fail",
            "command": f"py {control_script.relative_to(root).as_posix()}",
            "exit_code": 3,
            "evidence": "self-test control: this command exists to fail (exit 3)",
            "restore_is_byte_identical": True,
        }],
        "deployment_evidence": {
            "docker_available": False,
            "three_way": {},
            "why_not": "the Docker daemon is unavailable, so no three-way manifest can be measured (plan §8)",
        },
        "known_limitations": [
            "no deployment proof while the Docker daemon is unavailable",
            "this card exists to prove the gate is not reject-everything",
        ],
        "blocks_current_step": False,
        "status": "PARTIAL",
        "next_action": "restore the Docker daemon and re-measure the deployment gate",
        "commands": [{"command": "py scripts/capability-acceptance-gate.py --self-test", "exit_code": 1}],
    }


def fakes(root: pathlib.Path, honest: dict) -> list[tuple[str, dict, list[str]]]:
    """§4.4's six fakes, each with the violation code its rejection must cite."""
    rows: list[tuple[str, dict, list[str]]] = []

    t3_path = root / ".scratch" / "ghidra-c3" / "preflight" / "T3-artifact.json"
    rows.append(("1_the_current_T3_artifact_as_is", json.loads(t3_path.read_text(encoding="utf-8")),
                 ["CARD_SHAPE"]))

    unverified = copy.deepcopy(honest)
    unverified["status"] = "UNVERIFIED"
    rows.append(("2_decision_complete_with_capability_UNVERIFIED", unverified, ["STATUS_ENUM"]))

    no_consumer = copy.deepcopy(honest)
    no_consumer["status"] = "ACCEPTED"
    no_consumer["consumer"] = []
    no_consumer["known_limitations"] = ["a HIGH finding recorded as RECORDED with no consumer"]
    rows.append(("3_RECORDED_HIGH_finding_without_a_consumer", no_consumer,
                 ["ACCEPTED_WITH_NON_FINAL_TOKEN", "THREE_HOPS_MISSING"]))

    no_control = copy.deepcopy(honest)
    no_control["negative_controls"] = []
    rows.append(("4_official_Markdown_negative_control_removed", no_control, ["NO_NEGATIVE_CONTROL"]))

    stale = copy.deepcopy(honest)
    stale["source_sha"] = "0" * 40
    rows.append(("5_old_source_sha", stale, ["SOURCE_SHA_NOT_HEAD"]))

    zero_control = copy.deepcopy(honest)
    zero_control["negative_controls"] = [dict(honest["negative_controls"][0], exit_code=0)]
    rows.append(("6_negative_control_exit_code_zero", zero_control, ["CONTROL_DID_NOT_FAIL"]))
    return rows


def run_self_test(check_card, root: pathlib.Path) -> int:
    honest = honest_card(root)
    problems: list[str] = []

    admitted = check_card(honest, replay_controls=True)
    if admitted.rows:
        problems.append(f"the honest PARTIAL card was REJECTED: {admitted.codes()}")
        for row in admitted.rows:
            print(f"       unexpected {row['code']}: {row['detail']}")
    else:
        print("OK   the honest PARTIAL card is admissible (the gate is not reject-everything)")

    for name, card, expected_codes in fakes(root, honest):
        violations = check_card(card, replay_controls=False)
        codes = violations.codes()
        if not violations.rows:
            problems.append(f"fake {name} was ACCEPTED (expected rejection citing {expected_codes})")
            print(f"FAIL fake {name}: accepted - the gate cannot reject it")
            continue
        missing = [code for code in expected_codes if code not in codes]
        if missing:
            problems.append(f"fake {name} was rejected but not for {missing} (codes: {sorted(set(codes))})")
            print(f"FAIL fake {name}: rejected with {sorted(set(codes))}, missing {missing}")
        else:
            print(f"OK   fake {name}: rejected with {expected_codes}")

    print()
    if problems:
        print(f"SELF-TEST: FAIL ({len(problems)} problem(s))")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("SELF-TEST: PASS - six fakes rejected, honest card admitted")
    return 0
