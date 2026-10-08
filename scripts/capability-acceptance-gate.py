"""Capability acceptance gate (plan §4): the independent blocker for capability cards.

WHY THIS EXISTS. The plan's §4.1 replaces "a step record says complete" with an independent gate: capability status may
only be `ACCEPTED / PARTIAL / BLOCKED`, and `ACCEPTED` has to survive recomputation. The old
`scripts/ghidra-plan-preflight.py` stays for historical review of the Ghidra/C3 plan but is no longer the authority on
whether a CAPABILITY is finished.

WHAT IT REFUSES (plan §4.3, one violation code each):
  * a status outside `ACCEPTED/PARTIAL/BLOCKED` (§1.2: `OPEN/RECORDED/NOT_MEASURED/UNVERIFIED/NEEDS_REVIEW/STALE/`
    `NOT_PROVEN` are reasons, never completion states);
  * `ACCEPTED` while a limitation, control or finding still carries one of those tokens, or while `blocks_current_step`;
  * `ACCEPTED` without the three hops (producer -> consumer -> official renderer), each naming a file that exists;
  * evidence that never reached the official Markdown through the SAME Report Revision the other exits use;
  * a negative control that did not actually fail (exit 0, or a command that is not re-runnable);
  * `source_sha` that is not the current HEAD, or a worktree manifest that is not this tree's (G-14: the value is the
    manifest tool's own header, never the manifest file's digest);
  * changed files outside `allowed_files`, or absent from the ownership lock, or an ownership overlap;
  * deployment evidence that only proves the worktree (a three-way comparison against the current HEAD is required);
  * run assertions without task/revision/content hash and DB times;
  * a set published as a count, without an identity key, or whose recorded differences do not recompute from the sets
    it publishes (G-12);
  * any file the card cites that is not on disk (G-1);
  * a status the gate cannot recompute at all (`SELF_ATTESTED_STATUS`).

    py scripts/capability-acceptance-gate.py --card .scratch/capability-cards/B00-contract.json
    py scripts/capability-acceptance-gate.py --card-dir .scratch/capability-cards
    py scripts/capability-acceptance-gate.py --self-test          # the plan's §4.4 fakes must all be rejected

Exit codes: 0 = every card checked is admissible; 1 = at least one violation; 2 = the gate itself could not run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

ROOT = pathlib.Path(__file__).resolve().parents[1]
CARDS = ROOT / ".scratch" / "capability-cards"
EVIDENCE = ROOT / ".scratch" / "capability-evidence"
OWNERSHIP = ROOT / ".scratch" / "ghidra-c3-ownership.json"
CAPABILITY_OWNERSHIP = ROOT / ".scratch" / "capability-ownership.json"
MANIFEST_TOOL = ROOT / ".scratch" / "ghidra-worktree-manifest.py"
STATUS = ROOT / ".scratch" / "ghidra-c3-execution-status.json"

FINAL_STATUSES = ("ACCEPTED", "PARTIAL", "BLOCKED")
NON_FINAL_TOKENS = ("OPEN", "RECORDED", "NOT_MEASURED", "UNVERIFIED", "NEEDS_REVIEW", "NOT_PROVEN")
REQUIRED_FIELDS = (
    "capability_id", "requirement_ids", "source_sha", "worktree_manifest_sha", "allowed_files", "changed_files",
    "producer", "consumer", "official_renderer", "task_revision_content_records", "object_dumps", "set_differences",
    "negative_controls", "deployment_evidence", "known_limitations", "blocks_current_step", "status", "next_action",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Violations:
    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def add(self, code: str, detail: str) -> None:
        self.rows.append({"code": code, "detail": detail})

    def codes(self) -> list[str]:
        return [row["code"] for row in self.rows]


def run(command: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, errors="replace", check=False,
                          timeout=timeout)


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True, errors="replace")
    return done.stdout.strip()


def current_head() -> str:
    return git("rev-parse", "HEAD")


def measured_manifest() -> str:
    """The manifest tool's own header digest for THIS tree (never the file's digest - G-14)."""
    done = run([sys.executable, str(MANIFEST_TOOL)])
    match = re.search(r"worktree_manifest_sha\s+([0-9a-f]{64})", done.stdout)
    return match.group(1) if match else ""


def load_ownership() -> dict:
    if not OWNERSHIP.is_file():
        return {}
    return json.loads(OWNERSHIP.read_text(encoding="utf-8"))


def check_shape(violations: Violations, card: dict) -> None:
    missing = [field for field in REQUIRED_FIELDS if field not in card]
    if missing:
        violations.add("CARD_SHAPE", f"card is missing required field(s): {missing}")
    status = str(card.get("status") or "")
    if status not in FINAL_STATUSES:
        violations.add("STATUS_ENUM",
                       f"status {status!r} is not one of {list(FINAL_STATUSES)} (plan §1.2: OPEN/RECORDED/"
                       f"NOT_MEASURED/UNVERIFIED/NEEDS_REVIEW/STALE/NOT_PROVEN are reasons, not completion states)")
    if not str(card.get("next_action") or "").strip():
        violations.add("NEXT_ACTION_MISSING", "every card must carry `next_action`, including an ACCEPTED one")


def check_identity(violations: Violations, card: dict) -> None:
    declared = str(card.get("source_sha") or "")
    head = current_head()
    if declared != head:
        violations.add("SOURCE_SHA_NOT_HEAD", f"source_sha {declared[:12] or '(empty)'} != HEAD {head[:12]}")
    manifest = str(card.get("worktree_manifest_sha") or "")
    measured = measured_manifest()
    if not measured:
        violations.add("MANIFEST_UNMEASURABLE", "the worktree manifest could not be measured")
    elif manifest != measured:
        violations.add("MANIFEST_MISMATCH",
                       f"worktree_manifest_sha {manifest[:16] or '(empty)'} != this tree's {measured[:16]}")


def check_scope(violations: Violations, card: dict) -> None:
    changed = [str(item) for item in card.get("changed_files") or []]
    allowed = [str(item) for item in card.get("allowed_files") or []]
    outside = [item for item in changed if item not in allowed]
    if outside:
        violations.add("SCOPE_ESCAPE", f"changed files outside allowed_files: {outside}")
    # TWO LOCKS, ON PURPOSE. The Ghidra/C3 plan's lock is the artifact of its own P-0.1 step; rewriting it to admit
    # capability-plan files would silently move an accepted step's artifact. The capability plan therefore keeps its own
    # lock and a file is admissible when EITHER lock lists it - but a file listed in neither is unlisted, a file whose
    # state is an active lock is refused, and a file claimed by two DIFFERENT owners across the locks is an overlap.
    tables: list[tuple[str, dict]] = []
    for label, path in (("capability", CAPABILITY_OWNERSHIP), ("ghidra-c3", OWNERSHIP)):
        if path.is_file():
            document = json.loads(path.read_text(encoding="utf-8"))
            tables.append((label, document))
            if document.get("overlap"):
                violations.add("OWNERSHIP_OVERLAP", f"the {label} lock reports overlap: {document['overlap']}")
            if str(document.get("overlap_verdict") or "").upper() not in ("", "NO OVERLAP"):
                violations.add("OWNERSHIP_VERDICT", f"the {label} lock verdict is {document.get('overlap_verdict')!r}")
    if not tables:
        violations.add("OWNERSHIP_MISSING", "no ownership lock found at all")
        return
    # Which lock closes which file, and whether ANY lock reports an active hold on it. MEASURED while writing the first
    # version: reporting the state of every row in every lock produced four OWNERSHIP_GATE findings for files the card
    # never touched (the old lock marks its four tracked gates that way), and treating a file listed in BOTH locks as a
    # conflict produced two more - but a capability-plan row for a file the old plan also lists is a hand-off, not
    # contention. So: the capability lock closes a file, an active hold in either lock refuses it, and a genuine
    # conflict is the capability lock claiming one path twice under different owners.
    holds: dict[str, list[str]] = {}
    capability_rows: dict[str, list[str]] = {}
    for label, document in tables:
        for item in document.get("files") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("file") or "")
            if not name:
                continue
            owner = str(item.get("owner") or "")
            state = str(item.get("state") or "")
            if state.startswith(("LOCKED_BY_ACTIVE_TRACK", "OWNED_BY_STRUCTURE_PLAN")):
                holds.setdefault(name, []).append(f"{label}:{state}")
            if label == "capability":
                capability_rows.setdefault(name, []).append(owner)
    for name, owners in capability_rows.items():
        if len(set(owners)) > 1:
            violations.add("OWNERSHIP_CONFLICT", f"{name} is claimed twice in the capability lock by {sorted(set(owners))}")
    for path in changed:
        if holds.get(path):
            violations.add("OWNERSHIP_HELD", f"{path} is held by {holds[path]}")
        if path not in capability_rows and path not in {item for item in holds}:
            # A file the capability lock does not list and no lock holds is unlisted for capability work.
            listed_anywhere = any(path in {str(row.get("file")) for row in (document.get("files") or [])
                                           if isinstance(row, dict)}
                                  for _, document in tables)
            if not listed_anywhere:
                violations.add("OWNERSHIP_UNLISTED", f"{path} is in no ownership lock; it cannot be taken silently")


def check_accepted_requires(violations: Violations, card: dict) -> None:
    if str(card.get("status") or "") != "ACCEPTED":
        return
    limitations = card.get("known_limitations")
    if not isinstance(limitations, list):
        violations.add("LIMITATIONS_SHAPE", "known_limitations must be a list")
    else:
        text = json.dumps(limitations, ensure_ascii=False).upper()
        bad = [token for token in NON_FINAL_TOKENS if token in text]
        if bad:
            violations.add("ACCEPTED_WITH_NON_FINAL_TOKEN",
                           f"ACCEPTED with non-final token(s) in known_limitations: {bad}")
    if card.get("blocks_current_step"):
        violations.add("ACCEPTED_BLOCKS_STEP", "ACCEPTED while blocks_current_step is true")
    # The three hops: producer -> consumer -> official renderer, each naming something on disk.
    missing = [field for field in ("producer", "consumer", "official_renderer")
               if not card.get(field)]
    if missing:
        violations.add("THREE_HOPS_MISSING", f"ACCEPTED without {missing}")
    renderer = str(card.get("official_renderer") or "")
    if renderer and not (ROOT / renderer).exists() and "::" not in renderer:
        violations.add("RENDERER_NOT_ON_DISK", f"official_renderer {renderer!r} names nothing on disk")


def check_render_same_revision(violations: Violations, card: dict) -> None:
    if str(card.get("status") or "") != "ACCEPTED":
        return
    proof = card.get("producer_consumer_render_proof")
    if not isinstance(proof, list) or not proof:
        violations.add("NO_RENDER_PROOF", "ACCEPTED without a producer_consumer_render_proof list")
        return
    for index, row in enumerate(proof):
        if not isinstance(row, dict):
            violations.add("RENDER_PROOF_SHAPE", f"render proof [{index}] is not an object")
            continue
        revision = str(row.get("revision_id") or "")
        content = str(row.get("content_sha256") or "")
        rendered = str(row.get("rendered_markdown") or "")
        if not revision or not content:
            violations.add("RENDER_PROOF_UNBOUND",
                           f"render proof [{index}] has no revision_id/content_sha256")
        if rendered and not (ROOT / rendered).is_file():
            violations.add("RENDER_PROOF_FILE_MISSING", f"render proof [{index}] cites {rendered} which is not on disk")
        exits = row.get("same_revision_exits")
        if isinstance(exits, dict) and exits:
            distinct = {str(value) for value in exits.values()}
            if len(distinct) > 1:
                violations.add("REVISION_DIVERGENCE",
                               f"render proof [{index}] shows different revisions across exits: {exits}")


def check_negative_controls(violations: Violations, card: dict, *, replay: bool) -> None:
    controls = card.get("negative_controls")
    if not isinstance(controls, list) or not controls:
        violations.add("NO_NEGATIVE_CONTROL", "a card without a real failing negative control cannot be admissible")
        return
    for index, control in enumerate(controls):
        if not isinstance(control, dict):
            violations.add("CONTROL_SHAPE", f"negative_controls[{index}] is not an object")
            continue
        name = str(control.get("name") or f"[{index}]")
        command = str(control.get("command") or "")
        if not command:
            violations.add("CONTROL_NOT_RERUNNABLE", f"{name}: no command to re-run")
            continue
        if control.get("harness_mediated"):
            # A HARNESS-MEDIATED control is one whose command applies the tamper, runs the target test, requires it to
            # fail and restores the bytes - so the harness itself exits 0 when the control behaved. Its `exit_code` is
            # the TARGET TEST's exit under the tamper. MEASURED while writing the B00-contract card: treating that as
            # the command's exit reported CONTROL_REPLAY_EXIT_DIFFERS for a control that is stronger than a bare
            # command, since the harness also proves the restore and fails itself when the target test passes.
            target = control.get("exit_code")
            if not isinstance(target, int) or target == 0:
                violations.add("CONTROL_DID_NOT_FAIL", f"{name}: target exit_code={target!r} is not a real non-zero exit")
            markers = [str(marker) for marker in control.get("expect_output") or []]
            if not markers:
                violations.add("CONTROL_NO_EXPECTATION",
                               f"{name}: a harness-mediated control must name `expect_output` markers")
            if replay:
                done = run(command.split(), timeout=1800)
                output = f"{done.stdout}\n{done.stderr}"
                if done.returncode != 0:
                    violations.add("CONTROL_HARNESS_FAILED",
                                   f"{name}: the harness exits {done.returncode}, so the control did not hold")
                missing = [marker for marker in markers if marker not in output]
                if missing:
                    violations.add("CONTROL_EXPECTATION_MISSING",
                                   f"{name}: the harness output does not show {missing}")
            continue
        code = control.get("exit_code")
        if not isinstance(code, int) or code == 0:
            violations.add("CONTROL_DID_NOT_FAIL", f"{name}: exit_code={code!r} is not a real non-zero exit")
        if replay:
            done = run(command.split(), timeout=900) if not command.startswith("py ") else run(
                [sys.executable, *command.split()[1:]], timeout=900)
            if done.returncode == 0:
                violations.add("CONTROL_REPLAY_PASSED", f"{name}: the re-run exited 0, so it fails nothing")
            elif isinstance(code, int) and done.returncode != code:
                violations.add("CONTROL_REPLAY_EXIT_DIFFERS",
                               f"{name}: recorded {code} but the re-run exits {done.returncode}")


def check_sets(violations: Violations, card: dict) -> None:
    blocks = card.get("set_differences")
    if not isinstance(blocks, list):
        violations.add("SET_SHAPE", "set_differences must be a list")
        return
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            violations.add("SET_SHAPE", f"set_differences[{index}] is not an object")
            continue
        name = str(block.get("name") or f"[{index}]")
        if block.get("count_only") or ("count" in block and "enumerated_set" not in block):
            violations.add("SET_COUNT_ONLY", f"{name}: publishes a count instead of a set")
        for field in ("identity_key", "enumerated_set", "retrieved_set", "expected_minus_actual",
                      "actual_minus_expected"):
            if field not in block:
                violations.add("SET_FIELD_MISSING", f"{name}: no {field}")
        enumerated = block.get("enumerated_set")
        retrieved = block.get("retrieved_set")
        if isinstance(enumerated, list) and isinstance(retrieved, list):
            recomputed_minus = sorted({repr(item) for item in enumerated} - {repr(item) for item in retrieved})
            recomputed_plus = sorted({repr(item) for item in retrieved} - {repr(item) for item in enumerated})
            for field, recomputed in (("expected_minus_actual", recomputed_minus),
                                      ("actual_minus_expected", recomputed_plus)):
                recorded = block.get(field)
                if isinstance(recorded, list):
                    if sorted({repr(item) for item in recorded}) != recomputed:
                        violations.add("SET_DIFF_MISMATCH",
                                       f"{name}: {field} != recomputed {recomputed}")


def check_run_binding(violations: Violations, card: dict) -> None:
    records = card.get("task_revision_content_records")
    # A card that makes NO run-level assertion (a contract card: its claims are equalities between source-level
    # contracts) cannot carry a task/revision/content binding, and demanding one would invite a fabricated DB row.
    # §4.3's rule is about RUN ASSERTIONS, so the exemption must be declared explicitly and explained; silence still
    # requires the binding.
    if card.get("makes_run_assertions") is False:
        if not str(card.get("no_run_assertion_reason") or "").strip():
            violations.add("NO_RUN_ASSERTION_UNEXPLAINED",
                           "makes_run_assertions is false without `no_run_assertion_reason`")
        return
    if not isinstance(records, list) or not records:
        violations.add("NO_DB_BINDING", "no task_revision_content_records: assertions without a DB binding")
        return
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            violations.add("DB_BINDING_SHAPE", f"task_revision_content_records[{index}] is not an object")
            continue
        missing = [field for field in ("task_id", "revision_id", "content_sha256", "started_at", "finished_at")
                   if not str(record.get(field) or "").strip()]
        if missing:
            violations.add("DB_BINDING_INCOMPLETE",
                           f"task_revision_content_records[{index}] is missing {missing}")
        if not record.get("wrong_row_control"):
            violations.add("NO_WRONG_ROW_CONTROL",
                           f"task_revision_content_records[{index}] has no wrong-row/wrong-content control")


def check_object_dumps(violations: Violations, card: dict) -> None:
    dumps = card.get("object_dumps")
    if not isinstance(dumps, list) or not dumps:
        violations.add("NO_OBJECT_DUMP", "no object_dumps: a template is not a dump")
        return
    for index, dump in enumerate(dumps):
        if not isinstance(dump, dict):
            violations.add("OBJECT_DUMP_SHAPE", f"object_dumps[{index}] is not an object")
            continue
        has_value = bool(dump.get("field_values")) or dump.get("value") not in (None, "", [], {})
        if not has_value:
            violations.add("OBJECT_DUMP_TEMPLATE",
                           f"object_dumps[{index}] ({dump.get('name') or dump.get('type')}) carries no real value")


def check_cited_files(violations: Violations, card: dict) -> None:
    """G-1: every capture the card names must exist. Walks the whole card for path-looking strings."""
    def walk(value: object, path: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, f"{path}/{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return
            # A pytest NODE ID (`tests/x.py::test_y`) is a citation of a file plus a node, not a path: MEASURED on the
            # T3 artifact, where taking the whole string as a path produced eleven CITED_FILE_MISSING findings for
            # nodes whose files exist. The node half is not a filesystem object and must not be looked up.
            candidate_text = text.split()[0]
            node_half = ""
            if "::" in candidate_text:
                candidate_text, _, node_half = candidate_text.partition("::")
            # A trailing `:120-160` line range is a citation of a file, not part of its name.
            candidate_text = re.sub(r":\d+(?:-\d+)?$", "", candidate_text)
            if candidate_text.startswith((".scratch/", "docs/", "tests/", "src/", "scripts/")):
                candidate = ROOT / candidate_text
                if not candidate.exists():
                    violations.add("CITED_FILE_MISSING", f"{path} names {candidate_text!r}, which is not on disk")
                elif node_half and candidate.suffix == ".py":
                    # Only a PLAIN identifier is checkable here: `CONTRACT_KEYS` may be a constant, `Vb6ShimState.as_evidence()`
                    # is an attribute/expression descriptor that says which member carries the fact. MEASURED: demanding
                    # `def NAME(` for those produced three false CITED_NODE_MISSING findings on the T3 artifact.
                    node_name = node_half.split("[")[0].strip()
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", node_name):
                        body = candidate.read_text(encoding="utf-8", errors="replace")
                        defined = (f"def {node_name}(" in body or f"class {node_name}" in body
                                   or f"{node_name} =" in body or f"{node_name}:" in body)
                        if not defined:
                            violations.add("CITED_NODE_MISSING",
                                           f"{path} names node {node_name!r}, which is not defined in {candidate_text}")
    walk(card)


def check_deployment(violations: Violations, card: dict) -> None:
    evidence = card.get("deployment_evidence")
    if not isinstance(evidence, dict):
        violations.add("DEPLOYMENT_SHAPE", "deployment_evidence must be an object")
        return
    three_way = evidence.get("three_way") or {}
    if str(card.get("status")) == "ACCEPTED":
        if not three_way:
            violations.add("DEPLOYMENT_WORKTREE_ONLY",
                           "ACCEPTED without a three-way (HEAD/worktree/container) deployment comparison")
        else:
            head = str(three_way.get("head_sha") or "")
            if head != current_head():
                violations.add("DEPLOYMENT_NOT_CURRENT_HEAD",
                               f"deployment evidence names HEAD {head[:12] or '(none)'}, current is {current_head()[:12]}")
            if str(three_way.get("gate_state") or "") != "MATCHED_TO_HEAD":
                violations.add("DEPLOYMENT_NOT_MATCHED",
                               f"deployment gate_state is {three_way.get('gate_state')!r}, not MATCHED_TO_HEAD")
    if evidence.get("docker_available") is False and str(card.get("status")) == "ACCEPTED":
        violations.add("DEPLOYMENT_UNVERIFIABLE_ACCEPTED",
                       "the Docker daemon is unavailable, so no deployment claim can be ACCEPTED (plan §8)")


def check_self_attestation(violations: Violations, card: dict) -> None:
    """A status the gate cannot recompute at all is not a status (plan §4.3, last rule)."""
    commands = card.get("commands")
    if not isinstance(commands, list) or not commands:
        violations.add("SELF_ATTESTED_STATUS", "no `commands` with exit codes: the status cannot be recomputed")


def check_card(card: dict, *, replay_controls: bool = False) -> Violations:
    violations = Violations()
    check_shape(violations, card)
    check_identity(violations, card)
    check_scope(violations, card)
    check_accepted_requires(violations, card)
    check_render_same_revision(violations, card)
    check_negative_controls(violations, card, replay=replay_controls)
    check_sets(violations, card)
    check_run_binding(violations, card)
    check_object_dumps(violations, card)
    check_deployment(violations, card)
    check_self_attestation(violations, card)
    check_cited_files(violations, card)
    return violations


def report(name: str, violations: Violations) -> None:
    if not violations.rows:
        print(f"OK   {name}: admissible")
        return
    print(f"FAIL {name}: {len(violations.rows)} violation(s)")
    for row in violations.rows:
        print(f"       {row['code']}: {row['detail']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--card", default="")
    parser.add_argument("--card-dir", default=str(CARDS))
    parser.add_argument("--replay-controls", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", default="")
    arguments = parser.parse_args()

    if arguments.self_test:
        from capability_gate_selftest import run_self_test  # local import: the fixture builder stays out of the gate
        return run_self_test(check_card, ROOT)

    paths: list[pathlib.Path] = []
    if arguments.card:
        paths = [pathlib.Path(arguments.card)]
    else:
        directory = pathlib.Path(arguments.card_dir)
        paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if not paths:
        print(f"NO CARDS: nothing to check under {arguments.card_dir}")
        return 0

    results = []
    failed = 0
    for path in paths:
        if not path.is_file():
            print(f"FAIL {path}: card file does not exist")
            failed += 1
            continue
        card = json.loads(path.read_text(encoding="utf-8"))
        violations = check_card(card, replay_controls=arguments.replay_controls)
        report(path.name, violations)
        results.append({"card": str(path), "violations": violations.rows, "codes": violations.codes()})
        failed += 1 if violations.rows else 0
    if arguments.json:
        pathlib.Path(arguments.json).write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n",
                                                encoding="utf-8", newline="\n")
    print(f"\ncards={len(results)} failing={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
