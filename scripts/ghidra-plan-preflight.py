#!/usr/bin/env python
"""Blocking preflight for `.scratch/plan-ghidra-b3-c3-execution-plan-reviewed-20260922.md` (plan step P-0.3).

WHAT THIS IS FOR. Section 2.6 of the plan requires an executable opening hook that REFUSES to let a step advance on
prose. Everything it checks is recomputed from disk, git and the artifact itself; a `decision: complete` written into
the status file, a hand-typed verdict, or a boolean a test helper pre-set are all explicitly NOT inputs.

The six mechanisms the plan names, and where they live here:

  M1  `record_object()`          external objects are dumped with `type()`/`vars()`/`inspect.signature()` AND at least
                                 one actual field value; a bare `getattr(x, "field", None)` template is rejected.
  M2  `_check_edit_hashes()`     every edit records before/after SHA256, the edit method, and a compile command; a
                                 function-header-only anchor is rejected, and restoration must be from a byte backup.
  M3  `_check_sql_records()`     runtime claims carry task_id/revision_id/content_sha256/started_at/finished_at read by
                                 REAL SQL, plus a wrong-sample/wrong-revision negative control.
  M4  `_check_render_proofs()`   a new symbol is not done until producer -> consumer -> re-rendered official Markdown
                                 holds and disconnecting the consumer FAILS a test.
  M5  `_check_set_differences()` published collections carry enumerated/retrieved sets and BOTH differences.
  M6  `main()`                   recomputes git/structure/ownership inputs and exits non-zero on a missing field, a
                                 negative control that did not fail, an ownership overlap, or a step the state machine
                                 does not allow.

`--self-test` tampers with an INDEPENDENT COPY of a generated artifact and re-executes this file as a subprocess,
requiring a non-zero exit for every tamper. Mutating a boolean inside the current process would not be evidence.

    py scripts/ghidra-plan-preflight.py --step P-0.3 --self-test
    py scripts/ghidra-plan-preflight.py --step P-1.1 --files src/threat_report_agent/service.py
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import inspect
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLAN = ROOT / ".scratch" / "plan-ghidra-b3-c3-execution-plan-reviewed-20260922.md"
STATUS = ROOT / ".scratch" / "ghidra-c3-execution-status.json"
OWNERSHIP = ROOT / ".scratch" / "ghidra-c3-ownership.json"
STRUCTURE = ROOT / ".scratch" / "structure-status.json"
ARTIFACT_DIR = ROOT / ".scratch" / "ghidra-c3" / "preflight"

PLAN_REVISION = "20260922-reviewed-r1"

#: The step order of the plan. A step may only run when every step it depends on is `complete` in the status file -
#: and the status file's own `complete` is only believed for steps whose artifact ALSO validates (see `_check_history`).
STEPS: tuple[str, ...] = (
    "P-0.1", "P-0.2", "P-0.3", "P-0.4",
    "P-1.1", "P-1.2", "P-1.3", "P-1.4", "P-1.5", "P-1.6", "P-1.7",
    "P-2.1", "P-2.2", "P-2.3",
    "P-3", "P-4", "P-5", "P-6", "P-7", "P-8",
    "T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8",
)
DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "P-0.2": ("P-0.1",),
    "P-0.3": ("P-0.1",),
    "P-0.4": ("P-0.1",),
    "P-1.1": ("P-0.3", "P-0.4"),
    "P-1.2": ("P-1.1",),
    "P-1.3": ("P-1.1",),
    "P-1.4": ("P-1.1",),
    "P-1.5": ("P-1.1",),
    "P-1.6": ("P-1.1",),
    "P-1.7": ("P-1.1", "P-1.2", "P-1.3", "P-1.4", "P-1.5", "P-1.6"),
    "P-2.1": ("P-1.7",),
    "P-2.2": ("P-2.1",),
    "P-2.3": ("P-2.2",),
    "T1": ("P-2.3",),
    "T2": ("T1",),
    "T3": ("T2",),
    "T4": ("P-2.3",),
    "T6": ("P-1.7",),
    "T7": ("P-1.7",),
    "T8": ("T4",),
}

#: Phase-level steps. The plan's own P-1.7 / P-2 gate commands are `--step P-1` and `--step P-2`, which name a PHASE
#: rather than a sub-step; without this table the documented command would fail with `STEP_UNKNOWN` and P-1.7 could never
#: be discharged as written. A phase step means "every sub-step of this phase is complete, and the phase artifact
#: validates on its own".
PHASE_PREFIXES = ("P-0", "P-1", "P-2", "P-3", "P-4", "P-5", "P-6", "P-7", "P-8")


def sub_steps_of(phase: str) -> tuple[str, ...]:
    """The sub-steps that belong to a phase name (`P-1` -> `P-1.1` ... `P-1.7`)."""
    return tuple(step for step in STEPS if step.startswith(phase + "."))


#: Steps that may NOT be claimed while the deployment gate is not MATCHED_TO_HEAD (plan P-1.7 / P-2 rule). A local
#: pytest run is not a deployment result, so this gate is deliberately independent of the test outcome.
DEPLOYMENT_DEPENDENT = ("P-2", "P-2.1", "P-2.2", "P-2.3", "P-3", "P-4", "P-5", "P-6", "P-7", "P-8", "T1", "T2", "T3",
                        "T4", "T5", "T8")

REQUIRED_STEP_FIELDS = (
    "step", "source_sha", "worktree_manifest_sha", "allowed_files", "changed_files", "commands",
    "focused_failure_nodes_after", "full_failure_nodes_after", "negative_controls", "edit_hashes",
    "py_compile_or_typecheck", "deployment_manifest", "skill_audit", "decision",
)
#: Fields the plan names per MECHANISM rather than per step shape; a step that touches the mechanism must carry them.
MECHANISM_FIELDS = {
    "M1": "object_dumps",
    "M3": "task_revision_content_records",
    "M4": "producer_consumer_render_proof",
    "M5": "set_differences",
}


class Violations(list):
    """A list of strings that renders as the reason the step may not advance."""

    def add(self, code: str, detail: str) -> None:
        self.append(f"{code}: {detail}")


class NotApplicable(Exception):
    """Raised by a tamper whose target block is absent because THIS step does not exercise that mechanism.

    A step that introduces no product symbol cannot have its consumer disconnected, and pretending otherwise would make
    the self-test report a rejection it never performed. The mechanism must then be covered by a named unit test instead
    (`mechanism_unit_tests`), which `_check_mechanism_coverage` enforces by reading the test file.
    """


ALL_MECHANISMS = ("M1", "M2", "M3", "M4", "M5", "M6")


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout


# ---------------------------------------------------------------------------------------------------------------------
# M1: object dumps
# ---------------------------------------------------------------------------------------------------------------------
def record_object(obj: Any, *, name: str, fields: Sequence[str] | None = None,
                  samples: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Dump one external object with REAL values, never a `getattr(x, "field", None)` template.

    M1 of the plan exists because a field that never changes (`worker_isolated=False` forever) was once presented as
    path evidence. So the dump must carry `type()`, the public surface (`vars()` or `inspect.signature()`), and at least
    one concrete value read from the object itself. For an object with no `__dict__` (a `Path`, a C callable) the plan
    requires the public signature, the return type and AN ACTUAL RETURN VALUE - that is what `samples` carries, and its
    values must have been produced by really calling the expression (the caller does the calling, so the value is
    measured, not described).
    """
    kind = type(obj)
    dump: dict[str, Any] = {
        "name": name,
        "type": kind.__name__,
        "module": getattr(kind, "__module__", ""),
        "has_dict": hasattr(obj, "__dict__"),
        "field_values": {},
    }
    names = list(fields) if fields else []
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        names = names or [field.name for field in dataclasses.fields(obj)]
    if not names and hasattr(obj, "__dict__"):
        names = sorted(vars(obj))
    for field in names:
        if hasattr(obj, field):
            value = getattr(obj, field)
            dump["field_values"][field] = {"repr": _short(repr(value)), "source": "attribute"}
        elif isinstance(obj, Mapping) and field in obj:
            dump["field_values"][field] = {"repr": _short(repr(obj[field])), "source": "mapping"}
    for expression, value in (samples or {}).items():
        dump["field_values"][expression] = {"repr": _short(repr(value)), "source": "measured_return"}
    if hasattr(obj, "__dict__"):
        dump["vars"] = {key: _short(repr(value)) for key, value in sorted(vars(obj).items())}
    if callable(obj):
        try:
            dump["signature"] = str(inspect.signature(obj))
        except (TypeError, ValueError):  # builtins and C callables have no signature
            dump["signature"] = ""
        dump["return_type"] = type(obj).__name__
    return dump


def _short(text: str, limit: int = 400) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _check_object_dumps(violations: Violations, artifact: Mapping[str, Any]) -> int:
    dumps = artifact.get("object_dumps") or []
    if not dumps:
        violations.add("M1_MISSING", "`object_dumps` is empty: a step that touches an external object must dump it")
        return 0
    complete = 0
    for index, dump in enumerate(dumps):
        if not isinstance(dump, Mapping):
            violations.add("M1_SHAPE", f"object_dumps[{index}] is not an object")
            continue
        fields = dump.get("field_values") or {}
        real = {key: value for key, value in fields.items()
                if isinstance(value, Mapping) and str(value.get("repr", "")).strip() not in {"", "None"}}
        surface = bool(dump.get("vars")) or bool(str(dump.get("signature") or "").strip())
        if not str(dump.get("type") or "").strip():
            violations.add("M1_TYPE", f"object_dumps[{index}] has no `type`")
        if not surface and not real:
            violations.add("M1_SURFACE", f"object_dumps[{index}] ({dump.get('name')}) has neither vars()/signature() "
                                         f"nor a real field value")
        if not real:
            violations.add("M1_NO_VALUE", f"object_dumps[{index}] ({dump.get('name')}) records no actual field value")
        template = json.dumps(dump)
        if "getattr(" in template and not real:
            violations.add("M1_GETATTR_TEMPLATE", f"object_dumps[{index}] offers a getattr template as its only "
                                                 f"evidence")
        if surface and real:
            complete += 1
    return complete


# ---------------------------------------------------------------------------------------------------------------------
# M2: edit hashes and atomic edits
# ---------------------------------------------------------------------------------------------------------------------
_HEADER_ONLY = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+\w+\s*\(", re.M)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _check_edit_hashes(violations: Violations, artifact: Mapping[str, Any]) -> None:
    edits = artifact.get("edit_hashes") or []
    changed = [str(item) for item in artifact.get("changed_files") or []]
    if changed and not edits:
        violations.add("M2_MISSING", "`changed_files` is non-empty but `edit_hashes` records no before/after hash")
    for index, edit in enumerate(edits):
        if not isinstance(edit, Mapping):
            violations.add("M2_SHAPE", f"edit_hashes[{index}] is not an object")
            continue
        for key in ("path", "sha256_before", "sha256_after", "method"):
            if not str(edit.get(key) or "").strip():
                violations.add("M2_FIELD", f"edit_hashes[{index}] is missing `{key}`")
        before, after = str(edit.get("sha256_before") or ""), str(edit.get("sha256_after") or "")
        created = bool(edit.get("created"))
        # FORMAT MATTERS. MEASURED (P-0.3): a tamper that copies `sha256_before` into `sha256_after` on a CREATED file
        # produced no violation, because "(absent)" was accepted as a hash and `created` suppressed the equality rule.
        # A digest-shaped field that accepts a non-digest is not a check.
        if not _HEX64.match(after):
            violations.add("M2_AFTER_NOT_A_HASH", f"edit_hashes[{index}] `sha256_after` is not a 64-hex digest: {after!r}")
        if not created and not _HEX64.match(before):
            violations.add("M2_BEFORE_NOT_A_HASH", f"edit_hashes[{index}] `sha256_before` is not a 64-hex digest: "
                                                   f"{before!r}")
        if before and after and before == after and edit.get("changed") is not False and not created:
            violations.add("M2_NO_CHANGE", f"edit_hashes[{index}] claims an edit whose before and after hashes are equal")
        if created and before not in {"(absent)", ""}:
            violations.add("M2_CREATED", f"edit_hashes[{index}] is marked created but carries a before-hash")
        if created and not _HEX64.match(before or "") and before not in {"(absent)", ""}:
            violations.add("M2_BEFORE_NOT_A_HASH", f"edit_hashes[{index}] `sha256_before` must be a digest or the "
                                                   f"literal '(absent)' for a created file")
        if not str(edit.get("compile_or_typecheck") or "").strip():
            violations.add("M2_COMPILE", f"edit_hashes[{index}] records no compile/typecheck command")
        anchor = str(edit.get("anchor") or "")
        if anchor and _HEADER_ONLY.match(anchor) and not str(edit.get("anchor_next_line") or "").strip():
            violations.add("M2_ORPHAN_ANCHOR", f"edit_hashes[{index}] uses a function/class HEADER as its anchor with "
                                               f"no next-line match, which is how an orphan body gets inserted")
        if str(edit.get("restore") or "") == "git checkout":
            violations.add("M2_RESTORE", f"edit_hashes[{index}] restored with `git checkout`; a byte backup is required")
    backup = artifact.get("byte_backup_restore") or {}
    if backup and not (backup.get("restored_sha256") and backup.get("restored_sha256") == backup.get("original_sha256")):
        violations.add("M2_BACKUP", "the byte-backup restore did not return the original SHA256")


# ---------------------------------------------------------------------------------------------------------------------
# M3: SQL-bound runtime claims
# ---------------------------------------------------------------------------------------------------------------------
SQL_COLUMNS = ("task_id", "revision_id", "content_sha256", "started_at", "finished_at")


def _check_sql_records(violations: Violations, artifact: Mapping[str, Any]) -> None:
    if not artifact.get("claims_runtime_fact"):
        return
    records = artifact.get("task_revision_content_records") or []
    if not records:
        violations.add("M3_MISSING", "the step claims a runtime fact but records no SQL-bound task/revision row")
        return
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            violations.add("M3_SHAPE", f"task_revision_content_records[{index}] is not an object")
            continue
        missing = [column for column in SQL_COLUMNS if not str(record.get(column) or "").strip()]
        if missing:
            violations.add("M3_COLUMNS", f"task_revision_content_records[{index}] is missing {missing}")
        for key in ("sql_text", "connection", "schema_query"):
            if not str(record.get(key) or "").strip():
                violations.add("M3_PROVENANCE", f"task_revision_content_records[{index}] has no `{key}`: a hand-typed "
                                                f"task id is not SQL evidence")
        if int(record.get("exit_code", 1) or 0) != 0:
            violations.add("M3_EXIT", f"task_revision_content_records[{index}] SQL exit code is not 0")
        if not (record.get("rows") or []):
            violations.add("M3_ROWS", f"task_revision_content_records[{index}] returned no row")
        # THE DIGEST MUST BE CHECKABLE. MEASURED (P-0.3): replacing `content_sha256` with 64 zeros produced no
        # violation while the check only demanded a non-empty string, so the field proved nothing. A content hash is
        # only evidence when its SOURCE is named and, for a source on disk, recomputed here.
        source = str(record.get("content_source") or "").strip()
        if not source:
            violations.add("M3_CONTENT_SOURCE", f"task_revision_content_records[{index}] names no `content_source`, so "
                                                f"its content_sha256 cannot be checked")
        else:
            path = ROOT / source
            if path.is_file():
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                declared = str(record.get("content_sha256") or "")
                # A record may legitimately hash a file that LATER changed - P-0.3 hashed the preflight script itself.
                # It must then name the commit whose bytes it hashed; without that name a mismatch is still a violation,
                # so "the file moved on" can never become a blanket excuse.
                if actual != declared and _blob_sha256_at(str(record.get("content_source_at_commit") or ""),
                                                          source) != declared:
                    violations.add("M3_CONTENT_MISMATCH", f"task_revision_content_records[{index}] content_sha256 "
                                                          f"{declared[:12]} matches neither {source} ({actual[:12]}) "
                                                          f"nor that path at commit "
                                                          f"{record.get('content_source_at_commit') or '(none named)'}")
            elif "sql_text" not in record:
                violations.add("M3_CONTENT_UNVERIFIED", f"task_revision_content_records[{index}] content_source is not a "
                                                        f"local file and no SQL is recorded to have produced it")
    if not artifact.get("wrong_sample_or_revision_control"):
        violations.add("M3_NEGATIVE", "no wrong-sample/wrong-revision control: the same assertion was never shown to "
                                      "fail on the wrong row")


# ---------------------------------------------------------------------------------------------------------------------
# M4: producer -> consumer -> re-rendered official Markdown
# ---------------------------------------------------------------------------------------------------------------------
def _check_render_proofs(violations: Violations, artifact: Mapping[str, Any]) -> None:
    if not artifact.get("introduces_symbol"):
        return
    proofs = artifact.get("producer_consumer_render_proof") or []
    if not proofs:
        violations.add("M4_MISSING", "a new symbol was introduced without a producer/consumer/render proof")
        return
    control_names = {str(item.get("name")) for item in artifact.get("negative_controls") or []
                     if isinstance(item, Mapping)}
    for index, proof in enumerate(proofs):
        if not isinstance(proof, Mapping):
            violations.add("M4_SHAPE", f"producer_consumer_render_proof[{index}] is not an object")
            continue
        for key in ("symbol", "producer", "consumer", "rendered_markdown_contains", "renderer"):
            if not str(proof.get(key) or "").strip():
                violations.add("M4_FIELD", f"producer_consumer_render_proof[{index}] is missing `{key}`")
        if proof.get("read_from_json_only"):
            violations.add("M4_JSON_ONLY", f"producer_consumer_render_proof[{index}] reads the value from JSON instead "
                                           f"of the re-rendered Markdown")
        control = str(proof.get("consumer_disconnect_control") or "")
        if not control:
            violations.add("M4_CONTROL", f"producer_consumer_render_proof[{index}] has no consumer-disconnect control")
        elif control not in control_names:
            violations.add("M4_CONTROL_MISSING", f"producer_consumer_render_proof[{index}] cites control `{control}` "
                                                 f"which is not in `negative_controls`")


# ---------------------------------------------------------------------------------------------------------------------
# M5: publish set differences, not a pseudo-complete count
# ---------------------------------------------------------------------------------------------------------------------
def _check_set_differences(violations: Violations, artifact: Mapping[str, Any]) -> None:
    if not artifact.get("publishes_collection"):
        return
    sets = artifact.get("set_differences") or []
    if not sets:
        violations.add("M5_MISSING", "the step publishes a collection but records no set-difference block")
        return
    for index, block in enumerate(sets):
        if not isinstance(block, Mapping):
            violations.add("M5_SHAPE", f"set_differences[{index}] is not an object")
            continue
        for key in ("name", "identity_key", "enumerated_set", "retrieved_set", "expected_minus_actual",
                    "actual_minus_expected"):
            if key not in block:
                violations.add("M5_FIELD", f"set_differences[{index}] is missing `{key}`")
        if not str(block.get("identity_key") or "").strip():
            violations.add("M5_IDENTITY", f"set_differences[{index}] has no stable identity key")
        if block.get("count_only"):
            violations.add("M5_COUNT_ONLY", f"set_differences[{index}] publishes a count instead of the set difference")


# ---------------------------------------------------------------------------------------------------------------------
# M6: the blocking checks - inputs recomputed, never trusted
# ---------------------------------------------------------------------------------------------------------------------
def _check_plan_identity(violations: Violations, status: Mapping[str, Any]) -> None:
    if not PLAN.is_file():
        violations.add("PLAN_MISSING", f"{PLAN} does not exist")
        return
    actual = sha256_file(PLAN)
    declared = str(status.get("plan_sha256") or "")
    if not declared:
        violations.add("PLAN_HASH_MISSING", "the status file does not pin `plan_sha256`")
    elif declared != actual:
        violations.add("PLAN_HASH", f"plan_sha256 mismatch: status {declared[:12]} vs disk {actual[:12]}")
    if str(status.get("revision") or "") != PLAN_REVISION:
        violations.add("PLAN_REVISION", f"status revision {status.get('revision')!r} != {PLAN_REVISION!r}")


def _check_state_machine(violations: Violations, step: str, status: Mapping[str, Any]) -> None:
    if step not in STEPS and step not in PHASE_PREFIXES:
        violations.add("STEP_UNKNOWN", f"{step} is not a step of this plan")
        return
    completed = {str(item.get("step")) for item in status.get("steps") or []
                 if isinstance(item, Mapping) and item.get("decision") == "complete"}
    if step in completed:
        # RE-VALIDATING A FINISHED STEP IS ALWAYS ALLOWED. MEASURED: once the status advanced to P-1.1, `--step P-0.4`
        # started reporting STEP_NOT_ALLOWED, so the two artifacts that had already been accepted could no longer be
        # re-checked - a gate that forbids re-reading its own evidence.
        return
    allowed = status.get("allowed_steps")
    if allowed is not None and step not in allowed and step not in PHASE_PREFIXES:
        violations.add("STEP_NOT_ALLOWED", f"the status' state machine does not allow {step} (allowed: {allowed})")
    if step in PHASE_PREFIXES:
        # A phase step is allowed only when EVERY sub-step of the phase is complete; naming a phase must never be a way
        # to skip the sub-steps it contains (plan P-1.7's own command is `--step P-1`). The `allowed_steps` list is
        # generated per sub-step, so a phase name is deliberately not required to appear in it.
        missing = [sub for sub in sub_steps_of(step) if sub not in completed]
        if missing:
            violations.add("PHASE_INCOMPLETE", f"{step} still has incomplete sub-step(s): {missing}")
        return
    for dependency in DEPENDENCIES.get(step, ()):  # a step may run only after its dependencies are complete
        if dependency not in completed:
            violations.add("STEP_DEPENDENCY", f"{step} requires {dependency} to be complete first")


def _check_ownership(violations: Violations, ownership: Mapping[str, Any], files: Iterable[str]) -> None:
    if ownership.get("overlap"):
        violations.add("OWNERSHIP_OVERLAP", f"the ownership lock reports overlap: {ownership['overlap']}")
    if str(ownership.get("overlap_verdict") or "") != "NO OVERLAP":
        violations.add("OWNERSHIP_VERDICT", f"ownership verdict is {ownership.get('overlap_verdict')!r}")
    table = {str(item.get("file")): item for item in ownership.get("files") or [] if isinstance(item, Mapping)}
    for wanted in files:
        entry = table.get(wanted)
        if entry is None:
            violations.add("OWNERSHIP_UNLISTED", f"{wanted} is not in the ownership lock; it cannot be taken silently")
            continue
        state = str(entry.get("state") or "")
        if state.startswith("LOCKED_BY_ACTIVE_TRACK"):
            violations.add("OWNERSHIP_LOCKED", f"{wanted} is {state}")
        elif state.startswith("OWNED_BY_STRUCTURE_PLAN"):
            violations.add("OWNERSHIP_GATE", f"{wanted} belongs to the structure plan's tracked gate; call it, do not "
                                             f"edit it")


def _check_deployment(dependencies: Violations, step: str, status: Mapping[str, Any]) -> None:
    if step not in DEPLOYMENT_DEPENDENT:
        return
    gate = str((status.get("deployment") or {}).get("gate_state") or status.get("deployment_gate_state") or "")
    if gate != "MATCHED_TO_HEAD":
        dependencies.add("DEPLOYMENT_NOT_MATCHED", f"{step} depends on the deployment gate being MATCHED_TO_HEAD; it is "
                                                    f"{gate or 'unset'!r} - a local pytest run does not discharge this")


def _check_structure_conflicts(violations: Violations, ownership: Mapping[str, Any], step: str) -> None:
    for conflict in ownership.get("structure_plan_conflicts") or []:
        if not isinstance(conflict, Mapping):
            continue
        if str(conflict.get("status") or "").upper().startswith("OPEN") and step in str(conflict.get("blocks") or ""):
            violations.add("STRUCTURE_CONFLICT", f"{step} is blocked by open structure conflict {conflict.get('id')}")


def _check_artifact_fields(violations: Violations, artifact: Mapping[str, Any], step: str) -> None:
    for field in REQUIRED_STEP_FIELDS:
        if field not in artifact:
            violations.add("STEP_FIELD_MISSING", f"the step record has no `{field}`")
    if str(artifact.get("step") or "") != step:
        violations.add("STEP_MISMATCH", f"the artifact is for {artifact.get('step')!r}, not {step!r}")
    decision = str(artifact.get("decision") or "")
    allowed_decisions = {"complete", "blocked"}
    if step in PHASE_PREFIXES:
        # P-1.7: "部署门若仍 blocked，状态是 `P-1_COMPLETE_DEPLOYMENT_BLOCKED`，不能写成产品验收完成." The state machine has
        # to encode that name - a hand-written explanation is exactly what the plan forbids here.
        allowed_decisions.add(phase_deployment_blocked_state(step))
    if decision not in allowed_decisions:
        violations.add("DECISION", f"decision must be one of {sorted(allowed_decisions)}, got {decision!r}")
    if artifact.get("worktree_manifest_sha") in (None, "") or artifact.get("source_sha") in (None, ""):
        violations.add("MANIFEST", "the step record must carry both `source_sha` and `worktree_manifest_sha`")
    changed = [str(item) for item in artifact.get("changed_files") or []]
    allowed = [str(item) for item in artifact.get("allowed_files") or []]
    outside = [item for item in changed if item not in allowed]
    if outside:
        violations.add("SCOPE", f"changed files outside `allowed_files`: {outside}")


def phase_deployment_blocked_state(phase: str) -> str:
    """The ONLY way a phase may be recorded as finished while the deployment gate is not MATCHED_TO_HEAD."""
    return f"{phase}_COMPLETE_DEPLOYMENT_BLOCKED"


def _deployment_gate_state(status: Mapping[str, Any]) -> str:
    return str((status.get("deployment") or {}).get("gate_state") or status.get("deployment_gate_state") or "")


def _check_phase_deployment_state(violations: Violations, step: str, status: Mapping[str, Any],
                                  artifact: Mapping[str, Any]) -> None:
    """P-1.7 / P-2: a phase that finished on a blocked deployment gate must SAY so, and must not read as acceptance.

    Both directions are required:
      * a PHASE artifact's `decision` must be `complete` when the gate is MATCHED_TO_HEAD, and
        `<phase>_COMPLETE_DEPLOYMENT_BLOCKED` when it is not - so nobody can mistake a locally-green phase for a
        deployed one;
      * the status may not carry a phase row marked plain `complete` while the gate is blocked (`PHASE_OVERCLAIM`),
        which is how "P-1 done" would otherwise become "P-1 accepted".
    """
    gate = _deployment_gate_state(status)
    matched = gate == "MATCHED_TO_HEAD"
    if step in PHASE_PREFIXES:
        decision = str(artifact.get("decision") or "")
        if matched and decision != "complete":
            violations.add("PHASE_DECISION", f"{step} has the gate MATCHED_TO_HEAD but its decision is {decision!r}, "
                                             f"not 'complete'")
        if not matched and decision == "complete":
            violations.add("PHASE_DEPLOYMENT_OVERCLAIM",
                           f"{step} may not be recorded as 'complete' while the deployment gate is {gate or 'unset'!r}; "
                           f"the plan's name for this state is {phase_deployment_blocked_state(step)!r}")
    for row in status.get("steps") or []:
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("step") or "")
        if name in PHASE_PREFIXES and str(row.get("decision") or "") == "complete" and not matched:
            violations.add("PHASE_OVERCLAIM", f"the status records {name} as 'complete' while the deployment gate is "
                                              f"{gate or 'unset'!r}")


_CAPTURE_NODE_RE = re.compile(r"^(?:FAILED|ERROR)\s+(\S+)", re.M)


def _nodes_from_capture(path: pathlib.Path) -> set[str]:
    """The FAILURE NODE SET of a captured `pytest -q` run, parsed from the file rather than taken from the artifact."""
    raw = path.read_bytes()
    text = raw.decode("utf-16", errors="replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") \
        else raw.decode("utf-8-sig", errors="replace")
    return {match.group(1) for match in _CAPTURE_NODE_RE.finditer(text.replace("\x00", ""))}


def _check_failure_node_sets(violations: Violations, artifact: Mapping[str, Any], status: Mapping[str, Any]) -> None:
    """P-1.7's own condition: "全量失败节点集合不得新增". This compares SETS, never counts.

    The known set is the UNION of the plan's original P-0.2 baseline and the status' current baseline, because the
    generator re-points `baseline_failure_nodes` as nodes get FIXED: comparing only against the shrunken list would
    have called an older artifact's (larger, already-accepted) set a regression. Unioning cannot hide a NEW failure -
    a node absent from both lists is new by definition.
    """
    known = {str(node) for node in status.get("baseline_failure_nodes") or []}
    known |= {str(node) for node in status.get("baseline_failure_nodes_original_p0_2") or []}
    after = {str(node) for node in artifact.get("full_failure_nodes_after") or []}
    regressions = sorted(after - known)
    if regressions:
        violations.add("REGRESSION_NEW_FAILURES", f"the full-suite failure set gained node(s) that are in no baseline: "
                                                  f"{regressions}")
    capture = str(artifact.get("full_suite_capture") or "").strip()
    if capture:
        path = ROOT / capture
        if not path.is_file():
            violations.add("CAPTURE_MISSING", f"`full_suite_capture` names {capture!r}, which does not exist")
        else:
            parsed = _nodes_from_capture(path)
            if parsed != after:
                violations.add("CAPTURE_MISMATCH",
                               f"`full_failure_nodes_after` ({len(after)} node(s)) does not match the capture "
                               f"{capture!r} ({len(parsed)} node(s)); the artifact must report the set of the file it "
                               f"points at. in-artifact-only: {sorted(after - parsed)}; capture-only: "
                               f"{sorted(parsed - after)}")
    # A focused run must not gain failures either: that is where a step's own regression shows up first.
    before = {str(node) for node in artifact.get("focused_failure_nodes_before") or []}
    focused = {str(node) for node in artifact.get("focused_failure_nodes_after") or []}
    if before and (focused - before):
        violations.add("FOCUSED_NEW_FAILURES", f"the focused run gained failure node(s): {sorted(focused - before)}")


def _blob_sha256_at(commit: str, path: str) -> str:
    """SHA256 of `path` as stored in `commit`, or "" when the commit is absent/unreadable.

    Read-only (`git show`), never a tree-level command. The path is converted to a POSIX spec because a Windows
    backslash path is not a valid git object spec (`git show HEAD:src\\x.py` exits 128).
    """
    if not commit.strip():
        return ""
    spec = f"{commit.strip()}:{pathlib.PurePosixPath(path).as_posix()}"
    completed = subprocess.run(["git", "show", spec], cwd=ROOT, capture_output=True)
    if completed.returncode != 0:
        return ""
    return hashlib.sha256(completed.stdout).hexdigest()


def _check_negative_controls(violations: Violations, artifact: Mapping[str, Any]) -> None:
    controls = artifact.get("negative_controls") or []
    if not controls:
        violations.add("NEGATIVE_MISSING", "no negative control: the plan requires a result that actually fails")
        return
    for index, control in enumerate(controls):
        if not isinstance(control, Mapping):
            violations.add("NEGATIVE_SHAPE", f"negative_controls[{index}] is not an object")
            continue
        name = str(control.get("name") or "").strip()
        if not name:
            violations.add("NEGATIVE_NAME", f"negative_controls[{index}] has no name")
        code = control.get("exit_code")
        if code is None or int(code) == 0:
            violations.add("NEGATIVE_EXIT", f"negative control {name or index!r} exited {code!r}; a control that does "
                                            f"not fail proves nothing")
        if not str(control.get("evidence") or "").strip():
            violations.add("NEGATIVE_EVIDENCE", f"negative control {name or index!r} records no evidence")


def _check_mechanism_coverage(violations: Violations, artifact: Mapping[str, Any]) -> None:
    """Every one of M1-M6 must be either EXERCISED by a real tamper or covered by a named unit test.

    Without this rule a step could quietly skip the mechanism it found inconvenient, which is how "the hook blocks"
    turns into prose. The unit-test half is verified against the file on disk, not taken on trust.
    """
    exercised = {str(item) for item in artifact.get("mechanisms_exercised") or []}
    by_test = artifact.get("mechanism_unit_tests") or {}
    for mechanism in ALL_MECHANISMS:
        if mechanism in exercised:
            continue
        reference = str(by_test.get(mechanism) or "")
        if not reference:
            violations.add("MECHANISM_UNCOVERED", f"{mechanism} is neither exercised by a self-test tamper nor mapped "
                                                  f"to a unit test")
            continue
        path_text, _, test_name = reference.partition("::")
        path = ROOT / path_text
        if not path.is_file():
            violations.add("MECHANISM_TEST_MISSING", f"{mechanism} maps to {reference} but {path_text} does not exist")
            continue
        names = {node.name for node in ast.walk(ast.parse(path.read_text(encoding="utf-8", errors="replace")))
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        if test_name and test_name not in names:
            violations.add("MECHANISM_TEST_ABSENT", f"{mechanism} maps to `{test_name}` which is not defined in "
                                                    f"{path_text}")


def validate(step: str, status: Mapping[str, Any], ownership: Mapping[str, Any],
             artifact: Mapping[str, Any], files: Sequence[str]) -> Violations:
    """Return every reason `step` may not advance. An empty result is the ONLY thing that advances the state."""
    violations = Violations()
    _check_plan_identity(violations, status)
    _check_state_machine(violations, step, status)
    _check_artifact_fields(violations, artifact, step)
    _check_phase_deployment_state(violations, step, status, artifact)
    _check_failure_node_sets(violations, artifact, status)
    _check_ownership(violations, ownership, files)
    _check_structure_conflicts(violations, ownership, step)
    _check_deployment(violations, step, status)
    _check_object_dumps(violations, artifact)
    _check_edit_hashes(violations, artifact)
    _check_sql_records(violations, artifact)
    _check_render_proofs(violations, artifact)
    _check_set_differences(violations, artifact)
    _check_negative_controls(violations, artifact)
    _check_mechanism_coverage(violations, artifact)
    return violations


# ---------------------------------------------------------------------------------------------------------------------
# self-test: tamper with an independent COPY and re-run this file as a subprocess
# ---------------------------------------------------------------------------------------------------------------------
TAMPERS: tuple[tuple[str, str], ...] = (
    ("m1_drop_real_field_value", "M1"), ("m1_replace_field_with_getattr_template", "M1"),
    ("m2_remove_edit_hash", "M2"), ("m2_equal_before_after", "M2"),
    ("m3_corrupt_content_sha256", "M3"), ("m3_drop_negative_control", "M3"),
    ("m4_disconnect_consumer_from_control", "M4"), ("m4_json_only_proof", "M4"),
    ("m5_publish_count_only", "M5"), ("m5_drop_expected_minus_actual", "M5"),
    ("negative_control_zero_exit", "M6"), ("ownership_overlap", "M6"),
    ("scope_escape", "M6"),
)


def _scope_escape_candidates() -> tuple[str, ...]:
    """Paths a step must never be able to change silently; the first one it does NOT allow is the escape."""
    return ("src/threat_report_agent/emulation/emulation_plan.py",
            "src/threat_report_agent/tools/tool_execution.py",
            "src/threat_report_agent/static/ghidra_adapter.py",
            "src/threat_report_agent/service.py",
            "docs/import-policy.json")


def _tamper(name: str, status: dict[str, Any], ownership: dict[str, Any], artifact: dict[str, Any]) -> None:
    """Apply one tamper. Raises `NotApplicable` when this step's artifact has no such block to break."""
    def need(key: str) -> Any:
        value = artifact.get(key)
        if not value:
            raise NotApplicable(f"`{key}` is absent from this step's artifact")
        return value

    if name == "m1_drop_real_field_value":
        need("object_dumps")[0]["field_values"] = {}
    elif name == "m1_replace_field_with_getattr_template":
        need("object_dumps")[0]["field_values"] = {}
        artifact["object_dumps"][0]["vars"] = {}
        artifact["object_dumps"][0]["signature"] = ""
        artifact["object_dumps"][0]["note"] = "getattr(x, 'worker_isolated', None)"
    elif name == "m2_remove_edit_hash":
        need("edit_hashes")
        artifact["edit_hashes"] = []
    elif name == "m2_equal_before_after":
        need("edit_hashes")[0]["sha256_after"] = need("edit_hashes")[0]["sha256_before"]
    elif name == "m3_corrupt_content_sha256":
        need("task_revision_content_records")[0]["content_sha256"] = "0" * 64
    elif name == "m3_drop_negative_control":
        need("task_revision_content_records")
        # Remove the M3-SPECIFIC negative evidence (the wrong-revision control), not merely one entry of a set that may
        # still hold others: MEASURED (P-0.3), filtering by name left `wrong_sample_or_revision_control` in place and the
        # tamper was correctly accepted, i.e. the tamper - not the validator - was wrong.
        artifact.pop("wrong_sample_or_revision_control", None)
    elif name == "m4_disconnect_consumer_from_control":
        need("producer_consumer_render_proof")[0]["consumer_disconnect_control"] = "a_control_that_does_not_exist"
    elif name == "m4_json_only_proof":
        need("producer_consumer_render_proof")[0]["read_from_json_only"] = True
    elif name == "m5_publish_count_only":
        need("set_differences")
        artifact["set_differences"][0] = {"name": "ghidra_functions", "identity_key": "entry", "count_only": True}
    elif name == "m5_drop_expected_minus_actual":
        need("set_differences")[0].pop("expected_minus_actual", None)
    elif name == "negative_control_zero_exit":
        need("negative_controls")[0]["exit_code"] = 0
    elif name == "ownership_overlap":
        ownership["overlap"] = [{"file": "src/threat_report_agent/service.py", "claimed_by": ["root", "T1/T2"]}]
        ownership["overlap_verdict"] = "OVERLAP - P-0.2 MUST NOT RUN"
    elif name == "scope_escape":
        need("changed_files")
        # THE ESCAPE PATH MUST REALLY BE OUTSIDE `allowed_files`. MEASURED (P-1.1): the tamper appended
        # `src/threat_report_agent/service.py` unconditionally, but that path IS allowed for a step that owns the
        # service - so the tamper produced no violation and the self-test reported a control that "did not fail"
        # while its evidence claimed a rejection. A vacuous control is worse than a missing one.
        allowed = {str(item) for item in artifact.get("allowed_files") or []}
        candidates = _scope_escape_candidates()
        escape = next((item for item in candidates if item not in allowed), None)
        if escape is None:
            raise NotApplicable("every escape candidate is inside this step's `allowed_files`")
        artifact["changed_files"] = list(artifact["changed_files"]) + [escape]
    else:  # pragma: no cover - a tamper name that is not implemented must not silently pass
        raise SystemExit(f"unknown tamper {name!r}")


def run_self_test(step: str, artifact: Mapping[str, Any], json_path: pathlib.Path | None = None) -> int:
    """Tamper with a COPY and require a non-zero exit from a REAL subprocess run for every tamper.

    THE UNTAMPERED ARTIFACT MUST ALREADY VALIDATE. If it does not, every tamper "fails" for a reason that has nothing
    to do with the tamper and the whole self-test is vacuous - the same family of hole as a tamper that breaks nothing.
    MEASURED (round 167, found by asking whether the plan's own `--step P-1 --self-test` would mean anything): the CLI
    used to run the loop unconditionally, so a phase step with incomplete sub-steps would have reported "13 rejected"
    while proving nothing.
    """
    status = load(STATUS, {})
    ownership = load(OWNERSHIP, {})
    baseline = validate(step, status, ownership, artifact, [str(item) for item in artifact.get("changed_files") or []])
    if baseline:
        print("SELF-TEST REFUSED: the untampered artifact does not validate, so a rejection would prove nothing:")
        for violation in baseline:
            print(f"  VIOLATION {violation}")
        if json_path:
            write_artifact(json_path, {"step": step, "results": [], "verdict": "BASE_ARTIFACT_INVALID",
                                       "violations": list(baseline)})
        return 1
    results = []
    with tempfile.TemporaryDirectory(prefix="ghidra-preflight-selftest-") as raw:
        temp = pathlib.Path(raw)
        base_status = json.loads(STATUS.read_text(encoding="utf-8-sig")) if STATUS.is_file() else {}
        base_owner = json.loads(OWNERSHIP.read_text(encoding="utf-8-sig")) if OWNERSHIP.is_file() else {}
        base_artifact = json.loads(json.dumps(artifact))
        for name, mechanism in TAMPERS:
            case = temp / name
            case.mkdir(parents=True, exist_ok=True)
            status = json.loads(json.dumps(base_status))
            ownership = json.loads(json.dumps(base_owner))
            artifact_copy = json.loads(json.dumps(base_artifact))
            try:
                _tamper(name, status, ownership, artifact_copy)
            except NotApplicable as reason:
                # NOT a rejection: the block does not exist for this step. `_check_mechanism_coverage` requires the
                # mechanism to be covered by a unit test in that case, so a skip cannot become a silent hole.
                results.append({"name": name, "mechanism": mechanism, "exit_code": None, "skipped": str(reason),
                                "evidence": "", "command": ""})
                continue
            (case / "status.json").write_text(json.dumps(status, ensure_ascii=False), encoding="utf-8")
            (case / "ownership.json").write_text(json.dumps(ownership, ensure_ascii=False), encoding="utf-8")
            (case / "artifact.json").write_text(json.dumps(artifact_copy, ensure_ascii=False), encoding="utf-8")
            command = [sys.executable, str(pathlib.Path(__file__).resolve()), "--step", step,
                       "--status", str(case / "status.json"), "--ownership", str(case / "ownership.json"),
                       "--artifact", str(case / "artifact.json"), "--files", *list(artifact.get("changed_files") or []),
                       "--no-self-test"]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            # The evidence is the validator's OWN stated reason, taken from the real subprocess output. `--quiet` is
            # deliberately NOT passed: a control whose evidence is blank is a control nobody can audit.
            lines = [line.strip() for line in (completed.stdout or completed.stderr).splitlines() if line.strip()]
            evidence = next((line for line in lines if line.startswith("VIOLATION")), lines[-1] if lines else "")
            results.append({"name": name, "mechanism": mechanism, "exit_code": completed.returncode,
                            "evidence": evidence, "command": " ".join(command[1:])})
            if completed.returncode == 0:
                print(f"SELF-TEST FAILED: tamper {name} ({mechanism}) was ACCEPTED")
                for item in results:
                    print(f"  {item['name']:38s} {item['mechanism']} exit={item['exit_code']}")
                if json_path:
                    write_artifact(json_path, {"step": step, "results": results, "verdict": "TAMPER_ACCEPTED"})
                return 1
    print(f"self-test: {len([item for item in results if not item.get('skipped')])} tamper(s) rejected, "
          f"{len([item for item in results if item.get('skipped')])} skipped (mechanism not exercised by this step)")
    for item in results:
        detail = item.get("skipped") or f"exit={item['exit_code']}"
        print(f"  {item['name']:38s} {item['mechanism']} {detail}")
    if json_path:
        write_artifact(json_path, {"step": step, "results": results, "verdict": "ALL_TAMPERS_REJECTED"})
    return 0


def write_artifact(path: pathlib.Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def load(path: pathlib.Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--step", required=True)
    parser.add_argument("--status", type=pathlib.Path, default=STATUS)
    parser.add_argument("--ownership", type=pathlib.Path, default=OWNERSHIP)
    parser.add_argument("--artifact", type=pathlib.Path, default=None)
    parser.add_argument("--files", nargs="*", default=[])
    parser.add_argument("--json", type=pathlib.Path, default=None)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-json", type=pathlib.Path, default=None,
                        help="write every tamper's real exit code for the step artifact")
    parser.add_argument("--no-self-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    status = load(args.status, {})
    ownership = load(args.ownership, {})
    artifact_path = args.artifact or (ARTIFACT_DIR / f"{args.step}-artifact.json")
    artifact = load(artifact_path, {})

    # The ownership lock's own `files` table decides which paths this step may take; `--files` adds the ones the caller
    # intends to touch and must therefore ALSO be unlocked.
    files = list(dict.fromkeys([*args.files, *[str(item) for item in artifact.get("changed_files") or []]]))

    violations = validate(args.step, status, ownership, artifact, files)
    report = {
        "step": args.step,
        "plan": PLAN.as_posix(),
        "plan_sha256": sha256_file(PLAN) if PLAN.is_file() else "",
        "preflight_source_sha256": sha256_file(pathlib.Path(__file__).resolve()),
        "validation_input_sha256": sha256_text(json.dumps({"status": status, "ownership": ownership,
                                                          "artifact": artifact, "files": files},
                                                         sort_keys=True, default=str)),
        "source_sha": _git("rev-parse", "HEAD").strip(),
        # The ACTUAL changed-file set is recomputed from git here rather than copied from the artifact, so the report
        # cannot inherit a hand-typed list (plan M6: "实际 changed-file 集合").
        "changed_files": sorted(line[3:].strip() for line in
                                _git("status", "--porcelain", "--untracked-files=all").splitlines()
                                if line.strip() and line[:2].strip() in {"M", "A", "D", "R"}),
        "files_checked": files,
        "artifact": artifact_path.as_posix(),
        "violations": list(violations),
        "verdict": "BLOCKED" if violations else "READY",
    }
    if args.json:
        write_artifact(args.json, report)

    if not args.quiet:
        print(f"step {args.step}: {report['verdict']}")
        print(f"  plan_sha256        {report['plan_sha256'][:16]}")
        print(f"  preflight sha256   {report['preflight_source_sha256'][:16]}")
        print(f"  input sha256       {report['validation_input_sha256'][:16]}")
        print(f"  files checked      {files}")
        for violation in violations:
            print(f"  VIOLATION {violation}")
        if not violations:
            print("  no violation: the step may advance")

    if args.self_test and not args.no_self_test:
        if not artifact:
            print("self-test requires a generated artifact to tamper with")
            return 1
        return run_self_test(args.step, artifact, args.self_test_json)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
