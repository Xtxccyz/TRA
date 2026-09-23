"""P3.2 contract: the task path's port, and the first cluster that moved behind it.

Plan 7.1 step 2 is "stand up the minimal interface and its contract test before moving any implementation"
(P3.2-design); step 3 is "move the one implementation" - the `creation` cluster in P3.2c and the `lifecycle` cluster
(`archive_case`) in P3.2d, now in `task/task_runner.py`, with their service.py methods reduced to one-statement
delegations. This file pins both, and it is written this way on purpose:

  * `TASK_HOST_MEMBERS` is not trusted as a literal. `_direct_spine()` re-derives it from `service.py` on every run,
    using a FROZEN candidate list (no name heuristic), and the test fails if the derivation and the port disagree.
    That makes the pin a drift detector with a real subject: if a candidate starts touching a new outside member -
    or the port grows a member no candidate needs - the port has to be updated deliberately.
  * The criterion is "directly touched AND used by at least one method OUTSIDE the candidate set", which is the
    difference between a port and a copy of the class. Two synthetic cases pin both halves of that criterion, so a
    derivation that degenerates into "everything" or into "nothing" cannot pass quietly.

MEASURED (`.scratch/p32design-candidates.py`, `.scratch/p32design-scale.py`): 19 candidates / 585 lines, helper
closure 18 members / 1,040 lines of which only one (90 lines) travels with the cluster, direct spine exactly 6.
Outside-user counts for the 6, which is what makes the port small rather than arbitrary: `database` 86,
`_audit` 52, `settings` 34, `content_store` 24, `_seal_task_audit_chain` 6, `task_view` 1.

MEASURED FOR P3.2c (`.scratch/p32c-creation-analysis.py`), and it changed the step's scope rather than being fitted to
it: the creation cluster's host needs are only `_audit`, `content_store`, `database` (a subset of the port, so NO
widening), but its return type `SubmissionResult` was DEFINED in service.py and had to travel with it, and the
`bind_historical_analysis` / `workbench_bind_existing_analysis` pair had to stay behind (2-line forwarder plus 90
lines needing three further host helpers). Both facts are pinned below.

    python -m pytest -q tests/test_task_runner_contract.py
"""
from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService
from threat_report_agent.task.task_runner import (
    TASK_HOST_MEMBERS,
    TaskHost,
    missing_task_host_members,
)

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "threat_report_agent"
SERVICE_MODULE = PACKAGE / "service.py"
RUNNER_MODULE = PACKAGE / "task" / "task_runner.py"

#: FROZEN, from `.scratch/p32design-candidates.py`. Every `AnalysisService` member that belongs to plan P3.2's task
#: responsibilities (creation / lifecycle / budget / cancellation / the limitation and outcome projections) and is
#: still a real implementation, i.e. excluding the five the plan moved in P3.2a/P3.2b. The list is spelled out rather
#: than matched by substring so the derivation below cannot drift when an unrelated method happens to be named
#: `...lifecycle...`.
CANDIDATES: tuple[str, ...] = (
    "_actual_depth",
    "_apply_honest_analysis_outcome",
    "_completion_limitations",
    "_convergence_failure_contract",
    "_deferred_budget_thread_ids",
    "_failed_tool_run_limitations",
    "_failure_payload",
    "_is_task_cancelled",
    "_merge_operational_limitations",
    "_parent_process_attribute_token",
    "_persist_partial_how_ready",
    "_record_analysis_failure",
    "_static_decode_recovery_from_limitations",
    "archive_case",
    "bind_historical_analysis",
    "cancel_task",
    "cancel_tool_run",
    "create_submission_task",
    "prepare_blind_run",
)


def _class_methods(source: str, class_name: str = "AnalysisService") -> dict[str, ast.AST]:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                child.name: child
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError(f"{class_name} is not a top-level class any more; the derivation is stale")


def _touched(node: ast.AST) -> set[str]:
    return {
        child.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "self"
    }


def _direct_spine(source: str, candidates: tuple[str, ...] = CANDIDATES) -> set[str]:
    """The port a task cluster needs: members it touches directly that an OUTSIDE method also uses.

    A member only the candidates use is not a port, it is something that would travel with the cluster; that is why
    the outside-user test is part of the definition rather than a bonus check.
    """
    methods = _class_methods(source)
    candidate_set = set(candidates)
    users: dict[str, list[str]] = defaultdict(list)
    for name, node in methods.items():
        for member in _touched(node):
            users[member].append(name)

    spine: set[str] = set()
    for name in candidates:
        if name not in methods:
            continue
        spine |= {
            member
            for member in _touched(methods[name])
            if member not in candidate_set and any(user not in candidate_set for user in users[member])
        }
    return spine


def _protocol_members() -> set[str]:
    """The port's declared members, read from the module's own AST (attributes and methods alike)."""
    tree = ast.parse(RUNNER_MODULE.read_text(encoding="utf-8", errors="replace"))
    protocol = next(
        node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "TaskHost"
    )
    declared = {
        child.target.id
        for child in protocol.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    }
    declared |= {
        child.name for child in protocol.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return declared


@pytest.fixture
def facade(test_settings) -> AnalysisService:  # noqa: ANN001 - the fixture type is Settings from conftest
    """Construct the facade the way the HTTP path does: settings + database + content store."""
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    return service


def test_every_frozen_candidate_still_exists() -> None:
    """A derivation whose inputs vanished would pass vacuously, so the inputs are asserted first."""
    methods = _class_methods(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    missing = [name for name in CANDIDATES if name not in methods]
    assert not missing, (
        f"{missing} are no longer `AnalysisService` methods; the frozen candidate list is stale, so re-measure with "
        "`.scratch/p32design-candidates.py` rather than deleting the names"
    )


def test_the_port_is_exactly_the_measured_direct_spine() -> None:
    derived = _direct_spine(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    assert derived == set(TASK_HOST_MEMBERS), (
        "the task port and the measured spine disagree: "
        f"derived={sorted(derived)} port={sorted(TASK_HOST_MEMBERS)}. A new member means a task cluster started "
        "reaching outside the port - widen the port deliberately (and record why) instead of loosening this test"
    )


def test_the_declared_protocol_matches_the_pin() -> None:
    assert len(set(TASK_HOST_MEMBERS)) == len(TASK_HOST_MEMBERS), "the pin has a duplicate member"
    assert _protocol_members() == set(TASK_HOST_MEMBERS), (
        f"TaskHost declares {sorted(_protocol_members())} but the pin is {sorted(TASK_HOST_MEMBERS)}"
    )


def test_the_derivation_reports_a_new_reach_and_ignores_a_cluster_private_member() -> None:
    """Both halves of the criterion, on a synthetic class: an outside-used member is in, a cluster-only one is not.

    Without this, a derivation that returned every touched member (or none) would satisfy the equality test above
    only by accident of the current numbers.
    """
    source = (
        "class AnalysisService:\n"
        "    def helper(self): pass\n"
        "    def outside_user(self):\n"
        "        self.policy\n"
        "    def create_submission_task(self):\n"
        "        self.policy\n"
        "        self.cluster_private\n"
        "    def cancel_task(self):\n"
        "        self.cluster_private\n"
    )
    assert _direct_spine(source) == {"policy"}, (
        "the derivation must report a member an OUTSIDE method uses (`policy`) and ignore one only the candidates "
        "use (`cluster_private`, which travels with the cluster instead of widening the port)"
    )


def test_analysis_service_satisfies_the_port(facade: AnalysisService) -> None:
    """The host the port describes is the real one: every member is present on a constructed facade."""
    assert missing_task_host_members(facade) == ()


def test_a_host_missing_a_member_is_reported_rather_than_accepted() -> None:
    """The can-fail proof for `missing_task_host_members`: it must report, not silently approve."""

    class Partial:
        settings = object()
        database = object()
        content_store = object()

        def _audit(self) -> None: ...

    reported = missing_task_host_members(Partial())
    assert reported == ("_seal_task_audit_chain", "task_view"), reported


def test_the_runner_module_is_the_port_plus_the_creation_cluster_and_nothing_else() -> None:
    """The module's defined surface is PINNED, so a second implementation cannot hide here unnoticed.

    P3.2-design: port only. P3.2c added exactly the `creation` cluster - its two functions and the dataclass that is
    their return type - so this list growing is a deliberate act.
    """
    source = RUNNER_MODULE.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    defined = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert sorted(defined) == [
        "SubmissionResult",
        "TaskHost",
        "_actual_depth",
        "_deferred_budget_thread_ids",
        "archive_case",
        "create_submission_task",
        "missing_task_host_members",
        "prepare_blind_run",
    ], f"task_runner.py defines {sorted(defined)}; update this pin with the step that changed it"
    imported = {
        (node.module or "").split(".")[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert "service" not in imported, (
        "the port must not import its host: that would recreate the `task -> service` edge the split exists to avoid"
    )
    assert "main" not in imported
    assert isinstance(TaskHost, type)


def test_the_moved_cluster_reaches_the_host_only_through_the_port() -> None:
    """The anti-drift check on the MOVED code: every `host.X` in this module must be a declared port member.

    This is the one check that makes the port real rather than decorative. The design step measured that the
    creation cluster needs only `_audit`, `database` and `content_store` - a subset of the port - so this move
    needed no widening. If a later edit reaches for anything else, this fails and the widening becomes deliberate.
    """
    tree = ast.parse(RUNNER_MODULE.read_text(encoding="utf-8", errors="replace"))
    host_refs = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "host"
    }
    assert host_refs, "the moved cluster no longer touches `host` at all; either it moved again or this test is stale"
    assert host_refs <= set(TASK_HOST_MEMBERS), (
        f"the moved cluster reaches {sorted(host_refs - set(TASK_HOST_MEMBERS))}, which is not on the port; add it to "
        "TASK_HOST_MEMBERS AND to the TaskHost declaration deliberately, and record why"
    )
    assert host_refs == {"_audit", "content_store", "database", "task_view"}, (
        "the measured needs of the clusters moved so far were _audit/content_store/database (creation) plus "
        f"task_view (budget), now {sorted(host_refs)}"
    )


def test_submission_result_has_one_implementation_and_keeps_its_public_path() -> None:
    """The dataclass MOVED out of service.py, so both facts have to be pinned: one implementation, same public path.

    MEASURED before the move: `SubmissionResult` was defined in service.py (a dependency-free frozen dataclass) and
    is the creation cluster's return type, so the cluster could not leave without it. Re-exporting keeps
    `threat_report_agent.service.SubmissionResult` - and every one of service.py's own uses - working unchanged.
    """
    from threat_report_agent.service import SubmissionResult as from_service
    from threat_report_agent.task.task_runner import SubmissionResult as from_runner

    assert from_service is from_runner, "the re-export created a second class object"
    assert from_runner.__module__ == "threat_report_agent.task.task_runner"
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    assert "SubmissionResult" not in [node.name for node in tree.body if isinstance(node, ast.ClassDef)], (
        "service.py defines SubmissionResult again; the moved implementation must have exactly one home"
    )


def test_the_service_methods_are_one_statement_delegations() -> None:
    """Plan 7.1 step 4: the old path may keep a shim, never a second implementation."""
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AnalysisService")
    methods = {
        node.name: node for node in service.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in ("create_submission_task", "prepare_blind_run", "archive_case", "_deferred_budget_thread_ids",
                 "_actual_depth"):
        node = methods[name]
        assert len(node.body) == 1, f"{name} has {len(node.body)} statements; it is supposed to delegate only"
        statement = ast.unparse(node.body[0])
        assert statement.startswith(f"return _task_runner.{name}("), f"{name} does not delegate to the new module: {statement}"
        decorated = [ast.unparse(d) for d in node.decorator_list]
        if decorated == ["staticmethod"]:
            # `_actual_depth` has NO receiver at all (measured in P3.2e), so the delegation must not invent one.
            assert "self" not in statement, f"{name} is static but forwards `self`: {statement}"
        else:
            assert not decorated, f"{name} gained decorators {decorated}; re-measure before trusting this pin"
            assert "self" in statement, f"{name} must forward the host, not call the module function bare"


def test_the_workbench_binding_pair_is_still_on_the_host_and_that_is_recorded() -> None:
    """A MEASURED DEFERRAL, pinned so it cannot be moved by accident and cannot be forgotten either.

    Measured by `.scratch/p32c-creation-analysis.py`: `bind_historical_analysis` is a 2-line forwarder to
    `workbench_bind_existing_analysis`, whose 90 lines need THREE host helpers that are not on the port
    (`_context_payload_v3`, `_context_state_for_task_v3`, `_require_session_id`). Moving them therefore widens the
    port, which is a deliberate step of its own - not something to smuggle into the creation move.
    """
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AnalysisService")
    methods = {
        node.name: node for node in service.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in ("bind_historical_analysis", "workbench_bind_existing_analysis"):
        assert name in methods, f"{name} left service.py without this pin being updated - see the docstring"
    for helper in ("_context_payload_v3", "_context_state_for_task_v3", "_require_session_id"):
        assert helper in methods, f"{helper} is gone, so the deferral's reason no longer holds; re-measure"
    assert len(methods["bind_historical_analysis"].body) == 1, "the forwarder gained a body; re-measure before moving"
