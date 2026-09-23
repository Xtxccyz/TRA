"""P3.2 design contract: the task path's port must be exactly the spine it was measured from.

Plan 7.1 step 2 says to stand up the minimal interface and its contract test in the new package BEFORE moving any
implementation, so this file pins the interface while nothing depends on it yet. It is written this way on purpose:

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


def test_the_runner_module_is_an_interface_and_not_a_second_implementation() -> None:
    """No behaviour, no host import, and no hidden copy of a task method."""
    source = RUNNER_MODULE.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    defined = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert sorted(defined) == ["TaskHost", "missing_task_host_members"], (
        f"task_runner.py defines {defined}; until P3.2c moves the first cluster it must declare the port and nothing "
        "else, so a second implementation cannot hide here"
    )
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
