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
#: responsibilities (creation / lifecycle / budget / cancellation / the limitation and outcome projections), EXCLUDING
#: the five the plan moved in P3.2a/P3.2b. The list is spelled out rather than matched by substring so the derivation
#: below cannot drift when an unrelated method happens to be named `...lifecycle...`.
#:
#: SOME OF THESE HAVE SINCE MOVED, and that is expected rather than stale: P3.2c-P3.2g moved most of them, and other
#: P3.3 slices moved a few more (`_convergence_failure_contract`, for instance, went to `investigation/coordinator.py`
#: in P3.3d). The derivation tolerates it BY DESIGN - P3.2f changed the assertion from "the port equals the candidate
#: spine" to two-sided ones precisely because a moved member stops contributing port surface - so a name here may be a
#: delegation. What the pin still guarantees is that no candidate needs anything OFF the port and that no port member
#: is unused.
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


def test_the_port_is_exactly_what_the_task_path_needs() -> None:
    """Two-sided: nothing OFF the port is needed, and nothing ON it is unused.

    THIS TEST CHANGED SHAPE IN P3.2f, and the reason matters. Its original form asserted that the port equalled the
    direct spine of the FROZEN CANDIDATE SET. That was right while the candidates were the cluster under
    consideration; once P3.2c-P3.2f moved them, most candidates became one-line delegations, so the candidate spine
    shrank (a delegation that calls `_task_runner.<fn>` touches no port member) and the equality became false for a
    legitimate reason. Loosening it to a subset would have been the weak fix; instead the property the pin was always
    trying to state is now stated directly and in both directions:

      * `remaining <= port` - no still-unmoved candidate reaches anything off the port (drift still fails here);
      * `remaining | used_by_moved_code == port` - and the port has no member nothing uses.
    """
    runner = RUNNER_MODULE.read_text(encoding="utf-8", errors="replace")
    remaining = _direct_spine(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    used_by_moved_code = {
        node.attr
        for node in ast.walk(ast.parse(runner))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "host"
    }
    off_port = remaining - set(TASK_HOST_MEMBERS)
    assert not off_port, (
        f"a task candidate that has NOT moved yet reaches {sorted(off_port)}, which is not on the port; add it to "
        "TASK_HOST_MEMBERS and to the TaskHost declaration deliberately, and record why"
    )
    unused = set(TASK_HOST_MEMBERS) - (remaining | used_by_moved_code)
    assert not unused, (
        f"{sorted(unused)} are on the port but nothing uses them (neither the moved code nor a remaining candidate); "
        "a port member nobody needs is speculative surface"
    )
    assert (remaining | used_by_moved_code) == set(TASK_HOST_MEMBERS)


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
    """Both directions for `missing_task_host_members`, and it must NOT hard-code the port's size.

    The first version of this test listed the six members a stub happened to be missing, so the deliberate P3.2g
    widening (six -> nine) broke it in a way that said nothing about the function under test. It is now built FROM
    `TASK_HOST_MEMBERS`: a stub missing two named members must report exactly those two, and a stub providing all of
    them must report nothing. The first half is the can-fail proof (a function that always returned `()` fails it);
    the second half catches a function that over-reports.
    """
    missing_two = ("task_view", "_require_session_id")  # in TASK_HOST_MEMBERS declaration order
    complete = type(
        "Complete", (), {name: (lambda self: None) for name in TASK_HOST_MEMBERS}
    )
    partial = type(
        "Partial", (), {name: (lambda self: None) for name in TASK_HOST_MEMBERS if name not in missing_two}
    )
    assert missing_task_host_members(complete()) == ()
    assert missing_task_host_members(partial()) == missing_two


def test_the_runner_module_is_the_port_plus_the_moved_clusters_and_nothing_else() -> None:
    """The module's defined surface is PINNED, so a second implementation cannot hide here unnoticed.

    P3.2-design: port only. Then one cluster per step, in the measured order: `creation` (P3.2c, with the
    `SubmissionResult` dataclass that is its return type), `lifecycle` (P3.2d), `budget` (P3.2e, including the
    `@staticmethod`), `cancellation` (P3.2f) and workbench binding (P3.2g). Every addition is a deliberate act, and
    this list growing without a matching step record is the thing it exists to catch.
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
        "bind_historical_analysis",
        "cancel_task",
        "cancel_tool_run",
        "create_submission_task",
        "missing_task_host_members",
        "prepare_blind_run",
        "workbench_bind_existing_analysis",
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
    assert host_refs == set(TASK_HOST_MEMBERS), (
        "the clusters moved so far should now cover the WHOLE port - cancellation reaches every member, including "
        f"`_seal_task_audit_chain`, which only it needs - but the measured set is {sorted(host_refs)}"
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
                 "_actual_depth", "cancel_task", "cancel_tool_run", "bind_historical_analysis",
                 "workbench_bind_existing_analysis"):
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


def test_the_p3_2g_port_widening_is_still_visible_and_still_justified() -> None:
    """The ONE deliberate widening, pinned. It replaced a deferral pin, and the deferral's reason is what it records.

    MEASURED BEFORE P3.2g (`.scratch/p32-creation-analysis.py` and `p32-measure-cluster.py`): the workbench-binding
    pair was deferred out of P3.2c because `bind_historical_analysis` is a 2-line forwarder and
    `workbench_bind_existing_analysis` needs THREE host helpers that were not on the port
    (`_context_payload_v3`, `_context_state_for_task_v3`, `_require_session_id`). P3.2g then widened the port from six
    to nine ON PURPOSE. This pin keeps that widening honest in the direction that matters: the three helpers must STILL
    be host operations (they were not moved - they are the port's new surface), and they must still be declared on
    `TaskHost`, so the port cannot quietly lose the members that forced the widening.
    """
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AnalysisService")
    methods = {
        node.name: node for node in service.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for helper in ("_context_payload_v3", "_context_state_for_task_v3", "_require_session_id"):
        assert helper in methods, (
            f"{helper} is gone from AnalysisService; the P3.2g widening assumed it stays a HOST operation - if it "
            "moved, the port declaration and this pin change together"
        )
        assert helper in TASK_HOST_MEMBERS, f"{helper} is no longer declared on the port"
    declared = _protocol_members()
    for helper in ("_context_payload_v3", "_context_state_for_task_v3", "_require_session_id"):
        assert helper in declared, f"{helper} is in the pin but not declared on TaskHost"
