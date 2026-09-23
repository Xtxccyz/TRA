"""P3.3 contract: the investigation slices' port, the slices behind it, and the members that had to STAY.

Plan 7.1 step 2 is "stand up the minimal interface and its contract test before moving any implementation"; P3.3's
slices follow P3.2's recipe (`docs/p33-investigation-coordinator-design-20260922.md`), and this file pins the four that
have moved: P3.3b (frontier helpers), P3.3a (the ledger), P3.3c (action proposal) and P3.3d (convergence).

MEASURED, and it is why P3.3b's slice is smaller than the fragment scan suggested: four members that the scan grouped
with it stay on the host. `_is_unique_thread_seed_row`, `_unique_thread_start_keys` and
`_unique_execution_threads_for_view` read `_address_lookup_keys` / `build_unique_execution_threads` from
`report/reporting.py`, and plan 3.2's allowed-dependency matrix lets `investigation/` import only contracts, facts,
static/emulation/tools interfaces and the model port - "未列出的边默认禁止". `_select_unique_thread_seed_rows` stays
with them because it calls two of them. Moving those four would have created a NEW forbidden
`investigation -> report` edge; that is pinned below so a later step cannot do it by accident. (MEASURED afterwards:
the repository contains exactly ONE `investigation -> report` import, `investigation/persist_how.py`, and it is the
one recorded in `docs/import-policy.json`'s `known_violations` - so the first attempt would have made a known
violation worse.)

The port is SIX members: `database` and `_audit` (P3.3b/P3.3a), `_MAX_COMPLETED_ACTION_EVIDENCE_IDS` (P3.3c), and the
convergence slice's three (P3.3d: `_canonical_json` plus two annotated class constants).

    python -m pytest -q tests/test_investigation_coordinator_contract.py
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation.coordinator import (
    INVESTIGATION_HOST_MEMBERS,
    InvestigationHost,
    missing_investigation_host_members,
)
from threat_report_agent.service import AnalysisService

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "threat_report_agent"
SERVICE_MODULE = PACKAGE / "service.py"
COORDINATOR_MODULE = PACKAGE / "investigation" / "coordinator.py"

MOVED_MEMBERS = (
    # P3.3b
    "_build_investigation_frontier",
    "_convergence_frontier_fingerprint",
    "_frontier_value_present",
    "_unattempted_seed_thread_ids",
    "_mechanism_missing_fields",
    # P3.3a (the ledger slice; MEASURED host needs `database` + `_audit`)
    "_persist_evidence_delivery_ledger",
    "_finalize_tail_ledger",
    "_park_open_ledger",
    "_work_ledger",
    "_ledger_ids",
    # P3.3c (action-proposal validation; the tool FIRST reported "host need: NONE" and the contract test below is
    # what corrected it - `_bound_completed_actions` reads the host's `_MAX_COMPLETED_ACTION_EVIDENCE_IDS` through
    # `cls.`, which the measurement missed while it scanned only `self.`)
    "_grounded_planner_action_candidates",
    "_action_payload",
    "_deterministic_action_plan",
    "_planner_user_action",
    "_bound_completed_actions",
    # P3.3d (the convergence slice; MEASURED host needs: the shared `_canonical_json` helper and two CLASS constants)
    "_convergence_failure_contract",
    "_build_convergence_alternate",
    "_convergence_completed_fields",
    "_convergence_alternate_type",
    "_convergence_method_id",
)
MOVED_MODULE_FUNCS = ("frontier_status_is_open", "deferred_keeps_planner_open")
#: Stayed on the host: moving them would need `report.reporting`, which plan 3.2 does not allow `investigation/` to
#: import. `_select_unique_thread_seed_rows` calls two of them, so it stays too.
STAYED_MEMBERS = (
    "_is_unique_thread_seed_row",
    "_unique_thread_start_keys",
    "_unique_execution_threads_for_view",
    "_select_unique_thread_seed_rows",
)
ORIGINAL_DECORATORS = {
    "_build_investigation_frontier": ["classmethod"],
    "_convergence_frontier_fingerprint": ["classmethod"],
    "_frontier_value_present": ["staticmethod"],
    "_unattempted_seed_thread_ids": [],
    "_mechanism_missing_fields": ["classmethod"],
    "_persist_evidence_delivery_ledger": [],
    "_finalize_tail_ledger": [],
    "_park_open_ledger": [],
    "_work_ledger": [],
    "_ledger_ids": ["staticmethod"],
    "_grounded_planner_action_candidates": ["classmethod"],
    "_action_payload": ["staticmethod"],
    "_deterministic_action_plan": ["staticmethod"],
    "_planner_user_action": [],
    "_bound_completed_actions": ["classmethod"],
    "_convergence_failure_contract": ["classmethod"],
    "_build_convergence_alternate": ["classmethod"],
    "_convergence_completed_fields": ["classmethod"],
    "_convergence_alternate_type": ["classmethod"],
    "_convergence_method_id": ["classmethod"],
}
#: Stayed on the host from the methodology half of the P3.3d slice. TWO measured blockers, either of which is enough:
#:   * `_run_methodology_action` needs `threat_report_agent.methodology` (`DIMENSIONS`, `build_profile`), and that
#:     module is imported by ONE layer only (service.py) - MEASURED against the established shared primitives, which
#:     span several layers (`models` 5, `config` 5, `runtime_contracts` 3, `contracts` 2). So
#:     `investigation -> methodology` is an unlisted edge with no precedent;
#:   * it reads the MODULE-LEVEL `REFERENCE_ISOLATED_FACT_LIBRARY`, which is also read by `_freeze_blind_run_snapshot`
#:     (an un-moved method), so it cannot travel with the slice and this module may not import it.
#: It would also need five more port members (three shared helpers plus `_METHODOLOGY_EVIDENCE_LIMIT` and the
#: `methodology_library` attribute), which is recorded rather than acted on.
STAYED_FROM_P3_3D = ("_run_methodology_action",)
#: Stayed on the host from the action-proposal slice, each for a MEASURED reason (this is P3.3c(2)):
#: `_model_action_plan` and `_action_is_model_or_human` need a RUNTIME import (`isinstance` / a call) from a layer the
#: matrix does not allow `investigation/` to import.
#: UPDATED by P3.3 layer item 1: the reason recorded for `_action_is_model_or_human` (the edge would be a CYCLE, because
#: `task.analysis_task_orchestration` imports `investigation`) NO LONGER HOLDS - `action_is_model_or_human` now lives in
#: this package (`investigation/loop_path.py`), so that member's blocker is gone. `_model_action_plan`'s blocker
#: (`DynamicPlanAction` at run time) is unchanged, and the tuple below is a HISTORICAL list of what stayed in P3.3c,
#: not a claim about the current blockers.
#: `_has_complete_model_action_plan` and `_merge_planned_actions` name `DynamicPlanAction` in ANNOTATIONS only, so a
#: TYPE_CHECKING import would do - deliberately NOT taken here, because the clean fix is for the model PORT to expose
#: that type (plan P1.2's `ports.py` does not today), and a type-only edge to an unlisted layer is a decision that
#: belongs with that fix rather than smuggled into a move.
STAYED_FROM_P3_3C = (
    "_model_action_plan",
    "_has_complete_model_action_plan",
    "_merge_planned_actions",
    "_action_is_model_or_human",
)


@pytest.fixture
def facade(test_settings) -> AnalysisService:  # noqa: ANN001 - the fixture type is Settings from conftest
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    return service


def _service_class() -> ast.ClassDef:
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    return next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AnalysisService")


def _protocol_members() -> set[str]:
    tree = ast.parse(COORDINATOR_MODULE.read_text(encoding="utf-8", errors="replace"))
    protocol = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "InvestigationHost")
    declared = {
        child.target.id for child in protocol.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    }
    declared |= {child.name for child in protocol.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))}
    return declared


def test_the_coordinator_module_defines_exactly_the_port_and_the_moved_slice() -> None:
    tree = ast.parse(COORDINATOR_MODULE.read_text(encoding="utf-8", errors="replace"))
    defined = sorted(
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    assert defined == sorted(
        ["InvestigationHost", "missing_investigation_host_members", *MOVED_MEMBERS, *MOVED_MODULE_FUNCS]
    ), f"coordinator.py defines {defined}; update this pin with the step that changed it"
    assigned = {
        target.id for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    assert {"_FRONTIER_CLOSED_STATUSES", "_PLANNER_CLOSED_DEFERRED_REASONS"} <= assigned, (
        "the two frozensets the moved predicates close over must live HERE: they are closure state of functions that "
        "moved, and this module may not import service to reach them"
    )
    imported_modules = {
        (node.module or "") for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {a.name for node in ast.walk(tree) if isinstance(node, ast.Import) for a in node.names}
    assert "service" not in {m.split(".")[-1] for m in imported_modules}, (
        "the coordinator must never import its host: that would recreate the `investigation -> service` edge"
    )
    assert not any(m.startswith("threat_report_agent.report") for m in imported_modules), (
        "plan 3.2's matrix does not let `investigation/` import `report/` (未列出的边默认禁止). If a slice needs "
        "`report.reporting`, the shared helper must be pushed to a lower layer FIRST - see the module docstring."
    )
    assert isinstance(InvestigationHost, type)


def test_the_port_matches_the_pin_and_is_fully_used() -> None:
    assert len(set(INVESTIGATION_HOST_MEMBERS)) == len(INVESTIGATION_HOST_MEMBERS), "the pin has a duplicate"
    assert INVESTIGATION_HOST_MEMBERS == (
        "database",
        "_audit",
        "_MAX_COMPLETED_ACTION_EVIDENCE_IDS",
        "_CONVERGENCE_ALTERNATES",
        "_CONVERGENCE_EXPECTED_KINDS",
        "_canonical_json",
    ), (
        "the port is `database` (P3.3b) + `_audit` (P3.3a's ledger) + `_MAX_COMPLETED_ACTION_EVIDENCE_IDS` (P3.3c) + "
        "the convergence slice's three (P3.3d: two class constants and the shared `_canonical_json` helper); widening "
        "it further needs a measured reason in the step's findings"
    )
    assert _protocol_members() == set(INVESTIGATION_HOST_MEMBERS), (
        f"InvestigationHost declares {sorted(_protocol_members())} but the pin is {sorted(INVESTIGATION_HOST_MEMBERS)}"
    )
    refs = {
        node.attr for node in ast.walk(ast.parse(COORDINATOR_MODULE.read_text(encoding="utf-8", errors="replace")))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "host"
    }
    assert refs == set(INVESTIGATION_HOST_MEMBERS), (
        f"the moved slice's host references {sorted(refs)} do not equal the port "
        f"{sorted(INVESTIGATION_HOST_MEMBERS)}"
    )


def test_analysis_service_satisfies_the_port(facade: AnalysisService) -> None:
    assert missing_investigation_host_members(facade) == ()


def test_a_host_missing_a_member_is_reported_rather_than_accepted() -> None:
    complete = type("Complete", (), {n: (lambda self: None) for n in INVESTIGATION_HOST_MEMBERS})
    partial = type("Partial", (), {})
    assert missing_investigation_host_members(complete()) == ()
    assert missing_investigation_host_members(partial()) == INVESTIGATION_HOST_MEMBERS


def test_the_moved_members_are_one_statement_delegations_with_their_original_shape() -> None:
    """Every moved member delegates in ONE statement, keeps its call shape, and passes a host only if one is needed.

    MEASURED against the module's own signatures rather than a hand-written table, because P3.3c added a shape the
    earlier tests could not express: `_planner_user_action` is a plain INSTANCE method whose moved body needs no host
    at all. Its delegation must therefore KEEP `self` (or every existing `service._planner_user_action(...)` call would
    shift its arguments) while NOT forwarding it (the module function takes no host, so forwarding would raise).
    """
    import inspect

    from threat_report_agent.investigation import coordinator as coordinator_module

    methods = {
        node.name: node for node in _service_class().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in MOVED_MEMBERS:
        node = methods[name]
        assert len(node.body) == 1, f"{name} has {len(node.body)} statements; it is supposed to delegate only"
        statement = ast.unparse(node.body[0])
        assert statement.startswith(f"return _coordinator.{name}("), f"{name} does not delegate: {statement}"
        decorators = [ast.unparse(d) for d in node.decorator_list]
        assert decorators == ORIGINAL_DECORATORS[name], f"{name} changed call shape: {decorators}"

        parameters = list(inspect.signature(getattr(coordinator_module, name)).parameters)
        takes_host = bool(parameters) and parameters[0] == "host"
        # The forwarded receiver is the member's OWN first parameter, which is `cls` for a classmethod and `self` for
        # an instance method. Requiring the literal string "self" failed on `_bound_completed_actions` even though its
        # delegation was correct - a test that encodes one receiver name cannot check both shapes.
        own_receiver = node.args.args[0].arg if node.args.args else None
        if takes_host:
            assert own_receiver is not None, f"{name} has no receiver to forward but its module function needs a host"
            assert f"{own_receiver}," in statement or f"({own_receiver})" in statement, (
                f"{name} needs a host but does not forward its own receiver `{own_receiver}`: {statement}"
            )
        else:
            assert "self" not in statement and "cls" not in statement, (
                f"{name} forwards a receiver but its module function takes no host (that would raise): {statement}"
            )
        if decorators in ([], ["classmethod"]):
            receiver = "cls" if decorators == ["classmethod"] else "self"
            assert receiver in [a.arg for a in node.args.args[:1]], (
                f"{name} lost its `{receiver}` parameter, which changes how every existing caller must call it"
            )


def test_the_methodology_member_that_could_not_move_stayed_whole_with_measured_reasons() -> None:
    """P3.3d(2), pinned: `_run_methodology_action` stays because of LAYER and shared-STATE rules, not by oversight."""
    methods = {
        node.name: node for node in _service_class().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in STAYED_FROM_P3_3D:
        node = methods[name]
        assert "_coordinator." not in ast.unparse(node), f"{name} was moved after all; re-measure the layer rule"
        assert len(node.body) > 1, f"{name} looks like a delegation now, but this slice left it whole"
    source = ast.unparse(methods["_run_methodology_action"])
    assert "REFERENCE_ISOLATED_FACT_LIBRARY" in source, (
        "the module-level fact library is no longer read by `_run_methodology_action`; the second blocker changed, so "
        "re-measure before moving it"
    )
    service_text = SERVICE_MODULE.read_text(encoding="utf-8", errors="replace")
    assert "from threat_report_agent.methodology import" in service_text
    for investigation_module in (PACKAGE / "investigation").glob("*.py"):
        assert "threat_report_agent.methodology" not in investigation_module.read_text(
            encoding="utf-8", errors="replace"
        ), (
            f"{investigation_module.name} imports `methodology`; that edge has no precedent today (only service.py "
            "imports it), so if it was added deliberately the P3.3d(2) blocker must be re-measured"
        )


def test_no_call_omits_the_host_a_sibling_requires() -> None:
    """The ARITY pin, added after P3.3d shipped a silent behaviour change nothing else could see.

    MEASURED: the intra-cluster rewrite turned `cls._convergence_alternate_type(action_type, attempted)` into
    `_convergence_alternate_type(action_type, attempted)` while that function is `(host, action_type, attempted=())`.
    Every argument shifted by one, the `_CONVERGENCE_ALTERNATES` fallback died, and NO gate noticed: `compileall`
    passes on a missing argument, the behaviour probe says UNCHANGED, and the delegation pin is arity-blind. So the
    arity is now checked directly, over the whole module, for every function whose first parameter is `host`.
    """
    tree = ast.parse(COORDINATOR_MODULE.read_text(encoding="utf-8", errors="replace"))
    host_functions = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.args.args and node.args.args[0].arg == "host"
    }
    assert host_functions, "no function takes a host any more; this pin is stale"
    offenders = [
        f"{node.name}:{call.lineno} {ast.unparse(call)}"
        for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in host_functions
        and not (call.args and isinstance(call.args[0], ast.Name) and call.args[0].id == "host")
    ]
    assert not offenders, (
        "these calls omit the host their target requires, which SHIFTS every argument silently: " + "; ".join(offenders)
    )


def test_every_host_taking_function_is_delegated_with_its_own_receiver() -> None:
    """The other half of the same defect: if a member needs a host, its delegation must forward one."""
    import inspect

    from threat_report_agent.investigation import coordinator as coordinator_module

    methods = {
        node.name: node for node in _service_class().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in MOVED_MEMBERS:
        parameters = list(inspect.signature(getattr(coordinator_module, name)).parameters)
        if not parameters or parameters[0] != "host":
            continue
        receiver = methods[name].args.args[0].arg if methods[name].args.args else None
        assert receiver in {"self", "cls"}, f"{name} takes a host but its delegation has no receiver to forward"
        body = ast.unparse(methods[name].body[0])
        assert f"({receiver}," in body or f"({receiver})" in body, (
            f"{name} needs a host but its delegation does not forward `{receiver}`: {body}"
        )


def test_the_action_proposal_members_that_could_not_move_stayed_whole_with_measured_reasons() -> None:
    """P3.3c(2), pinned: these four stay because of a LAYER rule, not because they were forgotten."""
    methods = {
        node.name: node for node in _service_class().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in STAYED_FROM_P3_3C:
        node = methods[name]
        assert "_coordinator." not in ast.unparse(node), f"{name} was moved after all; re-measure the layer rule"
        assert len(node.body) > 1, f"{name} looks like a delegation now, but this slice left it whole"
    runtime_blocked = {
        "_model_action_plan": "DynamicPlanAction",
        "_action_is_model_or_human": "action_is_model_or_human",
    }
    for name, symbol in runtime_blocked.items():
        source = ast.unparse(methods[name])
        assert symbol in source, f"{name} no longer uses {symbol}; the reason it stayed changed, so re-measure"
        assert "isinstance" in source or f"{symbol}(" in source, (
            f"{name} no longer uses {symbol} at RUNTIME; if it is annotations-only now, it belongs in the movable set"
        )


def test_the_four_members_that_needed_report_reporting_stayed_whole() -> None:
    """They are NOT delegates: they keep their real bodies, because moving them would break plan 3.2's matrix."""
    methods = {
        node.name: node for node in _service_class().body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in STAYED_MEMBERS:
        node = methods[name]
        source = ast.unparse(node)
        assert "_coordinator." not in source, f"{name} was moved after all; see the module docstring for why it cannot"
        assert len(node.body) > 1, f"{name} looks like a delegation now, but this slice left it whole"
    for name in ("_is_unique_thread_seed_row", "_unique_thread_start_keys"):
        assert "_address_lookup_keys" in ast.unparse(methods[name]), (
            f"{name} no longer needs `_address_lookup_keys`; the reason it stayed changed, so re-measure"
        )
    assert "build_unique_execution_threads" in ast.unparse(methods["_unique_execution_threads_for_view"])


def test_the_moved_module_functions_are_one_object_behind_two_paths() -> None:
    """They have OTHER callers that stay in service.py, so the import must rebind the same object."""
    import threat_report_agent.investigation.coordinator as coordinator
    import threat_report_agent.service as service

    for name in MOVED_MODULE_FUNCS:
        assert getattr(service, name) is getattr(coordinator, name), f"{name} is not the same object in both"
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    defined = {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    for name in MOVED_MODULE_FUNCS:
        assert name not in defined, f"{name} is DEFINED in service.py again; the move kept one implementation only"
    callers = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(c, ast.Name) and c.id == "frontier_status_is_open" for c in ast.walk(node))
    }
    assert callers, "the other callers of `frontier_status_is_open` are gone; re-measure before trusting the import"


def test_the_class_constants_the_stayed_members_read_are_untouched() -> None:
    """`_CATALOG_HOW_SEED_SCAN_LIMIT` is read by un-moved code as well; nothing in this slice may move it.

    The numeric pin lives in `tests/test_pe_entry_function_budget.py` and is deliberately NOT repeated here - a second
    home for one pin is the same defect as a second copy of a port.
    """
    service = _service_class()
    assigned = {
        target.id for node in service.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    assert {"_CATALOG_HOW_SEED_SCAN_LIMIT", "_UNIQUE_THREAD_VIEW_KINDS"} <= assigned, (
        "a class constant read through the receiver has left AnalysisService; their readers stayed, so they must too"
    )
