"""P3.3 contract: the investigation slices' port, the slices behind it, and the members that had to STAY.

Plan 7.1 step 2 is "stand up the minimal interface and its contract test before moving any implementation"; P3.3's
slices follow P3.2's recipe (`docs/p33-investigation-coordinator-design-20260922.md`), and this file pins the two that
have moved: P3.3b (frontier helpers) and P3.3a (the ledger).

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

The port is TWO members: `database` (P3.3b, what the design measured) and `_audit` (P3.3a, which the ledger slice
measured for itself).

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
}


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
    assert INVESTIGATION_HOST_MEMBERS == ("database", "_audit"), (
        "the port is `database` (P3.3b) plus `_audit` (P3.3a's ledger slice writes an audit event through the host); "
        "widening it further needs a measured reason recorded in the step's findings"
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
        if decorators:
            assert "self" not in statement, f"{name} is a class/static member but forwards `self`: {statement}"
        else:
            assert "self" in statement, f"{name} must forward the host, not call the module function bare"


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
