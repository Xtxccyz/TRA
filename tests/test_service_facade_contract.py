"""P3.1 contract: the `AnalysisService` FACADE's public surface, exercised without touching a private member.

Plan section 8 opens with the rule for this whole phase: split `AnalysisService` "按职责和接缝拆", not by line count.
P3.1 is the prerequisite - before anything is extracted, state what the facade is FOR:

  * dependency assembly (settings, database, content store), and
  * the stable operations a caller may rely on: START an Analysis Task, READ status, READ a Report Revision, and an
    AUTHORISED workbench query.

P3.1's success criterion is narrow and checkable: **a new contract test must not need to call a private method**.
That is what this file does. It deliberately does NOT re-pin the 276 private methods - they are allowed to exist and
keep working by delegation during the split (plan P3.1: "现有 private tests 暂时仍能通过委托") - and it does not
enumerate all 76 public names, because a list that long would be a change-detector rather than a contract.

MEASURED BEFORE WRITING IT (`.scratch/p31-public-surface.py`): `AnalysisService` has 352 methods, 76 public and 276
private, in a 29,640-line module; `main.py` contains NO private access to the service (its only two underscore
attributes are `sys._current_frames` and `type(exc).__name__`), so the HTTP boundary already talks to the facade
through public members only.

    python -m pytest -q tests/test_service_facade_contract.py
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService

REPO = Path(__file__).resolve().parents[1]
SERVICE_MODULE = REPO / "src" / "threat_report_agent" / "service.py"
MAIN_MODULE = REPO / "src" / "threat_report_agent" / "main.py"

#: The stable operations plan P3.1 names, as the public names a caller may use.
STABLE_OPERATIONS = {
    "start an Analysis Task": ("create_case", "analyze_submission", "analyze_directory"),
    "read status": ("task_view",),
    "read a Report Revision": ("get_report_revision",),
    "authorised workbench query": ("get_evidence", "workbench_submit_action"),
}


@pytest.fixture
def facade(test_settings) -> AnalysisService:  # noqa: ANN001 - the fixture type is Settings from conftest
    """Construct the facade exactly the way the HTTP path does: settings + database + content store."""
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    return service


def test_the_stable_operations_are_public_members() -> None:
    for label, names in STABLE_OPERATIONS.items():
        for name in names:
            assert hasattr(AnalysisService, name), f"{label}: {name} is gone from the facade"
            assert not name.startswith("_"), f"{label}: {name} is private, so it cannot be a stable operation"
            assert callable(getattr(AnalysisService, name))


def test_the_facade_runs_a_task_and_reads_it_back_through_public_methods_only(facade: AnalysisService) -> None:
    """Start -> status -> revision -> evidence, every step on a PUBLIC member.

    49 tests depended on `document_to_markdown`'s exact output at P2-R; the equivalent risk here is that the facade
    only *looks* usable until a caller needs the revision, so the flow goes all the way to a revision body and an
    evidence row rather than stopping at "the task was created".
    """
    case = facade.create_case("facade contract")

    result = facade.analyze_submission(
        case_id=case.id,
        filename="contract_sample.py",
        content=b"import socket\nsocket.socket().connect(('example.invalid', 443))\n",
    )
    assert result.task_id, "the start operation returned no task id"

    view = facade.task_view(result.task_id)
    assert isinstance(view, dict), "task_view no longer returns a mapping"
    assert view.get("case_id") == case.id
    assert "claims" in view, "the status view lost its claims projection"

    revision_id = view.get("authoritative_report_revision_id")
    assert revision_id, (
        "task_view exposes no authoritative_report_revision_id, so a caller cannot reach the report through the "
        "public surface - that is the facade contract, not an implementation detail"
    )
    revision = facade.get_report_revision(revision_id)
    assert revision.get("id") == revision_id
    assert "markdown" in revision and "document" in revision
    assert revision.get("parent_revision_id") is None or isinstance(revision["parent_revision_id"], str)

    evidence_id = None
    for claim in view.get("claims") or []:
        for candidate in claim.get("evidence_ids") or []:
            evidence_id = candidate
            break
        if evidence_id:
            break
    assert evidence_id, "no evidence id is reachable from the public status view"
    row = facade.get_evidence(evidence_id)
    assert isinstance(row, dict) and row, "the workbench read returned nothing for an id the status view exposed"


def test_this_contract_test_never_reaches_a_private_member() -> None:
    """P3.1's success criterion, checked on the file that claims to meet it.

    MEASURED reason for checking the FILE rather than trusting the author: "the contract test does not use private
    members" is exactly the sort of claim that quietly stops being true when someone adds one convenient
    `service._helper(...)` line. Dunder names are excluded, because `__file__` and `__name__` are not encapsulation.
    """
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    offenders = [
        f"line {node.lineno}: {ast.unparse(node)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr.startswith("_")
        and not node.attr.startswith("__")
        and not (isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"})
    ]
    assert not offenders, (
        f"this contract test reaches private members: {offenders}; P3.1 requires the contract to be expressible "
        "through public operations only"
    )


def test_the_http_adapter_does_not_reach_private_service_members() -> None:
    """The other half of the boundary: `main.py` must talk to the facade, not into it.

    MEASURED before writing this: `main.py`'s only underscore attributes are `sys._current_frames` and
    `type(exc).__name__`, neither of which is a service member. This pins that, so a future handler cannot bind itself
    to a private method and make the P3 split impossible.
    """
    tree = ast.parse(MAIN_MODULE.read_text(encoding="utf-8"))
    suspicious: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and node.attr.startswith("_") and not node.attr.startswith("__")):
            continue
        text = ast.unparse(node)
        if text.startswith(("sys._", "type(", "os._", "json._")):
            continue
        suspicious.append(f"line {node.lineno}: {text}")
    assert not suspicious, (
        f"the HTTP adapter reaches private members: {suspicious}; the facade is the boundary, so this would bind the "
        "HTTP layer to internals the P3 split is supposed to be free to move"
    )
