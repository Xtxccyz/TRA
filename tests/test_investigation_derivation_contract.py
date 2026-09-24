"""The derivation slice's PORT contract (P3.3e's giant move), written to the same shape as the coordinator's.

Plan section 7.1 step 2 is "先建立最小公开接口和 contract test": the interface is `DerivationHost` plus the
`INVESTIGATION_HOST_MEMBERS` pin declared in `investigation/derivation.py`, and this file is its executable form. The
coordinator's sibling test (`test_investigation_coordinator_contract.py`) is the model, and its sharpest assertion is
copied deliberately: **the pin must equal EXACTLY the receiver references the moved bodies make** - a pin with an unused
member is an aspirational port, and a reference missing from the pin is a name that will not exist once the body runs
against a host.

WHAT IS PINNED HERE, and what each test would catch:

  * the real `AnalysisService` satisfies the port (`missing_investigation_host_members` is the runtime form of the
    contract, so a renamed or deleted host member fails here instead of at report time);
  * the helper REPORTS a missing member rather than accepting any object - a contract check that cannot fail is not a
    check;
  * pin == `DerivationHost`'s declarations == the references the module's own bodies actually make;
  * the giant is a ONE-STATEMENT delegation in `service.py` with its original signature, so `service.<name>` still
    resolves for every existing caller and test;
  * the moved module imports neither `service` nor `simulation_adapters` - the layer rule that made the execution seam a
    separate step;
  * the delegation and the moved function are the SAME behaviour for a real call (called through both paths).
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation.derivation import INVESTIGATION_HOST_MEMBERS
from threat_report_agent.service import AnalysisService

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
SERVICE_MODULE = SOURCE_ROOT / "service.py"
DERIVATION_MODULE = SOURCE_ROOT / "investigation" / "derivation.py"
GIANT = "_derive_investigation_observations"


def _missing_host_members(host: object) -> tuple[str, ...]:
    """The pin, evaluated - instead of a second copy of the coordinator's helper.

    The structure-diff gate rejected the copy as a `duplicate canonical implementation`, and it was right: a helper
    bound to one module's pin is not reusable by another module's pin without taking the pin as an argument, and this
    module deliberately exports the pin as DATA. The expression is the whole helper.
    """
    return tuple(name for name in INVESTIGATION_HOST_MEMBERS if not hasattr(host, name))


@pytest.fixture
def facade(test_settings) -> AnalysisService:  # noqa: ANN001 - conftest's Settings fixture
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    return service


def _derivation_tree() -> ast.Module:
    return ast.parse(DERIVATION_MODULE.read_text(encoding="utf-8", errors="replace"))


def _service_class() -> ast.ClassDef:
    tree = ast.parse(SERVICE_MODULE.read_text(encoding="utf-8", errors="replace"))
    return next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AnalysisService")


def _protocol_members() -> set[str]:
    tree = _derivation_tree()
    protocol = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DerivationHost")
    return {child.target.id for child in protocol.body if isinstance(child, ast.AnnAssign)} | {
        child.name for child in protocol.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _host_references() -> set[str]:
    """Every attribute the module's OWN bodies read through a receiver - computed, not listed."""
    refs: set[str] = set()
    for node in ast.walk(_derivation_tree()):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in {"host", "self", "cls"}:
                refs.add(node.attr)
    return refs


def test_the_pin_is_unique_and_matches_the_protocol() -> None:
    assert len(set(INVESTIGATION_HOST_MEMBERS)) == len(INVESTIGATION_HOST_MEMBERS), "the pin has a duplicate"
    assert _protocol_members() == set(INVESTIGATION_HOST_MEMBERS), (
        f"DerivationHost declares {sorted(_protocol_members())} but the pin is {sorted(INVESTIGATION_HOST_MEMBERS)}"
    )


def test_the_port_is_exactly_what_the_moved_bodies_use() -> None:
    """No unused member, no unreferenced need - the assertion that keeps a pin from drifting into aspiration."""
    assert _host_references() == set(INVESTIGATION_HOST_MEMBERS), (
        f"the moved bodies read {sorted(_host_references())} but the pin is {sorted(INVESTIGATION_HOST_MEMBERS)}"
    )


def test_analysis_service_satisfies_the_port(facade: AnalysisService) -> None:
    assert _missing_host_members(facade) == ()


def test_a_host_missing_a_member_is_reported_rather_than_accepted() -> None:
    complete = type("Complete", (), {name: (lambda self: None) for name in INVESTIGATION_HOST_MEMBERS})
    partial = type("Partial", (), {name: (lambda self: None) for name in INVESTIGATION_HOST_MEMBERS[:3]})
    assert _missing_host_members(complete()) == ()
    assert _missing_host_members(partial()) == INVESTIGATION_HOST_MEMBERS[3:]


def test_the_giant_is_a_one_statement_delegation_with_its_original_shape() -> None:
    giant = next(
        n for n in _service_class().body if isinstance(n, ast.FunctionDef) and n.name == GIANT
    )
    assert len(giant.body) == 1, "the delegation grew a body; the implementation is supposed to live in derivation.py"
    statement = giant.body[0]
    assert isinstance(statement, ast.Return), "the delegation must return"
    call = statement.value
    assert isinstance(call, ast.Call)
    forwarded = [arg.id for arg in call.args if isinstance(arg, ast.Name)]
    declared = [a.arg for a in giant.args.args]
    assert forwarded == declared, (
        f"the delegation forwards {forwarded} but declares {declared}; the host must be passed first and the rest in order"
    )


def test_the_moved_module_imports_neither_service_nor_the_emulation_implementation() -> None:
    """The layer rule, executable: plan section 3.2 admits emulation INTERFACES here, not `simulation_adapters`."""
    forbidden = {"threat_report_agent.service", "threat_report_agent.simulation_adapters"}
    imported = {
        node.module or "" for node in ast.walk(_derivation_tree()) if isinstance(node, ast.ImportFrom)
    } | {
        alias.name for node in ast.walk(_derivation_tree()) if isinstance(node, ast.Import) for alias in node.names
    }
    assert not {name for name in imported if name in forbidden}, (
        f"{DERIVATION_MODULE.name} imports {sorted(imported & forbidden)}; that is the cycle / layer violation the "
        "execution seam exists to prevent"
    )


def test_the_delegation_and_the_moved_function_agree_on_a_real_call(facade: AnalysisService) -> None:
    """Called through both paths with the same input: the values must match.

    This is the consumer-side evidence for the move - `service.<name>` still resolves AND produces what the new home
    produces, for a real action rather than for a signature. Both paths are called with EMPTY rows on purpose: the
    point is the forwarding of `self` and the arguments, not the derivation's logic, which the emulation/derivation
    test files already cover through the class.
    """
    from threat_report_agent.investigation.derivation import _derive_investigation_observations
    from threat_report_agent.investigation.investigation import ActionSpec, ActionType

    action = ActionSpec(
        id="contract",
        action_type=ActionType.GET_DATA_REFERENCES,
        thread_id="thread-1",
        hypothesis_id="hyp-1",
        artifact_id="artifact-1",
    )
    through_class = facade.derive_investigation_observations([], action)
    through_module = _derive_investigation_observations(facade, [], action)
    assert through_class == through_module
