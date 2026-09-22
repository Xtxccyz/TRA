"""P2-R contract: the report composition module lives in `report/`, is ONE module object, and has no duplicate
definition.

Two steps are pinned here.

P2-R step 1 (plan 7.3): delete the `_mechanism_catalog_id` that a later definition shadowed, and prove the
resolution is unchanged. MEASURED before the deletion (`.scratch/probe-p2r-mechanism-id.py`): the name was defined
at lines 1147 and 2247; the 1147 body read row fields and consulted `registry.by_id`, the 2247 body takes a SCALAR
and consults `registry.resolve_or_unknown`. Python binds the LAST definition, so `co_firstlineno` was 2247 and the
first body was unreachable - deleting it is behaviour-preserving BY CONSTRUCTION.

P2-R steps 2-5 (plan 7.1): move the SAME implementation into `report/analyst_report.py` and leave a
`sys.modules` shim at the old path. The moved file is byte-identical (sha256 checked by the move script), so the
two paths are two names for one module object - not a re-export and not a second implementation.

WHAT THE STEP-1 MEASUREMENT ALSO FOUND, RECORDED AND NOT FIXED: two call sites pass a MAPPING to the scalar
function. Measured, a mapping resolves to `""` while `row.get("catalog_id")` resolves correctly. So
`_topic_status`'s `"recovered"` branch (see `_topic_status`, around line 1202 of the moved file) evaluates
`"" == catalog_id` and can never fire for a non-empty catalog id, and `_mechanism_label` loses the catalog title.
Fixing either changes report text, which P1.4 and P2-R forbid inside a structural step ("正文 SHA 改变时先回滚本步
结构变更"). The last test asserts the gap is still exactly that, so closing it must be deliberate.

    python -m pytest -q tests/test_report_structure_contract.py
"""
from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import analyst_report  # noqa: E402
from threat_report_agent.behavior_catalog import BehaviorCatalog  # noqa: E402
from threat_report_agent.report import analyst_report as moved_report  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
#: The implementation, which after P2-R steps 2-5 is INSIDE the package.
IMPLEMENTATION = PACKAGE / "report" / "analyst_report.py"
#: The old path, which is now a shim.
SHIM = PACKAGE / "analyst_report.py"


def _implementation_tree() -> ast.Module:
    return ast.parse(IMPLEMENTATION.read_text(encoding="utf-8", errors="replace"))


def _definitions(name: str) -> list[int]:
    return [node.lineno for node in _implementation_tree().body
            if isinstance(node, ast.FunctionDef) and node.name == name]


# ------------------------------------------------------------------------------------------------------------
# P2-R step 1
# ------------------------------------------------------------------------------------------------------------
def test_the_shadowed_definition_is_gone_and_exactly_one_remains() -> None:
    definitions = _definitions("_mechanism_catalog_id")
    assert len(definitions) == 1, (
        f"{len(definitions)} definitions at {definitions}; P2-R step 1 removed the shadowed one, and a second "
        "definition makes the earlier body unreachable while looking authoritative in review"
    )


def test_the_surviving_definition_is_the_scalar_one_the_module_binds() -> None:
    """The LAST definition wins at import time; after the deletion that must be the scalar body."""
    assert list(inspect.signature(analyst_report._mechanism_catalog_id).parameters) == ["value", "registry"], (
        "the surviving signature is not the scalar one, so a different body is now live"
    )
    assert analyst_report._mechanism_catalog_id.__code__.co_firstlineno == _definitions("_mechanism_catalog_id")[0]


def test_the_resolution_is_unchanged_by_the_deletion() -> None:
    """The locking evidence: the values measured BEFORE the deletion still hold.

    Recorded before the change (probe output, commit 277ca05):
        scalar  value="file-operations"                  -> "file-operations"
        mapping value={"catalog_id": "file-operations"}  -> ""
        scalar  value=row.get("catalog_id")              -> "file-operations"
    """
    registry = BehaviorCatalog()
    catalog_id = next(iter(analyst_report.CATALOG_TITLES_ZH))
    row = {"catalog_id": catalog_id, "mechanism_type": catalog_id, "status": "VERIFIED"}

    assert analyst_report._mechanism_catalog_id(catalog_id, registry) == catalog_id
    assert analyst_report._mechanism_catalog_id(row.get("catalog_id"), registry) == catalog_id
    assert analyst_report._mechanism_catalog_id("", registry) == ""
    assert analyst_report._mechanism_catalog_id("definitely-not-a-catalog-alias", registry) == ""


def test_the_mapping_call_sites_are_still_the_recorded_gap() -> None:
    """Pins the RECORDED DEFECT, so closing it cannot happen by accident inside a structural step.

    When a behaviour work item fixes this, THIS TEST MUST BE INVERTED DELIBERATELY in the same commit, and the
    report body SHA must be re-frozen.
    """
    registry = BehaviorCatalog()
    catalog_id = next(iter(analyst_report.CATALOG_TITLES_ZH))
    row = {"catalog_id": catalog_id, "mechanism_type": catalog_id, "status": "VERIFIED"}

    assert analyst_report._mechanism_catalog_id(row, registry) == "", (
        "the mapping call sites now resolve; that is a BEHAVIOUR change to report text - invert this test and "
        "re-freeze the body SHA deliberately instead of deleting it"
    )

    # A MAPPING call site passes a bare row/item NAME. MEASURED reason for exactly this filter: the first version
    # also counted `_mechanism_catalog_id(row.get(key), registry)`, because `row.get(...)` is a Call and not an
    # Attribute - but `.get(...)` returns a SCALAR, which is the form that works.
    mapping_call_sites = [
        node.lineno
        for node in ast.walk(_implementation_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_mechanism_catalog_id"
        and node.args
        and isinstance(node.args[0], ast.Name)
    ]
    assert mapping_call_sites == [1161, 1203], (
        f"expected the two recorded mapping call sites [1161, 1203], measured {mapping_call_sites}; if one was "
        "fixed or moved, this record and the known_behavior_gap entry must be updated deliberately"
    )


# ------------------------------------------------------------------------------------------------------------
# P2-R steps 2-5 (the move)
# ------------------------------------------------------------------------------------------------------------
def test_the_module_is_one_object_behind_two_paths() -> None:
    """Plan 7.1 step 4: a `sys.modules` shim, so the old path IS the new module rather than a re-export."""
    assert analyst_report is moved_report, (
        "the old path and the new path are different module objects; the shim must rebind sys.modules, not "
        "re-export names"
    )
    assert analyst_report.__file__ == moved_report.__file__


def test_the_official_composer_is_the_same_function_behind_both_paths() -> None:
    """Plan 7.1 step 6: function identity, not 'both paths have a function of that name'."""
    assert analyst_report.compose_official_markdown is moved_report.compose_official_markdown
    assert analyst_report.compose_gate_violations is moved_report.compose_gate_violations
    # PRIVATE names must survive too: the report tests and `service.py` reach several of them.
    assert analyst_report._mechanism_catalog_id is moved_report._mechanism_catalog_id
    assert analyst_report.OPERATIONAL_LIMITATIONS_HEADING is moved_report.OPERATIONAL_LIMITATIONS_HEADING


def test_the_old_path_is_a_shim_and_not_a_second_implementation() -> None:
    """A 500-byte shim cannot be a second implementation, and this pins that it stays one."""
    source = SHIM.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    definitions = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    assert not definitions, (
        f"the old path defines {definitions}; it must be a shim, and a definition there would be a second "
        "canonical implementation (plan 3.2)"
    )
    assert len(source.encode("utf-8")) < 1500, "the old path grew beyond a shim"
    assert "sys.modules[__name__] = _real" in source
    # The implementation itself must not reference the old path, or the move would have left a cycle.
    implementation = IMPLEMENTATION.read_text(encoding="utf-8", errors="replace")
    for forbidden in ("from threat_report_agent.analyst_report import",
                      "from threat_report_agent import analyst_report",
                      'import_module("threat_report_agent.analyst_report'):
        assert forbidden not in implementation, (
            f"the moved implementation still references the old path via {forbidden!r}; plan 7.1 step 4 forbids "
            "the new implementation importing the old path"
        )


def test_no_production_module_imports_the_old_path() -> None:
    """Plan 7.1 step 5: production callers move to the new path FIRST.

    Only `service.py` imported this module (measured by the step-1 inventory), and both of its import sites now use
    `threat_report_agent.report.analyst_report`. The shim exists for the old path's own compatibility, not to keep
    a production caller on it.
    """
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts or path == SHIM:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if (
            "from threat_report_agent.analyst_report import" in text
            or "from threat_report_agent import analyst_report" in text
            or 'import_module("threat_report_agent.analyst_report' in text
        ):
            offenders.append(path.relative_to(PACKAGE).as_posix())
    assert not offenders, f"production modules still import the moved module by its old path: {offenders}"


# ------------------------------------------------------------------------------------------------------------
# The two small report modules that followed the same recipe
# ------------------------------------------------------------------------------------------------------------
MOVED_MODULES = {
    "report_verification": ("verify_report_correctness", "corrections_summary", "correctness_summary"),
    "gold_output_bar": (),
}


def test_the_small_report_modules_moved_with_the_same_recipe() -> None:
    """Byte-identical move + `sys.modules` shim + one module object, for each remaining small module."""
    for name, symbols in MOVED_MODULES.items():
        implementation = PACKAGE / "report" / f"{name}.py"
        shim = PACKAGE / f"{name}.py"
        assert implementation.is_file(), f"{name} was not moved into report/"
        assert shim.is_file(), f"the old path {name}.py is gone; the shim must stay until P4"

        shim_source = shim.read_text(encoding="utf-8", errors="replace")
        assert len(shim_source.encode("utf-8")) < 1500, f"{name}.py grew beyond a shim"
        assert "sys.modules[__name__] = _real" in shim_source
        shim_definitions = [
            node.name
            for node in ast.parse(shim_source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        assert not shim_definitions, f"{name}.py defines {shim_definitions}; it must be a shim only"

        # One module object behind two paths, by identity rather than by name.
        import importlib

        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.report.{name}")
        assert old is new, f"{name}: the two paths are different module objects"
        for symbol in symbols:
            assert getattr(old, symbol) is getattr(new, symbol), f"{name}.{symbol} is not the same object"

        # The implementation must not import its own old path, or the move left a cycle behind.
        text = implementation.read_text(encoding="utf-8", errors="replace")
        for forbidden in (f"from threat_report_agent.{name} import",
                          f"from threat_report_agent import {name}"):
            assert forbidden not in text, f"{name} imports its own old path"


def test_no_production_module_imports_the_small_modules_by_their_old_path() -> None:
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts or path.name in {f"{name}.py" for name in MOVED_MODULES}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in MOVED_MODULES:
            if (
                f"from threat_report_agent.{name} import" in text
                or f"from threat_report_agent import {name}" in text
                or f'import_module("threat_report_agent.{name}' in text
            ):
                offenders.append(f"{path.relative_to(PACKAGE).as_posix()} -> {name}")
    assert not offenders, f"production modules still import a moved module by its old path: {offenders}"
