"""P2-R contract: the report composition module lives in `report/`, is ONE module object, and has no duplicate
definition.

Two steps are pinned here.

P2-R step 1 (plan 7.3): delete the `_mechanism_catalog_id` that a later definition shadowed, and prove the
resolution is unchanged. MEASURED before the deletion (`.scratch/probe-p2r-mechanism-id.py`): the name was defined
at lines 1147 and 2247; the 1147 body read row fields and consulted `registry.by_id`, the 2247 body takes a SCALAR
and consults `registry.resolve_or_unknown`. Python binds the LAST definition, so `co_firstlineno` was 2247 and the
first body was unreachable - deleting it is behaviour-preserving BY CONSTRUCTION.

P2-R steps 2-5 (plan 7.1): move the SAME implementation into `report/analyst_report.py` and leave a
`sys.modules` shim at the old path. Byte-identity is a MEASURED property of the two revisions and is reproducible
with git rather than by trusting a script that is not in the repository:

    git show 5be786f:src/threat_report_agent/analyst_report.py            | sha256sum
    git show efc3ab7:src/threat_report_agent/report/analyst_report.py     | sha256sum

Both are `2049a0fa0120c2d9...` (305,478 blob bytes, 6,372 lines; ADR/plan comments that cite
`analyst_report.py:NNNN` still resolve, because the line numbers did not move).

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
import importlib
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import analyst_report  # noqa: E402
from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog  # noqa: E402
from threat_report_agent.report import analyst_report as moved_report  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
#: The implementation, which after P2-R steps 2-5 is INSIDE the package.
IMPLEMENTATION = PACKAGE / "report" / "analyst_report.py"
#: The old path, which is now a shim.
SHIM = PACKAGE / "analyst_report.py"


#: The modules P2-R moved into `report/`, whose old paths are now shims. Kept in step with
#: `scripts/check-structure-diff.py`'s LEGACY_PATHS, which is the detector the old-path test delegates to.
REPORT_MOVED_PATHS = ("analyst_report", "reporting", "report_verification", "gold_output_bar")


def load_gate_module():
    """`scripts/check-structure-diff.py` cannot be imported by name (dashes), so load it by path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_report_tests",
        Path(__file__).resolve().parents[1] / "scripts" / "check-structure-diff.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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
    #
    # IDENTITY IS (enclosing function), NOT an absolute line number. MEASURED (round 166): the pin used to read
    # `== [1161, 1203]`, so ANY edit above line 1203 in `report/analyst_report.py` broke a test that has nothing to do
    # with the edit - the P-1.1 step had to hide an import inside a function to avoid shifting those lines. A pin that
    # forbids unrelated edits gets worked around instead of obeyed. The defect itself is still pinned twice over: by the
    # behavioural assertion above, and by these two call sites still taking a bare NAME inside these two functions.
    mapping_call_sites = sorted(
        function_name
        for function in _implementation_tree().body
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for function_name in [function.name]
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_mechanism_catalog_id"
        and node.args
        and isinstance(node.args[0], ast.Name)
    )
    assert mapping_call_sites == ["_mechanism_label", "_topic_status"], (
        f"expected the two recorded mapping call sites in ['_mechanism_label', '_topic_status'], measured "
        f"{mapping_call_sites}; if one was fixed or moved, this record and the known_behavior_gap entry must be updated "
        f"deliberately"
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

    MEASURED BLIND SPOT this replaces (adversarial audit of the move): the first version tested three SUBSTRINGS
    (`from threat_report_agent.analyst_report import`, `from threat_report_agent import analyst_report`,
    `import_module("...`), and an audit injected three other spellings - `import
    threat_report_agent.analyst_report`, `from . import analyst_report`, `from .analyst_report import X` - into a
    copy and the test still reported 10 passed. The plainest spelling a developer writes was one of the three it
    could not see.

    It now DELEGATES to the structural gate's own `legacy_path_imports()`, so there is one detector rather than two
    (the gate's version is the one that was hardened to cover relative, alias and `importlib` forms), and the
    can-fail proof below shows every spelling is actually seen.
    """
    gate = load_gate_module()
    offenders = [item for item in gate.legacy_path_imports() if item["old"] in REPORT_MOVED_PATHS]
    assert not offenders, (
        f"production modules import a moved report module by its old path: {offenders}; the new path is "
        f"threat_report_agent.report.<module>"
    )


def test_the_old_path_detector_sees_every_import_spelling(tmp_path) -> None:
    """Can-fail proof for the delegation above, on a temp package that uses all six spellings at once."""
    import importlib

    gate = load_gate_module()
    fake = tmp_path / "threat_report_agent"
    fake.mkdir()
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "status.py").write_text(
        "import threat_report_agent.analyst_report\n"
        "import threat_report_agent.report_verification\n"
        "from threat_report_agent import gold_output_bar\n"
        "from threat_report_agent import reporting\n"
        "from . import analyst_report as _relative_alias\n"
        "from .report_verification import verify_report_correctness\n"
        "import importlib\n"
        "importlib.import_module('threat_report_agent.gold_output_bar')\n",
        encoding="utf-8",
    )
    real = PACKAGE
    gate.set_source(str(fake))
    try:
        found = {(item["old"], item["importer"]) for item in gate.legacy_path_imports()}
    finally:
        gate.set_source(str(real))
        importlib.invalidate_caches()
    missing = {name for name in REPORT_MOVED_PATHS if not any(old == name for old, _ in found)}
    assert not missing, (
        f"the detector missed the old path for {sorted(missing)}; measured findings were {sorted(found)}. Every "
        "import spelling must be seen, including plain `import pkg.mod` and relative forms."
    )


def test_no_second_copy_of_the_composer_exists_under_report() -> None:
    """The third-path evasion: a copy at `report/<anything>.py` is invisible to identity assertions.

    MEASURED by the audit: `report/analyst_report_copy.py` produced 8 passed, i.e. the contract tests alone could
    not see it (the gate's duplicate rule could). This closes it in the tracked suite too.
    """
    offenders: list[str] = []
    for path in sorted((PACKAGE / "report").rglob("*.py")):
        if path.name == "analyst_report.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        for symbol in ("compose_official_markdown", "compose_gate_violations", "render_official_markdown"):
            if symbol in names:
                offenders.append(f"{path.relative_to(PACKAGE).as_posix()}:{symbol}")
    assert not offenders, (
        f"a second definition of the official composition surface exists outside report/analyst_report.py: "
        f"{offenders}. Plan 3.2 allows ONE canonical implementation."
    )


# ------------------------------------------------------------------------------------------------------------
# The two small report modules that followed the same recipe
# ------------------------------------------------------------------------------------------------------------
MOVED_MODULES = {
    "reporting": ("build_report_document", "REPORT_MODULES", "render_ledger_markdown"),
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


def test_the_document_to_markdown_test_exit_has_been_retired() -> None:
    """P2-R step 5 is DONE, and this pin is INVERTED deliberately in the commit that did it - as it instructed.

    MEASURED before the retirement (`.scratch/p2r5-branch-split.py`, `.scratch/p2r5_legacy_plugin.py`):
    `document_to_markdown` had ZERO production callers and two branches - a V3 projection and a ~300-line pre-V3
    renderer. 49 tests depended on the projection and 7 exercised the pre-V3 renderer, each of whose assertions the
    projection also satisfies under a clearer label, so retiring it lost nothing.

    What must hold now: the retired name is GONE as code, and the ledger projection is reachable under the explicit
    name that says which artifact it produces.
    """
    import importlib

    reporting = importlib.import_module("threat_report_agent.report.reporting")
    assert not hasattr(reporting, "document_to_markdown"), (
        "the retired test exit is back; plan 7.3 step 5 removed it so that it could not be mistaken for a second "
        "official markdown producer"
    )
    assert callable(reporting.render_ledger_markdown), "the ledger projection must stay reachable"


def test_the_official_markdown_producer_is_unique() -> None:
    """Plan 7.3's success criterion, stated positively so a SECOND body producer also fails this."""
    producers = [
        path.name
        for path in sorted((PACKAGE / "report").glob("*.py"))
        if "def compose_official_markdown" in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert producers == ["analyst_report.py"], (
        f"the official markdown producer is defined in {producers}; plan 7.3 requires exactly one"
    )
    analyst = importlib.import_module("threat_report_agent.report.analyst_report")
    reporting = importlib.import_module("threat_report_agent.report.reporting")
    assert callable(analyst.compose_official_markdown)
    assert not hasattr(reporting, "compose_official_markdown"), (
        "the ledger module now also composes the official body; there must be one producer"
    )


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
