"""P1.1 contract: the domain-type modules must not depend on persistence, HTTP or a model SDK.

Plan step P1.1 requires the read-only domain projections (Analysis Snapshot, Report Document, Report Revision,
ToolRun, Evidence, Claim, Action Proposal) to exist WITHOUT importing `service`, a database layer, an HTTP
framework, the DSH packages or a concrete model SDK.

MEASURED when this test was written (`.scratch/probe-p11-domain-types.py`):

  * `contracts.py` (138 lines, 10 classes, including ActionProposal) -> NO banned import. Already satisfies it.
  * `runtime_contracts.py` (208 lines, 2 classes) -> NO banned import. Already satisfies it.
  * `models.py` (793 lines, 33 classes: ToolRun, Evidence, Claim, ClaimEvidence, AnalysisSnapshot,
    ReportRevision, InvestigationActionRecord, ...) -> imports `sqlalchemy` and `sqlalchemy.orm`.

So the projections the plan names ALREADY EXIST, but the canonical copies are ORM classes bound to the
persistence layer. A consumer that wants `Evidence` or `Claim` today must import `models.py` and therefore
sqlalchemy. That is the real P1.1 problem, and it is recorded rather than papered over: this test locks the
half that already holds, so the extraction work cannot silently regress it.

The check reads the SOURCE with `ast`, not the imported module, so an import added behind a conditional or a
`TYPE_CHECKING` block is still seen.

    python -m pytest -q tests/test_domain_type_boundaries.py
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"

#: Modules that must stay free of persistence / transport / SDK dependencies.
PURE_MODULES = ("contracts.py", "runtime_contracts.py")

#: P1.1's ban list, matched as substrings of an imported dotted path or of the raw source.
BANNED = (
    "threat_report_agent.service",
    "sqlalchemy",
    "psycopg",
    "fastapi",
    "starlette",
    "requests",
    "httpx",
    "openai",
    "anthropic",
)

#: Projections P1.1 names, with the module each lives in today. `models.py` is the ORM layer.
PROJECTIONS = {
    "ActionProposal": "contracts.py",
    "ToolRun": "models.py",
    "Evidence": "models.py",
    "Claim": "models.py",
    "AnalysisSnapshot": "models.py",
    "ReportRevision": "models.py",
}


def imported_paths(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append(node.module)
    return found


@pytest.mark.parametrize("name", PURE_MODULES)
def test_pure_domain_modules_import_nothing_banned(name: str) -> None:
    path = PACKAGE / name
    assert path.is_file(), f"{name} is missing"
    hits = [item for item in imported_paths(path) for ban in BANNED if ban in item]
    assert not hits, (
        f"{name} must stay free of persistence/transport/SDK imports; found {hits}. A domain projection that "
        "needs the database is not a projection."
    )


@pytest.mark.parametrize("name", PURE_MODULES)
def test_pure_domain_modules_do_not_hide_a_dynamic_dependency(name: str) -> None:
    """Catch a DYNAMIC import of a banned module, without flagging a legitimate mention of its name.

    MEASURED when this was written: a blunt substring scan failed on `runtime_contracts.py`, but reading the hits
    showed them at lines 149-150 as `or "psycopg" in text` / `or "sqlalchemy" in text` - a detection rule that
    looks FOR those words in some text, which is the opposite of depending on them. My own probe had warned
    about exactly this ("a substring hit without an import means a mention in text or a dynamic import, which
    must be read"); this test now reads instead of guessing.

    What is actually dangerous is `import_module("threat_report_agent.service")` or `__import__(...)`, because
    neither appears in an import statement. Those are looked for as string literals passed to a call.
    """
    tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8", errors="replace"))
    dynamic: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else "")
        if called not in {"import_module", "__import__"} or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            if any(ban in first.value for ban in BANNED):
                dynamic.append(f"{called}({first.value!r})")
    assert not dynamic, (
        f"{name} imports {dynamic} dynamically; a dynamic import is a dependency and must be registered in the "
        "policy, not hidden from an AST import walk"
    )


def test_the_named_projections_exist_where_this_test_says_they_do() -> None:
    """Pin the measurement, so a move that relocates one of them must update this record deliberately."""
    for projection, module in PROJECTIONS.items():
        source = (PACKAGE / module).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
        names = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
        assert projection in names, (
            f"{projection} is no longer defined in {module}; P1.1's record of where the canonical projection "
            "lives is now wrong"
        )


def test_models_py_is_still_the_orm_bound_copy() -> None:
    """NEGATIVE CONTROL for the recorded problem, so the extraction cannot be claimed without doing it.

    This asserts the coupling IS there. When the pure projections are extracted, this test must be deleted or
    inverted - deliberately, in the step that does the extraction - rather than becoming quietly false.
    """
    hits = [item for item in imported_paths(PACKAGE / "models.py") if "sqlalchemy" in item]
    assert hits, (
        "models.py no longer imports sqlalchemy, so either the extraction happened (update this test and the "
        "P1.1 record deliberately) or something else changed underneath"
    )
