"""P2-T contract: the tools package (plan section 7.5).

Scope moved, one module at a time with a root `sys.modules` shim each: `tool_execution.py` and
`tool_authoring.py` -> `threat_report_agent/tools/`.

Plan 7.5's success criteria are a BOUNDARY plus three invariants:
  * tools produce only structured ToolRun/Evidence,
  * sample execution still goes only through the isolated worker,
  * the tool allowlist and the failure statuses are unchanged,
  * and `tools` must not import `AnalysisService` - which is why P2-T.0 had to separate the control plane first.

This file pins the boundary and the invariants that a move could quietly break. It deliberately does NOT re-pin
what `tests/test_tool_execution.py` already covers behaviourally (activity semantics, isolation matrix); what it adds
is the structural claim and the frozen allowlist.

    python -m pytest -q tests/test_tools_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "threat_report_agent"

#: module -> symbols whose IDENTITY must be the same through both paths, read from the modules themselves.
MOVED = {
    "tool_execution": (
        "StaticToolActivities",
        "StaticToolRunWorkflow",
        "TemporalToolExecutor",
        "ToolRunRequest",
        "ToolRunResult",
        "ToolRunStorageAccess",
        "STATIC_TOOL_ALLOWLIST",
        "client_result_timeout_seconds",
        "emulation_overall_from_results",
        "intake_entries_from_payload",
        "static_result_from_payload",
    ),
    "tool_authoring": (
        "ToolAuthoringDecision",
        "ToolAuthoringRequest",
        "authored_tool_evidence_nature",
        "authored_tool_policy_metadata",
        "evaluate_tool_authoring_request",
    ),
}

#: The allowlist measured before the move. Plan 7.5 says it must not change.
FROZEN_ALLOWLIST = {
    "python-zipfile-safe-reader",
    "builtin-static-analyzer",
    "pe-parser",
    "script-parser",
    "document-carrier-parser",
    "ghidra-headless",
    "controlled-emulator",
}


def load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_tools_tests",
        REPO / "scripts" / "check-structure-diff.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def service_references(path: Path) -> list[str]:
    """Any reference to the service layer at ANY nesting depth - what plan 7.5 forbids in tools."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and "service" in node.module:
            hits.append(f"line {node.lineno}: {ast.unparse(node)}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if "service" in alias.name:
                    hits.append(f"line {node.lineno}: {ast.unparse(node)}")
        elif isinstance(node, ast.Name) and node.id == "AnalysisService":
            hits.append(f"line {node.lineno}: AnalysisService")
    return hits


def test_each_moved_module_is_one_object_behind_two_paths() -> None:
    for name, symbols in MOVED.items():
        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.tools.{name}")
        assert old is new, f"{name}: the shim did not rebind sys.modules, so there are two module objects"
        assert old.__file__ == new.__file__
        for symbol in symbols:
            assert hasattr(new, symbol), f"{name} no longer defines {symbol}; the contract test is stale"
            assert getattr(old, symbol) is getattr(new, symbol), f"{name}.{symbol} is not the same object"


def test_the_old_paths_are_shims_and_not_second_implementations() -> None:
    for name in MOVED:
        shim = PACKAGE / f"{name}.py"
        assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
        source = shim.read_text(encoding="utf-8", errors="replace")
        assert len(source.encode("utf-8")) < 1500, f"{name}.py grew beyond a shim"
        definitions = [
            node.name
            for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        assert not definitions, f"{name}.py defines {definitions}; that would be a second implementation"
        assert "sys.modules[__name__] = _real" in source


def test_the_tools_package_re_exports_nothing() -> None:
    source = (PACKAGE / "tools" / "__init__.py").read_text(encoding="utf-8", errors="replace")
    imported = [
        node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert not imported, f"tools/__init__.py imports {[ast.unparse(node) for node in imported]}"
    assert "__all__: tuple[str, ...] = ()" in source


def test_no_production_module_imports_a_moved_tool_module_by_its_old_path() -> None:
    gate = load_gate_module()
    offenders = [item for item in gate.legacy_path_imports() if item["old"] in MOVED]
    assert not offenders, (
        f"production modules still import a moved tool module by its old path: {offenders}; the canonical path is "
        "threat_report_agent.tools.<module>"
    )


def test_the_tool_layer_cannot_reach_the_service_layer() -> None:
    """Plan 7.5's boundary, re-checked at the new location - P2-T.0 removed this edge and the move must not add it."""
    for name in MOVED:
        path = PACKAGE / "tools" / f"{name}.py"
        assert not service_references(path), (
            f"tools/{name}.py references the service layer: {service_references(path)}; plan 7.5 forbids the tool "
            "layer from importing AnalysisService"
        )


def test_the_static_tool_allowlist_is_unchanged() -> None:
    module = importlib.import_module("threat_report_agent.tools.tool_execution")
    assert set(module.STATIC_TOOL_ALLOWLIST) == FROZEN_ALLOWLIST, (
        "the tool allowlist changed; plan 7.5 requires it to be identical after the move"
    )


def test_tool_authoring_still_has_no_production_importer() -> None:
    """MEASURED, and recorded rather than silently 'fixed': nothing in src/ imports it, only a test does.

    Deciding whether `tool_authoring` should be wired into the authoring route or retired is a behaviour/product
    decision, not a structural one, so the move must not change either answer. This test freezes the measured state
    and will fail loudly if the module is either wired up or deleted, so the decision is made on purpose.
    """
    importers = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "tool_authoring.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = {alias.name for alias in node.names}
                if node.module == "threat_report_agent.tool_authoring" or (
                    node.module == "threat_report_agent" and "tool_authoring" in names
                ):
                    importers.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.Import) and any(
                alias.name.endswith("tool_authoring") for alias in node.names
            ):
                importers.append(f"{path.name}:{node.lineno}")
    assert not importers, (
        f"`tool_authoring` now has production importers {importers}; that is a behaviour change (wiring the "
        "authoring route), so it needs its own step rather than riding along with a structural move"
    )
