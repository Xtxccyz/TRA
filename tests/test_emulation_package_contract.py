"""P2-E contract: the emulation package, and the module the plan's own rule refuses to move.

Plan section 7.8 names `simulation_adapters.py`, `emulation_plan.py`, `controlled_emulation.py` and
`vb6_runtime_shim.py` for `emulation/`. MEASURED in `.scratch/p2e-step1-inventory.py`:

  * `simulation_adapters.py` locates `tool-worker/qiling_linux_runtime` relative to `__file__` (line 1542), which
    the plan's own rule refuses to move - the breakage would be at RUNTIME, not at import, and changing it is a
    behaviour-adjacent edit that belongs in its own work item. It therefore STAYS at the package root, and the last
    test below pins that it is still there and still reachable.
  * the other three sit in NO module-level import cycle, so a root `sys.modules` shim cannot re-enter a
    half-initialised module - the failure mode that stopped the P2-V attempt.

    python -m pytest -q tests/test_emulation_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"

#: module -> symbols whose IDENTITY must be the same through both paths, read from the modules themselves.
MOVED = {
    "emulation_plan": ("controlled_emulation_windows", "readable_pe_memory_maps"),
    "controlled_emulation": ("is_placeholder_status", "is_real_simulation_row", "PLACEHOLDER_STATUSES"),
    "vb6_runtime_shim": ("Vb6ShimState", "install_vb6_shim"),
}

#: Refused by the plan's rule: module-relative resource discovery.
REFUSED = "simulation_adapters"


def load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_emulation_tests",
        Path(__file__).resolve().parents[1] / "scripts" / "check-structure-diff.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_each_moved_module_is_one_object_behind_two_paths() -> None:
    for name, symbols in MOVED.items():
        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.emulation.{name}")
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


def test_the_emulation_package_re_exports_nothing() -> None:
    source = (PACKAGE / "emulation" / "__init__.py").read_text(encoding="utf-8", errors="replace")
    imported = [
        node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert not imported, f"emulation/__init__.py imports {[ast.unparse(node) for node in imported]}"
    assert "__all__: tuple[str, ...] = ()" in source


def test_no_production_module_imports_a_moved_emulation_module_by_its_old_path() -> None:
    gate = load_gate_module()
    offenders = [item for item in gate.legacy_path_imports() if item["old"] in MOVED]
    assert not offenders, (
        f"production modules still import a moved emulation module by its old path: {offenders}; the canonical path "
        "is threat_report_agent.emulation.<module>"
    )


def test_the_refused_module_is_still_at_the_package_root_and_reachable() -> None:
    """The plan refuses to move a module whose resource discovery is module-relative; this pins BOTH halves."""
    source = PACKAGE / f"{REFUSED}.py"
    assert source.is_file(), f"{REFUSED}.py is not at the package root; was it moved despite the refusal rule?"
    text = source.read_text(encoding="utf-8", errors="replace")
    assert "Path(__file__)" in text, (
        f"{REFUSED}.py no longer locates a resource relative to __file__, so the refusal recorded in the plan "
        "conflict list and in the emulation package docstring needs re-measuring rather than being assumed"
    )
    assert not (PACKAGE / "emulation" / f"{REFUSED}.py").exists(), (
        f"{REFUSED}.py was moved into emulation/, where its `tool-worker/qiling_linux_runtime` path would break at "
        "runtime"
    )
    module = importlib.import_module(f"threat_report_agent.{REFUSED}")
    assert module is not None


def test_the_moved_placeholder_predicate_still_holds() -> None:
    """A light behaviour pin on the one moved module whose logic the P0.5 probe freezes in detail."""
    module = importlib.import_module("threat_report_agent.emulation.controlled_emulation")
    assert module.is_placeholder_status("DEFERRED_TO_WORKER") is True
    assert module.is_placeholder_status("SUCCEEDED") is False
    assert module.is_real_simulation_row(
        {"kind": "simulation_result", "value": {"status": "DEFERRED_TO_WORKER"}}
    ) is False
    assert "DEFERRED_TO_WORKER" in module.PLACEHOLDER_STATUSES
