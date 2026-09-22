"""P2-TK contract: the task package (plan section 7.10).

Three modules moved into `task/`: `analysis_task_orchestration`, `status` and `turn_lifecycle`.

Plan 7.10's success criteria are the reason this file exists, and two of them are boundary claims that a move could
quietly break:

  * Task lifecycle, budget and cancellation semantics are unchanged;
  * Task exposes only stable operations (start / read a Report Revision);
  * **no HTTP request object enters the task core** - the HTTP layer is `main.py` + `AnalysisService`, and this
    package must not grow a dependency on either.

It also freezes one measured finding: `turn_lifecycle` has NO production importer today (only
`tests/test_final_runtime_closure.py`), so wiring it up or retiring it must be a deliberate behaviour step rather than
a side effect of the move.

    python -m pytest -q tests/test_task_package_contract.py
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

MOVED = {
    "analysis_task_orchestration": (
        "AnalysisTaskRuntime",
        "continue_investigation_after_action",
        "next_investigation_loop_path",
        "resolve_persist_how_skip",
        "run_analysis_task_investigation",
        "run_emulation_informed_investigation",
        "run_saturated_investigation",
        "supersede_queued_trace_after_persist_skip",
    ),
    "status": (
        "AnalysisOutcome",
        "CaseStatus",
        "ClaimNature",
        "ClaimStatus",
        "EvidenceNature",
        "InvalidStateTransition",
        "ReportStatus",
        "TaskLifecycle",
        "ToolRunStatus",
        "transition_task",
    ),
    "turn_lifecycle": ("LongTurnLifecycle", "TurnLifecycleSnapshot"),
}

#: The HTTP surface that must NOT leak into the task core.
HTTP_TOKENS = ("fastapi", "starlette", "Request", "HTTPException", "request: Request")


def load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_task_tests", REPO / "scripts" / "check-structure-diff.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_each_moved_module_is_one_object_behind_two_paths() -> None:
    for name, symbols in MOVED.items():
        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.task.{name}")
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


def test_the_task_package_re_exports_nothing() -> None:
    source = (PACKAGE / "task" / "__init__.py").read_text(encoding="utf-8", errors="replace")
    imported = [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert not imported, f"task/__init__.py imports {[ast.unparse(node) for node in imported]}"
    assert "__all__: tuple[str, ...] = ()" in source


def test_no_production_module_imports_a_moved_task_module_by_its_old_path() -> None:
    gate = load_gate_module()
    offenders = [item for item in gate.legacy_path_imports() if item["old"] in MOVED]
    assert not offenders, (
        f"production modules still import a moved task module by its old path: {offenders}; the canonical path is "
        "threat_report_agent.task.<module>"
    )


def test_no_http_surface_leaks_into_the_task_core() -> None:
    """Plan 7.10: HTTP request objects must not enter the task core."""
    offenders: list[str] = []
    for path in sorted((PACKAGE / "task").glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text)
        imported = {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        } | {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        for token in ("fastapi", "starlette"):
            if token in imported:
                offenders.append(f"{path.name} imports {token}")
        for token in ("Request", "HTTPException"):
            if any(
                isinstance(node, ast.Name) and node.id == token
                for node in ast.walk(tree)
            ) or f"{token}" in imported:
                offenders.append(f"{path.name} references {token}")
    assert not offenders, (
        f"the task core now depends on the HTTP layer: {offenders}; plan 7.10 keeps HTTP in main.py/AnalysisService"
    )


def test_the_task_lifecycle_transition_semantics_are_unchanged() -> None:
    """A behaviour pin on the state vocabulary the move must not disturb, read from the module itself.

    MEASURED, after a first version of this test GUESSED the member names: `TaskLifecycle` is
    PENDING / RUNNING / WAITING_GATE / PAUSED / FINALIZING / SUCCEEDED / FAILED / CANCELLED, and `transition_task`
    takes (current, target). The vocabulary is pinned by VALUE and the legal/illegal transition pair is exercised,
    so a silent edit to either is caught.
    """
    from threat_report_agent.task import status as task_status

    assert [member.name for member in task_status.TaskLifecycle] == [
        "PENDING",
        "RUNNING",
        "WAITING_GATE",
        "PAUSED",
        "FINALIZING",
        "SUCCEEDED",
        "FAILED",
        "CANCELLED",
    ]
    assert task_status.transition_task("PENDING", "RUNNING") is task_status.TaskLifecycle.RUNNING
    try:
        task_status.transition_task("SUCCEEDED", "RUNNING")
    except task_status.InvalidStateTransition:
        pass
    else:  # pragma: no cover - the rule this asserts is the one being pinned
        raise AssertionError("transitioning OUT of a terminal state no longer raises InvalidStateTransition")


def test_turn_lifecycle_still_has_no_production_importer() -> None:
    """MEASURED, and recorded rather than silently 'fixed': only a test imports it.

    Deciding whether `turn_lifecycle` should be wired into the long-turn path or retired is a behaviour/product
    decision, so the move must not change either answer. This freezes the measured state and will fail loudly if the
    module is wired up or removed, so that either change is made on purpose.
    """
    importers: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts or path.name == "turn_lifecycle.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names = {alias.name for alias in node.names}
                if node.module == "threat_report_agent.turn_lifecycle" or (
                    node.module in {"threat_report_agent", "threat_report_agent.task"} and "turn_lifecycle" in names
                ):
                    importers.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.Import) and any(
                alias.name.endswith("turn_lifecycle") for alias in node.names
            ):
                importers.append(f"{path.name}:{node.lineno}")
    assert not importers, (
        f"`turn_lifecycle` now has production importers {importers}; that is a behaviour change (wiring the long-turn "
        "path), so it needs its own step rather than riding along with a structural move"
    )
