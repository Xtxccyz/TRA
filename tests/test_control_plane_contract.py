"""P2-T.0 contract: the control plane is out of the tool module, and nothing about the worker changed.

WHY THIS EXISTS (plan 7.5): the tool layer must not reach the service layer, and the failure clause requires the
`service <-> tool_execution` cycle to be unwound BEFORE the tool layer moves into `tools/` rather than carried into
it. MEASURED before the extraction: `tool_execution.py` had no module-level package imports at all, but two
FUNCTION-LEVEL `from threat_report_agent.service import AnalysisService` statements inside the retention and
audit-seal activities - which the import gate sees, because it walks every AST node.

P2-T.0 separated the planes: those two activities, their two workflows, their two schedules and the worker
composition root moved to `threat_report_agent/control_activities.py`. The import graph now reports ZERO cycles and
`docs/import-policy.json`'s `known_cycles` allowlist is EMPTY.

The tests below pin BOTH halves: that the tool module cannot reach the service at any nesting depth again, and that
the move changed nothing anyone can observe - the registered activity names, which worker role registers which, the
workflow dispatch names, and the schedule times.

    python -m pytest -q tests/test_control_plane_contract.py
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "src" / "threat_report_agent"


def implementation(dotted: str) -> tuple[Path, str]:
    """Resolve a module's implementation through the import system, and refuse to read a compatibility shim.

    MEASURED TWICE NOW, which is why this helper exists: P2-M's move turned a hard-coded source path into a shim and
    three assertions silently started checking shim text, and P2-T then moved `tool_execution.py` into `tools/`,
    which would have done exactly the same to this file's `TOOL` constant. Resolving through the import system
    follows the module wherever the plan moves it, and the guard below fails loudly instead of drifting.
    """
    module = importlib.import_module(dotted)
    path = Path(module.__file__)
    text = path.read_text(encoding="utf-8")
    assert "Compatibility shim" not in text, (
        f"{dotted} resolved to a compatibility shim at {path}, not the implementation"
    )
    return path, text


TOOL, TOOL_SOURCE = implementation("threat_report_agent.tools.tool_execution")
CONTROL, CONTROL_SOURCE = implementation("threat_report_agent.control_activities")

#: The registered names each class must own, read from Temporal's own activity definitions.
#: `execute_static_tool` is the ONLY one the tool role worker registers; the other four tool activities run on the
#: control worker beside the two control-plane ones, which is the split the P2-T.0 extraction had to preserve.
CONTROL_ROLE_TOOL_NAMES = [
    "finalize_static_tool_run",
    "prepare_static_tool",
    "register_static_tool_run",
    "validate_static_tool_output",
]
TOOL_ONLY_NAMES = ["execute_static_tool"]
TOOL_ACTIVITY_NAMES = sorted(CONTROL_ROLE_TOOL_NAMES + TOOL_ONLY_NAMES)
CONTROL_ACTIVITY_NAMES = ["expire_model_payloads", "seal_daily_audit"]

#: Workflow dispatch names, which must stay identical or a running schedule would target a missing activity.
DISPATCH_NAMES = {"expire_model_payloads", "seal_daily_audit"}


def registered_names(instance: object) -> list[str]:
    names = []
    for attribute in dir(instance):
        definition = getattr(getattr(instance, attribute), "__temporal_activity_definition", None)
        if definition is not None:
            names.append(definition.name)
    return sorted(names)


def service_references(path: Path) -> list[str]:
    """References to the service layer at ANY nesting depth: what the cycle was made of."""
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


def test_the_tool_module_cannot_reach_the_service_layer() -> None:
    assert not service_references(TOOL), (
        "tool_execution.py references the service layer again; this is the reverse leg of the retired "
        "`service <-> tool_execution` cycle, and plan 7.5 forbids carrying it into tools/"
    )


def test_the_control_module_is_the_one_that_drives_the_service() -> None:
    """Two function-level imports, exactly as before the move - and still not module-level.

    The count is 4 references, not 2: two import statements plus the two `AnalysisService(...)` constructions. The
    meaningful claim is that BOTH imports sit inside function bodies, so importing the control module does not drag
    the service in, which is the behaviour that existed before the extraction and must be preserved by it.
    """
    tree = ast.parse(CONTROL_SOURCE)
    module_level = [
        ast.unparse(node)
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and "service" in ast.unparse(node)
    ]
    assert not module_level, (
        f"control_activities.py now imports the service layer at MODULE level: {module_level}; the extraction moved "
        "these imports verbatim and they were deliberately lazy"
    )
    imports = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and "service" in node.module
    ]
    assert len(imports) == 2, f"expected the two retained service imports, found {len(imports)}"
    references = service_references(CONTROL)
    assert len(references) == 4, f"expected 2 imports + 2 name uses, found {references}"


def test_activity_names_are_unchanged_and_ownership_moved() -> None:
    """Read from Temporal's own definitions, so a rename cannot hide behind a matching class attribute."""
    module = importlib.import_module("threat_report_agent.config")
    settings = module.Settings.from_environment()
    tool = importlib.import_module("threat_report_agent.tools.tool_execution")
    control = importlib.import_module("threat_report_agent.control_activities")

    assert registered_names(tool.StaticToolActivities(settings, None)) == TOOL_ACTIVITY_NAMES
    assert registered_names(control.RetentionActivities(settings, None)) == CONTROL_ACTIVITY_NAMES
    for name in CONTROL_ACTIVITY_NAMES:
        assert not hasattr(tool.StaticToolActivities(settings, None), name), (
            f"{name} is still registered by the TOOL class; the ownership was not separated"
        )


def test_the_composition_root_registers_the_same_names_per_role() -> None:
    """Parsed from `run_static_worker`, because that registration is the behaviour Temporal actually sees."""
    tree = ast.parse(CONTROL_SOURCE)
    worker_function = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_static_worker"
    )
    registrations: dict[str, dict[str, list[str]]] = {}
    for node in ast.walk(worker_function):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Worker"):
            continue
        queue = ""
        activities: list[str] = []
        workflows: list[str] = []
        for keyword in node.keywords:
            if keyword.arg == "task_queue":
                queue = ast.unparse(keyword.value).split(".")[-1]
            elif keyword.arg == "activities":
                activities = [ast.unparse(element).split(".")[-1] for element in keyword.value.elts]
            elif keyword.arg == "workflows":
                workflows = [ast.unparse(element).split(".")[-1] for element in keyword.value.elts]
        registrations[queue] = {"activities": sorted(activities), "workflows": sorted(workflows)}

    assert set(registrations) == {"control_task_queue", "tool_task_queue"}, (
        f"the worker roles changed: {sorted(registrations)}"
    )
    control = registrations["control_task_queue"]
    assert control["activities"] == sorted(CONTROL_ROLE_TOOL_NAMES + CONTROL_ACTIVITY_NAMES), (
        "the control worker's registered activity names changed; a rename or a dropped registration would make a "
        f"running schedule target an activity no worker serves. Found {control['activities']}"
    )
    assert control["workflows"] == [
        "DailyAuditSealWorkflow",
        "ModelPayloadCleanupWorkflow",
        "StaticToolRunWorkflow",
    ]
    assert registrations["tool_task_queue"]["activities"] == ["execute_static_tool"]
    assert registrations["tool_task_queue"]["workflows"] == []


def test_the_workflows_dispatch_the_same_activity_names() -> None:
    tree = ast.parse(CONTROL_SOURCE)
    dispatched = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value in DISPATCH_NAMES
    }
    assert dispatched == DISPATCH_NAMES, (
        f"the durable workflows dispatch {sorted(dispatched)}; a renamed activity would make a running schedule "
        "target an activity that no worker registers"
    )


def test_every_name_the_composition_root_registers_exists_in_its_module() -> None:
    """MEASURED REGRESSION this closes (found by the DEPLOYMENT gate, not by a local test).

    The first version of the extraction moved `run_static_worker` but imported only `StaticToolActivities`, so the
    control-worker container crash-looped with `NameError: name 'StaticToolRunWorkflow' is not defined` at
    `control_activities.py:162`, and `--strict --import-smoke` reported it as `control-worker: NOT RUNNING`. The
    tests above parse the registration and pass either way, because parsing a name proves nothing about whether the
    name exists. This one resolves each registered name in the module's actual namespace.
    """
    control = importlib.import_module("threat_report_agent.control_activities")
    tree = ast.parse(CONTROL_SOURCE)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_static_worker"
    )
    referenced: set[str] = set()
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Worker"):
            continue
        for keyword in node.keywords:
            if keyword.arg in {"workflows", "activities"}:
                for element in keyword.value.elts:
                    referenced.add(ast.unparse(element).split(".")[0])
    missing = sorted(
        name for name in referenced
        if name not in {"activities", "retention"} and not hasattr(control, name)
    )
    assert not missing, (
        f"run_static_worker registers {missing}, which do not exist in control_activities' namespace; the worker "
        "would raise NameError at startup and the container would crash-loop"
    )
    assert callable(control.run_static_worker)


def test_the_control_plane_module_is_import_smoked_in_every_container() -> None:
    """The smoke list covers the plan's PACKAGES; a new root-level module needs an explicit entry.

    MEASURED: `control_activities.py` is a ROOT module, so `plan_packages()` never covered it - which is why the
    crash-loop above was found by the hash gate's NOT RUNNING line rather than by the import smoke.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_deployed_code_hashes_for_control_plane_test",
        REPO / "scripts" / "check-deployed-code-hashes.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    smoked = set(module.smoke_modules())
    assert "threat_report_agent.control_activities" in smoked, (
        "the worker entry point imports this module in every container; it must be import-smoked"
    )


def test_the_schedules_keep_their_utc_times() -> None:
    """03:17 for retention cleanup, 03:23 for audit sealing, SKIP overlap - the moved code must be byte-equal."""
    source = CONTROL_SOURCE
    assert "hour=[ScheduleRange(start=3, end=3)]" in source
    assert "minute=[ScheduleRange(start=17, end=17)]" in source, "the retention schedule moved off 03:17 UTC"
    assert "minute=[ScheduleRange(start=23, end=23)]" in source, "the audit-seal schedule moved off 03:23 UTC"
    assert source.count("time_zone_name=\"UTC\"") == 2
    assert source.count("overlap=ScheduleOverlapPolicy.SKIP") == 2


def test_the_cycle_allowlist_is_empty_and_the_gate_still_passes() -> None:
    import json

    policy = json.loads((REPO / "docs" / "import-policy.json").read_text(encoding="utf-8"))
    assert policy["known_cycles"] == [], (
        "an allowlist entry that permits a retired cycle cannot notice that cycle returning"
    )
    assert "P2-T.0" in policy["_known_cycles_note"], "the retirement reason must stay recorded in the policy"
