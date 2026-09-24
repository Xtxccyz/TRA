"""P3.5-0 / D-2 contract: tool execution goes through the PORT, and the executor arrives by HOST INJECTION.

WHY A SEPARATE TRACKED FILE (the choice, and the measured reason for it): the seam D-2 creates spans THREE modules -
`ports.py` (the signature), `tools/tool_execution.py` (the adapter that must satisfy it) and `task/task_runner.py`
(the consumer that must stop importing the adapter) - plus `service.py`, the host that supplies it. The existing
`tests/test_task_runner_contract.py` owns P3.2's TASK-path pin and keeps its own bidirectional assertion, which
covers the new pin member automatically because it re-derives `host.*` from the module. This file owns the SEAM, and
adds the one thing no existing test states: the port's `cancel` takes a workflow id, that signature is DIFFERENT from
`execute`'s, and a workflow id really reaches the executor through the host.

WHAT IS PINNED HERE, each because something else in the repository does NOT catch it:

  * the port's `cancel` signature. The pre-D-2 form `cancel(request: ToolRunRequestView)` closes on no real caller:
    the two cancellation callers in the tree hold an id STRING from the persisted row's `environment["workflow_id"]`
    (`task/task_runner.py:508`, `:625`), and `ToolRunRequestView` carries no `workflow_id` at all (18 declared
    fields, measured by `.scratch/p35-0-d2-measure.py`). This is the R2 resolution recorded in
    `docs/p35-prep-measurement-20260922.md` section 5, and it is a DECISION rather than an implementation detail.
  * `TemporalToolExecutor` satisfying the port in SHAPE (`isinstance` against the runtime-checkable Protocol) AND in
    SIGNATURE (`inspect.signature` of both methods), plus the pre-D-2 name `cancel_workflow` still existing for the
    callers that already use it. `isinstance` alone is NOT enough: `runtime_checkable` compares member PRESENCE, so a
    `cancel` that takes a request again would still satisfy it.
  * the host pin being exactly the members the module uses, in BOTH directions, and `tool_executor` being declared on
    `TaskHost` as the PORT type.
  * the consumer NOT importing `tools.tool_execution` - THE POINT OF THIS STEP. The import gate cannot see this: the
    deleted `task -> tools.tool_execution` edge was legal (no `forbidden_edges` entry, no cycle), so restoring it
    keeps `check-import-graph.py --strict` GREEN. `.scratch/p35-0-d2-canfail.py` T4 measures that.
  * the cancellation path END TO END: a workflow id read from the persisted row reaches the host-injected executor's
    PORT method (`cancel`), not the adapter's private path.

    python -m pytest -q tests/test_tool_execution_port_contract.py
"""
from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path

import pytest

from threat_report_agent import ports
from threat_report_agent import service as service_module
from threat_report_agent.config import Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, ToolRun
from threat_report_agent.service import AnalysisService
from threat_report_agent.task.task_runner import TASK_HOST_MEMBERS
from threat_report_agent.tools.tool_execution import TemporalToolExecutor

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "threat_report_agent"
RUNNER = PACKAGE / "task" / "task_runner.py"

#: The port method the host-injected executor is called through. Named once so the cancellation-path test and its
#: failure message cannot drift apart.
PORT_CANCEL = "cancel"


def _parameters(function: object) -> list[tuple[str, str]]:
    """`(name, kind)` for every parameter, so a RENAMED or REORDERED parameter fails and not only a retyped one."""
    return [
        (parameter.name, str(parameter.kind))
        for parameter in inspect.signature(function).parameters.values()  # type: ignore[arg-type]
    ]


def _runner_tree() -> ast.Module:
    return ast.parse(RUNNER.read_text(encoding="utf-8", errors="replace"))


def _task_host_protocol(tree: ast.Module) -> ast.ClassDef:
    return next(
        node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "TaskHost"
    )


def test_the_ports_cancel_takes_a_workflow_id_not_a_request_view() -> None:
    """R2, pinned as a SIGNATURE rather than as prose: the id, not a view - and `execute` unchanged.

    Both halves are asserted because only the pair states the asymmetry: a port whose BOTH methods took the view would
    pass a one-sided check, and the asymmetry is exactly what the decision is about.
    """
    cancel = _parameters(ports.ToolExecutionPort.cancel)
    assert cancel == [("self", "POSITIONAL_OR_KEYWORD"), ("workflow_id", "POSITIONAL_OR_KEYWORD")], (
        f"ToolExecutionPort.cancel must take the workflow id, not the request view; it takes {cancel}. MEASURED "
        "rationale (docs/p35-prep-measurement-20260922.md section 5, R2): the real cancellation callers hold an id "
        "string from the persisted row's environment['workflow_id'] (task/task_runner.py:508, :625), the id is "
        "DERIVED inside the implementation from ten fields the view already carries (tool_execution.py:112-130), and "
        "ToolRunRequestView has no workflow_id field at all"
    )
    annotation = inspect.signature(ports.ToolExecutionPort.cancel).parameters["workflow_id"].annotation
    assert annotation in (str, "str"), (
        f"cancel's id parameter is annotated {annotation!r}; it must be `str` - the callers' source is a JSON "
        "environment value and the port must say so"
    )
    execute = _parameters(ports.ToolExecutionPort.execute)
    assert execute == [("self", "POSITIONAL_OR_KEYWORD"), ("request", "POSITIONAL_OR_KEYWORD")], (
        f"ToolExecutionPort.execute must keep taking the request view; it takes {execute}"
    )


def test_the_temporal_executor_satisfies_the_port_in_shape_and_in_signature() -> None:
    """`isinstance` is necessary and NOT sufficient, so the signatures are compared too."""
    executor = TemporalToolExecutor("127.0.0.1:7233")
    assert isinstance(executor, ports.ToolExecutionPort), (
        "TemporalToolExecutor no longer satisfies the runtime-checkable ToolExecutionPort; the host can no longer "
        "hand it over as the seam"
    )
    for method in ("execute", PORT_CANCEL):
        expected = _parameters(getattr(ports.ToolExecutionPort, method))
        actual = _parameters(getattr(TemporalToolExecutor, method))
        assert actual == expected, (
            f"TemporalToolExecutor.{method} does not match ToolExecutionPort.{method}: {actual} != {expected}. "
            "`runtime_checkable` compares member PRESENCE only, so this signature comparison is the part that would "
            "notice a reverted parameter"
        )
    assert callable(TemporalToolExecutor.cancel_workflow), (
        "cancel_workflow is the name existing callers use (tests/test_tool_execution.py patches it to observe "
        "cancellation); the port method delegates to it and must not have replaced it"
    )


def test_the_port_cancel_delegates_to_cancel_workflow(monkeypatch: pytest.MonkeyPatch) -> None:
    """`cancel(id)` must reach `cancel_workflow(id)` with the SAME id - a delegation, not a second implementation."""
    seen: list[str] = []

    async def fake_cancel_workflow(_: TemporalToolExecutor, workflow_id: str) -> None:
        seen.append(workflow_id)

    monkeypatch.setattr(TemporalToolExecutor, "cancel_workflow", fake_cancel_workflow)
    asyncio.run(TemporalToolExecutor("127.0.0.1:7233").cancel("toolrun-delegated"))
    assert seen == ["toolrun-delegated"], (
        f"cancel did not delegate to cancel_workflow with the same id; cancel_workflow saw {seen}"
    )


def test_the_task_host_pin_is_the_members_the_module_uses_in_both_directions() -> None:
    """BOTH directions, from the module's own AST: nothing off the port, and no dead member on it.

    This is stated here as well as in `tests/test_task_runner_contract.py` ON PURPOSE: that file derives one side
    from `service.py`'s candidate spine, while this one compares the pin against the `host.` references the module
    actually makes and against the `TaskHost` declaration - which is the pair that catches a member added to the pin
    without a reader (dead interface) or a reader without a pin member (a runtime `AttributeError`).
    """
    tree = _runner_tree()
    host_refs = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "host"
    }
    protocol = _task_host_protocol(tree)
    declared = {
        child.target.id
        for child in protocol.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    } | {
        child.name for child in protocol.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert host_refs == set(TASK_HOST_MEMBERS), (
        f"the host pin and the module's `host.` references disagree: pin={sorted(TASK_HOST_MEMBERS)} "
        f"host_refs={sorted(host_refs)}"
    )
    assert declared == set(TASK_HOST_MEMBERS), (
        f"TaskHost declares {sorted(declared)} but the pin is {sorted(TASK_HOST_MEMBERS)}"
    )
    # Stated AFTER the two-way comparison on purpose: the comparison is the general property, and this one is the
    # D-2 specific backstop for the case where the pin AND the module's references were reverted TOGETHER (equality
    # then still holds, and this is what still names the missing member).
    assert "tool_executor" in TASK_HOST_MEMBERS, (
        "tool_executor is not on TASK_HOST_MEMBERS, so the module no longer declares how it reaches the executor the "
        "host injects; P3.5-0/D-2 requires the injected port to be a pin member"
    )
    annotations = {
        child.target.id: ast.unparse(child.annotation)
        for child in protocol.body
        if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
    }
    assert annotations.get("tool_executor") == "ToolExecutionPort", (
        f"TaskHost must declare tool_executor as the PORT; it declares {annotations.get('tool_executor')!r}. A "
        "locally invented Protocol here would be a second interface face for the same concept"
    )


def test_the_task_module_receives_the_executor_instead_of_importing_the_adapter() -> None:
    """THE POINT OF D-2, pinned where the import gate is blind.

    MEASURED (`.scratch/p35-0-d2-canfail.py` T4): re-adding the import and using it keeps
    `scripts/check-import-graph.py --strict` GREEN, because the edge was legal before this step. So this assertion,
    not the gate, is what keeps the consumer off the transport adapter.
    """
    tree = _runner_tree()
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)

    leaky = sorted(name for name in imported if name == "threat_report_agent.tools" or name.startswith("threat_report_agent.tools."))
    assert not leaky, (
        f"task/task_runner.py imports the tool implementation module ({leaky}); P3.5-0/D-2 requires the executor to "
        "arrive from the host as ports.ToolExecutionPort instead, so that a P3.5 emulation coordinator does not "
        "inherit the Temporal transport through this module"
    )
    assert "threat_report_agent.ports" in imported, (
        "the runner must import the PORT it is handed; it does not import threat_report_agent.ports at all"
    )
    names = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "TemporalToolExecutor" not in names, (
        "task_runner.py still names TemporalToolExecutor; the adapter must be reachable only through the host's "
        "tool_executor attribute"
    )


def test_a_workflow_id_reaches_the_host_injected_executor(
    test_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """END TO END: the id from the persisted row reaches the executor's PORT method, through the host.

    The executor is replaced at the NAME the host's property builds from (`service.TemporalToolExecutor`), so this
    exercises the real injection path - property -> adapter -> port method - instead of calling the module function
    with a hand-built stub host. A recorder that only implemented `cancel_workflow` would NOT pass: the assertion is
    on the port method, which is the seam D-2 defines.
    """
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    case = service.create_case("D-2 port injection")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        running = ToolRun(
            task_id=task.id,
            artifact_id=None,
            tool_name="ghidra-headless",
            tool_version="12.1.2",
            status="RUNNING",
            parameters={},
            environment={"workflow_id": "toolrun-d2-port"},
        )
        session.add(running)
        session.flush()
        task_id = task.id
        tool_run_id = running.id

    seen: list[str] = []
    built: list[object] = []

    class _PortRecorder:
        """A legal `ToolExecutionPort` that records what it is asked to cancel and refuses to run anything."""

        def __init__(self, temporal_address: str) -> None:
            self.temporal_address = temporal_address
            built.append(self)

        async def execute(self, request: object) -> object:
            raise AssertionError("a cancellation must not call execute")

        async def cancel(self, workflow_id: str) -> None:
            seen.append(workflow_id)

    monkeypatch.setattr(service_module, "TemporalToolExecutor", _PortRecorder)
    assert isinstance(_PortRecorder("127.0.0.1:7233"), ports.ToolExecutionPort), (
        "the recorder is not a legal ToolExecutionPort, so a pass here would say nothing about the seam"
    )

    result = service.cancel_tool_run(task_id, tool_run_id, actor="d2-contract")

    assert built, "the host never built an executor, so the port was not reached at all"
    assert seen == ["toolrun-d2-port"], (
        "the workflow id did not reach the host-injected executor's port method; the executor's "
        f"cancel({PORT_CANCEL}) saw {seen}. The id must come from the persisted row's environment['workflow_id']"
    )
    assert result["cancelled_tool_run_id"] == tool_run_id
