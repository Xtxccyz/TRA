"""P3.6 contract: the read-only query slice's host pin, its layer, its delegations AND that it stays read-only.

WHY THIS FILE EXISTS. Same reasons as `tests/test_report_revision_writer_contract.py` (the pin's authority must be a
TRACKED test, not a gitignored instrument), plus one that is specific to this slice: plan §P3.6's success criterion is
that **a query never changes a snapshot or a revision**, so "read-only" is asserted here rather than described in a
docstring. A later slice that turns a reader into a writer would still import cleanly and pass every structural gate -
this test is what stops that.

WHAT IT PINS DOWN:
* the pin is EXACTLY the receiver set, in both directions (a missing member is a runtime `NameError`; an unused one is
  dead interface);
* the Protocol declares exactly the pin;
* the module never imports `service` (and the HTTP adapter is not imported by `investigation` - checked by the import
  graph gate, this test covers the module's own side);
* every delegation forwards every signature parameter (this phase shipped a dropped parameter twice);
* each delegation's `__doc__` equals its implementation's (the mover dropped docstrings for eleven of eleven members
  until P3.4-2 fixed it);
* **no moved body writes to the session** - the read-only property, as a behavioural assertion on the AST.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import service, workbench_query  # noqa: E402

MODULE_PATH = pathlib.Path(workbench_query.__file__)
MODULE_TREE = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
MOVED_MEMBERS = (
    "task_view",
    "workbench_domain_view",
    "workbench_query_evidence",
    "model_configuration_view",
    "workbench_thread",
    "_config_route_view",
    "_unique_execution_threads_for_view",
)
WRITES = ("add", "delete", "flush", "commit", "merge")


def _module_functions() -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in MODULE_TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _host_receivers() -> set[str]:
    receivers: set[str] = set()
    for node in _module_functions().values():
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == "host"
            ):
                receivers.add(child.attr)
    return receivers


def _protocol_members() -> set[str]:
    for node in MODULE_TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "WorkbenchQueryReaderHost":
            declared = set()
            for body in node.body:
                if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    declared.add(body.name)
                elif isinstance(body, ast.AnnAssign) and isinstance(body.target, ast.Name):
                    declared.add(body.target.id)
            return declared
    raise AssertionError("WorkbenchQueryReaderHost is not declared in workbench_query.py")


def test_pin_equals_the_receivers_the_moved_bodies_actually_read() -> None:
    pin = set(workbench_query.WORKBENCH_QUERY_HOST_MEMBERS)
    receivers = _host_receivers()
    assert pin == receivers, (
        f"pin and bodies disagree: only in pin {sorted(pin - receivers)}, only in bodies "
        f"{sorted(receivers - pin)}"
    )


def test_protocol_declares_exactly_the_pin() -> None:
    assert _protocol_members() == set(workbench_query.WORKBENCH_QUERY_HOST_MEMBERS)


def test_module_never_imports_service() -> None:
    imports = {
        alias.name
        for node in ast.walk(MODULE_TREE)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        f"{node.module}.{alias.name}" if node.module else alias.name
        for node in ast.walk(MODULE_TREE)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    offenders = sorted(name for name in imports if "service" in name.split("."))
    assert not offenders, f"workbench_query.py imports the service layer: {offenders}"


def test_moved_names_exist_in_both_homes() -> None:
    for name in MOVED_MEMBERS:
        assert hasattr(workbench_query, name), f"{name} is not defined in workbench_query.py"
        assert hasattr(service.AnalysisService, name), f"service.AnalysisService lost its {name} delegation"


def test_the_slice_is_read_only() -> None:
    """Plan §P3.6's success criterion, asserted rather than described: no moved body writes to the session.

    MEASURED AT DESIGN TIME: all seven bodies contain zero `session.add`/`delete`/`flush`/`commit`/`merge` calls; the
    `scalars`/`scalar` calls they do contain are SELECT reads. The `workbench_*` members that DO write (submit_action,
    write_report_file, start_static_analysis, model_complete, link_session, evidence purge, unbind_analysis) and the one
    that DRIVES analysis (wait_for_analysis_update) were deliberately left in `service.py`, so this assertion also
    documents the boundary of the slice.
    """
    offenders: list[str] = []
    for name, node in _module_functions().items():
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            if not isinstance(func, ast.Attribute) or func.attr not in WRITES:
                continue
            owner = func.value
            if isinstance(owner, ast.Name) and owner.id in {"session", "host"}:
                offenders.append(f"{name}: {ast.unparse(child)[:60]}")
            elif isinstance(owner, ast.Attribute) and owner.attr == "database":
                offenders.append(f"{name}: {ast.unparse(child)[:60]}")
    assert not offenders, f"the read-only slice now writes to the session: {offenders}"


def test_every_delegation_forwards_every_parameter(monkeypatch) -> None:
    """The delegation-shape gate, checked BEHAVIOURALLY (a sentinel per parameter), never with `getsource`."""
    for name in MOVED_MEMBERS:
        original = getattr(workbench_query, name)
        static = inspect.getattr_static(service.AnalysisService, name)
        raw = static.__func__ if isinstance(static, (classmethod, staticmethod)) else static
        signature = inspect.signature(original)
        takes_host = "host" in signature.parameters
        record: dict[str, object] = {}

        def fake(*args, **kwargs):
            record["args"] = args
            record["kwargs"] = kwargs
            return "DELEGATED"

        monkeypatch.setattr(workbench_query, name, fake)
        sentinels = {
            parameter.name: object()
            for parameter in signature.parameters.values()
            if parameter.name != "host"
        }
        receiver = object()
        args: list[object] = [receiver] if not isinstance(static, staticmethod) else []
        kwargs: dict[str, object] = {}
        for parameter in signature.parameters.values():
            if parameter.name == "host":
                continue
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
                args.append(sentinels[parameter.name])
            else:
                kwargs[parameter.name] = sentinels[parameter.name]
        assert raw(*args, **kwargs) == "DELEGATED", f"{name}: the delegation did not reach the moved function"
        expected = ([receiver] if takes_host else []) + [
            sentinels[p.name] for p in signature.parameters.values()
            if p.name != "host" and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        assert record["args"] == tuple(expected), (
            f"{name}: the moved function received {len(record['args'])} positional argument(s), expected {len(expected)}"
        )
        assert record["kwargs"] == kwargs, f"{name}: keyword-only parameters were not forwarded verbatim"
        monkeypatch.undo()


def test_delegations_keep_the_implementations_docstring() -> None:
    for name in MOVED_MEMBERS:
        assert getattr(service.AnalysisService, name).__doc__ == getattr(workbench_query, name).__doc__, (
            f"{name}: the delegation and the implementation document themselves differently"
        )


def test_lifecycle_delegations_are_plain_instance_methods() -> None:
    for name in MOVED_MEMBERS:
        attribute = inspect.getattr_static(service.AnalysisService, name)
        assert not isinstance(attribute, (classmethod, staticmethod)), f"{name} gained a decorator"
