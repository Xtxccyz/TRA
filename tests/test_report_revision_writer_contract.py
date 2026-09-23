"""P3.4 contract: the revision-writer slice's host pin, its layer, and both call paths agreeing.

WHY THIS FILE EXISTS AS A TRACKED TEST AND NOT AS A `.scratch` INSTRUMENT. The design's Standards review found that the
pin assertion lived only in `.scratch/p34-pin.py` - and plan section 4.3/4.4 forbid gates that depend on gitignored
files, because a fresh clone cannot re-derive them. `p34-pin.py` stays as the design-time convenience; THIS file is the
authority, and the same checks run here as behavioural assertions rather than printed numbers.

WHAT IT PINS DOWN, each because a real defect in this phase came from NOT pinning it:

* **The pin is EXACTLY the receiver set**, in both directions. A pin missing a member makes the mover emit a bare name
  (a `NameError` when a report is written, not at import); a pin with a member the bodies no longer use is dead
  interface. Both were real: the P3.3f-2 pin instrument could not see `cls.` receivers at all.
* **The Protocol declares exactly the pin.** The bodies annotate `host: ReportRevisionWriterHost`, and a Protocol that
  does not match the pin documents an interface the module does not have.
* **The layer**: `report/revision_writer.py` must never import `service` (plan section 3.2), which is also what keeps
  the module graph acyclic.
* **Decorator preservation on the delegations**: `AnalysisService._select_report_evidence_rows`,
  `_migrate_snapshot_payload` and `_canonical_sha256` are called BY CLASS NAME from ten test sites
  (`AnalysisService._canonical_sha256(value)`), so a delegation that lost `@classmethod` would still import cleanly and
  fail only when a report was built.
* **Both call paths agree** on real inputs, which is the part a structural diff cannot see: the module function and the
  `service` delegation must return equal values, not merely exist.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import service  # noqa: E402
from threat_report_agent.report import revision_writer  # noqa: E402

MODULE_PATH = pathlib.Path(revision_writer.__file__)
MODULE_TREE = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
P3_4_1_MEMBERS = (
    "_snapshot_report_context",
    "_select_report_evidence_rows",
    "_migrate_snapshot_payload",
    "_canonical_sha256",
)


P3_4_2_MEMBERS = (
    "_create_report_revision",
    "edit_report",
    "get_report_revision",
    "recompose_report",
    "publish_report",
    "submit_analyst_draft",
    "workbench_submit_analyst_draft",
)
#: EVERY member the whole P3.4 slice moved. The gates below iterate THIS, and P3.4-2 is the reason: a pin that grew to
#: eleven members while the delegation gates still checked four would have left the seven new delegations uncovered.
MOVED_MEMBERS = P3_4_1_MEMBERS + P3_4_2_MEMBERS


def _module_functions() -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in MODULE_TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _host_receivers() -> set[str]:
    """Every `host.<name>` the moved bodies read, i.e. what the pin must contain - derived, never listed."""
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
        if isinstance(node, ast.ClassDef) and node.name == "ReportRevisionWriterHost":
            declared = set()
            for body in node.body:
                if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    declared.add(body.name)
                elif isinstance(body, ast.AnnAssign) and isinstance(body.target, ast.Name):
                    declared.add(body.target.id)
            return declared
    raise AssertionError("ReportRevisionWriterHost is not declared in report/revision_writer.py")


def test_pin_equals_the_receivers_the_moved_bodies_actually_read() -> None:
    pin = set(revision_writer.REVISION_WRITER_HOST_MEMBERS)
    receivers = _host_receivers()
    assert pin == receivers, (
        f"pin and bodies disagree: only in pin {sorted(pin - receivers)}, only in bodies "
        f"{sorted(receivers - pin)} - a pin missing a member ships a NameError, a pin with an unused member ships "
        "dead interface"
    )


def test_protocol_declares_exactly_the_pin() -> None:
    pin = set(revision_writer.REVISION_WRITER_HOST_MEMBERS)
    declared = _protocol_members()
    assert declared == pin, f"Protocol {sorted(declared)} != pin {sorted(pin)}"


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
    assert not offenders, f"report/revision_writer.py imports the service layer: {offenders}"


def test_moved_names_exist_in_both_homes() -> None:
    for name in MOVED_MEMBERS:
        assert hasattr(revision_writer, name), f"{name} is not defined in report/revision_writer.py"
        assert hasattr(service.AnalysisService, name), f"service.AnalysisService lost its {name} delegation"


def test_delegations_keep_their_decorators() -> None:
    """Ten test sites call these BY CLASS NAME; a lost `@classmethod` imports fine and fails when a report is built."""
    expected = {
        "_select_report_evidence_rows": "classmethod",
        "_migrate_snapshot_payload": "classmethod",
        "_canonical_sha256": "classmethod",
        "_snapshot_report_context": None,
    }
    for name, decorator in expected.items():
        attribute = inspect.getattr_static(service.AnalysisService, name)
        if decorator is None:
            assert not isinstance(attribute, (classmethod, staticmethod)), f"{name} gained a decorator"
        else:
            assert isinstance(attribute, classmethod), f"{name} is not a {decorator} any more"
        # AND THE MOVE DID NOT FLATTEN THE MODULE SIDE EITHER: the body lives in the new module as a plain function.
        assert name in _module_functions(), f"{name}'s implementation did not move into report/revision_writer.py"


def test_both_call_paths_agree_on_canonical_sha256() -> None:
    class Host:
        SNAPSHOT_SCHEMA_VERSION = service.AnalysisService.SNAPSHOT_SCHEMA_VERSION

        @staticmethod
        def _canonical_json_chunks(value, *, exclude_keys=(), chunk_bytes=None):
            return service.AnalysisService._canonical_json_chunks(
                value, exclude_keys=exclude_keys, chunk_bytes=chunk_bytes
            )

    host = Host()
    for value in ({"b": 1, "a": [1, 2, {"c": None}]}, {"a": 1, "secret": "x"}, [1, "two", None]):
        from_module = revision_writer._canonical_sha256(host, value)
        from_service = service.AnalysisService._canonical_sha256(value)
        assert from_module == from_service, f"the two homes disagree for {value!r}"
        assert isinstance(from_module, str) and len(from_module) == 64


def test_both_call_paths_agree_on_evidence_selection() -> None:
    rows = [
        {"id": f"e{index}", "kind": kind, "priority": index}
        for index, kind in enumerate(["string", "api", "string", "hash", "api", "thread"])
    ]
    from_module = revision_writer._select_report_evidence_rows(
        copy.deepcopy(rows), referenced_ids={"e5"}, limit=4
    )
    from_service = service.AnalysisService._select_report_evidence_rows(
        copy.deepcopy(rows), referenced_ids={"e5"}, limit=4
    )
    assert list(from_module) == list(from_service), "the two homes select different evidence rows"
    assert from_module, "the selection is empty, so agreement would be vacuous"


def test_evidence_window_limit_moved_with_its_value() -> None:
    """The P1.4 `threshold_comparisons` surface changed by ONE entry when this constant moved, and this test is why
    re-recording that surface is legitimate rather than a gate being silenced: the comparison text went from
    `len(evidence_rows) > self._REPORT_PROJECTION_EVIDENCE_LIMIT` to the module-level spelling, so the THRESHOLD must be
    proven unchanged (4,096 - the value the surface recorded), and the class must no longer carry a second definition
    that could drift from the moved one.
    """
    assert revision_writer._REPORT_PROJECTION_EVIDENCE_LIMIT == 4096, (
        "the moved Evidence window limit is not the recorded 4,096, so the P1.4 surface change was NOT a pure rename"
    )
    assert not hasattr(service.AnalysisService, "_REPORT_PROJECTION_EVIDENCE_LIMIT"), (
        "the class still defines the limit, so there are now TWO thresholds that can drift apart"
    )


def test_snapshot_payload_migration_uses_the_pinned_schema_version() -> None:
    class Host:
        SNAPSHOT_SCHEMA_VERSION = service.AnalysisService.SNAPSHOT_SCHEMA_VERSION

    payload = {"schema_version": "1.0", "payload": {"sealed": True}, "rows": [1, 2, 3]}
    migrated = revision_writer._migrate_snapshot_payload(Host(), "snapshot-1", copy.deepcopy(payload))
    from_service = service.AnalysisService._migrate_snapshot_payload("snapshot-1", copy.deepcopy(payload))
    assert migrated == from_service, "the two homes migrate the payload differently"


def test_every_delegation_forwards_every_parameter(monkeypatch) -> None:
    """THE DELEGATION-SHAPE GATE (design section 8, gate 11), checked BEHAVIOURALLY.

    This phase has twice shipped a delegation that did not forward everything: P3.2e dropped a receiver parameter and
    P3.3f-2 dropped `*args, **kwargs`. Both were found by a failing test far from the move, because a delegation with
    the WRONG SHAPE still imports and still carries the right NAME.

    WHY NOT `inspect.getsource`. The first version of this gate read the delegation's source. That is the pattern plan
    P3.7 exists to remove from tests, and the P1.4 surface counts it (`test_getsource_count`), so the tracked gates went
    red for the right reason. This version is also strictly stronger: the moved function is monkeypatched, the
    delegation is called with a UNIQUE SENTINEL per parameter, and the recording must show exactly those sentinels - in
    order positionally, by name for keyword-only. Source text cannot see a substituted literal, a reordered argument or
    a swapped pair; a sentinel can.
    """
    for name in MOVED_MEMBERS:
        original = getattr(revision_writer, name)
        static = inspect.getattr_static(service.AnalysisService, name)
        raw = static.__func__ if isinstance(static, (classmethod, staticmethod)) else static
        signature = inspect.signature(original)
        takes_host = "host" in signature.parameters
        record: dict[str, object] = {}

        def fake(*args, **kwargs):
            record["args"] = args
            record["kwargs"] = kwargs
            return "DELEGATED"

        monkeypatch.setattr(revision_writer, name, fake)

        # ONE SENTINEL PER PARAMETER, so a swapped or duplicated argument cannot look correct by accident.
        sentinels = {
            parameter.name: object()
            for parameter in signature.parameters.values()
            if parameter.name != "host"
        }
        receiver = object()
        # THE RECEIVER IS ALWAYS PASSED, but only a HOST-TAKING moved function RECEIVES it. MEASURED failure of the
        # first behavioural version: for the classmethod `_select_report_evidence_rows` the moved function takes no host,
        # so I passed no receiver at all and the call died with `missing 1 required positional argument: 'rows'` -
        # `cls` is consumed by the delegation, not forwarded.
        needs_receiver = not isinstance(static, staticmethod)
        args: list[object] = [receiver] if needs_receiver else []
        kwargs: dict[str, object] = {}
        for parameter in signature.parameters.values():
            if parameter.name == "host":
                continue
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
                args.append(sentinels[parameter.name])
            else:
                kwargs[parameter.name] = sentinels[parameter.name]

        assert raw(*args, **kwargs) == "DELEGATED", f"{name}: the delegation did not reach the moved function"

        expected_args = ([receiver] if takes_host else []) + [
            sentinels[p.name] for p in signature.parameters.values()
            if p.name != "host" and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        assert record["args"] == tuple(expected_args), (
            f"{name}: the moved function received {len(record['args'])} positional argument(s) but the delegation was "
            f"given {len(expected_args)} - a dropped, duplicated, reordered or literal-substituted argument is exactly "
            "the P3.2e/P3.3f-2 defect"
        )
        assert record["kwargs"] == kwargs, (
            f"{name}: keyword-only parameters were not forwarded verbatim (got {sorted(record['kwargs'])}, "
            f"expected {sorted(kwargs)})"
        )

        monkeypatch.undo()


def test_compose_gate_exception_is_the_same_object() -> None:
    """The exception is the compose gate's PUBLIC contract, so the move had to preserve IDENTITY, not just the name.

    `service.ReportComposeGateRejected` is caught by the workbench route's 422 handler and the plugin's
    `GATE_REJECTED` branch. A second definition in the new module would import cleanly, pass every structural gate, and
    silently stop catching the exception the module actually raises - so the assertion is `is`, not `==`, plus the
    attributes handlers read (`code`, `violations`) and the `ValueError` base the existing handlers rely on.
    """
    assert service.ReportComposeGateRejected is revision_writer.ReportComposeGateRejected, (
        "the compose-gate exception exists twice; `except service.ReportComposeGateRejected` would stop catching"
    )
    rejected = revision_writer.ReportComposeGateRejected(["first", "second"])
    assert rejected.code == "REPORT_COMPOSE_GATE_REJECTED"
    assert rejected.violations == ("first", "second")
    assert isinstance(rejected, ValueError)
    assert "analyst draft failed the report compose gate: first; second" in str(rejected)


def test_lifecycle_delegations_are_plain_instance_methods() -> None:
    """The seven P3.4-2 delegations are ordinary methods - and saying so separates them from the P3.4-1 four.

    `_select_report_evidence_rows`, `_migrate_snapshot_payload` and `_canonical_sha256` are `@classmethod`s that TEN
    test sites call BY CLASS NAME (`AnalysisService._canonical_sha256(value)`), so their decorators must survive; these
    seven are reached through an instance. A slice that flattened one into the other would still import cleanly, which is
    why the expectation is written down per member instead of assumed from the previous slice.
    """
    for name in P3_4_2_MEMBERS:
        attribute = inspect.getattr_static(service.AnalysisService, name)
        assert not isinstance(attribute, (classmethod, staticmethod)), (
            f"{name} gained a {type(attribute).__name__}; callers reach it through an instance"
        )
        assert name in _module_functions(), f"{name}'s implementation did not move into report/revision_writer.py"


def test_delegations_keep_the_implementations_docstring() -> None:
    """`service.<name>.__doc__` must equal the implementation's - the mover dropped it for eleven of eleven members.

    MEASURED: `tests/test_analyst_draft_submission.py::test_service_method_exists_with_gate_semantics` reads
    `AnalysisService.submit_analyst_draft.__doc__` and asserts it mentions the compose gate. It failed because the
    delegated method's `__doc__` was `""` - the tool emitted signature + return only. One reader caught it; equality
    across every member is what stops the next slice from reintroducing it.
    """
    for name in MOVED_MEMBERS:
        implementation_doc = getattr(revision_writer, name).__doc__
        delegation_doc = getattr(service.AnalysisService, name).__doc__
        assert delegation_doc == implementation_doc, (
            f"{name}: the delegation and the implementation document themselves differently "
            f"({delegation_doc!r} vs {implementation_doc!r})"
        )
