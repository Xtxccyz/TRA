"""P1.2 contract: the ports stay small, stay pure, and are actually satisfiable.

Plan P1.2 mandates a **deletion test** on every port: a port that merely forwards a large class's methods verbatim
has failed. "Small enough" is otherwise an opinion, so the surface is CAPPED and asserted here: growing one of
these into a façade of `AnalysisService` fails this test instead of passing review by looking reasonable.

It also proves the ports are satisfiable, because a `runtime_checkable` Protocol is only a shape - a port nobody
can implement is a design that has not been tested. Two deterministic adapters below implement both ports with
no database, no model and no container.

    python -m pytest -q tests/test_ports.py
"""
from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import ports  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
BANNED = ("sqlalchemy", "psycopg", "fastapi", "starlette", "requests", "httpx", "openai", "anthropic",
          "threat_report_agent.service", "threat_report_agent.models")

#: The most callables any port here may expose. Two is P1.2's "smaller than the implementation" made checkable;
#: if a real need exceeds it, the plan's remedy is to narrow the seam rather than to raise this number silently.
MAX_PORT_METHODS = 2


def port_protocols() -> list[type]:
    """The PORTS only. Data-only projection protocols (named `*View`) are inputs and outputs, not seams, and a
    view has no callables to cap - counting them as ports would let a real port hide among them."""
    return [
        member
        for name, member in vars(ports).items()
        if inspect.isclass(member) and getattr(member, "_is_protocol", False)
        and member.__module__ == ports.__name__ and not name.endswith("View")
    ]


def view_protocols() -> list[type]:
    return [
        member
        for name, member in vars(ports).items()
        if inspect.isclass(member) and getattr(member, "_is_protocol", False)
        and member.__module__ == ports.__name__ and name.endswith("View")
    ]


def public_callables(protocol: type) -> list[str]:
    return sorted(
        name
        for name, value in vars(protocol).items()
        if not name.startswith("_") and callable(value)
    )


def test_every_port_exposes_a_small_surface() -> None:
    """THE DELETION TEST, made mechanical."""
    found = port_protocols()
    assert found, "no protocols found in ports.py, so this test would pass vacuously"
    for protocol in found:
        callables = public_callables(protocol)
        assert len(callables) <= MAX_PORT_METHODS, (
            f"{protocol.__name__} exposes {len(callables)} callables ({callables}); P1.2 requires an interface "
            "smaller than its implementation, and the deletion test says a wider port must go back to P1"
        )


def test_ports_module_is_free_of_the_banned_imports() -> None:
    tree = ast.parse((PACKAGE / "ports.py").read_text(encoding="utf-8", errors="replace"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    hits = [item for item in imports for ban in BANNED if ban in item]
    assert not hits, (
        f"ports.py must stay pure; found {hits}. A port that imports the ORM or the service is not a seam."
    )


class _DeterministicRevisionWriter:
    """The deterministic test adapter P1.2 asks for: no database, no model, no container."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []

    def compose(self, snapshot: object, *, draft: str = "") -> str:
        body = "# 静态分析报告\n\n确定性正文。\n"
        return body if not draft.strip() else body

    def write(self, snapshot: object, *, draft: str = "", parent_revision_id: str | None = None) -> object:
        markdown = self.compose(snapshot, draft=draft)
        self.writes.append((getattr(snapshot, "id", "?"), markdown))
        return _FakeRevision(markdown, parent_revision_id)


class _FakeRevision:
    """Minimal ReportRevisionView shape, so the adapter satisfies the projection protocol too."""

    id = "rev-1"
    task_id = "task-1"
    snapshot_id = "snap-1"
    parent_revision_id = None
    status = "draft"
    author = "system"
    selected_modules: tuple[str, ...] = ()
    document: dict[str, object] = {}
    edit_kind = "compose"
    created_at = None

    def __init__(self, markdown: str, parent_revision_id: str | None) -> None:
        self.markdown = markdown
        self.parent_revision_id = parent_revision_id


class _FakeQueryReader:
    def revision(self, task_id: str, revision_id: str | None = None) -> object:
        return _FakeRevision("# 正文\n", None)

    def evidence(self, task_id: str, limit: int | None = None) -> tuple[object, ...]:
        return ()


# --- deterministic adapters for the four ports added after the consumer surveys (P1.2) ---------------


class _FakePlanner:
    """No provider, no HTTP, no key. Returns the same outcome for the same request, which is the point."""

    def __init__(self, status: str = "SUCCEEDED", parsed: object | None = None) -> None:
        self.status = status
        self.parsed = parsed if parsed is not None else {"actions": []}
        self.calls: list[str] = []

    def plan(self, request: object) -> object:
        self.calls.append(str(getattr(request, "module", "?")))
        return _FakePlanningOutcome(self.status, self.parsed)


class _FakePlanningOutcome:
    error: str | None = None
    run_id = "run-1"
    attempts: tuple[object, ...] = ()
    model_call_id = "call-1"
    raw_response: bytes | None = None

    def __init__(self, status: str, parsed: object) -> None:
        self.status = status
        self.parsed = parsed


class _FakeToolExecutor:
    """No Temporal, no container. Records the requests so idempotence can be asserted by a caller."""

    def __init__(self, status: str = "SUCCEEDED") -> None:
        self.status = status
        self.executed: list[str] = []
        self.cancelled: list[str] = []

    async def execute(self, request: object) -> object:
        self.executed.append(str(getattr(request, "tool_name", "?")))
        return _FakeToolResult(self.status)

    async def cancel(self, request: object) -> None:
        self.cancelled.append(str(getattr(request, "tool_name", "?")))


class _FakeToolResult:
    output_sha256: str | None = "sha"
    output_storage_key: str | None = "key"
    error: str | None = None
    started_at: object | None = None
    finished_at: object | None = None
    worker_metadata: object = {}

    def __init__(self, status: str) -> None:
        self.status = status


class _FakeStaticEvidence:
    """No subprocess. `disassemble` returns the tool-missing shape, so the caller's reason path is exercised."""

    detected_type = "pe"

    def analyze(self, content: bytes, logical_path: str) -> object:
        return _FakeParserResult(len(content))

    def disassemble(
        self,
        content: bytes,
        logical_path: str,
        *,
        budget_seconds: int,
        cancelled: object | None = None,
        processor: str | None = None,
    ) -> object:
        return _FakeDisassembly("FAILED", "GHIDRA_HEADLESS_UNAVAILABLE", {})


class _FakeParserResult:
    facts: tuple[object, ...] = ()
    pe: object | None = None
    limitations: tuple[str, ...] = ()

    def __init__(self, size: int) -> None:
        self.detected_type = "pe" if size else "unknown"


class _FakeDisassembly:
    def __init__(self, status: str, error: str | None, output: object) -> None:
        self.status = status
        self.error = error
        self.output = output


class _FakeEmulation:
    """No emulator. Every pass reports a deferral as a placeholder, never as an executed window."""

    def __init__(self, placeholder_status: str = "DEFERRED_TO_WORKER") -> None:
        self.placeholder_status = placeholder_status
        self.passes: list[str] = []

    def emulate(
        self,
        task_id: str,
        artifact_id: str,
        *,
        scheduler: str | None = None,
        planned_tool_names: tuple[str, ...] = (),
        cancellation_requested: object | None = None,
    ) -> object:
        self.passes.append(task_id)
        return _FakeEmulationOutcome(self.placeholder_status)

    def is_real_result(self, row: object) -> bool:
        status = str(getattr(row, "status", "") or "").upper()
        return bool(status) and status not in _PLACEHOLDERS


class _FakeEmulationOutcome:
    real_result_count = 0
    real_result_count_delta = 0
    cancelled = False
    output_read_error: str | None = None
    limitations: tuple[str, ...] = ("emulation deferred to the isolated worker",)

    def __init__(self, placeholder_status: str) -> None:
        self.placeholder_status = placeholder_status


#: Mirrors `controlled_emulation.PLACEHOLDER_STATUSES` for the adapter above. Duplicated HERE on purpose: this is
#: test data, not a second canonical definition, and the real predicate is exercised by
#: `tests/test_controlled_emulation.py`.
_PLACEHOLDERS = frozenset({"", "DEFERRED_TO_WORKER", "WORKER_REQUIRED", "SUPERSEDED_BY_WORKER", "NOT_EXECUTED"})


def test_the_ports_are_satisfiable_by_a_deterministic_adapter() -> None:
    """A port nobody can implement is an untested design, so implement all six here without any infrastructure."""
    assert isinstance(_DeterministicRevisionWriter(), ports.ReportRevisionWriter)
    assert isinstance(_FakeQueryReader(), ports.WorkbenchQueryReader)
    assert isinstance(_FakePlanner(), ports.ModelPlanningPort)
    assert isinstance(_FakeToolExecutor(), ports.ToolExecutionPort)
    assert isinstance(_FakeStaticEvidence(), ports.StaticEvidencePort)
    assert isinstance(_FakeEmulation(), ports.EmulationPort)


def test_the_measured_view_fields_are_satisfied_by_the_adapters() -> None:
    """The views are contracts too, and a misspelt field there is silent for the same reason a misspelt port
    member is: `runtime_checkable` compares member presence only."""
    assert isinstance(_FakePlanningOutcome("SUCCEEDED", {}), ports.PlanningOutcomeView)
    assert isinstance(_FakeToolResult("SUCCEEDED"), ports.ToolRunResultView)
    assert isinstance(_FakeParserResult(4), ports.StaticEvidenceView)
    assert isinstance(_FakeDisassembly("FAILED", None, {}), ports.StaticDisassemblyView)
    assert isinstance(_FakeEmulationOutcome("DEFERRED_TO_WORKER"), ports.EmulationOutcomeView)


def test_views_carry_no_callables_so_the_cap_counts_only_real_seams() -> None:
    """`port_protocols()` splits on the `View` suffix, so a mis-split would silently move a port out of the cap.

    MEASURED reason to assert it: if a data view ever grew a method it would be classified as a port and the cap
    would fail loudly - which is correct - but if a PORT were named `...View` it would escape the deletion test
    entirely. This pins both directions.
    """
    views = view_protocols()
    assert views, "no `*View` protocols found, so the port/view split is not being exercised"
    for view in views:
        assert not public_callables(view), f"{view.__name__} has callables, so it is a seam named like a view"
    for port in port_protocols():
        assert not port.__name__.endswith("View"), f"{port.__name__} is a port the cap would skip"


def test_the_deletion_test_can_fail() -> None:
    """Can-fail proof for the cap: a port that forwards a large class's methods must exceed it."""
    from typing import Protocol, runtime_checkable

    @runtime_checkable
    class _WidePort(Protocol):
        def a(self) -> None: ...
        def b(self) -> None: ...
        def c(self) -> None: ...

    assert len(public_callables(_WidePort)) == 3 > MAX_PORT_METHODS, (
        "the cap instrument cannot see a wide surface, so `test_every_port_exposes_a_small_surface` proves nothing"
    )


#: Fields a view declares that the canonical class does NOT have under that name, with where the adapter takes them
#: from. MEASURED by `.scratch/probe-p12-view-fidelity.py`: these two are the ONLY ones, and both are deliberate -
#: `AgentRunResult` nests the model response, and `StaticResult` keeps `pe` inside `summary`.
FLATTENED_FIELDS: dict[str, dict[str, str]] = {
    "PlanningOutcomeView": {
        "parsed": "AgentRunResult.response.parsed (service.py:14125, :22146, :23984)",
        "model_call_id": "AgentRunResult.response.model_call_id (service.py:22231)",
        "raw_response": "AgentRunResult.response.raw_response (service.py:14082, :22212)",
    },
    "StaticEvidenceView": {"pe": "StaticResult.summary['pe'] (service.py:16451, :16706, :19280)"},
}

#: Views with NO canonical class in the tree. `EmulationOutcomeView` is derived from what the orchestrator reads
#: today (`analysis_task_orchestration.py:432-435` -> `service.py:8579-8593`), and the adapter that produces it is
#: P3.5. Naming it here rather than leaving it out of the pairing is the difference between a measured gap and an
#: oversight.
VIEWS_WITHOUT_A_CANONICAL_CLASS: dict[str, str] = {
    "EmulationOutcomeView": "no producer exists yet; the adapter is P3.5",
}


def _canonical_classes() -> dict[str, type | None]:
    from threat_report_agent.agent_runtime import AgentRunResult
    from threat_report_agent.ghidra_adapter import GhidraRun
    from threat_report_agent.model_gateway import ModelAttempt, ModelRequest
    from threat_report_agent.static_analysis import StaticResult
    from threat_report_agent.tools.tool_execution import ToolRunRequest, ToolRunResult

    return {
        "PlanningRequestView": ModelRequest,
        "PlanningAttemptView": ModelAttempt,
        "PlanningOutcomeView": AgentRunResult,
        "ToolRunRequestView": ToolRunRequest,
        "ToolRunResultView": ToolRunResult,
        "StaticEvidenceView": StaticResult,
        "StaticDisassemblyView": GhidraRun,
        "EmulationOutcomeView": None,
    }


def _declared_fields(cls: type) -> set[str]:
    found = set(getattr(cls, "__annotations__", {}))
    model_fields = getattr(cls, "model_fields", None)
    if isinstance(model_fields, dict):
        found |= set(model_fields)
    return found


def test_every_view_field_comes_from_the_canonical_class_or_a_declared_flattening() -> None:
    """A view field with no source is a contract NOBODY can satisfy, and `runtime_checkable` would report the real
    object as unsatisfied at the point of use.

    This is the strongest statement available about the views without running the pipeline: every field is either
    on the canonical class today, or listed in `FLATTENED_FIELDS` with the expression the adapter uses. A future
    field added on a hunch fails here instead of becoming an unsatisfiable seam.
    """
    pairs = _canonical_classes()
    defined = {view.__name__ for view in view_protocols()}
    assert set(pairs) == defined, (
        "every `*View` in ports.py must be paired with the canonical class it projects, or recorded as having "
        f"none; paired={sorted(pairs)} defined={sorted(defined)}"
    )
    unpaired = {name for name, canonical in pairs.items() if canonical is None}
    assert unpaired == set(VIEWS_WITHOUT_A_CANONICAL_CLASS), (
        f"views with no canonical class are {sorted(unpaired)} but only "
        f"{sorted(VIEWS_WITHOUT_A_CANONICAL_CLASS)} is recorded with a reason"
    )
    for name, canonical in pairs.items():
        if canonical is None:
            continue
        view = getattr(ports, name)
        missing = sorted(_declared_fields(view) - _declared_fields(canonical))
        declared = sorted(FLATTENED_FIELDS.get(name, {}))
        assert missing == declared, (
            f"{name} declares {missing} which {canonical.__name__} does not have; declared flattenings for this "
            f"view are {declared}. Either the field is misspelt, or it is a real flattening and must be recorded "
            "in FLATTENED_FIELDS with the expression the adapter uses"
        )


def test_the_writer_adapter_publishes_without_mutating_its_snapshot() -> None:
    """Pins the contract clause that matters most: `write` must not mutate the snapshot it was given."""
    writer = _DeterministicRevisionWriter()

    class _Snapshot:
        id = "snap-1"
        task_id = "task-1"
        object_versions: dict[str, object] = {"evidence": 3}
        created_at = None

    snapshot = _Snapshot()
    before = dict(snapshot.object_versions)
    revision = writer.write(snapshot, parent_revision_id="rev-0")

    assert snapshot.object_versions == before, "write mutated its snapshot, which ADR-0024 forbids"
    assert revision.parent_revision_id == "rev-0", "revision lineage was dropped"
    assert writer.writes and writer.writes[0][0] == "snap-1"


def test_the_port_record_matches_the_defined_ports() -> None:
    """P1.2's record must not claim a port that does not exist, nor omit one that does.

    P1.2 names six. After the four consumer surveys all six are defined as declarations; the notes say which of
    them still lack an ADAPTER, which is a different and later thing from existing.
    """
    defined = {protocol.__name__ for protocol in port_protocols()}

    assert set(ports.P12_PORTS) == defined, (
        f"P12_PORTS names {sorted(ports.P12_PORTS)} but ports.py defines {sorted(defined)}"
    )
    assert len(ports.P12_PORTS) == 6, "P1.2 names six ports; the record must list all six"
    assert all(note.strip() for note in ports.P12_PORTS.values()), "every port needs its note"
    # The honest part: a port with no producer is a declaration. Recorded, so it cannot be read as decoupling.
    assert "no producer yet" in ports.P12_PORTS["EmulationPort"], (
        "EmulationOutcomeView has no producer in the tree; if an adapter now exists, update this note rather than "
        "deleting the admission"
    )


def test_the_model_action_contract_is_reachable_without_the_model_implementation() -> None:
    """P3.3 layer item 4, pinned where it belongs: the decoupling property, not just the move.

    WHY THIS EXISTS: P3.3c(2)'s three members need `DynamicPlanAction`, and `investigation/` may not import the model
    IMPLEMENTATION (`model/model_gateway.py` imports httpx). The class therefore moved to `contracts.py` - the pure
    pydantic contract layer the plan's matrix already allows `investigation/` to import - and BOTH the gateway and this
    port module re-export the same object. This test asserts the property that makes the port re-export legitimate:
    importing the contract must NOT import the gateway. MEASURED, and it is why the port re-exports the class from
    `contracts` rather than from the gateway: the gateway would pull httpx into every importer of this file, which its
    own docstring forbids.
    """
    import subprocess
    import sys as _sys

    code = (
        "import sys\n"
        "import threat_report_agent.contracts as contracts\n"
        "leaked = sorted(name for name in sys.modules if 'model_gateway' in name)\n"
        "print(contracts.DynamicPlanAction.__module__)\n"
        "assert not leaked, f'the contract layer imported the model implementation: {leaked}'\n"
    )
    result = subprocess.run(
        [_sys.executable, "-c", code],
        cwd=str(PACKAGE.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr[-800:]
    assert result.stdout.strip() == "threat_report_agent.contracts", (
        f"the canonical class must live in contracts.py; it reports {result.stdout.strip()!r}"
    )


def _definitions_of(name: str, root: Path, source: str | None = None) -> list[str]:
    """Every `class <name>` in `root` (or in `source`, for the self-check), as `path:line`.

    Kept as a helper so the CHECK ITSELF can be shown to fail: §4.3 of the plan wants verification reproducible from
    tracked files, and a can-fail proof that lives only in a gitignored script cannot be re-run by a reader.
    """
    found: list[str] = []
    paths = [Path(f"<{name}-synthetic>")] if source is not None else sorted(root.rglob("*.py"))
    for path in paths:
        text = source if source is not None else path.read_text(encoding="utf-8", errors="replace")
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ClassDef) and node.name == name:
                found.append(f"{path.name}:{node.lineno}")
    return found


def test_the_model_action_contract_is_defined_once_and_only_reexported() -> None:
    """The plan's rule 3.2 line 142: "re-export is not a second implementation" - made checkable.

    Scans ALL of `src/threat_report_agent`, not just `model/`, because the claim being pinned is that there is exactly
    ONE definition of the type anywhere in the product - a duplicate in `contracts.py`, `service.py` or
    `investigation/` would be the same violation.

    Also pins the OLD path's promise: `threat_report_agent.model.model_gateway.DynamicPlanAction`, the root shim
    `threat_report_agent.model_gateway.DynamicPlanAction` and the model PORT are the same object as the contract's, so
    every existing caller keeps working while the canonical home changed.
    """
    definitions = _definitions_of("DynamicPlanAction", PACKAGE)
    #: The LINE NUMBER is pinned on purpose: the pin's job is to force a deliberate update when `contracts.py` changes
    #: shape, so a silent move of the canonical class cannot slip through. MEASURED shift 141 -> 142: the P3.5-0/M-2
    #: move sank `PackageEntry` into `contracts.py` (appended at the end of the file) and added the module's
    #: `from dataclasses import dataclass` import above this class. One line, hence 142.
    #: MEASURED shift 142 -> 146: the P3.5-0/M-1 move put the 17-definition contract cluster at the END of the file
    #: (so appending moved nothing) but had to add FOUR import lines above this class - `import hashlib`,
    #: `import json`, `import re` and `from enum import Enum, StrEnum`, which the moved `canonical_action_key`,
    #: `_FUNCTION_LOCATOR`, `ActionType` and `InvestigationThreadState` need. Its two other import changes are
    #: in-line (`dataclasses` gained `field`, `typing` gained `Iterable, Mapping`) and add no line. 142 + 4 = 146.
    #: In both cases the assertion below still proves the substance (exactly ONE definition, in the contract layer).
    assert definitions == ["contracts.py:146"], (
        f"expected exactly one definition, in contracts.py; found {definitions}. The canonical class is the contract "
        "layer's and every other path must only re-export it"
    )

    from threat_report_agent import contracts as contracts_module
    from threat_report_agent import model_gateway as root_shim
    from threat_report_agent import ports as ports_module
    from threat_report_agent.model import model_gateway as package_path

    assert package_path.DynamicPlanAction is contracts_module.DynamicPlanAction
    assert root_shim.DynamicPlanAction is contracts_module.DynamicPlanAction
    assert ports_module.DynamicPlanAction is contracts_module.DynamicPlanAction, (
        "the model port must EXPOSE the type (plan 3.2 line 132 lists the model port among the things "
        "`investigation/` may import), and it must be the same object rather than a second declaration"
    )


def test_the_duplicate_definition_check_can_fail() -> None:
    """The self-check the plan asks for: a check whose failure mode is not demonstrated is not a check.

    MEASURED: the layer-item-4 move first pinned only `model/*.py`, so a duplicate in `contracts.py` or `service.py`
    would have passed it while the design doc claimed "exactly one definition in src/". This pins the checker against a
    synthetic duplicate, and against the real tree, so both halves are exercised from a tracked file.
    """
    assert _definitions_of(
        "DynamicPlanAction", PACKAGE, source="class DynamicPlanAction:\n    pass\n"
    ) == ["<DynamicPlanAction-synthetic>:1"], (
        "the checker does not detect a duplicate definition, so the pin above proves nothing"
    )
    assert (
        _definitions_of("DynamicPlanAction", PACKAGE, source="class SomethingElse:\n    pass\n")
        == []
    )
    assert _definitions_of("DynamicPlanAction", PACKAGE) == ["contracts.py:146"]  # same pin as above: M-1 142 -> 146
