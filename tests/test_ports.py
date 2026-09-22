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
    return [
        member
        for name, member in vars(ports).items()
        if inspect.isclass(member) and getattr(member, "_is_protocol", False) and member.__module__ == ports.__name__
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


def test_the_ports_are_satisfiable_by_a_deterministic_adapter() -> None:
    """A port nobody can implement is an untested design, so implement both here without any infrastructure."""
    assert isinstance(_DeterministicRevisionWriter(), ports.ReportRevisionWriter)
    assert isinstance(_FakeQueryReader(), ports.WorkbenchQueryReader)


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


def test_the_record_of_unwritten_ports_matches_reality() -> None:
    """P1.2's record must not claim more ports than exist, and must list the four that remain."""
    written = [name for name, note in ports.P12_PORTS.items() if note.startswith("written")]
    remaining = [name for name, note in ports.P12_PORTS.items() if note.startswith("NOT WRITTEN")]
    defined = {protocol.__name__ for protocol in port_protocols()}

    assert set(written) == defined, (
        f"P12_PORTS claims {sorted(written)} are written but ports.py defines {sorted(defined)}"
    )
    assert len(remaining) == 4, f"expected four remaining ports, found {sorted(remaining)}"
    assert len(ports.P12_PORTS) == 6, "P1.2 names six ports; the record must list all six"
