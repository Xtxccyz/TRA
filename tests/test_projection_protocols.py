"""P1.1 contract: the ORM classes must structurally satisfy the read-only projection protocols.

WHY THIS TEST IS THE POINT: `runtime_checkable` isinstance checks member PRESENCE ONLY. A protocol whose member
name is misspelt, or that the ORM class no longer provides, is not "approximately right" - it is
**unsatisfiable in silence**, and every consumer that annotated itself with it gets an AttributeError at some
later, less obvious moment. So the protocol definitions and the ORM classes are checked against each other here
rather than trusted.

MEASURED inputs (`.scratch/probe-p11-projection-members.py`): models.py is the canonical, SQLAlchemy-bound copy
of these entities, and the member lists in `projection_protocols.py` were read out of its class bodies.

    python -m pytest -q tests/test_projection_protocols.py
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import models, projection_protocols  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
BANNED = ("sqlalchemy", "psycopg", "fastapi", "starlette", "requests", "httpx", "openai", "anthropic",
          "threat_report_agent.service")


@pytest.mark.parametrize(("protocol_name", "orm_name"), projection_protocols.PROJECTION_PAIRS)
def test_the_orm_class_satisfies_its_projection_protocol(protocol_name: str, orm_name: str) -> None:
    protocol = getattr(projection_protocols, protocol_name)
    orm_class = getattr(models, orm_name)
    assert isinstance(orm_class, protocol), (
        f"{orm_name} does not satisfy {protocol_name}. Either a member was renamed or removed in the ORM class, "
        "or a member name in the protocol is misspelt - and runtime_checkable would fail this in silence at the "
        "point of use if it were not asserted here."
    )


def test_projection_protocols_module_is_free_of_the_banned_imports() -> None:
    """P1.1's success criterion, applied to the module this step added."""
    path = PACKAGE / "projection_protocols.py"
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    hits = [item for item in imports for ban in BANNED if ban in item]
    assert not hits, f"projection_protocols.py must stay pure; found {hits}"


def test_the_protocol_module_does_not_import_the_orm_layer() -> None:
    """The whole point is that a consumer can depend on these types WITHOUT pulling in SQLAlchemy.

    NEGATIVE CONTROL for the route decision: if this module ever imports `models`, the seam is decorative and
    P1.1 has only renamed the coupling.
    """
    source = (PACKAGE / "projection_protocols.py").read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not any("models" in item for item in imported), (
        f"projection_protocols.py imports the ORM layer ({sorted(imported)}), so it does not decouple anything"
    )


def test_a_wrong_member_name_would_be_caught() -> None:
    """Can-fail proof for the central assertion.

    Building a protocol with a member the ORM class does not have must NOT be satisfied - otherwise the
    parametrised test above could pass for the wrong reason.
    """
    from typing import Protocol, runtime_checkable

    @runtime_checkable
    class _DeliberatelyWrong(Protocol):
        id: str
        definitely_not_a_column_on_evidence: str

    assert not isinstance(models.Evidence, _DeliberatelyWrong), (
        "a protocol naming a non-existent member was reported as satisfied, so the protocol check proves nothing"
    )
