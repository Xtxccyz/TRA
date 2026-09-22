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
import sqlalchemy

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import models, projection_protocols  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
BANNED = ("sqlalchemy", "psycopg", "fastapi", "starlette", "requests", "httpx", "openai", "anthropic",
          "threat_report_agent.service")


def imported_modules(path: Path) -> set[str]:
    """Every module name a file imports, INCLUDING relative and dynamic imports.

    The first version of this helper collected `node.module` only when it was truthy. MEASURED consequence: an
    r1 audit appended `from . import models` to `projection_protocols.py` and this file still reported
    `imported=[]` - a relative import is exactly how a module inside the package would re-couple itself to the
    ORM layer, so the negative controls below were blind to the one form they exist to catch. `import_module`
    and `__import__` calls with a literal argument are collected for the same reason.
    """
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # `from . import models` -> level=1, module=None. Both spellings are recorded: the alias name and
            # the dotted relative form, so a substring test catches either.
            names.update(alias.name for alias in node.names)
            names.add("." * node.level)
        elif isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if called in {"import_module", "__import__"} and node.args:
                target = node.args[0]
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    names.add(target.value)
    return names


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
    hits = [item for item in imported_modules(PACKAGE / "projection_protocols.py")
            for ban in BANNED if ban in item]
    assert not hits, f"projection_protocols.py must stay pure; found {hits}"


def test_imported_modules_helper_sees_relative_and_dynamic_imports(tmp_path: Path) -> None:
    """Can-fail proof for the helper above, because the audit measured the old one returning `imported=[]`.

    A negative control that cannot see the import form it exists to reject is worse than no control: it reports
    PASS while the coupling it was written against is present.
    """
    source = (
        "from . import models\n"
        "from .models import Evidence\n"
        "from threat_report_agent import service\n"
        "import importlib\n"
        "m = importlib.import_module('threat_report_agent.report.reporting')\n"
        "n = __import__('sqlalchemy')\n"
    )
    scratch = tmp_path / "_import-helper-canfail.py"
    scratch.write_text(source, encoding="utf-8")
    found = imported_modules(scratch)
    for expected in ("models", "Evidence", "service", "threat_report_agent.report.reporting", "sqlalchemy"):
        assert expected in found, f"helper missed {expected!r} in {sorted(found)}"


def test_the_protocol_module_does_not_import_the_orm_layer() -> None:
    """The whole point is that a consumer can depend on these types WITHOUT pulling in SQLAlchemy.

    NEGATIVE CONTROL for the route decision: if this module ever imports `models`, the seam is decorative and
    P1.1 has only renamed the coupling. MEASURED FALSE-GREEN this replaces: an r1 audit added `from . import
    models` to the module and the previous version of this test still passed, because it skipped every
    `ImportFrom` whose `module` was `None`.
    """
    imported = imported_modules(PACKAGE / "projection_protocols.py")
    assert not any("models" in item for item in imported), (
        f"projection_protocols.py imports the ORM layer ({sorted(imported)}), so it does not decouple anything"
    )


@pytest.mark.parametrize(("protocol_name", "orm_name"), projection_protocols.PROJECTION_PAIRS)
def test_every_protocol_member_is_a_mapped_column_on_the_orm_class(protocol_name: str, orm_name: str) -> None:
    """The stronger instrument, because the isinstance check above proves member PRESENCE ONLY.

    MEASURED LIMIT of `runtime_checkable`: CPython's `_ProtocolMeta.__instancecheck__` uses `getattr_static` and
    compares no types, so a protocol member that exists as a plain (unpersisted) attribute, or whose value is
    `None`, satisfies it. Reading only the class-level fields is not enough either. This asserts the members are
    MAPPED COLUMNS or RELATIONSHIPS on the ORM class, measured through SQLAlchemy's own mapper - so a column
    rename, a column removed from the mapping, or a member invented purely to satisfy the protocol is caught.
    """
    protocol = getattr(projection_protocols, protocol_name)
    orm_class = getattr(models, orm_name)
    members = set(getattr(protocol, "__annotations__", {}))
    assert members, f"{protocol_name} declares no members, so it constrains nothing"
    mapper = sqlalchemy.inspect(orm_class)
    mapped = set(mapper.columns.keys()) | set(mapper.relationships.keys())
    unmapped = sorted(members - mapped)
    assert not unmapped, (
        f"{protocol_name} names {unmapped} which are not mapped columns/relationships on {orm_name}; "
        f"isinstance would still report the protocol satisfied because it checks presence only"
    )


def test_isinstance_does_not_check_member_types_and_the_mapper_test_is_why() -> None:
    """Pins the LIMIT, so the parametrised isinstance test is never read as type-checking.

    A protocol that names `id: str` is satisfied by a class whose `id` is `None`, and by a `@property` that
    raises when touched. That is why `test_every_protocol_member_is_a_mapped_column_on_the_orm_class` exists:
    presence is the weak half, the mapping is the strong half, and neither of them checks the TYPE. Type
    fidelity is not asserted anywhere in this suite and is not claimed by it.
    """
    from typing import Protocol, runtime_checkable

    @runtime_checkable
    class _TwoMembers(Protocol):
        id: str
        task_id: str

    class _WrongTypes:
        id = None

        @property
        def task_id(self) -> str:
            raise RuntimeError("never touched by isinstance")

    assert isinstance(_WrongTypes(), _TwoMembers), (
        "isinstance started comparing types; the docstrings in this file and in projection_protocols.py that say "
        "'presence only' must be updated, and the mapper test may now be redundant"
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
