"""P2-R step 1 contract: `_mechanism_catalog_id` has exactly ONE definition, and the resolution is unchanged.

The plan's P2-R order is explicit about its first step:

    1. 先删除 `analyst_report.py` 中被后定义覆盖的重复 `_mechanism_catalog_id`，用锁定测试证明解析结果不变。

MEASURED before the deletion (`.scratch/probe-p2r-mechanism-id.py`): the name was defined at lines 1147 and 2247.
The 1147 body read `row["catalog_id"] / ["mechanism_type"] / ["verifier_id"] / ["dimension"]` and consulted
`registry.by_id`; the 2247 body takes a SCALAR and consults `registry.resolve_or_unknown`. Python binds the LAST
definition at import time, so the first was unreachable - `co_firstlineno` was measured as 2247 while both
definitions existed. Deleting it is therefore behaviour-preserving BY CONSTRUCTION, and this file pins that:

  * there is one definition, and it is the scalar one;
  * the surviving object resolves exactly what it resolved before the deletion.

WHAT THE MEASUREMENT ALSO FOUND, RECORDED AND NOT FIXED HERE: two call sites pass a MAPPING to that scalar
function. Measured, a mapping resolves to `""` (the string form of the dict matches no alias), while
`row.get("catalog_id")` resolves correctly. The consequences are:

  * `_topic_status` (analyst_report.py:1203) evaluates `_mechanism_ready(item) and _mechanism_catalog_id(item,
    catalog) == catalog_id`, i.e. `"" == catalog_id`, which is False for every non-empty catalog id - so the
    `"recovered"` branch at 1202-1206 can never fire from a ready mechanism;
  * `_mechanism_label` (analyst_report.py:1160-1161) always receives `""`, so a label falls back to the raw
    `mechanism_type` instead of the catalog title.

FIXING EITHER CHANGES REPORT TEXT, which P1.4 and P2-R both forbid inside a structural step ("正文 SHA 改变时先
回滚本步结构变更"). It is recorded as a known behaviour gap with its step, and the last test below asserts the gap
is STILL exactly that - so closing it must be deliberate rather than accidental.

    python -m pytest -q tests/test_report_structure_contract.py
"""
from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import analyst_report  # noqa: E402
from threat_report_agent.behavior_catalog import BehaviorCatalog  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"


def _definitions(name: str) -> list[int]:
    tree = ast.parse((PACKAGE / "analyst_report.py").read_text(encoding="utf-8", errors="replace"))
    return [node.lineno for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]


def test_the_shadowed_definition_is_gone_and_exactly_one_remains() -> None:
    definitions = _definitions("_mechanism_catalog_id")
    assert len(definitions) == 1, (
        f"{len(definitions)} definitions at {definitions}; P2-R step 1 removed the shadowed one, and a second "
        "definition makes the earlier body unreachable while looking authoritative in review"
    )


def test_the_surviving_definition_is_the_scalar_one_the_module_binds() -> None:
    """The LAST definition wins at import time; after the deletion that must be the scalar body."""
    assert list(inspect.signature(analyst_report._mechanism_catalog_id).parameters) == ["value", "registry"], (
        "the surviving signature is not the scalar one, so a different body is now live"
    )
    assert analyst_report._mechanism_catalog_id.__code__.co_firstlineno == _definitions("_mechanism_catalog_id")[0]


def test_the_resolution_is_unchanged_by_the_deletion() -> None:
    """The locking evidence: the values measured BEFORE the deletion still hold.

    Recorded before the change (probe output, commit 277ca05):
        scalar  value="file-operations"                  -> "file-operations"
        mapping value={"catalog_id": "file-operations"}  -> ""
        scalar  value=row.get("catalog_id")              -> "file-operations"
    The first and third are what a correct call site gets; the second is the defect recorded below.
    """
    registry = BehaviorCatalog()
    catalog_id = next(iter(analyst_report.CATALOG_TITLES_ZH))
    row = {"catalog_id": catalog_id, "mechanism_type": catalog_id, "status": "VERIFIED"}

    assert analyst_report._mechanism_catalog_id(catalog_id, registry) == catalog_id
    assert analyst_report._mechanism_catalog_id(row.get("catalog_id"), registry) == catalog_id
    assert analyst_report._mechanism_catalog_id("", registry) == ""
    assert analyst_report._mechanism_catalog_id("definitely-not-a-catalog-alias", registry) == ""


def test_the_mapping_call_sites_are_still_the_recorded_gap() -> None:
    """Pins the RECORDED DEFECT, so closing it cannot happen by accident inside a structural step.

    Measured: a Mapping resolves to "" while its extracted scalar resolves correctly. Two live call sites pass the
    Mapping (`analyst_report.py:1161` inside `_mechanism_label`, and `analyst_report.py:1203` inside
    `_topic_status`), which is why the `"recovered"` branch cannot fire and a mechanism label loses its catalog
    title. When a behaviour work item fixes this, THIS TEST MUST BE INVERTED DELIBERATELY in the same commit, and
    the report body SHA must be re-frozen.
    """
    registry = BehaviorCatalog()
    catalog_id = next(iter(analyst_report.CATALOG_TITLES_ZH))
    row = {"catalog_id": catalog_id, "mechanism_type": catalog_id, "status": "VERIFIED"}

    assert analyst_report._mechanism_catalog_id(row, registry) == "", (
        "the mapping call sites now resolve; that is a BEHAVIOUR change to report text - invert this test and "
        "re-freeze the body SHA deliberately instead of deleting it"
    )

    source = (PACKAGE / "analyst_report.py").read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    # A MAPPING call site passes a bare row/item NAME. MEASURED reason for exactly this filter: the first version
    # also counted `_mechanism_catalog_id(row.get(key), registry)` at line 2385, because `row.get(...)` is a Call
    # and not an Attribute - but `.get(...)` returns a SCALAR, which is the form that works. Only a bare Name can
    # be the mapping that resolves to "".
    mapping_call_sites = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_mechanism_catalog_id"
        and node.args
        and isinstance(node.args[0], ast.Name)
    ]
    assert mapping_call_sites == [1161, 1203], (
        f"expected the two recorded mapping call sites [1161, 1203], measured {mapping_call_sites}; if one was "
        "fixed or moved, this record and the known_behaviour_gap entry must be updated deliberately"
    )
