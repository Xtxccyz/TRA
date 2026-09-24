"""Tracked pins for the canonical HOMES of the names M-2/M-1/M-3 sank into the contract layer.

WHY THIS FILE EXISTS, measured by an adversarial review of the round: the structure gate's duplicate check ignores
definition bodies under 120 characters, and NOTHING tracked pinned where these names live - only gitignored `.scratch`
instruments did. So re-adding a small duplicate `PackageEntry` or `TaskLifecycle` in another module would have been
invisible to every gate and every test.

WHAT IT PINS, in three directions:
  1. each name is DEFINED exactly once in the whole package, and that one definition is in `contracts.py`
     (`facts/investigation_protocol.py` for the M-4 cluster, whose home is the facts layer by decision);
  2. the OLD paths still expose the SAME objects, so the re-export promise is checked rather than assumed;
  3. `contracts.py` itself imports no `threat_report_agent.*` implementation module - the purity that made it the right
     home for a sink, checked where the sink happened rather than only in the domain-boundary test.
"""
from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
sys.path.insert(0, str(PACKAGE.parent))

#: name -> the module that must hold the single definition.
HOMES = {
    "PackageEntry": "contracts.py",
    "ActionSpec": "contracts.py",
    "TaskLifecycle": "contracts.py",
    "InvalidStateTransition": "contracts.py",
    "TASK_TRANSITIONS": "contracts.py",
    "transition_task": "contracts.py",
    "FailureInterpretation": "contracts.py",
    "canonical_action_key": "contracts.py",
    "scoped_investigation_action_key": "contracts.py",
    "fill_protocol": "facts/investigation_protocol.py",
    "is_empty_marker": "facts/investigation_protocol.py",
    "function_call_names": "facts/investigation_protocol.py",
}

#: (old import path, attribute, canonical module attribute) - the re-export promise.
REEXPORTS = [
    ("threat_report_agent.intake", "PackageEntry"),
    ("threat_report_agent.intake.intake", "PackageEntry"),
    ("threat_report_agent.task.status", "TaskLifecycle"),
    ("threat_report_agent.task.status", "transition_task"),
    ("threat_report_agent.status", "TaskLifecycle"),
    ("threat_report_agent.investigation", "ActionSpec"),
    ("threat_report_agent.investigation.investigation", "ActionSpec"),
    ("threat_report_agent.static.evidence_recovery", "canonical_action_key"),
    ("threat_report_agent.investigation.seed_support", "scoped_investigation_action_key"),
    ("threat_report_agent.investigation.investigation_protocol", "fill_protocol"),
    ("threat_report_agent.investigation_protocol", "fill_protocol"),
]


def _definitions(name: str) -> list[str]:
    """Every place that DEFINES `name` at top level, as `path:line` (an import or a re-export is not a definition).

    LINE-AWARE ON PURPOSE, and the reason is a hole this test had in its first version: returning the set of MODULE
    names made a SECOND definition inside the same module invisible, because the set still had one element. The
    structure gate cannot cover that either - its duplicate check ignores definition bodies under 120 characters - so a
    copy-pasted `PackageEntry` next to the original would have passed both.
    """
    found: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(PACKAGE).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in tree.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                found.append(f"{relative}:{node.lineno}")
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                    found.append(f"{relative}:{node.lineno}")
    return sorted(found)


def test_every_sunk_name_is_defined_exactly_once_and_in_its_recorded_home() -> None:
    """One definition per name, in the layer that was chosen deliberately - not in whatever module is convenient."""
    wrong: dict[str, list[str]] = {}
    for name, home in HOMES.items():
        found = _definitions(name)
        if len(found) != 1 or not found[0].startswith(home + ":"):
            wrong[name] = found
    assert not wrong, (
        "these names are not defined exactly once in their recorded home: "
        + "; ".join(f"{name} -> {found} (expected one definition in '{HOMES[name]}')" for name, found in wrong.items())
        + ". Plan section 3.2 allows exactly ONE canonical implementation; a second one here is a duplicate the "
        "structure gate cannot see, because its duplicate check ignores definition bodies under 120 characters. Note "
        "the expected form is `path:line`, so a SECOND definition inside the same module fails too."
    )


def test_the_old_paths_expose_the_same_object_as_the_canonical_home() -> None:
    """The re-export promise, checked through every path the callers actually use."""
    contracts = importlib.import_module("threat_report_agent.contracts")
    facts_protocol = importlib.import_module("threat_report_agent.facts.investigation_protocol")
    broken: list[str] = []
    for module_name, attribute in REEXPORTS:
        module = importlib.import_module(module_name)
        assert hasattr(module, attribute), f"{module_name} no longer exposes {attribute}"
        canonical = getattr(contracts, attribute, None) if attribute in HOMES and HOMES[attribute] == "contracts.py" \
            else getattr(facts_protocol, attribute, None)
        if canonical is None:
            canonical = getattr(contracts, attribute)
        if getattr(module, attribute) is not canonical:
            broken.append(f"{module_name}.{attribute}")
    assert not broken, f"these paths hold a DIFFERENT object than the canonical home: {broken}"


def test_the_private_alias_kept_for_backwards_compatibility_is_the_public_function() -> None:
    """D-3's alias is a PROMISE, not a leftover: anything still spelling the private name must get the one object.

    Stated separately from `REEXPORTS` because that list maps a path to a CANONICAL name, while this is an alias whose
    whole purpose is that the old private spelling keeps working after the function moved into the contract layer.
    """
    seed_support = importlib.import_module("threat_report_agent.investigation.seed_support")
    contracts = importlib.import_module("threat_report_agent.contracts")
    assert hasattr(seed_support, "_scoped_investigation_action_key"), (
        "the in-place private alias is gone; the worklist row required it to survive the move so no caller breaks"
    )
    assert seed_support._scoped_investigation_action_key is contracts.scoped_investigation_action_key, (
        "the private alias is not the contract layer's function - a caller using the old spelling would get a different "
        "object, which is exactly what the alias exists to prevent"
    )


def test_the_contract_layer_imports_no_implementation_module() -> None:
    """`contracts.py` is the sink precisely because it depends on nothing in the product; check it where it matters."""
    tree = ast.parse((PACKAGE / "contracts.py").read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("threat_report_agent") or node.level:
                offenders.append(f"line {node.lineno}: from {'.' * node.level}{module}")
        elif isinstance(node, ast.Import):
            offenders.extend(f"line {node.lineno}: import {alias.name}" for alias in node.names
                             if alias.name.startswith("threat_report_agent"))
    assert not offenders, (
        f"the contract layer must import nothing from the product, or the sink direction becomes a cycle: {offenders}"
    )
