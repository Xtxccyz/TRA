"""P2-V contract: `investigation` is a package whose facade serves the old module path LAZILY.

Plan section 7.9 puts `investigation.py` (and seven sibling modules) in `investigation/`. A package SHADOWS a
same-named module, so the move needs a compatibility surface; the naive attempt produced 145 ImportErrors. The
recipe was chosen by measurement (`docs/plan-conflict-resolutions-20260922.md`) and re-verified in round 78 with a
copy whose test bodies actually run: moving `investigation.py` ALONE gives zero new failures, while moving
`investigation_protocol.py` with it does not.

The assertions below are the properties that make the facade correct rather than merely present:

  1. every public name of the 8,446-line implementation is served through the package, by IDENTITY;
  2. importing the package does NOT import the implementation (laziness), checked in a fresh interpreter;
  3. the package keeps `__path__`, so plan 7.9's seven sibling modules can still move in;
  4. there is NO root `investigation.py`: for a module whose old path became a package, a shim FILE would be dead
     code;
  5. a MISSING name raises AttributeError, and the facade chains an implementation-import failure instead of
     disguising it as a missing attribute - the defect that misled three separate diagnoses;
  6. the retired 4-module cycle is recorded as retired, with the leg that disappeared named, so the record cannot
     silently regress.

    python -m pytest -q tests/test_investigation_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
DOTTED = "threat_report_agent.investigation"
POLICY = Path(__file__).resolve().parents[1] / "docs" / "import-policy.json"


def test_the_package_serves_every_name_of_the_implementation_by_identity() -> None:
    exposed = importlib.import_module(DOTTED)
    implementation = importlib.import_module(f"{DOTTED}.investigation")

    names = [name for name in dir(implementation) if not name.startswith("__")]
    assert len(names) > 100, f"the implementation exposes only {len(names)} names; is this the right module?"
    wrong = [name for name in names if getattr(exposed, name, None) is not getattr(implementation, name)]
    assert not wrong, f"{len(wrong)} name(s) are not served by identity through {DOTTED}: {wrong[:8]}"


def test_the_facade_is_lazy_in_a_fresh_interpreter() -> None:
    code = (
        "import sys; sys.path.insert(0, 'src');"
        f"import {DOTTED};"
        f"print('IMPORTED' if '{DOTTED}.investigation' in sys.modules else 'LAZY')"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    output = (done.stdout or "") + (done.stderr or "")
    assert done.returncode == 0, f"importing the package failed:\n{output[-800:]}"
    assert "LAZY" in output, (
        "the package pulled in its implementation during initialisation. That is the eager form, MEASURED twice to "
        f"make a module-level importer resolve a half-initialised implementation:\n{output[-400:]}"
    )


def test_the_package_keeps_a_path_for_plan_7_9s_sibling_modules() -> None:
    exposed = importlib.import_module(DOTTED)
    assert hasattr(exposed, "__path__"), "the facade is not a package any more, so no sibling module can move in"
    assert (PACKAGE / "investigation" / "investigation.py").is_file()
    assert not (PACKAGE / "investigation.py").exists(), (
        "a root investigation.py exists; the import system probes the package directory first, so it is dead code"
    )


def test_a_missing_name_is_an_attribute_error_not_an_import_error() -> None:
    """Absence must stay distinguishable from a broken implementation import."""
    exposed = importlib.import_module(DOTTED)
    try:
        exposed.definitely_not_a_name_on_this_module
    except AttributeError as exc:
        assert "has no attribute" in str(exc)
    else:  # pragma: no cover - the attribute is invented, so this cannot happen
        raise AssertionError("a non-existent name resolved")


def test_the_facade_mechanism_chains_an_implementation_import_failure() -> None:
    """The mechanism must not disguise a failed import as a missing attribute.

    MEASURED why this is pinned: the first facade caught AttributeError around the name lookup and re-raised its
    own, so a failure inside the implementation's import chain surfaced as
    "module 'threat_report_agent.investigation' has no attribute 'X'". Three diagnoses in a row reported only that
    symptom before the cause was found.
    """
    mechanism = (PACKAGE / "package_facade.py").read_text(encoding="utf-8")
    assert "raise ImportError(" in mechanism and ") from exc" in mechanism, (
        "package_facade.install_module_facade no longer chains the implementation-import failure"
    )
    assert "def install_module_facade(" in mechanism
    # Both packages must use the ONE mechanism, not their own copy (the structure gate flagged that as a duplicate).
    for package in ("intake", "investigation"):
        source = (PACKAGE / package / "__init__.py").read_text(encoding="utf-8")
        assert "install_module_facade(__name__," in source, f"{package}/__init__.py does not use the shared facade"
        assert "def __getattr__" not in source, f"{package}/__init__.py defines its own __getattr__ again"


def test_the_retired_cycle_is_recorded_as_retired_with_its_reason() -> None:
    """P2-V.0 removed the `static_analysis -> investigation` leg, which dissolved a recorded cycle."""
    import json

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    cycles = [sorted(item) for item in policy.get("known_cycles", [])]
    retired = sorted(["controlled_emulation", "emulation_plan", "investigation", "static_analysis"])
    assert retired not in cycles, (
        "the 4-module cycle is still listed as known, but the predicate move removed its `static_analysis -> "
        "investigation` leg; re-measure before restoring the entry"
    )
    note = str(policy.get("_known_cycles_note", ""))
    assert "NO LONGER EXISTS" in note and "static_analysis -> investigation" in note, (
        "the retirement must keep the reason it disappeared, or a future reader will re-add it"
    )


def test_the_function_call_names_helper_has_exactly_one_implementation() -> None:
    """P2-V.1 resolved the ONE recorded duplicate implementation; this is its durable pin.

    The policy record is gone (the gate treats a stale record as a problem), so the invariant needs a test or it
    could regress silently. MEASURED at the consolidation: both copies were byte-identical (name-normalised body
    hash 0c5ca4fb1ca89f71), the canonical home is `investigation_protocol.py` because
    `investigation_protocol -> reporting` is a FORBIDDEN edge while `reporting -> investigation_protocol` already
    existed, and nothing was reimplemented - the survivor is byte-identical to both HEAD copies. P2-V.2 then moved
    that module into `investigation/`, so the file lives there now while the canonical identity is unchanged.

    P3.5-0/M-4 CHANGED THE PINNED PATH DELIBERATELY, and the invariant it protects is unchanged: the helper is now
    DEFINED in `facts/investigation_protocol.py` and re-exported by `investigation/investigation_protocol.py`, because
    P3.5's `EmulationCoordinator` needs it and `emulation -> investigation` is an upward edge while `emulation -> facts`
    is matrix-legal. The original reasoning is not weakened by the move but STRENGTHENED: `facts -> reporting` is a
    forbidden edge too (it is in `docs/import-policy.json`), and `reporting -> facts` is legal, so `facts/` is the lower
    and therefore better home for a helper that the report layer must import. The identity assertions below still prove
    there is exactly one implementation and that `reporting` imports it rather than holding a copy.
    """
    import json

    defined_in: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in {"function_call_names", "_function_call_names"}:
                defined_in.append(path.relative_to(PACKAGE).as_posix())
    assert defined_in == ["facts/investigation_protocol.py"], (
        f"the helper is defined in {defined_in}; plan 3.2 allows exactly ONE canonical implementation, and since "
        "P3.5-0/M-4 it lives in `facts/investigation_protocol.py` - the lowest layer that can hold it, because both "
        "`facts -> reporting` and `investigation_protocol -> reporting` are forbidden edges while the report layer "
        "importing `facts` is legal"
    )

    protocol = importlib.import_module("threat_report_agent.investigation.investigation_protocol")
    assert callable(protocol.function_call_names), "the canonical helper must be public now that it is imported"
    reporting = importlib.import_module("threat_report_agent.report.reporting")
    assert reporting.function_call_names is protocol.function_call_names, (
        "reporting must IMPORT the canonical helper rather than hold its own copy"
    )

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert policy.get("known_duplicate_implementations") == [], (
        "a resolved duplication must not keep a record: the gate reports a stale record as a problem, and an entry "
        "that no longer matches anything cannot notice the duplication returning"
    )
