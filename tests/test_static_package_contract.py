"""P2-S contract: the first static-layer module moved into `static/`, and the package's shape.

Plan section 7.7 puts nine modules in `static/`. The P2-S inventory measured that NO PAIR of those nine imports the
other at module level, so relocation cannot re-enter a half-initialised module the way `investigation` did, and that
`static` is not the name of any module, so nothing is shadowed. That means this package needs NO lazy facade - the
opposite of P2-I - and each moved module keeps an effective root `sys.modules` shim.

The assertions below pin the properties that make the move a MOVE:

  1. the old path and the new path are ONE module object (so the eight modules importing `static_analysis`, which
     imports this one, keep working untouched);
  2. the old path is a shim, not a second implementation;
  3. `static/__init__.py` re-exports nothing, so the package is not a second import surface;
  4. production modules no longer import the old path (plan 7.1 step 5) - checked through the structure gate's own
     `legacy_path_imports()`, so there is one detector rather than two;
  5. the moved code still computes the same fingerprints and distances, pinned on fixed inputs.

    python -m pytest -q tests/test_static_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest  # noqa: E402

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
#: module -> symbols whose IDENTITY must be the same through both paths. Names are read from the moved modules
#: (`py .scratch/p2s-list-symbols.py`), never guessed: the first version of this file asserted a fingerprint was an
#: int because I assumed the contract instead of reading it.
MOVED = {
    "function_simhash": ("hamming_distance", "fingerprint_mnemonics", "ALGORITHM"),
    "evidence_index": ("canonical_selector", "evidence_search_keys", "INDEXED_EVIDENCE_KINDS"),
    "function_similarity": ("FunctionSimilarityIndex", "SimilarityQuery", "hamming_distance"),
    "literal_table": ("discover_hex_literal_table", "RecoveredScript", "AnchoredTableSet"),
    "static_simulation": ("StaticAbstractExecutor", "SimulationTraceStep", "PathCondition"),
}


def load_gate_module():
    """`scripts/check-structure-diff.py` cannot be imported by name (dashes), so load it by path."""
    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_static_tests",
        Path(__file__).resolve().parents[1] / "scripts" / "check-structure-diff.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_each_moved_module_is_one_object_behind_two_paths() -> None:
    for name, symbols in MOVED.items():
        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.static.{name}")
        assert old is new, f"{name}: the shim did not rebind sys.modules, so there are two module objects"
        assert old.__file__ == new.__file__
        for symbol in symbols:
            assert getattr(old, symbol) is getattr(new, symbol), f"{name}.{symbol} is not the same object"


def test_the_old_path_is_a_shim_and_not_a_second_implementation() -> None:
    for name in MOVED:
        shim = PACKAGE / f"{name}.py"
        assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
        source = shim.read_text(encoding="utf-8", errors="replace")
        assert len(source.encode("utf-8")) < 1500, f"{name}.py grew beyond a shim"
        definitions = [
            node.name
            for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        assert not definitions, f"{name}.py defines {definitions}; a definition there is a second implementation"
        assert "sys.modules[__name__] = _real" in source


def test_the_static_package_re_exports_nothing() -> None:
    """Plan 3.2 forbids a second canonical implementation, and a re-export list is also a second import surface."""
    source = (PACKAGE / "static" / "__init__.py").read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    imported = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert not imported, f"static/__init__.py imports {[ast.unparse(node) for node in imported]}"
    assert "__all__" in source and "__all__: tuple[str, ...] = ()" in source


def test_no_production_module_imports_the_moved_module_by_its_old_path() -> None:
    gate = load_gate_module()
    offenders = [
        item for item in gate.legacy_path_imports() if item["old"] in MOVED
    ]
    assert not offenders, (
        f"production modules still import a static-layer module by its old path: {offenders}; the canonical path "
        "is threat_report_agent.static.<module>"
    )


def test_the_moved_code_still_computes_the_same_values() -> None:
    """Pinned on fixed inputs, because a structural move must not change what the code computes.

    `fingerprint_mnemonics` returns a 16-hex-digit STRING (the module's own contract, read from the moved source),
    and it DROPS blank entries and lower-cases what it keeps - so a punctuation-only change would be visible here.
    """
    implementation = importlib.import_module("threat_report_agent.static.function_simhash")
    first = implementation.fingerprint_mnemonics(["mov", "push", "call", "ret"])
    second = implementation.fingerprint_mnemonics(["mov", "push", "call", "pop"])
    assert isinstance(first, str) and len(first) == 16, f"fingerprint shape changed: {first!r}"
    int(first, 16)  # it must stay a hex string the caller can parse
    assert implementation.hamming_distance(first, first) == 0
    assert implementation.hamming_distance(first, second) > 0, (
        "two different mnemonic windows produced the same fingerprint, which would make the similarity feature "
        "useless"
    )
    # Blank entries are dropped and case is folded: pin both, since a move must not alter either.
    assert implementation.fingerprint_mnemonics([" MOV ", "", "PUSH", "call", "ret"]) == first
    assert implementation.ALGORITHM == "charikar-simhash-64"
    assert implementation.FEATURE == "mnemonic-4gram"
    assert implementation.FEATURE_HASH == "md5-prefix-64-le"
    assert implementation.generate_ngrams(["a", "b", "c"], n=2) == ["a b", "b c"]
