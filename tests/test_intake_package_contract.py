"""P2-I contract: `intake` is now a package whose facade serves the old module path LAZILY.

Plan section 7.6 puts `intake.py` (and `content_store.py`) in `intake/`. A package SHADOWS a same-named module, so
the move needs a compatibility surface; an earlier attempt at this migration produced 145 ImportErrors because that
surface was empty. The recipe here was chosen by measurement, in a copy of the tree with the real suite
(`docs/plan-conflict-resolutions-20260922.md`):

  * `sys.modules` rebinding   -> 157 collection errors and broken submodule imports
  * eager namespace copy      -> 157 collection errors (the implementation resolves half-initialised)
  * LAZY `__getattr__` facade -> ZERO new failures against a copy control   <- used here

The assertions below are the properties that make the lazy facade correct rather than merely present:

  1. every public name of the implementation is served through the package, by IDENTITY;
  2. importing the package does NOT import the implementation (that is what "lazy" buys, and it is checked in a
     fresh interpreter because import order cannot be asserted in-process);
  3. the package keeps `__path__`, so plan 7.6's second module can move in beside the implementation;
  4. there is NO root `intake.py`: for a module whose old path became a package, a shim FILE would be dead code
     (the import system probes the package directory first), and a dead shim reads as if it were doing the work;
  5. no star-import of this module exists, because `from ... import *` does NOT go through `__getattr__`.

    python -m pytest -q tests/test_intake_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
DOTTED = "threat_report_agent.intake"


def test_the_package_serves_every_public_name_of_the_implementation() -> None:
    exposed = importlib.import_module(DOTTED)
    implementation = importlib.import_module(f"{DOTTED}.intake")

    names = [name for name in dir(implementation) if not name.startswith("__")]
    assert names, "the implementation exposes no names, so this test would pass vacuously"
    wrong = [name for name in names if getattr(exposed, name, None) is not getattr(implementation, name)]
    assert not wrong, (
        f"{len(wrong)} name(s) are not served through {DOTTED}: {wrong[:8]}. A facade that misses a name turns a "
        "structural move into an ImportError at some later, less obvious moment"
    )


def test_the_facade_is_lazy_and_does_not_import_the_implementation_at_package_init() -> None:
    """Checked in a FRESH interpreter: in-process import order cannot be asserted after the suite has imported it."""
    code = (
        "import sys; sys.path.insert(0, 'src');"
        f"import {DOTTED};"
        f"print('IMPORTED' if '{DOTTED}.intake' in sys.modules else 'LAZY')"
    )
    done = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    output = (done.stdout or "") + (done.stderr or "")
    assert done.returncode == 0, f"importing the package failed:\n{output[-800:]}"
    assert "LAZY" in output, (
        "importing the package pulled in the implementation during package initialisation. That is the eager form, "
        "which MEASURED 157 collection errors because a module other modules import at module level can then be "
        f"resolved half-initialised:\n{output[-400:]}"
    )


def test_the_package_keeps_a_path_so_a_second_module_can_move_in() -> None:
    """Plan 7.6 also names `content_store.py` for this package; `sys.modules` rebinding would have made that
    impossible, because the replacement module has no `__path__`."""
    exposed = importlib.import_module(DOTTED)
    assert hasattr(exposed, "__path__"), "the facade is not a package any more, so no module can move in beside it"
    spec = importlib.util.find_spec(f"{DOTTED}.intake")
    assert spec is not None and spec.origin, "the implementation submodule is not importable"


def test_there_is_no_root_shim_file_for_the_old_path() -> None:
    """The old dotted path IS the package, so a root `intake.py` would never be imported."""
    assert not (PACKAGE / "intake.py").exists(), (
        "a root intake.py exists; the import system probes the package directory before the module suffix, so that "
        "file is dead code that reads like the compatibility shim - the package's facade is the shim"
    )
    facade = PACKAGE / "intake" / "__init__.py"
    implementation = PACKAGE / "intake" / "intake.py"
    assert facade.is_file() and implementation.is_file()
    assert facade.stat().st_size < implementation.stat().st_size, (
        "the facade is larger than the implementation, so something other than a forwarding surface is in there"
    )


def test_no_star_import_of_intake_exists_because_getattr_would_be_bypassed() -> None:
    """`from ... import *` reads the module `__dict__`, not `__getattr__`; MEASURED 0 such imports today."""
    offenders: list[str] = []
    for base in (PACKAGE, Path(__file__).resolve().parents[1] / "tests"):
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if f"from {DOTTED} import *" in text:
                offenders.append(path.name)
    assert not offenders, (
        f"star-imports of {DOTTED} found in {offenders}: a star import bypasses `__getattr__`, so the names would "
        "silently be missing. Import the name explicitly, or give the facade an `__all__`"
    )


def test_the_implementation_does_not_import_its_own_old_path() -> None:
    """Plan 7.1 step 4: the moved implementation must not reach back through the old path."""
    source = (PACKAGE / "intake" / "intake.py").read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module == DOTTED:
            raise AssertionError(
                f"the implementation imports {DOTTED} (line {node.lineno}), which is the package that imports it"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == DOTTED:
                    raise AssertionError(f"the implementation imports {DOTTED} (line {node.lineno})")
