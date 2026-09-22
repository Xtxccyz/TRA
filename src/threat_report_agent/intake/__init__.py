"""Intake package: plan section 7.6 (P2-I), and the compatibility surface for the old module path.

`threat_report_agent.intake` was a MODULE (`intake.py`) and is now this package. A package SHADOWS a same-named
module, so without this file `from threat_report_agent.intake import <name>` would resolve to the package and lose
every name the module exported - MEASURED on an earlier attempt at this migration: 145 ImportErrors.

WHY LAZY (PEP 562 `__getattr__`) AND NOT AN EAGER RE-EXPORT: an eager facade imports the implementation while the
package is still initialising, and a module that other modules import at module level can then be resolved in a
half-initialised state. MEASURED in a copy of the tree with the real suite: the eager form produced 157 collection
errors, the lazy form produced ZERO new failures against a copy control.

WHY THERE IS NO ROOT `intake.py` SHIM: plan section 7.1 step 4 says the old path keeps a `sys.modules` shim, but
for a module whose old path became a PACKAGE the shim FILE would be dead code - the import system probes the
package directory before the module suffix, so `intake.py` at the package root would never be imported while
reading as though it were. THIS FILE is the shim: it serves the old dotted path.

WHAT IS IN HERE: `intake/intake.py`, the same implementation, moved byte-identically. Further intake-layer modules
(plan 7.6 also names `content_store.py`) can move in beside it, which is why the package stays a package instead of
rebinding `sys.modules` to the implementation - that form was measured to break submodule imports.
"""
from __future__ import annotations

import importlib

_IMPLEMENTATION = "intake"


def __getattr__(name: str):
    implementation = importlib.import_module(f"{__name__}.{_IMPLEMENTATION}")
    try:
        return getattr(implementation, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None


def __dir__() -> list[str]:
    implementation = importlib.import_module(f"{__name__}.{_IMPLEMENTATION}")
    return sorted(set(globals()) | set(dir(implementation)))
