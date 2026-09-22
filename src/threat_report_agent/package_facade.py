"""One lazy package-facade mechanism, shared by the packages that shadow a same-named module.

WHY THIS MODULE EXISTS (the gate found the duplication, and the honest fix is one implementation):
`intake/__init__.py` and `investigation/__init__.py` both define an identical two-line `__dir__` plus an identical
`__getattr__`, so `scripts/check-structure-diff.py` reported a duplicate canonical implementation - its body-hash
comparison strips docstrings, so adding a comment did NOT clear it. Two copies of one mechanism is exactly what plan
3.2 forbids, and the right answer is the one the architecture skill's "one adapter = hypothetical seam, two adapters
= real seam" describes: with two callers the mechanism becomes a module of its own.

WHAT A FACADE IS FOR: plan 7.1 moves a MODULE whose dotted path becomes a PACKAGE. A package SHADOWS a same-named
module, so `from threat_report_agent.investigation import <name>` would resolve to the package and lose every name
the module exported - MEASURED on the first attempt at this migration: 145 ImportErrors.

WHY THE FORWARDING IS LAZY (PEP 562): an eager facade imports the implementation while the package is still
initialising, and a module that imports the package at MODULE level then resolves a HALF-INITIALISED implementation.
MEASURED twice in copies of this tree with the real suite.

WHY THE IMPLEMENTATION-IMPORT FAILURE IS CHAINED: the first version caught `AttributeError` around the name lookup
and re-raised its own, so a failure inside the implementation's own import chain surfaced as
"module 'X' has no attribute 'Y'" and hid the cause. Three separate diagnoses were misled by that. The import is now
wrapped so its real error is raised WITH its cause.
"""
from __future__ import annotations

import importlib
import sys
from typing import Any


def install_module_facade(package: str, implementation: str) -> None:
    """Make `package` (already in `sys.modules`) forward name lookups to `package.implementation`, lazily.

    Called from a package's `__init__.py` as `install_module_facade(__name__, "investigation")`, which mutates the
    package module object: PEP 562 looks `__getattr__` up on the module, so it has to live there, and this is the one
    place that knows how to build it.
    """
    module = sys.modules[package]

    def __getattr__(name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            target = importlib.import_module(f"{package}.{implementation}")
        except Exception as exc:  # noqa: BLE001 - a failed import must not look like a missing attribute
            raise ImportError(f"{package}: the implementation failed to import: {exc!r}") from exc
        try:
            return getattr(target, name)
        except AttributeError:
            raise AttributeError(f"module {package!r} has no attribute {name!r}") from None

    def __dir__() -> list[str]:
        target = importlib.import_module(f"{package}.{implementation}")
        return sorted(set(vars(module)) | set(dir(target)))

    module.__getattr__ = __getattr__  # type: ignore[attr-defined]
    module.__dir__ = __dir__  # type: ignore[attr-defined]
