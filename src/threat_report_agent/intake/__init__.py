"""Intake package: plan section 7.6 (P2-I), and the compatibility surface for the old module path.

`threat_report_agent.intake` was a MODULE (`intake.py`) and is now this package. A package SHADOWS a same-named
module, so this file installs the lazy facade that keeps `from threat_report_agent.intake import <name>` working -
MEASURED, the naive move produced 145 ImportErrors.

The MECHANISM lives in `threat_report_agent.package_facade` rather than here: `investigation/__init__.py` needs
exactly the same forwarding, and two copies of it were flagged as a duplicate canonical implementation by the
structure gate. The measurements behind the design - why the forwarding is lazy, why an implementation-import
failure is chained instead of disguised, and why there is no root shim file - are recorded in that module's
docstring.

WHAT IS IN HERE: `intake/intake.py`, the same implementation, moved byte-identically. Further intake-layer modules
(plan 7.6 also names `content_store.py`) can move in beside it, which is why the package stays a package instead of
rebinding `sys.modules` to the implementation - that form was measured to break submodule imports.
"""
from __future__ import annotations

from threat_report_agent.package_facade import install_module_facade

install_module_facade(__name__, "intake")

__all__: tuple[str, ...] = ()
