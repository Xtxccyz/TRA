"""Investigation package: plan section 7.9 (P2-V), and the compatibility surface for the old module path.

`threat_report_agent.investigation` was a MODULE (`investigation.py`, 8,446 lines) and is now this package. A
package SHADOWS a same-named module, so this file installs the lazy facade that keeps
`from threat_report_agent.investigation import <name>` working - MEASURED, the naive move produced 145 ImportErrors.

The MECHANISM lives in `threat_report_agent.package_facade` rather than here: `intake/__init__.py` needs exactly the
same forwarding, and two copies of it were flagged as a duplicate canonical implementation by the structure gate.
The measurements behind the design - why the forwarding is lazy, why an implementation-import failure is chained
instead of disguised, and why there is no root shim file - are recorded in that module's docstring.

WHY `__path__` MATTERS: plan 7.9 also names `investigation_protocol.py`, `investigation_ledger.py`,
`behavior_catalog.py`, `persist_how.py`, `mechanism_completeness.py`, `mechanism_ready.py` and
`semantic_predicates.py` for this layer, so the package must stay a package. MEASURED: `investigation_protocol.py`
cannot move in the same step - it brings an edge that re-enters this package while it initialises (126 collection
errors) - so those modules move in their own later steps.
"""
from __future__ import annotations

from threat_report_agent.package_facade import install_module_facade

install_module_facade(__name__, "investigation")

__all__: tuple[str, ...] = ()
