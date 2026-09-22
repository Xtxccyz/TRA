"""Emulation package: plan section 7.8 (P2-E).

WHAT IS IN HERE: the moved implementations, one module at a time

WHY THERE ARE NO RE-EXPORTS AND NO FACADE: plan 3.2 allows a re-export but a re-export list is also a second
import surface, and `emulation` is not the name of any module, so nothing is shadowed and every moved module keeps an
effective root `sys.modules` shim. MEASURED in `.scratch/p2e-step1-inventory.py`: none of these modules sits in a
module-level import cycle, so a shim cannot re-enter a half-initialised module.

REFUSED BY THE PLAN'S OWN RULE: `simulation_adapters.py` locates `tool-worker/qiling_linux_runtime` relative to
`__file__` (line 1542), so moving it would break that path at RUNTIME. It stays at the package root until its
resource discovery is changed in a work item of its own.
"""

__all__: tuple[str, ...] = ()
