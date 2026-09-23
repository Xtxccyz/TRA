"""Emulation package: plan section 7.8 (P2-E).

WHAT IS IN HERE: the moved implementations, one module at a time - PLUS one module that was NOT moved as a whole:
`policy.py` (P3.3 layer item 2). It holds the PURE simulation policy - the predicates, the request/policy dataclasses
and the constants they close over - SUNK OUT of `simulation_adapters` so that `investigation/` can reach it without
importing an implementation module (plan section 3.2 lets `investigation/` import emulation INTERFACES, which is what
this module is). Its module-level imports are stdlib only, so importing it drags nothing in.

WHY THERE ARE NO RE-EXPORTS AND NO FACADE: plan 3.2 allows a re-export but a re-export list is also a second
import surface, and `emulation` is not the name of any module, so nothing is shadowed and every moved module keeps an
effective root `sys.modules` shim. MEASURED in `.scratch/p2e-step1-inventory.py`: none of these modules sits in a
module-level import cycle, so a shim cannot re-enter a half-initialised module.

REFUSED BY THE PLAN'S OWN RULE: `simulation_adapters.py` locates `tool-worker/qiling_linux_runtime` relative to
`__file__` (line 1542), so moving it would break that path at RUNTIME. It stays at the package root until its
resource discovery is changed in a work item of its own - and that refusal is exactly why only its PURE POLICY half
could be sunk here: layer item 2 left `default_simulation_runner` and `qiling_unavailable_observation`, the two names
whose closure reaches the qiling adapter, where they were.
"""

__all__: tuple[str, ...] = ()
