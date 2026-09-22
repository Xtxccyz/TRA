"""Static-recovery package: plan section 7.7 (P2-S).

WHAT IS IN HERE SO FAR: `function_simhash.py`, moved byte-identically from the package root. The rest of P2-S's
scope (`static_analysis.py`, `ghidra_adapter.py`, `literal_table.py`, `function_similarity.py`,
`evidence_recovery.py`, `evidence_index.py`, `static_simulation.py`, `pma_static_plan.py`) is still at the root and
moves one module at a time, each with its own verification.

WHY THERE ARE NO RE-EXPORTS HERE: plan section 3.2 says one concept may have only one canonical implementation and
that re-exporting is not a second implementation - but a re-export list is also a second IMPORT SURFACE. Every moved
module keeps a root `sys.modules` shim, so both the old path and this package serve the SAME module object, and a
consumer needs no list from this file.

WHY THIS PACKAGE NEEDS NO LAZY FACADE (unlike `intake/` and `investigation/`): `static` is not the name of any
module, so nothing is shadowed. Measured in `.scratch/p2s-step1-inventory.py`: no pair of the nine static modules
imports the other at module level either.
"""

__all__: tuple[str, ...] = ()
