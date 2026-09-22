"""Task package: plan section 7.10 (P2-TK).

WHAT IS IN HERE - P2-TK's three modules, each moved byte-identically behind a root `sys.modules` shim (plan step P4
deletes the shims, in its own checkpoint):

  * `analysis_task_orchestration` - the investigation-loop orchestration: which loop path to take next, the persist-how
    decision, and the saturated / emulation-informed continuations,
  * `status` - the task/case/report/claim state vocabulary and `transition_task`, the one place a lifecycle
    transition is validated,
  * `turn_lifecycle` - the long-turn lifecycle snapshot.

WHY THERE ARE NO RE-EXPORTS AND NO FACADE: plan 3.2 allows a re-export but a re-export list is also a second import
surface, and `task` is not the name of any module, so nothing is shadowed and each moved module keeps an effective root
shim.

BOUNDARY (plan 7.10's success criteria): Task lifecycle, budget and cancellation semantics are unchanged, Task exposes
only stable operations, and NO HTTP request object enters this package - `AnalysisService` (which owns the HTTP-facing
methods) still constructs the task path exactly as before, and the move touched only import lines.

MEASURED WHILE MOVING (recorded, not fixed here): `turn_lifecycle` has NO production importer - the only importer
anywhere is `tests/test_final_runtime_closure.py`. Whether it should be wired into the long-turn path or retired is a
behaviour/product decision, so the move preserves it exactly as it was.
"""

__all__: tuple[str, ...] = ()
