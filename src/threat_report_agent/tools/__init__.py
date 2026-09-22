"""Tools package: plan section 7.5 (P2-T).

WHAT IS IN HERE: `tool_execution` (the ToolRun request/result models, the static tool allowlist, the worker-side
`StaticToolActivities`, `StaticToolRunWorkflow`, and the `TemporalToolExecutor` client adapter) and
`tool_authoring` (the policy evaluation that decides whether an authored tool request may run at all). Both moved
through the plan 7.1 recipe: `git mv`, one root `sys.modules` shim each, and no re-exports.

WHY THERE ARE NO RE-EXPORTS AND NO FACADE: plan 3.2 allows a re-export but a re-export list is also a second import
surface, and `tools` is not the name of any module, so nothing is shadowed and each moved module keeps an effective
root shim. Deleting the shims is plan step P4, in its own checkpoint.

THE BOUNDARY, AND WHY THIS PACKAGE NEEDED A PRE-STEP: plan 7.5 requires that tools only produce structured
ToolRun/Evidence, that sample execution still goes only through the isolated worker, that the tool allowlist and
failure statuses are unchanged, and that `tools` must not import `AnalysisService`. That last clause did not hold
before: `tool_execution.py` reached the service layer through two FUNCTION-LEVEL imports inside its retention and
audit-seal activities, which is the reverse leg of the allowlisted `service <-> tool_execution` cycle. P2-T.0
separated the control plane into `threat_report_agent/control_activities.py` first, so the import graph went to
ZERO cycles and this package now has no path back to `service` at any nesting depth - pinned by
`tests/test_control_plane_contract.py`.

MEASURED WHILE MOVING (recorded, not fixed here): `tool_authoring.py` has NO production importer - the only
importer anywhere is `tests/test_tool_authoring.py`. Whether it should be wired into the tool-authoring route or
retired is a behaviour/product decision, not a structural one, so the move preserves it exactly as it was.
"""

__all__: tuple[str, ...] = ()
