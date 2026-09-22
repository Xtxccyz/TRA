"""Ports: the seams the later steps depend on instead of depending on `AnalysisService`. PURE TYPES ONLY.

Plan step P1.2 asks for `ModelPlanningPort`, `ToolExecutionPort`, `EmulationPort`, `StaticEvidencePort`,
`ReportRevisionWriter` and `WorkbenchQueryReader`, each stating its inputs, outputs, errors, budget and ordering,
with at least one deterministic test adapter. It also mandates a **deletion test**: a port that merely forwards a
large class's methods verbatim has FAILED and must go back to P1 to be narrowed.

THIS FILE IS A FIRST SLICE, NOT P1.2. It defines the two ports whose contracts the plan describes precisely
enough to write without first reading every consumer:

  * `ReportRevisionWriter` - plan section P3.4: assemble a Report Document from an immutable Analysis Snapshot,
    run the compose gate, write a Report Revision.
  * `WorkbenchQueryReader`  - plan section P3.6: read-only queries (evidence, timeline, report revision) that
    must not enter the analysis loop and must not change a snapshot or revision.

The remaining four need each consumer's real needs read first, and inventing them from a summary would produce
exactly the forwarding-shaped port the deletion test exists to reject. Recorded as partial; `current_step` does
not advance.

WHY THE SURFACE IS CAPPED AND CHECKED IN A TEST: "interfaces smaller than their implementations" is otherwise an
opinion. `tests/test_ports.py` asserts each port here exposes at most two callables, so a future edit that grows
one into a façade of the whole service fails rather than passing review by looking reasonable.

This module must stay free of persistence, transport, SDK and ORM imports.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from threat_report_agent.projection_protocols import AnalysisSnapshotView, ReportRevisionView


@runtime_checkable
class ReportRevisionWriter(Protocol):
    """Assemble and persist one Report Revision from an immutable Analysis Snapshot (ADR-0024/0025/0036).

    CONTRACT
      input   : a snapshot, plus an optional model-authored `draft`.
      output  : the published revision. `compose` returns the markdown that WOULD be published.
      errors  : never raises for a gate rejection. Per ADR-0036 a rejected draft is not a failure - the
                deterministic body is published instead - so the outcome is carried by the returned revision,
                not by an exception. Raising here would turn "the model wrote something unsuitable" into "the
                run failed", which is the failure shape recorded as `8e75f6dc`.
      ordering: `compose` is pure and must not persist; `write` persists exactly once and must not mutate its
                snapshot. A late-arriving result must produce a NEW snapshot and revision, never edit an existing
                revision's markdown.

    WHY TWO METHODS AND NOT MORE: a caller needs to (a) know what would be published and (b) publish it. Anything
    else - gate internals, draft selection, snapshot bookkeeping - is implementation the caller must not see; the
    deletion test would reject a wider surface.
    """

    def compose(self, snapshot: AnalysisSnapshotView, *, draft: str = "") -> str:
        """The markdown that would be published for this snapshot. MUST NOT persist anything."""
        ...

    def write(
        self,
        snapshot: AnalysisSnapshotView,
        *,
        draft: str = "",
        parent_revision_id: str | None = None,
    ) -> ReportRevisionView:
        """Publish a revision. MUST NOT mutate `snapshot` or any existing revision."""
        ...


@runtime_checkable
class WorkbenchQueryReader(Protocol):
    """Read-only queries for the workbench surfaces (plan section P3.6).

    CONTRACT
      input   : a task id (and, where relevant, a revision id).
      output  : the revision, or a sequence of evidence rows. Both come from the P1.1 projection protocols so a
                caller never needs `models.py`.
      errors  : a missing task or revision raises `LookupError`; absence is NOT returned as an empty result,
                because "no rows" and "no such task" mean different things to a reader.
      ordering: results are returned in a stable order so two identical queries can be compared; a query MUST
                NOT change a snapshot, a revision or any evidence row.

    `evidence` returns `object` rather than a concrete row type on purpose: the row shape is not settled enough to
    freeze, and pinning it here would make this port a second canonical definition of the evidence projection.
    """

    def revision(self, task_id: str, revision_id: str | None = None) -> ReportRevisionView:
        """The named revision, or the latest published one for the task."""
        ...

    def evidence(self, task_id: str, limit: int | None = None) -> tuple[object, ...]:
        """Evidence rows for the task, in a stable order."""
        ...


#: name -> the plan section that describes its contract. Kept here so a later step can tell which of P1.2's six
#: ports still have to be written.
P12_PORTS: dict[str, str] = {
    "ReportRevisionWriter": "written (P3.4)",
    "WorkbenchQueryReader": "written (P3.6)",
    "ModelPlanningPort": "NOT WRITTEN - needs the planning consumers read first",
    "ToolExecutionPort": "NOT WRITTEN - needs the tool dispatch consumers read first",
    "EmulationPort": "NOT WRITTEN - needs the worker dispatch consumers read first",
    "StaticEvidencePort": "NOT WRITTEN - needs the static recovery consumers read first",
}
