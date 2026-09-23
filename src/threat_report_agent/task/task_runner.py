"""P3.2 task runner: the port the task path needs from its host, declared BEFORE anything moves.

STATUS: interface declared, not yet load-bearing. Plan 7.1 orders every migration in nine steps and step 2 is
"在新包先建立最小公开接口和 contract test" - build the minimal interface and its contract test in the new package
first, then move the one implementation (step 3). This module is that step-2 artefact for P3.2; the first cluster
move (`creation`) is P3.2c and is what makes this module load-bearing. Until then it is imported only by
`tests/test_task_runner_contract.py`, and it is deliberately NOT a second implementation of anything.

WHY A PORT AT ALL (MEASURED, `.scratch/p32design-candidates.py` and `.scratch/p32design-scale.py`):

  * The P3.2 wish list is 19 methods / 585 lines of `AnalysisService` covering task creation, lifecycle, budget,
    cancellation and the limitation/outcome projections.
  * Their full helper closure is 18 more members / 1,040 lines, but all of it is reached TRANSITIVELY through the
    entry points below, so it stays on the host. Only ONE closure member would travel with the cluster
    (`workbench_bind_existing_analysis`, 90 lines, used by no outside method).
  * The port-relevant spine - members the candidates touch DIRECTLY that also have at least one user OUTSIDE the
    candidate set - is exactly the six members pinned in `TASK_HOST_MEMBERS`. An earlier "31 shared members of a
    163-member closure" figure counted the whole transitive closure and made the cluster look unbounded; the
    measured direct spine is what a port actually has to provide, and it is small.
  * So the whole of P3.2 is at most 675 lines / 20 members behind a 6-member port, and it can be moved one cluster
    at a time in this order: `creation` (3 methods, spine 3) -> `lifecycle` (1, spine 2) -> `budget`
    (spine 1: `task_view`) -> `cancellation` (2, spine 6 - the only cluster that needs
    `_seal_task_audit_chain`).

WHY TWO PRIVATE NAMES APPEAR ON A PORT (a deliberate, reviewable choice):

  `_audit` and `_seal_task_audit_chain` are host-private, and naming them here is not an oversight. The host is
  `AnalysisService`, whose PUBLIC surface is a contract in its own right: P3.1 fixed it to four stable operation
  groups and `tests/test_service_facade_contract.py` plus `tests/test_task_runner_contract.py` pin it, and plan 7.10
  keeps the HTTP boundary on public members only. Publishing `audit` / `seal_task_audit_chain` as new public methods
  just to make the port look tidy would widen that published surface for a purely internal collaboration, so the port
  states the host's real name instead. A future P3/P4 step that genuinely needs a public audit entry point should
  rename the member AND update this port and its pin together, in one deliberate change.

`missing_task_host_members` is the executable form of the port, so "does this object satisfy the host contract?" is
answerable at runtime rather than only by a type checker.

    python -m pytest -q tests/test_task_runner_contract.py
"""
from __future__ import annotations

from typing import Protocol

from sqlalchemy.orm import Session

from threat_report_agent.config import Settings
from threat_report_agent.content_store import ContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, AuditEvent

#: The measured direct spine of the P3.2 candidate set - the ONLY things a task cluster may require of its host.
#: Pinned by `tests/test_task_runner_contract.py`, which re-derives it from `service.py` and fails if it grew, so
#: adding a seventh member is a deliberate act rather than a silent widening of the port.
TASK_HOST_MEMBERS: tuple[str, ...] = (
    "_audit",
    "_seal_task_audit_chain",
    "content_store",
    "database",
    "settings",
    "task_view",
)


class TaskHost(Protocol):
    """What the task path may use on the object that owns it.

    Deliberately three pieces of HOST STATE plus three HOST OPERATIONS and nothing else: state the task path reads
    (`settings`, `database`, `content_store`), the audit writer it must call (`_audit`), the terminal audit-chain
    seal that only cancellation needs (`_seal_task_audit_chain`), and the public read of a task (`task_view`).

    `task_view` being here is the one member that is a PUBLISHED facade operation (P3.1's "read status" group):
    the budget cluster asks the host for the task view rather than reading task rows itself, which keeps that read
    single-sourced.
    """

    settings: Settings
    database: Database
    content_store: ContentStore

    def _audit(
        self,
        session: Session,
        *,
        case_id: str | None,
        event_type: str,
        actor: str,
        object_type: str,
        object_id: str,
        payload: dict[str, object],
        task_id: str | None = None,
    ) -> AuditEvent: ...

    def _seal_task_audit_chain(
        self,
        session: Session,
        task: AnalysisTask,
        terminal_event_type: str,
    ) -> None: ...

    def task_view(self, task_id: str) -> dict[str, object]: ...


def missing_task_host_members(host: object) -> tuple[str, ...]:
    """Return the `TASK_HOST_MEMBERS` this object does not provide, in declaration order.

    Empty means the object satisfies the port. Used by the contract test to prove `AnalysisService` DOES satisfy it
    (and that a stub missing a member is reported rather than silently accepted).
    """
    return tuple(name for name in TASK_HOST_MEMBERS if not hasattr(host, name))
