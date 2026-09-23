"""Analysis Task investigation phases.

This is not a second planner. DeepMiningPlanner still proposes actions;
InvestigationLoopDriver still executes them. AnalysisService remains the
ADR-0002 orchestrator adapter: it starts the Analysis Task and injects loop
and worker dispatch here.

Callers:
- first-round analyze: ``run_analysis_task_investigation``
- DSH workbench after a catalog action: ``continue_investigation_after_action``

Persist HOW skip and the loop path (READY / BOUNDARY / budget / planner) no
longer live here: they MOVED to ``threat_report_agent.investigation.loop_path``
so the investigation package can use them without importing ``task`` (that
import was a cycle). They are re-exported below for existing callers, with the
same object identity. Work-ledger OPEN / DEFERRED / tail / UNKNOWN sequencing
and 受控模拟 interleave live here so coverage cannot finalize UNKNOWN before the
worker.
"""

from __future__ import annotations

from typing import Iterable, Protocol

# Explicit re-exports of the P3.3 layer-item-1 move (`NAME as NAME` is the explicit-re-export idiom, which keeps the
# linter's F401 quiet). They exist for callers that still import from this path; the implementation lives in
# investigation/loop_path.py. Delete this block in Phase 4 with the other compatibility re-exports, after the callers
# have moved.
from threat_report_agent.investigation.loop_path import (
    LOOP_PATH_BUDGET_DEFER as LOOP_PATH_BUDGET_DEFER,
    LOOP_PATH_PERSIST_BOUNDARY as LOOP_PATH_PERSIST_BOUNDARY,
    LOOP_PATH_PERSIST_READY as LOOP_PATH_PERSIST_READY,
    LOOP_PATH_PLANNER as LOOP_PATH_PLANNER,
    PERSIST_HOW_BOUNDARY as PERSIST_HOW_BOUNDARY,
    PERSIST_HOW_MINE as PERSIST_HOW_MINE,
    PERSIST_HOW_READY as PERSIST_HOW_READY,
    PersistHowBoundaryFn as PersistHowBoundaryFn,
    PersistHowDecision as PersistHowDecision,
    PersistHowSeedFn as PersistHowSeedFn,
    SLOT_DEAD_LETTER_ATTEMPTS as SLOT_DEAD_LETTER_ATTEMPTS,
    SUPPORTING_SKIP_CATEGORIES as SUPPORTING_SKIP_CATEGORIES,
    action_is_model_or_human as action_is_model_or_human,
    next_investigation_loop_path as next_investigation_loop_path,
    resolve_persist_how_skip as resolve_persist_how_skip,
    unique_os_thread_playbook as unique_os_thread_playbook,
)

from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.investigation.investigation_ledger import (
    completion_allows_stop,
    deferred_item_ids,
    open_item_ids,
)
from threat_report_agent.models import utcnow
from threat_report_agent.investigation.seed_support import (
    HOW_SEED_CATEGORIES as HOW_SEED_CATEGORIES,
)

PERSIST_SKIP_TRACE_ERROR = "PERSIST_HOW_SKIP"
PERSIST_KEEP_ACTION_TYPES = frozenset(
    {
        ActionType.CONTROLLED_EMULATE.value,
        ActionType.TRACE_API_ARGUMENT.value,
        ActionType.GET_DECOMPILE.value,
        ActionType.READ_BYTES.value,
        ActionType.DECODE_CANDIDATE.value,
        ActionType.EVALUATE_CONSTANT.value,
    }
)


class AnalysisTaskRuntime(Protocol):
    """I/O the phase machine does not own in this slice.

    ``_run_investigation_loop`` and ``_run_post_static_emulation`` stay on
    AnalysisService. Ledger park/finalize/reverify also stay there so existing
    SQLAlchemy sessions are unchanged.
    """

    def _work_ledger(self, task_id: str) -> list[dict[str, object]]: ...

    def _park_open_ledger(self, task_id: str) -> None: ...

    def _finalize_tail_ledger(self, task_id: str) -> None: ...

    def _run_investigation_loop(
        self,
        task_id: str,
        *,
        model_actions_only: bool = False,
        ledger_phase: str = "coverage",
    ) -> list[str]: ...

    def _run_post_static_emulation(self, task_id: str) -> list[str]: ...

    def _deferred_budget_thread_ids(self, task_id: str) -> tuple[str, ...]: ...

    def _unattempted_seed_thread_ids(self, task_id: str) -> tuple[str, ...]: ...

    def _real_simulation_result_count(self, task_id: str) -> int: ...

    def _reverify_how_after_emulation(self, task_id: str) -> None: ...

    def _run_saturated_investigation(self, task_id: str) -> list[str]: ...

    def _run_emulation_informed_investigation(
        self,
        task_id: str,
        *,
        saturated: bool = True,
    ) -> list[str]: ...


def _action_type_name(action_type: object) -> str:
    return str(getattr(action_type, "value", action_type) or "").upper()


def is_persist_recovery_action(action_type: object) -> bool:
    return _action_type_name(action_type) in PERSIST_KEEP_ACTION_TYPES


def keep_recovery_after_persist_skip(
    actions: Iterable[object],
) -> tuple[ActionSpec, ...]:
    """Keep required recovery tools after persist CANDIDATE; drop leftover TRACE."""
    kept: list[ActionSpec] = []
    for item in actions:
        action_type = getattr(item, "action_type", None)
        if action_type is None:
            continue
        if not is_persist_recovery_action(action_type) and not action_is_model_or_human(item):
            continue
        if isinstance(item, ActionSpec):
            kept.append(item)
    return tuple(kept)


def supersede_queued_trace_after_persist_skip(
    queued_rows: Iterable[object],
    *,
    thread_id: str,
) -> None:
    """Do not leave leftover DSH TRACE tickets QUEUED after persist HOW skip.

    Artifact-wide QUEUED rows are rebound onto every seed thread. A still
    QUEUED GET_CALLEES row makes chat ask 再深入 even though the official
    revision already recorded persist CANDIDATE/UNKNOWN HOW. Required
    recovery actions (argument trace, decompile, granted bytes, emu)
    stay queued so missing cipher/flags can still close.
    """
    del thread_id
    for queued in queued_rows:
        if str(getattr(queued, "status", "") or "") != "QUEUED":
            continue
        if is_persist_recovery_action(getattr(queued, "action_type", "")):
            continue
        if action_is_model_or_human(queued):
            continue
        queued.status = "CANCELLED"
        queued.error = PERSIST_SKIP_TRACE_ERROR
        queued.finished_at = utcnow()


def run_saturated_investigation(runtime: AnalysisTaskRuntime, task_id: str) -> list[str]:
    """Keep investigating until the work ledger has no OPEN or DEFERRED items.

    Coverage parks timeboxed seeds as DEFERRED (待完成) and continues with
    the rest. After OPEN is empty, isolated emulation runs before the tail
    pass so CONTROLLED_EMULATE placeholders can consume worker bytes. Honest
    UNKNOWN is allowed only after that tail pass.
    """
    limitations: list[str] = []
    previous_open: tuple[str, ...] | None = None
    previous_deferred: tuple[str, ...] | None = None
    emu_dispatched = False
    for _round in range(8):
        ledger = runtime._work_ledger(task_id)
        if completion_allows_stop(ledger):
            break
        open_ids = open_item_ids(ledger)
        deferred_ids = deferred_item_ids(ledger)
        if not ledger:
            limitations.extend(
                runtime._run_investigation_loop(task_id, ledger_phase="coverage")
            )
            continue
        if open_ids:
            if open_ids == previous_open:
                limitations.append(
                    "Investigation coverage stalled; remaining OPEN seeds parked as DEFERRED for the tail pass."
                )
                runtime._park_open_ledger(task_id)
                previous_open = None
                continue
            limitations.extend(
                runtime._run_investigation_loop(task_id, ledger_phase="coverage")
            )
            previous_open = open_ids
            continue
        if deferred_ids:
            waiting_for_emu = any(
                str(item.get("next_method") or "") == ActionType.CONTROLLED_EMULATE.value
                for item in ledger
                if str(item.get("status") or "").upper() == "DEFERRED"
            )
            if waiting_for_emu and not emu_dispatched:
                limitations.extend(runtime._run_post_static_emulation(task_id))
                emu_dispatched = True
            if deferred_ids == previous_deferred:
                limitations.append(
                    "Investigation tail pass did not shrink remaining DEFERRED seeds."
                )
                remaining = tuple(
                    dict.fromkeys(
                        (
                            *runtime._deferred_budget_thread_ids(task_id),
                            *runtime._unattempted_seed_thread_ids(task_id),
                        )
                    )
                )
                if remaining:
                    limitations.extend(runtime._run_investigation_loop(task_id))
                    previous_deferred = None
                    continue
                runtime._finalize_tail_ledger(task_id)
                break
            limitations.extend(
                runtime._run_investigation_loop(task_id, ledger_phase="tail")
            )
            previous_deferred = deferred_ids
            continue
        remaining = tuple(
            dict.fromkeys(
                (
                    *runtime._deferred_budget_thread_ids(task_id),
                    *runtime._unattempted_seed_thread_ids(task_id),
                )
            )
        )
        if remaining:
            limitations.extend(runtime._run_investigation_loop(task_id))
            continue
        break
    return list(dict.fromkeys(limitations))


def run_emulation_informed_investigation(
    runtime: AnalysisTaskRuntime,
    task_id: str,
    *,
    saturated: bool = True,
) -> list[str]:
    """Dispatch isolated emu, then continue investigation on the new facts.

    Kunglao DISPATCH then continue: worker bytes/registers are not a tail
    job after saturation.  A second pass is skipped when the worker did
    not add a real simulation_result, so later DSH actions do not burn
    another action budget against an unchanged frontier.
    """
    before = runtime._real_simulation_result_count(task_id)
    limitations = list(runtime._run_post_static_emulation(task_id))
    after = runtime._real_simulation_result_count(task_id)
    if after <= before:
        return list(dict.fromkeys(limitations))
    runtime._reverify_how_after_emulation(task_id)
    if saturated:
        limitations.extend(runtime._run_saturated_investigation(task_id))
    else:
        limitations.extend(runtime._run_investigation_loop(task_id))
    return list(dict.fromkeys(limitations))


def run_analysis_task_investigation(
    runtime: AnalysisTaskRuntime,
    task_id: str,
) -> list[str]:
    """First-round analyze: saturate the work ledger, then continue after 受控模拟."""
    limitations = list(runtime._run_saturated_investigation(task_id))
    limitations.extend(runtime._run_emulation_informed_investigation(task_id))
    return list(dict.fromkeys(limitations))


def continue_investigation_after_action(
    runtime: AnalysisTaskRuntime,
    task_id: str,
) -> list[str]:
    """Workbench path: emulate, reverify on real rows, one loop. Never saturate."""
    return runtime._run_emulation_informed_investigation(task_id, saturated=False)
