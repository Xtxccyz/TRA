"""Analysis Task investigation phases.

This is not a second planner. DeepMiningPlanner still proposes actions;
InvestigationLoopDriver still executes them. AnalysisService remains the
ADR-0002 orchestrator adapter: it starts the Analysis Task and injects loop
and worker dispatch here.

Callers:
- first-round analyze: ``run_analysis_task_investigation``
- DSH workbench after a catalog action: ``continue_investigation_after_action``

Persist HOW skip lives here so leftover TRACE cannot cancel required recovery
tools. ``next_investigation_loop_path`` encodes READY/BOUNDARY before budget
before DeepMiningPlanner. Work-ledger OPEN / DEFERRED / tail / UNKNOWN
sequencing and 受控模拟 interleave live here so coverage cannot finalize
UNKNOWN before the worker.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Callable, Iterable, Mapping, Protocol

from threat_report_agent.investigation import ActionSpec, ActionType, recovery_actions_for_gap
from threat_report_agent.investigation_ledger import (
    completion_allows_stop,
    deferred_item_ids,
    open_item_ids,
)
from threat_report_agent.models import utcnow

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

HOW_SEED_CATEGORIES = frozenset(
    {
        "dynamic_api",
        "loader",
        "decode",
        "network",
        "execution",
        "process",
        "ppid",
        "thread",
    }
)

# Keyword supporting seeds still get durable UNKNOWN threads so reports and
# multi-seed tests see the question, but leftover TRACE is not charged.
SUPPORTING_SKIP_CATEGORIES = frozenset(
    {
        "persistence",
        "evasion",
        "pe_parser",
        "injection",
        "entrypoint",
    }
)

SLOT_DEAD_LETTER_ATTEMPTS = 3

PERSIST_HOW_READY = "ready"
PERSIST_HOW_BOUNDARY = "boundary"
PERSIST_HOW_MINE = "mine"

PersistHowSeedFn = Callable[..., object | None]
PersistHowBoundaryFn = Callable[..., object | None]


@dataclass(frozen=True)
class PersistHowDecision:
    """Whether leftover TRACE may run after persist HOW facts are already in the ledger."""

    disposition: str
    result: object | None = None
    playbook: object | None = None


def unique_os_thread_playbook() -> SimpleNamespace:
    return SimpleNamespace(id="unique-os-thread", mechanism_type="THREAD_CALLBACK")


def resolve_persist_how_skip(
    *,
    playbook: object | None,
    evidence: Iterable[object],
    thread_id: str,
    artifact_id: str,
    cluster_category: str,
    model_actions_only: bool,
    proposed_actions: Iterable[object],
    historical_attempts: int,
    seed_result: PersistHowSeedFn,
    static_boundary: PersistHowBoundaryFn,
    unique_thread: PersistHowSeedFn,
    supporting_boundary: PersistHowBoundaryFn,
) -> PersistHowDecision:
    """Decide persist HOW skip before budget deferral or DeepMiningPlanner.

    Persist CANDIDATE/UNKNOWN is report content. Leftover TRACE cannot invent
    missing catalog tokens. Required recovery tools and first-round model
    catalog actions cancel skip so the seed stays mineable.
    """
    persist_ready = (
        seed_result(
            playbook=playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if playbook is not None and not model_actions_only
        else None
    )
    persist_boundary = (
        static_boundary(
            playbook=playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if playbook is not None and persist_ready is None and not model_actions_only
        else None
    )
    resolved_playbook = playbook
    if (
        persist_boundary is None
        and persist_ready is None
        and playbook is None
        and not model_actions_only
    ):
        unique_ready = unique_thread(
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        )
        if unique_ready is not None:
            persist_ready = unique_ready
            resolved_playbook = unique_os_thread_playbook()
        elif cluster_category in SUPPORTING_SKIP_CATEGORIES:
            persist_boundary = supporting_boundary(
                evidence=evidence,
                thread_id=thread_id,
                artifact_id=artifact_id,
                category=cluster_category,
            )
    if (
        persist_ready is None
        and persist_boundary is None
        and int(historical_attempts or 0) >= SLOT_DEAD_LETTER_ATTEMPTS
    ):
        persist_boundary = static_boundary(
            playbook=resolved_playbook,
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
        ) or supporting_boundary(
            evidence=evidence,
            thread_id=thread_id,
            artifact_id=artifact_id,
            category=cluster_category,
        )
    persist_gate = None
    if persist_ready is not None:
        persist_gate = getattr(persist_ready, "gate", None)
    elif persist_boundary is not None:
        persist_gate = getattr(persist_boundary, "gate", None)
    persist_recovery = (
        recovery_actions_for_gap(
            str(getattr(resolved_playbook, "mechanism_type", "") or ""),
            getattr(persist_gate, "missing", ()) or (),
            evidence=evidence if isinstance(evidence, Iterable) else (),
        )
        if resolved_playbook is not None
        else ()
    )
    if persist_ready is not None and (
        persist_recovery or any(action_is_model_or_human(item) for item in proposed_actions)
    ):
        persist_ready = None
        persist_boundary = None
    if persist_ready is not None:
        return PersistHowDecision(PERSIST_HOW_READY, persist_ready, resolved_playbook)
    if persist_boundary is not None:
        return PersistHowDecision(PERSIST_HOW_BOUNDARY, persist_boundary, resolved_playbook)
    return PersistHowDecision(PERSIST_HOW_MINE, None, resolved_playbook)


LOOP_PATH_PERSIST_READY = "persist_ready"
LOOP_PATH_PERSIST_BOUNDARY = "persist_boundary"
LOOP_PATH_BUDGET_DEFER = "budget_defer"
LOOP_PATH_PLANNER = "planner"


def next_investigation_loop_path(
    persist_how: PersistHowDecision,
    *,
    budget_exhausted: bool,
) -> str:
    """Persist HOW skip beats budget; budget beats DeepMiningPlanner.

    READY / BOUNDARY still run leftover CONTROLLED_EMULATE. MINE with a full
    budget defers the seed instead of charging TRACE. There is no zero-cost
    skip that treats an empty proposal list as persist-ready.
    """
    if persist_how.disposition == PERSIST_HOW_READY:
        return LOOP_PATH_PERSIST_READY
    if persist_how.disposition == PERSIST_HOW_BOUNDARY:
        return LOOP_PATH_PERSIST_BOUNDARY
    if budget_exhausted:
        return LOOP_PATH_BUDGET_DEFER
    return LOOP_PATH_PLANNER


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


def action_is_model_or_human(item: object) -> bool:
    """First-round analyze catalog actions must survive persist HOW skip."""
    provenance = getattr(item, "provenance", None)
    if isinstance(provenance, Mapping):
        origin = str(provenance.get("origin") or "").casefold()
        if origin in {"model", "human"}:
            return True
    if str(getattr(item, "planner_turn_id", "") or "").strip():
        return True
    parameters = getattr(item, "parameters", None)
    if not isinstance(parameters, Mapping):
        parameters = {}
    origin = str(parameters.get("origin") or "").casefold()
    if origin in {"model", "human"}:
        return True
    if parameters.get("_planner_turn_id") or parameters.get("_model_provenance"):
        return True
    return False


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
