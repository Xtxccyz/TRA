from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from threat_report_agent.task.analysis_task_orchestration import (
    PERSIST_SKIP_TRACE_ERROR,
    continue_investigation_after_action,
    keep_recovery_after_persist_skip,
    run_analysis_task_investigation,
    run_emulation_informed_investigation,
    run_saturated_investigation,
    supersede_queued_trace_after_persist_skip,
)
from threat_report_agent.investigation.loop_path import action_is_model_or_human
from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.investigation.investigation_ledger import LEDGER_CLOSED, LEDGER_DEFERRED, LEDGER_OPEN

#: The P3.3 layer-item-1 cluster. It is DEFINED in `investigation/loop_path.py` and re-exported by
#: `task/analysis_task_orchestration.py`; the tests below pin both ends of that, because the extractor's first draft
#: moved the bodies without their decorator and no structural gate noticed.
LOOP_PATH_CLUSTER = (
    "LOOP_PATH_PERSIST_READY",
    "LOOP_PATH_PERSIST_BOUNDARY",
    "LOOP_PATH_BUDGET_DEFER",
    "LOOP_PATH_PLANNER",
    "PERSIST_HOW_READY",
    "PERSIST_HOW_BOUNDARY",
    "PERSIST_HOW_MINE",
    "PersistHowDecision",
    "PersistHowBoundaryFn",
    "PersistHowSeedFn",
    "SLOT_DEAD_LETTER_ATTEMPTS",
    "SUPPORTING_SKIP_CATEGORIES",
    "action_is_model_or_human",
    "unique_os_thread_playbook",
    "next_investigation_loop_path",
    "resolve_persist_how_skip",
)


class _PhaseRuntime:
    def __init__(self, ledger: list[dict[str, object]] | None = None) -> None:
        self.ledger = list(ledger or [])
        self.calls: list[object] = []
        self.budget_ids: tuple[str, ...] = ()
        self.unattempted_ids: tuple[str, ...] = ()
        self.simulation_count = 0

    def _work_ledger(self, task_id: str) -> list[dict[str, object]]:
        del task_id
        return [dict(item) for item in self.ledger]

    def _park_open_ledger(self, task_id: str) -> None:
        del task_id
        self.calls.append("park")
        parked: list[dict[str, object]] = []
        for item in self.ledger:
            row = dict(item)
            if str(row.get("status") or "").upper() in {LEDGER_OPEN, "IN_PROGRESS"}:
                row["status"] = LEDGER_DEFERRED
                row["next_method"] = ActionType.CONTROLLED_EMULATE.value
            parked.append(row)
        self.ledger = parked

    def _finalize_tail_ledger(self, task_id: str) -> None:
        del task_id
        self.calls.append("finalize")
        self.ledger = [
            {**item, "status": "UNKNOWN"} if str(item.get("status") or "").upper() == LEDGER_DEFERRED else dict(item)
            for item in self.ledger
        ]

    def _run_investigation_loop(self, task_id: str, **kwargs: object) -> list[str]:
        del task_id
        phase = str(kwargs.get("ledger_phase") or "coverage")
        self.calls.append(("loop", phase))
        return []

    def _run_post_static_emulation(self, task_id: str) -> list[str]:
        del task_id
        self.calls.append("emu")
        return []

    def _deferred_budget_thread_ids(self, task_id: str) -> tuple[str, ...]:
        del task_id
        return self.budget_ids

    def _unattempted_seed_thread_ids(self, task_id: str) -> tuple[str, ...]:
        del task_id
        return self.unattempted_ids

    def _real_simulation_result_count(self, task_id: str) -> int:
        del task_id
        return self.simulation_count

    def _reverify_how_after_emulation(self, task_id: str) -> None:
        del task_id
        self.calls.append("reverify")

    def _run_saturated_investigation(self, task_id: str) -> list[str]:
        self.calls.append("saturated")
        return ["sat"]

    def _run_emulation_informed_investigation(
        self,
        task_id: str,
        *,
        saturated: bool = True,
    ) -> list[str]:
        del task_id
        self.calls.append(("informed", saturated))
        return ["informed"]


def test_first_round_analyze_saturates_then_continues_after_emulation() -> None:
    runtime = _PhaseRuntime()
    limitations = run_analysis_task_investigation(runtime, "task-1")
    assert runtime.calls == ["saturated", ("informed", True)]
    assert limitations == ["sat", "informed"]


def test_workbench_path_never_saturates() -> None:
    runtime = _PhaseRuntime()
    limitations = continue_investigation_after_action(runtime, "task-1")
    assert runtime.calls == [("informed", False)]
    assert limitations == ["informed"]


def test_saturated_investigation_dispatches_emu_before_deferred_tail() -> None:
    runtime = _PhaseRuntime(
        [{"id": "thread-how", "status": LEDGER_OPEN, "next_method": ""}]
    )
    limitations = run_saturated_investigation(runtime, "task-1")
    assert runtime.calls == [
        ("loop", "coverage"),
        "park",
        "emu",
        ("loop", "tail"),
        "finalize",
    ]
    assert any("parked as DEFERRED" in item for item in limitations)
    assert runtime.ledger[0]["status"] == "UNKNOWN"


def test_emulation_informed_reverifies_then_saturates_only_on_real_rows() -> None:
    runtime = _PhaseRuntime()
    runtime.simulation_count = 0

    def _count(_task_id: str) -> int:
        return runtime.simulation_count

    runtime._real_simulation_result_count = _count  # type: ignore[method-assign]
    empty = run_emulation_informed_investigation(runtime, "task-1")
    assert empty == []
    assert "reverify" not in runtime.calls
    assert "saturated" not in runtime.calls

    runtime.calls.clear()
    runtime.simulation_count = 0

    def _emu(_task_id: str) -> list[str]:
        runtime.simulation_count = 1
        runtime.calls.append("emu")
        return ["dispatched"]

    runtime._run_post_static_emulation = _emu  # type: ignore[method-assign]
    continued = run_emulation_informed_investigation(runtime, "task-1")
    assert runtime.calls == ["emu", "reverify", "saturated"]
    assert continued == ["dispatched", "sat"]

    runtime.calls.clear()
    runtime.simulation_count = 0
    one_loop = run_emulation_informed_investigation(runtime, "task-1", saturated=False)
    assert runtime.calls == ["emu", "reverify", ("loop", "coverage")]
    assert one_loop == ["dispatched"]


def test_persist_skip_keeps_recovery_tools_and_cancels_leftover_trace() -> None:
    trace = ActionSpec(
        id="queued-trace",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    recover = ActionSpec(
        id="queued-arg",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"api": "CryptDecrypt"},
    )
    emu = ActionSpec(
        id="queued-emu",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    kept = keep_recovery_after_persist_skip((trace, recover, emu))
    assert [item.id for item in kept] == ["queued-arg", "queued-emu"]

    model_trace = ActionSpec(
        id="model-xrefs",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
        provenance={"origin": "model"},
    )
    kept_model = keep_recovery_after_persist_skip((trace, model_trace))
    assert [item.id for item in kept_model] == ["model-xrefs"]
    assert action_is_model_or_human(model_trace) is True

    queued_trace = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.GET_CALLEES.value,
        error=None,
        finished_at=None,
    )
    queued_arg = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.TRACE_API_ARGUMENT.value,
        error=None,
        finished_at=None,
    )
    queued_emu = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.CONTROLLED_EMULATE.value,
        error=None,
        finished_at=None,
    )
    supersede_queued_trace_after_persist_skip(
        (queued_trace, queued_arg, queued_emu),
        thread_id="thread-decode",
    )
    assert queued_trace.status == "CANCELLED"
    assert queued_trace.error == PERSIST_SKIP_TRACE_ERROR
    assert queued_arg.status == "QUEUED"
    assert queued_emu.status == "QUEUED"


def test_closed_ledger_stops_without_another_loop() -> None:
    runtime = _PhaseRuntime(
        [{"id": "thread-done", "status": LEDGER_CLOSED, "next_method": ""}]
    )
    assert run_saturated_investigation(runtime, "task-1") == []
    assert runtime.calls == []


class _PersistMint:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.ready: object | None = None
        self.boundary: object | None = None
        self.unique: object | None = None
        self.supporting: object = SimpleNamespace(gate=SimpleNamespace(missing=()))

    def seed_result(self, **kwargs: object) -> object | None:
        del kwargs
        self.calls.append("seed")
        return self.ready

    def static_boundary(self, **kwargs: object) -> object | None:
        del kwargs
        self.calls.append("boundary")
        return self.boundary

    def unique_thread(self, **kwargs: object) -> object | None:
        del kwargs
        self.calls.append("unique")
        return self.unique

    def supporting_boundary(self, **kwargs: object) -> object | None:
        del kwargs
        self.calls.append("supporting")
        return self.supporting

    def resolve(
        self,
        *,
        playbook: object | None = None,
        cluster_category: str = "process",
        model_actions_only: bool = False,
        proposed_actions: tuple[object, ...] = (),
        historical_attempts: int = 0,
    ):
        from threat_report_agent.investigation.loop_path import resolve_persist_how_skip

        return resolve_persist_how_skip(
            playbook=playbook,
            evidence=(),
            thread_id="thread-1",
            artifact_id="artifact-1",
            cluster_category=cluster_category,
            model_actions_only=model_actions_only,
            proposed_actions=proposed_actions,
            historical_attempts=historical_attempts,
            seed_result=self.seed_result,
            static_boundary=self.static_boundary,
            unique_thread=self.unique_thread,
            supporting_boundary=self.supporting_boundary,
        )


def test_persist_how_ready_skips_mining_when_playbook_is_present() -> None:
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    decision = mint.resolve(playbook=playbook)
    assert decision.disposition == PERSIST_HOW_READY
    assert decision.result is mint.ready
    assert mint.calls == ["seed"]


def test_a_zero_cost_round_still_mines_and_never_fabricates_persist_ready() -> None:
    """P3.7: the retired `persist_zero_cost` shortcut, asserted as BEHAVIOUR on `resolve_persist_how_skip`.

    The shortcut read `not model_actions_only and not proposed_actions` - "nothing was proposed, so this
    round is free / persist-ready". Both calls below ARE that shape. The first shows the mining is still
    ATTEMPTED (a shortcut would skip it and call the round free); the second shows an unsatisfied gate is not
    upgraded to a skip. Only a gate that accepts may return READY.
    """
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_MINE, PERSIST_HOW_READY

    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")

    satisfied = _PersistMint()
    satisfied.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    ready = satisfied.resolve(playbook=playbook, model_actions_only=False, proposed_actions=())
    assert ready.disposition == PERSIST_HOW_READY
    assert satisfied.calls == ["seed"], (
        "a round with no proposed actions skipped the persist-HOW mining: the retired `persist_zero_cost` "
        f"shortcut is back (calls={satisfied.calls!r})"
    )

    unsatisfied = _PersistMint()
    mined = unsatisfied.resolve(playbook=playbook, model_actions_only=False, proposed_actions=())
    assert mined.disposition == PERSIST_HOW_MINE, (
        "an unsatisfied persist gate was turned into a persist skip: a zero-cost shortcut is treating an "
        "empty proposal list as persist-ready"
    )
    assert unsatisfied.calls == ["seed", "boundary"], (
        f"the mining was not attempted before the skip was decided: {unsatisfied.calls!r}"
    )


def test_persist_how_does_not_call_seed_without_playbook() -> None:
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_MINE

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    decision = mint.resolve(playbook=None, cluster_category="process")
    assert decision.disposition == PERSIST_HOW_MINE
    assert "seed" not in mint.calls
    assert mint.calls == ["unique"]


def test_unique_thread_persist_runs_before_supporting_skip() -> None:
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.unique = SimpleNamespace(gate=SimpleNamespace(missing=()))
    decision = mint.resolve(playbook=None, cluster_category="persistence")
    assert decision.disposition == PERSIST_HOW_READY
    assert getattr(decision.playbook, "id", "") == "unique-os-thread"
    assert mint.calls == ["unique"]
    assert "supporting" not in mint.calls


def test_supporting_keyword_seed_skips_trace_when_unique_thread_absent() -> None:
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_BOUNDARY

    mint = _PersistMint()
    decision = mint.resolve(playbook=None, cluster_category="entrypoint")
    assert decision.disposition == PERSIST_HOW_BOUNDARY
    assert mint.calls == ["unique", "supporting"]


def test_model_origin_and_recovery_gaps_cancel_persist_ready() -> None:
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_MINE
    from threat_report_agent.investigation import ActionSpec, ActionType

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    model_action = ActionSpec(
        id="model-xrefs",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-1",
        hypothesis_id="hyp-1",
        artifact_id="artifact-1",
        provenance={"origin": "model"},
    )
    decision = mint.resolve(playbook=playbook, proposed_actions=(model_action,))
    assert decision.disposition == PERSIST_HOW_MINE

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=("cipher/data",)))
    decode = SimpleNamespace(id="xor-config-recovery", mechanism_type="DECODE_CONFIG")
    decision = mint.resolve(playbook=decode)
    assert decision.disposition == PERSIST_HOW_MINE


def test_dead_letter_attempts_force_static_boundary() -> None:
    from threat_report_agent.investigation.loop_path import (
        PERSIST_HOW_BOUNDARY,
        PERSIST_HOW_MINE,
        SLOT_DEAD_LETTER_ATTEMPTS,
    )

    mint = _PersistMint()
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    open_slot = mint.resolve(playbook=playbook, historical_attempts=0)
    assert open_slot.disposition == PERSIST_HOW_MINE
    assert mint.calls == ["seed", "boundary"]

    mint = _PersistMint()
    dead = mint.resolve(playbook=playbook, historical_attempts=SLOT_DEAD_LETTER_ATTEMPTS)
    assert dead.disposition == PERSIST_HOW_BOUNDARY
    assert mint.calls.count("boundary") == 2
    assert "supporting" in mint.calls


def test_investigation_loop_resolves_persist_how_before_budget_or_planner() -> None:
    from threat_report_agent.investigation.loop_path import (
        LOOP_PATH_BUDGET_DEFER,
        LOOP_PATH_PERSIST_BOUNDARY,
        LOOP_PATH_PERSIST_READY,
        LOOP_PATH_PLANNER,
        PERSIST_HOW_BOUNDARY,
        PERSIST_HOW_MINE,
        PERSIST_HOW_READY,
        PersistHowDecision,
        next_investigation_loop_path,
    )

    ready = PersistHowDecision(PERSIST_HOW_READY, object(), None)
    boundary = PersistHowDecision(PERSIST_HOW_BOUNDARY, object(), None)
    mine = PersistHowDecision(PERSIST_HOW_MINE, None, None)
    assert next_investigation_loop_path(ready, budget_exhausted=True) == LOOP_PATH_PERSIST_READY
    assert next_investigation_loop_path(boundary, budget_exhausted=True) == LOOP_PATH_PERSIST_BOUNDARY
    assert next_investigation_loop_path(mine, budget_exhausted=True) == LOOP_PATH_BUDGET_DEFER
    assert next_investigation_loop_path(mine, budget_exhausted=False) == LOOP_PATH_PLANNER
    # P3.7: the two `persist_zero_cost` NEGATIVE guards that used to stand here - one against this function,
    # one against `resolve_persist_how_skip` - are replaced by the behaviour they named. The retired shortcut
    # treated "nothing was proposed" as a zero-cost route to the persist-ready branch. `mine` IS that shape
    # (no mined result at all), so the two properties below are what a reintroduced shortcut breaks: it could
    # never reach the persist-ready branch at any budget, and the budget alone decides DEFER vs PLANNER.
    reached = {
        budget: next_investigation_loop_path(mine, budget_exhausted=budget)
        for budget in (True, False)
    }
    assert LOOP_PATH_PERSIST_READY not in reached.values(), (
        "a decision carrying no mined result was routed to the persist-ready branch: the retired "
        f"`persist_zero_cost` shortcut is back ({reached!r})"
    )
    assert reached == {
        True: LOOP_PATH_BUDGET_DEFER,
        False: LOOP_PATH_PLANNER,
    }, f"the budget no longer decides defer-vs-planner for an unmined seed: {reached!r}"


def test_investigation_loop_defers_an_unmined_seed_once_the_budget_is_spent(
    test_settings,
) -> None:
    """P3.7: the loop's own routing, as behaviour - it consults the loop-path decision, not a cost guess.

    Replaces the last two `getsource` guards on the loop body (`"next_investigation_loop_path" in` it, and
    the `persist_zero_cost` NEGATIVE). `persist_zero_cost` read `not model_actions_only and not
    proposed_actions`, i.e. "a round that proposed nothing is zero-cost, so do NOT defer it". This fixture is
    exactly that shape and the budget is spent by an earlier seed IN THE SAME invocation, so the two
    behaviours differ observably: the retired shortcut mined the seed, while the loop-path decision must
    leave it DEFERRED with `INVESTIGATION_BUDGET_EXHAUSTED` so a later bounded pass can close it.
    """
    from dataclasses import replace

    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings, environment="development", investigation_task_max_actions=1
    )
    database = Database(settings.database_url)
    service = AnalysisService(
        settings, database, LocalContentStore(settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("loop budget deferral")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="5" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/loop-budget-deferral",
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-budget-deferral",
            task_id=task.id,
            content_sha256="5" * 64,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                id="create-process-trace",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="api_argument_trace",
                nature="STATIC_DERIVED",
                value={"api": "CreateProcessW", "command": "cmd.exe"},
                anchor={"function_entry": "0x401000"},
            )
        )
        session.add(
            Evidence(
                id="func-entry",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function",
                nature="STATIC_DERIVED",
                value={"entry": "0x401000"},
                anchor={"function_entry": "0x401000"},
            )
        )
        session.add(
            Evidence(
                id="thread-context",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_DERIVED",
                value={"entry": "0x401000"},
                anchor={"function_entry": "0x401000"},
            )
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                # A CreateProcess trace WITHOUT the creation flags: the persist-time seed
                                # gate cannot close on it, so this seed is MINE and must be planned.
                                "id": "process-cluster",
                                "category": "process",
                                "question": "How is the child process created?",
                                "evidence_ids": ["create-process-trace", "func-entry"],
                            },
                            {
                                "id": "thread-cluster",
                                "category": "thread",
                                "question": "Which thread start is recovered?",
                                "evidence_ids": ["thread-context"],
                            },
                        ]
                    }
                },
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    limitations = service._run_investigation_loop(task_id)

    snapshot = service.task_view(task_id)["strategy_snapshot"]["investigation"]
    ledger = [dict(item) for item in (snapshot.get("work_ledger") or [])]
    deferred = [
        item
        for item in ledger
        if str(item.get("status") or "").upper() == "DEFERRED"
        and str(item.get("reason") or "").upper() == "INVESTIGATION_BUDGET_EXHAUSTED"
    ]
    assert deferred, (
        "no seed was left DEFERRED after the invocation budget was spent; the loop either ignored the "
        "loop-path decision or treated the round as zero-cost. "
        f"ledger={ledger!r} runtime={(snapshot.get('runtime') or {}).get('events')!r} "
        f"limitations={limitations!r} artifact={artifact_id}"
    )
    # Positive control: the deferral must be BECAUSE the invocation budget was spent (the loop's own
    # `action_budget` projection must read used == limit == 1). If an earlier seed stops charging the action
    # it attempted, the budget never becomes exhausted and this fails instead of the test passing because
    # the seed was unmined for some other reason.
    budget = dict(snapshot.get("action_budget") or {})
    assert (budget.get("scope"), budget.get("limit"), budget.get("used")) == ("invocation", 1, 1), (
        f"the seed was deferred without the invocation budget being spent: action_budget={budget!r}"
    )
    # Anchored a second time on the phase the budget-defer branch records. The reason string alone is also
    # written when an over-budget ACTION is parked (a different branch that never consults the loop-path
    # decision), so this is what keeps the assertion specific to the deferral of the SEED.
    runtime_events = (snapshot.get("runtime") or {}).get("events") or []
    assert any(
        str(event.get("phase") or "") == "budget_deferred"
        and str(event.get("thread_id") or "") in {str(item.get("thread_id")) for item in deferred}
        for event in runtime_events
    ), (
        "the deferred seed was not recorded in the runtime projection as `budget_deferred`: "
        f"events={runtime_events!r}"
    )


def test_persist_how_is_not_ready_while_recoverable_gaps_remain() -> None:
    """G0 §4.3：命中线程缺镜像内可恢复槽时，不得因已写出 CANDIDATE HOW 就 skip。

    只有 missing 为空（真正没有待恢复槽）才允许 READY。
    """
    from threat_report_agent.investigation.loop_path import (
        PERSIST_HOW_MINE,
        PERSIST_HOW_READY,
    )

    for gap in (
        "consumer",
        "unknown(consumer)",
        "creation_flags",
        "start_routine",
        "plaintext",
        "join",
        "parent identity",
    ):
        mint = _PersistMint()
        mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=(gap,)))
        playbook = SimpleNamespace(id="xor-config-recovery", mechanism_type="DECODE_CONFIG")
        decision = mint.resolve(playbook=playbook)
        assert decision.disposition != PERSIST_HOW_READY, gap
        assert decision.disposition == PERSIST_HOW_MINE, gap


def test_persist_how_ready_still_allowed_when_no_recoverable_gap() -> None:
    """G0 §4.3：无缺口的 TRACE 仍可取消，避免聊天要求「再深入」时刷无关动作。"""
    from threat_report_agent.investigation.loop_path import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    decision = mint.resolve(playbook=playbook)
    assert decision.disposition == PERSIST_HOW_READY


def test_the_loop_path_cluster_lives_in_its_new_module_and_keeps_its_behaviour() -> None:
    """P3.3 layer item 1: the cluster is DEFINED in `investigation/loop_path.py` and re-exported, not re-declared.

    MEASURED, and this pins a defect that actually shipped into a draft of the move: the extractor's span started at
    `node.lineno` - the `class` keyword - so `@dataclass(frozen=True)` was left behind in the source module (where it
    re-bound onto the next statement, see the sibling test) and `PersistHowDecision` became a plain class whose
    construction raised `TypeError: PersistHowDecision() takes no arguments`. Nine tests in this file failed and NO
    structural gate saw it: `compileall` is happy, the import graph is happy, the behaviour probe says UNCHANGED, and the
    text comparison of the move is byte-identical apart from exactly the line that comparison could not look at.

    The pins here are deliberately PUBLIC behaviour (`is_dataclass`, construction, frozen assignment) rather than
    private CPython internals such as `__dataclass_params__`: plan 3.3 line 154 keeps private members out of the test
    interface, and the frozen assertion below fails just as loudly without them.
    """
    import dataclasses

    from threat_report_agent.investigation import loop_path
    from threat_report_agent.task import analysis_task_orchestration as task

    # 1. the implementation lives in the new module, at module level, and the old path RE-EXPORTS the same object
    assert loop_path.__file__.replace("\\", "/").endswith("investigation/loop_path.py")
    home = ast.parse(Path(loop_path.__file__).read_text(encoding="utf-8"))
    defined = {
        node.name
        for node in home.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    } | {
        target.id
        for node in home.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    missing = sorted(set(LOOP_PATH_CLUSTER) - defined)
    assert not missing, f"these names are no longer defined in investigation/loop_path.py: {missing}"
    for name in LOOP_PATH_CLUSTER:
        assert getattr(task, name) is getattr(loop_path, name), f"{name} is not one object behind both paths"

    # 2. and the decoration travelled WITH the body
    assert dataclasses.is_dataclass(loop_path.PersistHowDecision)
    decision = loop_path.PersistHowDecision(loop_path.PERSIST_HOW_MINE, None, None)
    assert (decision.disposition, decision.result, decision.playbook) == (loop_path.PERSIST_HOW_MINE, None, None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.disposition = loop_path.PERSIST_HOW_READY


def test_the_task_module_has_no_top_level_decorator_left_behind() -> None:
    """The other half of the same defect, and the GENERAL form of it: a decorator left behind does not vanish, it
    decorates the NEXT statement.

    MEASURED on the defective draft: `@dataclass(frozen=True)` landed on `class AnalysisTaskRuntime(Protocol)` - a
    Protocol silently became a frozen dataclass, in a statement the move was not allowed to touch.

    MEASURED after the move: this module has ZERO decorated top-level statements, so ANY decorator appearing at module
    level is either a deliberate new decision (update this pin and say why) or a move that left one behind. That is the
    point of asserting the set rather than one landing site: the first version of this test only checked
    `AnalysisTaskRuntime`, so a decorator dragged anywhere else would have passed it.
    """
    import ast
    import dataclasses
    from pathlib import Path
    from typing import Protocol

    from threat_report_agent.task import analysis_task_orchestration as task

    tree = ast.parse(Path(task.__file__).read_text(encoding="utf-8"))
    decorated = [
        getattr(node, "name", "?")
        for node in tree.body
        if getattr(node, "decorator_list", None)
    ]
    assert not decorated, (
        f"top-level statements in the task module are decorated: {decorated}; this module had none after P3.3 layer "
        f"item 1 moved the loop-path cluster out, so a decorator here is most likely one that was left behind"
    )
    assert issubclass(task.AnalysisTaskRuntime, Protocol)
    assert not dataclasses.is_dataclass(task.AnalysisTaskRuntime)
