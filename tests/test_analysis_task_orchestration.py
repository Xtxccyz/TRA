from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.analysis_task_orchestration import (
    PERSIST_SKIP_TRACE_ERROR,
    action_is_model_or_human,
    continue_investigation_after_action,
    keep_recovery_after_persist_skip,
    run_analysis_task_investigation,
    run_emulation_informed_investigation,
    run_saturated_investigation,
    supersede_queued_trace_after_persist_skip,
)
from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.investigation.investigation_ledger import LEDGER_CLOSED, LEDGER_DEFERRED, LEDGER_OPEN


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
        from threat_report_agent.analysis_task_orchestration import resolve_persist_how_skip

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
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    decision = mint.resolve(playbook=playbook)
    assert decision.disposition == PERSIST_HOW_READY
    assert decision.result is mint.ready
    assert mint.calls == ["seed"]


def test_persist_how_does_not_call_seed_without_playbook() -> None:
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_MINE

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    decision = mint.resolve(playbook=None, cluster_category="process")
    assert decision.disposition == PERSIST_HOW_MINE
    assert "seed" not in mint.calls
    assert mint.calls == ["unique"]


def test_unique_thread_persist_runs_before_supporting_skip() -> None:
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.unique = SimpleNamespace(gate=SimpleNamespace(missing=()))
    decision = mint.resolve(playbook=None, cluster_category="persistence")
    assert decision.disposition == PERSIST_HOW_READY
    assert getattr(decision.playbook, "id", "") == "unique-os-thread"
    assert mint.calls == ["unique"]
    assert "supporting" not in mint.calls


def test_supporting_keyword_seed_skips_trace_when_unique_thread_absent() -> None:
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_BOUNDARY

    mint = _PersistMint()
    decision = mint.resolve(playbook=None, cluster_category="entrypoint")
    assert decision.disposition == PERSIST_HOW_BOUNDARY
    assert mint.calls == ["unique", "supporting"]


def test_model_origin_and_recovery_gaps_cancel_persist_ready() -> None:
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_MINE
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
    from threat_report_agent.analysis_task_orchestration import (
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
    import inspect

    from threat_report_agent.analysis_task_orchestration import (
        LOOP_PATH_BUDGET_DEFER,
        LOOP_PATH_PERSIST_BOUNDARY,
        LOOP_PATH_PERSIST_READY,
        LOOP_PATH_PLANNER,
        PERSIST_HOW_BOUNDARY,
        PERSIST_HOW_MINE,
        PERSIST_HOW_READY,
        PersistHowDecision,
        next_investigation_loop_path,
        resolve_persist_how_skip,
    )
    from threat_report_agent.service import AnalysisService

    ready = PersistHowDecision(PERSIST_HOW_READY, object(), None)
    boundary = PersistHowDecision(PERSIST_HOW_BOUNDARY, object(), None)
    mine = PersistHowDecision(PERSIST_HOW_MINE, None, None)
    assert next_investigation_loop_path(ready, budget_exhausted=True) == LOOP_PATH_PERSIST_READY
    assert next_investigation_loop_path(boundary, budget_exhausted=True) == LOOP_PATH_PERSIST_BOUNDARY
    assert next_investigation_loop_path(mine, budget_exhausted=True) == LOOP_PATH_BUDGET_DEFER
    assert next_investigation_loop_path(mine, budget_exhausted=False) == LOOP_PATH_PLANNER

    loop_source = inspect.getsource(AnalysisService._run_investigation_loop)
    assert "next_investigation_loop_path" in loop_source
    assert "persist_zero_cost = not model_actions_only and not proposed_actions" not in loop_source
    assert "persist_zero_cost" not in inspect.getsource(next_investigation_loop_path)
    assert "persist_zero_cost" not in inspect.getsource(resolve_persist_how_skip)


def test_persist_how_is_not_ready_while_recoverable_gaps_remain() -> None:
    """G0 §4.3：命中线程缺镜像内可恢复槽时，不得因已写出 CANDIDATE HOW 就 skip。

    只有 missing 为空（真正没有待恢复槽）才允许 READY。
    """
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_MINE, PERSIST_HOW_READY

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
    from threat_report_agent.analysis_task_orchestration import PERSIST_HOW_READY

    mint = _PersistMint()
    mint.ready = SimpleNamespace(gate=SimpleNamespace(missing=()))
    playbook = SimpleNamespace(id="process-execution", mechanism_type="PROCESS_EXECUTION")
    decision = mint.resolve(playbook=playbook)
    assert decision.disposition == PERSIST_HOW_READY
