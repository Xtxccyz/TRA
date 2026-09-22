"""The investigation loop must *converge*, not grind.

Measured defect (storm task ``e53de9f7``): 144 executed actions over 15.5 min
covering only 81 distinct ``(action_type, target)`` pairs; 46 of them returned
``gain_class=REUSED_CONTEXT`` with ``evidence_delta=0`` (the query was already
answerable from the ledger), and one thread recorded 26
``investigation.stalled`` events and then kept running for another 76 actions.
Live task ``45cbd992`` sat at ~100% CPU for 20+ minutes inside a single
``_run_investigation_loop`` invocation with no durable rows.

These tests assert on **convergence**, never on wall-clock time:

* an action whose input evidence is unchanged is not re-executed;
* a corpus that yields no new evidence reaches a terminal state within a
  bounded number of action selections and records a stall/limitation;
* the ordered set of *useful* action keys produced for a fixed corpus is
  unchanged by the fix (oracle-differential against the non-retiring
  behaviour);
* a thread whose durable convergence record says STALLED is not re-worked.

They are deliberately cheap: no database, no model, no wall-clock budgets.
"""

from __future__ import annotations

from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    InvestigationLoopDriver,
    InvestigationThreadState,
)
from threat_report_agent.investigation.investigation_ledger import completion_allows_stop
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    InvestigationHypothesisRecord,
    InvestigationActionRecord,
    InvestigationThreadRecord,
    ToolRun,
)
from threat_report_agent.service import AnalysisService

THREAD_ID = "thread-convergence"
HYPOTHESIS_ID = "hyp-convergence"
ARTIFACT_ID = "artifact-convergence"
QUESTION = "Which evidence explains the artifact's highest-risk static mechanism?"
STATEMENT = (
    "The artifact may contain an ordered process, loading, decode, network, "
    "or evasion mechanism."
)


def _action(
    action_id: str,
    action_type: ActionType,
    target: str,
    *,
    scope: str,
    priority: int = 10,
) -> ActionSpec:
    return ActionSpec(
        id=action_id,
        action_type=action_type,
        thread_id=THREAD_ID,
        hypothesis_id=HYPOTHESIS_ID,
        artifact_id=ARTIFACT_ID,
        priority=priority,
        reason=f"probe {scope}",
        target_selector={"target": target},
        expected_evidence_kinds=("bytes_read",),
        plan={"mechanism_type": scope},
    )


def _seed_row() -> dict[str, object]:
    return {
        "id": "ev-seed",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "sub_1000", "function_entry": "0x1000"},
        "anchor": {"function_entry": "0x1000"},
    }


def _run(
    *,
    proposed: tuple[ActionSpec, ...],
    produced_for,
    initial=(),
    max_steps: int = 16,
    allow_investigator_actions: bool = False,
) -> tuple[list[dict[str, object]], object]:
    """Drive one thread; return the executed-action log and the result."""
    executed: list[dict[str, object]] = []
    driver = InvestigationLoopDriver(max_steps=max_steps)

    def execute(action: ActionSpec):
        rows = produced_for(action)
        executed.append(
            {
                "method_id": driver._semantic_method_key(action),
                "scope": str(dict(action.plan).get("mechanism_type") or ""),
                "target": dict(action.target_selector).get("target"),
                "reused": bool(rows) and all(row.get("reused") for row in rows),
            }
        )
        return rows

    result = driver.run_until_converged(
        thread_id=THREAD_ID,
        artifact_id=ARTIFACT_ID,
        question=QUESTION,
        hypothesis_id=HYPOTHESIS_ID,
        hypothesis_statement=STATEMENT,
        initial_evidence=initial or (_seed_row(),),
        execute=execute,
        proposed_actions=proposed,
        allow_investigator_actions=allow_investigator_actions,
        max_rounds=4,
        max_total_steps=max_steps,
    )
    return executed, result


def _reuse_executor(store: dict[tuple[str, str], dict[str, object]]):
    """First query for a (action_type, target) mints a row; later ones reuse it.

    The service keys reuse on ``(kind, nature, value, anchor)`` and every
    action type emits its own ``kind``, so a repeat of the *same*
    ``(action_type, target)`` - which is what a scope-relabelled duplicate is -
    is the only thing that can collide.
    """

    def produced_for(action: ActionSpec) -> list[dict[str, object]]:
        target = str(dict(action.target_selector).get("target") or "")
        key = (action.action_type.value, target)
        existing = store.get(key)
        if existing is None:
            kind = f"{action.action_type.value.casefold()}_row"
            existing = {
                "id": f"ev-{len(store)}",
                "kind": kind,
                "nature": "STATIC_OBSERVED",
                "value": {"target": target},
                "anchor": {"function_entry": target},
            }
            store[key] = existing
            return [dict(existing)]
        return [{**existing, "reused": True}]

    return produced_for


def _novel_executor():
    """Every query mints a fresh row, so nothing is ever retired."""

    def produced_for(action: ActionSpec) -> list[dict[str, object]]:
        target = str(dict(action.target_selector).get("target") or "")
        return [
            {
                "id": f"ev-{action.id}",
                "kind": f"{action.action_type.value.casefold()}_row",
                "nature": "STATIC_OBSERVED",
                "value": {"target": target, "nonce": action.id},
                "anchor": {"function_entry": target, "investigation_action_id": action.id},
            }
        ]

    return produced_for


def test_scope_relabelled_duplicate_of_a_retired_method_is_not_executed() -> None:
    """A no-gain method must not re-run because a sibling scope queued it.

    ``_derive_investigation_observations`` never reads ``action.plan``, so the
    three probes below are the same physical query under three mechanism
    scopes.  The first two executions are honest - the first mints evidence and
    the second is what *discovers* that the query is now already answered - but
    the third must not run at all.
    """
    produced_for = _reuse_executor({})
    executed, result = _run(
        proposed=(
            _action("q:1", ActionType.READ_BYTES, "0x1000", scope="alpha", priority=5),
            _action("q:2", ActionType.READ_BYTES, "0x1000", scope="beta", priority=6),
            _action("q:3", ActionType.READ_BYTES, "0x1000", scope="gamma", priority=7),
        ),
        produced_for=produced_for,
    )
    assert [item["scope"] for item in executed] == ["alpha", "beta"]
    assert [item["reused"] for item in executed] == [False, True]
    assert [event.phase for event in result.events].count("no_new_evidence") == 1


def test_dry_corpus_converges_within_a_bounded_number_of_action_selections() -> None:
    """A corpus that yields no new evidence must reach a terminal state.

    The loop may select each distinct method once plus the one confirmation
    that proves the query is already answered; it must not keep re-selecting
    the same frontier merely because a later mechanism scope re-labels it.
    """
    scopes = ("alpha", "beta", "gamma", "delta", "epsilon")
    proposed = tuple(
        _action(
            f"q:{index}",
            ActionType.READ_BYTES,
            "0x1000",
            scope=scope,
            priority=5 + index,
        )
        for index, scope in enumerate(scopes)
    )
    produced_for = _reuse_executor({})
    executed, result = _run(proposed=proposed, produced_for=produced_for, max_steps=16)

    assert len(executed) == 2, executed
    assert result.thread_state in {
        InvestigationThreadState.UNKNOWN,
        InvestigationThreadState.CLAIM_READY,
    }
    # The no-gain result is recorded, not silently dropped: the loop keeps an
    # auditable autopsy for the method it retired.
    phases = [event.phase for event in result.events]
    assert phases.count("no_new_evidence") == 1
    assert phases.count("no_new_evidence_autopsy") == 1


def test_useful_action_key_set_for_a_fixed_corpus_is_unchanged() -> None:
    """Oracle-differential: retirement must not change *which* methods run.

    Two drivers see the identical proposed frontier and evidence.  One executor
    always returns novel rows (so nothing is ever retired, which is the
    pre-fix behaviour of an always-reused frontier); the other returns the
    already-present row for a repeat.  The ordered list of distinct semantic
    method ids executed must be identical - the fix removes duplicate
    executions, never a useful action.
    """
    proposed = (
        _action("q:1", ActionType.READ_BYTES, "0x1000", scope="alpha", priority=5),
        _action("q:2", ActionType.READ_BYTES, "0x1000", scope="beta", priority=6),
        _action("q:3", ActionType.READ_BYTES, "0x1000", scope="gamma", priority=7),
        _action("q:4", ActionType.GET_CFG_SLICE, "0x1000", scope="alpha", priority=8),
        _action("q:5", ActionType.GET_CFG_SLICE, "0x2000", scope="alpha", priority=9),
        _action("q:6", ActionType.GET_DECOMPILE, "0x2000", scope="delta", priority=10),
    )

    novel, _ = _run(proposed=proposed, produced_for=_novel_executor())
    reused, _ = _run(proposed=proposed, produced_for=_reuse_executor({}))

    def ordered_methods(log: list[dict[str, object]]) -> list[str]:
        return list(dict.fromkeys(str(item["method_id"]) for item in log))

    def ordered_targets(log: list[dict[str, object]]) -> list[object]:
        seen: dict[str, object] = {}
        for item in log:
            seen.setdefault(str(item["method_id"]), item["target"])
        return list(seen.values())

    assert ordered_methods(novel) == ordered_methods(reused)
    assert ordered_targets(novel) == ordered_targets(reused)
    assert len(reused) < len(novel)
    # Every method that ran at all is still the same method identity.
    assert {item["method_id"] for item in reused} == {item["method_id"] for item in novel}


def test_reused_rows_are_not_re_appended_to_the_frontier(monkeypatch) -> None:
    """A reused observation must not add a second payload copy.

    The frontier a round hands to the next one is already collapsed by id, so a
    re-appended copy is invisible in the final result but not in the scans that
    happen *inside* the round: every ``propose``/``evaluate`` pass costs
    ~0.12/0.22 s per MB of accumulated value text, and the loop's own
    decompile/CFG/pcode payloads are the bulk of it.
    """
    sizes: list[list[object]] = []
    original = InvestigationLoopDriver._evaluate_gate

    def spy(self, evidence, question, statement):  # noqa: ANN001
        sizes.append([row.get("id") for row in evidence])
        return original(self, evidence, question, statement)

    monkeypatch.setattr(InvestigationLoopDriver, "_evaluate_gate", spy)
    produced_for = _reuse_executor({})
    executed, _ = _run(
        proposed=(
            _action("q:1", ActionType.READ_BYTES, "0x1000", scope="alpha", priority=5),
            _action("q:2", ActionType.READ_BYTES, "0x1000", scope="beta", priority=6),
            _action("q:3", ActionType.READ_BYTES, "0x1000", scope="gamma", priority=7),
        ),
        produced_for=produced_for,
        max_steps=8,
    )
    assert [item["reused"] for item in executed] == [False, True]
    assert sizes, "the gate must have been evaluated over the frontier"
    for observed in sizes:
        assert len(observed) == len(set(observed)), f"duplicated frontier rows: {observed}"
        assert observed.count("ev-0") <= 1, f"reused row appended again: {observed}"


def _stalled_snapshot(thread_id: str) -> dict[str, object]:
    return {
        "threads": [
            {
                "id": thread_id,
                "artifact_id": ARTIFACT_ID,
                "question": QUESTION,
            }
        ],
        "convergence": {
            thread_id: {
                "thread_id": thread_id,
                "status": "STALLED",
                "intervention": "STATIC_BOUNDARY",
                "method_ids": ["READ_BYTES:deadbeefdeadbeef"],
                "no_gain_method_ids": ["READ_BYTES:deadbeefdeadbeef"],
                "no_gain_streak": 2,
                "distinct_no_gain_methods": 2,
                "frontier_fingerprint": "0" * 64,
                "last_method_id": "READ_BYTES:deadbeefdeadbeef",
                "last_gain_class": "REUSED_CONTEXT",
            }
        },
        "work_ledger": [
            {
                "id": thread_id,
                "thread_id": thread_id,
                "artifact_id": ARTIFACT_ID,
                "question": QUESTION,
                "seed_kind": "artifact_triage",
                "status": "OPEN",
            }
        ],
    }


def _build_stalled_task(test_settings) -> tuple[Database, AnalysisService, str]:
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    blob = store.put(b"MZ" + b"\0" * 64)
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-stalled-skip", title="Stalled skip"))
        session.add(
            ContentBlob(
                sha256=blob.sha256,
                size=blob.size,
                media_type="application/octet-stream",
                storage_key=blob.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(
            case_id="case-stalled-skip",
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": _stalled_snapshot(THREAD_ID),
                "seed_maps": {},
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id=ARTIFACT_ID,
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="pe-parser",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                id="seed-context",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={"name": "sub_1000", "function_entry": "0x1000"},
                anchor={"function_entry": "0x1000"},
            )
        )
        session.add(
            InvestigationThreadRecord(
                id=THREAD_ID,
                task_id=task.id,
                artifact_id=artifact.id,
                question=QUESTION,
            )
        )
        session.flush()
        session.add(
            InvestigationHypothesisRecord(
                id=HYPOTHESIS_ID,
                task_id=task.id,
                thread_id=THREAD_ID,
                statement=STATEMENT,
                dimension="mechanism_discovery",
            )
        )
        session.flush()
        task_id = task.id
    return database, service, task_id


def _ledger_status(database: Database, task_id: str, thread_id: str) -> str:
    with database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        assert task is not None
        snapshot = dict(task.strategy_snapshot or {}).get("investigation", {})
        for item in snapshot.get("work_ledger") or []:
            if str(item.get("id")) == thread_id:
                return str(item.get("status") or "")
    return ""


def test_recorded_stall_is_not_replayed_and_reaches_a_terminal_ledger_state(
    test_settings,
) -> None:
    """A recorded STALLED frontier must stop consuming the loop."""
    database, service, task_id = _build_stalled_task(test_settings)

    limitations = service._run_investigation_loop(task_id, ledger_phase="coverage")
    assert any("STALLED" in item for item in limitations)
    # The exhausted frontier is stamped terminal immediately: a DEFERRED item
    # would keep `completion_allows_stop` false forever.
    assert _ledger_status(database, task_id, THREAD_ID) == "UNKNOWN"
    with database.session_factory() as session:
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id
                )
            )
        )
    assert actions == []

    # Once the item is terminal the loop must not touch it again - not in a
    # tail pass, not in a later coverage pass.
    for phase in ("tail", "coverage"):
        assert service._run_investigation_loop(task_id, ledger_phase=phase) == []
        assert _ledger_status(database, task_id, THREAD_ID) == "UNKNOWN"
    with database.session_factory() as session:
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id
                )
            )
        )
        assert actions == []
        task = session.get(AnalysisTask, task_id)
        assert task is not None
        convergence = dict(task.strategy_snapshot or {}).get("investigation", {}).get(
            "convergence", {}
        )
        assert convergence[THREAD_ID]["status"] == "STALLED"
        assert task.limitations, "a stalled thread must record an honest limitation"


def test_a_stalled_ledger_is_terminal_so_the_loop_can_stop(test_settings) -> None:
    """`completion_allows_stop` is the loop's own convergence predicate."""
    database, service, task_id = _build_stalled_task(test_settings)
    service._run_investigation_loop(task_id, ledger_phase="coverage")
    with database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        assert task is not None
        ledger = (
            (task.strategy_snapshot or {}).get("investigation") or {}
        ).get("work_ledger") or []
    assert ledger, "the thread must be registered in the work ledger"
    assert completion_allows_stop(ledger)


def test_stall_skip_records_a_replay_free_audit_trail(test_settings) -> None:
    """The stall must be visible in the audit trail as *not* replayed."""
    from threat_report_agent.models import AuditEvent

    database, service, task_id = _build_stalled_task(test_settings)
    service._run_investigation_loop(task_id, ledger_phase="coverage")
    with database.session_factory() as session:
        events = list(
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.task_id == task_id,
                    AuditEvent.event_type == "investigation.stalled",
                )
            )
        )
    assert events, "the recorded stall must survive into the audit trail"
    payload = dict(events[-1].payload or {})
    assert payload.get("replayed") is False
    assert payload.get("intervention") in {"CONTROLLED_EMULATE", "STATIC_BOUNDARY"}
    assert payload.get("frontier_fingerprint") == "0" * 64
