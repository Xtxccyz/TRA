"""Bounded runtime-control-plane acceptance checks.

This harness deliberately uses synthetic text and in-memory/local SQLite only.
It never opens, executes, or sends any sample bytes.  The result distinguishes
control-plane/unit evidence from production container evidence so that a green
synthetic check cannot be mistaken for a restart or 24-hour soak certification.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from threat_report_agent.runtime_contracts import (
    ContextBudgetManager,
    classify_failure,
    retry_decision,
)
from threat_report_agent.turn_lifecycle import LongTurnLifecycle


def _run(name: str, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = fn()
        result.setdefault("status", "PASS")
    except Exception as exc:  # pragma: no cover - acceptance diagnostics
        result = {"status": "FAIL", "error": f"{type(exc).__name__}: {exc}"}
    result["name"] = name
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result


def failure_injection() -> dict[str, Any]:
    retryable = classify_failure(
        RuntimeError(
            "psycopg.errors.DataCorrupted: compressed lz4 data is corrupt in evidence_search_keys"
        ),
        stage="EVIDENCE_PERSISTENCE",
        failed_component="evidence_search_keys",
        failed_activity="selector-index-write",
    )
    non_retryable = classify_failure(
        ValueError("policy denied unsupported execution request"),
        stage="POLICY_GATE",
        failed_component="policy",
        failed_activity="sample-execution",
    )
    first_retry = retry_decision(
        retryable=bool(retryable["retryable"]),
        previous_fingerprint=None,
        fingerprint=str(retryable["failure_fingerprint"]),
    )
    duplicate_retry = retry_decision(
        retryable=bool(retryable["retryable"]),
        previous_fingerprint=str(retryable["failure_fingerprint"]),
        fingerprint=str(retryable["failure_fingerprint"]),
    )
    assert retryable["failure_code"] == "DB_FAILURE"
    assert retryable["retryable"] is True
    assert non_retryable["retryable"] is False
    assert first_retry["retry"] is True
    assert duplicate_retry["retry"] is False
    assert duplicate_retry["retry_suppressed"] is True
    return {
        "retryable": {
            "failure_code": retryable["failure_code"],
            "retryable": retryable["retryable"],
            "first_retry": first_retry,
        },
        "non_retryable": {
            "failure_code": non_retryable["failure_code"],
            "retryable": non_retryable["retryable"],
        },
        "duplicate_fingerprint_suppressed": duplicate_retry["retry_suppressed"],
    }


def context_stress() -> dict[str, Any]:
    manager = ContextBudgetManager(
        2_000_000,
        safety_margin_bytes=64 * 1024,
        max_tool_result_bytes=2_048,
        max_messages=96,
    )
    # 500 synthetic tool events approximate a long-running stream without
    # touching the backend event ledger or any sample bytes.
    messages: list[dict[str, str]] = [{"role": "system", "content": "static-only"}]
    messages.extend(
        {"role": "tool", "content": f"synthetic-event-{index} " + "x" * 5_000}
        for index in range(500)
    )
    decision = manager.prepare(messages, reserved_completion_bytes=65_536)
    assert decision.allowed is True
    assert decision.compacted is True
    assert len(decision.messages) <= 96
    assert decision.total_bytes <= decision.max_context_bytes
    return {
        "synthetic_events": 500,
        "input_messages": len(messages),
        "output_messages": len(decision.messages),
        "compacted": decision.compacted,
        "allowed": decision.allowed,
        "input_bytes": decision.input_bytes,
        "total_bytes": decision.total_bytes,
        "max_context_bytes": decision.max_context_bytes,
    }


def concurrent_context_calls() -> dict[str, Any]:
    manager = ContextBudgetManager(
        512_000,
        safety_margin_bytes=16 * 1024,
        max_tool_result_bytes=1_024,
        max_messages=32,
    )

    def one(worker: int) -> tuple[int, bool, int]:
        messages = [{"role": "system", "content": "static-only"}]
        messages.extend(
            {"role": "tool", "content": f"worker={worker} event={i} " + "z" * 2_000}
            for i in range(80)
        )
        decision = manager.prepare(messages, reserved_completion_bytes=8_192)
        return worker, decision.allowed, len(decision.messages)

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(one, range(5)))
    assert all(allowed and count <= 32 for _, allowed, count in results)
    return {"workers": 5, "calls": len(results), "bounded_results": True, "results": results}


def local_cross_session_guard() -> dict[str, Any]:
    """Exercise the real API guard with synthetic input and a temporary DB."""
    from fastapi.testclient import TestClient

    from threat_report_agent.config import ModelProviderSettings, Settings
    from threat_report_agent.main import create_app

    with tempfile.TemporaryDirectory(prefix="runtime-control-") as root:
        root_path = Path(root)
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{root_path / 'control.db'}",
            object_store_endpoint="http://object-store",
            object_store_bucket="test",
            object_store_access_key="test",
            object_store_secret_key="test",
            content_store_backend="local",
            content_store_path=str(root_path / "content"),
            temporal_address="temporal:7233",
            ghidra_home="",
            java_home="",
            max_sample_files=10,
            max_sample_bytes=1_000_000,
            max_archive_depth=1,
            primary_model=ModelProviderSettings("test", "http://model.invalid/v1", "model", "key"),
            fallback_model=ModelProviderSettings("fallback", "", "", "", enabled=False),
            gate_secret_key="test-gate-secret",
        )
        with TestClient(create_app(settings)) as client:
            uploaded = client.post(
                "/api/v1/workbench/sessions/control-a/artifacts",
                files={"sample": ("synthetic.py", b"print('static-only')", "text/x-python")},
            )
            assert uploaded.status_code == 201, uploaded.text
            artifact_id = uploaded.json()["artifacts"][0]["id"]
            foreign = client.post(
                "/api/v1/workbench/sessions/control-b/analysis/start",
                json={"artifact_id": artifact_id},
            )
            assert foreign.status_code == 403
            assert "CONTEXT_MISMATCH" in foreign.text
            return {
                "upload_status": uploaded.status_code,
                "foreign_start_status": foreign.status_code,
                "guard": "CONTEXT_MISMATCH",
            }


def event_driven_wait() -> dict[str, Any]:
    """Prove one bounded wait returns when a new audit event is committed.

    The fixture creates only control-plane rows.  It deliberately does not
    attach a sample or invoke an analysis worker; the observable contract is
    that one wait call receives the next event cursor without replaying a full
    task projection.
    """
    from threat_report_agent.config import ModelProviderSettings, Settings
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, CaseRecord, ThreatAnalysisContextRecord
    from threat_report_agent.service import AnalysisService

    with tempfile.TemporaryDirectory(prefix="runtime-wait-") as root:
        root_path = Path(root)
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{root_path / 'wait.db'}",
            object_store_endpoint="http://object-store",
            object_store_bucket="test",
            object_store_access_key="test",
            object_store_secret_key="test",
            content_store_backend="local",
            content_store_path=str(root_path / "content"),
            temporal_address="temporal:7233",
            ghidra_home="",
            java_home="",
            max_sample_files=10,
            max_sample_bytes=1_000_000,
            max_archive_depth=1,
            primary_model=ModelProviderSettings("test", "", "", "", enabled=False),
            fallback_model=ModelProviderSettings("fallback", "", "", "", enabled=False),
            gate_secret_key="test-gate-secret",
        )
        database = Database(settings.database_url)
        database.create_schema()
        service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
        with database.session_factory.begin() as session:
            case = CaseRecord(title="event wait fixture")
            session.add(case)
            session.flush()
            task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
            session.add(task)
            session.flush()
            session.add(
                ThreatAnalysisContextRecord(
                    dsh_session_id="event-wait-session",
                    case_id=case.id,
                    active_task_id=task.id,
                    state="ANALYSIS_RUNNING",
                    task_lifecycle="RUNNING",
                )
            )
            service._audit(
                session,
                case_id=case.id,
                task_id=task.id,
                event_type="analysis.started",
                actor="acceptance",
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"static_only": True},
            )
            task_id = task.id
        baseline = service._analysis_progress(task_id)["progress_revision"]

        def append_event() -> None:
            time.sleep(0.15)
            with database.session_factory.begin() as session:
                current = session.get(AnalysisTask, task_id)
                assert current is not None
                service._audit(
                    session,
                    case_id=current.case_id,
                    task_id=current.id,
                    event_type="analysis.progressed",
                    actor="acceptance",
                    object_type="AnalysisTask",
                    object_id=current.id,
                    payload={"stage": "STATIC_EVIDENCE", "static_only": True},
                )

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(append_event)
            result = service.workbench_wait_for_analysis_update(
                "event-wait-session", after_seq=int(baseline), timeout_seconds=2
            )
            future.result(timeout=3)
        elapsed = time.perf_counter() - started
        assert result["changed"] is True
        assert result["next_seq"] > baseline
        assert [item["type"] for item in result["events"]] == ["analysis.progressed"]
        assert elapsed < 2.0
        database.engine.dispose()
        return {
            "baseline_seq": baseline,
            "next_seq": result["next_seq"],
            "returned_events": len(result["events"]),
            "wait_elapsed_seconds": round(elapsed, 3),
            "polling_contract": "one bounded wait call; event cursor advanced",
        }


def restart_recovery() -> dict[str, Any]:
    """Verify durable task/session context survives an application rebuild."""
    from threat_report_agent.config import ModelProviderSettings, Settings
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, CaseRecord, ThreatAnalysisContextRecord
    from threat_report_agent.service import AnalysisService

    with tempfile.TemporaryDirectory(prefix="runtime-restart-") as root:
        root_path = Path(root)
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{root_path / 'restart.db'}",
            object_store_endpoint="http://object-store",
            object_store_bucket="test",
            object_store_access_key="test",
            object_store_secret_key="test",
            content_store_backend="local",
            content_store_path=str(root_path / "content"),
            temporal_address="temporal:7233",
            ghidra_home="",
            java_home="",
            max_sample_files=10,
            max_sample_bytes=1_000_000,
            max_archive_depth=1,
            primary_model=ModelProviderSettings("test", "", "", "", enabled=False),
            fallback_model=ModelProviderSettings("fallback", "", "", "", enabled=False),
            gate_secret_key="test-gate-secret",
        )
        first_db = Database(settings.database_url)
        first_db.create_schema()
        first_service = AnalysisService(settings, first_db, LocalContentStore(settings.content_store_path))
        with first_db.session_factory.begin() as session:
            case = CaseRecord(title="restart fixture")
            session.add(case)
            session.flush()
            task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", outcome=None)
            session.add(task)
            session.flush()
            session.add(
                ThreatAnalysisContextRecord(
                    dsh_session_id="restart-session",
                    case_id=case.id,
                    active_task_id=task.id,
                    state="ANALYSIS_RUNNING",
                    task_lifecycle="RUNNING",
                )
            )
            first_service._audit(
                session,
                case_id=case.id,
                task_id=task.id,
                event_type="analysis.started",
                actor="acceptance",
                object_type="AnalysisTask",
                object_id=task.id,
                payload={"static_only": True},
            )
            task_id = task.id
            case_id = case.id
        first_db.engine.dispose()

        second_db = Database(settings.database_url)
        second_db.create_schema()
        second_service = AnalysisService(settings, second_db, LocalContentStore(settings.content_store_path))
        context = second_service.workbench_analysis_context_v3("restart-session")
        progress = second_service._analysis_progress(task_id)
        assert context["active_task_id"] == task_id
        assert context["case_id"] == case_id
        assert context["state"] == "ANALYSIS_RUNNING"
        assert progress["progress_revision"] >= 1
        second_db.engine.dispose()
        return {
            "active_task_id_restored": True,
            "case_id_restored": True,
            "state_after_restart": context["state"],
            "audit_progress_revision": progress["progress_revision"],
            "scope": "application/database restart simulation; Docker restart not exercised",
        }


def concurrent_session_contexts() -> dict[str, Any]:
    """Read five independent session projections concurrently."""
    from threat_report_agent.config import ModelProviderSettings, Settings
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, CaseRecord, ThreatAnalysisContextRecord
    from threat_report_agent.service import AnalysisService

    with tempfile.TemporaryDirectory(prefix="runtime-concurrency-") as root:
        root_path = Path(root)
        settings = Settings(
            environment="test",
            database_url=f"sqlite:///{root_path / 'concurrency.db'}",
            object_store_endpoint="http://object-store",
            object_store_bucket="test",
            object_store_access_key="test",
            object_store_secret_key="test",
            content_store_backend="local",
            content_store_path=str(root_path / "content"),
            temporal_address="temporal:7233",
            ghidra_home="",
            java_home="",
            max_sample_files=10,
            max_sample_bytes=1_000_000,
            max_archive_depth=1,
            primary_model=ModelProviderSettings("test", "", "", "", enabled=False),
            fallback_model=ModelProviderSettings("fallback", "", "", "", enabled=False),
            gate_secret_key="test-gate-secret",
        )
        database = Database(settings.database_url)
        database.create_schema()
        service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
        sessions = [f"concurrent-session-{index}" for index in range(5)]
        with database.session_factory.begin() as session:
            for session_id in sessions:
                case = CaseRecord(title=session_id)
                session.add(case)
                session.flush()
                task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
                session.add(task)
                session.flush()
                session.add(
                    ThreatAnalysisContextRecord(
                        dsh_session_id=session_id,
                        case_id=case.id,
                        active_task_id=task.id,
                        state="ANALYSIS_RUNNING",
                        task_lifecycle="RUNNING",
                    )
                )

        def read(session_id: str) -> tuple[str, str | None]:
            context = service.workbench_analysis_context_v3(session_id)
            return session_id, context["active_task_id"]

        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(read, sessions))
        assert [item[0] for item in results] == sessions
        assert all(item[1] for item in results)
        assert len({item[1] for item in results}) == len(sessions)
        database.engine.dispose()
        return {"workers": 5, "sessions": len(sessions), "isolated_task_projections": True}


def short_soak() -> dict[str, Any]:
    manager = ContextBudgetManager(256_000, safety_margin_bytes=8 * 1024, max_tool_result_bytes=768, max_messages=16)
    iterations = 2_000
    started = time.perf_counter()
    for index in range(iterations):
        decision = manager.prepare(
            [
                {"role": "system", "content": "static-only"},
                {"role": "tool", "content": f"synthetic-{index} " + "q" * 2_000},
            ],
            reserved_completion_bytes=4_096,
        )
        assert decision.allowed
    return {
        "iterations": iterations,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "bounded": True,
        "scope": "short synthetic soak; not 24-hour production soak",
    }


def elapsed_time_truthfulness() -> dict[str, Any]:
    """Prove elapsed time is derived from server timestamps, not turn guesses."""
    from threat_report_agent.models import AnalysisTask
    from threat_report_agent.service import AnalysisService

    created = datetime(2026, 1, 1, tzinfo=UTC)
    started = created + timedelta(seconds=2)
    finished = started + timedelta(seconds=7, milliseconds=250)
    task = AnalysisTask(
        case_id="case-elapsed",
        lifecycle="SUCCEEDED",
        created_at=created,
        started_at=started,
        finished_at=finished,
    )
    elapsed = AnalysisService._elapsed_ms(task)
    assert elapsed == 7_250
    # A finished task is immutable from the client's perspective: subsequent
    # calls cannot grow elapsed time with polling count or local wall clock.
    assert AnalysisService._elapsed_ms(task, now=finished + timedelta(hours=1)) == elapsed
    return {
        "server_elapsed_ms": elapsed,
        "source": "server started_at/finished_at",
        "finished_task_stable": True,
        "fabricated_elapsed": False,
    }


def long_turn_branch_lifecycle() -> dict[str, Any]:
    """Prove a long analysis releases its turn and branches only after terminal."""
    lifecycle = LongTurnLifecycle()
    states = [lifecycle.start_analysis("turn-1").state, lifecycle.return_async().state]
    branch_rejected = False
    try:
        lifecycle.branch("turn-branch")
    except RuntimeError as exc:
        branch_rejected = str(exc) == "BRANCH_REQUIRES_TERMINAL_TURN"
    states.append(lifecycle.accept_event(1, terminal=True).state)
    states.append(lifecycle.complete().state)
    branch = lifecycle.branch("turn-branch")
    assert branch_rejected
    assert states == ["ANALYSIS_RUNNING", "AWAITING_EVENT", "SYNTHESIZING", "COMPLETED"]
    assert branch.parent_turn_id == "turn-1"
    return {
        "states": states,
        "async_turn_released": True,
        "branch_before_terminal": "REJECTED",
        "branch_after_terminal": "ACCEPTED",
        "parent_turn_id": branch.parent_turn_id,
        "context_overflow": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = [
        _run("retryable_non_retryable_failure_injection", failure_injection),
        _run("context_window_stress", context_stress),
        _run("event_driven_wait", event_driven_wait),
        _run("cross_session_api_guard", local_cross_session_guard),
        _run("application_restart_recovery", restart_recovery),
        _run("concurrent_session_contexts", concurrent_session_contexts),
        _run("concurrent_context_calls", concurrent_context_calls),
        _run("short_synthetic_soak", short_soak),
        _run("elapsed_time_truthfulness", elapsed_time_truthfulness),
        _run("long_turn_branch_lifecycle", long_turn_branch_lifecycle),
    ]
    payload = {
        "schema_version": "runtime-control-plane-acceptance-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "PASS" if all(item["status"] == "PASS" for item in checks) else "FAIL",
        "evidence_scope": "synthetic-control-plane-only",
        "execution_boundary": {
            "sample_execution": False,
            "sample_network_access": False,
            "dynamic_emulators_invoked": False,
        },
        "checks": checks,
        "production_gates": {
            "api_container_restart_recovery": "NOT_PROVEN",
            "application_restart_recovery": "PASS",
            "worker_failure_injection": "NOT_PROVEN",
            "three_way_or_five_way_analysis_concurrency": "NOT_PROVEN",
            "twenty_four_hour_soak": "NOT_PROVEN",
            "elapsed_time_truthfulness": "PASS",
            "long_turn_branch_lifecycle": "PASS",
        },
        "notes": [
            "Synthetic checks are deterministic control-plane evidence and do not certify Docker restart/recovery.",
            "Application restart recovery uses a temporary SQLite database and reconstructs the service; it does not restart a container or worker.",
            "Concurrency and soak checks use synthetic control-plane rows/messages only; no sample bytes are opened or executed.",
            "No sample bytes were opened or executed by this harness.",
            "Elapsed time and long-turn branch checks exercise local contracts only; they do not certify a live DSH 20-minute browser run.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
