from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation.investigation_ledger import (
    LEDGER_CLOSED,
    LEDGER_DEFERRED,
    LEDGER_OPEN,
    LEDGER_UNKNOWN,
    begin_item,
    close_item,
    completion_allows_stop,
    defer_item,
    next_items,
    register_work_item,
    should_skip_work_item,
    terminate_item,
)
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob
from threat_report_agent.service import AnalysisService


def test_completion_gate_blocks_while_deferred_items_remain() -> None:
    ledger = register_work_item(
        [],
        {"id": "t1", "question": "How is config decoded?", "seed_kind": "decode"},
    )
    ledger = register_work_item(
        ledger,
        {"id": "t2", "question": "How is HTTP downloaded?", "seed_kind": "network"},
    )
    ledger = begin_item(ledger, "t1")
    ledger = close_item(ledger, "t1", evidence_ids=["e1"], claim_ids=["c1"])
    ledger = begin_item(ledger, "t2")
    ledger = defer_item(ledger, "t2", reason="TIMEBOX")

    assert completion_allows_stop(ledger) is False
    assert [item["id"] for item in next_items(ledger, phase="coverage")] == []
    assert [item["id"] for item in next_items(ledger, phase="tail")] == ["t2"]
    # No OPEN remains, so a coverage invocation is the tail pass.
    assert should_skip_work_item(ledger[1], phase="coverage", ledger=ledger) is False
    assert should_skip_work_item(ledger[1], phase="tail") is False

    overlapping = register_work_item(
        [],
        {"id": "t1", "question": "How is config decoded?", "seed_kind": "decode"},
    )
    overlapping = register_work_item(
        overlapping,
        {"id": "t2", "question": "How is HTTP downloaded?", "seed_kind": "network"},
    )
    overlapping = begin_item(overlapping, "t1")
    overlapping = defer_item(overlapping, "t2", reason="TIMEBOX")
    assert should_skip_work_item(overlapping[1], phase="coverage", ledger=overlapping) is True


def test_completion_gate_allows_stop_only_after_every_item_is_terminal() -> None:
    ledger = register_work_item(
        [],
        {"id": "t1", "question": "How is config decoded?", "seed_kind": "decode"},
    )
    ledger = register_work_item(
        ledger,
        {"id": "t2", "question": "How is HTTP downloaded?", "seed_kind": "network"},
    )

    assert completion_allows_stop([]) is False
    assert completion_allows_stop(ledger) is False

    ledger = close_item(ledger, "t1", evidence_ids=["e1"], claim_ids=["c1"])
    ledger = terminate_item(ledger, "t2", reason="STATIC_BOUNDARY after tail pass")

    assert [item["status"] for item in ledger] == [LEDGER_CLOSED, LEDGER_UNKNOWN]
    assert completion_allows_stop(ledger) is True


def test_workbench_exposes_unfinished_work_ledger(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("work ledger view")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="a" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/work-ledger-view",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "threads": [],
                    "work_ledger": [
                        {
                            "id": "thread-decode",
                            "thread_id": "thread-decode",
                            "question": "How is config decoded?",
                            "seed_kind": "decode",
                            "status": "DEFERRED",
                        }
                    ],
                }
            },
        )
        session.add(task)
        session.flush()
        session.add(
            Artifact(
                task_id=task.id,
                content_sha256=blob.sha256,
                logical_path="ledger.exe",
                detected_type="pe",
                role="EXECUTABLE",
            )
        )
        task_id = task.id
    view = service.workbench_domain_view(task_id)
    assert view["work_ledger"][0]["status"] == "DEFERRED"
    assert view["work_ledger"][0]["id"] == "thread-decode"
