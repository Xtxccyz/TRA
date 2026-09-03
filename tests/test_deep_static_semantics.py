from types import SimpleNamespace

from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.service import AnalysisService
from threat_report_agent.database import Database
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.reporting import document_to_markdown
from threat_report_agent.models import AnalysisTask, Evidence, ReportRevision


def test_trace_api_argument_recovers_x64_call_arguments_and_consumer(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-1", artifact_id="artifact-1", kind="function_context",
            value={"name": "FUN_transport", "entry": "0x401000", "call_targets": [
                {"target_name": "WinHttpOpenRequest", "from": "0x401020"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1", artifact_id="artifact-1", kind="function_instruction_window",
            value={"entry": "0x401000", "instructions": [
                {"address": "0x401010", "text": 'MOV RCX, "GET"'},
                {"address": "0x401014", "text": 'MOV RDX, "stage"'},
                {"address": "0x401018", "text": 'MOV R8, "https://updates.example/a"'},
                {"address": "0x401020", "text": "CALL WinHttpOpenRequest"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1", artifact_id="artifact-1", kind="function_call",
            value={"api": "WinHttpOpenRequest", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-args", action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1", hypothesis_id="hyp-1", artifact_id="artifact-1",
        target_selector={"target": "WinHttpOpenRequest"},
        source_evidence_ids=("ctx-1", "ins-1", "call-1"),
    )

    observations = service._derive_investigation_observations(rows, action)

    trace = next(item for item in observations if item["kind"] == "api_argument_trace")
    value = trace["value"]
    assert value["api"] == "WinHttpOpenRequest"
    assert value["consumer"] == "WinHttpOpenRequest"
    assert {item["index"]: item["value"] for item in value["arguments"]} == {
        0: '"GET"', 1: '"stage"', 2: '"https://updates.example/a"', 3: "UNKNOWN",
    }
    assert value["function_entry"] == "0x401000"
    assert set(value["source_evidence_ids"]) >= {"ctx-1", "ins-1", "call-1"}


def test_report_renders_argument_trace_as_how_not_raw_field_dump() -> None:
    markdown = document_to_markdown(
        {
            "case_id": "case-1",
            "task_id": "task-1",
            "report_version": "3.0",
            "report_sections": ["static_triage"],
            "analysis_outcome": "PARTIAL",
            "analysis_class": "STATIC_ANALYSIS",
            "modules": [
                {
                    "id": "static_triage",
                    "title": "Static Triage",
                    "summary": "semantic evidence",
                    "rows": [
                        {
                            "type": "api_argument_recovery",
                            "evidence_id": "trace-1",
                            "api": "WinHttpOpenRequest",
                            "function": "FUN_transport",
                            "function_entry": "0x401000",
                            "callsite": "0x401020",
                            "consumer": "WinHttpOpenRequest",
                            "recovered_argument_count": 3,
                            "arguments": [
                                {"index": 0, "register": "RCX", "value": '"GET"', "source_kind": "string"},
                            ],
                            "static_only": True,
                        }
                    ],
                }
            ],
        }
    )
    assert "Static API Argument Recovery" in markdown
    assert "WinHttpOpenRequest" in markdown
    assert "arg0 (RCX):" in markdown


def test_static_submission_persists_seed_map_and_queues_frontier(test_settings) -> None:
    """Parser observations must enter the durable investigation control plane."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    database.create_schema()
    case = service.create_case("seed map integration")
    result = service.analyze_submission(
        case_id=case.id,
        filename="resolver.py",
        content=(
            "import urllib.request\n"
            "def resolve():\n"
            "    return 'https://example.invalid/update'\n"
        ).encode(),
    )
    with database.session_factory() as session:
        task = session.get(AnalysisTask, result.task_id)
        assert task is not None
        maps = session.query(Evidence).filter_by(
            task_id=result.task_id,
            kind="investigation_seed_map",
        ).all()
        assert maps
        assert all(item.nature == "STATIC_DERIVED" for item in maps)
        investigation = (task.strategy_snapshot or {}).get("investigation", {})
        assert investigation.get("seed_maps")
        queue = investigation.get("seed_queue", [])
        assert queue
        assert any(item.get("evidence_ids") for item in queue)
        revision = session.query(ReportRevision).filter_by(task_id=result.task_id).first()
        assert revision is not None
        assert "Investigation Seed Map" in revision.markdown
        timeline_rows = [
            row
            for module in revision.document.get("modules", [])
            if isinstance(module, dict)
            for row in module.get("rows", [])
            if isinstance(row, dict) and row.get("type") == "investigation_timeline"
        ]
        assert timeline_rows
        events = timeline_rows[0].get("events", [])
        assert any(event.get("phase") == "SEED_CLUSTER_QUEUED" for event in events)
