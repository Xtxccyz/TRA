from types import SimpleNamespace

from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.service import AnalysisService
from threat_report_agent.database import Database
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.report.reporting import document_to_markdown
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


def test_trace_api_argument_projects_catalog_facts_off_unresolved_slots(test_settings) -> None:
    """ClaimGate reads flat fields; nested UNKNOWN slots must not poison them."""
    from threat_report_agent.behavior_catalog import BehaviorCatalog

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-1", artifact_id="artifact-1", kind="function_context",
            value={"name": "FUN_spawn", "entry": "0x401000", "call_targets": [
                {"target_name": "CreateProcessW", "from": "0x401020"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1", artifact_id="artifact-1", kind="function_instruction_window",
            value={"entry": "0x401000", "instructions": [
                {"address": "0x401010", "text": "MOV RCX, 0"},
                {"address": "0x401014", "text": 'MOV RDX, "schtasks.exe /create"'},
                {"address": "0x401018", "text": "MOV R8, R14"},
                {"address": "0x401020", "text": "CALL CreateProcessW"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1", artifact_id="artifact-1", kind="function_call",
            value={"api": "CreateProcessW", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-create", action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1", hypothesis_id="hyp-1", artifact_id="artifact-1",
        target_selector={"target": "CreateProcessW"},
        source_evidence_ids=("ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    nested = next(
        item["value"]
        for item in observations
        if item["kind"] == "api_argument_trace" and item["value"].get("arguments")
    )
    assert any(item.get("resolved") is False or item.get("value") == "UNKNOWN" for item in nested["arguments"])
    projected = next(
        item["value"]
        for item in observations
        if item["kind"] == "api_argument_trace" and item["value"].get("command_line")
    )
    assert projected["command_line"] == "schtasks.exe /create"
    assert "arguments" not in projected
    assert any(
        item["kind"] == "value_flow"
        and item["value"].get("relation") == "command_to_process_sink"
        for item in observations
    )

    catalog_rows = [
        {
            "id": row.id,
            "kind": row.kind,
            "nature": "STATIC_OBSERVED",
            "value": row.value if isinstance(row.value, dict) else {},
        }
        for row in rows
    ]
    catalog_rows.extend(
        {
            "id": f"obs-{index}",
            "kind": item["kind"],
            "nature": item.get("nature") or "STATIC_DERIVED",
            "value": item["value"],
        }
        for index, item in enumerate(observations)
    )
    result = BehaviorCatalog().evaluate("process-creation", catalog_rows)
    assert "image_or_command" not in result.missing
    assert "command_to_process_sink" not in result.missing
    assert result.accepted is False


def test_trace_api_argument_projects_creation_flags_and_return_branch(test_settings) -> None:
    """x64 windows omit arg5; the unique nearby immediate and TEST/Jcc are CFG facts."""
    from threat_report_agent.behavior_catalog import BehaviorCatalog

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-1", artifact_id="artifact-1", kind="function_context",
            value={"name": "FUN_spawn", "entry": "0x401000", "call_targets": [
                {"target_name": "CreateProcessW", "from": "0x401020"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-1", artifact_id="artifact-1", kind="function_instruction_window",
            value={"entry": "0x401000", "instructions": [
                {"address": "0x401010", "text": "MOV RCX, 0"},
                {"address": "0x401014", "text": 'MOV RDX, "schtasks.exe /create"'},
                {"address": "0x401018", "text": "MOV dword ptr [RSP+0x28], 0x08000008"},
                {"address": "0x401020", "text": "CALL CreateProcessW"},
                {"address": "0x401025", "text": "TEST EAX, EAX"},
                {"address": "0x401027", "text": "JZ 0x401080"},
            ]}, anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-1", artifact_id="artifact-1", kind="function_call",
            value={"api": "CreateProcessW", "from": "0x401020"},
            anchor={"function_entry": "0x401000", "callsite": "0x401020"},
        ),
    ]
    action = ActionSpec(
        id="trace-create-flags", action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-1", hypothesis_id="hyp-1", artifact_id="artifact-1",
        target_selector={"target": "CreateProcessW"},
        source_evidence_ids=("ctx-1", "ins-1", "call-1"),
    )
    observations = service._derive_investigation_observations(rows, action)
    projected = next(
        item["value"]
        for item in observations
        if item["kind"] == "api_argument_trace" and item["value"].get("command_line")
    )
    assert projected["creation_flags"] == "0x08000008"
    assert projected["return_branch"] == "JZ 0x401080"
    flag_row = next(item for item in observations if item["kind"] == "process_creation_flags")
    assert flag_row["value"]["creation_flags"] == "0x08000008"
    assert "CREATE_SUSPENDED" not in (flag_row["value"].get("set_flags") or [])
    catalog_rows = [
        {
            "id": row.id,
            "kind": row.kind,
            "nature": "STATIC_OBSERVED",
            "value": row.value if isinstance(row.value, dict) else {},
        }
        for row in rows
    ]
    catalog_rows.extend(
        {
            "id": f"obs-{index}",
            "kind": item["kind"],
            "nature": item.get("nature") or "STATIC_DERIVED",
            "value": item["value"],
        }
        for index, item in enumerate(observations)
    )
    result = BehaviorCatalog().evaluate("process-creation", catalog_rows)
    assert result.missing == ()
    assert result.accepted is True


def test_resource_payload_frontier_and_static_format_probe_are_deep_mined(test_settings) -> None:
    """Resource extraction must continue past inventory into bounded payload evidence."""
    from threat_report_agent.investigation import DeepMiningPlanner

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="resource-inventory",
            artifact_id="artifact-resource",
            kind="resource_inventory",
            value={
                "count": 1,
                "rcdata_count": 1,
                "entries": [
                    {
                        "type": "RT_RCDATA",
                        "file_offset": 2,
                        "size": 8,
                        "sha256": "resource-digest",
                    }
                ],
            },
            anchor={"type": "pe_resource_directory", "rva": "0x2000"},
        ),
        SimpleNamespace(
            id="resource-extraction",
            artifact_id="artifact-resource",
            kind="mechanism_resource_extraction",
            value={"api": "FindResourceW", "call_sites": [{"api": "LoadResource"}]},
            anchor={"function_entry": "0x401000"},
        ),
    ]

    frontier = DeepMiningPlanner.build_frontier(
        [
            {
                "id": row.id,
                "kind": row.kind,
                "value": row.value,
                "anchor": row.anchor,
            }
            for row in rows
        ]
    )
    resource_target = next(item for item in frontier if item.category == "resource")
    planned = DeepMiningPlanner.plan_actions(
        [
            {
                "id": row.id,
                "kind": row.kind,
                "value": row.value,
                "anchor": row.anchor,
            }
            for row in rows
        ],
        scheduled=set(),
        max_actions=16,
    )
    assert resource_target.selector == {"target": "resource"}
    assert {
        ActionType.GET_DATA_REFERENCES,
        ActionType.READ_BYTES,
        ActionType.GET_XREFS_TO,
        ActionType.GET_CALLEES,
        ActionType.DECODE_CANDIDATE,
    } <= {item.action_type for item in planned}

    def make_action(action_type: ActionType) -> ActionSpec:
        return ActionSpec(
            id=f"resource-{action_type.value.lower()}",
            action_type=action_type,
            thread_id="thread-resource",
            hypothesis_id="hypothesis-resource",
            artifact_id="artifact-resource",
            parameters={"target": "resource"},
            target_selector={"target": "resource"},
            expected_evidence_kinds=("resource",),
            source_evidence_ids=("resource-inventory", "resource-extraction"),
        )

    content = b"xxMZpayload-child-pe"
    byte_rows = service._derive_investigation_observations(
        rows,
        make_action(ActionType.READ_BYTES),
        artifact_content=content,
    )
    read = next(item for item in byte_rows if item["kind"] == "bytes_read")
    assert read["value"]["offset"] == 2
    assert read["value"]["preview_hex"].startswith("4d5a")

    decode_rows = service._derive_investigation_observations(
        rows,
        make_action(ActionType.DECODE_CANDIDATE),
        artifact_content=content,
    )
    decoded = next(item for item in decode_rows if item["kind"] == "decoded_artifact")
    assert decoded["value"]["format_candidate"] == "pe"
    assert decoded["value"]["runtime_execution"] == "not_performed"

    data_rows = service._derive_investigation_observations(
        rows,
        make_action(ActionType.GET_DATA_REFERENCES),
    )
    assert any(item["kind"] == "data_reference" for item in data_rows)

    consumer_rows = service._derive_investigation_observations(
        rows,
        make_action(ActionType.GET_CALLEES),
    )
    consumer = next(item for item in consumer_rows if item["kind"] == "resource_consumer")
    assert consumer["value"]["api"] == "LoadResource"


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
        assert all(item.nature == "STATIC_INFERRED" for item in maps)
        assert all(
            (item.value or {}).get("derivation", {}).get("exact") is False
            for item in maps
        )
        investigation = (task.strategy_snapshot or {}).get("investigation", {})
        assert investigation.get("seed_maps")
        queue = investigation.get("seed_queue", [])
        assert queue
        assert any(item.get("evidence_ids") for item in queue)
        revision = session.query(ReportRevision).filter_by(task_id=result.task_id).first()
        assert revision is not None
        assert "Investigation Seed Map" not in revision.markdown
        assert "Investigation Seed Map" in document_to_markdown(revision.document)
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


def test_evaluate_constant_recovers_gettickcount_comparison_threshold(test_settings) -> None:
    """C4: EVALUATE_CONSTANT recovers a probe comparison; it is not CREATE_SUSPENDED."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ins-tick",
            artifact_id="artifact-1",
            kind="function_instruction_window",
            value={
                "instructions": [
                    {"address": "0x401000", "text": "CALL GetTickCount64"},
                    {"address": "0x401006", "text": "CMP RAX, 0x493e1"},
                    {"address": "0x40100d", "text": "JBE 0x401080"},
                ]
            },
            anchor={"function_entry": "0x401000"},
        ),
    ]
    action = ActionSpec(
        id="eval-tick",
        action_type=ActionType.EVALUATE_CONSTANT,
        thread_id="thread-1",
        hypothesis_id="hyp-1",
        artifact_id="artifact-1",
        target_selector={"target": "GetTickCount64"},
        source_evidence_ids=("ins-tick",),
    )
    observations = service._derive_investigation_observations(rows, action)
    threshold = next(
        item["value"]
        for item in observations
        if item["kind"] == "constant" and item["value"].get("name") == "threshold"
    )
    assert threshold["api"] == "GetTickCount64"
    assert str(threshold["comparison"]).casefold() in {"0x493e1", "0x0493e1"}
    assert threshold.get("return_branch") == "JBE 0x401080"
    assert not any(
        item["kind"] == "constant" and item["value"].get("name") == "creation_flags"
        for item in observations
    )
