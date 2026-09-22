from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from sqlalchemy import select

from tests.fixtures.t3_callback_missing_consumer import (
    FIXTURE_BIN,
    GLOBAL_NAME,
    GLOBAL_MARKER,
    IMAGE_BASE,
    TLS_CALLBACK_RVA,
    WORKER_RVA,
    ENTRY_RVA,
    t3_callback_missing_consumer_pe,
    t3_global_usage_relation,
    t3_seeded_snapshot,
    t3_value_flow_relation,
    write_t3_fixture_bin,
)
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    DeepMiningPlanner,
    InvestigationLoopDriver,
    recovered_thread_start_address,
)
from threat_report_agent.investigation.investigation_protocol import fill_protocol
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    ContentBlob,
    Evidence,
    InvestigationActionRecord,
    ToolRun,
)
from threat_report_agent.service import AnalysisService
from threat_report_agent.static_analysis import _parse_pe, _scan_x86_code, analyze_bytes


def test_t3_pe_is_compiled_windows_image_with_tls_callback_and_global() -> None:
    pe = t3_callback_missing_consumer_pe()
    path = write_t3_fixture_bin(FIXTURE_BIN)
    assert path.is_file()
    assert path.read_bytes() == pe
    assert pe[:2] == b"MZ"
    parsed = _parse_pe(pe, "t3-callback.exe")
    assert parsed["format"] == "PE32"
    assert parsed["entry_rva"] == 0x1000
    assert parsed["image_base"] == IMAGE_BASE
    imported = {
        name
        for row in parsed["imports"]
        for name in row.get("functions", [])
    }
    assert "CreateThread" in imported
    callbacks = parsed.get("tls_callbacks") or ()
    assert callbacks
    assert callbacks[0]["entry"] == hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    assert callbacks[0]["role"] == "tls_callback"
    text = next(section for section in parsed["sections"] if section["name"] == ".text")
    callback_off = int(text["raw_offset"]) + (TLS_CALLBACK_RVA - int(text["virtual_address"]))
    assert struct_marker_written(pe, callback_off)
    facts = analyze_bytes(pe, "t3-callback.exe")
    pe_facts = [fact for fact in facts.facts if fact.kind == "pe_structure"]
    assert pe_facts
    assert pe_facts[0].value.get("tls_callbacks")
    assert any(fact.kind == "tls_callback" for fact in facts.facts)


def struct_marker_written(pe: bytes, callback_off: int) -> bool:
    return GLOBAL_MARKER.to_bytes(4, "little") in pe[callback_off : callback_off + 16]


def test_t3_product_parser_seeds_tls_callback_frontier_without_seeded_snapshot() -> None:
    """Live pe-parser facts, not the Ghidra-shaped snapshot, seed TRACE_GLOBAL_USAGE."""
    pe = t3_callback_missing_consumer_pe()
    result = analyze_bytes(pe, "t3-callback.exe")
    snapshot = [
        {
            "id": f"t3-parser-{index}",
            "kind": fact.kind,
            "nature": "STATIC_OBSERVED",
            "value": fact.value,
            "anchor": fact.anchor,
        }
        for index, fact in enumerate(result.facts)
    ]
    callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    frontier = DeepMiningPlanner.build_frontier(snapshot, max_targets=32)
    assert any(
        item.category == "thread_start_routine"
        and item.selector.get("function_entry") == callback_entry
        and item.selector.get("role") == "tls_callback"
        for item in frontier
    )
    planned = DeepMiningPlanner.plan_actions(snapshot, scheduled=set(), max_actions=24)
    callback_types = {
        item.action_type
        for item in planned
        if item.parameters.get("target") == callback_entry
    }
    assert ActionType.TRACE_GLOBAL_USAGE in callback_types


def test_overlay_pe_parser_fills_unresolved_ghidra_createthread() -> None:
    """Ghidra x64 UNKNOWN traces take PE32 stdcall lpStartAddress from the parser."""
    pe = t3_callback_missing_consumer_pe()
    result = analyze_bytes(pe, "t3-callback.exe")
    pe_summary = result.summary["pe"]
    assert isinstance(pe_summary, dict)
    parser_trace = next(fact for fact in result.facts if fact.kind == "api_argument_trace")
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    spawn_entry = hex(IMAGE_BASE + ENTRY_RVA)
    unresolved = {
        "api": "CreateThread",
        "callsite": parser_trace.value["callsite"],
        "function_entry": spawn_entry,
        "arguments": [
            {"index": 0, "value": "UNKNOWN", "resolved": False},
            {"index": 1, "value": "UNKNOWN", "resolved": False},
            {"index": 2, "name": "lpStartAddress", "value": "UNKNOWN", "resolved": False},
        ],
    }
    merged = AnalysisService._overlay_pe_parser_thread_start(unresolved, pe_summary)
    assert recovered_thread_start_address(merged) == worker_entry
    assert merged["function_entry"] == spawn_entry
    assert merged["trace_quality"] == "x86_stdcall_push"


def test_overlay_pe_parser_fills_unresolved_x64_createthread() -> None:
    """PE32+ CreateThread uses R8, not PUSH stdcall."""
    unresolved = {
        "api": "CreateThread",
        "callsite": "0x140001010",
        "function_entry": "0x140001000",
        "arguments": [
            {"index": 2, "name": "lpStartAddress", "value": "UNKNOWN", "resolved": False},
        ],
    }
    pe_summary = {
        "format": "PE32+",
        "image_base": 0x140000000,
        "code_signals": {
            "api_calls": [
                {
                    "api": "kernel32.dll!CreateThread",
                    "address": 0x1010,
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "0x140001040",
                            "resolved": True,
                        },
                    ],
                }
            ]
        },
    }
    merged = AnalysisService._overlay_pe_parser_thread_start(unresolved, pe_summary)
    assert recovered_thread_start_address(merged) == "0x140001040"
    assert merged["trace_quality"] == "x64_register_window"


def test_scan_x64_createthread_recovers_lpstartaddress_from_r8() -> None:
    """Capstone x64 window: MOV R8, worker; CALL [rip+IAT] is lpStartAddress."""
    image_base = 0x140000000
    text_rva = 0x1000
    iat_rva = 0x2000
    worker = image_base + 0x1040
    mov_r8 = b"\x49\xb8" + worker.to_bytes(8, "little")
    call_rva = text_rva + len(mov_r8)
    call_size = 6
    disp = (image_base + iat_rva) - (image_base + call_rva + call_size)
    code = mov_r8 + b"\xff\x15" + disp.to_bytes(4, "little", signed=True)
    data = code + b"\x00" * 64
    signals = _scan_x86_code(
        data,
        [
            {
                "name": ".text",
                "raw_offset": 0,
                "raw_size": len(data),
                "virtual_address": text_rva,
                "executable": True,
            }
        ],
        image_base,
        [
            {
                "module": "kernel32.dll",
                "thunk_rva": iat_rva,
                "thunk_width": 8,
                "functions": ["CreateThread"],
            }
        ],
        is_64=True,
    )
    create = next(item for item in signals["api_calls"] if "CreateThread" in str(item.get("api")))
    start = recovered_thread_start_address({"api": "CreateThread", "arguments": create["arguments"]})
    assert start == hex(worker)


def test_t3_pe_parser_recovers_createthread_start_routine_from_stdcall_pushes() -> None:
    """PE32 CreateThread is stdcall: the worker VA is lpStartAddress, not UNKNOWN."""
    pe = t3_callback_missing_consumer_pe()
    result = analyze_bytes(pe, "t3-callback.exe")
    traces = [fact for fact in result.facts if fact.kind == "api_argument_trace"]
    assert traces
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    starts = [recovered_thread_start_address(fact.value) for fact in traces]
    assert worker_entry in starts
    snapshot = [
        {
            "id": f"t3-thread-{index}",
            "kind": fact.kind,
            "nature": "STATIC_OBSERVED",
            "value": fact.value,
            "anchor": fact.anchor,
        }
        for index, fact in enumerate(result.facts)
    ]
    frontier = DeepMiningPlanner.build_frontier(snapshot, max_targets=32)
    assert any(
        item.category == "thread_start_routine"
        and item.selector.get("function_entry") == worker_entry
        and item.selector.get("role") == "os_thread_start_routine"
        for item in frontier
    )


def test_ghidra_data_references_keep_unnamed_writes_and_classify_data_stores() -> None:
    rows = AnalysisService._ghidra_data_reference_rows(
        [
            {"from": "0x401034", "to": "0x402000", "type": "WRITE"},
            {"from": "0x401038", "to": "0x402004", "type": "DATA"},
            {
                "from": "0x40103c",
                "to": "0x401100",
                "type": "UNCONDITIONAL_CALL",
                "target_name": "CreateThread",
            },
            {"from": "0x401040", "to": "0x403000", "type": "DATA", "target_name": "g_named"},
        ],
        [{"address": "0x401038", "text": "MOV dword ptr [0x402004],0x1"}],
    )
    by_to = {str(item["to"]): item["type"] for item in rows}
    assert by_to["0x402000"] == "WRITE"
    assert by_to["0x402004"] == "WRITE"
    assert by_to["0x403000"] == "DATA"
    assert "0x401100" not in by_to


def test_ghidra_data_references_keep_unnamed_data_without_instruction_text() -> None:
    rows = AnalysisService._ghidra_data_reference_rows(
        [
            {"from": "0x140003010", "to": "0x14004c8e1", "type": "DATA"},
        ],
        [],
    )
    assert rows
    assert rows[0]["to"] == "0x14004c8e1"


def test_trace_global_usage_executor_recovers_producer_without_consumer(test_settings) -> None:
    """TRACE_GLOBAL_USAGE must emit a producer relation, not an unresolved dump."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    global_addr = hex(IMAGE_BASE + 0x2000)
    rows = [
        SimpleNamespace(
            id="t3-tls-fn",
            artifact_id="artifact-t3",
            kind="function_context",
            value={
                "name": "tls_callback",
                "entry": callback_entry,
                "data_references": [
                    {
                        "from": callback_entry,
                        "to": global_addr,
                        "type": "WRITE",
                        "target_name": GLOBAL_NAME,
                    }
                ],
            },
            anchor={"function_entry": callback_entry},
        ),
        SimpleNamespace(
            id="t3-worker-fn",
            artifact_id="artifact-t3",
            kind="function_context",
            value={"name": "worker", "entry": worker_entry, "data_references": []},
            anchor={"function_entry": worker_entry},
        ),
    ]
    observations = service._derive_investigation_observations(
        rows,
        ActionSpec(
            id="t3-trace-global",
            action_type=ActionType.TRACE_GLOBAL_USAGE,
            thread_id="t3-thread",
            hypothesis_id="t3-hypothesis",
            artifact_id="artifact-t3",
            target_selector={"target": callback_entry},
        ),
    )
    usage = next(item for item in observations if item["kind"] == "global_usage")
    assert usage["value"]["name"] == GLOBAL_NAME
    assert usage["value"]["writes"] is True
    assert usage["value"]["readers"] == []
    assert usage["value"]["relation"] == "producer_to_global"
    flow = next(
        item
        for item in observations
        if item["kind"] == "value_flow" and item["value"].get("relation") == "producer_to_global"
    )
    assert flow["value"]["consumer"] in (None, "", [])
    protocol = fill_protocol(
        [
            {**item, "id": item.get("id") or f"obs-{index}"}
            for index, item in enumerate(observations)
        ]
    )
    assert protocol["output"]["status"] == "ANSWERED"
    assert protocol["consumer"]["status"] == "UNKNOWN"
    assert "no recovered consumer" in str(protocol["consumer"]["reason"]).casefold()


def test_trace_global_usage_recovers_unnamed_ghidra_data_store(test_settings) -> None:
    """Ghidra often exports DATA refs without target_name; MOV [global] is a write."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    global_addr = hex(IMAGE_BASE + 0x2000)
    store_site = hex(IMAGE_BASE + TLS_CALLBACK_RVA + 4)
    rows = [
        SimpleNamespace(
            id="t3-tls-fn",
            artifact_id="artifact-t3",
            kind="function_context",
            value={
                "name": "tls_callback",
                "entry": callback_entry,
                "data_references": [
                    {
                        "from": store_site,
                        "to": global_addr,
                        "type": "DATA",
                    }
                ],
            },
            anchor={"function_entry": callback_entry},
        ),
        SimpleNamespace(
            id="t3-tls-window",
            artifact_id="artifact-t3",
            kind="function_instruction_window",
            value={
                "name": "tls_callback",
                "entry": callback_entry,
                "instructions": [
                    {
                        "address": store_site,
                        "text": f"MOV dword ptr [{global_addr}],0x1",
                    }
                ],
            },
            anchor={"function_entry": callback_entry},
        ),
        SimpleNamespace(
            id="t3-worker-fn",
            artifact_id="artifact-t3",
            kind="function_context",
            value={"name": "worker", "entry": worker_entry, "data_references": []},
            anchor={"function_entry": worker_entry},
        ),
    ]
    observations = service._derive_investigation_observations(
        rows,
        ActionSpec(
            id="t3-trace-global-data",
            action_type=ActionType.TRACE_GLOBAL_USAGE,
            thread_id="t3-thread",
            hypothesis_id="t3-hypothesis",
            artifact_id="artifact-t3",
            target_selector={"target": callback_entry},
        ),
    )
    usage = next(item for item in observations if item["kind"] == "global_usage")
    assert usage["value"]["writes"] is True
    assert usage["value"]["readers"] == []
    assert AnalysisService._locator_key(usage["value"]["address"]) == AnalysisService._locator_key(
        global_addr
    )
    protocol = fill_protocol(
        [
            {**item, "id": item.get("id") or f"obs-{index}"}
            for index, item in enumerate(observations)
        ]
    )
    assert protocol["output"]["status"] == "ANSWERED"
    assert protocol["consumer"]["status"] == "UNKNOWN"


def test_trace_api_argument_recovers_pe32_createthread_from_ghidra_pushes(
    test_settings,
) -> None:
    """Ghidra 32-bit instruction windows use PUSH stdcall, not RCX/RDX/R8/R9."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    spawn_entry = hex(IMAGE_BASE + 0x1000)
    rows = [
        SimpleNamespace(
            id="t3-spawn",
            artifact_id="artifact-t3",
            kind="function_context",
            value={
                "name": "entry",
                "entry": spawn_entry,
                "call_targets": [{"target_name": "CreateThread", "from": "0x40100f"}],
            },
            anchor={"function_entry": spawn_entry},
        ),
        SimpleNamespace(
            id="t3-window",
            artifact_id="artifact-t3",
            kind="function_instruction_window",
            value={
                "name": "entry",
                "entry": spawn_entry,
                "instructions": [
                    {"address": "0x401000", "text": "PUSH 0x0"},
                    {"address": "0x401002", "text": "PUSH 0x0"},
                    {"address": "0x401004", "text": "PUSH 0x0"},
                    {"address": "0x401006", "text": f"PUSH {worker_entry}"},
                    {"address": "0x40100b", "text": "PUSH 0x0"},
                    {"address": "0x40100d", "text": "PUSH 0x0"},
                    {"address": "0x40100f", "text": "CALL dword ptr [0x402058]"},
                ],
            },
            anchor={"function_entry": spawn_entry},
        ),
    ]
    observations = service._derive_investigation_observations(
        rows,
        ActionSpec(
            id="t3-trace-createthread",
            action_type=ActionType.TRACE_API_ARGUMENT,
            thread_id="t3-thread",
            hypothesis_id="t3-hypothesis",
            artifact_id="artifact-t3",
            target_selector={"target": spawn_entry},
        ),
    )
    traces = [item for item in observations if item["kind"] == "api_argument_trace"]
    assert traces
    starts = [recovered_thread_start_address(item["value"]) for item in traces]
    assert worker_entry in starts


def test_t3_start_enqueues_multiple_distinct_callback_and_global_actions() -> None:
    snapshot = t3_seeded_snapshot()
    planned = DeepMiningPlanner.plan_actions(snapshot, scheduled=set(), max_actions=24)
    callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    worker_entry = hex(IMAGE_BASE + WORKER_RVA)
    callback_types = {
        item.action_type
        for item in planned
        if item.parameters.get("target") == callback_entry
    }
    worker_types = {
        item.action_type
        for item in planned
        if item.parameters.get("target") == worker_entry
    }
    assert ActionType.TRACE_GLOBAL_USAGE in callback_types
    assert len(callback_types | worker_types) >= 4
    frontier = DeepMiningPlanner.build_frontier(snapshot, max_targets=32)
    assert any(
        item.category == "thread_start_routine"
        and item.selector.get("function_entry") == callback_entry
        and item.selector.get("role") == "tls_callback"
        for item in frontier
    )
    assert any(
        item.category == "thread_start_routine"
        and item.selector.get("function_entry") == worker_entry
        for item in frontier
    )
    required = next(
        item.plan["deep_investigation_contract"]["required_action_types"]
        for item in planned
        if item.parameters.get("target") == callback_entry
    )
    assert ActionType.TRACE_GLOBAL_USAGE.value in required


def test_t3_protocol_answers_callback_global_and_keeps_missing_consumer() -> None:
    snapshot = t3_seeded_snapshot()
    protocol = fill_protocol([*snapshot, t3_global_usage_relation(), t3_value_flow_relation()])
    assert protocol["initiator"]["status"] == "ANSWERED"
    assert "tls" in str(protocol["initiator"]["value"]).casefold()
    assert protocol["state_config"]["status"] == "ANSWERED"
    assert GLOBAL_NAME in str(protocol["state_config"]["value"])
    assert protocol["output"]["status"] == "ANSWERED"
    assert GLOBAL_NAME in str(protocol["output"]["value"])
    assert protocol["consumer"]["status"] == "UNKNOWN"
    assert "no recovered consumer" in str(protocol["consumer"]["reason"]).casefold()


def _execute_t3(action: ActionSpec) -> list[dict[str, object]]:
    callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
    target = str(action.target_selector.get("target") or "")
    if action.action_type == ActionType.TRACE_GLOBAL_USAGE and target == callback_entry:
        row = t3_global_usage_relation()
        row["source_action_id"] = action.id
        flow = t3_value_flow_relation()
        flow["source_action_id"] = action.id
        return [row, flow]
    if action.action_type == ActionType.GET_CALLEES and target == callback_entry:
        return []
    if action.action_type == ActionType.TRACE_API_ARGUMENT:
        return []
    return [
        {
            "id": f"{action.id}:obs",
            "kind": action.expected_evidence_kinds[0],
            "nature": "STATIC_OBSERVED",
            "value": {"api": action.action_type.value, "name": action.action_type.value},
            "anchor": {"function_entry": target or callback_entry},
        }
    ]


def test_t3_one_start_discovers_global_relation_for_behavior_explanation() -> None:
    snapshot = t3_seeded_snapshot()
    executed: list[ActionType] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type)
        return _execute_t3(action)

    result = InvestigationLoopDriver(max_steps=10, max_consecutive_no_gain=2).run(
        thread_id="t3-thread",
        artifact_id="artifact-t3",
        question="Which TLS callback, shared global and consumer form this behavior?",
        hypothesis_id="t3-hypothesis",
        hypothesis_statement="A TLS callback writes g_stage that may have a consumer.",
        initial_evidence=snapshot,
        execute=execute,
    )
    assert len({item for item in executed}) >= 3
    protocol = result.coverage["protocol"]
    assert protocol["initiator"]["status"] == "ANSWERED"
    assert protocol["output"]["status"] == "ANSWERED"
    assert GLOBAL_NAME in str(protocol["output"]["value"])
    assert protocol["consumer"]["status"] == "UNKNOWN"
    kinds = {str(row.get("kind")) for row in result.evidence}
    assert "global_usage" in kinds
    relation = next(row for row in result.evidence if row.get("kind") == "global_usage")
    assert relation["value"]["relation"] == "producer_to_global"
    assert not relation["value"]["readers"]


def test_t3_resume_does_not_replay_the_same_no_gain_tool() -> None:
    snapshot = t3_seeded_snapshot()
    first_executed: list[str] = []

    def dry(action: ActionSpec) -> tuple[()]:
        first_executed.append(action.dedupe_key)
        return ()

    first = InvestigationLoopDriver(max_steps=2, max_consecutive_no_gain=2).run(
        thread_id="t3-resume",
        artifact_id="artifact-t3",
        question="Which TLS callback, shared global and consumer form this behavior?",
        hypothesis_id="t3-hypothesis",
        hypothesis_statement="A TLS callback writes g_stage that may have a consumer.",
        initial_evidence=snapshot,
        execute=dry,
    )
    attempted = {
        event.action_id
        for event in first.events
        if event.action_id and event.phase in {"action_completed", "no_new_evidence"}
    }
    scheduled = {action.dedupe_key for action in first.actions if action.id in attempted}
    assert scheduled
    autopsies = [event for event in first.events if event.phase == "no_new_evidence_autopsy"]
    assert autopsies
    assert any("next_action=" in event.message for event in autopsies)
    assert any(
        "TRACE_GLOBAL_USAGE" in event.message or "GET_" in event.message.split("next_action=")[-1]
        for event in autopsies
    )

    second_executed: list[str] = []

    def resume_execute(action: ActionSpec) -> list[dict[str, object]]:
        second_executed.append(action.dedupe_key)
        return _execute_t3(action)

    second = InvestigationLoopDriver(max_steps=6, max_consecutive_no_gain=2).run(
        thread_id="t3-resume",
        artifact_id="artifact-t3",
        question="Which TLS callback, shared global and consumer form this behavior?",
        hypothesis_id="t3-hypothesis",
        hypothesis_statement="A TLS callback writes g_stage that may have a consumer.",
        initial_evidence=snapshot,
        execute=resume_execute,
        initial_scheduled=scheduled,
        initial_completed_action_ids=attempted,
    )
    assert not (set(second_executed) & scheduled)
    first_types = {
        action.action_type
        for action in first.actions
        if action.dedupe_key in scheduled
    }
    second_types = {
        action.action_type
        for action in second.actions
        if action.dedupe_key in second_executed
    }
    assert second_types
    assert ActionType.TRACE_GLOBAL_USAGE in second_types or bool(second_types - first_types)


def _seed_t3_task(test_settings, name: str):
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case(name)
    pe = t3_callback_missing_consumer_pe()
    blob = store.put(pe)
    snapshot = t3_seeded_snapshot()
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=blob.sha256,
                size=blob.size,
                media_type="application/octet-stream",
                storage_key=blob.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="t3-callback.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="seeded-static-snapshot",
            tool_version="t3",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        for row in snapshot:
            session.add(
                Evidence(
                    id=str(row["id"]),
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind=str(row["kind"]),
                    nature=str(row.get("nature") or "STATIC_OBSERVED"),
                    value=row["value"],
                    anchor=row.get("anchor") or {},
                )
            )
        callback_entry = hex(IMAGE_BASE + TLS_CALLBACK_RVA)
        worker_entry = hex(IMAGE_BASE + WORKER_RVA)
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "cluster-tls-callback",
                                "category": "thread",
                                "priority": 1,
                                "question": "Which TLS callback, shared global and consumer form this behavior?",
                                "evidence_ids": ["t3-tls-callback", "t3-tls-fn", "t3-global-write"],
                            },
                            {
                                "id": "cluster-worker",
                                "category": "thread_start_routine",
                                "priority": 2,
                                "question": f"What unique loop runs inside the start routine at {worker_entry}?",
                                "evidence_ids": ["t3-create-trace", "t3-worker"],
                            },
                        ]
                    }
                },
            }
        }
        return database, service, task.id, artifact.id, callback_entry


def test_t3_service_does_not_replay_no_gain_when_unrelated_evidence_arrives(
    test_settings,
) -> None:
    """K01: an artifact-wide Evidence timestamp is not a new input for the same method."""
    settings = replace(test_settings, investigation_max_steps=8, investigation_max_rounds=1)
    database, service, task_id, artifact_id, _callback = _seed_t3_task(settings, "t3-k01")
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        first = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                )
            )
        )
        tool_run_id = session.scalar(
            select(ToolRun.id).where(ToolRun.task_id == task_id).limit(1)
        )
    no_gain = [
        row
        for row in first
        if row.status == "FAILED" and row.error == "NO_NEW_EVIDENCE"
    ]
    assert no_gain
    watched = {
        (row.action_type, tuple(sorted((row.target_selector or {}).items())))
        for row in no_gain
    }
    finished_ids = {row.id for row in first}
    with database.session_factory.begin() as session:
        session.add(
            Evidence(
                id="t3-unrelated-later",
                task_id=task_id,
                artifact_id=artifact_id,
                tool_run_id=str(tool_run_id),
                module="static",
                kind="string",
                nature="STATIC_OBSERVED",
                value={"text": "unrelated later observation"},
                anchor={"type": "file_offset", "offset": 0},
            )
        )
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        second = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                )
            )
        )
    replayed = [
        row
        for row in second
        if row.id not in finished_ids
        and (row.action_type, tuple(sorted((row.target_selector or {}).items()))) in watched
        and "bounded alternate" not in str(row.reason or "")
    ]
    assert not replayed


def test_t3_service_one_start_enqueues_multiple_distinct_actions(test_settings) -> None:
    settings = replace(test_settings, investigation_max_steps=8, investigation_max_rounds=1)
    database, service, task_id, artifact_id, _callback = _seed_t3_task(settings, "t3-service")
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        first = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                )
            )
        )
    assert len({row.action_type for row in first}) >= 3
    completed = [row for row in first if row.status in {"SUCCEEDED", "FAILED"}]
    assert completed
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        second = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                )
            )
        )
    finished_ids = {row.id for row in first if row.status in {"SUCCEEDED", "FAILED"}}
    reopened = [
        row for row in second if row.id in finished_ids and row.status == "QUEUED"
    ]
    assert not reopened
