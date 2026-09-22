import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import httpx
from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import (
    AnalysisFailureRecord,
    AnalysisTask,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    InvestigationHypothesisRecord,
    InvestigationActionRecord,
    InvestigationThreadRecord,
    ToolRun,
    AnalysisTurnRecord,
    Claim,
    ClaimEvidence,
    ModelCall,
    utcnow,
)
from threat_report_agent.service import (
    AnalysisService,
    _seed_context_rows,
    admit_investigation_seed_clusters,
    coalesce_investigation_seed_clusters,
    deferred_keeps_planner_open,
    frontier_status_is_open,
    investigation_budget_charged_action_count,
    investigation_seed_step_budget,
)
from threat_report_agent.model_gateway import DynamicPlanAction, ModelGateway
from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    InvestigationLoopDriver,
    verify_mechanism,
)
from threat_report_agent.investigation_ledger import completion_allows_stop
from threat_report_agent.static_analysis import StaticFact


def test_investigation_seed_step_budget_caps_per_high_value_slot() -> None:
    """Kunglao dead-letter: leftover 64 is not poured into one OPEN TRACE seed."""
    from threat_report_agent.service import how_seed_slot_rank

    assert investigation_seed_step_budget(remaining=64) == 8
    assert investigation_seed_step_budget(remaining=3) == 3
    assert investigation_seed_step_budget(remaining=0) == 0
    assert investigation_seed_step_budget(remaining=64) > 64 // 12
    assert how_seed_slot_rank({"_seed_cluster": {"category": "process"}}) < how_seed_slot_rank(
        {"_seed_cluster": {"category": "thread"}}
    )
    assert how_seed_slot_rank({"_seed_cluster": {"category": "keyword"}}) == 9


def test_placeholder_controlled_emulate_does_not_charge_invocation_budget() -> None:
    deferred = SimpleNamespace(id="emu-deferred", action_type=ActionType.CONTROLLED_EMULATE)
    decode = SimpleNamespace(id="decode-1", action_type=ActionType.DECODE_CANDIDATE)
    evidence = [
        {
            "kind": "simulation_result",
            "source_action_id": "emu-deferred",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        },
        {
            "kind": "decode_result",
            "source_action_id": "decode-1",
            "value": {"algorithm": "xor"},
        },
    ]
    assert (
        investigation_budget_charged_action_count(
            attempted_ids={"emu-deferred", "decode-1"},
            actions=(deferred, decode),
            evidence=evidence,
        )
        == 1
    )
    failed = SimpleNamespace(id="emu-failed", action_type=ActionType.CONTROLLED_EMULATE)
    assert (
        investigation_budget_charged_action_count(
            attempted_ids={"emu-failed"},
            actions=(failed,),
            evidence=[
                {
                    "kind": "simulation_result",
                    "source_action_id": "emu-failed",
                    "value": {"status": "FAILED", "stop_reason": "EXECUTION_ERROR"},
                }
            ],
        )
        == 1
    )


def test_grounded_model_candidates_require_a_function_scoped_anchor() -> None:
    """A model may not turn a PE-header entry RVA into a deep action target."""
    candidates = AnalysisService._grounded_planner_action_candidates(
        [
            {
                "artifact_id": "artifact-1",
                "evidence_id": "pe-header",
                "nature": "STATIC_OBSERVED",
                "kind": "pe_structure",
                "value": {"entry_rva": 5152},
                "anchor": {"type": "pe_header"},
            },
            {
                "artifact_id": "artifact-1",
                "evidence_id": "import-1",
                "nature": "STATIC_OBSERVED",
                "kind": "import_symbol",
                "value": {"name": "CreateProcessW"},
                "anchor": {"type": "pe_import"},
            },
        ],
        artifact_ids={"artifact-1"},
    )

    assert all(item["target_selector"] != {"target": "5152"} for item in candidates)
    assert len(candidates) == 1
    assert candidates[0]["evidence_id"] == "import-1"
    assert candidates[0]["target_selector"] == {"target": "CreateProcessW"}
    assert candidates[0]["action"]["action_type"] == "GET_XREFS_TO"


def test_static_result_persists_mechanism_link_without_model_action(test_settings) -> None:
    """Baseline static extraction must expose correlated mechanisms without an LLM."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("baseline mechanism correlation")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="f" * 64,
            size=3,
            media_type="application/octet-stream",
            storage_key="sha256/baseline-correlation",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="sample.exe",
            detected_type="pe",
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
        result = SimpleNamespace(
            limitations=(),
            facts=(
                StaticFact(
                    "loader", "function_call", {"target_function": "GetProcAddress"},
                    {"type": "function_call", "function_entry": "0x1000"},
                ),
                StaticFact(
                    "network", "function_call", {"target_function": "WinHttpOpen"},
                    {"type": "function_call", "function_entry": "0x1000"},
                ),
            ),
        )
        service._record_static_result(session, task, artifact, run, result)
        session.flush()
        links = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id,
                    Evidence.kind == "mechanism_dynamic_api_link",
                )
            )
        )
        assert len(links) == 1
        assert links[0].nature == "STATIC_DERIVED"
        source_ids = links[0].value["source_evidence_ids"]
        assert len(source_ids) == 2
        assert set(source_ids).issubset({row.id for row in session.scalars(select(Evidence)).all()})


def test_specialized_verifier_context_recovers_prior_static_link_sources() -> None:
    """A narrow thread result must not hide a task-local verified mechanism."""
    narrow = [
        {
            "id": "thread-resolver",
            "artifact_id": "artifact-1",
            "kind": "function_call",
            "value": {"target_function": "GetProcAddress"},
            "anchor": {"function_entry": "0x1000"},
        }
    ]
    scope = [
        {
            "id": "resolver",
            "artifact_id": "artifact-1",
            "kind": "function_call",
            "value": {"target_function": "GetProcAddress"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "module",
            "artifact_id": "artifact-1",
            "kind": "function_data_correlation",
            "value": {"text": "plugin.dll entry_point"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "consumer",
            "artifact_id": "artifact-1",
            "kind": "indirect_function_pointer_link",
            "value": {"consumer": "VirtualProtect", "indirect": True},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "prior-link",
            "artifact_id": "artifact-1",
            "kind": "mechanism_dynamic_api_link",
            "value": {
                "mechanism_type": "DYNAMIC_API_RESOLUTION",
                "resolver": ["getprocaddress"],
                "module": "plugin.dll",
                "entry_point": "resolved entry",
                "consumer": ["VirtualProtect"],
                "function_pointer": "resolved pointer",
                "source_evidence_ids": ["resolver", "module", "consumer"],
            },
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    prior = {
        "status": "VERIFIED",
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "evidence_ids": ["prior-link", "resolver", "module", "consumer"],
    }

    recovered = AnalysisService._specialized_verifier_context(
        narrow,
        scope,
        mechanism_type="DYNAMIC_API_RESOLUTION",
        prior_mechanism=prior,
    )

    assert {"prior-link", "resolver", "module", "consumer"} <= {
        str(row["id"]) for row in recovered
    }
    result = verify_mechanism("DYNAMIC_API_RESOLUTION", recovered)
    assert result.accepted is True


def test_specialized_verifier_context_recovers_decode_result_and_consumer_flow() -> None:
    current = [
        {
            "id": "blob",
            "artifact_id": "artifact-1",
            "kind": "encoded_blob",
            "value": {"virtual_address": 0x14004C8E1},
            "anchor": {"rva": "0x4c8e1"},
        }
    ]
    scope = [
        current[0],
        {
            "id": "decode",
            "artifact_id": "artifact-1",
            "kind": "decode_result",
            "value": {
                "algorithm": "key_table_modulo_xor_counter",
                "source_evidence_ids": ["blob"],
            },
            "anchor": {"function_entry": "0x140003000"},
        },
        {
            "id": "flow",
            "artifact_id": "artifact-1",
            "kind": "value_flow",
            "value": {
                "relation": "output_to_consumer",
                "source_evidence_ids": ["blob", "xref"],
            },
            "anchor": {"function_entry": "0x140003000"},
        },
        {
            "id": "xref",
            "artifact_id": "artifact-1",
            "kind": "data_reference",
            "value": {"from": "0x140003010", "to": "0x14004c8e1"},
            "anchor": {"function_entry": "0x140003000"},
        },
    ]
    recovered = AnalysisService._specialized_verifier_context(
        current,
        scope,
        mechanism_type="DECODE_CONFIG",
    )
    assert {"blob", "decode", "flow", "xref"} <= {str(row["id"]) for row in recovered}


def test_verified_mechanism_cannot_be_downgraded_by_narrow_verifier_result() -> None:
    """A later bounded pass preserves a previously accepted static mechanism."""
    current = {"status": "VERIFIED", "verifier": {"status": "VERIFIED"}}
    narrowed = {"status": "UNKNOWN", "verifier": {"status": "UNKNOWN"}}
    merged = AnalysisService._preserve_verified_mechanism(current, narrowed)
    assert merged["status"] == "VERIFIED"
    assert merged["verifier"]["status"] == "VERIFIED"


def test_capstone_fallback_persists_rva_mechanism_link(test_settings) -> None:
    """x64 fallback call sites must reach the report mechanism projection."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("fallback mechanism correlation")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="e" * 64,
            size=3,
            media_type="application/octet-stream",
            storage_key="sha256/fallback-correlation",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="fallback.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="builtin-static-analyzer",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        result = SimpleNamespace(
            summary={
                "pe": {
                    "code_signals": {
                        "architecture": "x86-64",
                        "api_calls": [
                            {"api": "KERNEL32.dll!CreateProcessW", "address": 0x1240, "file_offset": 0x240},
                            {"api": "KERNEL32.dll!CreatePipe", "address": 0x12A0, "file_offset": 0x2A0},
                            {"api": "KERNEL32.dll!ReadFile", "address": 0x1310, "file_offset": 0x310},
                        ],
                    }
                }
            }
        )
        service._record_builtin_code_signal_evidence(session, task, artifact, run, result)
        links = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task.id,
                    Evidence.kind == "mechanism_shell_output_link",
                )
            )
        )
        assert len(links) == 1
        assert links[0].value["mechanism_type"] == "SHELL_OUTPUT"
        assert links[0].value["source_evidence_ids"]


def test_seed_context_expands_an_api_lead_to_its_function_evidence_closure() -> None:
    """An unanchored API seed must reach the recovered function before mining."""
    seed = Evidence(
        id="seed-import",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="import_symbol",
        nature="STATIC_OBSERVED",
        value={"name": "CreateProcessW"},
        anchor={"type": "pe_import"},
    )
    context = Evidence(
        id="spawn-context",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "spawn_worker",
            "entry": "0x401000",
            "entry_rva": 4096,
            "call_targets": [{"target_name": "CreateProcessW", "from": "0x401050"}],
        },
        anchor={"rva": 4096},
    )
    window = Evidence(
        id="spawn-window",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="function_instruction_window",
        nature="STATIC_OBSERVED",
        value={"instructions": [{"address": "0x401050", "text": "CALL CreateProcessW"}]},
        anchor={"rva": 4096},
    )

    selected = _seed_context_rows(
        [seed, context, window],
        {"evidence_ids": [seed.id]},
    )

    assert [row.id for row in selected] == [seed.id, context.id, window.id]


def test_seed_context_keeps_derived_link_and_its_bridge_inside_cap() -> None:
    """A late mechanism link must survive the bounded prompt context."""
    seed = Evidence(
        id="seed-resolver",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="mechanism_dynamic_resolution",
        nature="STATIC_OBSERVED",
        value={"apis": ["LoadLibraryA", "GetProcAddress"]},
        anchor={"function_entry": "0x401000"},
    )
    source = Evidence(
        id="resolver-context",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "resolver",
            "entry": "0x401000",
            "call_targets": [
                {"target_name": "LoadLibraryA"},
                {"target_name": "GetProcAddress"},
            ],
            "data_references": [{"target_name": "plugin.dll"}],
        },
        anchor={"function_entry": "0x401000"},
    )
    link = Evidence(
        id="late-derived-link",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="mechanism_dynamic_api_link",
        nature="STATIC_DERIVED",
        value={
            "apis": ["getprocaddress", "loadlibrarya"],
            "consumer": ["indirect function-pointer consumer"],
            "function_pointer": "resolved function pointer",
            "source_evidence_ids": [seed.id, source.id],
        },
        anchor={"function_entry": "0x401000"},
    )
    noise = [
        Evidence(
            id=f"noise-{index}",
            task_id="task",
            artifact_id="artifact",
            tool_run_id="run",
            module="static",
            kind="string",
            nature="STATIC_OBSERVED",
            value={"text": f"noise-{index}"},
            anchor={"function_entry": "0x401000"},
        )
        for index in range(300)
    ]

    selected = _seed_context_rows(
        [seed, *noise, source, link],
        {"evidence_ids": [seed.id]},
        limit=3,
    )

    selected_ids = {row.id for row in selected}
    assert {seed.id, source.id, link.id} <= selected_ids


def test_seeded_api_recovers_late_function_context_beyond_prompt_working_set(test_settings) -> None:
    """A seed closure must not depend on the early evidence working-set cap.

    Real Ghidra runs write many parser observations before function contexts.
    The selected API seed still has to recover its concrete caller and queue a
    function-level action, rather than falling back to a query on the API name.
    """
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("late function closure")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="c" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/late-function-closure",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="late-context.exe",
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
        base_time = utcnow()
        seed = Evidence(
            id="seed-create-process",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=run.id,
            module="static",
            kind="import_symbol",
            nature="STATIC_OBSERVED",
            value={"name": "CreateProcessW", "library": "KERNEL32.dll"},
            anchor={"type": "pe_import"},
            created_at=base_time,
        )
        session.add(seed)
        session.add_all(
            Evidence(
                id=f"early-fact-{index}",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_call",
                nature="STATIC_OBSERVED",
                value={"api": f"benign_helper_{index}"},
                anchor={},
                created_at=base_time + timedelta(seconds=index + 1),
            )
            for index in range(800)
        )
        session.add_all(
            [
                Evidence(
                    id="late-spawn-context",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={
                        "name": "spawn_worker",
                        "entry": "0x401000",
                        "call_targets": [
                            {"target_name": "CreateProcessW", "from": "0x401050"}
                        ],
                    },
                    anchor={"type": "function_context", "entry": "0x401000", "rva": 4096},
                    created_at=base_time + timedelta(hours=1),
                ),
                Evidence(
                    id="late-spawn-window",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_instruction_window",
                    nature="STATIC_OBSERVED",
                    value={"instructions": [{"address": "0x401050", "text": "CALL CreateProcessW"}]},
                    anchor={"function_entry": "0x401000", "rva": 4096},
                    created_at=base_time + timedelta(hours=1, seconds=1),
                ),
            ]
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "process-seed",
                                "category": "execution",
                                "question": "Which function constructs the child process?",
                                "evidence_ids": [seed.id],
                            }
                        ]
                    }
                },
            }
        }
        task_id = task.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id
                )
            )
        )
    assert any(
        action.target_selector == {"target": "0x401000"}
        and action.action_type
        in {"TRACE_API_ARGUMENT", "GET_PCODE_SLICE", "GET_DATA_REFERENCES", "GET_CFG_SLICE"}
        for action in actions
    )


def test_sql_execution_corpus_prioritizes_late_high_signal_rows_before_limit(
    test_settings, monkeypatch
) -> None:
    """The SQL working-set cap must not hide late semantic evidence.

    The prompt-oriented sample is intentionally dominated by early strings;
    the rows needed by a deep action arrive later.  This exercises the actual
    ORM query in ``_run_investigation_loop`` rather than only its in-memory
    sorter, so a regression that applies ``LIMIT`` before the priority
    ``ORDER BY`` is observable.
    """
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    # Keep the fixture fast while preserving the production query shape.
    service._INVESTIGATION_EXECUTION_EVIDENCE_LIMIT = 5
    captured_rows: list[list[str]] = []
    original_derive = service._derive_investigation_observations

    def capture_execution_rows(
        source_rows,
        action,
        *,
        artifact_content=None,
        pe_summary=None,
    ):
        captured_rows.append([str(row.id) for row in source_rows])
        return original_derive(
            source_rows,
            action,
            artifact_content=artifact_content,
            pe_summary=pe_summary,
        )

    monkeypatch.setattr(
        service,
        "_derive_investigation_observations",
        capture_execution_rows,
    )
    case = service.create_case("SQL execution corpus priority")
    stored = store.put(b"MZ" + b"\x00" * 64)
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "dynamic_planning": {
                    "action_history": [
                        {
                            "tool_name": "ghidra-headless",
                            "action_type": "GET_DECOMPILE",
                            "target_artifact_id": "pending",
                            "priority": 1,
                            "reason": "recover late semantic function evidence",
                            "target_selector": {"target": "0x9000"},
                            "expected_evidence_kinds": ["abstract_execution_trace"],
                            "success_condition": "new_targeted_evidence",
                            "failure_interpretation": "UNKNOWN",
                        }
                    ]
                }
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="late-semantic.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        # The action history is artifact-scoped and is populated after the ID
        # exists, avoiding an ungrounded model action in the fixture. Assign a
        # new JSON value so SQLAlchemy persists the nested update.
        task.strategy_snapshot = {
            "dynamic_planning": {
                "action_history": [
                    {
                        "tool_name": "ghidra-headless",
                        "action_type": "GET_DECOMPILE",
                        "target_artifact_id": artifact.id,
                        "priority": 1,
                        "reason": "recover late semantic function evidence",
                        "target_selector": {"target": "0x9000"},
                        "expected_evidence_kinds": ["abstract_execution_trace"],
                        "success_condition": "new_targeted_evidence",
                        "failure_interpretation": "UNKNOWN",
                    }
                ]
            }
        }
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        base_time = utcnow()
        session.add_all(
            Evidence(
                id=f"early-string-{index:03d}",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="string",
                nature="STATIC_OBSERVED",
                value={"text": f"noise-{index}"},
                anchor={},
                created_at=base_time + timedelta(seconds=index),
            )
            for index in range(300)
        )
        session.add_all(
            Evidence(
                id=f"late-trace-{index}",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="abstract_execution_trace",
                nature="STATIC_INFERRED",
                value={
                    "function_entry": "0x9000",
                    "api": "CreateProcessW",
                    "step": index,
                },
                anchor={"function_entry": "0x9000"},
                created_at=base_time + timedelta(hours=1, seconds=index),
            )
            for index in range(3)
        )
        task_id = task.id

    service._run_investigation_loop(task_id, model_actions_only=True)

    assert captured_rows, "the model action should reach the static executor"
    assert any(
        late_id in captured_rows[0]
        for late_id in {"late-trace-0", "late-trace-1", "late-trace-2"}
    ), "SQL LIMIT must retain late high-priority semantic evidence"


def test_investigation_driver_stops_after_cooperative_cancellation() -> None:
    """Cancellation must prevent queued actions from running after the first boundary."""
    driver = InvestigationLoopDriver(max_steps=8)
    executed: list[str] = []
    proposed = ActionSpec(
        id="cancel-action-1",
        action_type=ActionType.GET_STRINGS_REFERENCED,
        thread_id="cancel-thread",
        hypothesis_id="cancel-hypothesis",
        artifact_id="cancel-artifact",
        parameters={"target": "file"},
        target_selector={"target": "file"},
        expected_evidence_kinds=("string",),
    )

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.id)
        return [{"id": "cancel-evidence", "kind": "string", "value": {"text": "lead"}}]

    result = driver.run(
        thread_id="cancel-thread",
        artifact_id="cancel-artifact",
        question="What static evidence is present?",
        hypothesis_id="cancel-hypothesis",
        hypothesis_statement="A static mechanism may be present.",
        proposed_actions=(proposed,),
        execute=execute,
        allow_investigator_actions=False,
        should_stop=lambda: bool(executed),
    )

    assert executed == ["cancel-action-1"]
    assert any(event.phase == "cancelled" for event in result.events)


def test_investigation_driver_covers_distinct_action_families_before_no_gain_stop() -> None:
    """Two empty queries must not suppress a queued, different evidence probe."""
    proposed = [
        ActionSpec(
            id=f"coverage-{action_type.value}",
            action_type=action_type,
            thread_id="thread-coverage",
            hypothesis_id="hypothesis-coverage",
            artifact_id="artifact-coverage",
            priority=index,
            reason="exercise a distinct static evidence family",
            parameters={"target": "resolver"},
            target_selector={"target": "resolver"},
            expected_evidence_kinds=("function_context",),
            success_condition="new_targeted_evidence",
        )
        for index, action_type in enumerate(
            (ActionType.GET_XREFS_TO, ActionType.GET_CALLERS, ActionType.GET_PCODE_SLICE),
            start=1,
        )
    ]
    attempted: list[ActionType] = []

    def execute(action: ActionSpec):
        attempted.append(action.action_type)
        if action.action_type == ActionType.GET_PCODE_SLICE:
            return [
                {
                    "id": "coverage-context",
                    "kind": "function_context",
                    "nature": "STATIC_OBSERVED",
                    "value": {"entry": "0x401000"},
                    "anchor": {"function_entry": "0x401000"},
                }
            ]
        return []

    result = InvestigationLoopDriver(max_steps=4, max_consecutive_no_gain=2).run(
        thread_id="thread-coverage",
        artifact_id="artifact-coverage",
        question="Which resolver path is statically recoverable?",
        hypothesis_id="hypothesis-coverage",
        hypothesis_statement="A resolver path may be present.",
        proposed_actions=proposed,
        execute=execute,
        allow_investigator_actions=False,
    )

    assert attempted == [
        ActionType.GET_XREFS_TO,
        ActionType.GET_CALLERS,
        ActionType.GET_PCODE_SLICE,
    ]
    assert any(event.phase == "coverage_continue" for event in result.events)


def test_specialist_static_link_is_materialized_into_snapshot_without_claim(test_settings) -> None:
    """Derived mechanism links remain visible even before a Claim exists."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("specialist snapshot projection")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="b" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/specialist-link",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="sample.exe",
            detected_type="pe",
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
        session.add_all(
            [
                Evidence(
                    id="merge-source-resolver",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "GetProcAddress"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="merge-source-consumer",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "WinHttpOpen"},
                    anchor={"function_entry": "0x1000"},
                ),
            ]
        )
        session.add(
            Evidence(
                id="src-resolver",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_call",
                nature="STATIC_OBSERVED",
                value={"target_function": "GetProcAddress"},
                anchor={"function_entry": "0x1000"},
            )
        )
        session.add(
            Evidence(
                id="src-consumer",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_call",
                nature="STATIC_OBSERVED",
                value={"target_function": "WinHttpOpen"},
                anchor={"function_entry": "0x1000"},
            )
        )
        session.add(
            Evidence(
                id="derived-link",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="investigation",
                kind="mechanism_dynamic_api_link",
                nature="STATIC_DERIVED",
                value={
                    "mechanism_type": "DYNAMIC_API_RESOLUTION",
                    "resolver": ["getprocaddress"],
                    "consumer": ["winhttpopen"],
                    "module": "winhttp.dll",
                    "entry_point": "resolved entry point",
                    "function_pointer": "resolved pointer",
                    "relationship": "GetProcAddress -> function pointer -> consumer",
                    "source_evidence_ids": ["src-resolver", "src-consumer"],
                    "static_only": True,
                    "derivation": {
                        "evaluator": "derive_static_mechanism_links",
                        "input_evidence_ids": ["src-resolver", "src-consumer"],
                        "input_digest": "i" * 64,
                        "output_digest": "o" * 64,
                    },
                },
                anchor={"type": "static_mechanism_link", "function_entry": "0x1000"},
            )
        )
        service._materialize_mechanism_snapshot(session, task)
        investigation = (task.strategy_snapshot or {}).get("investigation", {})
        mechanisms = investigation.get("mechanisms", [])
        assert len(mechanisms) == 1
        mechanism = mechanisms[0]
        assert mechanism["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
        assert mechanism["status"] == "CANDIDATE"
        assert "derived-link" in mechanism["evidence_ids"]
        assert set(mechanism["provenance"]["source_evidence_ids"]) == {
            "src-resolver", "src-consumer"
        }


def test_specialist_static_link_enriches_matching_investigation_mechanism(test_settings) -> None:
    """A TRACE thread receives specialist fields without a duplicate row."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("specialist merge")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="c" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/specialist-merge",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "mechanisms": [
                        {
                            "id": "mechanism-thread",
                            "thread_id": "thread-resolver",
                            "artifact_id": "artifact-placeholder",
                            "type": "TRACE_DYNAMIC_API_RESOLUTION",
                            "status": "UNKNOWN",
                            "evidence_ids": [],
                        }
                    ]
                }
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-placeholder",
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="resolver.exe",
            detected_type="pe",
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
                id="merge-link",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="investigation",
                kind="mechanism_dynamic_api_link",
                nature="STATIC_DERIVED",
                value={
                    "mechanism_type": "DYNAMIC_API_RESOLUTION",
                    "resolver": ["getprocaddress"],
                    "consumer": ["winhttpopen"],
                    "module": "winhttp.dll",
                    "relationship": "resolver -> consumer",
                    "source_evidence_ids": ["merge-source-resolver", "merge-source-consumer"],
                },
                anchor={"type": "static_mechanism_link"},
            )
        )
        service._materialize_mechanism_snapshot(session, task)
        mechanisms = task.strategy_snapshot["investigation"]["mechanisms"]
        assert len(mechanisms) == 1
        assert mechanisms[0]["id"] == "mechanism-thread"
        assert mechanisms[0]["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
        assert mechanisms[0]["transformation_or_control"]


def test_verified_static_shell_link_is_attached_to_investigation_claim(test_settings) -> None:
    """A verified derived link remains reportable even without a matching playbook verifier."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("verified shell link")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="d" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/verified-shell",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="shell.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add_all(
            [
                Evidence(
                    id="source-context",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "spawn", "entry": "0x1000"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="source-process",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "CreateProcessW"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="source-pipe",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "CreatePipe"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="source-constant",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="constant",
                    nature="STATIC_OBSERVED",
                    value={"name": "creation_flags", "value": "0x00000000"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="source-flow",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="value_flow",
                    nature="STATIC_OBSERVED",
                    value={"source": "command buffer", "target": "CreateProcessW"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="derived-shell-link",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="mechanism_shell_output_link",
                    nature="STATIC_DERIVED",
                    value={
                        "input": "shell command or child-process standard stream",
                        "relationship": "CreateProcess -> CreatePipe -> PeekNamedPipe/ReadFile",
                        "output_capture": "PeekNamedPipe/ReadFile drains child output",
                        "source_evidence_ids": ["source-process", "source-pipe", "source-context", "source-constant", "source-flow"],
                        "derivation": {
                            "evaluator": "derive_static_mechanism_links",
                            "input_evidence_ids": ["source-process", "source-pipe", "source-context", "source-constant", "source-flow"],
                            "input_digest": "a" * 64,
                            "output_digest": "b" * 64,
                        },
                    },
                    anchor={"type": "static_mechanism_link", "function_entry": "0x1000"},
                ),
            ]
        )
        task_id = task.id

    service._run_investigation_loop(task_id)
    view = service.task_view(task_id)
    verified = [
        item for item in view["strategy_snapshot"]["investigation"]["mechanisms"]
        if item.get("mechanism_type") == "SHELL_OUTPUT"
    ]
    assert verified
    assert verified[0]["status"] == "VERIFIED"
    assert verified[0].get("claim_ids")


def test_late_specialist_link_is_verified_and_reportable_after_high_signal_cap(test_settings) -> None:
    """A late, provenance-bearing link cannot be starved by generic facts."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("late specialist link")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="e" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/late-specialist-link",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="late-shell.exe",
            detected_type="pe",
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
        # The real ComHost regression occurs when Ghidra emits a large function
        # corpus before the derived semantic link. These rows intentionally
        # consume the generic 768-row budget first.
        session.add_all(
            Evidence(
                id=f"generic-high-signal-{index:04d}",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function",
                nature="STATIC_OBSERVED",
                value={"name": f"FUN_{index:04X}"},
                anchor={"function_entry": f"0x{0x2000 + index:X}"},
            )
            for index in range(768)
        )
        session.add_all(
            [
                Evidence(
                    id="late-shell-process",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "CreateProcessW"},
                    anchor={"function_entry": "0x9000"},
                ),
                Evidence(
                    id="late-shell-pipe",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "CreatePipe"},
                    anchor={"function_entry": "0x9000"},
                ),
                Evidence(
                    id="late-shell-read",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"target_function": "ReadFile"},
                    anchor={"function_entry": "0x9000"},
                ),
                Evidence(
                    id="late-shell-link",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="investigation",
                    kind="mechanism_shell_output_link",
                    nature="STATIC_DERIVED",
                    value={
                        "input": "child-process standard stream",
                        "consumer": "ReadFile",
                        "relationship": "CreateProcessW -> CreatePipe -> ReadFile",
                        "output_capture": "ReadFile drains child output",
                        "source_evidence_ids": [
                            "late-shell-process",
                            "late-shell-pipe",
                            "late-shell-read",
                        ],
                        "derivation": {
                            "evaluator": "derive_static_mechanism_links",
                            "input_evidence_ids": [
                                "late-shell-process",
                                "late-shell-pipe",
                                "late-shell-read",
                            ],
                            "input_digest": "a" * 64,
                            "output_digest": "b" * 64,
                        },
                    },
                    anchor={"type": "static_mechanism_link", "function_entry": "0x9000"},
                ),
            ]
        )
        task_id = task.id

    service._run_investigation_loop(task_id)
    view = service.task_view(task_id)
    mechanisms = view["strategy_snapshot"]["investigation"]["mechanisms"]
    shell = next(item for item in mechanisms if item.get("mechanism_type") == "SHELL_OUTPUT")
    assert shell["status"] == "VERIFIED"
    assert "late-shell-link" in shell["evidence_ids"]
    assert shell["claim_ids"]
    with database.session_factory() as session:
        claim = session.get(Claim, shell["claim_ids"][0])
        assert claim is not None
        assert claim.nature == "STATIC_INFERRED"
        assert claim.status == "SUPPORTED"
        from threat_report_agent.report.reporting import build_report_document

        task = session.get(AnalysisTask, task_id)
        assert task is not None
        document = build_report_document(
            case=session.get(CaseRecord, task.case_id),
            task=task,
            artifacts=list(session.scalars(select(Artifact).where(Artifact.task_id == task_id))),
            tool_runs=list(session.scalars(select(ToolRun).where(ToolRun.task_id == task_id))),
            evidence=list(session.scalars(select(Evidence).where(Evidence.task_id == task_id))),
            claims=list(session.scalars(select(Claim).where(Claim.task_id == task_id))),
            claim_evidence=list(
                session.scalars(
                    select(ClaimEvidence).join(Claim).where(Claim.task_id == task_id)
                )
            ),
            relations=[],
            gates=[],
            mechanisms=mechanisms,
            selected_modules=["behavior_attack"],
        )
    findings = document["modules"][0]["rows"]
    finding = next(item for item in findings if item.get("type") == "security_finding")
    assert finding["mechanism_type"] == "SHELL_OUTPUT"
    assert finding["claim_id"] == claim.id
    assert "late-shell-link" in finding["evidence_ids"]
    assert finding["boundary"].startswith("Static evidence")


def test_verified_static_link_survives_narrow_runtime_thread_context(test_settings) -> None:
    """A narrow seed gate must retain a previously verified static bridge."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("verified link runtime context")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="c" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/verified-link-runtime-context",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="narrow-context.exe",
            detected_type="pe",
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
        session.add_all(
            [
                Evidence(
                    id="runtime-resolver",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"api": "GetProcAddress"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id="runtime-module",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "resolver", "entry": "0x2000", "module": "plugin.dll"},
                    anchor={"function_entry": "0x2000"},
                ),
                Evidence(
                    id="runtime-consumer",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"api": "CreateFileW", "consumer": True},
                    anchor={"function_entry": "0x3000"},
                ),
                Evidence(
                    id="runtime-link",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="mechanism_dynamic_api_link",
                    nature="STATIC_DERIVED",
                    value={
                        "mechanism_type": "DYNAMIC_API_RESOLUTION",
                        "resolver": ["GetProcAddress"],
                        "consumer": ["CreateFileW"],
                        "module": "plugin.dll",
                        "relationship": "resolver -> consumer",
                        "function_pointer": "resolved function pointer",
                        "source_evidence_ids": [
                            "runtime-resolver",
                            "runtime-module",
                            "runtime-consumer",
                        ],
                        "derivation": {
                            "evaluator": "derive_static_mechanism_links",
                            "input_evidence_ids": [
                                "runtime-resolver",
                                "runtime-module",
                                "runtime-consumer",
                            ],
                            "input_digest": "a" * 64,
                            "output_digest": "b" * 64,
                        },
                    },
                    anchor={"type": "static_mechanism_link"},
                ),
                Evidence(
                    id="runtime-unrelated-seed",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "unrelated_entry"},
                    anchor={"function_entry": "0x9000"},
                ),
            ]
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "unrelated-seed",
                                "category": "dynamic_api",
                                "playbook_id": "dynamic-api-resolution",
                                "question": "Which unrelated resolver path is used?",
                                "evidence_ids": ["runtime-unrelated-seed"],
                            }
                        ]
                    }
                },
            }
        }
        task_id = task.id

    service._run_investigation_loop(task_id)

    snapshot = service.task_view(task_id)["strategy_snapshot"]["investigation"]
    mechanism = next(
        item
        for item in snapshot["mechanisms"]
        if item.get("mechanism_type") == "DYNAMIC_API_RESOLUTION"
    )
    assert mechanism["status"] == "VERIFIED"
    assert {"runtime-link", "runtime-resolver", "runtime-module", "runtime-consumer"}.issubset(
        set(mechanism["evidence_ids"])
    )


def test_investigation_loop_uses_matching_playbook_for_ppid(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("playbook hypothesis")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256="7" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/playbook"))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256="7" * 64, logical_path="sample.exe", detected_type="pe")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add_all(
            [
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_context", nature="STATIC_OBSERVED", value={"name": "spawn", "entry": "0x1000", "call_targets": [{"target_name": "OpenProcess"}, {"target_name": "UpdateProcThreadAttribute"}]}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_call", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "api": "OpenProcess"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_call", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "api": "UpdateProcThreadAttribute"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="constant", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "value": "0x00020000"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="api_argument_trace", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "api": "OpenProcess"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="pcode_slice", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "operation": "CALL"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="data_reference", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "to": "startupinfo"}, anchor={"function_entry": "0x1000"}),
                    Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="cfg_block", nature="STATIC_OBSERVED", value={"function_entry": "0x1000", "branch": "success"}, anchor={"function_entry": "0x1000"}),
            ]
        )
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        threads = session.query(InvestigationThreadRecord).filter_by(task_id=task_id, artifact_id=artifact_id).all()
        assert threads
        thread = next(item for item in threads if item.seed_kind == "ppid-process-chain")
        hypothesis = session.query(InvestigationHypothesisRecord).filter_by(thread_id=thread.id).one()
        assert thread.seed_kind == "ppid-process-chain"
        assert "parent-process spoofing" in thread.question
        assert hypothesis.dimension == "process_creation"
        assert hypothesis.required_evidence == ["function_call", "constant", "function_context"]
        # This fixture establishes that the PPID playbook is selected, but it
        # intentionally lacks the typed parent-handle -> attribute-list data
        # flow and CreateProcess/STARTUPINFOEX facts required to verify the
        # mechanism.  A matching seed must not promote an API co-occurrence.
        assert hypothesis.status == "UNKNOWN"


def test_investigation_loop_does_not_spawn_empty_corroboration_thread(test_settings) -> None:
    """One seed cluster is one thread. A fake resolver-callers sibling spends budget and never closes."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("no empty corroboration thread")
    with database.session_factory.begin() as session:
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(ContentBlob(sha256="e" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/no-empty-thread"))
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256="e" * 64, logical_path="sample.exe", detected_type="pe")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                id="resolver-only",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_call",
                nature="STATIC_OBSERVED",
                value={"api": "GetProcAddress"},
                anchor={"function_entry": "0x1000"},
            )
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "dynamic-only",
                                "category": "dynamic_api",
                                "playbook_id": "dynamic-api-resolution",
                                "question": "Which APIs are resolved statically?",
                                "evidence_ids": ["resolver-only"],
                            }
                        ]
                    }
                },
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        threads = session.query(InvestigationThreadRecord).filter_by(task_id=task_id, artifact_id=artifact_id).all()
        kinds = {item.seed_kind for item in threads}
        assert "resolver-callers" not in kinds
        assert "generic-mechanism-thread" not in kinds
        assert all("corroborat" not in str(item.question or "").casefold() for item in threads)


def test_investigation_runtime_projection_keeps_prior_turns(test_settings) -> None:
    """A later no-op loop must not erase an earlier auditable runtime trace."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("runtime projection retention")
    prior_event = {"phase": "state", "state": "CLAIM_READY", "message": "prior turn"}
    prior_action = {"id": "prior-action", "action_type": "GET_XREFS_TO", "outcome": "PRODUCTIVE"}
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "runtime": {
                        "events": [prior_event],
                        "actions": [prior_action],
                        "gates": [{"status": "SUPPORTED", "accepted": True}],
                    }
                }
            },
        )
        session.add(task)
        session.flush()
        task_id = task.id

    service._run_investigation_loop(task_id)

    snapshot = service.task_view(task_id)["strategy_snapshot"]["investigation"]
    assert prior_event in snapshot["runtime"]["events"]
    assert prior_action in snapshot["runtime"]["actions"]
    assert snapshot["runtime"]["gates"]


def test_workbench_domain_view_exposes_snapshot_mechanisms(test_settings) -> None:
    """Rich mechanism projections remain visible even without a Claim row."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("mechanism projection")
    mechanism = {
        "id": "mechanism-1",
        "mechanism_type": "DYNAMIC_API_RESOLUTION",
        "status": "VERIFIED",
        "target": "sample.exe",
        "inputs": ["module name"],
        "transformation_or_control": ["LoadLibrary -> GetProcAddress"],
        "conditions": ["static ordering"],
        "outputs": ["resolved address"],
        "consumers": ["caller"],
        "side_effects": ["prepares indirect call"],
        "evidence_ids": ["evidence-1"],
    }
    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"investigation": {"mechanisms": [mechanism]}},
        )
        session.add(task)
        session.flush()
        task_id = task.id

    view = service.workbench_domain_view(task_id)
    assert view["mechanisms"]
    assert view["mechanisms"][0]["id"] == "mechanism-1"
    assert view["mechanisms"][0]["status"] == "VERIFIED"


def test_workbench_domain_view_exposes_unique_execution_threads(test_settings) -> None:
    """DSH task_gaps reads OS-thread rows from the domain view, not a full ledger."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("unique threads view")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="c" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/unique-threads-view",
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256="c" * 64,
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
                id="ev-createthread-view",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static_triage",
                kind="api_argument_trace",
                nature="STATIC_DERIVED",
                value={
                    "api": "CreateThread",
                    "function_entry": "0x401000",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "UNKNOWN",
                            "resolved": False,
                        }
                    ],
                },
                anchor={"function_entry": "0x401000"},
            )
        )
        session.flush()
        task_id = task.id

    view = service.workbench_domain_view(task_id)
    rows = view["unique_execution_threads"]
    assert rows
    assert rows[0]["api"] == "CreateThread"
    assert str(rows[0]["start_routine"]).startswith("UNKNOWN")
    assert view["task"]["unique_execution_threads"] == rows
    assert "value" not in rows[0]


def test_workbench_domain_view_separates_model_failure_from_static_boundary(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("model failure projection")

    with database.session_factory.begin() as session:
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="FAILED",
            analysis_class="FAILED_ANALYSIS",
        )
        session.add(task)
        session.flush()
        session.add(
            AnalysisFailureRecord(
                task_id=task.id,
                lifecycle="FAILED",
                analysis_class="FAILED_ANALYSIS",
                failure_code="MODEL_FAILURE",
                failure_stage="model.complete",
                failed_component="model-gateway",
                failed_activity="static-analysis-agent",
                retryable=True,
                failure_fingerprint="a" * 64,
            )
        )
        session.add(
            ModelCall(
                task_id=task.id,
                module="static-analysis-agent",
                provider="deepseek",
                model="test-model",
                prompt_id="static-analysis-agent",
                prompt_version="1.0.0",
                prompt_sha256="b" * 64,
                status="FAILED",
                request_sha256="c" * 64,
                error_type="http_error",
                parameters={"http_status": 402},
            )
        )
        task_id = task.id

    view = service.workbench_domain_view(task_id)
    task_row = view["task"]
    assert task_row["failure"]["failure_code"] == "MODEL_FAILURE"
    assert task_row["model_status"]["kind"] == "MODEL_OR_TRANSPORT"
    assert task_row["model_status"]["http_status"] == 402
    assert task_row["model_status"]["distinct_from_static_boundary"] is True
    assert task_row["model_status"]["prompt_sha256"] == "b" * 64
    assert task_row["model_status"]["provider"] == "deepseek"
    assert task_row["model_status"]["model"] == "test-model"
    assert task_row["model_status"]["distinct_from_dsh_chat"] is False
    assert "402" in str(task_row["model_status"]["user_action"])
    assert "配额" in str(task_row["model_status"]["user_action"]) or "余额" in str(
        task_row["model_status"]["user_action"]
    )
    assert "分析规划" not in str(task_row["model_status"]["user_action"])
    assert "STATIC_BOUNDARY" not in str(task_row["model_status"])


def test_investigation_loop_executes_all_seed_clusters(test_settings) -> None:
    """Every bounded seed cluster enters its own persisted investigation thread."""
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    case = service.create_case("multi-seed frontier")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="8" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/multi-seed",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="multi-seed.exe",
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
        session.add_all(
            [
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"api": "GetProcAddress"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "resolver", "entry": "0x1000"},
                    anchor={"function_entry": "0x1000"},
                ),
            ]
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "cluster-a",
                                "category": "dynamic_api",
                                "priority": 1,
                                "question": "Which resolver path is used?",
                            },
                            {
                                "id": "cluster-b",
                                "category": "entrypoint",
                                "priority": 2,
                                "question": "Which entry path consumes it?",
                            },
                            {
                                "id": "cluster-c",
                                "category": "loader",
                                "priority": 3,
                                "question": "Which loader side effect follows?",
                            },
                            {
                                "id": "cluster-d",
                                "category": "network",
                                "priority": 4,
                                "question": "Which transport path is reached?",
                            },
                            {
                                "id": "cluster-e",
                                "category": "decode",
                                "priority": 5,
                                "question": "Which decoder consumer is recovered?",
                            },
                            {
                                "id": "cluster-f",
                                "category": "persistence",
                                "priority": 6,
                                "question": "Which persistence path is prepared?",
                            },
                            {
                                "id": "cluster-g",
                                "category": "evasion",
                                "priority": 7,
                                "question": "Which environment check gates behavior?",
                            },
                        ]
                    }
                },
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == task_id,
                    InvestigationThreadRecord.artifact_id == artifact_id,
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                )
            )
        )
    assert len(threads) >= 3
    assert len({thread.id for thread in threads}) == len(threads)
    assert {
        "Which resolver path is used?",
        "Which entry path consumes it?",
        "Which loader side effect follows?",
        "Which transport path is reached?",
        "Which decoder consumer is recovered?",
        "Which persistence path is prepared?",
        "Which environment check gates behavior?",
    }.issubset(
        {thread.question for thread in threads}
    )
    assert {action.thread_id for action in actions} >= {thread.id for thread in threads[:3] if thread.action_ids}


def test_investigation_loop_resumes_frontier_for_each_seed_cluster_with_small_round_budget(
    test_settings,
) -> None:
    """A bounded service pass must consume every independent cluster frontier.

    This models a PE with several high-value functions while forcing a tiny
    per-round action budget.  The service must resume each thread's pending
    actions across continuation rounds instead of leaving later clusters as
    snapshot-only descriptions.
    """
    settings = replace(test_settings, investigation_max_steps=4, investigation_max_rounds=4)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("multi-seed continuation")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="9" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/multi-seed-continuation",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="multi-seed-continuation.exe",
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
        clusters = []
        cluster_specs = [
            ("cluster-process", "process", "CreateProcessW"),
            ("cluster-network", "network", "WinHttpSendRequest"),
            ("cluster-loader", "loader", "LoadLibraryW"),
        ]
        for index, (cluster_id, category, api) in enumerate(cluster_specs, start=1):
            entry = f"0x{0x1000 * index:x}"
            context_id = f"context-{index}"
            call_id = f"call-{index}"
            session.add_all(
                [
                    Evidence(
                        id=context_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_context",
                        nature="STATIC_OBSERVED",
                        value={"name": f"FUN_{entry[2:]}", "entry": entry, "call_targets": [{"target_name": api}]},
                        anchor={"function_entry": entry},
                    ),
                    Evidence(
                        id=call_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_call",
                        nature="STATIC_OBSERVED",
                        value={"api": api, "function_entry": entry},
                        anchor={"function_entry": entry},
                    ),
                ]
            )
            clusters.append(
                {
                    "id": cluster_id,
                    "category": category,
                    "priority": index,
                    "question": f"Which {category} path is used?",
                    "evidence_ids": [context_id, call_id],
                }
            )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {artifact.id: {"clusters": clusters}},
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == task_id,
                    InvestigationThreadRecord.artifact_id == artifact_id,
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                )
            )
        )

    assert {thread.question for thread in threads} >= {
        "Which process path is used?",
        "Which network path is used?",
        "Which loader path is used?",
    }
    actions_by_thread = {thread.id: [item for item in actions if item.thread_id == thread.id] for thread in threads}
    # Every independent cluster must get more than a seed row and must not be
    # stranded in a queued/waiting state after continuation rounds.
    for thread in threads:
        thread_actions = actions_by_thread[thread.id]
        assert len(thread_actions) >= 4
        assert all(item.status in {"SUCCEEDED", "FAILED"} for item in thread_actions)


def test_investigation_keeps_dispatching_deferred_high_value_seeds_until_saturated(
    test_settings,
) -> None:
    """One user request must not idle while high-value seeds remain deferred.

    Kunglao's SATURATED rule: open investigation questions plus unused later
    passes are not a stop.  A tiny per-invocation action budget will defer
    later clusters; the service must continue bounded passes until every
    independent high-value cluster has attempted work or a concrete boundary.
    """
    settings = replace(
        test_settings,
        investigation_max_steps=4,
        investigation_max_rounds=1,
        investigation_task_max_actions=8,
    )
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("saturated high-value seeds")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="b" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/saturated-high-value-seeds",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="saturated-high-value.exe",
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
        clusters = []
        cluster_specs = [
            ("cluster-process", "process", "CreateProcessW"),
            ("cluster-network", "network", "WinHttpSendRequest"),
            ("cluster-loader", "loader", "LoadLibraryW"),
            ("cluster-decode", "decode", "CryptDecrypt"),
            ("cluster-persist", "persistence", "RegSetValueExW"),
            ("cluster-inject", "injection", "WriteProcessMemory"),
        ]
        for index, (cluster_id, category, api) in enumerate(cluster_specs, start=1):
            entry = f"0x{0x1000 * index:x}"
            context_id = f"sat-context-{index}"
            call_id = f"sat-call-{index}"
            session.add_all(
                [
                    Evidence(
                        id=context_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_context",
                        nature="STATIC_OBSERVED",
                        value={
                            "name": f"FUN_{entry[2:]}",
                            "entry": entry,
                            "call_targets": [{"target_name": api}],
                        },
                        anchor={"function_entry": entry},
                    ),
                    Evidence(
                        id=call_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_call",
                        nature="STATIC_OBSERVED",
                        value={"api": api, "function_entry": entry},
                        anchor={"function_entry": entry},
                    ),
                ]
            )
            clusters.append(
                {
                    "id": cluster_id,
                    "category": category,
                    "priority": 40 - index,
                    "question": f"Which {category} path is used?",
                    "evidence_ids": [context_id, call_id],
                    "function": entry,
                }
            )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {artifact.id: {"clusters": clusters}},
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_saturated_investigation(task_id)

    with database.session_factory() as session:
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == task_id,
                    InvestigationThreadRecord.artifact_id == artifact_id,
                )
            )
        )
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.artifact_id == artifact_id,
                    InvestigationActionRecord.status.in_(("SUCCEEDED", "FAILED")),
                )
            )
        )

    questions = {thread.question for thread in threads}
    assert {
        "Which process path is used?",
        "Which network path is used?",
        "Which loader path is used?",
        "Which decode path is used?",
        "Which persistence path is used?",
        "Which injection path is used?",
    } <= questions
    attempted_threads = {item.thread_id for item in actions}
    seed_threads = [
        thread
        for thread in threads
        if thread.question.startswith("Which ") and thread.question.endswith(" path is used?")
    ]
    assert len(seed_threads) == 6
    how_questions = {
        "Which process path is used?",
        "Which network path is used?",
        "Which loader path is used?",
        "Which decode path is used?",
    }
    for thread in seed_threads:
        thread_actions = [item for item in actions if item.thread_id == thread.id]
        if thread.question in how_questions:
            assert thread_actions, thread.question
            assert thread.id in attempted_threads
        else:
            assert thread.state in {
                "UNKNOWN",
                "CLAIM_READY",
                "CLOSED",
                "BLOCKED",
            }, thread.question

    with database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        ledger = list(
            ((task.strategy_snapshot or {}).get("investigation") or {}).get("work_ledger")
            or []
        )
    assert len(ledger) >= 6
    assert completion_allows_stop(ledger)
    assert {item.get("status") for item in ledger} <= {"CLOSED", "UNKNOWN", "UNSUPPORTED"}


def test_claim_evidence_duplicate_pair_does_not_abort_task(test_settings) -> None:
    """Re-attaching the same claim/evidence pair must not abort the task."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("claim evidence reentry")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="c" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/claim-evidence-reentry",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="claim-evidence-reentry.exe",
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
        evidence = Evidence(
            id="claim-evidence-reentry-row",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=run.id,
            module="static",
            kind="function_call",
            nature="STATIC_OBSERVED",
            value={"api": "CreateProcessW", "function_entry": "0x1000"},
            anchor={"function_entry": "0x1000"},
        )
        session.add(evidence)
        claim = Claim(
            task_id=task.id,
            module="investigation",
            claim_type="INVESTIGATED_MECHANISM",
            subject=artifact.logical_path,
            action="exhibits_static_mechanism",
            object="ordered static behavior indicators",
            mechanism="static observations",
            condition="static evidence threshold satisfied",
            statement="duplicate claim-evidence attachment must remain idempotent",
            nature="STATIC_INFERRED",
            status="CANDIDATE",
            confidence="LOW",
        )
        session.add(claim)
        session.flush()
        service._link_claim_evidence(
            session, claim_id=claim.id, evidence_id=evidence.id
        )
        service._link_claim_evidence(
            session, claim_id=claim.id, evidence_id=evidence.id
        )
        service._link_claim_evidence(
            session, claim_id=claim.id, evidence_id=evidence.id
        )
        claim_id = claim.id
        evidence_id = evidence.id

    with database.session_factory() as session:
        links = list(
            session.scalars(
                select(ClaimEvidence).where(ClaimEvidence.claim_id == claim_id)
            )
        )
    assert [(item.claim_id, item.evidence_id, item.stance) for item in links] == [
        (claim_id, evidence_id, "SUPPORTS")
    ]


def test_investigation_loop_does_not_drop_later_function_frontier_after_round_cap(
    test_settings,
) -> None:
    """Continuation rounds must eventually inspect every function target.

    A single seed can expose multiple high-value functions.  With a four-action
    round budget, the service must keep resuming until all mandatory facets for
    the admitted targets have been attempted; stopping after a fixed four
    rounds leaves the tail of the frontier report-only.
    """
    settings = replace(test_settings, investigation_max_steps=4, investigation_max_rounds=4)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("single seed multi-function frontier")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="a" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/single-seed-multi-function",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="single-seed-multi-function.exe",
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
        for index, api in enumerate(("CreateProcessW", "WinHttpSendRequest", "LoadLibraryW"), start=1):
            entry = f"0x{0x1000 * index:x}"
            session.add_all(
                [
                    Evidence(
                        id=f"multi-context-{index}",
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_context",
                        nature="STATIC_OBSERVED",
                        value={"name": f"FUN_{entry[2:]}", "entry": entry, "call_targets": [{"target_name": api}]},
                        anchor={"function_entry": entry},
                    ),
                    Evidence(
                        id=f"multi-call-{index}",
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_call",
                        nature="STATIC_OBSERVED",
                        value={"api": api, "function_entry": entry},
                        anchor={"function_entry": entry},
                    ),
                ]
            )
        # Deliberately omit cluster evidence IDs: this is a broad seed whose
        # bounded context contains three concrete function/RVA targets.
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": "broad-cluster",
                                "category": "generic",
                                "priority": 1,
                                "question": "Which high-value function paths are used?",
                            }
                        ]
                    }
                },
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        thread = session.scalar(
            select(InvestigationThreadRecord).where(
                InvestigationThreadRecord.task_id == task_id,
                InvestigationThreadRecord.artifact_id == artifact_id,
            )
        )
        assert thread is not None
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id,
                    InvestigationActionRecord.thread_id == thread.id,
                )
            )
        )

    # Three function targets produce eight mandatory facets each. A bounded
    # four-action round therefore needs continuation beyond four rounds.
    assert len(actions) >= 24
    assert all(item.status in {"SUCCEEDED", "FAILED"} for item in actions)


def test_equivalent_seed_clusters_are_coalesced_without_losing_provenance() -> None:
    """One dimension gets one bounded thread, with every seed still traceable."""
    clusters = [
        {
            "id": "dynamic-low",
            "category": "dynamic_api",
            "priority": 20,
            "question": "Which resolver candidate is used?",
            "evidence_ids": ["e-low"],
            "hypotheses": ["custom export hash"],
        },
        {
            "id": "network",
            "category": "network",
            "priority": 22,
            "question": "Which endpoint and transport path are linked?",
            "evidence_ids": ["e-network"],
            "hypotheses": ["HTTP transport"],
        },
        {
            "id": "dynamic-high",
            "mechanism_type": "DYNAMIC_API_RESOLUTION",
            "category": "dynamic_api",
            "priority": 30,
            "question": "Which resolver path reaches its API consumer?",
            "evidence_ids": ["e-high", "e-low"],
            "hypotheses": ["runtime API resolution"],
        },
    ]

    result = coalesce_investigation_seed_clusters(clusters)

    assert len(result) == 2
    dynamic = next(item for item in result if item["category"] == "dynamic_api")
    assert dynamic["id"] == "dynamic-high"
    assert dynamic["source_cluster_ids"] == ["dynamic-high", "dynamic-low"]
    assert dynamic["evidence_ids"] == ["e-high", "e-low"]
    assert dynamic["hypotheses"] == ["runtime API resolution", "custom export hash"]
    assert dynamic["frontier_questions"] == [
        "Which resolver path reaches its API consumer?",
        "Which resolver candidate is used?",
    ]


def test_seed_clusters_merge_same_mechanism_across_functions() -> None:
    """One HOW dimension gets one thread; leftover budget goes to depth, not copies."""
    clusters = [
        {
            "id": "resolver-a",
            "category": "dynamic_api",
            "function": "0x1000",
            "priority": 30,
            "question": "Which resolver path is used in A?",
            "evidence_ids": ["e-a"],
        },
        {
            "id": "resolver-b",
            "category": "dynamic_api",
            "function": "0x2000",
            "priority": 29,
            "question": "Which resolver path is used in B?",
            "evidence_ids": ["e-b"],
        },
        {
            "id": "resolver-a-duplicate",
            "category": "dynamic_api",
            "function": "0x1000",
            "priority": 20,
            "question": "Which resolver candidate is used in A?",
            "evidence_ids": ["e-a2"],
        },
        {
            "id": "generic-a",
            "category": "generic",
            "function": "0x1000",
            "priority": 8,
            "question": "What else happens in A?",
            "evidence_ids": ["g-a"],
        },
        {
            "id": "generic-b",
            "category": "generic",
            "function": "0x2000",
            "priority": 8,
            "question": "What else happens in B?",
            "evidence_ids": ["g-b"],
        },
    ]

    result = coalesce_investigation_seed_clusters(clusters)
    dynamic = [item for item in result if item["category"] == "dynamic_api"]
    generic = [item for item in result if item["category"] == "generic"]
    assert len(dynamic) == 1
    assert set(dynamic[0]["source_cluster_ids"]) == {
        "resolver-a",
        "resolver-b",
        "resolver-a-duplicate",
    }
    assert set(dynamic[0]["evidence_ids"]) == {"e-a", "e-b", "e-a2"}
    assert len(generic) == 2


def test_seed_clusters_keep_ppid_separate_from_process_execution() -> None:
    """Parent-process spoofing is not a CreateProcess command/flags question."""
    clusters = [
        {
            "id": "exec-a",
            "category": "execution",
            "mechanism_type": "PROCESS_EXECUTION",
            "function": "0x140004605",
            "priority": 22,
            "question": "Which process command is constructed?",
            "evidence_ids": ["e-create"],
        },
        {
            "id": "ppid-a",
            "category": "ppid",
            "mechanism_type": "PPID_SPOOFING",
            "function": "0x140004605",
            "priority": 24,
            "question": "Does the artifact spoof its parent process?",
            "evidence_ids": ["e-ppid"],
        },
    ]
    result = coalesce_investigation_seed_clusters(clusters)
    assert len(result) == 2
    by_category = {str(item["category"]): item for item in result}
    assert by_category["execution"]["evidence_ids"] == ["e-create"]
    assert by_category["ppid"]["evidence_ids"] == ["e-ppid"]


def test_admit_investigation_seed_clusters_keeps_how_drops_empty_supporting() -> None:
    """Kunglao priority_ratio: keyword seeds stay in the map, not as empty threads."""
    clusters = [
        {
            "id": "exec-a",
            "category": "execution",
            "priority": 22,
            "question": "Which process command is constructed?",
            "evidence_ids": ["e-create"],
        },
        {
            "id": "dyn-a",
            "category": "dynamic_api",
            "priority": 30,
            "question": "Which resolver path is used?",
            "evidence_ids": ["e-dyn"],
        },
        {
            "id": "persist-a",
            "category": "persistence",
            "priority": 20,
            "question": "Which persistence path is prepared?",
            "evidence_ids": ["e-persist"],
        },
        {
            "id": "generic-a",
            "category": "generic",
            "function": "0x1000",
            "priority": 8,
            "question": "What else happens in A?",
            "evidence_ids": ["g-a"],
        },
    ]
    coalesced = coalesce_investigation_seed_clusters(clusters)
    assert {item["category"] for item in coalesced} >= {"execution", "dynamic_api", "persistence", "generic"}
    admitted = admit_investigation_seed_clusters(clusters)
    assert {item["category"] for item in admitted} == {"execution", "dynamic_api"}
    thread_admitted = admit_investigation_seed_clusters(
        [
            {
                "id": "thread-a",
                "category": "thread",
                "priority": 23,
                "question": "Which same-process OS thread start is recovered?",
                "evidence_ids": ["e-thread"],
            },
            {
                "id": "generic-a",
                "category": "generic",
                "function": "0x1000",
                "priority": 8,
                "question": "What else happens in A?",
                "evidence_ids": ["g-a"],
            },
        ]
    )
    assert {item["category"] for item in thread_admitted} == {"thread"}
    assert frontier_status_is_open("UNKNOWN") is False
    assert frontier_status_is_open("PARTIAL") is False
    assert frontier_status_is_open("UNSUPPORTED") is False
    assert frontier_status_is_open("CANDIDATE") is False
    assert frontier_status_is_open("CLAIM_READY") is False
    assert frontier_status_is_open("INVESTIGATING") is True
    assert frontier_status_is_open("BLOCKED") is True
    assert deferred_keeps_planner_open({"action_type": "CONTROLLED_EMULATE"}) is False
    assert deferred_keeps_planner_open({"reason": "INVESTIGATION_BUDGET_EXHAUSTED"}) is False
    assert deferred_keeps_planner_open({"reason": "dependency", "action_type": "GET_CALLEES"}) is True
    loop_source = __import__("inspect").getsource(AnalysisService._run_investigation_loop)
    assert "admit_investigation_seed_clusters" in loop_source
    frontier_source = __import__("inspect").getsource(AnalysisService._build_investigation_frontier)
    assert "frontier_status_is_open" in frontier_source
    assert "deferred_keeps_planner_open" in frontier_source


def test_model_plan_accepts_legacy_expected_evidence_field(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        context = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        artifact_id = context["artifacts"][0]["artifact_id"]
        evidence_id = context["evidence"][0]["evidence_id"]
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({
                "objective": "follow resolver",
                "actions": [{
                    "action_type": "GET_XREFS_TO",
                    "target_artifact_id": artifact_id,
                    "priority": 1,
                    "reason": "follow the cited resolver anchor",
                    "question": "Which call sites resolve GetProcAddress and what consumes the pointer?",
                    "hypothesis": "The cited resolver participates in a statically recoverable dispatch path.",
                    "alternatives": ["unused compatibility import"],
                    "missing_evidence": ["caller xref", "resolved-pointer consumer"],
                    "failure_meaning": "The cited selector has no recoverable xref in this artifact.",
                    "evidence_ids": [evidence_id],
                    "target_selector": {"target": "GetProcAddress"},
                    "expected_evidence": ["xref"],
                }],
            })}}]},
        )

    service.model_gateway = ModelGateway(settings.primary_model, settings.fallback_model, transport=httpx.MockTransport(handler))
    case = service.create_case("legacy expected evidence")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(sha256="6" * 64, size=1, media_type="application/octet-stream", storage_key="sha256/legacy"))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(id="artifact-legacy", task_id=task.id, content_sha256="6" * 64, logical_path="resolver.exe", detected_type="pe", role="EXECUTABLE", obligation="REQUIRED")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add(Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="xref", nature="STATIC_OBSERVED", value={"target_name": "GetProcAddress"}, anchor={"function_entry": "0x1000"}, id="getproc-evidence"))
        session.flush()
        task_id = task.id

    actions, limitations = service._run_model_planning(task_id, [artifact], [artifact.id], phase="test")

    assert not limitations
    assert actions and actions[0].expected_evidence == ["xref"]
    assert actions[0].expected_evidence_kinds == ["xref"]
    assert service._model_action_plan(actions[0])["hypothesis"]


def test_model_planner_repairs_an_empty_plan_using_only_concrete_candidates(test_settings) -> None:
    """An empty JSON object is not a usable plan when a static target exists."""
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    seen_packets: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        packet = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        seen_packets.append(packet)
        repair = packet.get("planner_repair")
        if not isinstance(repair, dict):
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
        required_action_count = int(repair.get("required_action_count", 1))
        candidates = repair["candidates"][:required_action_count]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "objective": "Reduce uncertainty at the cited function anchors.",
                                    "actions": [candidate["action"] for candidate in candidates],
                                    "stop_conditions": ["No grounded candidate remains."],
                                    "limitations": [],
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model, settings.fallback_model, transport=httpx.MockTransport(handler)
    )
    case = service.create_case("empty planner repair")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="7" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/repair",
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-plan-repair",
            task_id=task.id,
            content_sha256="7" * 64,
            logical_path="spawn.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
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
                id="repair-anchor",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={
                    "name": "spawn_worker",
                    "entry": "0x401000",
                    "call_targets": [{"target_name": "CreateProcessW", "from": "0x401020"}],
                },
                anchor={"function_entry": "0x401000"},
            )
        )
        session.add_all(
            [
                Evidence(
                    id="repair-anchor-2",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "resolve_worker", "entry": "0x402000"},
                    anchor={"function_entry": "0x402000"},
                ),
                Evidence(
                    id="repair-anchor-3",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "decode_worker", "entry": "0x403000"},
                    anchor={"function_entry": "0x403000"},
                ),
            ]
        )
        task_id = task.id

    actions, limitations = service._run_model_planning(
        task_id, [artifact], [artifact.id], phase="empty-plan-repair"
    )

    assert not limitations
    assert len(seen_packets) == 2
    assert seen_packets[0]["action_requirement"]["minimum_actions_when_candidates_exist"] == 1
    assert seen_packets[1]["planner_repair"]["reason"] == "EMPTY_ACTION_PLAN_WITH_GROUNDED_CANDIDATES"
    assert seen_packets[1]["planner_repair"]["required_action_count"] == 3
    assert [action.target_selector for action in actions] == [
        {"target": "0x401000"},
        {"target": "0x402000"},
        {"target": "0x403000"},
    ]
    with database.session_factory() as session:
        calls = list(
            session.scalars(
                select(ModelCall).where(ModelCall.task_id == task_id).order_by(ModelCall.created_at)
            )
        )
    assert len(calls) == 2


def test_model_planner_uses_portable_text_after_two_empty_json_envelopes(test_settings) -> None:
    """A JSON-mode proxy cannot strand a concrete planner action at ``{}``."""
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    seen_requests: list[tuple[dict[str, object], dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        wire_payload = json.loads(request.content)
        packet = json.loads(
            wire_payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        seen_requests.append((wire_payload, packet))
        if len(seen_requests) < 3:
            return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
        candidate = packet["planner_repair"]["candidates"][0]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "objective": "Follow the function anchor using the supplied static action.",
                                    "actions": [candidate["action"]],
                                    "stop_conditions": ["No grounded candidate remains."],
                                    "limitations": [],
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model, settings.fallback_model, transport=httpx.MockTransport(handler)
    )
    case = service.create_case("portable empty planner repair")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="8" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/portable-repair",
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-portable-repair",
            task_id=task.id,
            content_sha256="8" * 64,
            logical_path="loader.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
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
                id="portable-repair-anchor",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={
                    "name": "resolve_module",
                    "entry": "0x402000",
                    "call_targets": [{"target_name": "LoadLibraryW", "from": "0x402018"}],
                },
                anchor={"function_entry": "0x402000"},
            )
        )
        task_id = task.id

    actions, limitations = service._run_model_planning(
        task_id, [artifact], [artifact.id], phase="portable-empty-plan-repair"
    )

    assert not limitations
    assert len(seen_requests) == 3
    # The compact repair contains only the concrete candidate contract, not
    # the original full evidence/context packet.
    assert "evidence" not in seen_requests[1][1]
    assert "context_packet" not in seen_requests[1][1]
    assert seen_requests[2][1]["transport_compatibility"]["response_format"] == "not_forced"
    assert "response_format" not in seen_requests[2][0]
    assert actions and actions[0].target_selector == {"target": "0x402000"}
    with database.session_factory() as session:
        calls = list(
            session.scalars(
                select(ModelCall).where(ModelCall.task_id == task_id).order_by(ModelCall.created_at)
            )
        )
    assert len(calls) == 3


def test_model_investigation_action_is_replayed_by_static_executor(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        context = json.loads(
            payload["messages"][1]["content"].split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        artifact_id = context["artifacts"][0]["artifact_id"]
        evidence_id = context["evidence"][0]["evidence_id"]
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({
                "objective": "investigate resolver",
                "actions": [{
                    "tool_name": "ghidra-headless",
                    "action_type": "GET_XREFS_TO",
                    "target_artifact_id": artifact_id,
                    "priority": 1,
                    "reason": "follow resolver",
                    "question": "Which xrefs call the cited resolver and where does its output flow?",
                    "hypothesis": "The resolver produces a function pointer consumed by a local dispatch path.",
                    "alternatives": ["unused wrapper"],
                    "missing_evidence": ["caller xref", "pointer consumer"],
                    "failure_meaning": "No artifact-local reference would bound this hypothesis to unknown.",
                    "evidence_ids": [evidence_id],
                    "target_selector": {"target": "GetProcAddress"},
                    "expected_evidence_kinds": ["xref"],
                    "success_condition": "new_targeted_evidence",
                }],
            })}}]},
        )

    service.model_gateway = ModelGateway(
        settings.primary_model, settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("model action replay")
    with database.session_factory.begin() as session:
        blob = store.put(b"MZ" + b"\0" * 64)
        session.add(ContentBlob(sha256=blob.sha256, size=blob.size, media_type="application/octet-stream", storage_key=blob.storage_key))
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256=blob.sha256, logical_path="resolver.exe", detected_type="pe", role="EXECUTABLE")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        session.add(Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="xref", nature="STATIC_OBSERVED", value={"target_name": "GetProcAddress"}, anchor={"function_entry": "0x1000"}, id="resolver-evidence"))
        task_id = task.id
        artifact_id = artifact.id

    actions, _ = service._run_model_planning(task_id, [artifact], [artifact_id], phase="action-replay")
    assert actions and actions[0].action_type == "GET_XREFS_TO"
    with database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        task.strategy_snapshot["dynamic_planning"]["action_history"] = [item.model_dump(mode="json") for item in actions]
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        rows = list(session.query(Evidence).filter(Evidence.task_id == task_id, Evidence.module == "investigation"))
        turns = list(session.query(AnalysisTurnRecord).filter(AnalysisTurnRecord.task_id == task_id))
        claims = list(session.query(Claim).filter(Claim.task_id == task_id))
        action_records = list(
            session.query(InvestigationActionRecord).filter(InvestigationActionRecord.task_id == task_id)
        )
    assert rows
    assert any(row.kind == "function_call" for row in rows)
    assert turns
    model_action = next(item for item in action_records if item.action_type == "GET_XREFS_TO")
    assert model_action.parameters["_analysis_plan"]["planner_protocol"] == "plan-first-static-v1"
    # The immediate model-action pass produces evidence only; the later full
    # verifier owns Claim creation and therefore cannot duplicate a claim.
    assert claims == []


def test_model_action_dependencies_are_enforced_at_execution_boundary(test_settings) -> None:
    """A later model probe must wait for its cited prerequisite to finish."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    blob = store.put(b"MZ" + b"\0" * 64)
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-dependency-order", title="Dependency order"))
        session.add(
            ContentBlob(
                sha256=blob.sha256,
                size=blob.size,
                media_type="application/octet-stream",
                storage_key=blob.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id="case-dependency-order", lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-dependency-order",
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="dependency.exe",
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
                id="dependency-anchor",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="xref",
                nature="STATIC_OBSERVED",
                value={"target_name": "GetProcAddress"},
                anchor={"function_entry": "0x1000"},
            )
        )
        session.add(
            Evidence(
                id="dependency-context",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={
                    "name": "resolve_api",
                    "entry": "0x1000",
                    "call_targets": [{"target_name": "GetProcAddress", "from": "0x1010"}],
                },
                anchor={"function_entry": "0x1000"},
            )
        )
        task.strategy_snapshot = {
            "dynamic_planning": {
                "action_history": [
                    {
                        "tool_name": "ghidra-headless",
                        "action_type": "GET_XREFS_TO",
                        "target_artifact_id": artifact.id,
                        "priority": 50,
                        "reason": "locate resolver callers",
                        "evidence_ids": ["dependency-anchor"],
                        "target_selector": {"target": "GetProcAddress"},
                        "expected_evidence_kinds": ["xref"],
                        "success_condition": "new_targeted_evidence",
                        "depends_on": None,
                    },
                    {
                        "tool_name": "ghidra-headless",
                        "action_type": "GET_CALLEES",
                        "target_artifact_id": artifact.id,
                        "priority": 1,
                        "reason": "inspect the resolver consumer",
                        "evidence_ids": ["dependency-anchor"],
                        "target_selector": {"target": "0x1000"},
                        "expected_evidence_kinds": ["function_call"],
                        "success_condition": "new_targeted_evidence",
                        "depends_on": ["action:0"],
                    },
                ]
            }
        }
        task_id = task.id

    service._run_investigation_loop(task_id, model_actions_only=True)

    with database.session_factory() as session:
        rows = list(
            session.scalars(
                select(InvestigationActionRecord)
                .where(InvestigationActionRecord.task_id == task_id)
                .order_by(InvestigationActionRecord.created_at)
            )
        )
    first = next(item for item in rows if item.action_type == "GET_XREFS_TO")
    second = next(item for item in rows if item.action_type == "GET_CALLEES")
    assert first.status == "SUCCEEDED"
    assert second.status == "SUCCEEDED"
    assert first.result_evidence_ids
    assert second.result_evidence_ids
    assert second.depends_on == [first.id]
    assert first.finished_at is not None and second.finished_at is not None
    assert first.finished_at <= second.finished_at


def test_model_action_recovers_cited_evidence_outside_prompt_window(test_settings) -> None:
    """Execution must reload a cited target omitted from the bounded prompt corpus."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    blob = store.put(b"MZ" + b"\0" * 64)
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-window-recovery", title="Window recovery"))
        session.add(ContentBlob(sha256=blob.sha256, size=blob.size, media_type="application/octet-stream", storage_key=blob.storage_key))
        session.flush()
        task = AnalysisTask(case_id="case-window-recovery", lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(task_id=task.id, content_sha256=blob.sha256, logical_path="window.exe", detected_type="pe", role="EXECUTABLE")
        session.add(artifact)
        session.flush()
        run = ToolRun(task_id=task.id, artifact_id=artifact.id, tool_name="ghidra-headless", tool_version="test", status="SUCCEEDED")
        session.add(run)
        session.flush()
        # More than the 768-row planner context cap, with the cited target at
        # the end.  The action must still recover it from the database.
        for index in range(900):
            session.add(
                Evidence(
                    id=f"filler-{index:04d}",
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"api": "UnrelatedApi", "from": f"0x{index:x}"},
                    anchor={"function_entry": f"0x{index + 0x1000:x}"},
                )
            )
        session.add(
            Evidence(
                id="zz-target-evidence",
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="function_context",
                nature="STATIC_OBSERVED",
                value={
                    "name": "FUN_target",
                    "entry": "0x9000",
                    "call_targets": [{"target_name": "GetProcAddress", "from": "0x9010"}],
                },
                anchor={"function_entry": "0x9000"},
            )
        )
        task.strategy_snapshot = {
            "dynamic_planning": {
                "action_history": [
                    {
                        "tool_name": "ghidra-headless",
                        "action_type": "GET_XREFS_TO",
                        "target_artifact_id": artifact.id,
                        "priority": 1,
                        "reason": "recover cited xref",
                        "evidence_ids": ["zz-target-evidence"],
                        "target_selector": {"target": "GetProcAddress"},
                        "expected_evidence_kinds": ["xref"],
                        "success_condition": "new_targeted_evidence",
                    }
                ]
            }
        }
        task_id = task.id

    service._run_investigation_loop(task_id, model_actions_only=True)

    with database.session_factory() as session:
        rows = list(session.query(Evidence).filter(Evidence.task_id == task_id, Evidence.module == "investigation"))
        actions = list(session.query(InvestigationActionRecord).filter(InvestigationActionRecord.task_id == task_id))
    assert any(row.kind == "function_call" for row in rows)
    action = next(item for item in actions if item.action_type == "GET_XREFS_TO")
    assert action.status == "SUCCEEDED"
    assert action.result_evidence_ids
    assert action.parameters["_source_evidence_ids"] == ["zz-target-evidence"]


def test_entry_selector_resolves_to_pe_entry_rva(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(task_id="task-entry", artifact_id="artifact-entry", tool_name="ghidra", tool_version="1", status="SUCCEEDED")
    context = Evidence(
        id="entry-context", task_id="task-entry", artifact_id="artifact-entry", tool_run_id=run.id,
        module="static", kind="function_context", nature="STATIC_OBSERVED",
        value={"name": "entry_function", "entry": "140001420", "entry_rva": 5152, "call_targets": [{"target_name": "CreateProcessW", "from": "140001430"}]},
        anchor={"function_entry": "140001420"},
    )
    action = ActionSpec(
        id="entry-action", action_type=ActionType.GET_CALLEES, thread_id="thread-entry",
        hypothesis_id="hyp-entry", artifact_id="artifact-entry", target_selector={"target": "entry"},
    )
    rows = service._derive_investigation_observations([context], action, pe_summary={"entry_rva": 5152})
    assert rows
    assert rows[0]["value"]["callee"] == "CreateProcessW"


def test_entry_selector_resolves_image_base_plus_rva_without_entry_rva_field(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(task_id="task-entry-va", artifact_id="artifact-entry-va", tool_name="ghidra", tool_version="1", status="SUCCEEDED")
    context = Evidence(
        id="entry-va-context", task_id="task-entry-va", artifact_id="artifact-entry-va", tool_run_id=run.id,
        module="static", kind="function_context", nature="STATIC_OBSERVED",
        value={"name": "entry_function", "entry": "0x140001420", "call_targets": [{"target_name": "CreateProcessW", "from": "140001430"}]},
        anchor={"function_entry": "0x140001420"},
    )
    decoy = Evidence(
        id="decoy-111c", task_id="task-entry-va", artifact_id="artifact-entry-va", tool_run_id=run.id,
        module="static", kind="function_context", nature="STATIC_OBSERVED",
        value={"name": "tiny", "entry": "0x111c", "entry_rva": 0x111c, "call_targets": [{"target_name": "TlsSetValue", "from": "0x1120"}]},
        anchor={"function_entry": "0x111c"},
    )
    action = ActionSpec(
        id="entry-va-action", action_type=ActionType.GET_CALLEES, thread_id="thread-entry-va",
        hypothesis_id="hyp-entry-va", artifact_id="artifact-entry-va", target_selector={"target": "entrypoint"},
    )
    rows = service._derive_investigation_observations(
        [decoy, context],
        action,
        pe_summary={"entry_rva": 5152, "image_base": 0x140000000},
    )
    assert rows
    callees = [row["value"].get("callee") for row in rows if isinstance(row.get("value"), dict)]
    assert "CreateProcessW" in callees
    assert "TlsSetValue" not in callees


def test_get_decompile_numeric_export_does_not_absorb_pe_entry(test_settings) -> None:
    """A VA/export selector must decompile that function, not the PE entry that jumps to it."""
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(
        task_id="task-export-decompile",
        artifact_id="artifact-export-decompile",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    entry = Evidence(
        id="entry-thunk",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "entry",
            "entry": "0x1800074D0",
            "entry_rva": 0x74D0,
            "call_targets": [
                {
                    "from": "0x1800074D0",
                    "target_name": "dll_u",
                    "to": "0x1800012C0",
                    "consumer_kind": "JUMP",
                }
            ],
        },
        anchor={"function_entry": "0x1800074D0", "rva": "0x74D0"},
    )
    export = Evidence(
        id="export-dll-u",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "dll_u",
            "entry": "0x1800012C0",
            "entry_rva": 0x12C0,
            "call_targets": [{"from": "0x1800012C8", "target_name": "GetProcAddress"}],
        },
        anchor={"function_entry": "0x1800012C0", "rva": "0x12C0"},
    )
    action = ActionSpec(
        id="decompile-export",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-export",
        hypothesis_id="hyp-export",
        artifact_id=run.artifact_id,
        target_selector={"target": "0x1800012c0"},
    )
    rows = service._derive_investigation_observations(
        [entry, export],
        action,
        pe_summary={"entry_rva": 0x74D0, "image_base": 0x180000000},
    )
    slice_row = next(item for item in rows if item["kind"] == "decompile_slice")
    function = slice_row["value"]["function"]
    assert str(function.get("entry") or "").casefold() in {"0x1800012c0", "1800012c0"}
    assert str(function.get("name") or "") == "dll_u"
    assert str(function.get("thunk_from") or "").casefold() not in {"0x1800074d0", "1800074d0"}
    callees = [str(item.get("target_name") or "") for item in function.get("call_targets") or []]
    assert "GetProcAddress" in callees
    assert "dll_u" not in callees


def test_get_decompile_named_export_does_not_use_caller_that_mentions_it(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(
        task_id="task-named-export",
        artifact_id="artifact-named-export",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    entry = Evidence(
        id="entry-mentions-export",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "DllMain",
            "entry": "0x1800074D0",
            "call_targets": [{"target_name": "dll_u", "to": "0x1800012C0", "consumer_kind": "JUMP"}],
        },
        anchor={"function_entry": "0x1800074D0"},
    )
    export = Evidence(
        id="named-export",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "dll_u",
            "entry": "0x1800012C0",
            "call_targets": [{"target_name": "LoadLibraryW"}],
        },
        anchor={"function_entry": "0x1800012C0"},
    )
    action = ActionSpec(
        id="decompile-named",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-named",
        hypothesis_id="hyp-named",
        artifact_id=run.artifact_id,
        target_selector={"target": "dll_u"},
    )
    rows = service._derive_investigation_observations([entry, export], action)
    function = next(item for item in rows if item["kind"] == "decompile_slice")["value"]["function"]
    assert function["name"] == "dll_u"
    assert "LoadLibraryW" in [str(item.get("target_name") or "") for item in function.get("call_targets") or []]


def test_get_decompile_follows_unconditional_local_jmp(test_settings) -> None:
    """A PE entry that only jmps to a local function must decompile the real body."""
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(
        task_id="task-tail-jmp",
        artifact_id="artifact-tail-jmp",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    thunk = Evidence(
        id="entry-jmp",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "entry",
            "entry": "0x1800074D0",
            "instructions": [{"address": "0x1800074D0", "text": "jmp FUN_180006FD4"}],
            "call_targets": [
                {
                    "from": "0x1800074D0",
                    "target_name": "FUN_180006FD4",
                    "to": "0x180006FD4",
                    "consumer_kind": "JUMP",
                }
            ],
        },
        anchor={"function_entry": "0x1800074D0"},
    )
    body = Evidence(
        id="real-dllmain",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "FUN_180006FD4",
            "entry": "0x180006FD4",
            "call_targets": [{"from": "0x180007010", "target_name": "CreateThread"}],
        },
        anchor={"function_entry": "0x180006FD4"},
    )
    action = ActionSpec(
        id="decompile-entry",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-jmp",
        hypothesis_id="hyp-jmp",
        artifact_id=run.artifact_id,
        target_selector={"target": "entry"},
    )
    rows = service._derive_investigation_observations(
        [thunk, body],
        action,
        pe_summary={"entry_rva": 0x74D0, "image_base": 0x180000000},
    )
    summary = next(item for item in rows if item["kind"] == "function_semantic_summary")["value"]
    apis = [str(item.get("api") or "") for item in summary.get("call_sequence") or []]
    assert "CreateThread" in apis


def test_decompile_action_projects_legacy_call_targets_into_abstract_execution(test_settings) -> None:
    """The real investigation seam must recover API steps from legacy context rows."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-legacy-abstract",
        artifact_id="artifact-legacy-abstract",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    context = Evidence(
        id="legacy-context",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "loader",
            "entry": "0x401000",
            "call_targets": [
                {"from": "0x401010", "target_name": "VirtualAlloc"},
                {"from": "0x401020", "target_name": "WriteProcessMemory"},
                {"from": "0x401030", "target_name": "VirtualProtect"},
                {"from": "0x401040", "target_name": "CreateThread"},
            ],
        },
        anchor={"function_entry": "0x401000"},
    )
    window = Evidence(
        id="legacy-window",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_instruction_window",
        nature="STATIC_OBSERVED",
        value={"instructions": [{"address": "0x401010", "text": "CALL VirtualAlloc"}]},
        anchor={"function_entry": "0x401000"},
    )
    action = ActionSpec(
        id="legacy-decompile-action",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-legacy-abstract",
        hypothesis_id="hyp-legacy-abstract",
        artifact_id=run.artifact_id,
        target_selector={"target": "0x401000"},
    )

    observations = service._derive_investigation_observations([context, window], action)

    trace = next(item["value"] for item in observations if item["kind"] == "abstract_execution_trace")
    assert [step["api"] for step in trace["steps"] if step["api"]] == [
        "VirtualAlloc",
        "WriteProcessMemory",
        "VirtualProtect",
        "CreateThread",
    ]
    assert any(item["kind"] == "memory_loader" for item in trace["mechanism_candidates"])


def test_get_callers_matches_ghidra_function_symbol_to_rva_selector(test_settings) -> None:
    """Caller lookup must bridge FUN_<RVA> symbols and canonical RVA targets."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-callers-alias",
        artifact_id="artifact-callers-alias",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    caller = Evidence(
        id="caller-context",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "FUN_140001000",
            "entry": "140001000",
            "call_targets": [
                {"target_name": "FUN_14000a2c0", "from": "140001030"}
            ],
        },
        anchor={"function_entry": "140001000"},
    )
    action = ActionSpec(
        id="callers-alias-action",
        action_type=ActionType.GET_CALLERS,
        thread_id="thread-callers-alias",
        hypothesis_id="hyp-callers-alias",
        artifact_id=run.artifact_id,
        target_selector={"target": "14000a2c0"},
    )

    rows = service._derive_investigation_observations([caller], action)

    assert rows
    assert rows[0]["kind"] == "function_call"
    assert rows[0]["value"]["callee"] == "FUN_14000a2c0"
    assert rows[0]["value"]["caller"] == "FUN_140001000"


def test_get_callers_expands_from_cited_target_to_sibling_caller_context(test_settings) -> None:
    """A cited target function must still recover callers stored in sibling rows."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-callers-cited-target",
        artifact_id="artifact-callers-cited-target",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    target = Evidence(
        id="target-context",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={"name": "FUN_14000a2c0", "entry": "14000a2c0", "call_targets": []},
        anchor={"type": "function_context", "function_entry": "14000a2c0", "rva": 41664},
    )
    caller = Evidence(
        id="caller-context-sibling",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "FUN_140001000",
            "entry": "140001000",
            "call_targets": [{"target_name": "FUN_14000a2c0", "from": "140001030"}],
        },
        anchor={"type": "function_context", "function_entry": "140001000", "rva": 4096},
    )
    action = ActionSpec(
        id="callers-cited-target-action",
        action_type=ActionType.GET_CALLERS,
        thread_id="thread-callers-cited-target",
        hypothesis_id="hyp-callers-cited-target",
        artifact_id=run.artifact_id,
        target_selector={"target": "14000a2c0"},
        source_evidence_ids=(target.id,),
    )

    rows = service._derive_investigation_observations([target, caller], action)

    assert rows
    assert rows[0]["value"]["callee"] == "FUN_14000a2c0"
    assert rows[0]["value"]["caller"] == "FUN_140001000"


def test_trace_return_value_handles_target_row_pairs(test_settings) -> None:
    """TRACE_RETURN_VALUE must consume the executor's (row, text) pairs."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-return",
        artifact_id="artifact-return",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    context = Evidence(
        id="return-context",
        task_id="task-return",
        artifact_id="artifact-return",
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "resolve_api",
            "entry": "0x1000",
            "call_targets": [{"target_name": "resolved_consumer"}],
        },
        anchor={"function_entry": "0x1000"},
    )
    action = ActionSpec(
        id="return-action",
        action_type=ActionType.TRACE_RETURN_VALUE,
        thread_id="thread-return",
        hypothesis_id="hyp-return",
        artifact_id="artifact-return",
        target_selector={"target": "0x1000"},
    )

    rows = service._derive_investigation_observations([context], action)

    value_flow = [item for item in rows if item["kind"] == "value_flow"]
    assert value_flow
    # The target's callee is not proof of a caller consuming its return value.
    assert value_flow[0]["value"]["consumers"] == []
    assert value_flow[0]["value"]["resolved"] is False


def test_investigation_executor_scopes_model_action_to_cited_evidence(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    action = ActionSpec(
        id="action-scope",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-scope",
        hypothesis_id="hypothesis-scope",
        artifact_id="artifact-scope",
        target_selector={"target": "GetProcAddress"},
        source_evidence_ids=("e-cited",),
    )
    run = ToolRun(task_id="task-scope", artifact_id="artifact-scope", tool_name="test", tool_version="1", status="SUCCEEDED")
    cited = Evidence(
        id="e-cited", task_id="task-scope", artifact_id="artifact-scope", tool_run_id=run.id,
        module="static", kind="xref", nature="STATIC_OBSERVED", value={"target_name": "GetProcAddress"}, anchor={},
    )
    unrelated = Evidence(
        id="e-unrelated", task_id="task-scope", artifact_id="artifact-scope", tool_run_id=run.id,
        module="static", kind="function_call", nature="STATIC_OBSERVED", value={"api": "CreateProcessA"}, anchor={},
    )
    rows = service._derive_investigation_observations([cited], action)
    assert rows
    assert all(item["value"]["source_evidence_ids"] == ["e-cited"] for item in rows)
    assert unrelated.id not in {source for item in rows for source in item["value"]["source_evidence_ids"]}


def test_xref_action_derives_static_evidence_from_an_import_indicator(test_settings) -> None:
    """An API import can seed a useful model action without claiming execution."""
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    run = ToolRun(task_id="task-import", artifact_id="artifact-import", tool_name="pe-parser", tool_version="1", status="SUCCEEDED")
    imported = Evidence(
        id="import-getproc",
        task_id="task-import",
        artifact_id="artifact-import",
        tool_run_id=run.id,
        module="loader",
        kind="import_symbol",
        nature="STATIC_OBSERVED",
        value={"indicator": "GetProcAddress", "library": "KERNEL32.dll"},
        anchor={"type": "pe_import"},
    )
    action = ActionSpec(
        id="import-xref",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread-import",
        hypothesis_id="hypothesis-import",
        artifact_id="artifact-import",
        target_selector={"target": "GetProcAddress"},
        source_evidence_ids=("import-getproc",),
    )

    rows = service._derive_investigation_observations([imported], action)

    assert len(rows) == 1
    assert rows[0]["kind"] == "function_call"
    assert rows[0]["value"]["api"] == "GetProcAddress"
    assert rows[0]["value"]["source_evidence_ids"] == ["import-getproc"]
    assert rows[0]["nature"] == "STATIC_DERIVED"


def test_investigation_observations_collapse_equivalent_rows_and_union_provenance(test_settings) -> None:
    """Equivalent static rows yield one semantic observation with all provenance."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-observation-dedupe",
        artifact_id="artifact-observation-dedupe",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    rows = [
        Evidence(
            id="context-a",
            task_id=run.task_id,
            artifact_id=run.artifact_id,
            tool_run_id=run.id,
            module="static",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "resolve_target",
                "entry": "0x1000",
                "call_targets": [{"target_name": "GetProcAddress", "from": "0x1010"}],
            },
            anchor={"function_entry": "0x1000"},
        ),
        Evidence(
            id="context-b",
            task_id=run.task_id,
            artifact_id=run.artifact_id,
            tool_run_id=run.id,
            module="static",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "resolve_target",
                "entry": "0x1000",
                "call_targets": [{"target_name": "GetProcAddress", "from": "0x1010"}],
            },
            anchor={"function_entry": "0x1000"},
        ),
    ]
    action = ActionSpec(
        id="dedupe-observation-action",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-observation-dedupe",
        hypothesis_id="hypothesis-observation-dedupe",
        artifact_id=run.artifact_id,
        target_selector={"target": "0x1000"},
    )

    observations = service._derive_investigation_observations(rows, action)

    calls = [item for item in observations if item["kind"] == "function_call"]
    assert len(calls) == 1
    assert calls[0]["value"]["callee"] == "GetProcAddress"
    assert calls[0]["value"]["source_evidence_ids"] == ["context-a", "context-b"]
    assert calls[0]["value"]["derivation"]["input_evidence_ids"] == [
        "context-a",
        "context-b",
    ]


def test_investigation_observation_dedupe_keeps_distinct_edges_on_one_anchor(test_settings) -> None:
    """Same API at one function must retain distinct call-site semantics."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    run = ToolRun(
        task_id="task-observation-edge-dedupe",
        artifact_id="artifact-observation-edge-dedupe",
        tool_name="ghidra",
        tool_version="1",
        status="SUCCEEDED",
    )
    context = Evidence(
        id="context-edges",
        task_id=run.task_id,
        artifact_id=run.artifact_id,
        tool_run_id=run.id,
        module="static",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={
            "name": "resolve_target",
            "entry": "0x1000",
            "call_targets": [
                {"target_name": "GetProcAddress", "from": "0x1010"},
                {"target_name": "GetProcAddress", "from": "0x1020"},
            ],
        },
        anchor={"function_entry": "0x1000"},
    )
    action = ActionSpec(
        id="edge-dedupe-action",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-edge-dedupe",
        hypothesis_id="hypothesis-edge-dedupe",
        artifact_id=run.artifact_id,
        target_selector={"target": "0x1000"},
    )

    observations = service._derive_investigation_observations([context], action)

    calls = [item for item in observations if item["kind"] == "function_call"]
    assert len(calls) == 2
    assert {item["value"]["edge"]["from"] for item in calls} == {"0x1010", "0x1020"}


def test_selector_anchor_rejects_cross_artifact_citation() -> None:
    assert not AnalysisService._selector_is_anchored_in_evidence(
        {"target": "GetProcAddress"},
        ["e-other"],
        [{"evidence_id": "e-other", "artifact_id": "artifact-other", "value": {"target": "GetProcAddress"}, "anchor": {}}],
        target_artifact_id="artifact-target",
    )


def test_model_action_results_exclude_failed_actions_and_keep_turn_metadata(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-results", title="Model action results"))
        session.flush()
        session.add(ContentBlob(
            sha256="a" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/aa/test-results",
        ))
        task = AnalysisTask(id="task-results", case_id="case-results", lifecycle="RUNNING")
        session.add(task)
        session.flush()
        session.add(Artifact(
            id="artifact",
            task_id=task.id,
            content_sha256="a" * 64,
            logical_path="sample.exe",
            detected_type="pe",
        ))
        session.flush()
        session.add(InvestigationThreadRecord(
            id="thread",
            task_id=task.id,
            artifact_id="artifact",
            question="What is the mechanism?",
        ))
        session.flush()
        session.add(InvestigationHypothesisRecord(
            id="hyp",
            task_id=task.id,
            thread_id="thread",
            statement="A loader is present",
            dimension="loader",
        ))
        session.flush()
        session.add_all([
            InvestigationActionRecord(
                id="action-ok", task_id=task.id, thread_id="thread", hypothesis_id="hyp", artifact_id="artifact",
                action_type="GET_XREFS_TO", target_selector={"target": "GetProcAddress"}, status="SUCCEEDED",
                result_evidence_ids=["e1"], finished_at=utcnow(),
            ),
            InvestigationActionRecord(
                id="action-fail", task_id=task.id, thread_id="thread", hypothesis_id="hyp", artifact_id="artifact",
                action_type="GET_XREFS_TO", target_selector={"target": "LoadLibraryA"}, status="FAILED",
                result_evidence_ids=[],
                parameters={
                    "origin": "model",
                    "_planner_turn_id": "turn-2",
                    "_autopsy": {
                        "category": "TARGET_ERROR",
                        "target_selector": {"target": "LoadLibraryA"},
                        "target": "LoadLibraryA",
                        "dedupe_key": "action-key",
                        "artifact_boundary": "artifact",
                        "next_action": "RESOLVE_TARGET_FROM_ARTIFACT",
                        "reason": "The selector could not be resolved within the artifact scope.",
                    },
                },
                error="NO_NEW_EVIDENCE",
                finished_at=utcnow(),
            ),
        ])
    actions = [
        DynamicPlanAction(
            tool_name="ghidra-headless", action_type="GET_XREFS_TO", target_artifact_id="artifact",
            reason="ok", evidence_ids=["e1"], target_selector={"target": "GetProcAddress"},
            expected_evidence_kinds=["xref"], planner_turn_id="turn-1",
        ),
        DynamicPlanAction(
            tool_name="ghidra-headless", action_type="GET_XREFS_TO", target_artifact_id="artifact",
            reason="failed", evidence_ids=["e1"], target_selector={"target": "LoadLibraryA"},
            expected_evidence_kinds=["xref"], planner_turn_id="turn-2",
        ),
    ]
    results = service._collect_model_action_results(task.id, actions)
    assert len(results) == 2
    succeeded = next(item for item in results if item["status"] == "SUCCEEDED")
    failed = next(item for item in results if item["status"] == "FAILED")
    assert succeeded["planner_turn_id"] == "turn-1"
    assert succeeded["target_selector"] == {"target": "GetProcAddress"}
    assert failed["outcome"] == "NO_NEW_EVIDENCE"
    assert failed["autopsy_category"] == "TARGET_ERROR"
    assert failed["next_action"] == "RESOLVE_TARGET_FROM_ARTIFACT"


def test_model_planner_rejects_investigation_action_without_plan_first_contract(test_settings) -> None:
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({
                "objective": "inspect resolver",
                "actions": [{
                    "tool_name": "ghidra-headless",
                    "action_type": "GET_XREFS_TO",
                    "target_artifact_id": "artifact-plan-required",
                    "priority": 1,
                    "reason": "follow cited resolver",
                    "evidence_ids": ["plan-evidence"],
                    "target_selector": {"target": "GetProcAddress"},
                    "expected_evidence_kinds": ["xref"],
                }],
            })}}]},
        )

    service.model_gateway = ModelGateway(
        settings.primary_model, settings.fallback_model, transport=httpx.MockTransport(handler)
    )
    case = service.create_case("plan contract")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(
            sha256="e" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/e",
        ))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-plan-required",
            task_id=task.id,
            content_sha256="e" * 64,
            logical_path="resolver.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(Evidence(
            id="plan-evidence",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=run.id,
            module="static",
            kind="xref",
            nature="STATIC_OBSERVED",
            value={"target_name": "GetProcAddress"},
            anchor={"function_entry": "0x1000"},
        ))
        task_id = task.id

    actions, _ = service._run_model_planning(
        task_id, [artifact], [artifact.id], phase="plan-contract"
    )

    assert actions == []
    rejected = service.task_view(task_id)["strategy_snapshot"]["dynamic_planning"]["rejected_actions"]
    assert rejected[0]["reason"] == "incomplete_plan_first_contract"


def test_no_new_evidence_action_is_not_replayed_when_later_evidence_arrives(test_settings) -> None:
    """K01: a later Evidence timestamp is not a new input for the same method."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    blob = store.put(b"MZ" + b"\0" * 64)
    with database.session_factory.begin() as session:
        session.add(CaseRecord(id="case-no-gain-dedupe", title="No gain dedupe"))
        session.add(ContentBlob(
            sha256=blob.sha256,
            size=blob.size,
            media_type="application/octet-stream",
            storage_key=blob.storage_key,
        ))
        session.flush()
        task = AnalysisTask(case_id="case-no-gain-dedupe", lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
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
        session.add(Evidence(
            id="seed-import",
            task_id=task.id,
            artifact_id=artifact.id,
            tool_run_id=run.id,
            module="static",
            kind="import_symbol",
            nature="STATIC_OBSERVED",
            value={"indicator": "GetProcAddress", "library": "KERNEL32.dll"},
            anchor={"type": "pe_import"},
        ))
        session.add(InvestigationThreadRecord(
            id="thread-no-gain",
            task_id=task.id,
            artifact_id=artifact.id,
            question="What resolver mechanism is present?",
        ))
        session.flush()
        session.add(InvestigationHypothesisRecord(
            id="hyp-no-gain",
            task_id=task.id,
            thread_id="thread-no-gain",
            statement="The sample resolves APIs dynamically.",
            dimension="dynamic_resolution",
        ))
        session.flush()
        session.add(InvestigationActionRecord(
            id="prior-no-gain",
            task_id=task.id,
            thread_id="thread-no-gain",
            hypothesis_id="hyp-no-gain",
            artifact_id=artifact.id,
            action_type="GET_XREFS_TO",
            target_selector={"target": "LoadLibraryA"},
            expected_evidence_kinds=["xref"],
            status="FAILED",
            error="NO_NEW_EVIDENCE",
            finished_at=utcnow(),
            parameters={"origin": "model"},
        ))
        task.strategy_snapshot = {
            "dynamic_planning": {
                "action_history": [{
                    "tool_name": "ghidra-headless",
                    "action_type": "GET_XREFS_TO",
                    "target_artifact_id": artifact.id,
                    "priority": 1,
                    "reason": "follow resolver",
                    "target_selector": {"target": "LoadLibraryA"},
                    "evidence_ids": ["seed-import"],
                    "expected_evidence_kinds": ["xref"],
                    "success_condition": "new_targeted_evidence",
                }],
            }
        }
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id, model_actions_only=True)
    with database.session_factory() as session:
        rows = list(session.query(InvestigationActionRecord).filter(
            InvestigationActionRecord.task_id == task_id,
            InvestigationActionRecord.action_type == "GET_XREFS_TO",
            InvestigationActionRecord.target_selector == {"target": "LoadLibraryA"},
        ))
    assert len(rows) == 1
    assert rows[0].error == "NO_NEW_EVIDENCE"

    with database.session_factory.begin() as session:
        run = session.query(ToolRun).filter(ToolRun.task_id == task_id).one()
        session.add(Evidence(
            id="new-loadlibrary-evidence",
            task_id=task_id,
            artifact_id=artifact_id,
            tool_run_id=run.id,
            module="static",
            kind="import_symbol",
            nature="STATIC_OBSERVED",
            value={"indicator": "LoadLibraryA", "library": "KERNEL32.dll"},
            anchor={"type": "pe_import"},
        ))

    service._run_investigation_loop(task_id, model_actions_only=True)
    with database.session_factory() as session:
        rows = list(session.query(InvestigationActionRecord).filter(
            InvestigationActionRecord.task_id == task_id,
            InvestigationActionRecord.action_type == "GET_XREFS_TO",
            InvestigationActionRecord.target_selector == {"target": "LoadLibraryA"},
        ))
    assert len(rows) == 1
    assert rows[0].id == "prior-no-gain"
    assert rows[0].error == "NO_NEW_EVIDENCE"


def test_investigation_task_budget_defers_later_seed_threads(test_settings) -> None:
    """Seed fan-out cannot multiply a task into an unbounded action storm."""
    settings = replace(test_settings, investigation_task_max_actions=8)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("task action budget")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="b" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/task-action-budget",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="task-action-budget.exe",
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
        clusters = []
        for index, category in enumerate(("process", "network", "loader", "decode"), start=1):
            entry = f"0x{0x1000 * index:x}"
            context_id = f"budget-context-{index}"
            call_id = f"budget-call-{index}"
            api = {
                "process": "CreateProcessW",
                "network": "WinHttpSendRequest",
                "loader": "LoadLibraryW",
                "decode": "CryptDecrypt",
            }[category]
            session.add_all(
                [
                    Evidence(
                        id=context_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_context",
                        nature="STATIC_OBSERVED",
                        value={"name": f"FUN_{index}", "entry": entry},
                        anchor={"function_entry": entry},
                    ),
                    Evidence(
                        id=call_id,
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=run.id,
                        module="static",
                        kind="function_call",
                        nature="STATIC_OBSERVED",
                        value={"api": api, "function_entry": entry},
                        anchor={"function_entry": entry},
                    ),
                ]
            )
            clusters.append(
                {
                    "id": f"budget-cluster-{category}",
                    "category": category,
                    "priority": index,
                    "question": f"Which {category} path is used?",
                    "evidence_ids": [context_id, call_id],
                }
            )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {artifact.id: {"clusters": clusters}},
            }
        }
        task_id = task.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        task = session.get(AnalysisTask, task_id)
        actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task_id
                )
            )
        )
        threads = list(
            session.scalars(
                select(InvestigationThreadRecord).where(
                    InvestigationThreadRecord.task_id == task_id
                )
            )
        )
    terminal = [item for item in actions if item.status in {"SUCCEEDED", "FAILED", "RUNNING"}]
    investigation = dict((task.strategy_snapshot or {}).get("investigation", {}))
    budget = dict(investigation.get("action_budget", {}))
    events = list((investigation.get("runtime") or {}).get("events", []))
    assert len(terminal) <= 8
    assert budget.get("limit") == 8
    assert budget.get("used", 0) <= 8
    assert budget.get("deferred_count", 0) >= 1
    assert any(item.get("phase") in {"budget_deferred", "budget_exhausted"} for item in events)
    attempted_threads = {item.thread_id for item in terminal}
    assert attempted_threads
    actions_by_thread = {}
    for item in terminal:
        actions_by_thread[item.thread_id] = actions_by_thread.get(item.thread_id, 0) + 1
    equal_share = 8 // max(1, len(threads))
    assert max(actions_by_thread.values()) > equal_share, (
        "Remaining budget must concentrate on the current OPEN seed, not equal-split"
    )

    before = len(actions)
    service._run_investigation_loop(task_id)
    with database.session_factory() as session:
        after = len(
            list(
                session.scalars(
                    select(InvestigationActionRecord).where(
                        InvestigationActionRecord.task_id == task_id
                    )
                )
            )
        )
        rerun_task = session.get(AnalysisTask, task_id)
    rerun_investigation = dict((rerun_task.strategy_snapshot or {}).get("investigation", {}))
    assert after > before, "A fresh bounded pass must advance the deferred frontier"
    assert after - before <= 8
    assert rerun_investigation["action_budget"]["scope"] == "invocation"
    assert rerun_investigation["action_budget"]["used"] <= 8
