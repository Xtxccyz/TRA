import json
from dataclasses import replace

import httpx
from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
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
    AnalysisTurnRecord,
    Claim,
    utcnow,
)
from threat_report_agent.service import AnalysisService
from threat_report_agent.model_gateway import DynamicPlanAction, ModelGateway
from threat_report_agent.investigation import ActionSpec, ActionType


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
                Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_context", nature="STATIC_OBSERVED", value={"name": "spawn", "entry": "0x1000", "call_targets": [{"target_name": "OpenProcess"}, {"target_name": "UpdateProcThreadAttribute"}]}, anchor={}),
                Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_call", nature="STATIC_OBSERVED", value={"api": "OpenProcess"}, anchor={}),
                Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="function_call", nature="STATIC_OBSERVED", value={"api": "UpdateProcThreadAttribute"}, anchor={}),
                Evidence(task_id=task.id, artifact_id=artifact.id, tool_run_id=run.id, module="static", kind="constant", nature="STATIC_OBSERVED", value={"name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS", "value": "0x00020000"}, anchor={}),
            ]
        )
        task_id = task.id
        artifact_id = artifact.id

    service._run_investigation_loop(task_id)

    with database.session_factory() as session:
        threads = session.query(InvestigationThreadRecord).filter_by(task_id=task_id, artifact_id=artifact_id).all()
        assert len(threads) >= 2
        thread = next(item for item in threads if item.seed_kind == "ppid-process-chain")
        hypothesis = session.query(InvestigationHypothesisRecord).filter_by(thread_id=thread.id).one()
        assert thread.seed_kind == "ppid-process-chain"
        assert "parent-process spoofing" in thread.question
        assert hypothesis.dimension == "process_creation"
        assert hypothesis.required_evidence == ["function_call", "constant", "function_context"]
        assert hypothesis.status == "SUPPORTED"


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
    assert {"Which resolver path is used?", "Which entry path consumes it?", "Which loader side effect follows?"}.issubset(
        {thread.question for thread in threads}
    )
    assert {action.thread_id for action in actions} >= {thread.id for thread in threads[:3] if thread.action_ids}


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
    assert rows
    assert any(row.kind == "function_call" for row in rows)
    assert turns
    # The immediate model-action pass produces evidence only; the later full
    # verifier owns Claim creation and therefore cannot duplicate a claim.
    assert claims == []


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
