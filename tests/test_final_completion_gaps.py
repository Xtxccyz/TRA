from __future__ import annotations

from dataclasses import replace

import httpx

from threat_report_agent.investigation import (
    verify_dynamic_api_mechanism,
    verify_etw_mechanism,
    verify_http_download_mechanism,
    verify_shell_output_mechanism,
)
from threat_report_agent.models import (
    AnalysisTask,
    AnalysisTurnRecord,
    Artifact,
    CaseRecord,
    ContentBlob,
    Evidence,
    MechanismEffectivenessTraceRecord,
    ToolRun,
)
from threat_report_agent.model_gateway import ModelGateway
from threat_report_agent.service import AnalysisService
from threat_report_agent.database import Database
from threat_report_agent.content_store import LocalContentStore


def _settings(test_settings):
    return test_settings


def _service(test_settings):
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    return service


def _row(evidence_id: str, kind: str, value: object, entry: str) -> dict[str, object]:
    return {
        "id": evidence_id,
        "kind": kind,
        "value": value,
        "anchor": {"function_entry": entry, "rva": entry},
    }


def test_mechanism_effectiveness_trace_is_persisted_and_snapshotted(test_settings):
    service = _service(test_settings)
    with service.database.session_factory.begin() as session:
        case = CaseRecord(title="trace persistence")
        session.add(case)
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "mechanisms": [
                        {
                            "id": "mechanism-1",
                            "artifact_id": "artifact-1",
                            "mechanism_type": "DYNAMIC_API_RESOLUTION",
                            "status": "SUPPORTED",
                        }
                    ],
                    "hypotheses": [],
                    "seed_rankings": [],
                }
            },
        )
        session.add(task)
        session.flush()
        session.add(
            ContentBlob(
                sha256="a" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/a",
            )
        )
        session.flush()
        session.add(
            Artifact(
                id="artifact-1",
                task_id=task.id,
                content_sha256="a" * 64,
                logical_path="sample.exe",
                detected_type="pe",
                role="EXECUTABLE",
            )
        )
        session.flush()
        session.add(
            AnalysisTurnRecord(
                task_id=task.id,
                thread_id="thread-1",
                turn_id="turn-1",
                phase="mechanism",
                action_proposals=[
                    {
                        "id": "action-1",
                        "origin": "model",
                        "action_type": "GET_XREFS_TO",
                        "prompt_sha256": "a" * 64,
                        "profile_digest": "b" * 64,
                        "policy_digest": "c" * 64,
                        "action_validation_digest": "d" * 64,
                    }
                ],
                new_evidence_ids=["e-1"],
                mechanism_state="INVESTIGATING",
            )
        )
        session.flush()
        task_id = task.id

    with service.database.session_factory.begin() as session:
        task = session.get(AnalysisTask, task_id)
        service._persist_mechanism_effectiveness_traces(session, task)
        session.flush()
        traces = list(
            session.query(MechanismEffectivenessTraceRecord)
            .filter(MechanismEffectivenessTraceRecord.task_id == task_id)
        )
        snapshot = service._freeze_snapshot(session, task)
        assert len(traces) == 1
        assert traces[0].mechanism_id == "mechanism-1"
        assert traces[0].trace_sha256
        assert traces[0].action_proposals[0]["prompt_sha256"] == "a" * 64
        assert snapshot.object_versions["mechanism_effectiveness_traces"][0]["id"] == traces[0].id


def test_repeated_sample_analysis_persists_effectiveness_traces_per_task(test_settings):
    """A second analysis of the same sample must still finalize instead of UniqueViolation."""
    service = _service(test_settings)
    snapshot = {
        "investigation": {
            "mechanisms": [
                {
                    "id": "mechanism-1",
                    "mechanism_type": "DYNAMIC_API_RESOLUTION",
                    "status": "SUPPORTED",
                }
            ],
            "hypotheses": [],
            "seed_rankings": [],
        }
    }
    with service.database.session_factory.begin() as session:
        case = CaseRecord(title="repeated sample traces")
        session.add(case)
        session.flush()
        first = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot=snapshot)
        second = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot=snapshot)
        session.add_all([first, second])
        session.flush()
        first_id = first.id
        second_id = second.id

    with service.database.session_factory.begin() as session:
        first = session.get(AnalysisTask, first_id)
        second = session.get(AnalysisTask, second_id)
        assert service._persist_mechanism_effectiveness_traces(session, first) >= 1
        assert service._persist_mechanism_effectiveness_traces(session, second) >= 1
        first_rows = list(
            session.query(MechanismEffectivenessTraceRecord).filter(
                MechanismEffectivenessTraceRecord.task_id == first_id
            )
        )
        second_rows = list(
            session.query(MechanismEffectivenessTraceRecord).filter(
                MechanismEffectivenessTraceRecord.task_id == second_id
            )
        )
        assert len(first_rows) == 1
        assert len(second_rows) == 1
        assert first_rows[0].trace_sha256 != second_rows[0].trace_sha256


def test_c1_rejects_unlinked_evidence_rows():
    rows = [
        _row("resolver", "function_call", {"api": "GetProcAddress"}, "0x1000"),
        _row("module", "data_reference", {"name": "plugin.dll", "entry_name": "Init"}, "0x2000"),
        _row("consumer", "function_call", {"api": "FreeLibrary", "consumer": "resolved pointer"}, "0x3000"),
    ]
    assert verify_dynamic_api_mechanism(rows).accepted is False


def test_c2_rejects_unlinked_transport_rows():
    rows = [
        _row("open", "function_call", {"target_function": "WinHttpOpen"}, "0x1000"),
        _row("url", "string", {"text": "https://example.invalid/checkin"}, "0x2000"),
        _row("send", "function_call", {"target_function": "WinHttpSendRequest"}, "0x3000"),
        _row("recv", "function_call", {"target_function": "WinHttpReceiveResponse"}, "0x4000"),
    ]
    assert verify_http_download_mechanism(rows).accepted is False


def test_c3_rejects_unlinked_shell_rows():
    rows = [
        _row("proc", "function_call", {"target_function": "CreateProcessW"}, "0x1000"),
        _row("pipe", "function_call", {"target_function": "CreatePipe"}, "0x2000"),
        _row("read", "function_call", {"target_function": "ReadFile"}, "0x3000"),
    ]
    assert verify_shell_output_mechanism(rows).accepted is False


def test_c4_rejects_unlinked_etw_patch_rows():
    rows = [
        _row("etw", "function_call", {"target_function": "EtwEventWrite"}, "0x1000"),
        _row("vp", "function_call", {"target_function": "VirtualProtect"}, "0x2000"),
        _row("patch", "function_instruction_window", {"bytes": "33 C0 C3"}, "0x3000"),
        _row("flush", "function_call", {"target_function": "FlushInstructionCache"}, "0x4000"),
    ]
    assert verify_etw_mechanism(rows).accepted is False


def test_model_action_has_action_level_provenance(test_settings):
    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    service.database.create_schema()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"objective":"inspect","actions":[{"tool_name":"pe-parser","target_artifact_id":"artifact-provenance","priority":1,"reason":"baseline"}]}'
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    with service.database.session_factory.begin() as session:
        case = CaseRecord(title="action provenance")
        session.add(case)
        session.flush()
        blob = ContentBlob(
            sha256="b" * 64,
            size=2,
            media_type="application/octet-stream",
            storage_key="sha256/b",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-provenance",
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
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="static",
                kind="pe_structure",
                nature="STATIC_OBSERVED",
                value={"format": "PE"},
                anchor={"function_entry": "0x1000"},
                id="provenance-evidence",
            )
        )
        task_id = task.id
        artifact_id = artifact.id

    with service.database.session_factory() as session:
        artifact = session.get(Artifact, artifact_id)
    actions, limitations = service._run_model_planning(
        task_id,
        [artifact],
        [artifact_id],
        phase="provenance",
    )
    assert not limitations
    assert len(actions) == 1
    action = actions[0]
    assert action.prompt_sha256 and len(action.prompt_sha256) == 64
    assert action.profile_digest and len(action.profile_digest) == 64
    assert action.policy_digest and len(action.policy_digest) == 64
    assert action.action_validation_digest and len(action.action_validation_digest) == 64
    assert action.action_validation["allowed"] is True
    with service.database.session_factory() as session:
        turn = session.query(AnalysisTurnRecord).filter_by(task_id=task_id).one()
        recorded = turn.action_proposals[0]
        assert recorded["profile_digest"] == action.profile_digest
        assert recorded["action_validation_digest"] == action.action_validation_digest
        assert turn.policy_decisions[0]["policy_digest"] == action.policy_digest
