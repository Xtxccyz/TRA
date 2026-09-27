from __future__ import annotations

from dataclasses import replace

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from threat_report_agent.config import Settings
from threat_report_agent.emulation_plan import (
    controlled_emulation_windows,
    unicorn_granted_windows_for_worker,
)
from threat_report_agent.main import create_app
from threat_report_agent.report.reporting import REPORT_MODULES
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisSnapshot, AnalysisTask, Artifact, Claim, ContentBlob, TaskSecret, ToolRun
from threat_report_agent.intake import IntakeGateRequired, PackageEntry
from threat_report_agent.service import AnalysisService
from threat_report_agent.tools.tool_execution import ToolRunResult


def sample_zip(path: str = "payload.txt") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            path,
            (
                b"http://evil.example.com/api "
                b"VirtualAlloc WriteProcessMemory "
                b"IsDebuggerPresent vmware "
                b"CryptDecrypt AES"
            ),
        )
    return output.getvalue()


def create_case(client: TestClient) -> str:
    response = client.post("/api/v1/cases", json={"title": "Static validation"})
    assert response.status_code == 201
    return response.json()["id"]


def test_meta_exposes_the_frozen_three_mode_preset_catalog(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.get("/api/v1/meta")

    assert response.status_code == 200
    catalog = response.json()["preset_catalog"]
    assert len(catalog["digest"]) == 64
    assert {preset["task_type"] for preset in catalog["presets"]} == {
        "SINGLE_SAMPLE_STATIC_DEEP",
        "FILE_SET_AND_CARRIER",
        "INCIDENT_REPORT_GENERATION",
    }
    required = {
        "id",
        "version",
        "task_type",
        "object_scope",
        "expected_outputs",
        "default_breadth",
        "default_depth",
        "resource_limits",
        "completion_conditions",
        "analysis_modules",
        "tool_names",
    }
    assert all(set(preset) == required for preset in catalog["presets"])


def test_submission_freezes_background_context_provenance(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("context.py", b"print('context')", "text/x-python")},
            data={
                "background_context": "Observed during incident response.",
                "background_source": "ir-ticket-2026-081",
                "background_observed_at": "2026-08-01T09:30:00+08:00",
                "background_confidence": "HIGH",
                "background_human_confirmed": "true",
            },
        )

        assert submitted.status_code == 202, submitted.text
        task = client.get(f"/api/v1/tasks/{submitted.json()['task_id']}").json()

    assert task["request_snapshot"]["background_context"] == {
        "content": "Observed during incident response.",
        "source": "ir-ticket-2026-081",
        "observed_at": "2026-08-01T09:30:00+08:00",
        "confidence": "HIGH",
        "human_confirmed": True,
        "version": "1.0",
        "trust_zone": "untrusted_background",
    }


def test_multiple_uploaded_files_are_analyzed_as_one_traceable_batch(
    test_settings: Settings,
) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files=[
                ("sample", ("network.py", b"import socket\nsocket.create_connection(('x', 1))", "text/x-python")),
                ("sample", ("loader.py", b"import base64\nbase64.b64decode('YQ==')", "text/x-python")),
            ],
        )
        assert submitted.status_code == 202, submitted.text
        task = client.get(f"/api/v1/tasks/{submitted.json()['task_id']}").json()

    assert task["lifecycle"] == "SUCCEEDED"
    assert task["outcome"] == "PARTIAL"
    assert len(task["artifacts"]) == 3  # root batch archive plus two submitted files
    assert {item["logical_path"].split("!/")[-1] for item in task["artifacts"]} >= {
        "network.py",
        "loader.py",
    }
    container_ids = {
        item["id"] for item in task["artifacts"] if item["role"] == "CONTAINER"
    }
    profile_rows = [item for item in task["evidence"] if item["kind"] == "analysis_profile"]
    assert profile_rows
    assert all(item["artifact_id"] not in container_ids for item in profile_rows)
    assert {item["module"] for item in task["claims"]} >= {"c2_network", "decryption"}
    assert all(
        any(link["claim_id"] == claim["id"] for link in task["claim_evidence"])
        for claim in task["claims"]
    )


def test_task_status_is_a_bounded_polling_projection(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("status.py", b"print('status')", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        status = client.get(f"/api/v1/tasks/{task_id}/status")

    assert status.status_code == 200, status.text
    payload = status.json()
    assert payload["id"] == task_id
    assert payload["lifecycle"] in {"SUCCEEDED", "FAILED", "CANCELLED", "WAITING_GATE", "PAUSED"}
    assert payload["evidence_count"] >= 1
    assert "evidence" not in payload
    assert "claims" not in payload


def test_script_calls_are_promoted_to_evidence_backed_behavior_claims(
    test_settings: Settings,
) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    case = service.create_case("script behavior analysis")
    result = service.analyze_submission(
        case_id=case.id,
        filename="stage.py",
        content=(
            b"import socket\nimport subprocess\nimport base64\n"
            b"socket.create_connection(('x', 1))\n"
            b"subprocess.Popen('whoami', shell=True)\n"
            b"base64.b64decode('YQ==')\n"
        ),
    )
    task = service.task_view(result.task_id)
    modules = {item["module"] for item in task["claims"]}
    assert {"c2_network", "execution", "decryption"} <= modules
    assert all(item["nature"] == "STATIC_INFERRED" for item in task["claims"])
    evidence_ids = {item["id"] for item in task["evidence"]}
    linked = {
        item["evidence_id"] for item in task["claim_evidence"]
    }
    assert linked <= evidence_ids


def test_report_recomposition_uses_frozen_snapshot_content(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("bundle.zip", sample_zip(), "application/zip")},
        )
        task = client.get(f"/api/v1/tasks/{submitted.json()['task_id']}").json()
        original = client.get(f"/api/v1/reports/{task['latest_report_revision_id']}").json()
        frozen_loader = next(
            module for module in original["document"]["modules"] if module["id"] == "loader"
        )

        with app.state.database.session_factory.begin() as session:
            claim = (
                session.query(Claim)
                .filter(Claim.task_id == task["id"], Claim.module == "loader")
                .first()
            )
            assert claim is not None
            claim.statement = "LIVE DATABASE MUTATION MUST NOT ENTER A FROZEN REPORT"

        recomposed = client.post(
            f"/api/v1/tasks/{task['id']}/reports",
            json={"modules": ["loader"]},
        )

    assert recomposed.status_code == 201, recomposed.text
    assert recomposed.json()["document"]["modules"] == [frozen_loader]
    assert recomposed.json()["snapshot_id"] == original["snapshot_id"]


def test_end_to_end_static_analysis_and_report_revisions(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        response = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("bundle.zip", sample_zip(), "application/zip")},
            data={
                "background_context": "Submitted by the incident response team.",
                "selected_modules": "[]",
            },
        )
        assert response.status_code == 202, response.text
        submission = response.json()
        assert submission["lifecycle"] == "PENDING"
        assert submission["outcome"] is None
        task_id = submission["task_id"]

        task = client.get(f"/api/v1/tasks/{task_id}").json()
        assert task["lifecycle"] == "SUCCEEDED"
        assert task["outcome"] == "PARTIAL"
        assert len(task["artifacts"]) == 2
        assert {item["module"] for item in task["claims"]} == {
            "decryption",
            "loader",
            "c2_network",
            "anti_analysis",
        }
        assert all("artifact_id" in item["anchor"] for item in task["evidence"])
        assert set(task["request_snapshot"]) == {
            "task_request",
            "sample_package",
            "background_context",
            "knowledge_snapshot",
        }
        assert task["strategy_snapshot"]["preset"]["id"] == "first-phase-full-static"
        assert len(task["strategy_snapshot"]["preset"]["catalog_digest"]) == 64
        assert task["strategy_snapshot"]["tool_policy_version"] == "1.0.0"
        assert task["strategy_snapshot"]["prompt_versions"] == {
            "static-analysis-agent": "1.0.0",
            "triage-agent": "1.0.0",
        }
        assert task["strategy_snapshot"]["orchestration_stages"] == [
            "validate_inputs",
            "schedule_intake",
            "schedule_triage",
            "schedule_static_modules",
            "finalize",
        ]
        audit = client.get(f"/api/v1/tasks/{task_id}/audit")
        assert audit.status_code == 200
        audit_events = audit.json()
        assert {event["event_type"] for event in audit_events} >= {
            "analysis_task.created",
            "orchestration.plan_created",
            "tool_run.completed",
            "evidence.recorded",
            "claim.created",
            "report.generated",
        }
        assert len({event["trace_id"] for event in audit_events}) == 1
        assert [event["chain_sequence"] for event in audit_events] == list(
            range(1, len(audit_events) + 1)
        )
        assert audit_events[0]["previous_hash"] == "0" * 64
        assert all(len(event["event_hash"]) == 64 for event in audit_events)
        integrity = client.get(f"/api/v1/tasks/{task_id}/audit/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["valid"] is True
        assert integrity.json()["seals"]

        report_id = task["latest_report_revision_id"]
        report = client.get(f"/api/v1/reports/{report_id}").json()
        assert report["selected_modules"] == list(REPORT_MODULES)
        attribution = next(item for item in report["document"]["modules"] if item["id"] == "attribution")
        profiles = [row for row in attribution["rows"] if row.get("type") == "analysis_profile"]
        assert profiles
        profile = profiles[0]["profile"]
        assert set(profile["dimension_coverage"]) >= {
            "loading_chain", "cryptography", "c2_design", "anti_analysis", "build_system", "codenames"
        }
        assert profile["assessment"]["actual_verdict"] in {
            "EXCLUDE_NSA", "POSSIBLE_MATCH", "INCONCLUSIVE"
        }
        assert "评测基准报告" in report["markdown"]

        before_evidence = len(task["evidence"])
        recomposed = client.post(
            f"/api/v1/tasks/{task_id}/reports",
            json={"modules": ["executive_summary", "c2_network", "limitations"]},
        )
        assert recomposed.status_code == 201, recomposed.text
        recomposed_json = recomposed.json()
        assert recomposed_json["selected_modules"] == [
            "executive_summary",
            "c2_network",
            "limitations",
        ]
        assert recomposed_json["parent_revision_id"] == report_id
        after_task = client.get(f"/api/v1/tasks/{task_id}").json()
        assert len(after_task["evidence"]) == before_evidence
        assert client.get(f"/api/v1/tasks/{task_id}/audit/integrity").json()["valid"] is True

        edited = client.post(
            f"/api/v1/reports/{recomposed_json['id']}/edits",
            json={"markdown": recomposed_json["markdown"] + "\n人工复核备注。\n"},
        )
        assert edited.status_code == 201
        assert edited.json()["edit_kind"] == "MANUAL_EDIT"
        assert edited.json()["parent_revision_id"] == recomposed_json["id"]

        package = client.get(f"/api/v1/tasks/{task_id}/analysis-package")
        assert package.status_code == 200
        assert package.json()["selected_modules"] == list(REPORT_MODULES)

        docx = client.get(f"/api/v1/reports/{report_id}/download?format=docx")
        pdf = client.get(f"/api/v1/reports/{report_id}/download?format=pdf")
        assert docx.status_code == 200
        assert docx.content.startswith(b"PK")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")


def test_unsafe_archive_opens_input_gate(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        response = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("unsafe.zip", sample_zip("../escape.bin"), "application/zip")},
        )

        assert response.status_code == 202
        submission = response.json()
        assert submission["lifecycle"] == "PENDING"
        assert submission["outcome"] is None
        task = client.get(f"/api/v1/tasks/{submission['task_id']}").json()
        assert task["lifecycle"] == "WAITING_GATE"
        assert task["gates"][0]["type"] == "INPUT_REVIEW"
        assert task["gates"][0]["status"] == "PENDING"


def test_task_cancel_endpoint_persists_cancelled_lifecycle(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        with app.state.database.session_factory.begin() as session:
            task = AnalysisTask(case_id=case_id, lifecycle="PENDING")
            session.add(task)
            session.flush()
            task_id = task.id

        response = client.post(f"/api/v1/tasks/{task_id}/cancel")

        assert response.status_code == 200
        assert response.json()["lifecycle"] == "CANCELLED"


def test_tool_run_cancel_endpoint_keeps_task_running(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        with app.state.database.session_factory.begin() as session:
            task = AnalysisTask(case_id=case_id, lifecycle="RUNNING")
            session.add(task)
            session.flush()
            run = ToolRun(
                task_id=task.id,
                artifact_id=None,
                tool_name="controlled-emulator",
                tool_version="0.1.0",
                status="RUNNING",
                parameters={},
                environment={"workflow_id": "toolrun-api-cancel"},
            )
            session.add(run)
            session.flush()
            task_id = task.id
            tool_run_id = run.id

        response = client.post(f"/api/v1/tasks/{task_id}/tool-runs/{tool_run_id}/cancel")

        assert response.status_code == 200
        body = response.json()
        assert body["lifecycle"] == "RUNNING"
        assert body["cancelled_tool_run_id"] == tool_run_id
        assert body["tool_runs"][0]["status"] == "CANCELLED"


def test_retention_routes_expose_archive_daily_seal_and_purge_gate(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("sample.py", b"print(1)", "text/x-python")},
        )
        task_id = submitted.json()["task_id"]
        archived = client.post(
            f"/api/v1/cases/{case_id}/archive",
            json={"actor": "reviewer"},
        )
        assert archived.status_code == 200, archived.text
        assert archived.json()["status"] == "ARCHIVED"

        audit = client.get(f"/api/v1/tasks/{task_id}/audit").json()
        utc_day = audit[0]["created_at"][:10]
        sealed = client.post(
            "/api/v1/audit/daily-seals",
            json={"utc_day": utc_day, "actor": "scheduler"},
        )
        assert sealed.status_code == 200, sealed.text
        assert sealed.json()["created"] >= 1

        requested = client.post(
            f"/api/v1/cases/{case_id}/evidence-purge-requests",
            json={"requested_by": "requester", "reason": "retention policy"},
        )
        assert requested.status_code == 201, requested.text
        request_id = requested.json()["id"]
        reviewed = client.post(
            f"/api/v1/evidence-purge-requests/{request_id}/review",
            json={"reviewer": "reviewer", "approve": True},
        )
        assert reviewed.status_code == 200, reviewed.text
        executed = client.post(
            f"/api/v1/evidence-purge-requests/{request_id}/execute",
            json={"admin": "admin"},
        )
        assert executed.status_code == 200, executed.text
        assert executed.json()["status"] == "EXECUTED"


def test_ooxml_embedded_object_is_materialized_as_child_artifact(test_settings: Settings) -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types />")
        archive.writestr("word/document.xml", b"<w:document />")
        archive.writestr("word/embeddings/oleObject1.bin", b"embedded-object")

    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        response = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("carrier.docx", content.getvalue(), "application/octet-stream")},
        )
        assert response.status_code == 202, response.text
        task = client.get(f"/api/v1/tasks/{response.json()['task_id']}").json()

    children = [item for item in task["artifacts"] if item["role"] == "EMBEDDED_OBJECT"]
    assert len(children) == 1
    assert children[0]["parent_artifact_id"] == task["artifacts"][0]["id"]
    assert any(
        item["kind"] == "embedded_artifact"
        and item["value"]["child_artifact_id"] == children[0]["id"]
        for item in task["evidence"]
    )
    assert any(
        item["relation_type"] == "EXTRACTED_FROM"
        and item["target_artifact_id"] == children[0]["id"]
        for item in task["relations"]
    )
    assert any(
        item["relation_type"] == "CONTAINS" and item["target_artifact_id"] == children[0]["id"]
        for item in task["relations"]
    )


def test_submission_api_is_asynchronous_and_idempotent(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        sample = b"print('queued')"
        request = {
            "files": {"sample": ("sample.py", sample, "text/x-python")},
            "headers": {"Idempotency-Key": "submission-001"},
        }

        first = client.post(f"/api/v1/cases/{case_id}/tasks", **request)
        replay = client.post(f"/api/v1/cases/{case_id}/tasks", **request)

        assert first.status_code == 202
        assert first.json()["lifecycle"] == "PENDING"
        assert replay.status_code == 202
        assert replay.json()["task_id"] == first.json()["task_id"]
        task = client.get(f"/api/v1/tasks/{first.json()['task_id']}").json()
        assert task["lifecycle"] == "SUCCEEDED"
        assert task["target_granularity"] == {"breadth": "B0", "depth": "D3"}
        assert task["actual_granularity"]["breadth"] == "B0"
        assert task["actual_granularity"]["depth"] == "D3"
        assert isinstance(task["actual_granularity"]["unmet_reasons"], list)
        sample_package = task["request_snapshot"]["sample_package"]
        assert sample_package["content_sha256"] == hashlib.sha256(sample).hexdigest()
        assert (
            LocalContentStore(test_settings.content_store_path).read(sample_package["storage_key"])
            == sample
        )
        mismatch = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("sample.py", b"print('different')", "text/x-python")},
            headers={"Idempotency-Key": "submission-001"},
        )
        assert mismatch.status_code == 422
        assert "different sample content" in mismatch.json()["detail"]


def test_encrypted_zip_gate_accepts_a_separate_secret_and_resumes(
    test_settings: Settings,
) -> None:
    encrypted_zip = base64.b64decode(
        "UEsDBAoACQAAAM+sAl0I+HzjHgAAABIAAAAIAKQAc3RhZ2UucHlTRI8AEAEAAAAIAM8cOQ9j"
        "ZGBpEWFgYDBggAAfIGZkBTNZRYFExz7xmulfw3/cCuC4/4oZtxwjEwMDE8MRBjaQrIAKw39"
        "GYRS1By1ahT5Pyt0f1P3xmt4BozJsapDNe8OM3ZzCkh3l8isOvNJIFr36rUB/LYOACFCNPA"
        "MjI0SNENh+CYgYE0RMAUgoMMHMk8frPwBVVA0AB1VIb2pVSG9qVUhvaiCy3W7wZHzCgbkd"
        "AVP4591WupRKJEJj+l/3CPLZ3VBLBwgI+HzjHgAAABIAAABQSwECHwAKAAkAAADPrAJdCPh8"
        "4x4AAAASAAAACAARAAAAAAABACAAAAAAAAAAc3RhZ2UucHlTRAQAEAEAAFVUBQAHVUhvalBL"
        "BQYAAAAAAQABAEcAAAD4AAAAAAA="
    )
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("encrypted.zip", encrypted_zip, "application/zip")},
        )
        task_id = submitted.json()["task_id"]
        waiting = client.get(f"/api/v1/tasks/{task_id}").json()
        gate_id = waiting["gates"][0]["id"]

        resumed = client.post(
            f"/api/v1/gates/{gate_id}/decision",
            json={"decision": "APPROVE", "archive_password": "infected"},
        )

        assert waiting["lifecycle"] == "WAITING_GATE"
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["lifecycle"] == "SUCCEEDED"
        assert resumed.json()["gates"][0]["status"] == "APPROVED"
        serialized_task = json.dumps(resumed.json(), ensure_ascii=False)
        serialized_audit = json.dumps(
            client.get(f"/api/v1/tasks/{task_id}/audit").json(),
            ensure_ascii=False,
        )
        assert "infected" not in serialized_task
        assert "infected" not in serialized_audit


def test_encrypted_zip_gate_rejects_wrong_password_without_stranding_task(
    test_settings: Settings,
) -> None:
    encrypted_zip = base64.b64decode(
        "UEsDBAoACQAAAM+sAl0I+HzjHgAAABIAAAAIAKQAc3RhZ2UucHlTRI8AEAEAAAAIAM8cOQ9j"
        "ZGBpEWFgYDBggAAfIGZkBTNZRYFExz7xmulfw3/cCuC4/4oZtxwjEwMDE8MRBjaQrIAKw39"
        "GYRS1By1ahT5Pyt0f1P3xmt4BozJsapDNe8OM3ZzCkh3l8isOvNJIFr36rUB/LYOACFCNPA"
        "MjI0SNENh+CYgYE0RMAUgoMMHMk8frPwBVVA0AB1VIb2pVSG9qVUhvaiCy3W7wZHzCgbkd"
        "AVP4591WupRKJEJj+l/3CPLZ3VBLBwgI+HzjHgAAABIAAABQSwECHwAKAAkAAADPrAJdCPh8"
        "4x4AAAASAAAACAARAAAAAAABACAAAAAAAAAAc3RhZ2UucHlTRAQAEAEAAFVUBQAHVUhvalBL"
        "BQYAAAAAAQABAEcAAAD4AAAAAAA="
    )
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("encrypted.zip", encrypted_zip, "application/zip")},
        )
        task_id = submitted.json()["task_id"]
        gate_id = client.get(f"/api/v1/tasks/{task_id}").json()["gates"][0]["id"]

        rejected = client.post(
            f"/api/v1/gates/{gate_id}/decision",
            json={"decision": "APPROVE", "archive_password": "wrong-password"},
        )
        waiting = client.get(f"/api/v1/tasks/{task_id}").json()
        audit = client.get(f"/api/v1/tasks/{task_id}/audit").json()

        assert rejected.status_code == 409
        assert waiting["lifecycle"] == "WAITING_GATE"
        assert waiting["gates"][0]["status"] == "PENDING"
        assert audit[-1]["event_type"] == "gate.approval_failed"
        assert "wrong-password" not in json.dumps(audit)
        with app.state.database.session_factory() as session:
            attempted_secret = session.query(TaskSecret).filter(TaskSecret.task_id == task_id).one()
            assert attempted_secret.consumed_at is not None

        resumed = client.post(
            f"/api/v1/gates/{gate_id}/decision",
            json={"decision": "APPROVE", "archive_password": "infected"},
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["lifecycle"] == "SUCCEEDED"


def test_progress_events_metrics_and_trace_id_are_exposed(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("sample.py", b"print('trace')", "text/x-python")},
        )
        task_id = submitted.json()["task_id"]
        trace_id = submitted.headers["x-trace-id"]

        progress = client.get(f"/api/v1/tasks/{task_id}/events?after_sequence=0")
        metrics = client.get("/metrics")
        task = client.get(f"/api/v1/tasks/{task_id}").json()

        assert progress.status_code == 200
        assert progress.json()["events"]
        assert progress.json()["next_sequence"] >= 1
        assert task["trace_id"] == trace_id
        assert metrics.status_code == 200
        assert "threat_report_http_requests_total" in metrics.text
        assert "threat_report_http_request_duration_seconds" in metrics.text


def test_local_folder_uses_same_analysis_chain(test_settings: Settings, tmp_path) -> None:
    sample_dir = tmp_path / "white-elephant-subset"
    (sample_dir / "nested").mkdir(parents=True)
    (sample_dir / "loader.txt").write_bytes(b"VirtualAlloc CryptDecrypt")
    (sample_dir / "nested" / "config.txt").write_bytes(b"http://evil.example.com")
    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    case = service.create_case("Folder validation")

    result = service.analyze_directory(case_id=case.id, directory=sample_dir)
    task = service.task_view(result.task_id)

    assert result.lifecycle == "SUCCEEDED"
    assert result.outcome == "PARTIAL"
    assert len(task["artifacts"]) == 2
    assert {item["logical_path"] for item in task["artifacts"]} == {
        "white-elephant-subset/loader.txt",
        "white-elephant-subset/nested/config.txt",
    }
    assert task["request_snapshot"]["sample_package"]["source_kind"] == "local_folder"


def test_temporal_folder_preflight_blocks_global_limit_before_worker(
    test_settings: Settings,
    tmp_path,
    monkeypatch,
) -> None:
    settings = replace(
        test_settings,
        tool_execution_mode="temporal",
        max_sample_files=3,
    )
    sample_dir = tmp_path / "temporal-folder"
    sample_dir.mkdir()
    (sample_dir / "first.zip").write_bytes(sample_zip("first.txt"))
    (sample_dir / "second.zip").write_bytes(sample_zip("second.txt"))

    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(
        settings,
        database,
        LocalContentStore(settings.content_store_path),
    )
    calls: list[str] = []

    def unexpected_worker_call(*args, **kwargs):
        calls.append(str(args[1]))
        raise AssertionError("directory preflight should gate before Worker dispatch")

    monkeypatch.setattr(service, "_execute_intake_tool", unexpected_worker_call)
    case = service.create_case("Temporal folder preflight")

    result = service.analyze_directory(case_id=case.id, directory=sample_dir)

    assert result.lifecycle == "WAITING_GATE"
    assert result.gate_id is not None
    assert calls == []


def test_local_folder_gate_replays_all_siblings_after_password_approval(
    test_settings: Settings,
    tmp_path,
) -> None:
    encrypted_zip = base64.b64decode(
        "UEsDBAoACQAAAM+sAl0I+HzjHgAAABIAAAAIAKQAc3RhZ2UucHlTRI8AEAEAAAAIAM8cOQ9j"
        "ZGBpEWFgYDBggAAfIGZkBTNZRYFExz7xmulfw3/cCuC4/4oZtxwjEwMDE8MRBjaQrIAKw39"
        "GYRS1By1ahT5Pyt0f1P3xmt4BozJsapDNe8OM3ZzCkh3l8isOvNJIFr36rUB/LYOACFCNPA"
        "MjI0SNENh+CYgYE0RMAUgoMMHMk8frPwBVVA0AB1VIb2pVSG9qVUhvaiCy3W7wZHzCgbkd"
        "AVP4591WupRKJEJj+l/3CPLZ3VBLBwgI+HzjHgAAABIAAABQSwECHwAKAAkAAADPrAJdCPh8"
        "4x4AAAASAAAACAARAAAAAAABACAAAAAAAAAAc3RhZ2UucHlTRAQAEAEAAFVUBQAHVUhvalBL"
        "BQYAAAAAAQABAEcAAAD4AAAAAAA="
    )
    sample_dir = tmp_path / "folder-with-gate"
    sample_dir.mkdir()
    (sample_dir / "encrypted.zip").write_bytes(encrypted_zip)
    (sample_dir / "sibling.txt").write_bytes(b"VirtualAlloc")

    database = Database(test_settings.database_url)
    database.create_schema()
    service = AnalysisService(
        test_settings,
        database,
        LocalContentStore(test_settings.content_store_path),
    )
    case = service.create_case("Folder Gate validation")

    waiting = service.analyze_directory(case_id=case.id, directory=sample_dir)
    assert waiting.lifecycle == "WAITING_GATE"
    assert waiting.gate_id is not None

    with pytest.raises(IntakeGateRequired):
        service.decide_input_gate(
            waiting.gate_id,
            decision="APPROVE",
            archive_password="wrong-password",
        )
    still_waiting = service.task_view(waiting.task_id)
    assert still_waiting["lifecycle"] == "WAITING_GATE"
    assert still_waiting["gates"][0]["status"] == "PENDING"

    resumed = service.decide_input_gate(
        waiting.gate_id,
        decision="APPROVE",
        archive_password="infected",
    )
    assert resumed["lifecycle"] == "SUCCEEDED"
    assert {item["logical_path"] for item in resumed["artifacts"]} == {
        "folder-with-gate/encrypted.zip",
        "folder-with-gate/encrypted.zip!/stage.py",
        "folder-with-gate/sibling.txt",
    }


def test_audit_events_are_database_append_only(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        result = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("sample.txt", b"VirtualAlloc", "text/plain")},
        )
        assert result.status_code == 202
        task_id = result.json()["task_id"]
        event_id = client.get(f"/api/v1/tasks/{task_id}/audit").json()[0]["id"]
        with pytest.raises(IntegrityError):
            with app.state.database.engine.begin() as connection:
                connection.execute(
                    text("UPDATE audit_events SET actor = 'tampered' WHERE id = :event_id"),
                    {"event_id": event_id},
                )
        assert client.get(f"/api/v1/tasks/{task_id}/audit/integrity").json()["valid"] is True


def test_analysis_snapshots_are_database_immutable(test_settings: Settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        case_id = create_case(client)
        submitted = client.post(
            f"/api/v1/cases/{case_id}/tasks",
            files={"sample": ("sample.txt", b"VirtualAlloc", "text/plain")},
        )
        task_id = submitted.json()["task_id"]
        with app.state.database.session_factory() as session:
            snapshot_id = (
                session.query(AnalysisSnapshot.id)
                .filter(AnalysisSnapshot.task_id == task_id)
                .scalar()
            )
        assert snapshot_id is not None

        with pytest.raises(IntegrityError):
            with app.state.database.engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE analysis_snapshots "
                        "SET object_versions = '{}' WHERE id = :snapshot_id"
                    ),
                    {"snapshot_id": snapshot_id},
                )


# =====================================================================================================
# P-4.1 T1: THE FULL-PE EMULATOR'S WINDOW-SOURCE FIELD, written BEFORE the fix (plan §8.1 clauses 1-3)
# =====================================================================================================
#
# THE DEFECT THESE PIN. `emulation_plan.controlled_emulation_windows` plans a full-PE
# `simulator="speakeasy"` window and records WHY it starts where it starts, inside that window's anchor:
#
#     {"simulator": "speakeasy", "entry_address": 0x1000000,
#      "anchor": {"type": "controlled_emulation", "simulator": "speakeasy",
#                 "start_basis": "image_entry"}}
#
# `unicorn_granted_windows_for_worker` then serialises that plan into `parameters["granted_windows"]` --
# and drops every window whose simulator is not `unicorn`, in SILENCE. MEASURED on this fixture: the plan
# holds 2 windows (`unicorn/pe_entry` at 0x1000 and `speakeasy`), the grant holds 1, and the grant's keys
# are `architecture, entry_address, function_entry, input_hex, role, simulator` -- no `start_basis`.
#
# The API process therefore has NO record that it ever planned a full-PE window, and
# `service._run_controlled_emulator` sends a request whose parameter keys are
# `allow_speakeasy, functions, granted_windows, planned_tools, scheduler, traces` -- no window-source
# field at all. The worker re-plans the full-PE window from the stored artifact (correct in itself: the
# grant never carried those bytes) and publishes ITS OWN start basis under the SAME label. MEASURED: with
# and without any window-source field, the published Speakeasy anchor read
# `{"start_basis": "image_entry", "type": "controlled_emulation"}` identically, so nothing in the record
# distinguished the API's recorded decision from the worker's independent second derivation of it.
#
# That is why the assertions below are TWO, and why the second is load-bearing: labelling a value is not
# evidence that the labelled value came from the plan. The fix must make the drop REPORTED and the
# published basis ATTRIBUTED, and disconnecting the window-source field must make the attribution
# assertion FAIL rather than be satisfied by the worker's own re-plan.
#
# WHERE THESE TESTS LIVE, and why not in a new `test_t1_*.py`. Plan §8.2's ownership lock
# (`.scratch/ghidra-c3-ownership.json`) lists 45 exact paths; no T1/T2 test file is among them, and
# `scripts/ghidra-plan-preflight.py::_check_ownership` matches that table by EXACT string, so a step that
# edits a file absent from the lock records it BLOCKED rather than taking it. `tests/test_analysis_api.py`
# IS in the lock (`main-plan:P-1.1`, `AVAILABLE_PENDING_LOCK`, "acquire explicitly in the step record
# before editing") and is this repository's API-surface test file, which is where a plan-to-request seam
# test belongs. This is a MEASURED accommodation of the lock, not a claim that the file is the ideal home;
# the P-4 artifact states it in `test_placement`.

PLANNER_FILTER = "emulation_plan.unicorn_granted_windows_for_worker drops non-Unicorn windows"
API_CALL = "service._run_controlled_emulator built the request without a window-source field"
WORKER_ANCHOR = "tool_execution._execute_controlled_emulator hard-coded the anchor type"
BASIS_SOURCE = "the published anchor's start_basis_source"


def _t1_pe() -> bytes:
    """A tiny STRUCTURALLY VALID PE32 whose entry is real code (`ret`).

    MEASURED while writing the first version of this fixture: `b"MZ" + zeros` is NOT enough --
    `analyze_bytes` returns no PE summary for it, `controlled_emulation_windows` plans no PE-entry
    window, and a "red" reading taken on it would have been about the FIXTURE rather than the defect.
    """
    data = bytearray(0x1000)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    # Every data directory stays ZERO. MEASURED: an export-directory size of 16 at RVA 0x1100 made the
    # parser read past the end of the buffer (`struct.error: requires a buffer of at least 1284 bytes`),
    # so the fixture failed in a way that looks like a planner failure and is not.
    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x400).to_bytes(4, "little")    # virtual_size
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")  # virtual_address
    data[section + 16 : section + 20] = (0x400).to_bytes(4, "little")   # raw_size
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")   # raw_offset
    data[0x400:0x401] = b"\xc3"
    return bytes(data)


def _bai_xiang_pe() -> bytes:
    """The 白象 entry shape: `push imm32 ; call <IAT thunk>` -- a bootstrap trampoline, not real code.

    `_entry_is_bootstrap_trampoline` recognises this and the planner records the PE-entry window as a
    NOT-EMULATABLE decision with `input_bytes=b""`, which is why the real 白象 sample's grant list is
    empty and why the worker has to build the full-PE plan itself. Fixture, so the regression control
    never needs the sample bytes in this process.

    MEASURED off-by-one while writing the first version: the call displacement is relative to the END of
    the call, so `rel=0x10` from RVA 0x1000 lands on RVA 0x101A and the thunk belongs at file offset
    0x21A. One byte early and the detector reads `25 e4 10 ...` and rejects the fixture.
    """
    code = bytearray(0x20)
    code[0] = 0x68
    code[1:5] = (0x2000).to_bytes(4, "little")
    code[5] = 0xE8
    code[6:10] = (0x10).to_bytes(4, "little", signed=True)   # -> RVA 0x101A
    thunk = b"\xff\x25" + (0x10E4).to_bytes(4, "little")
    data = bytearray(_t1_pe())
    data[0x98 + 28 : 0x98 + 32] = (0x400000).to_bytes(4, "little")  # ImageBase
    data[0x200 : 0x220] = code
    data[0x21A : 0x21A + len(thunk)] = thunk
    return bytes(data)


_T1_FUNCTIONS = [
    {"entry": "0x401100", "entry_rva": 0x1100, "name": "FUN_401100", "caller_count": 1}
]


def _t1_plan(content: bytes, functions=None):
    """The REAL planner on the fixture. Returns `(pe_summary, windows)`."""
    from threat_report_agent.static.static_analysis import analyze_bytes

    pe_summary = analyze_bytes(content, "full-pe.dll").summary.get("pe") or {}
    windows = controlled_emulation_windows(
        content,
        pe_summary,
        _T1_FUNCTIONS if functions is None else functions,
        (),
        allow_speakeasy=True,
        allow_qiling=False,
        max_windows=4,
        snippet_length=512,
        max_pe_bytes=4_194_304,
        preferred_entries=(),
    )
    return pe_summary, [dict(window) for window in windows]


def _speakeasy_window(windows) -> dict:
    return next(
        (window for window in windows if str(window.get("simulator") or "").casefold() == "speakeasy"),
        {},
    )


def _emulator_settings(test_settings: Settings, tmp_path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "simulation_profile": "static-first-controlled-emulation",
        "simulation_worker_identity": "controlled-emu-worker-v1",
        "simulation_worker_image_digest": "sha256:emu-worker-v1",
        "simulation_allowed_simulators": ("unicorn", "speakeasy"),
        "simulation_allow_local_process": False,
        "tool_execution_mode": "temporal",
        "simulation_timeout_seconds": 8,
        "simulation_instruction_budget": 100_000,
        "simulation_max_output_bytes": 65536,
        "simulation_max_input_bytes": 4_194_304,
        "content_store_backend": "local",
        "content_store_path": str(tmp_path / "content"),
        # A FILE-BACKED database, not the fixture's `sqlite://`: `AnalysisService` opens several sessions
        # across the plan/dispatch seam and an in-memory SQLite would hand each one a different database.
        "database_url": f"sqlite:///{tmp_path / 't1-emulation.db'}",
    }
    values.update(overrides)
    return replace(test_settings, **values)


def _captured_api_request(test_settings: Settings, tmp_path, content: bytes) -> dict:
    """Run the REAL `AnalysisService.run_controlled_emulator`; return the request it builds.

    Only `TemporalToolExecutor` is replaced, by a recorder that starts no workflow. The policy, the
    `speakeasy` decision, the grant plan and the `parameters` dict are production code, and the
    assertions read the request object the Temporal worker would actually be handed.
    """
    from threat_report_agent import service as service_module

    settings = _emulator_settings(test_settings, tmp_path)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    case = service.create_case("t1 speakeasy reachability")
    stored = store.put(content)
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="full-pe.dll",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        task_id, artifact_id = task.id, artifact.id

    captured: list[object] = []

    class _ExecutorRecorder:
        def __init__(self, temporal_address: str) -> None:
            self.temporal_address = temporal_address

        async def execute(self, request: object) -> ToolRunResult:
            captured.append(request)
            return ToolRunResult(status="FAILED", error="RECORDED_NOT_EXECUTED", worker_metadata={})

    saved_executor = service_module.TemporalToolExecutor
    service_module.TemporalToolExecutor = _ExecutorRecorder  # type: ignore[assignment]
    try:
        service.run_controlled_emulator(
            task_id,
            artifact_id,
            PackageEntry(
                logical_path="full-pe.dll",
                content=content,
                parent_path=None,
                discovery="submitted",
                detected_type="pe",
            ),
        )
    finally:
        service_module.TemporalToolExecutor = saved_executor  # type: ignore[assignment]
    assert captured, (
        "the emulator decision path did not reach the tool executor at all, so this test observes nothing"
    )
    request = captured[0]
    return {
        "parameters": dict(getattr(request, "parameters", {}) or {}),
        "content_sha256": getattr(request, "content_sha256", ""),
        "storage_key": getattr(request, "storage_key", ""),
    }


def _worker_record(
    test_settings: Settings,
    tmp_path,
    content: bytes,
    *,
    storage_key: str,
    content_sha256: str,
    parameters: dict,
) -> dict:
    """Drive the REAL `StaticToolActivities._execute`; return what it dispatched and published.

    `IsolatedSimulationRunner` is patched on the `tool_execution` module object itself, because that is
    the name the module resolved at import time -- patching a name the module never imported is how an
    earlier probe measured nothing at all.
    """
    from threat_report_agent.tools import tool_execution as te

    settings = _emulator_settings(test_settings, tmp_path)
    store = LocalContentStore(settings.content_store_path)
    stored = store.put(content)
    assert stored.sha256 == content_sha256, (
        "the content store returned a different digest than the API request carried, so this test would "
        "exercise a different sample than the one the API planned for"
    )
    activities = te.StaticToolActivities(settings, store)
    dispatched: list[object] = []

    class _RecordedResult:
        """The 白象-shaped outcome: the adapter ran and could not model a runtime call."""

        def __init__(self, simulator: str) -> None:
            self.status = "FAILED"
            self.stop_reason = "EXECUTION_ERROR"
            self.output_bytes = b""
            self.simulator = simulator
            self.limitations = (
                "Speakeasy stopped before observing any API call: unsupported_api "
                "api=MSVBVM60.ordinal_100 pc=0xfeedf0f0 instr=disasm_failed",
            )

        def as_dict(self) -> dict[str, object]:
            return {
                "status": self.status,
                "simulator": self.simulator,
                "stop_reason": self.stop_reason,
                "limitations": list(self.limitations),
                "observations": [],
            }

    class _RecordingRunner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, request: object, cancellation_requested: object = None) -> object:
            dispatched.append(request)
            return _RecordedResult(str(getattr(request, "simulator", "")))

    request = te.ToolRunRequest(
        case_id="t1-case",
        task_id="t1-task",
        trace_id="t1-trace",
        artifact_id="t1-artifact",
        tool_run_id="t1-emu",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=content_sha256,
        storage_key=storage_key,
        logical_path="full-pe.dll",
        parameters=parameters,
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    saved_runner = te.IsolatedSimulationRunner
    te.IsolatedSimulationRunner = _RecordingRunner  # type: ignore[assignment]
    try:
        result = activities._execute(request)
    finally:
        te.IsolatedSimulationRunner = saved_runner  # type: ignore[assignment]
    stored_key = result.get("output_storage_key") if isinstance(result, dict) else None
    payload: dict[str, object] = {}
    if stored_key:
        raw = store.read(str(stored_key))
        payload = json.loads(raw) if raw else {}
    rows = [row for row in (payload.get("results") or []) if isinstance(row, dict)]
    speakeasy_rows = [
        row for row in rows if str(row.get("simulator") or "").casefold() == "speakeasy"
    ]
    metadata = result.get("worker_metadata") if isinstance(result, dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    return {
        "tool_status": result.get("status") if isinstance(result, dict) else None,
        # The payload's OWN `kind`, read back from the object store this dispatch wrote, plus the
        # `tool_run_id` from the result envelope that points at it - the two halves of "one ToolRun".
        "payload_kind": payload.get("kind"),
        "payload_status": payload.get("status"),
        "result_tool_run_id": metadata.get("tool_run_id"),
        "result_input_sha256": metadata.get("input_sha256"),
        "dispatched": [str(getattr(item, "simulator", "")) for item in dispatched],
        "dispatched_speakeasy_entries": [
            getattr(item, "entry_address", None)
            for item in dispatched
            if str(getattr(item, "simulator", "")).casefold() == "speakeasy"
        ],
        "results": rows,
        "speakeasy_anchor": (speakeasy_rows[0].get("anchor") if speakeasy_rows else None),
    }


def test_the_planner_plans_a_speakeasy_window_that_records_its_own_start_basis() -> None:
    """The premise of the whole step: the plan HAS the fact, recorded inside the window's anchor."""
    _summary, windows = _t1_plan(_t1_pe())
    window = _speakeasy_window(windows)

    assert window, "the planner produced no full-PE window for a valid PE with allow_speakeasy=True"
    assert [str(item.get("simulator")) for item in windows] == ["unicorn", "speakeasy"], (
        "the plan must hold a real Unicorn window AND the full-PE window; this fixture is the shape plan "
        "§8.1 clause 1 names"
    )
    anchor = window.get("anchor") or {}
    assert anchor.get("type") == "controlled_emulation", anchor
    assert str(anchor.get("start_basis") or ""), (
        "the planner recorded no start_basis, so there is no planner decision for T1 to carry"
    )


def test_the_grant_serialisation_reports_the_window_it_drops() -> None:
    """§8.1 clause 1 + §8.2 point 1: the Unicorn-only grant must not drop the full-PE window in silence.

    Three statements, in the order the seam is built:
      * the grant list stays Unicorn-only (the worker must not be handed PE bytes through the grant
        budget, and §8.2 forbids deleting the Unicorn window);
      * the dropped window's identity and the planner's own `start_basis` are REPORTED to the caller;
      * passing the new parameter changes no grant -- two calls differing only in that argument must
        return byte-identical payloads, or every existing caller's request silently moves.
    """
    _summary, windows = _t1_plan(_t1_pe())
    planned_basis = str((_speakeasy_window(windows).get("anchor") or {}).get("start_basis") or "")
    assert planned_basis, "fixture no longer plans a start_basis, so this test cannot observe a drop"

    skipped: list[dict[str, object]] = []
    granted = unicorn_granted_windows_for_worker(windows, max_windows=4, skipped_out=skipped)
    granted_again = unicorn_granted_windows_for_worker(windows, max_windows=4)

    assert [str(item.get("simulator")) for item in granted] == ["unicorn"], (
        f"{PLANNER_FILTER}: the grant list must remain Unicorn-only; got "
        f"{[item.get('simulator') for item in granted]}"
    )
    assert granted == granted_again, (
        "passing `skipped_out` changed the grant payload itself; reporting a drop must not alter what is "
        "granted"
    )
    dropped = [item for item in skipped if str(item.get("simulator") or "").casefold() == "speakeasy"]
    assert dropped, (
        f"{PLANNER_FILTER}: the full-PE window was dropped and NOT reported. `skipped_out` held "
        f"{skipped!r}; the caller cannot tell 'there were only Unicorn windows' from 'non-Unicorn windows "
        f"were dropped', because both arrive as a shorter tuple"
    )
    record = dropped[0]
    assert record.get("skipped_because") == "not_a_unicorn_window", record
    assert str(record.get("start_basis") or "") == planned_basis, (
        f"{PLANNER_FILTER}: the drop record does not carry the planner's own start_basis "
        f"({planned_basis!r}); got {record!r}"
    )
    assert record.get("anchor_type") == "controlled_emulation", record
    assert record.get("entry_address") == _speakeasy_window(windows).get("entry_address"), record


def test_a_plan_with_no_speakeasy_window_reports_no_drop() -> None:
    """The negative direction of the same seam: nothing was dropped, so nothing may be reported.

    Without this, an implementation that appended a constant row would satisfy the test above while
    reporting a drop that never happened -- the EC-1 shape (absence converted into a finding).
    """
    _summary, windows = _t1_plan(_t1_pe())
    unicorn_only = [
        window for window in windows if str(window.get("simulator") or "").casefold() == "unicorn"
    ]
    skipped: list[dict[str, object]] = []
    granted = unicorn_granted_windows_for_worker(unicorn_only, max_windows=4, skipped_out=skipped)

    assert granted, "a Unicorn-only plan must still grant its windows"
    assert skipped == [], f"no window was dropped, yet skipped_out reported {skipped!r}"


def test_the_api_request_carries_the_window_the_grant_filter_dropped(
    test_settings: Settings, tmp_path
) -> None:
    """§8.2 point 2: `service.py`'s request is where the plan's decision was lost.

    Measured pre-fix shape: `parameters` keys were `allow_speakeasy, functions, granted_windows,
    planned_tools, scheduler, traces` -- the API had planned a full-PE window and told the worker
    nothing about it.
    """
    content = _t1_pe()
    captured = _captured_api_request(test_settings, tmp_path, content)
    parameters = captured["parameters"]

    assert parameters.get("granted_windows"), (
        "the fixture no longer grants a Unicorn window, so this test cannot tell the defect from the fix"
    )
    planned_basis = str(
        (_speakeasy_window(_t1_plan(content)[1]).get("anchor") or {}).get("start_basis") or ""
    )
    skipped = parameters.get("grants_skipped")
    assert isinstance(skipped, list) and skipped, (
        f"{API_CALL}: the request carries no record of the window the grant filter removed (parameter "
        f"keys: {sorted(parameters)}); the worker is left to re-derive a decision the API already made"
    )
    bases = [str(item.get("start_basis") or "") for item in skipped if isinstance(item, dict)]
    assert planned_basis in bases, (
        f"{API_CALL}: the plan's start_basis {planned_basis!r} is not in the request's grants_skipped "
        f"({skipped!r})"
    )
    # §8.2's explicit prohibition: PE bytes must not be inlined into the request. Temporal rejects
    # payloads over 2 MiB (measured), and a 4 MiB sample inlined as hex is ~8 MiB.
    assert "input_hex" not in json.dumps(skipped), (
        "the drop record inlined bytes into the request payload; the worker reads the artifact through "
        "its storage grant and must not be handed the sample through parameters"
    )
    assert len(json.dumps(parameters, ensure_ascii=False, default=str)) < 65536, (
        "the emulator request payload grew past a bounded size; §8.2 forbids inlining PE bytes here"
    )


def _worker_parameters(captured: dict, *, with_the_api_record: bool = True) -> dict:
    parameters = dict(captured["parameters"])
    if not with_the_api_record:
        parameters.pop("grants_skipped", None)
    return parameters


def test_the_published_anchor_attributes_the_basis_to_the_apis_plan(
    test_settings: Settings, tmp_path
) -> None:
    """§8.3: `start_basis`, its source, the simulator and the status come from ONE ToolRun/Evidence.

    The worker runs the full-PE window regardless -- it has to, the grant never carried those bytes -- so
    the honest record says WHICH plan the published basis came from. The pre-fix record said
    `start_basis` and nothing else, which reads as "the API decided this" while actually being the
    worker's own second derivation.
    """
    content = _t1_pe()
    captured = _captured_api_request(test_settings, tmp_path, content)
    assert captured["parameters"].get("grants_skipped"), (
        "the API did not record the dropped window, so this test cannot observe attribution"
    )
    record = _worker_record(
        test_settings,
        tmp_path,
        content,
        storage_key=captured["storage_key"],
        content_sha256=captured["content_sha256"],
        parameters=_worker_parameters(captured),
    )
    anchor = record["speakeasy_anchor"] or {}

    assert record["dispatched_speakeasy_entries"], (
        f"{WORKER_ANCHOR}: no Speakeasy window was dispatched at all, so there is nothing to attribute; "
        f"dispatched={record['dispatched']!r}"
    )
    assert anchor.get("start_basis_source") == "api_grants_skipped", (
        f"{BASIS_SOURCE}: the published anchor does not say the basis came from the API's plan; "
        f"anchor={anchor!r}. The worker re-plans the full-PE window from the stored artifact, so without "
        f"this field the record cannot distinguish the planner's decision from the worker's own re-plan"
    )
    assert str(anchor.get("start_basis") or ""), anchor
    assert str(anchor.get("type") or "") == "controlled_emulation", (
        f"{WORKER_ANCHOR}: a full-PE window was published under anchor type {anchor.get('type')!r}; the "
        f"window's source and its anchor type disagree in the same record"
    )
    assert anchor.get("simulator") == "speakeasy", anchor
    # SAME ToolRun/Evidence (§8.3): the anchor travels INSIDE the stored emulation payload this very
    # dispatch produced, so it cannot have been read from a different run's projection.
    #
    # MEASURED while writing this: the stored result carries `kind` and an `environment` block but no
    # top-level `tool_run_id`, so an earlier version of this assertion (`record["same_tool_run"]`) failed
    # for a reason that had nothing to do with the fix. The identity is asserted on the fields the record
    # actually has, read back from the store this dispatch wrote.
    assert record["payload_kind"] == "emulation", record["payload_kind"]
    assert record["result_tool_run_id"] == "t1-emu", record["result_tool_run_id"]
    assert record["result_input_sha256"] == captured["content_sha256"], (
        "the stored payload and the request it came from disagree on the sample digest, so the anchor "
        "cannot be tied to the run it is published for"
    )
    assert record["payload_status"] == "FAILED", (
        "the blocker result was published as a success; a FAILED simulator outcome must stay FAILED"
    )


def test_disconnecting_the_window_source_field_makes_attribution_impossible(
    test_settings: Settings, tmp_path
) -> None:
    """§8.1 clause 3, the load-bearing control: break the window-source field and A2 must FAIL.

    MEASURED on the pre-fix tree: the identical run WITHOUT any window-source field published
    `{"start_basis": "image_entry", "type": "controlled_emulation"}` -- the same anchor. That is the
    difference between an observation and a label: the label was present, the provenance was not. This
    control asserts the published basis is `worker_replan` (not the API's) once the API's record is
    removed, which is what makes the sibling assertion above non-vacuous.
    """
    content = _t1_pe()
    captured = _captured_api_request(test_settings, tmp_path, content)
    assert captured["parameters"].get("grants_skipped"), (
        "fixture produced no drop record, so removing it would prove nothing"
    )
    without = _worker_record(
        test_settings,
        tmp_path,
        content,
        storage_key=captured["storage_key"],
        content_sha256=captured["content_sha256"],
        parameters=_worker_parameters(captured, with_the_api_record=False),
    )
    anchor = without["speakeasy_anchor"] or {}

    assert without["dispatched_speakeasy_entries"], (
        "the worker stopped dispatching Speakeasy when the API's record was removed; T1's reachability "
        "must not depend on the record, only the ATTRIBUTION may"
    )
    assert anchor.get("start_basis_source") != "api_grants_skipped", (
        f"{BASIS_SOURCE}: with the API's record removed the anchor still claims the basis came from the "
        f"API's plan ({anchor!r}); the attribution assertion is therefore satisfied by the worker's own "
        f"re-plan and proves nothing"
    )
    assert anchor.get("start_basis_source") == "worker_replan", (
        f"the worker's own re-plan is not labelled as such: anchor={anchor!r}. The two read paths must be "
        f"distinguishable or the published basis is an unlabelled second guess"
    )


def test_bai_xiang_trampoline_entry_still_grants_nothing() -> None:
    """§8.2's prohibition: the fix must NOT make 白象's grants non-empty.

    白象's entry is a bootstrap trampoline, so the planner records a NOT-EMULATABLE decision with
    `input_bytes=b""`; `unicorn_granted_windows_for_worker` skips it because a payload under 8 bytes is
    not a window. That empty grant list is load-bearing: it is what makes the worker build the full-PE
    plan itself. MEASURED on the real sample: Unicorn contributes no window at all.
    """
    _summary, windows = _t1_plan(_bai_xiang_pe(), functions=[])
    skipped: list[dict[str, object]] = []
    granted = unicorn_granted_windows_for_worker(windows, max_windows=4, skipped_out=skipped)

    assert any(
        str(window.get("skip_reason") or "") == "pe_entry_is_bootstrap_trampoline" for window in windows
    ), f"the fixture is no longer recognised as a bootstrap trampoline: {windows!r}"
    assert granted == (), (
        f"白象 REGRESSION: the trampoline-entry sample now grants {granted!r}. Its empty grant list is "
        f"load-bearing"
    )
    # The Speakeasy window is still PLANNED (so the worker can dispatch it); it is simply not granted.
    assert _speakeasy_window(windows), "the planner stopped planning the full-PE window for 白象"
    assert unicorn_granted_windows_for_worker(windows, max_windows=4) == ()


def test_the_grants_empty_regression_has_a_grants_nonempty_wrong_sample_control() -> None:
    """The control that makes the 白象 assertion falsifiable: the SAME call on a real-code entry.

    A `grants == ()` assertion that would also hold for every input is not a regression test. This runs
    the identical grant call on a sample whose entry is real code and requires a NON-empty grant, so the
    pair pins both directions of the same code path.
    """
    _tramp_summary, trampoline_windows = _t1_plan(_bai_xiang_pe(), functions=[])
    _plain_summary, plain_windows = _t1_plan(_t1_pe(), functions=[])
    plain_granted = unicorn_granted_windows_for_worker(plain_windows, max_windows=4)
    trampoline_granted = unicorn_granted_windows_for_worker(trampoline_windows, max_windows=4)

    assert plain_granted, (
        "the wrong-sample control granted nothing either, so the 白象 grants-empty assertion cannot "
        "distinguish 'this entry is a trampoline' from 'this function never grants anything'"
    )
    assert trampoline_granted == (), (
        "the two samples produced the same grant shape, so the control is not a control"
    )
    assert [item.get("simulator") for item in plain_granted] == ["unicorn"]


def test_no_new_numeric_threshold_constant_was_added_and_the_function_window_stays_capped(
    test_settings: Settings, tmp_path
) -> None:
    """§8.2: keep `functions[:64]`, and introduce no new named numeric threshold constant.

    `docs/structure-surface.json` records the pre-existing thresholds; a new named constant or a new
    comparison changes that surface and fails `check-structure-diff.py --all --strict` until it is
    recorded, which §8.2 says needs a separate decision. The authoritative half of that check is the gate
    itself (run in the P-4 artifact's `commands`, exit 0); this asserts the narrow, mechanical half: the
    set of module-level numeric constants in `emulation_plan.py` is UNCHANGED from the pre-step HEAD, and
    the request still carries at most the pre-existing 64-function window.

    The comparison is against `git show HEAD:<path>` rather than against a hard-coded list, so it cannot
    be satisfied by editing the expectation. MEASURED while writing the first version: an assertion of
    "the module has no module-level numeric constant" failed on the pre-existing
    `_SPEAKEASY_RECOVERY_SPAN_FALLBACK` -- a test that fails on the unfixed tree for the wrong reason.
    """
    import ast
    import subprocess
    from pathlib import Path

    import threat_report_agent.emulation.emulation_plan as plan_module

    path = "src/threat_report_agent/emulation/emulation_plan.py"

    def numeric_constants(source: str) -> set[str]:
        return {
            node.targets[0].id
            for node in ast.parse(source).body
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, (int, float))
            and not isinstance(node.value.value, bool)
        }

    head_source = subprocess.run(
        ["git", "show", f"HEAD:{path}"], capture_output=True, check=True
    ).stdout.decode("utf-8")
    added = numeric_constants(Path(plan_module.__file__).read_text(encoding="utf-8")) - numeric_constants(
        head_source
    )
    assert added == set(), (
        f"module-level numeric constant(s) {sorted(added)} were added to {path}. §8.2 keeps the existing "
        f"thresholds and requires a separate decision to change them"
    )

    content = _t1_pe()
    captured = _captured_api_request(test_settings, tmp_path, content)
    assert len(captured["parameters"].get("functions") or []) <= 64, (
        "the function window grew past its pre-existing cap"
    )


def test_the_worker_derives_the_anchor_type_from_the_granted_window() -> None:
    """§8.2 point 3, driven directly: the anchor type is copied from the window, never hard-coded.

    The grant branch used to stamp `type: "unique_thread_emulation"` on EVERY grant, which is the type
    that belongs to a Unicorn snippet. A grant-shaped Speakeasy window therefore published itself under a
    thread-emulation anchor -- the window's simulator and its anchor type disagreeing in one record.
    Driven through the real helper so the assertion is about behaviour, not about source text.
    """
    from threat_report_agent.tools.tool_execution import _granted_anchor

    unicorn_anchor = _granted_anchor(
        {"simulator": "unicorn", "role": "pe_entry", "function_entry": "0x1000"}
    )
    speakeasy_anchor = _granted_anchor(
        {"simulator": "speakeasy", "role": "", "function_entry": "", "start_basis": "image_entry"}
    )

    assert unicorn_anchor["type"] == "unique_thread_emulation", unicorn_anchor
    assert speakeasy_anchor["type"] == "controlled_emulation", (
        f"{WORKER_ANCHOR}: a granted Speakeasy window was given anchor type "
        f"{speakeasy_anchor['type']!r}; the planner's own type for that window is `controlled_emulation`"
    )
    assert speakeasy_anchor["start_basis"] == "image_entry", speakeasy_anchor
    assert speakeasy_anchor["simulator"] == "speakeasy", speakeasy_anchor
    # An explicit type on the window WINS: the planner's decision is copied, not second-guessed.
    explicit = _granted_anchor({"simulator": "speakeasy", "anchor": {"type": "planner_chose_this"}})
    assert explicit["type"] == "planner_chose_this", explicit


#: A benign PE64 that ships IN THIS REPOSITORY (a vendored build-tool launcher, not a sample). Used as the
#: observation fixture because a hand-built synthetic PE cannot carry this test: MEASURED, on the
#: hand-built fixture Speakeasy dies in its loader (`UcError: Invalid memory write
#: (UC_ERR_WRITE_UNMAPPED)`) and returns ONE `request` observation, so the "addition" was a `request`
#: event - non-empty by COUNT and naming nothing, which is exactly the shape §8.3 forbids.
SPEAKEASY_OBSERVATION_FIXTURE = Path(__file__).resolve().parents[1] / "vendor" / "setuptools" / "cli-64.exe"


def _observation_identity(observation: object) -> str:
    """One observation's stable identity, built ONLY from fields the record actually carries.

    Naming the event first is what makes the two simulators' sets comparable at all: Unicorn emits
    `instruction|0x...` events, Speakeasy emits `api|<name>` / `unsupported_api|<name>`. A key that
    assumed one shape would have reported an empty identity list for the other and read as "no
    observations" rather than as a mismatch.
    """
    row = observation if isinstance(observation, dict) else {}
    event = str(row.get("event") or row.get("kind") or "?")
    detail = " ".join(
        str(row.get(field) or "")
        for field in ("api", "name", "api_name", "symbol", "module", "address", "pc", "path")
    ).strip()
    return f"{event}|{detail}".rstrip("|")


def _run_planned_window(window: dict, *, instruction_budget: int, timeout_seconds: int) -> dict:
    """Run ONE planner-built window through the REAL in-process adapters.

    No subprocess, no network, no host sample: the request is built by `request_for_granted_window` from
    the planner's own window, which is the same object the service serialises into
    `parameters["granted_windows"]`.
    """
    from threat_report_agent.emulation.policy import (
        SimulationExecutionPolicy,
        request_for_granted_window,
    )
    from threat_report_agent.simulation_adapters import default_simulation_runner

    simulator = str(window.get("simulator") or "")
    policy = SimulationExecutionPolicy(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="controlled-emu-worker-v1",
        worker_image_digest="sha256:emu-worker-v1",
        allowed_simulators=(simulator,),
        max_timeout_seconds=timeout_seconds,
        max_instruction_budget=instruction_budget,
        max_output_bytes=65536,
        isolation_kind="subprocess",
        allow_local_process=True,
        max_input_bytes=4_194_304,
    )
    result = default_simulation_runner(policy, execute_in_process=True).run(
        request_for_granted_window(policy, window)
    )
    payload = result.as_dict()
    observations = payload.get("observations") or []
    return {
        "simulator": simulator,
        "status": result.status,
        "stop_reason": result.stop_reason,
        "limitations": list(result.limitations)[:6],
        "observation_count": len(observations),
        "identities": sorted({_observation_identity(item) for item in observations}),
        "unsupported_apis": list(payload.get("unsupported_apis") or []),
    }


def test_the_full_pe_window_observes_a_non_empty_locatable_addition_over_unicorn() -> None:
    """§8.3, the T1 acceptance condition: a real ADDITION, published as a SET, not as a count.

    Same sample, same `content_sha256`: the Unicorn baseline is the planner's own snippet window (the
    exact bytes the API grants) and the addition is the planner's full-PE window. The assertion is a SET
    DIFFERENCE with both directions, because "14 new observations" is a count a reader cannot check --
    the element that matters is the one that names the unmodelled runtime call.

    HONESTY BOUNDARY. This is the repository's own in-process adapter run, NOT the deployed emu-worker,
    so it establishes reachability and what the full-PE window observes on this tree; it does not accept
    the capability. `capability_status` stays UNVERIFIED.
    """
    content = SPEAKEASY_OBSERVATION_FIXTURE.read_bytes()
    _summary, windows = _t1_plan(content, functions=[])
    speakeasy = _speakeasy_window(windows)
    unicorn_windows = [
        window
        for window in windows
        if str(window.get("simulator") or "").casefold() == "unicorn"
        and len(window.get("input_bytes") or b"") >= 8
    ]
    assert speakeasy, "the planner produced no full-PE window for the observation fixture"
    assert unicorn_windows, "the planner produced no runnable Unicorn window for the observation fixture"

    baseline_ids: set[str] = set()
    baseline_runs = [
        _run_planned_window(window, instruction_budget=100_000, timeout_seconds=20)
        for window in unicorn_windows
    ]
    for run in baseline_runs:
        baseline_ids |= set(run["identities"])
    added_run = _run_planned_window(speakeasy, instruction_budget=900_000, timeout_seconds=60)
    added_ids = set(added_run["identities"])

    assert baseline_ids, (
        f"the Unicorn baseline observed nothing, so an 'addition' would be unmeasurable: {baseline_runs!r}"
    )
    addition = added_ids - baseline_ids
    assert addition, (
        f"the full-PE window added no observation over the Unicorn baseline "
        f"(speakeasy status={added_run['status']} stop={added_run['stop_reason']} "
        f"limitations={added_run['limitations']!r}). §8.3 requires a NON-EMPTY addition or an explicit "
        f"PARTIAL/BLOCKED limitation"
    )
    # §8.3: the elements must name a concrete entry/API/unsupported API, not only a generic error class.
    locatable = [identity for identity in addition if identity.partition("|")[2].strip()]
    assert locatable, (
        f"every added element is a bare event name with no symbol: {sorted(addition)!r}; §8.3 forbids an "
        f"addition that is 'only EXECUTION_ERROR'"
    )
    assert any(identity.startswith("api|") for identity in addition), (
        f"the addition carries no API observation at all: {sorted(addition)!r}"
    )
    assert added_run["unsupported_apis"], (
        f"the run stopped without recording WHICH runtime call it could not model "
        f"(status={added_run['status']} stop={added_run['stop_reason']}); the concrete blocker is the "
        f"whole point of both T1's acceptance and T2"
    )
    blocker = added_run["unsupported_apis"][0]
    assert str(blocker.get("name") or "").strip(), blocker
    # The STOP REASON is part of the published addition, not only the observations.
    assert added_run["stop_reason"] and added_run["stop_reason"] != "EXECUTION_ERROR" or (
        any(str(item).startswith("Speakeasy observed") for item in added_run["limitations"])
    ), (
        f"the full-PE window's outcome is a bare {added_run['stop_reason']!r} with no naming limitation: "
        f"{added_run['limitations']!r}"
    )
    # The two sets come from ONE sample: both windows were planned from the same bytes above, and the
    # record says which bytes, so a reader can recompute both sets from the published fixture digest.
    assert added_run["identities"], added_run


# =====================================================================================================
# P-4.4 T2: THE INDEPENDENT CONCRETE-BLOCKER PROBE, AND THE CONTROL THAT MAKES IT FALSIFIABLE
# =====================================================================================================
#
# THE TWO READ PATHS, plan §8.4 ("产品运行结果与独立 emu-worker blocker probe 使用两条取数路径").
#
#   PATH A - the PRODUCT's record. `tool_execution.emulation_concrete_blocker` turns the executed
#   window's own `observations` (and, when the adapter named the stall only in prose, its `limitations`)
#   into `row["concrete_blocker"]`, which `_persist_emulation_result` writes into the
#   `kind="simulation_result"` Evidence value.
#
#   PATH B - the PROBE. `.scratch/ghidra-c3/preflight/p4-t2-probe.py` runs a SEPARATE worker invocation
#   and derives the answer again with its OWN rules (a different event filter, a different prose
#   extractor, a different not-run rule). It is imported from its file path, NOT copied here.
#
# WHY IT IS A SEPARATE FILE AND NOT A COPY. §8.4's last clause: "删除独立 probe 后，T2 的『具体卡点』断言
# 必须失败，而不是从同一 projection 复制字符串". A test that called the product's helper twice would
# satisfy nothing - deleting the probe would change no assertion. The control below therefore renames the
# probe away on disk, runs THIS test through a real pytest subprocess, requires exit 1, and restores the
# file from a byte snapshot (never git).
#
# WHAT AGREEMENT HERE DOES AND DOES NOT PROVE. Both paths read the observations the SAME repository
# adapter produced; what is independent is the INVOCATION and the DERIVATION, not the emulator. An
# adapter that lied about its own observations would move both answers together. The artifact says so.
P4_T2_PROBE = Path(__file__).resolve().parents[1] / ".scratch" / "ghidra-c3" / "preflight" / "p4-t2-probe.py"

#: The concrete blocker the vendored PE64 fixture measures. Named rather than pattern-matched: a test
#: that accepted any symbol would pass on a record naming the wrong API.
VENDOR_BLOCKER_SYMBOL = "KERNEL32!GetFinalPathNameByHandleA"
VENDOR_BLOCKER_API = "KERNEL32.GetFinalPathNameByHandleA"


def _load_probe_module():
    """Import the probe FROM ITS FILE, by path, so an unreachable probe is a hard failure.

    Not a copy and not a skip: `importlib` raises when the file is gone, which is exactly the failure the
    deletion control below requires. `pytest.importorskip` would have turned that into a silent skip -
    the "control that cannot fail" shape this plan keeps removing.

    `P4_T2_PROBE_PATH` overrides the location FOR THIS PROCESS ONLY, which is how the deletion control
    makes the probe unreachable without touching the worktree: MEASURED, an earlier version renamed the
    real file, and a concurrent pytest process then saw the probe vanish mid-test.
    """
    import importlib.util
    import os

    probe = Path(os.environ.get("P4_T2_PROBE_PATH") or P4_T2_PROBE)
    if not probe.is_file():
        raise FileNotFoundError(
            f"{probe} is MISSING. T2's concrete blocker is only an observation because an INDEPENDENT "
            f"probe derives it a second time; with the probe gone this assertion has nothing to compare "
            f"against and must not pass"
        )
    spec = importlib.util.spec_from_file_location("p4_t2_probe", probe)
    assert spec is not None and spec.loader is not None, probe
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _t2_worker_rows(content: bytes, *, logical_path: str = "p4-t2-fixture.bin") -> list[dict]:
    """One REAL worker invocation with the adapters included; returns the stored result rows.

    Unlike `_worker_record` above, this drives the ACTUAL adapters (`IsolatedSimulationRunner` is not
    replaced), because T2 is about what the emulator really reported and not about a stand-in's prose.
    """
    from threat_report_agent.tools import tool_execution as te

    store = LocalContentStore(str(_t2_tempdir() / "content"))
    stored = store.put(content)
    activities = te.StaticToolActivities(_t2_settings(), store)
    request = te.ToolRunRequest(
        case_id="p4-t2-case",
        task_id="p4-t2-task",
        trace_id="p4-t2-trace",
        artifact_id="p4-t2-artifact",
        tool_run_id="p4-t2-emu",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=stored.sha256,
        storage_key=stored.storage_key,
        logical_path=logical_path,
        parameters={"allow_speakeasy": True, "functions": [], "traces": []},
        max_cpu_seconds=60,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activities._execute(request)
    stored_key = result.get("output_storage_key") if isinstance(result, dict) else None
    payload: dict[str, object] = {}
    if stored_key:
        raw = store.read(str(stored_key))
        payload = json.loads(raw) if raw else {}
    return [row for row in (payload.get("results") or []) if isinstance(row, dict)]


_T2_TMP: list = []


def _t2_tempdir():
    import tempfile

    if not _T2_TMP:
        _T2_TMP.append(Path(tempfile.mkdtemp(prefix="p4-t2-")))
    return _T2_TMP[0]


def _t2_settings() -> Settings:
    from threat_report_agent.config import ModelProviderSettings, Settings

    return Settings(
        environment="test",
        database_url="sqlite://",
        object_store_endpoint="http://object-store",
        object_store_bucket="test",
        object_store_access_key="test",
        object_store_secret_key="test",
        content_store_backend="local",
        content_store_path=str(_t2_tempdir() / "content"),
        temporal_address="temporal:7233",
        ghidra_home="",
        java_home="",
        max_sample_files=100,
        max_sample_bytes=16 * 1024 * 1024,
        max_archive_depth=3,
        primary_model=ModelProviderSettings(
            "test-provider", "http://model.invalid/v1", "test-model", "test-key"
        ),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
        gate_secret_key="test-gate-secret",
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy"),
        simulation_allow_local_process=False,
        tool_execution_mode="temporal",
        simulation_timeout_seconds=60,
        simulation_instruction_budget=900_000,
        simulation_max_output_bytes=65536,
        simulation_max_input_bytes=4_194_304,
    )


def _probe_derivation_for(row: dict):
    """PATH B's answer for ONE stored row, through the probe's own rules."""
    probe = _load_probe_module()
    return probe.probe_derivation(
        observations=row.get("observations") if isinstance(row.get("observations"), list) else [],
        limitations=[str(item) for item in (row.get("limitations") or [])],
        status=str(row.get("status") or ""),
        stop_reason=str(row.get("stop_reason") or ""),
    )


def test_the_concrete_blocker_in_the_product_record_matches_the_independent_probe() -> None:
    """§8.4: the named blocker is derived TWICE and the two answers must agree.

    Path A is the row the worker stored; path B is a separate invocation read through the probe's own
    rules. The assertion is on the SYMBOL, not on a status code: `EXECUTION_ERROR` alone is what §8.4
    says does not satisfy B1.
    """
    rows = _t2_worker_rows(SPEAKEASY_OBSERVATION_FIXTURE.read_bytes())
    speakeasy = [row for row in rows if str(row.get("simulator") or "") == "speakeasy"]
    assert speakeasy, (
        f"no Speakeasy row was produced, so this test observes nothing; rows={[r.get('simulator') for r in rows]!r}"
    )
    row = speakeasy[0]
    published = row.get("concrete_blocker")
    derived = _probe_derivation_for(row)

    assert isinstance(published, dict), (
        f"the product record carries no concrete blocker for the run that stalled "
        f"(status={row.get('status')!r}, stop_reason={row.get('stop_reason')!r}, "
        f"limitations={list(row.get('limitations') or [])!r}); a generic stop reason is what §8.4 forbids"
    )
    assert published.get("reason") == derived.get("reason"), (
        f"PATH A says {published.get('reason')!r} and PATH B (independent probe) says "
        f"{derived.get('reason')!r}: {published!r} vs {derived!r}"
    )
    assert published.get("symbol") == derived.get("symbol"), (
        f"the two read paths name different symbols: {published.get('symbol')!r} vs {derived.get('symbol')!r}"
    )
    assert published.get("symbol") == VENDOR_BLOCKER_SYMBOL, (
        f"the blocker is not the measured one; the record names {published.get('symbol')!r} "
        f"(api={published.get('api')!r})"
    )
    assert published.get("api") == VENDOR_BLOCKER_API, published
    assert published.get("stop_reason") == "EXECUTION_ERROR", published
    # The stop reason alone is NOT the blocker: the record must name the dependency beside it.
    assert published.get("symbol") != published.get("stop_reason"), published


def test_a_window_that_never_ran_reports_not_run_and_names_no_blocker() -> None:
    """§8.4: "仿真完全没跑" must publish 未运行, not "it got stuck somewhere".

    Two shapes, both measured: the planner's bootstrap-trampoline decision (a window that was NEVER
    dispatched) and a sample for which the planner built no window at all. Neither may be published as a
    stall - the first would blame the simulator for a decision the plan made, the second would blame it
    for a window that never existed.
    """
    # (1) The 白象 entry shape: the Unicorn window is a plan-level NOT_APPLICABLE decision.
    rows = _t2_worker_rows(_bai_xiang_pe(), logical_path="p4-t2-trampoline.dll")
    nominal = [
        row
        for row in rows
        if str(row.get("stop_reason") or "") == "pe_entry_is_bootstrap_trampoline"
    ]
    assert nominal, (
        f"the trampoline fixture produced no NOT_APPLICABLE window: "
        f"{[(r.get('simulator'), r.get('status'), r.get('stop_reason')) for r in rows]!r}"
    )
    for row in nominal:
        published = row.get("concrete_blocker") or {}
        derived = _probe_derivation_for(row)
        assert published.get("reason") == "not_run", (
            f"a window that was never dispatched is published as {published.get('reason')!r}: {published!r}. "
            f"§8.4 requires 未运行 for a simulation that did not run"
        )
        assert derived.get("reason") == "not_run", derived
        assert "symbol" not in published or not published.get("symbol"), (
            f"a never-run window names a blocker {published.get('symbol')!r}; there is no blocker because "
            f"there was no run"
        )

    # (2) No window was planned at all. Driven through the PRODUCT's own helper on the row the API-side
    # fallback builds (`AnalysisService._emulation_fallback_payload`), because a sample short enough to
    # plan NO window at all cannot carry a Speakeasy run to compare against - and this file's job is the
    # blocker CLASSIFICATION, not the planner's window budget.
    #
    # MEASURED while writing the first version: a 424-byte non-PE blob still produces a Unicorn snippet
    # window (the planner needs only 8 bytes), so "no window at all" had to be driven directly rather
    # than hoped for from a fixture.
    from threat_report_agent.service import AnalysisService
    from threat_report_agent.tools.tool_execution import emulation_concrete_blocker

    for fallback in (
        AnalysisService._emulation_fallback_payload(None),
        AnalysisService._emulation_fallback_payload("OSError: boom [storage_key=tool-runs/x]"),
    ):
        published = emulation_concrete_blocker(fallback, observations=[])
        derived = _probe_derivation_for(fallback)
        assert published is not None, fallback
        assert published.get("reason") == derived.get("reason"), (published, derived)
        assert published.get("reason") in {"not_run", "output_unreadable"}, published
        assert not published.get("symbol"), (
            f"a run with no window at all named a symbol {published.get('symbol')!r}: {published!r}"
        )


def test_a_generic_execution_error_does_not_satisfy_the_concrete_blocker() -> None:
    """§8.4: 泛化 `EXECUTION_ERROR` 不满足 B1. Driven through the real helper and the real probe.

    The distinction under test is between "the emulator is broken" and "ONE runtime call is not
    modelled". A record that says only `EXECUTION_ERROR` is the first, and the product must still name
    what it can - so this asserts BOTH directions: an unnameable fault is classified as
    `no_observation` with no invented symbol, and the same fault WITH the adapter's prose detail is
    upgraded to a named blocker by the prose path.
    """
    from threat_report_agent.tools.tool_execution import emulation_concrete_blocker

    nameless = emulation_concrete_blocker(
        {"status": "FAILED", "stop_reason": "EXECUTION_ERROR"}, observations=[]
    )
    assert nameless is not None and nameless.get("reason") == "no_observation", nameless
    assert not nameless.get("symbol"), (
        f"a fault the record cannot name was given a symbol anyway: {nameless!r}. Inventing a blocker is "
        f"the inverse of the error T2 exists to remove"
    )
    assert nameless.get("reason") != "unsupported_api", nameless

    prose = (
        "Speakeasy stopped before observing any API call: unsupported_api "
        "api=MSVBVM60.ordinal_100 pc=0xfeedf0f0 instr=disasm_failed"
    )
    named = emulation_concrete_blocker(
        {"status": "FAILED", "stop_reason": "EXECUTION_ERROR", "limitations": [prose]},
        observations=[{"event": "request"}],
    )
    assert named is not None and named.get("reason") == "unsupported_api", named
    assert named.get("symbol") == "MSVBVM60!ordinal_100", named
    assert named.get("mechanism") == "limitation_prose", named
    # The independent probe reads the SAME prose and must reach the SAME name.
    derived = _load_probe_module().probe_derivation(
        observations=[{"event": "request"}],
        limitations=[prose],
        status="FAILED",
        stop_reason="EXECUTION_ERROR",
    )
    assert derived.get("symbol") == named.get("symbol"), (derived, named)

    # A run that simply succeeded has no blocker at all - on BOTH paths.
    clean = emulation_concrete_blocker(
        {"status": "SUCCEEDED", "stop_reason": "END_ADDRESS"}, observations=[]
    )
    assert clean is None, clean
    assert _load_probe_module().probe_derivation(
        observations=[{"event": "api", "name": "KERNEL32.MultiByteToWideChar"}],
        limitations=[],
        status="SUCCEEDED",
        stop_reason="END_ADDRESS",
    ).get("reason") is None


def test_deleting_the_independent_probe_fails_this_assertion() -> None:
    """§8.4's last clause, AS A CONTROL: with the probe gone, T2's blocker assertion must FAIL.

    A real subprocess runs ONE node of this file with the probe UNREACHABLE, requires exit 1, and shows
    the mechanism by calling the SAME loader that node calls. Then the same node is re-run in another
    real subprocess with the probe reachable and must exit 0.

    NO FILE IS RENAMED OR REWRITTEN. MEASURED: the first version of this control renamed the probe away
    for the duration of the subprocess, which made it interfere with any OTHER pytest process running
    this file at the same time - the concurrent full-suite run saw the probe vanish mid-test and the
    deletion control itself failed. The override is now an ENVIRONMENT VARIABLE read by
    `_load_probe_module` at call time, so only the subprocess sees a missing probe, the worktree is never
    mutated, and there is nothing to restore or to leave behind.

    The marker is grepped under `src/`, `tests/` and `scripts/` with THIS file excluded by construction
    (it contains the literal), which is the leftover scan the review rule asks for.
    """
    import os
    import subprocess

    repo = Path(__file__).resolve().parents[1]
    node = (
        "tests/test_analysis_api.py"
        "::test_the_concrete_blocker_in_the_product_record_matches_the_independent_probe"
    )
    absent = repo / ".scratch" / "ghidra-c3" / "preflight" / "p4-t2-probe-p4-t2-absent.py"
    assert not absent.exists(), f"{absent} must not exist for this control to mean anything"
    before_sha = hashlib.sha256(P4_T2_PROBE.read_bytes()).hexdigest()

    tampered_env = {**os.environ, "P4_T2_PROBE_PATH": str(absent)}
    completed = subprocess.run(
        ["py", "-m", "pytest", "-q", "-x", "-rf", node],
        cwd=repo,
        capture_output=True,
        env=tampered_env,
    )
    # A SECOND subprocess states the MECHANISM explicitly. MEASURED: pytest's assertion-rewriting
    # traceback for an exception raised inside a test is present in the captured stream, but its exact
    # rendering (path, quotes, tail truncation) is not something to key an assertion on, so an
    # exit-code-only control cannot show WHY the node failed. This one calls the SAME loader the node
    # calls, so with the probe unreachable it must raise the loader's own sentence.
    mechanism = subprocess.run(
        [
            "py",
            "-W",
            "ignore",
            "-c",
            "from tests.test_analysis_api import _load_probe_module; _load_probe_module(); "
            "print('PROBE_LOADED')",
        ],
        cwd=repo,
        capture_output=True,
        env=tampered_env,
    )
    tampered = {
        "returncode": completed.returncode,
        # BYTES, decoded explicitly. MEASURED: capturing this subprocess with `text=True` raised
        # `UnicodeDecodeError: 'gbk' codec can't decode byte 0xae` on this host, and the except-path left
        # the captured text EMPTY - so the control could not read its own evidence and the assertion on
        # the failure message failed on a decoding artefact rather than on behaviour.
        "stdout_tail": (completed.stdout or b"").decode("utf-8", errors="replace")[-1600:],
        "stderr_tail": (completed.stderr or b"").decode("utf-8", errors="replace")[-600:],
        "probe_still_on_disk": P4_T2_PROBE.is_file(),
        "probe_sha_unchanged": hashlib.sha256(P4_T2_PROBE.read_bytes()).hexdigest() == before_sha,
        "loader_returncode": mechanism.returncode,
        "loader_output": ((mechanism.stdout or b"") + (mechanism.stderr or b"")).decode(
            "utf-8", errors="replace"
        )[-800:],
    }

    assert tampered["probe_still_on_disk"], (
        "the probe file itself moved; this control must not touch the worktree"
    )
    assert tampered["probe_sha_unchanged"], "the probe's bytes changed during this control"
    assert tampered["returncode"] == 1, (
        f"making the independent probe unreachable left the node exiting {tampered['returncode']!r}; a T2 "
        f"blocker assertion that survives the probe's absence is reading the product's own projection "
        f"back to itself. Output was:\n{tampered['stdout_tail']}"
    )
    assert "is MISSING" in tampered["loader_output"], (
        f"with the probe unreachable, the loader this node calls did not report it as MISSING "
        f"(exit {tampered['loader_returncode']}):\n{tampered['loader_output']}"
    )
    assert tampered["loader_returncode"] == 1, (
        f"the loader exited {tampered['loader_returncode']!r} with the probe unreachable; a control that "
        f"cannot fail is not a control"
    )
    assert "PROBE_LOADED" not in tampered["loader_output"], (
        "the loader reported the probe as loaded while it was unreachable, so the tamper was not applied"
    )

    # GREEN AGAIN, in a real subprocess, with the probe reachable.
    green = subprocess.run(
        ["py", "-m", "pytest", "-q", "-rf", node],
        cwd=repo,
        capture_output=True,
        env={**os.environ},
    )
    assert green.returncode == 0, (
        f"the node does not pass again once the probe is reachable (exit {green.returncode}):\n"
        f"{(green.stdout or b'').decode('utf-8', errors='replace')[-1600:]}"
    )

    # LEFTOVER MARKER SCAN. The harness file is EXCLUDED by construction: it contains this literal.
    marker = "p4-t2-absent"
    hits: list[str] = []
    for root in ("src", "tests", "scripts"):
        for path in (repo / root).rglob("*"):
            if not path.is_file() or path.suffix not in {".py", ".json", ".md", ".txt", ".ps1"}:
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            if marker in path.read_text(encoding="utf-8", errors="replace"):
                hits.append(str(path.relative_to(repo)))
    assert hits == [], f"the tamper marker was left behind in: {hits}"
    assert not absent.exists(), f"{absent} exists after the control"
