from __future__ import annotations

from dataclasses import replace

import base64
import hashlib
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from threat_report_agent.config import Settings
from threat_report_agent.main import create_app
from threat_report_agent.reporting import REPORT_MODULES
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisSnapshot, AnalysisTask, Claim, TaskSecret
from threat_report_agent.intake import IntakeGateRequired
from threat_report_agent.service import AnalysisService


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

    assert task["outcome"] == "COMPLETE"
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
        assert task["outcome"] == "COMPLETE"
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
        assert response.json()["outcome"] is None
        assert client.get(f"/api/v1/tasks/{task_id}").json()["lifecycle"] == "CANCELLED"


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
        assert task["actual_granularity"] == {
            "breadth": "B0",
            "depth": "D3",
            "unmet_reasons": [],
        }
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
    assert result.outcome == "COMPLETE"
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
