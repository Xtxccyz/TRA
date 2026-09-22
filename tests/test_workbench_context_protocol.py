from __future__ import annotations

from fastapi.testclient import TestClient
from dataclasses import replace
import pytest

from threat_report_agent.main import create_app
from threat_report_agent.models import ModelCall
from threat_report_agent.service import ContextMismatchError


def test_upload_only_context_then_explicit_static_start(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        session_id = "context-upload-only"
        initial = client.get(f"/api/v1/workbench/sessions/{session_id}/analysis-context")
        assert initial.status_code == 200
        assert initial.json()["state"] == "UNBOUND"
        assert initial.json()["code"] == "NO_ACTIVE_ANALYSIS"
        planner = initial.json()["analysis_planner"]
        assert planner["distinct_from_dsh_chat"] is False
        assert planner["role"] == "dsh-conversation"
        assert planner["source"] == "settings.models"
        assert "user_action" in planner
        assert "分析规划" not in planner["user_action"]
        assert "设置" in planner["user_action"] or "模型" in planner["user_action"]

        uploaded = client.post(
            f"/api/v1/workbench/sessions/{session_id}/artifacts",
            files={"sample": ("sample.py", b"import socket\nprint('static')", "text/x-python")},
        )
        assert uploaded.status_code == 201, uploaded.text
        body = uploaded.json()
        assert body["context"]["state"] == "ARTIFACT_READY"
        assert body["context"]["active_task_id"] is None
        assert body["artifacts"]

        artifacts = client.get(f"/api/v1/workbench/sessions/{session_id}/artifacts")
        assert artifacts.status_code == 200
        assert len(artifacts.json()["items"]) == 1

        started = client.post(
            f"/api/v1/workbench/sessions/{session_id}/analysis/start",
            json={"artifact_id": body["artifacts"][0]["id"]},
        )
        assert started.status_code == 202, started.text
        start_body = started.json()
        assert start_body["active_task_id"]
        assert start_body["state"] in {"ANALYSIS_QUEUED", "ANALYSIS_RUNNING", "ANALYSIS_READY"}
        assert start_body["created"] is True


def test_context_foreign_bind_and_unbind(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "context-bind"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"print('static')", "text/x-python")},
        )
        assert submitted.status_code == 202
        task_id = submitted.json()["task_id"]
        bound = client.post(
            "/api/v1/workbench/sessions/context-history/analysis/bind",
            json={"task_id": task_id},
        )
        assert bound.status_code == 200, bound.text
        assert bound.json()["active_task_id"] == task_id
        assert bound.json()["state"] == "HISTORICAL_ANALYSIS_BOUND"

        unbound = client.post("/api/v1/workbench/sessions/context-history/analysis/unbind")
        assert unbound.status_code == 200
        # Unbinding clears the active task but retains explicitly attached
        # artifacts, so the next action is to start a new analysis.
        assert unbound.json()["state"] == "ARTIFACT_READY"
        assert unbound.json()["active_task_id"] is None


def test_start_rejects_artifact_from_another_session(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        uploaded = client.post(
            "/api/v1/workbench/sessions/context-a/artifacts",
            files={"sample": ("sample.py", b"print('a')", "text/x-python")},
        )
        artifact_id = uploaded.json()["artifacts"][0]["id"]
        response = client.post(
            "/api/v1/workbench/sessions/context-b/analysis/start",
            json={"artifact_id": artifact_id},
        )
        assert response.status_code == 403
        assert "CONTEXT_MISMATCH" in response.text


def test_workspace_import_is_relative_and_static_only(test_settings, tmp_path) -> None:
    settings = replace(test_settings, workbench_workspace_root=str(tmp_path))
    (tmp_path / "Resume.exe").write_bytes(b"MZ" + b"\x00" * 64)
    with TestClient(create_app(settings)) as client:
        listed = client.get(
            "/api/v1/workbench/sessions/workspace-session/workspace-artifacts"
        )
        assert listed.status_code == 200
        assert listed.json()["items"][0]["relative_path"] == "Resume.exe"

        imported = client.post(
            "/api/v1/workbench/sessions/workspace-session/workspace-artifacts/import",
            json={"relative_path": "Resume.exe"},
        )
        assert imported.status_code == 201
        assert imported.json()["state"] == "ARTIFACT_READY"
        assert imported.json()["active_task_id"] is None

        escaped = client.get(
            "/api/v1/workbench/sessions/workspace-session/workspace-artifacts",
            params={"relative_dir": "../"},
        )
        assert escaped.status_code == 403
        assert "WORKSPACE_PATH_ESCAPE" in escaped.text


def test_workspace_import_creates_case_when_model_invents_case_id(
    test_settings, tmp_path
) -> None:
    """3080 import must not 404 when the model guesses default/current case IDs."""
    settings = replace(test_settings, workbench_workspace_root=str(tmp_path))
    (tmp_path / "sample.bin").write_bytes(b"MZ" + b"\x00" * 64)
    with TestClient(create_app(settings)) as client:
        imported = client.post(
            "/api/v1/workbench/sessions/workspace-invented-case/workspace-artifacts/import",
            json={"relative_path": "sample.bin", "case_id": "default"},
        )
        assert imported.status_code == 201, imported.text
        body = imported.json()
        assert body["state"] == "ARTIFACT_READY"
        assert body["active_task_id"] is None
        assert body["case_id"]
        assert body["case_id"] != "default"


def test_model_gateway_requires_active_session_context(test_settings) -> None:
    """Model turns resolve the task from the server-authoritative session binding."""
    app = create_app(test_settings)
    service = app.state.analysis_service
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/workbench/model/complete",
            json={
                "operation": "planning",
                "case_id": "case-not-bound",
                "session_id": "model-unbound",
                "turn_id": "turn-1",
                "step_id": "step-1",
                "module": "planning",
                "prompt_id": "test",
                "prompt_version": "1",
                "prompt_sha256": "0" * 64,
                "messages": [{"role": "user", "content": "plan"}],
            },
        )
        assert response.status_code == 409
        assert "NO_ACTIVE_ANALYSIS" in response.text

    with pytest.raises(ContextMismatchError, match="CONTEXT_MISMATCH"):
        service.workbench_model_complete(
            {
                "operation": "planning",
                "case_id": "case-not-bound",
                "session_id": "model-unbound",
                "task_id": "foreign-task",
                "turn_id": "turn-1",
                "step_id": "step-1",
                "module": "planning",
                "prompt_id": "test",
                "prompt_version": "1",
                "prompt_sha256": "0" * 64,
                "messages": [{"role": "user", "content": "plan"}],
            }
        )


def test_model_gateway_kill_switch_blocks_active_session_without_transport_call(test_settings) -> None:
    """An active DSH session cannot bypass ``MODEL_CALLS_ENABLED=false``."""
    app = create_app(test_settings)
    service = app.state.analysis_service
    calls = 0

    class CountingGateway:
        def complete(self, request):  # pragma: no cover - failure proves the guard ran first
            nonlocal calls
            calls += 1
            raise AssertionError("model gateway must not be entered while disabled")

    service.model_gateway = CountingGateway()
    service.database.create_schema()
    case = service.create_case("disabled-model")
    submitted, _ = service.create_submission_task(
        case_id=case.id,
        filename="sample.py",
        submitted_size=len(b"print('static')"),
        content=b"print('static')",
    )
    service.workbench_link_session(submitted.task_id, "disabled-model-session")
    with pytest.raises(ValueError, match="MODEL_CALLS_DISABLED"):
        service.workbench_model_complete(
            {
                "operation": "planning",
                "case_id": case.id,
                "session_id": "disabled-model-session",
                "prompt_id": "test",
                "prompt_version": "1",
                "prompt_sha256": "0" * 64,
                "messages": [{"role": "user", "content": "plan"}],
            }
        )
    assert calls == 0
    with service.database.session_factory() as session:
        assert session.query(ModelCall).count() == 0


def test_workspace_import_rejects_host_paths_and_symlink_escape(test_settings, tmp_path) -> None:
    settings = replace(test_settings, workbench_workspace_root=str(tmp_path))
    outside = tmp_path.parent / "outside-threat-workbench.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "linked-outside.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        link = None

    with TestClient(create_app(settings)) as client:
        for path in ("C:/Windows/win.ini", "\\\\server\\share\\sample.exe", "../outside.txt"):
            response = client.post(
                "/api/v1/workbench/sessions/path-security/workspace-artifacts/import",
                json={"relative_path": path},
            )
            assert response.status_code == 403, (path, response.text)
            assert "WORKSPACE_PATH_ESCAPE" in response.text
        if link is not None:
            response = client.post(
                "/api/v1/workbench/sessions/path-security/workspace-artifacts/import",
                json={"relative_path": link.name},
            )
            assert response.status_code == 403
            assert "WORKSPACE_SYMLINK_ESCAPE" in response.text


def test_task_projections_require_matching_dsh_session_for_ordinary_roles(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        uploaded = client.post(
            "/api/v1/workbench/sessions/task-scope-a/artifacts",
            files={"sample": ("scope.py", b"print('scope')", "text/x-python")},
        )
        assert uploaded.status_code == 201, uploaded.text
        started = client.post(
            "/api/v1/workbench/sessions/task-scope-a/analysis/start",
            json={"artifact_id": uploaded.json()["artifacts"][0]["id"]},
        )
        assert started.status_code == 202, started.text
        task_id = started.json()["active_task_id"]
        analyst = {"X-Principal-Id": "analyst-1", "X-Principal-Roles": "analyst"}

        denied_without_context = client.get(
            f"/api/v1/workbench/tasks/{task_id}", headers=analyst
        )
        assert denied_without_context.status_code == 403
        assert "X-DSH-Session-ID" in denied_without_context.text

        denied_foreign = client.get(
            f"/api/v1/workbench/tasks/{task_id}",
            headers={**analyst, "X-DSH-Session-ID": "task-scope-b"},
        )
        assert denied_foreign.status_code == 403
        assert "CONTEXT_MISMATCH" in denied_foreign.text

        allowed_bound = client.get(
            f"/api/v1/workbench/tasks/{task_id}",
            headers={**analyst, "X-DSH-Session-ID": "task-scope-a"},
        )
        assert allowed_bound.status_code == 200, allowed_bound.text


def test_workbench_cors_allows_session_scope_header(test_settings) -> None:
    """The DSH port must be able to preflight session-scoped API requests."""
    with TestClient(create_app(test_settings)) as client:
        response = client.options(
            "/api/v1/workbench/sessions/cors-session/artifacts",
            headers={
                "Origin": "http://127.0.0.1:3080",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-dsh-session-id",
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:3080"
        allowed = response.headers["access-control-allow-headers"].lower()
        assert "x-dsh-session-id" in allowed


def test_workbench_cors_allows_put_model_config(test_settings) -> None:
    """Admin model-config writes remain PUT across the 3080/8000 origin split."""
    with TestClient(create_app(test_settings)) as client:
        response = client.options(
            "/api/v1/model-config",
            headers={
                "Origin": "http://127.0.0.1:3080",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert response.status_code == 200, response.text
        assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:3080"
        allowed = response.headers["access-control-allow-methods"].upper()
        assert "PUT" in allowed


def test_analysis_intent_does_not_start_without_analyze_request(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        session_id = "intent-no-analyze"
        uploaded = client.post(
            f"/api/v1/workbench/sessions/{session_id}/artifacts",
            files={"sample": ("sample.py", b"print('static')", "text/x-python")},
        )
        assert uploaded.status_code == 201, uploaded.text
        skipped = client.post(
            f"/api/v1/workbench/sessions/{session_id}/analysis/intent",
            json={"question": "这个样本是什么格式"},
        )
        assert skipped.status_code == 200, skipped.text
        body = skipped.json()
        assert body["dispatched"] is False
        assert body["created"] is False
        assert body["reason"] == "NOT_ANALYSIS_INTENT"
        assert body["active_task_id"] is None
        assert body["state"] == "ARTIFACT_READY"


def test_analysis_intent_starts_attached_sample(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        session_id = "intent-attached"
        uploaded = client.post(
            f"/api/v1/workbench/sessions/{session_id}/artifacts",
            files={"sample": ("sample.py", b"print('static')", "text/x-python")},
        )
        assert uploaded.status_code == 201, uploaded.text
        started = client.post(
            f"/api/v1/workbench/sessions/{session_id}/analysis/intent",
            json={"question": "分析这个样本"},
        )
        assert started.status_code == 200, started.text
        body = started.json()
        assert body["dispatched"] is True
        assert body["created"] is True
        assert body["active_task_id"]
        assert body["state"] in {"ANALYSIS_QUEUED", "ANALYSIS_RUNNING", "ANALYSIS_READY"}
        again = client.post(
            f"/api/v1/workbench/sessions/{session_id}/analysis/intent",
            json={"question": "分析这个样本"},
        )
        assert again.status_code == 200, again.text
        assert again.json()["created"] is False
        assert again.json()["reason"] in {"ALREADY_RUNNING", "ALREADY_BOUND"}
        assert again.json()["active_task_id"] == body["active_task_id"]


def test_analysis_intent_imports_single_workspace_candidate(test_settings, tmp_path) -> None:
    settings = replace(test_settings, workbench_workspace_root=str(tmp_path))
    (tmp_path / "Resume.py").write_bytes(b"print('static')")
    with TestClient(create_app(settings)) as client:
        started = client.post(
            "/api/v1/workbench/sessions/intent-workspace/analysis/intent",
            json={"question": "analyze this sample"},
        )
        assert started.status_code == 200, started.text
        body = started.json()
        assert body["dispatched"] is True
        assert body["created"] is True
        assert body["imported_relative_path"] == "Resume.py"
        assert body["active_task_id"]
        context = client.get("/api/v1/workbench/sessions/intent-workspace/analysis-context")
        assert context.json()["attached_artifact_ids"]


def test_analysis_intent_requires_choice_when_workspace_has_two_candidates(
    test_settings, tmp_path
) -> None:
    settings = replace(test_settings, workbench_workspace_root=str(tmp_path))
    (tmp_path / "a.py").write_bytes(b"print('a')")
    (tmp_path / "b.py").write_bytes(b"print('b')")
    with TestClient(create_app(settings)) as client:
        skipped = client.post(
            "/api/v1/workbench/sessions/intent-two-candidates/analysis/intent",
            json={"question": "分析这个样本"},
        )
        assert skipped.status_code == 200, skipped.text
        body = skipped.json()
        assert body["dispatched"] is False
        assert body["reason"] == "SAMPLE_SELECTION_REQUIRED"
        assert body["workspace_candidate_count"] == 2
        assert body["active_task_id"] is None


def test_analysis_intent_replaces_leftover_sample_with_single_workspace_candidate(
    test_settings, tmp_path
) -> None:
    """3080 '分析这个样本' must not wait on a reused session's leftover PE."""
    workspace = tmp_path / "samples"
    workspace.mkdir()
    (workspace / "Resume.pdf.exe.VIR").write_bytes(b"print('resume-static')")
    settings = replace(test_settings, workbench_workspace_root=str(workspace))
    with TestClient(create_app(settings)) as client:
        leftover = client.post(
            "/api/v1/workbench/sessions/intent-leftover/artifacts",
            files={
                "sample": (
                    "ComHost.exe.VIR",
                    b"print('comhost-static')",
                    "application/octet-stream",
                )
            },
        )
        assert leftover.status_code == 201, leftover.text
        started = client.post(
            "/api/v1/workbench/sessions/intent-leftover/analysis/start",
            json={"artifact_id": leftover.json()["artifacts"][0]["id"]},
        )
        assert started.status_code == 202, started.text
        leftover_task = started.json()["active_task_id"]
        assert leftover_task

        dispatched = client.post(
            "/api/v1/workbench/sessions/intent-leftover/analysis/intent",
            json={"question": "分析这个样本"},
        )
        assert dispatched.status_code == 200, dispatched.text
        body = dispatched.json()
        assert body["dispatched"] is True
        assert body["created"] is True
        assert body["imported_relative_path"] == "Resume.pdf.exe.VIR"
        assert body["active_task_id"]
        assert body["active_task_id"] != leftover_task
        context = client.get(
            "/api/v1/workbench/sessions/intent-leftover/analysis-context"
        )
        names = [
            item["logical_path"] for item in context.json()["attached_artifacts"]
        ]
        assert names == ["Resume.pdf.exe.VIR"]
