from __future__ import annotations

from fastapi.testclient import TestClient
from dataclasses import replace
import pytest

from threat_report_agent.main import create_app
from threat_report_agent.service import ContextMismatchError


def test_upload_only_context_then_explicit_static_start(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        session_id = "context-upload-only"
        initial = client.get(f"/api/v1/workbench/sessions/{session_id}/analysis-context")
        assert initial.status_code == 200
        assert initial.json()["state"] == "UNBOUND"
        assert initial.json()["code"] == "NO_ACTIVE_ANALYSIS"

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
