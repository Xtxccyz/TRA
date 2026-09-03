from __future__ import annotations

import io
import zipfile

from fastapi.testclient import TestClient

from threat_report_agent.main import create_app


def _zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("sample.py", "import socket\nprint('static')")
    return out.getvalue()


def test_workbench_contract_is_task_scoped_and_reconnectable(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Workbench"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.zip", _zip(), "application/zip")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]

        capabilities = client.get("/api/v1/workbench/capabilities/static-actions")
        assert capabilities.status_code == 200
        assert capabilities.json()["api_version"] == 1
        assert "GET_XREFS_TO" in {row["name"] for row in capabilities.json()["actions"]}

        link = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "dsh-session-1", "profile": "threat-static"},
        )
        assert link.status_code == 201, link.text
        assert link.json()["dsh_session_id"] == "dsh-session-1"
        resolved = client.get("/api/v1/workbench/sessions/dsh-session-1/task")
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["link"]["task_id"] == task_id
        unbound = client.get("/api/v1/workbench/sessions/unbound/task")
        assert unbound.status_code == 200, unbound.text
        assert unbound.json()["link"] is None
        assert unbound.json()["state"] == "UNBOUND"
        assert unbound.json()["code"] == "NO_ACTIVE_ANALYSIS"
        duplicate = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "dsh-session-2", "profile": "threat-static"},
        )
        assert duplicate.status_code == 409

        view = client.get(f"/api/v1/workbench/tasks/{task_id}")
        assert view.status_code == 200
        assert view.json()["schema_version"] == 1
        assert view.json()["task"]["id"] == task_id
        events = client.get(f"/api/v1/workbench/tasks/{task_id}/events?after_seq=0")
        assert events.status_code == 200
        body = events.json()
        assert all(body["events"][i]["seq"] < body["events"][i + 1]["seq"] for i in range(len(body["events"]) - 1))
        if body["events"]:
            again = client.get(
                f"/api/v1/workbench/tasks/{task_id}/events?after_seq={body['events'][-1]['seq']}"
            ).json()
            assert again["events"] == []


def test_workbench_evidence_query_never_accepts_cross_task_ids(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.post(
            "/api/v1/workbench/evidence/query",
            json={"task_id": "missing-task", "limit": 10},
        )
        assert response.status_code == 404


def test_workbench_domain_projections_are_task_scoped(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Projection"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.zip", _zip(), "application/zip")},
        )
        task_id = submitted.json()["task_id"]

        for suffix, key in (
            ("mechanisms", "mechanisms"),
            ("claims", "claims"),
            ("relations", "relations"),
            ("sample-timeline", "items"),
        ):
            response = client.get(f"/api/v1/workbench/tasks/{task_id}/{suffix}")
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["schema_version"] == 1
            assert body["task_id"] == task_id
            assert isinstance(body[key], list)

        missing = client.get("/api/v1/workbench/tasks/missing/claims")
        assert missing.status_code == 404


def test_workbench_action_detail_and_execution_projection(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Action detail"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.zip", _zip(), "application/zip")},
        )
        task_id = submitted.json()["task_id"]
        before = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        before_revision = before["report"]["revision_id"]
        # A queued action can be submitted through the closed catalog and is
        # immediately processed by the static evidence executor.
        view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        artifact_id = view["artifacts"][0]["id"]
        payload = {
            "action_type": "GET_FUNCTION",
            "target_artifact_id": artifact_id,
            "reason": "inspect the selected function",
            "target_selector": {"function": "entrypoint"},
            "expected_evidence_kinds": ["function_context"],
        }
        submitted_action = client.post(
            f"/api/v1/workbench/tasks/{task_id}/actions", json=payload
        )
        assert submitted_action.status_code == 202, submitted_action.text
        action_id = submitted_action.json()["id"]

        detail = client.get(
            f"/api/v1/workbench/tasks/{task_id}/actions/{action_id}"
        )
        assert detail.status_code == 200, detail.text
        assert detail.json()["id"] == action_id
        assert detail.json()["task_id"] == task_id
        missing = client.get(
            f"/api/v1/workbench/tasks/{task_id}/actions/missing-action"
        )
        assert missing.status_code == 404

        after = client.get(
            f"/api/v1/workbench/tasks/{task_id}/actions/{action_id}"
        )
        assert after.status_code == 200, after.text
        body = after.json()
        assert body["status"] in {"QUEUED", "RUNNING", "SUCCEEDED", "FAILED"}
        assert "result_evidence_ids" in body
        assert "semantic_result" in body
        assert "report_revision_id" in body
        assert body["report_revision_id"] != before_revision


def test_workbench_domain_projections_and_action_execution_are_public(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Action execution"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"import socket\nprint('static')", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        artifact_id = view["artifacts"][0]["id"]
        thread = view["threads"][0]
        action = client.post(
            f"/api/v1/workbench/tasks/{task_id}/actions",
            json={
                "action_type": "GET_XREFS_TO",
                "target_artifact_id": artifact_id,
                "hypothesis_id": thread["hypothesis_ids"][0],
                "reason": "Expand the current static investigation frontier",
                "target_selector": {"target": "socket"},
                "expected_evidence_kinds": ["xref", "function_context"],
            },
        )
        assert action.status_code == 202, action.text
        action_id = action.json()["id"]
        detail = client.get(f"/api/v1/workbench/actions/{action_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["status"] in {"SUCCEEDED", "QUEUED", "FAILED"}
        for suffix in ("mechanisms", "claims", "relations", "sample-timeline"):
            response = client.get(f"/api/v1/workbench/tasks/{task_id}/{suffix}")
            assert response.status_code == 200, response.text
            assert response.json()["task_id"] == task_id
