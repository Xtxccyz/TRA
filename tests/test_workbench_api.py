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


def test_session_model_action_provenance_survives_execution(test_settings) -> None:
    """A DSH-planned action keeps its model correlation through the static executor."""
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Model action provenance"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"import socket\nprint('static')", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        task_view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        task_detail = client.get(f"/api/v1/tasks/{task_id}").json()
        artifact_id = task_view["artifacts"][0]["id"]
        thread_id = task_view["threads"][0]["id"]
        hypothesis_id = task_view["threads"][0]["hypothesis_ids"][0]
        evidence_id = next(
            item["id"]
            for item in task_detail["evidence"]
            if item["artifact_id"] == artifact_id
        )
        linked = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "model-action-session", "profile": "threat-static"},
        )
        assert linked.status_code == 201, linked.text

        response = client.post(
            "/api/v1/workbench/sessions/model-action-session/analysis/actions",
            json={
                "action_type": "GET_STRINGS_REFERENCED",
                "target_artifact_id": artifact_id,
                "thread_id": thread_id,
                "hypothesis_id": hypothesis_id,
                "reason": "The planner requested string references for the loader hypothesis.",
                "question": "Which strings are referenced by the selected loader lead?",
                "hypothesis": "The selected static lead may expose loader-relevant strings.",
                "alternatives": ["The string is unrelated application text."],
                "missing_evidence": ["artifact-local string reference"],
                "failure_meaning": "The selected static lead remains unresolved.",
                "evidence_ids": [evidence_id],
                "target_selector": {"target": "strings"},
                "expected_evidence_kinds": ["string_reference"],
                "origin": "model",
                "planner_turn_id": "dsh-turn-model-1",
                "model_call_id": "model-call-1",
                "model_run_id": "agent-run-1",
                "model_provider": "router",
                "model_name": "qwen-test",
                "model_provenance": {
                    "provider": "router",
                    "model": "qwen-test",
                    "source": "dsh-tool",
                },
            },
        )
        assert response.status_code == 202, response.text
        action_id = response.json()["id"]
        detail = client.get(f"/api/v1/workbench/actions/{action_id}")
        assert detail.status_code == 200, detail.text
        body = detail.json()
        assert body["origin"] == "model"
        assert body["planner_turn_id"] == "dsh-turn-model-1"
        assert body["model_call_id"] == "model-call-1"
        assert body["provider"] == "router"
        assert body["model"] == "qwen-test"
        assert body["model_provenance"]["model_call_id"] == "model-call-1"
        assert body["model_provenance"]["provider"] == "router"
        assert body["result_evidence_ids"]

        events = client.get(f"/api/v1/workbench/tasks/{task_id}/events?after_seq=0").json()["events"]
        completed = next(
            event
            for event in events
            if event["type"] == "investigation.action_completed"
            and event["payload_summary"].get("planner_turn_id") == "dsh-turn-model-1"
        )
        event_payload = completed["payload_summary"]
        assert event_payload["origin"] == "model"
        assert event_payload["planner_turn_id"] == "dsh-turn-model-1"
        assert event_payload["model_call_id"] == "model-call-1"
        assert event_payload["evidence_ids"] == body["result_evidence_ids"]
        observed = next(
            event
            for event in events
            if event["type"] == "investigation.evidence_observed"
            and event["payload_summary"].get("action_id") == action_id
        )
        assert observed["payload_summary"]["planner_turn_id"] == "dsh-turn-model-1"
        for evidence in body["evidence"]:
            assert evidence["anchor"]["investigation_action_id"] == action_id
            assert evidence["anchor"]["origin"] == "model"
            assert evidence["anchor"]["planner_turn_id"] == "dsh-turn-model-1"


def test_session_action_accepts_prose_failure_interpretation(test_settings) -> None:
    """DSH often writes a branching sentence; the token still has to be accepted."""
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Failure interpretation coerce"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"import socket\nprint('static')", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        task_view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        task_detail = client.get(f"/api/v1/tasks/{task_id}").json()
        artifact_id = task_view["artifacts"][0]["id"]
        hypothesis_id = task_view["threads"][0]["hypothesis_ids"][0]
        evidence_id = next(
            item["id"]
            for item in task_detail["evidence"]
            if item["artifact_id"] == artifact_id
        )
        linked = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "failure-interp-session", "profile": "threat-static"},
        )
        assert linked.status_code == 201, linked.text

        response = client.post(
            "/api/v1/workbench/sessions/failure-interp-session/analysis/actions",
            json={
                "action_type": "GET_STRINGS_REFERENCED",
                "target_artifact_id": artifact_id,
                "hypothesis_id": hypothesis_id,
                "reason": "Recover strings referenced by the selected loader lead.",
                "question": "Which strings are referenced by the selected loader lead?",
                "hypothesis": "The selected static lead may expose loader-relevant strings.",
                "alternatives": ["The string is unrelated application text."],
                "missing_evidence": ["artifact-local string reference"],
                "failure_meaning": "The selected static lead remains unresolved.",
                "failure_interpretation": "NO_NEW_EVIDENCE 或空集 → 改查 GET_DECOMPILE",
                "evidence_ids": [evidence_id],
                "target_selector": {"target": "strings"},
                "expected_evidence_kinds": ["string_reference"],
                "origin": "model",
                "planner_turn_id": "dsh-turn-failure-interp-1",
            },
        )
        assert response.status_code == 202, response.text
        detail = client.get(f"/api/v1/workbench/actions/{response.json()['id']}")
        assert detail.status_code == 200, detail.text
        body = detail.json()
        assert body["failure_interpretation"] == "NO_NEW_EVIDENCE"
        plan = (body.get("parameters") or {}).get("_analysis_plan") or {}
        combined = " ".join(
            [
                str(body.get("failure_meaning") or ""),
                str(plan.get("failure_meaning") or ""),
            ]
        )
        assert "GET_DECOMPILE" in combined


def test_a_model_transport_failure_is_never_coerced_into_a_static_boundary() -> None:
    """B00/B04 handoff: a provider 402/timeout/empty reply is a PLATFORM fact, not a property of the sample.

    The DSH track measured that those failures arrive inside `attempts[]` on an HTTP-200 `{status: "FAILED"}`, so a
    client that only says "could not establish STATIC_BOUNDARY: provider returned 402" must not have that recorded as a
    static boundary of the artifact. The transport markers are checked BEFORE the substring loop for exactly that
    reason, and a plain STATIC_BOUNDARY statement must still map to itself.
    """
    from threat_report_agent.main import WorkbenchActionRequest, _coerce_failure_interpretation

    assert _coerce_failure_interpretation("provider returned 402 for the model call")[0] == "MODEL_TRANSPORT_FAILURE"
    assert _coerce_failure_interpretation("could not establish STATIC_BOUNDARY: provider 402")[0] == (
        "MODEL_TRANSPORT_FAILURE"
    ), "transport evidence must outrank the STATIC_BOUNDARY substring"
    assert _coerce_failure_interpretation("MODEL_CALLS_DISABLED")[0] == "MODEL_TRANSPORT_FAILURE"
    assert _coerce_failure_interpretation("EMPTY_REPLY from the provider")[0] == "MODEL_TRANSPORT_FAILURE"
    # No over-reach: an honest static boundary, a no-gain statement and an ambiguous TOOL timeout keep their meaning.
    assert _coerce_failure_interpretation("STATIC_BOUNDARY: the payload needs a live server")[0] == "STATIC_BOUNDARY"
    assert _coerce_failure_interpretation("NO_NEW_EVIDENCE")[0] == "NO_NEW_EVIDENCE"
    assert _coerce_failure_interpretation("tool TIMED_OUT after 30s")[0] == "UNKNOWN"

    request = WorkbenchActionRequest(
        action_type="GET_STRINGS_REFERENCED",
        target_artifact_id="artifact-1",
        reason="model call failed before any action could run",
        target_selector={"target": "strings"},
        expected_evidence_kinds=["string_reference"],
        failure_interpretation="transport error: provider 402, no completion returned",
    )
    assert request.failure_interpretation == "MODEL_TRANSPORT_FAILURE"
    assert request.failure_meaning, "the original prose must survive as the failure meaning, not be discarded"


def test_session_action_accepts_dsh_selector_aliases_and_long_success_condition(test_settings) -> None:
    """Live DSH sessions 422'd on function_name, length, and 160-char success_condition."""
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Selector dialect coerce"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"import socket\nprint('static')", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        task_view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        task_detail = client.get(f"/api/v1/tasks/{task_id}").json()
        artifact_id = task_view["artifacts"][0]["id"]
        hypothesis_id = task_view["threads"][0]["hypothesis_ids"][0]
        evidence_id = next(
            item["id"]
            for item in task_detail["evidence"]
            if item["artifact_id"] == artifact_id
        )
        linked = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "selector-dialect-session", "profile": "threat-static"},
        )
        assert linked.status_code == 201, linked.text

        function_response = client.post(
            "/api/v1/workbench/sessions/selector-dialect-session/analysis/actions",
            json={
                "action_type": "GET_FUNCTION",
                "target_artifact_id": artifact_id,
                "hypothesis_id": hypothesis_id,
                "reason": "Locate the selected function by the decompiler name.",
                "question": "Where is FUN_180001000 defined?",
                "hypothesis": "The named function is a recoverable static lead.",
                "alternatives": ["The name is an unrelated label."],
                "missing_evidence": ["function_context"],
                "failure_meaning": "The named function remains unresolved.",
                "success_condition": (
                    "Recover a function_context or function row for FUN_180001000 "
                    "so later GET_DECOMPILE can recover arguments, constants, and consumers."
                ),
                "evidence_ids": [evidence_id],
                "target_selector": {"function_name": "FUN_180001000"},
                "expected_evidence_kinds": ["function", "function_context"],
                "origin": "model",
                "planner_turn_id": "dsh-turn-selector-dialect-1",
            },
        )
        assert function_response.status_code == 202, function_response.text
        function_detail = client.get(f"/api/v1/workbench/actions/{function_response.json()['id']}")
        assert function_detail.status_code == 200, function_detail.text
        function_body = function_detail.json()
        assert function_body["target_selector"]["function"] == "FUN_180001000"
        assert "function_name" not in function_body["target_selector"]
        assert len(function_body["success_condition"]) <= 160

        bytes_response = client.post(
            "/api/v1/workbench/sessions/selector-dialect-session/analysis/actions",
            json={
                "action_type": "READ_BYTES",
                "target_artifact_id": artifact_id,
                "hypothesis_id": hypothesis_id,
                "reason": "Read a bounded encoded window.",
                "question": "What bytes sit at the selected window?",
                "hypothesis": "The window may be a decode input.",
                "alternatives": ["The window is padding."],
                "missing_evidence": ["bytes_read"],
                "failure_meaning": "The window remains unread.",
                "evidence_ids": [evidence_id],
                "target_selector": {"address": "0x18006de28", "length": 64},
                "expected_evidence_kinds": ["bytes_read"],
                "origin": "model",
                "planner_turn_id": "dsh-turn-selector-dialect-2",
            },
        )
        assert bytes_response.status_code == 202, bytes_response.text
        bytes_detail = client.get(f"/api/v1/workbench/actions/{bytes_response.json()['id']}")
        assert bytes_detail.status_code == 200, bytes_detail.text
        assert bytes_detail.json()["target_selector"]["length"] == 64
