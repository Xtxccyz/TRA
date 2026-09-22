from __future__ import annotations

from threat_report_agent.main import create_app
from threat_report_agent.runtime_contracts import ContextBudgetManager, classify_failure, retry_decision
from fastapi.testclient import TestClient


def test_context_budget_compacts_tool_history_and_enforces_reserve() -> None:
    manager = ContextBudgetManager(4096, safety_margin_bytes=128, max_tool_result_bytes=256, max_messages=8)
    messages = [{"role": "system", "content": "static-only"}]
    messages.extend({"role": "tool", "content": "x" * 1200} for _ in range(20))
    decision = manager.prepare(messages, reserved_completion_bytes=512)
    assert decision.compacted is True
    assert decision.allowed is True
    assert len(decision.messages) <= 8
    assert any("tool_result_compacted" in item["content"] for item in decision.messages if item["role"] == "tool")


def test_failure_contract_is_sanitized_and_retries_identical_failures_are_suppressed() -> None:
    first = classify_failure(RuntimeError("worker failed with secret=do-not-expose"), stage="MECHANISM_INVESTIGATION")
    assert first["failure_code"] == "STATIC_WORKFLOW_ACTIVITY_FAILED"
    assert first["retryable"] is False
    decision = retry_decision(
        retryable=bool(first["retryable"]),
        previous_fingerprint=str(first["failure_fingerprint"]),
        fingerprint=str(first["failure_fingerprint"]),
    )
    assert decision["retry"] is False
    assert decision["retry_suppressed"] is True


def test_failure_contract_classifies_derived_index_corruption_as_retryable_db_failure() -> None:
    failure = classify_failure(
        RuntimeError("psycopg.errors.DataCorrupted: compressed lz4 data is corrupt while writing evidence_search_keys"),
        stage="EVIDENCE_PERSISTENCE",
    )
    assert failure["failure_code"] == "DB_FAILURE"
    assert failure["failed_activity"]
    assert failure["retryable"] is True


def test_workbench_capabilities_distinguish_model_tools_from_backend_actions(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.get("/api/v1/workbench/capabilities/static-actions")
        assert response.status_code == 200
        body = response.json()
        names = {item["name"] for item in body["backend_static_action_catalog"]}
        model_tools = {item["name"] for item in body["model_callable_tools"]}
        assert "GET_DECOMPILE" in names
        assert "threat_propose_static_action" in model_tools
        assert body["action_submission_tool"] == "threat_propose_static_action"
        assert "sample_execution" in body["unavailable_capabilities"]
        assert body["sample_execution"] is False
        assert body["isolated_emulation"]["host_sample_execution"] is False
        assert "granted-window" in str(body["isolated_emulation"]["description"]).casefold()
        assert "static analysis" in str(body["isolated_emulation"]["description"]).casefold()
        assert "sandbox/dynamic analysis" in str(body["isolated_emulation"]["description"]).casefold()
        assert "threat_get_analysis_planner_model" not in model_tools
        assert "threat_configure_analysis_planner_model" not in model_tools
        assert body["analysis_planner_model"]["distinct_from_dsh_chat"] is False
        assert body["analysis_planner_model"]["role"] == "dsh-conversation"
        assert body["analysis_planner_model"]["owned_by"] == "dsh-conversation"


def test_wait_endpoint_returns_bounded_unbound_projection(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.get(
            "/api/v1/workbench/sessions/runtime-wait-empty/analysis/wait",
            params={"after_seq": 0, "timeout_seconds": 0},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["changed"] is False
        assert body["context"]["state"] == "UNBOUND"
        assert body["context"]["code"] == "NO_ACTIVE_ANALYSIS"
        assert body["events"] == []


def test_app_lifespan_releases_sqlite_handles(tmp_path, test_settings) -> None:
    """Windows must be able to remove a temporary DB after TestClient exits."""
    from dataclasses import replace
    import shutil

    db_path = tmp_path / "lifespan.db"
    settings = replace(test_settings, database_url=f"sqlite:///{db_path}")
    with TestClient(create_app(settings)) as client:
        assert client.get("/healthz").status_code == 200
    # A lingering pooled connection would make this fail on Windows.
    shutil.rmtree(tmp_path)


def test_analysis_coverage_does_not_treat_pipeline_completion_as_verified_semantics(test_settings) -> None:
    service, database = _service_for_runtime(test_settings)
    case = service.create_case("coverage semantics")
    result = service.analyze_submission(case_id=case.id, filename="coverage.py", content=b"print('x')")
    task = service.task_view(result.task_id)
    coverage = task["analysis_coverage"]
    assert coverage["pipeline_completion"]["score"] == 100.0
    assert coverage["dimensions"]["verified_mechanism_coverage"] == 0.0
    assert coverage["dimensions"]["relation_flow_coverage"] == 0.0
    assert coverage["score"] < 100.0


def _service_for_runtime(test_settings):
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.service import AnalysisService
    database = Database(test_settings.database_url)
    service = AnalysisService(test_settings, database, LocalContentStore(test_settings.content_store_path))
    database.create_schema()
    return service, database
