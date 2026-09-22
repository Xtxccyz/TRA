from __future__ import annotations

import json
from dataclasses import replace

from fastapi.testclient import TestClient

from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.main import create_app
from threat_report_agent.models import ModelConfiguration


def _payload(revision: int = 0, primary_key: str = "primary-secret") -> dict[str, object]:
    return {
        "expected_revision": revision,
        "enabled": True,
        "context_max_bytes": 2500000,
        "primary": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat",
            "api_style": "openai",
            "enabled": True,
            "api_key": primary_key,
        },
        "fallback": {
            "provider": "glm",
            "base_url": "https://open.bigmodel.cn/api/paas/v4",
            "model": "glm-4-flash",
            "api_style": "openai",
            "enabled": True,
            "api_key": "fallback-secret",
        },
    }


def test_model_config_is_redacted_and_hot_reloaded(test_settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        initial = client.get("/api/v1/model-config")
        assert initial.status_code == 200
        assert initial.json()["revision"] == 0

        updated = client.put("/api/v1/model-config", json=_payload())
        assert updated.status_code == 200, updated.text
        body = updated.json()
        assert body["revision"] == 1
        assert body["primary"]["api_key_configured"] is True
        assert "primary-secret" not in json.dumps(body)
        assert "fallback-secret" not in json.dumps(body)
        assert app.state.analysis_service.settings.primary_model.api_key == "primary-secret"
        assert app.state.analysis_service.settings.primary_model.model == "deepseek-chat"

        cleared = _payload(revision=1, primary_key="")
        cleared["primary"]["clear_api_key"] = True
        cleared_response = client.put("/api/v1/model-config", json=cleared)
        assert cleared_response.status_code == 200
        assert cleared_response.json()["primary"]["api_key_configured"] is False

        conflict = client.put("/api/v1/model-config", json=_payload(revision=0))
        assert conflict.status_code == 409

        with app.state.database.session_factory() as session:
            row = session.get(ModelConfiguration, "active")
            assert row is not None
            assert row.primary_api_key_ciphertext != "primary-secret"
            assert row.fallback_api_key_ciphertext != "fallback-secret"


def test_model_config_rejects_non_tls_provider_url(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        payload = _payload()
        payload["primary"]["base_url"] = "http://untrusted.example/v1"
        response = client.put("/api/v1/model-config", json=payload)
        assert response.status_code == 422
        payload = _payload()
        payload["primary"]["base_url"] = "https://api.example/v1?token=not-allowed"
        response = client.put("/api/v1/model-config", json=payload)
        assert response.status_code == 422


def test_model_config_persists_streaming_and_sampling_controls(test_settings) -> None:
    app = create_app(test_settings)
    payload = _payload()
    payload["primary"].update(
        {
            "stream": True,
            "supports_json_mode": False,
            "temperature": 0.6,
            "top_p": 0.7,
            "disable_reasoning": True,
        }
    )
    payload["timeout_s"] = 90
    payload["max_tokens"] = 4096
    with TestClient(app) as client:
        response = client.put("/api/v1/model-config", json=payload)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["primary"]["stream"] is True
        assert body["primary"]["supports_json_mode"] is False
        assert body["primary"]["temperature"] == 0.6
        assert body["primary"]["top_p"] == 0.7
        assert body["primary"]["disable_reasoning"] is True
        assert body["timeout_s"] == 90
        assert body["max_tokens"] == 4096
        assert app.state.analysis_service.settings.primary_model.supports_json_mode is False
        assert app.state.analysis_service.settings.model_timeout_s == 90
        assert app.state.analysis_service.settings.model_max_tokens == 4096


def test_model_config_allows_disabled_fallback_without_credentials(test_settings) -> None:
    app = create_app(test_settings)
    payload = _payload()
    payload["fallback"] = {
        "provider": "",
        "base_url": "",
        "model": "",
        "enabled": False,
        "stream": False,
        "supports_json_mode": False,
    }
    with TestClient(app) as client:
        response = client.put("/api/v1/model-config", json=payload)
        assert response.status_code == 200, response.text
        assert response.json()["fallback"]["configured"] is False

def test_conversation_owned_planning_still_runs_backend_gap_rounds_when_task_missing(test_settings) -> None:
    from dataclasses import replace

    from threat_report_agent.database import Database
    from threat_report_agent.service import AnalysisService
    from threat_report_agent.content_store import LocalContentStore

    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    assert settings.dsh_conversation_owns_planning is True
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    assert service._run_gap_driven_model_rounds("task-does-not-matter") == []


def test_workbench_investigation_uses_conversation_model(test_settings) -> None:
    app = create_app(test_settings)
    with TestClient(app) as client:
        visible = client.get("/api/v1/workbench/analysis-planner-model")
        assert visible.status_code == 200, visible.text
        body = visible.json()
        assert body["distinct_from_dsh_chat"] is False
        assert body["role"] == "dsh-conversation"
        assert body["source"] == "settings.models"
        assert "分析规划" not in str(body.get("user_action", ""))
        capabilities = client.get("/api/v1/workbench/capabilities/static-actions").json()
        assert capabilities["analysis_planner_model"]["owned_by"] == "dsh-conversation"
        assert capabilities["analysis_planner_model"].get("configure_path") is None
        model_tools = {item["name"] for item in capabilities["model_callable_tools"]}
        assert "threat_configure_analysis_planner_model" not in model_tools
        forbidden = client.put("/api/v1/workbench/analysis-planner-model", json=_payload())
        assert forbidden.status_code == 405


def test_model_config_write_requires_admin(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.put(
            "/api/v1/model-config",
            headers={"X-Principal-Id": "analyst", "X-Principal-Roles": "analyst"},
            json=_payload(),
        )
        assert response.status_code == 403


def test_model_config_survives_api_restart(test_settings, tmp_path) -> None:
    settings = replace(
        test_settings,
        database_url=f"sqlite:///{tmp_path / 'config.db'}",
        content_store_path=str(tmp_path / "content"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.put("/api/v1/model-config", json=_payload())
        assert response.status_code == 200
    with TestClient(create_app(settings)) as client:
        loaded = client.get("/api/v1/model-config").json()
        assert loaded["source"] == "database"
        assert loaded["revision"] == 1
        assert loaded["primary"]["configured"] is True
        assert client.get("/healthz").json()["capabilities"]["primary_model_configured"] is True


def test_deployment_model_kill_switch_overrides_persisted_enable(test_settings, tmp_path) -> None:
    """A persisted UI preference must not re-enable calls after restart.

    ``MODEL_CALLS_ENABLED`` is represented by ``Settings.model_calls_enabled``
    in this in-process test.  The database row deliberately asks for model
    routing, then each API instance must still expose the effective disabled
    state and disabled provider routes.
    """
    settings = replace(
        test_settings,
        model_calls_enabled=False,
        database_url=f"sqlite:///{tmp_path / 'kill-switch.db'}",
        content_store_path=str(tmp_path / "content"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.put("/api/v1/model-config", json=_payload())
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["stored_enabled"] is True
        assert body["deployment_enabled"] is False
        assert body["enabled"] is False
        assert body["primary"]["stored_enabled"] is True
        assert body["primary"]["enabled"] is True
        assert body["primary"]["effective_enabled"] is False
        assert client.get("/healthz").json()["capabilities"]["agent_mode"] == (
            "deterministic_static_agent"
        )
        assert client.app.state.analysis_service.settings.model_calls_enabled is False

    with TestClient(create_app(settings)) as client:
        loaded = client.get("/api/v1/model-config").json()
        assert loaded["stored_enabled"] is True
        assert loaded["deployment_enabled"] is False
        assert loaded["enabled"] is False
        assert loaded["primary"]["enabled"] is True
        assert loaded["primary"]["effective_enabled"] is False
        assert client.app.state.analysis_service.settings.model_calls_enabled is False


def test_model_config_view_is_unconfigured_without_user_model(test_settings) -> None:
    settings = replace(
        test_settings,
        model_calls_enabled=True,
        primary_model=ModelProviderSettings("", "", "", "", enabled=True),
        fallback_model=ModelProviderSettings("", "", "", "", enabled=False),
    )
    with TestClient(create_app(settings)) as client:
        body = client.get("/api/v1/model-config").json()
    assert body["source"] == "unconfigured"
    assert body["primary"]["configured"] is False
    assert body["primary"]["provider"] == ""
    assert body["primary"]["model"] == ""
    assert body["fallback"]["enabled"] is False
    assert body["fallback"]["configured"] is False
