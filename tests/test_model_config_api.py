from __future__ import annotations

import json
from dataclasses import replace

from fastapi.testclient import TestClient

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
