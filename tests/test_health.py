from fastapi.testclient import TestClient

from threat_report_agent.config import Settings
from threat_report_agent.main import create_app


def test_health_exposes_capability_flags_without_secrets(test_settings: Settings) -> None:
    response = TestClient(create_app(test_settings)).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "environment": "test",
        "capabilities": {
            "deterministic_static_analysis": True,
            "all_static_modules": True,
            "report_formats": ["markdown", "docx", "pdf", "json"],
            "primary_model_configured": True,
                "fallback_model_configured": False,
                "configured_model_families": ["custom"],
                "model_provider_contracts": {
                    "gpt": {
                        "family": "gpt",
                        "protocol": "openai-chat-completions-v1",
                        "endpoint_path": "/chat/completions",
                        "auth_header": "Authorization",
                        "default_base_url": "https://api.openai.com/v1",
                        "structured_output": "json_object",
                    },
                    "claude": {
                        "family": "claude",
                        "protocol": "anthropic-messages-v1",
                        "endpoint_path": "/messages",
                        "auth_header": "x-api-key",
                        "default_base_url": "https://api.anthropic.com/v1",
                        "structured_output": "json_object",
                    },
                    "qwen": {
                        "family": "qwen",
                        "protocol": "openai-chat-completions-v1",
                        "endpoint_path": "/chat/completions",
                        "auth_header": "Authorization",
                        "default_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                        "structured_output": "json_object",
                    },
                    "kimi": {
                        "family": "kimi",
                        "protocol": "openai-chat-completions-v1",
                        "endpoint_path": "/chat/completions",
                        "auth_header": "Authorization",
                        "default_base_url": "https://api.moonshot.cn/v1",
                        "structured_output": "json_object",
                    },
                    "glm": {
                        "family": "glm",
                        "protocol": "openai-chat-completions-v1",
                        "endpoint_path": "/chat/completions",
                        "auth_header": "Authorization",
                        "default_base_url": "https://open.bigmodel.cn/api/paas/v4",
                        "structured_output": "json_object",
                    },
                },
                "model_context_max_bytes": 2_000_000,
                "model_call_timeout_s": 180.0,
                "model_call_max_tokens": 2048,
                "ghidra_home_configured": False,
            "agent_mode": "deterministic_static_agent",
        },
    }
    assert "test-key" not in response.text


def test_readiness_probes_database_without_exposing_secrets(test_settings: Settings) -> None:
    response = TestClient(create_app(test_settings)).get("/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "checks": {"database": "ok"}}
    assert "test-key" not in response.text
