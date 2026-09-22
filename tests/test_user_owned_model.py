from __future__ import annotations

import os

from threat_report_agent.config import Settings


def test_from_environment_ships_no_builtin_analysis_model(monkeypatch) -> None:
    for name in list(os.environ):
        if name.startswith("MODEL_PRIMARY_") or name.startswith("MODEL_FALLBACK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    settings = Settings.from_environment()
    assert settings.primary_model.provider == ""
    assert settings.primary_model.model == ""
    assert settings.primary_model.base_url == ""
    assert settings.primary_model.configured is False
    assert settings.fallback_model.provider == ""
    assert settings.fallback_model.model == ""
    assert settings.fallback_model.enabled is False
    assert settings.fallback_model.configured is False
