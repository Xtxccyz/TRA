from __future__ import annotations

from pathlib import Path

import pytest

from threat_report_agent.config import ModelProviderSettings, Settings


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite://",
        object_store_endpoint="http://object-store",
        object_store_bucket="test",
        object_store_access_key="test",
        object_store_secret_key="test",
        content_store_backend="local",
        content_store_path=str(tmp_path / "content"),
        temporal_address="temporal:7233",
        ghidra_home="",
        java_home="",
        max_sample_files=100,
        max_sample_bytes=16 * 1024 * 1024,
        max_archive_depth=3,
        primary_model=ModelProviderSettings(
            "test-provider",
            "http://model.invalid/v1",
            "test-model",
            "test-key",
        ),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
        gate_secret_key="test-gate-secret",
    )
