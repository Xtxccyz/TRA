from threat_report_agent.main import create_app
from fastapi.testclient import TestClient


def test_workbench_capability_manifest_is_read_only_static(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        response = client.get("/api/v1/workbench/capabilities/static-actions")
        assert response.status_code == 200
        actions = response.json()["actions"]
        assert actions
        assert all(item["security_class"] == "READ_ONLY_STATIC" for item in actions)
        assert not {item["name"] for item in actions} & {"bash", "pwsh", "terminal", "run_code", "web_fetch"}
