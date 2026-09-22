import importlib.util
import json
from pathlib import Path


_MODULE_PATH = Path(__file__).parents[1] / "scripts" / "real_sample_baseline.py"
_SPEC = importlib.util.spec_from_file_location("real_sample_baseline", _MODULE_PATH)
assert _SPEC and _SPEC.loader
baseline = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(baseline)


def test_timeout_keeps_task_identifier() -> None:
    error = baseline.BaselineTimeoutError("task-123")
    assert error.task_id == "task-123"
    assert str(error) == "task-123"


def test_archive_password_requirement_keeps_task_identifier() -> None:
    error = baseline.ArchivePasswordRequired("encrypted.7z", "task-123")

    assert error.task_id == "task-123"
    assert str(error) == "encrypted.7z requires --archive-password"
    assert baseline._should_cancel_after_failure(error) is False


def test_only_a_real_baseline_timeout_is_cancelled() -> None:
    assert baseline._should_cancel_after_failure(baseline.BaselineTimeoutError("task-123")) is True
    assert baseline._should_cancel_after_failure(RuntimeError("analysis failed")) is False


def test_poll_returns_bounded_terminal_status_without_full_task_projection() -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "id": "task-123",
                "lifecycle": "SUCCEEDED",
                "outcome": "PARTIAL",
                "artifact_count": 1,
                "evidence_count": 20000,
                "claim_count": 12,
            }

    class FakeClient:
        def get(self, path: str) -> FakeResponse:
            assert path == "/api/v1/tasks/task-123/status"
            return FakeResponse()

    result = baseline._poll(FakeClient(), "task-123", timeout=1)
    assert result["evidence_count"] == 20000
    assert "evidence" not in result


def test_incremental_payload_is_incomplete_when_sample_times_out(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"
    baseline._write_payload(
        output,
        [
            {"status": "PASS", "sample_name": "ok.exe"},
            {"status": "TIMEOUT", "sample_name": "slow.exe", "task_id": "task-2"},
        ],
    )
    payload = output.read_text(encoding="utf-8")
    assert '"status": "INCOMPLETE"' in payload
    assert '"task_id": "task-2"' in payload


def test_baseline_payload_records_source_identity(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"

    baseline._write_payload(
        output,
        [{"status": "PASS", "sample_name": "ok.exe"}],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "real-sample-baseline-v2"
    assert payload["generated_at"]
    assert payload["git_commit"] == baseline._git_output("rev-parse", "HEAD")
    assert payload["git_tree"] == baseline._git_output("rev-parse", "HEAD^{tree}")


def test_cancel_task_uses_product_cancel_endpoint() -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def post(self, path: str) -> FakeResponse:
            self.calls.append(("POST", path))
            return FakeResponse()

    client = FakeClient()
    assert baseline._cancel_task(client, "task-123") is True
    assert client.calls == [("POST", "/api/v1/tasks/task-123/cancel")]


def test_cancel_and_refresh_records_final_task_state() -> None:
    class FakeResponse:
        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self.payload

    class FakeClient:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def post(self, path: str) -> FakeResponse:
            self.calls.append(("POST", path))
            return FakeResponse({"lifecycle": "CANCELLED"})

        def get(self, path: str) -> FakeResponse:
            self.calls.append(("GET", path))
            return FakeResponse({
                "id": "task-123",
                "lifecycle": "CANCELLED",
                "outcome": None,
                "artifact_count": 1,
                "evidence_count": 12,
                "claim_count": 2,
                "artifacts": [{}],
                "evidence": [{}],
                "claims": [{"module": "static"}],
            })

    client = FakeClient()
    result = baseline._cancel_and_refresh(client, "task-123", {"status": "TIMEOUT"})
    assert result["cancel_requested"] is True
    assert result["lifecycle"] == "CANCELLED"
    assert result["evidence_count"] == 12
    assert client.calls == [
        ("POST", "/api/v1/tasks/task-123/cancel"),
        ("GET", "/api/v1/tasks/task-123/status"),
    ]
