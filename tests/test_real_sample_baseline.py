import importlib.util
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
