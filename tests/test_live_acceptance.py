from __future__ import annotations

import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).parents[1] / "scripts" / "live_acceptance.py"
_SPEC = importlib.util.spec_from_file_location("live_acceptance", _MODULE_PATH)
assert _SPEC and _SPEC.loader
acceptance = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(acceptance)


class _Response:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class _Client:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def post(self, path: str, **kwargs: object) -> _Response:
        self.calls.append(("POST", path, kwargs))
        return _Response(self.payload)


def test_acceptance_session_binding_persists_and_returns_backend_id() -> None:
    client = _Client({"dsh_session_id": "session-1"})

    result = acceptance._bind_acceptance_session(client, "task-1", " session-1 ")

    assert result == "session-1"
    assert client.calls == [
        (
            "POST",
            "/api/v1/workbench/tasks/task-1/session",
            {"json": {"dsh_session_id": "session-1", "profile": "threat-static"}},
        )
    ]


def test_acceptance_session_binding_rejects_empty_or_mismatched_ids() -> None:
    client = _Client({"dsh_session_id": "session-1"})

    try:
        acceptance._bind_acceptance_session(client, "task-1", " ")
    except ValueError as exc:
        assert "must not be empty" in str(exc)
    else:
        raise AssertionError("empty acceptance session id must fail")

    try:
        acceptance._bind_acceptance_session(client, "task-1", "session-2")
    except ValueError as exc:
        assert "unexpected acceptance session link" in str(exc)
    else:
        raise AssertionError("mismatched acceptance session id must fail")
