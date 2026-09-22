from __future__ import annotations

from threat_report_agent.investigation.mechanism_completeness import mechanism_is_critical_ready
from threat_report_agent.investigation.mechanism_ready import inspect_mechanism_ready


def _closed_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "status": "VERIFIED",
        "target": "CreateProcessW",
        "inputs": "command line buffer at 0x401000",
        "transformation_or_control": (
            "CreateProcessW command=C:\\Windows\\System32\\cmd.exe "
            "creation_flags=CREATE_NO_WINDOW parent=explorer.exe"
        ),
        "conditions": "parent process handle recovered",
        "outputs": "new process object",
        "consumers": "child process startup",
        "side_effects": "process creation",
        "evidence_ids": ["ev-1", "ev-2"],
        "verifier": {"status": "VERIFIED"},
    }
    row.update(overrides)
    return row


def test_candidate_with_recovered_how_is_not_critical_ready() -> None:
    row = _closed_row(status="CANDIDATE", verifier={"status": "VERIFIED"})
    view = inspect_mechanism_ready(row)
    assert view.persist_how_recovered is True
    assert view.critical_ready is False
    assert mechanism_is_critical_ready(row) is True


def test_claim_eligible_does_not_imply_critical_ready() -> None:
    view = inspect_mechanism_ready(
        _closed_row(
            status="CANDIDATE",
            coverage={"claim_eligible": True},
            verifier={"status": "CANDIDATE"},
        )
    )
    assert view.claim_eligible is True
    assert view.critical_ready is False


def test_verified_complete_row_is_critical_ready() -> None:
    row = _closed_row()
    view = inspect_mechanism_ready(row)
    assert view.critical_ready is True
    assert view.completeness >= 80
    assert view.persist_how_recovered is True
    assert mechanism_is_critical_ready(row) is True


def test_missing_transform_is_not_persist_how_recovered() -> None:
    view = inspect_mechanism_ready(
        _closed_row(
            transformation_or_control="not recovered",
            how="not recovered",
        )
    )
    assert view.persist_how_recovered is False
    assert view.critical_ready is False


def test_inspect_critical_ready_excludes_candidate_only() -> None:
    rows = (
        _closed_row(),
        _closed_row(status="CANDIDATE"),
        _closed_row(consumers="unknown"),
        _closed_row(verifier={"status": "CANDIDATE"}),
        {"status": "VERIFIED", "how": "CreateProcessW command=cmd.exe"},
    )
    for row in rows:
        status = str(row.get("status") or "").upper()
        expected = mechanism_is_critical_ready(row) and status != "CANDIDATE"
        assert inspect_mechanism_ready(row).critical_ready is expected
