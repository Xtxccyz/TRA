from __future__ import annotations

from scripts.release_issue_register import build_issue_register


def test_issue_register_counts_open_p0_and_p1_and_binds_identity() -> None:
    payload = build_issue_register(
        commit="commit-1", tree="tree-1", generated_at="2026-09-04T00:00:00Z"
    )

    assert payload["schema_version"] == "p0-p1-issue-register-v1"
    assert payload["git_commit"] == "commit-1"
    assert payload["git_tree"] == "tree-1"
    assert payload["open_p0"] == 3
    assert payload["open_p1"] == 5
    assert payload["status"] == "BLOCKED"
    assert all(issue["status"] == "OPEN" for issue in payload["issues"])


def test_issue_register_does_not_count_closed_issues() -> None:
    issues = [
        {"id": "p0", "severity": "P0", "status": "CLOSED"},
        {"id": "p1", "severity": "P1", "status": "OPEN"},
    ]

    payload = build_issue_register(commit="c", tree="t", issues=issues)

    assert payload["open_p0"] == 0
    assert payload["open_p1"] == 1
    assert payload["status"] == "BLOCKED"


def test_issue_register_rejects_unknown_status() -> None:
    issues = [{"id": "p0", "severity": "P0", "status": "RESOLVED"}]

    try:
        build_issue_register(commit="c", tree="t", issues=issues)
    except ValueError as exc:
        assert "unsupported issue status" in str(exc)
    else:
        raise AssertionError("unknown issue status must fail closed")
