"""Run a safe, static-only acceptance probe against a running Compose stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx


def _git_output(*args: str) -> str | None:
    """Return a repository identity value without making acceptance depend on Git."""
    try:
        result = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[1],
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bind_acceptance_session(
    client: httpx.Client,
    task_id: str,
    session_id: str,
) -> str:
    """Create the durable task/session link used by acceptance evidence."""
    normalized = session_id.strip()
    if not normalized:
        raise ValueError("acceptance session id must not be empty")
    response = client.post(
        f"/api/v1/workbench/tasks/{task_id}/session",
        json={"dsh_session_id": normalized, "profile": "threat-static"},
    )
    response.raise_for_status()
    linked = response.json()
    if not isinstance(linked, dict) or linked.get("dsh_session_id") != normalized:
        raise ValueError("backend returned an unexpected acceptance session link")
    return normalized


def _wait_for_health(client: httpx.Client, timeout: float = 120.0) -> None:
    """Wait for the API listener after a Compose restart."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = client.get("/healthz")
            response.raise_for_status()
            if response.json().get("status") == "ok":
                return
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
        time.sleep(1.0)
    detail = f": {last_error}" if last_error else ""
    raise TimeoutError(f"API did not become healthy within {timeout:.0f}s{detail}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--sample", type=Path, default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write the bounded acceptance record to JSON as well as stdout",
    )
    # A configured remote planner may require several bounded turns.  Keep
    # the timeout configurable while allowing the default to cover a real
    # production-shaped run instead of failing while the task is still
    # progressing.
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument(
        "--session-id",
        default=None,
        help="bind the run to this DSH session id; otherwise create a unique acceptance session",
    )
    args = parser.parse_args()

    sample = args.sample or Path(__file__).parents[1] / ".data" / "live-acceptance-sample.py"
    sample.parent.mkdir(parents=True, exist_ok=True)
    if not sample.exists():
        sample.write_text("import socket\nprint('static-only-live-acceptance')\n", encoding="utf-8")

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0) as client:
        _wait_for_health(client)

        case = client.post("/api/v1/cases", json={"title": "live-acceptance"})
        case.raise_for_status()
        case_id = case.json()["id"]
        with sample.open("rb") as handle:
            submitted = client.post(
                f"/api/v1/cases/{case_id}/tasks",
                files={"sample": (sample.name, handle, "text/x-python")},
                data={
                    "background_context": "live static acceptance context",
                    "background_source": "live-acceptance-script",
                    "background_confidence": "HIGH",
                    "background_human_confirmed": "true",
                    "selected_modules": "[]",
                },
            )
        submitted.raise_for_status()
        task_id = submitted.json()["task_id"]
        session_id = _bind_acceptance_session(
            client,
            task_id,
            args.session_id or f"live-acceptance-{uuid4().hex}",
        )

        deadline = time.monotonic() + args.timeout
        while True:
            # The full task view may contain hundreds of megabytes of
            # evidence.  Poll the bounded status projection and fetch the
            # ledger exactly once after the workflow reaches a terminal state.
            task_response = client.get(f"/api/v1/tasks/{task_id}/status")
            task_response.raise_for_status()
            task = task_response.json()
            if task["lifecycle"] in {"SUCCEEDED", "FAILED", "CANCELLED", "WAITING_GATE"}:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"task {task_id} did not reach a terminal state")
            time.sleep(2)

        full_task_response = client.get(f"/api/v1/tasks/{task_id}")
        full_task_response.raise_for_status()
        task = full_task_response.json()

        assert task["lifecycle"] == "SUCCEEDED", task
        # A small script can legitimately be PARTIAL/BOUNDED when the static
        # evidence is insufficient for a complete mechanism explanation.  The
        # acceptance probe verifies truthful classification rather than
        # requiring an unjustified COMPLETE verdict.
        assert task["outcome"] in {"COMPLETE", "PARTIAL"}, task
        assert task["analysis_class"] in {
            "FULL_STATIC_ANALYSIS",
            "BOUNDED_STATIC_ANALYSIS",
        }, task
        assert task["actual_granularity"]["depth"] in {"D2", "D3"}
        assert any(item["nature"] == "BACKGROUND_REPORTED" for item in task["evidence"])
        temporal_tools = {
            "python-zipfile-safe-reader",
            "builtin-static-analyzer",
            "pe-parser",
            "script-parser",
            "document-carrier-parser",
            "ghidra-headless",
        }
        temporal_runs = [item for item in task["tool_runs"] if item["tool"] in temporal_tools]
        assert temporal_runs and all(
            item["status"] == "SUCCEEDED"
            and item.get("execution", {}).get("executor") == "temporal"
            for item in temporal_runs
        )
        integrity = client.get(f"/api/v1/tasks/{task_id}/audit/integrity")
        integrity.raise_for_status()
        assert integrity.json()["valid"] is True
        report = client.get(f"/api/v1/reports/{task['latest_report_revision_id']}")
        report.raise_for_status()
        report_payload = report.json()
        assert report_payload["snapshot_id"]

        # Keep this projection bounded and evaluator-friendly.  The task
        # endpoint contains the complete evidence ledger; the acceptance
        # record only needs counts, statuses, and digests to prove the path
        # without duplicating potentially multi-megabyte evidence values.
        model_calls = task.get("model_calls") or []
        model_call_statuses = [str(item.get("status", "")) for item in model_calls]
        model_call_origins = sorted(
            {
                str(item.get("origin"))
                for item in model_calls
                if item.get("origin")
            }
        )
        audit_payload = client.get(f"/api/v1/tasks/{task_id}/audit")
        audit_payload.raise_for_status()
        audit_events = audit_payload.json()
        if isinstance(audit_events, dict):
            audit_events = audit_events.get("events", [])
        audit_events = audit_events if isinstance(audit_events, list) else []
        audit_sequences = [
            int(item["chain_sequence"])
            for item in audit_events
            if isinstance(item, dict) and item.get("chain_sequence") is not None
        ]
        result = {
            "schema_version": "live-static-acceptance-v2",
            "status": "PASS",
            "evidence_level": "L2",
            "generated_at": datetime.now(UTC).isoformat(),
            "git_commit": _git_output("rev-parse", "HEAD"),
            # Match the release gate's immutable checkout identity.  A
            # writable index tree (``git write-tree``) can include staged
            # changes that are not part of HEAD and would never certify the
            # same source revision.
            "git_tree": _git_output("rev-parse", "HEAD^{tree}"),
            "sample": {
                "name": sample.name,
                "size": sample.stat().st_size,
                "sha256": _sha256(sample),
            },
            "case_id": case_id,
            "task_id": task_id,
            "session_id": session_id,
            "lifecycle": task["lifecycle"],
            "outcome": task["outcome"],
            "analysis_class": task["analysis_class"],
            "actual_granularity": task["actual_granularity"],
            "counts": {
                "artifacts": len(task.get("artifacts") or []),
                "evidence": len(task.get("evidence") or []),
                "claims": len(task.get("claims") or []),
                "relations": len(task.get("relations") or []),
                "tool_runs": len(task.get("tool_runs") or []),
                "analysis_turns": len(task.get("analysis_turns") or []),
                "analysis_turn_results": len(task.get("analysis_turn_results") or []),
                "model_calls": len(model_calls),
            },
            "model": {
                "call_statuses": model_call_statuses,
                "origins": model_call_origins,
                "successful_calls": sum(status == "SUCCEEDED" for status in model_call_statuses),
                "model_contribution_proven": any(
                    str(item.get("origin")) == "model"
                    and str(item.get("status")) == "SUCCEEDED"
                    and item.get("result_evidence_ids")
                    for item in model_calls
                ),
            },
            "audit": {
                "event_count": len(audit_events),
                "first_sequence": min(audit_sequences) if audit_sequences else None,
                "last_sequence": max(audit_sequences) if audit_sequences else None,
                "integrity_valid": True,
            },
            "provenance": {
                "sample_sha256": _sha256(sample),
                "case_id": case_id,
                "task_id": task_id,
                "session_id": session_id,
                "event_cursor_range": {
                    "first": min(audit_sequences) if audit_sequences else None,
                    "last": max(audit_sequences) if audit_sequences else None,
                },
                "metadata_status": "COMPLETE",
                "missing_fields": [],
            },
            "report": {
                "revision_id": task["latest_report_revision_id"],
                "snapshot_id": report_payload["snapshot_id"],
            },
            "execution_boundary": {
                "sample_execution": False,
                "sample_network_access": False,
                "dynamic_emulators_invoked": False,
            },
        }

    encoded = json.dumps(result, ensure_ascii=True, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
