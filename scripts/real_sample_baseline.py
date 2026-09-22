"""Run a metadata-only static acceptance baseline against supplied samples.

The script never opens a sample as an executable and never invokes a shell,
macro host, interpreter, or dynamic analysis tool.  Encrypted sample archives
may be released only through the normal input Gate using ``--archive-password``;
the password is never written to the output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx


TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED", "WAITING_GATE", "PAUSED"}
FORBIDDEN_EVENT_PARTS = ("execute_sample", "dynamic", "sandbox", "macro_run", "shell")


def _git_output(*args: str) -> str | None:
    """Return a trusted repository value, or ``None`` outside a Git checkout."""
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


class BaselineTimeoutError(TimeoutError):
    """Timeout retaining the task identifier for post-run inspection."""

    def __init__(self, task_id: str) -> None:
        super().__init__(task_id)
        self.task_id = task_id


class ArchivePasswordRequired(RuntimeError):
    """A normal input-Gate outcome that retains the submitted task identifier."""

    def __init__(self, sample_name: str, task_id: str) -> None:
        super().__init__(f"{sample_name} requires --archive-password")
        self.task_id = task_id


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


def _poll(client: httpx.Client, task_id: str, timeout: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while True:
        response = client.get(f"/api/v1/tasks/{task_id}/status")
        response.raise_for_status()
        payload = response.json()
        if payload["lifecycle"] in TERMINAL:
            # Keep the baseline bounded even for large Ghidra runs.  The
            # full task projection contains every Evidence row and can be
            # hundreds of megabytes; status already carries all counters
            # needed by this acceptance script.  Callers needing Gate
            # context explicitly fetch the detail projection below.
            return payload
        if time.monotonic() >= deadline:
            raise BaselineTimeoutError(task_id)
        time.sleep(1.0)


def _cancel_task(client: httpx.Client, task_id: str) -> bool:
    """Cancel a task after the client-side budget expires.

    The product keeps task execution asynchronous, so abandoning the polling
    loop without cancelling would leave an unobserved backend workflow alive.
    Cancellation is best-effort: the timeout remains the primary result and a
    failed cancellation is recorded by the caller for reliability review.
    """
    try:
        response = client.post(f"/api/v1/tasks/{task_id}/cancel")
        response.raise_for_status()
    except (httpx.HTTPError, OSError):
        return False
    return True


def _cancel_and_refresh(
    client: httpx.Client,
    task_id: str,
    result: dict[str, object],
) -> dict[str, object]:
    """Cancel a timed-out task and record its post-cancel lifecycle."""
    requested = _cancel_task(client, task_id)
    result["cancel_requested"] = requested
    if not requested:
        return result
    try:
        response = client.get(f"/api/v1/tasks/{task_id}/status")
        response.raise_for_status()
        payload = response.json()
        result.update(_task_summary(payload))
    except (httpx.HTTPError, ValueError, OSError) as exc:
        result["cancel_refresh_error"] = str(exc)
    return result


def _should_cancel_after_failure(error: Exception) -> bool:
    """Only timeouts abandon an already-running product task.

    An input Gate is a deliberate pause that must remain available for the
    operator to approve later.  Cancelling it would discard the exact static
    intake state that the acceptance artifact is meant to preserve.
    """
    return isinstance(error, BaselineTimeoutError)


def _task_summary(task: dict[str, object]) -> dict[str, object]:
    """Keep baseline output small while retaining auditable task metadata."""
    claims = task.get("claims") if isinstance(task.get("claims"), list) else []
    artifacts = task.get("artifacts") if isinstance(task.get("artifacts"), list) else []
    evidence = task.get("evidence") if isinstance(task.get("evidence"), list) else []

    def count(field: str, fallback: list[object]) -> int:
        value = task.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        return len(fallback)

    return {
        "task_id": task.get("id"),
        "lifecycle": task.get("lifecycle"),
        "outcome": task.get("outcome"),
        "analysis_class": task.get("analysis_class"),
        "artifact_count": count("artifact_count", artifacts),
        "evidence_count": count("evidence_count", evidence),
        "claim_count": count("claim_count", claims),
        "claim_modules": sorted({claim.get("module") for claim in claims if claim.get("module")}),
        "coverage": task.get("coverage"),
    }


def _release_gate(client: httpx.Client, task: dict[str, object], password: str) -> None:
    gates = [item for item in task.get("gates", []) if item.get("status") == "PENDING"]
    for gate in gates:
        if gate.get("type") != "INPUT_REVIEW":
            continue
        response = client.post(
            f"/api/v1/gates/{gate['id']}/decision",
            json={
                "decision": "APPROVE",
                "archive_password": password,
                "note": "controlled static baseline; no sample execution",
            },
        )
        response.raise_for_status()


def analyze_one(client: httpx.Client, sample: Path, password: str, timeout: float) -> dict[str, object]:
    case = client.post("/api/v1/cases", json={"title": f"real-static-baseline:{sample.name}"})
    case.raise_for_status()
    with sample.open("rb") as handle:
        submitted = client.post(
            f"/api/v1/cases/{case.json()['id']}/tasks",
            files={"sample": (sample.name, handle, "application/octet-stream")},
            data={"selected_modules": "[]"},
        )
    submitted.raise_for_status()
    task_id = submitted.json()["task_id"]
    task = _poll(client, task_id, timeout)
    if task["lifecycle"] == "WAITING_GATE":
        detail = client.get(f"/api/v1/tasks/{task_id}")
        detail.raise_for_status()
        task = detail.json()
        if not password:
            raise ArchivePasswordRequired(sample.name, task_id)
        _release_gate(client, task, password)
        task = _poll(client, task_id, timeout)

    events_response = client.get(f"/api/v1/tasks/{task_id}/audit")
    events_response.raise_for_status()
    events = events_response.json()
    forbidden = [
        event["event_type"]
        for event in events
        if any(part in event["event_type"].lower() for part in FORBIDDEN_EVENT_PARTS)
    ]
    integrity = client.get(f"/api/v1/tasks/{task_id}/audit/integrity")
    integrity.raise_for_status()
    if forbidden:
        raise AssertionError(f"forbidden execution-like events for {sample.name}: {forbidden}")
    if not integrity.json()["valid"]:
        raise AssertionError(f"audit integrity failed for {sample.name}")
    if task["lifecycle"] != "SUCCEEDED":
        raise AssertionError(
            f"analysis did not succeed for {sample.name}: "
            f"lifecycle={task.get('lifecycle')} class={task.get('analysis_class')}"
        )
    if not task.get("claim_count") and task["lifecycle"] == "SUCCEEDED":
        raise AssertionError(f"successful sample produced no Claims: {sample.name}")
    return {
        "status": "PASS",
        "sample_name": sample.name,
        "size": sample.stat().st_size,
        "task_id": task_id,
        "lifecycle": task["lifecycle"],
        "outcome": task["outcome"],
        "analysis_class": task.get("analysis_class"),
        "artifact_count": task.get("artifact_count", 0),
        "evidence_count": task.get("evidence_count", 0),
        "claim_count": task.get("claim_count", 0),
        "claim_modules": [],
        # The full analysis-trace projection contains every Evidence delivery
        # row and can be hundreds of megabytes for a real Ghidra run.  The
        # already-fetched audit stream is the authoritative bounded process
        # trace for this baseline and avoids a second unbounded JSON decode.
        "trace_steps": len(events),
        "audit_integrity": integrity.json()["valid"],
        "sample_execution": False,
    }


def _failed_result(
    client: httpx.Client,
    sample: Path,
    error: Exception,
    task_id: str | None = None,
) -> dict[str, object]:
    """Record a failed/unfinished sample without discarding the batch."""
    result: dict[str, object] = {
        "status": "TIMEOUT" if isinstance(error, TimeoutError) else "ERROR",
        "sample_name": sample.name,
        "size": sample.stat().st_size,
        "task_id": task_id,
        "error_type": type(error).__name__,
        "error": str(error),
        "sample_execution": False,
    }
    if task_id:
        try:
            response = client.get(f"/api/v1/tasks/{task_id}/status")
            response.raise_for_status()
            result.update(_task_summary(response.json()))
        except httpx.HTTPError as exc:
            result["summary_error"] = str(exc)
    return result


def _write_payload(path: Path | None, results: list[dict[str, object]]) -> dict[str, object]:
    payload = {
        "schema_version": "real-sample-baseline-v2",
        "status": "PASS" if all(item.get("status") == "PASS" for item in results) else "INCOMPLETE",
        "sample_count": len(results),
        "results": results,
        "generated_at": datetime.now(UTC).isoformat(),
        # Bind every incremental and final baseline snapshot to the source
        # revision that produced it.  Missing Git identity remains explicit;
        # release gates must fail closed instead of guessing a revision.
        "git_commit": _git_output("rev-parse", "HEAD"),
        "git_tree": _git_output("rev-parse", "HEAD^{tree}"),
    }
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--archive-password", default="")
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=900.0,
        help="HTTP read/write timeout for long-running Gate decisions",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="record a sample failure/timeout and continue with the remaining samples",
    )
    args = parser.parse_args()
    samples = [path.resolve() for path in args.samples]
    missing = [str(path) for path in samples if not path.is_file()]
    if missing:
        raise SystemExit(f"sample path does not exist: {missing}")

    with httpx.Client(
        base_url=args.base_url.rstrip("/"),
        timeout=httpx.Timeout(args.request_timeout, connect=30.0),
    ) as client:
        _wait_for_health(client)
        results: list[dict[str, object]] = []
        for sample in samples:
            try:
                result = analyze_one(client, sample, args.archive_password, args.timeout)
            except Exception as exc:
                if not args.continue_on_error:
                    raise
                task_id = getattr(exc, "task_id", None)
                result = _failed_result(client, sample, exc, task_id)
                if task_id and _should_cancel_after_failure(exc):
                    result = _cancel_and_refresh(client, task_id, result)
            results.append(result)
            # A long-running Ghidra task must not erase completed sample results.
            _write_payload(args.output, results)
    payload = _write_payload(args.output, results)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2)
    print(encoded)


if __name__ == "__main__":
    main()
