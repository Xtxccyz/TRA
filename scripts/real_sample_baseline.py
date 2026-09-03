"""Run a metadata-only static acceptance baseline against supplied samples.

The script never opens a sample as an executable and never invokes a shell,
macro host, interpreter, or dynamic analysis tool.  Encrypted sample archives
may be released only through the normal input Gate using ``--archive-password``;
the password is never written to the output.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx


TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED", "WAITING_GATE", "PAUSED"}
FORBIDDEN_EVENT_PARTS = ("execute_sample", "dynamic", "sandbox", "macro_run", "shell")


class BaselineTimeoutError(TimeoutError):
    """Timeout retaining the task identifier for post-run inspection."""

    def __init__(self, task_id: str) -> None:
        super().__init__(task_id)
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
            # Fetch the full projection once, after finalization only.
            detail = client.get(f"/api/v1/tasks/{task_id}")
            detail.raise_for_status()
            return detail.json()
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


def _task_summary(task: dict[str, object]) -> dict[str, object]:
    """Keep baseline output small while retaining auditable task metadata."""
    claims = task.get("claims") or []
    artifacts = task.get("artifacts") or []
    evidence = task.get("evidence") or []
    return {
        "task_id": task.get("id"),
        "lifecycle": task.get("lifecycle"),
        "outcome": task.get("outcome"),
        "analysis_class": task.get("analysis_class"),
        "artifact_count": len(artifacts),
        "evidence_count": len(evidence),
        "claim_count": len(claims),
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
        if not password:
            raise RuntimeError(f"{sample.name} requires --archive-password")
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
    if not task["claims"] and task["lifecycle"] == "SUCCEEDED":
        raise AssertionError(f"successful sample produced no Claims: {sample.name}")
    return {
        "status": "PASS",
        "sample_name": sample.name,
        "size": sample.stat().st_size,
        "task_id": task_id,
        "lifecycle": task["lifecycle"],
        "outcome": task["outcome"],
        "analysis_class": task.get("analysis_class"),
        "artifact_count": len(task["artifacts"]),
        "evidence_count": len(task["evidence"]),
        "claim_modules": sorted({claim["module"] for claim in task["claims"]}),
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


def _write_payload(path: Path | None, results: list[dict[str, object]]) -> None:
    if path is None:
        return
    payload = {
        "status": "PASS" if all(item.get("status") == "PASS" for item in results) else "INCOMPLETE",
        "sample_count": len(results),
        "results": results,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
                if task_id:
                    result["cancel_requested"] = _cancel_task(client, task_id)
            results.append(result)
            # A long-running Ghidra task must not erase completed sample results.
            _write_payload(args.output, results)
    payload = {
        "status": "PASS" if all(item.get("status") == "PASS" for item in results) else "INCOMPLETE",
        "sample_count": len(results),
        "results": results,
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
