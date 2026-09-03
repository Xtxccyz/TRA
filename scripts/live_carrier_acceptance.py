"""Verify a carrier sample creates child Artifacts and supported relations in PostgreSQL."""

from __future__ import annotations

import argparse
import io
import json
import time
import zipfile

import httpx


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


def carrier_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'></Types>",
        )
        archive.writestr(
            "word/document.xml",
            "<document xmlns='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>"
            "<body><p>static carrier acceptance</p></body></document>",
        )
        archive.writestr("word/embeddings/payload.bin", b"CreateProcessA VirtualAlloc")
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    # Carrier analysis can include one planner turn per extracted child.
    # Leave enough time for a configured remote model while allowing callers
    # to reduce the budget explicitly in a local deterministic run.
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args()

    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0) as client:
        _wait_for_health(client)
        case = client.post("/api/v1/cases", json={"title": "live-carrier-acceptance"})
        case.raise_for_status()
        response = client.post(
            f"/api/v1/cases/{case.json()['id']}/tasks",
            files={
                "sample": (
                    "carrier.docx",
                    carrier_bytes(),
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
            data={
                "background_context": "synthetic carrier only",
                "background_source": "live-carrier-acceptance",
                "background_confidence": "HIGH",
                "selected_modules": "[]",
            },
        )
        response.raise_for_status()
        task_id = response.json()["task_id"]
        deadline = time.monotonic() + args.timeout
        while True:
            task_response = client.get(f"/api/v1/tasks/{task_id}")
            task_response.raise_for_status()
            task = task_response.json()
            if task["lifecycle"] in {"SUCCEEDED", "FAILED", "CANCELLED", "WAITING_GATE"}:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(task_id)
            time.sleep(2)
        assert task["lifecycle"] == "SUCCEEDED", task
        assert task["analysis_class"] in {
            "FULL_STATIC_ANALYSIS",
            "BOUNDED_STATIC_ANALYSIS",
        }, task
        assert len(task["artifacts"]) >= 2, task
        relation_types = {item["relation_type"] for item in task["relations"]}
        assert "CONTAINS" in relation_types, task
        assert "EXTRACTED_FROM" in relation_types, task
    print(
        json.dumps({"status": "PASS", "task_id": task_id, "relation_types": sorted(relation_types)})
    )


if __name__ == "__main__":
    main()
