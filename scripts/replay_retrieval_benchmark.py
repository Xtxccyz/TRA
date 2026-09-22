"""Measure existing static Evidence retrieval on a disposable SQLite backup.

This is a recorded-evidence replay, not a new sample or model certification.
The source database is opened read-only; only its derived selector projection
is backfilled in the disposable copy. No sample bytes or Gold are loaded.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import statistics
import subprocess
import tempfile
import time

from sqlalchemy import func, select

from threat_report_agent.database import Database
from threat_report_agent.evidence_index import INDEXED_EVIDENCE_KINDS
from threat_report_agent.evidence_recovery import BoundedEvidenceRepository, RetrievalRequest
from threat_report_agent.models import AnalysisTask, Artifact, Evidence, EvidenceSearchKey


ROOT = Path(__file__).resolve().parents[1]
DEEP_KINDS = ("pcode_slice", "value_flow", "resolved_api", "mechanism_decode_window", "abstract_execution_trace")


def measure(database: Database, task_id: str) -> dict[str, object]:
    observations = []
    latencies = []
    expected_all: set[str] = set()
    retrieved_all: set[str] = set()
    with database.session_factory() as session:
        deep_rows = list(session.scalars(select(Evidence).where(Evidence.task_id == task_id, Evidence.kind.in_(DEEP_KINDS))))
        requests: dict[tuple[str, str], set[str]] = {}
        for row in deep_rows:
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            value = row.value if isinstance(row.value, dict) else {}
            source = value.get("source", {})
            source = source if isinstance(source, dict) else {}
            entry = anchor.get("function_entry") or anchor.get("entry") or value.get("function_entry") or value.get("entry") or source.get("entry")
            if not entry:
                continue
            requests.setdefault((row.artifact_id, str(entry)), set()).add(row.id)
        repository = BoundedEvidenceRepository()
        for (artifact_id, entry), expected in sorted(requests.items()):
            request = RetrievalRequest(thread_id="replay-only", artifact_id=artifact_id,
                                       hypothesis_type="function-followup", target_anchors=(entry,),
                                       required_evidence_kinds=(), candidate_limit=256)
            started = time.perf_counter()
            batch = repository.retrieve(session, task_id=task_id, request=request)
            latencies.append((time.perf_counter() - started) * 1000)
            received = {row.id for row in batch.rows}
            expected_all.update(expected)
            retrieved_all.update(expected & received)
            observations.append({"artifact_id": artifact_id, "entry": entry,
                                 "expected_deep_ids": sorted(expected), "retrieved_deep_ids": sorted(expected & received),
                                 "candidate_count": batch.candidate_count, "query_count": batch.query_count})
    return {
        "queries": len(observations), "deep_rows": len(deep_rows), "anchored_deep_rows": len(expected_all),
        "retrieved_deep_rows": len(retrieved_all),
        "retrieval_recall": len(retrieved_all) / len(expected_all) if expected_all else None,
        "deep_kind_counts": dict(Counter(row.kind for row in deep_rows)),
        "median_query_ms": round(statistics.median(latencies), 3) if latencies else None,
        "max_query_ms": round(max(latencies), 3) if latencies else None,
        "max_sql_queries": max((row["query_count"] for row in observations), default=0),
        "observations": observations,
    }


def run(source: Path, task_id: str | None) -> dict[str, object]:
    source = source.resolve(strict=True)
    with source.open("rb") as handle:
        source_digest = hashlib.file_digest(handle, "sha256").hexdigest()
    scratch = ROOT / ".scratch"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="retrieval-replay-", dir=scratch) as temp:
        copy = Path(temp) / "evidence.db"
        with closing(sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)) as origin:
            with closing(sqlite3.connect(copy)) as destination:
                origin.backup(destination)
        database = Database(f"sqlite:///{copy.as_posix()}")
        try:
            with database.session_factory() as session:
                task = session.get(AnalysisTask, task_id) if task_id else session.scalar(
                    select(AnalysisTask).where(AnalysisTask.lifecycle == "SUCCEEDED").order_by(AnalysisTask.created_at.desc()).limit(1))
                if task is None:
                    raise ValueError("No matching completed task in source snapshot")
                task_id = task.id
                artifacts = [{"artifact_id": row.id, "sample_sha256": row.content_sha256} for row in session.scalars(select(Artifact).where(Artifact.task_id == task_id))]
                evidence_count = session.scalar(select(func.count()).select_from(Evidence).where(Evidence.task_id == task_id))
            before = measure(database, task_id)
            previous_missing = None
            passes = 0
            for _ in range(128):
                with database.session_factory() as session:
                    missing = session.scalar(select(func.count()).select_from(Evidence).where(
                        Evidence.kind.in_(tuple(sorted(INDEXED_EVIDENCE_KINDS))),
                        ~select(EvidenceSearchKey.id).where(EvidenceSearchKey.evidence_id == Evidence.id).exists()))
                if not missing:
                    break
                if missing == previous_missing:
                    raise RuntimeError("Selector backfill made no progress")
                previous_missing = missing
                database.create_schema()
                passes += 1
            else:
                raise RuntimeError("Replay migration budget exceeded")
            after = measure(database, task_id)
        finally:
            database.engine.dispose()
    files = [ROOT / "src/threat_report_agent" / name for name in ("evidence_index.py", "evidence_recovery.py", "database.py")]
    return {
        "schema_version": "retrieval-replay-v1", "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if after["retrieval_recall"] == 1.0 else "PARTIAL",
        "scope": "recorded-evidence-retrieval-only", "evidence_level": "L1", "evaluator_only": True,
        "fresh_sample_run": False, "model_contribution_proven": False, "release_gate": "BLOCKED",
        "source_database": str(source), "source_database_sha256": source_digest,
        "source_database_modified": False, "task_id": task_id, "artifacts": artifacts,
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_files_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
        "evidence_count": evidence_count, "migration_pages": passes, "before": before, "after": after,
        "execution_boundary": {"sample_execution": False, "sample_network_access": False, "dynamic_emulators_invoked": False},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--task-id")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = run(args.database, args.task_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in payload.items() if key not in {"before", "after"}}, indent=2))
    for label in ("before", "after"):
        print(label, json.dumps({key: value for key, value in payload[label].items() if key != "observations"}))


if __name__ == "__main__":
    main()
