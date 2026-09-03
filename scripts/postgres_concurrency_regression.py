"""Run the PostgreSQL task-snapshot lock regression against Compose.

The script deliberately performs only two short, task-scoped control-plane
transactions. It never touches sample bytes or drops database objects.
"""

from __future__ import annotations

import json
import os
import threading
import time

from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, CaseRecord


def main() -> int:
    url = os.environ.get("THREAT_POSTGRES_TEST_URL") or os.environ.get("DATABASE_URL")
    if not url or not url.startswith("postgres"):
        raise SystemExit("THREAT_POSTGRES_TEST_URL or DATABASE_URL must be a PostgreSQL URL")
    database = Database(url)
    database.create_schema()
    with database.session_factory.begin() as session:
        case = CaseRecord(title="postgres task lock regression")
        session.add(case)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        task_id = task.id

    barrier = threading.Barrier(2)
    errors: list[str] = []

    def writer(value: str) -> None:
        try:
            barrier.wait(timeout=5)
            with database.session_factory.begin() as session:
                row = session.get(AnalysisTask, task_id, with_for_update=True)
                if row is None:
                    raise RuntimeError("task disappeared")
                snapshot = dict(row.strategy_snapshot or {})
                snapshot["writer"] = value
                row.strategy_snapshot = snapshot
                time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - diagnostic script
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=writer, args=(str(index),)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    result = {
        "task_id": task_id,
        "threads_finished": all(not thread.is_alive() for thread in threads),
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["threads_finished"] and not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
