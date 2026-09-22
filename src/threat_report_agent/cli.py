from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict, replace
from datetime import date
from pathlib import Path

from threat_report_agent.config import Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService
from threat_report_agent.control_activities import run_static_worker


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threat-report-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--title", default="")
    analyze.add_argument("--background", default="")
    analyze.add_argument("--database-url")
    analyze.add_argument("--content-store")
    analyze.add_argument("--task-view-output", type=Path)
    worker = subparsers.add_parser("worker")
    worker.add_argument("--task-queue")
    worker.add_argument("--role", choices=("control", "tool"), default="tool")
    sealer = subparsers.add_parser("seal-audit-day")
    sealer.add_argument("utc_day", type=date.fromisoformat)
    sealer.add_argument("--actor", default="audit-sealer")
    sealer.add_argument("--database-url")
    sealer.add_argument("--content-store")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = Settings.from_environment()
    if args.command == "worker":
        if args.task_queue:
            settings = replace(settings, tool_task_queue=args.task_queue)
        asyncio.run(run_static_worker(settings, role=args.role))
        return
    if args.database_url:
        settings = replace(settings, database_url=args.database_url)
    if args.content_store:
        settings = replace(settings, content_store_path=args.content_store)
    database = Database(settings.database_url)
    database.create_schema()
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    service.reload_model_configuration()
    if args.command == "seal-audit-day":
        created = service.run_daily_audit_sealer(utc_day=args.utc_day, actor=args.actor)
        print(json.dumps({"utc_day": args.utc_day.isoformat(), "created": created}))
        return
    path = args.path.resolve()
    if not path.exists():
        raise SystemExit(f"Sample path does not exist: {path}")
    case = service.create_case(args.title or path.name, actor="cli-analyst")
    if path.is_dir():
        result = service.analyze_directory(
            case_id=case.id,
            directory=path,
            background_context=args.background,
            actor="cli-analyst",
        )
    else:
        result = service.analyze_submission(
            case_id=case.id,
            filename=path.name,
            content=path.read_bytes(),
            background_context=args.background,
            actor="cli-analyst",
        )
    if args.task_view_output:
        task_view = service.task_view(result.task_id)
        args.task_view_output.parent.mkdir(parents=True, exist_ok=True)
        args.task_view_output.write_text(
            json.dumps(task_view, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
