"""Offline entry point for the seven-mechanism Resume differential.

This module is deliberately under ``benchmarks``. It reads a completed task
view and evaluator-only Gold rubric, then writes a scorecard. It has no import
path into the runtime service and never mutates an Agent task.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from benchmarks.semantic_differential import build_semantic_differential


DEFAULT_GOLD = Path(__file__).with_name("gold") / "resume-mechanisms-v2.json"


def evaluate_task_view(
    task_view: Mapping[str, Any],
    *,
    gold_path: str | Path = DEFAULT_GOLD,
) -> dict[str, object]:
    """Evaluate a serialized static task view without exposing Gold at runtime."""
    path = Path(gold_path)
    gold = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(gold, dict) or gold.get("evaluator_only") is not True:
        raise ValueError("Resume Gold rubric must be explicitly evaluator-only")
    return build_semantic_differential(task_view, gold)


def evaluate_task_view_file(
    task_view_path: str | Path,
    *,
    gold_path: str | Path = DEFAULT_GOLD,
    output_path: str | Path | None = None,
) -> dict[str, object]:
    """Read a task view JSON and optionally persist the resulting scorecard."""
    task_view = json.loads(Path(task_view_path).read_text(encoding="utf-8"))
    if not isinstance(task_view, Mapping):
        raise ValueError("task view must be a JSON object")
    scorecard = evaluate_task_view(task_view, gold_path=gold_path)
    if output_path is not None:
        Path(output_path).write_text(
            json.dumps(scorecard, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return scorecard

