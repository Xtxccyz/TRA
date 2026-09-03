"""Evaluator-only ComHost scorecard.

The runtime never imports this module or the private ComHost Gold rubric.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from benchmarks.semantic_differential import build_semantic_differential


DEFAULT_GOLD = Path(__file__).with_name("gold") / "comhost-critical-v1.json"


def evaluate_task_view(task_view: Mapping[str, Any], gold_path: Path | None = None) -> dict[str, object]:
    path = gold_path or DEFAULT_GOLD
    gold = json.loads(path.read_text("utf-8"))
    result = build_semantic_differential(task_view, gold)
    result["sample"] = "ComHost"
    result["critical_mechanism_ids"] = list(gold.get("critical_mechanisms", []))
    return result
