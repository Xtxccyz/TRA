"""Run an evaluator-only semantic differential from JSON files.

Usage: python scripts/evaluate_semantic_differential.py task-view.json gold.json
The Gold file is intentionally an explicit evaluator input, never a runtime
Agent configuration file.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# This evaluator is intentionally a repository-level tool, not a packaged
# runtime dependency. Make its sibling evaluator-only package importable when
# the script is invoked directly from any working directory.
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

def main(argv: list[str]) -> int:
    from benchmarks.semantic_differential import build_semantic_differential

    if len(argv) != 3:
        print("usage: evaluate_semantic_differential.py TASK_VIEW_JSON GOLD_JSON")
        return 2
    task_view = json.loads(Path(argv[1]).read_text("utf-8"))
    gold = json.loads(Path(argv[2]).read_text("utf-8"))
    if not isinstance(gold, dict) or gold.get("evaluator_only") is not True:
        print("GOLD_JSON must declare evaluator_only=true", file=sys.stderr)
        return 2
    print(json.dumps(build_semantic_differential(task_view, gold), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
