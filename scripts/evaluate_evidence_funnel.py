"""Evaluate a serialized Task View against evaluator-only Gold evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Keep this evaluator runnable from any working directory, matching the
# semantic differential evaluator.  The evaluator-only ``benchmarks`` package
# lives at the repository root and is intentionally not a runtime dependency.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.evidence_funnel import build_evidence_funnel  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_view", type=Path)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    task_view = json.loads(args.task_view.read_text(encoding="utf-8"))
    gold = json.loads(args.gold.read_text(encoding="utf-8"))
    scorecard = build_evidence_funnel(task_view, gold)
    encoded = json.dumps(scorecard, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
