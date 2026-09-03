"""Run the offline portion of the Round 11 product release gate.

This command reads evaluator-owned result and Gold JSON files.  It never sends
Gold answers to the runtime and it never upgrades a missing external check to
PASS.  Use ``--external-blocker`` for Docker/browser/soak checks not available
on the current host.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# ``python scripts/round11_release_gate.py`` sets ``sys.path[0]`` to the
# scripts directory.  Add the repository root explicitly so the evaluator
# package is importable both from a checkout and from an editable install.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from benchmarks.generalization import build_failure_taxonomy  # noqa: E402
from threat_report_agent.product_certification import evaluate_gold, release_gate  # noqa: E402


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("release-artifacts/round11-release-gate.json"))
    parser.add_argument("--external-blocker", action="append", default=[])
    args = parser.parse_args()
    results_payload = _load(args.results)
    gold_payload = _load(args.gold)
    results = results_payload.get("results", results_payload) if isinstance(results_payload, dict) else results_payload
    gold = gold_payload.get("samples", gold_payload) if isinstance(gold_payload, dict) else gold_payload
    if not isinstance(results, list) or not isinstance(gold, list):
        raise SystemExit("results and gold must be JSON arrays or objects containing results/samples")
    metrics = evaluate_gold(results, gold)
    gate = release_gate(
        metrics,
        corpus_errors=[] if len(gold) >= 10 else ["certification Gold corpus is incomplete"],
        external_blockers=args.external_blocker,
    )
    payload = {
        **gate,
        "version": "round11-release-gate-v1",
        "failure_taxonomy": build_failure_taxonomy(results),
        "gold_source": str(args.gold.resolve()),
        "results_source": str(args.results.resolve()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if payload["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
