#!/usr/bin/env python3
"""Stop hook: keep working the first-usable static analysis plan.

Supersedes the Lite/Complete C10 completion definition (ADR-0034). The old
``complete_c10_passed`` flag is **not** a stop condition any more: it only ever
meant "HOW or an explicit UNKNOWN was written", which is exactly the definition
ADR-0034 voids.

The single stop condition is ``first_usable_g5_passed`` in
``.scratch/first-usable-status.json`` — the 3080 user path in the current plan.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

STATUS = Path(".scratch/first-usable-status.json")
PLAN = "docs/first-usable-static-analysis-plan-20260916.md"
PROMPT = f"继续 `{PLAN}` 的当前 gate，禁止用 HOW 或 UNKNOWN 宣称完成。"


def main() -> int:
    payload = json.loads(sys.stdin.read() or "{}")
    del payload
    if STATUS.is_file():
        try:
            status = json.loads(STATUS.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            status = {}
        # Only the 3080 user path G5 may stop the loop.
        if status.get("first_usable_g5_passed") is True:
            json.dump({}, sys.stdout)
            return 0
    json.dump({"followup_message": PROMPT}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
