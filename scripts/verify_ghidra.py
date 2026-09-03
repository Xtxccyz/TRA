from __future__ import annotations

import json
import argparse
import os
from pathlib import Path
import sys

WORKSPACE = Path(__file__).resolve().parents[1]
if str(WORKSPACE) not in sys.path:
    sys.path.insert(0, str(WORKSPACE))

from threat_report_agent.ghidra_adapter import GhidraHeadlessRunner  # noqa: E402


GHIDRA_HOME = WORKSPACE / ".tools" / "ghidra-12.1.2" / "ghidra_12.1.2_PUBLIC"
JAVA_HOME = Path("C:/Program Files/Eclipse Adoptium/jdk-21.0.12.8-hotspot")


def main() -> None:
    parser = argparse.ArgumentParser(description="Static-only Ghidra Headless acceptance probe")
    parser.add_argument(
        "sample",
        nargs="?",
        default=os.getenv("GHIDRA_ACCEPTANCE_SAMPLE"),
        help="PE/DLL path; no sample code is executed",
    )
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    if not args.sample:
        raise SystemExit(
            "An explicit PE/DLL path is required; refusing to use an arbitrary system binary."
        )
    sample = Path(args.sample)
    if not sample.is_file():
        raise SystemExit(f"acceptance sample does not exist: {sample}")
    runner = GhidraHeadlessRunner(GHIDRA_HOME, JAVA_HOME)
    result = runner.analyze(sample.read_bytes(), sample.name, timeout_seconds=args.timeout)
    output_file = WORKSPACE / ".data" / "ghidra-acceptance-latest.json"
    output_file.write_text(
        json.dumps(
            {
                "sample": str(sample),
                "status": result.status,
                "error": result.error,
                "output": result.output,
                "stderr_tail": result.stderr[-4000:],
            },
            ensure_ascii=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    functions = result.output.get("functions", []) if isinstance(result.output, dict) else []
    print(
        json.dumps(
            {
                "status": result.status,
                "error": result.error,
                "functions": len(functions),
                "output": str(output_file),
            }
        )
    )
    if result.status != "SUCCEEDED":
        raise SystemExit(2)
    if not functions:
        raise SystemExit("Ghidra completed without function evidence; D3 acceptance not met")


if __name__ == "__main__":
    main()
