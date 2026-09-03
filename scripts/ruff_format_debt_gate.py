"""Record and enforce the repository's Ruff format-debt baseline.

The project deliberately keeps existing formatting debt out of semantic
changes.  This gate freezes the current debt set and fails only when a later
run introduces a new file or increases the total count.  It never formats or
rewrites source files.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGETS = ("src", "tests", "scripts", "benchmarks")
DEFAULT_BASELINE = ROOT / "release-artifacts" / "final-round" / "ruff-format-debt-baseline.json"


def _git(*args: str) -> str | None:
    """Return a repository identity value, or None when Git is unavailable."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def parse_ruff_format_output(output: str) -> list[str]:
    """Extract normalized repository-relative paths from Ruff output."""
    paths: set[str] = set()
    for line in output.splitlines():
        marker = "Would reformat:"
        if marker not in line:
            continue
        raw = line.split(marker, 1)[1].strip().replace("\\", "/")
        if not raw:
            continue
        path = Path(raw)
        if path.is_absolute():
            try:
                raw = path.resolve().relative_to(ROOT).as_posix()
            except ValueError:
                raw = path.resolve().as_posix()
        else:
            raw = raw.removeprefix("./")
        paths.add(raw)
    return sorted(paths)


def evaluate_format_debt(current: Iterable[str], baseline: Iterable[str]) -> dict[str, object]:
    """Compare a current debt set to a frozen baseline without mutation."""
    current_set = set(current)
    baseline_set = set(baseline)
    new_paths = sorted(current_set - baseline_set)
    removed_paths = sorted(baseline_set - current_set)
    count_increased = len(current_set) > len(baseline_set)
    passed = not new_paths and not count_increased
    return {
        "status": "PASS" if passed else "FAIL",
        "baseline_count": len(baseline_set),
        "current_count": len(current_set),
        "new_paths": new_paths,
        "removed_paths": removed_paths,
        "count_increased": count_increased,
        "reason": "no new format debt" if passed else "new format debt exceeds frozen baseline",
    }


def collect_format_debt(targets: Iterable[str]) -> tuple[list[str], str]:
    """Run Ruff's read-only check and return debt paths plus raw output."""
    try:
        result = subprocess.run(
            ["ruff", "format", "--check", *targets],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"ruff format check unavailable: {exc}") from exc
    output = (result.stdout + result.stderr).strip()
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"ruff format check failed with exit code {result.returncode}: {output[-1000:]}"
        )
    return parse_ruff_format_output(output), output


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target", action="append", dest="targets")
    args = parser.parse_args()
    targets = tuple(args.targets or DEFAULT_TARGETS)
    current_paths, raw_output = collect_format_debt(targets)
    git_commit = _git("rev-parse", "HEAD")
    git_tree = _git("rev-parse", "HEAD^{tree}")
    if args.write_baseline:
        payload = {
            "schema_version": "ruff-format-debt-baseline-v1",
            "status": "RECORDED",
            "generated_at": datetime.now(UTC).isoformat(),
            "git_commit": git_commit,
            "git_tree": git_tree,
            "targets": list(targets),
            "planned_count": 63,
            "observed_count": len(current_paths),
            "paths": current_paths,
            "note": "The planned 63-file baseline was stale; this artifact freezes the current observed tree.",
        }
        _write(args.baseline, payload)
        if args.output:
            _write(args.output, payload)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    if not args.baseline.is_file():
        raise SystemExit(f"format debt baseline does not exist: {args.baseline}")
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    baseline_paths = baseline.get("paths", [])
    if not isinstance(baseline_paths, list) or not all(
        isinstance(item, str) for item in baseline_paths
    ):
        raise SystemExit("format debt baseline has invalid paths")
    result = evaluate_format_debt(current_paths, baseline_paths)
    result["baseline"] = str(args.baseline.resolve())
    result["targets"] = list(targets)
    result["checked_at"] = datetime.now(UTC).isoformat()
    result["git_commit"] = git_commit
    result["git_tree"] = git_tree
    result["raw_output_tail"] = raw_output[-2000:]
    if args.output:
        _write(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
