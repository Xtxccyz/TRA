"""S0 instrument: freeze the PUBLISHED layer so a structural move cannot change it silently.

Why this exists (two-axis review of `docs/code-structure-optimization-plan-20260922.md`):

* The plan's §0.2 "behaviour freeze" is a PROHIBITION with no instrument, and the plan contains no golden
  markdown snapshot anywhere. Under it the suite can stay green while the published body changes.
* The repo's only end-to-end behaviour gate, `.scratch/check-report-acceptance.py`, grades 24 pinned criteria -
  but its `--render` mode renders with **`render_official_markdown`**, the INNER layer. The published body comes
  from **`compose_official_markdown`**, which returns the analyst DRAFT when it clears the compose gate
  (`publish_composed_markdown`), i.e. bytes the inner function never produced. So the existing grader shares the
  blind spot it was supposed to catch.
* Measured consequence: revision `414cb724`'s published body contains zero occurrences of `限制`/`limitation`,
  which is what a published draft looks like - while the deterministic chapters do render them.

What this freezes, per frozen task:

  * `stored_markdown_sha256` - the bytes the API serves today for the official revision (the published layer);
  * `render_verdict` / `render_criteria` - the 24-criteria verdict when the stored document is re-composed, so a
    migration that changes the deterministic layer is caught even though no new revision exists;
  * `render_sha256` where obtainable.

Usage:

    python .scratch/check-published-markdown-frozen.py --freeze
    python .scratch/check-published-markdown-frozen.py --check      # exit 1 on drift

The corpus file lives at `docs/frozen/published-markdown.json` ON PURPOSE: `.scratch/` is gitignored, so a
frozen corpus kept there would vanish in a clone and the gate would compare against nothing - the same
silent-reset failure the review found in the plan's own status file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

def _repo_root() -> Path:
    """Find the repository root by walking up to `.git`, NOT by counting parents.

    MEASURED: this file was first written in `.scratch/` and then copied to `docs/frozen/`, one level deeper.
    A `parents[1]` root silently became `docs/`, so the checker looked for `docs/docs/frozen/...`, reported
    NO CORPUS and exited 2. That failure was loud only because a missing corpus is coded as "not a pass" - if
    the missing case had defaulted to success, a broken gate would have shipped.
    """
    here = Path(__file__).resolve()
    for candidate in [here.parent, *here.parents]:
        if (candidate / ".git").exists():
            return candidate
    return here.parents[2]


ROOT = _repo_root()
CORPUS = ROOT / "docs" / "frozen" / "published-markdown.json"
GRADER = ROOT / ".scratch" / "check-report-acceptance.py"
PSQL = ["docker", "exec", "threat-report-agent-postgres-1", "psql", "-U", "threat_agent", "-d", "threat_agent", "-t", "-A"]

#: Frozen by MEASURED identity, not by recall: task id + the official revision, both read back from the DB
#: before being written into the corpus.
FROZEN_TASKS: dict[str, str] = {
    # Resume sample (content_sha256 6bb6bfcb...), the acceptance harness's reference task.
    "resume": "673ecdd6-4782-41d1-9dbd-91923139181d",
}


def sql(query: str) -> str:
    # `encoding=` is REQUIRED: subprocess defaults to the locale codec (GBK on this machine), and the grader's
    # Chinese criterion output then raises UnicodeDecodeError inside subprocess's reader thread - which returns
    # EMPTY output rather than an error, so every measurement silently became "" and the corpus froze as nulls.
    # A corpus of nulls compares equal to itself and would have passed forever.
    done = subprocess.run(
        PSQL + ["-c", query], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    return (done.stdout or "").strip()


def stored_markdown_sha(task_id: str) -> tuple[str, str]:
    # `convert_to(..., 'UTF8')`, not `markdown::bytea`: the direct cast of a text column raises
    # "invalid input syntax for type bytea" on this data.
    row = sql(
        "select id, encode(sha256(convert_to(markdown, 'UTF8')), 'hex') from report_revisions "
        f"where task_id = '{task_id}' and author = 'system' order by created_at desc limit 1;"
    )
    if not row or "|" not in row:
        return "", ""
    revision, digest = row.split("|", 1)
    return revision, digest


def read_log(path: Path) -> str:
    """The suite logs are written by PowerShell redirection and are UTF-16; reading them as UTF-8 yields NULs.

    MEASURED: the first freeze recorded `"pytest_summary": "\\u0000"` for exactly this reason.
    """
    raw = path.read_bytes()
    for encoding in ("utf-16", "utf-8-sig", "utf-8"):
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if text.count("\x00") <= len(text) // 100:  # reject a decode that produced pervasive NULs
            return text
    return raw.decode("utf-8", errors="replace")


def grader_summary(task_id: str, mode: str) -> dict[str, object]:
    """Run the acceptance grader and keep only its verdict lines, so warnings cannot cause false drift."""
    done = subprocess.run(
        [sys.executable, str(GRADER), task_id, mode],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False, cwd=str(ROOT),
    )
    text = (done.stdout or "") + (done.stderr or "")
    criteria = re.search(r"criteria:\s*(\d+)\s*passed,\s*(\d+)\s*failed", text)
    verdict = re.search(r"RESULT:\s*([A-Z ]+)", text)
    return {
        "mode": mode,
        "exit_code": done.returncode,
        "criteria_passed": int(criteria.group(1)) if criteria else None,
        "criteria_failed": int(criteria.group(2)) if criteria else None,
        "verdict": (verdict.group(1).strip() if verdict else None),
    }


def measure() -> dict[str, object]:
    corpus: dict[str, object] = {"measurement": {}, "tasks": {}}
    # Newest by MTIME, not by name: the logs are named by round, so lexicographic order picks the wrong file.
    baseline_log = sorted((ROOT / ".scratch").glob("full-suite-*.log"), key=lambda p: p.stat().st_mtime)
    if baseline_log:
        lines = [ln.strip() for ln in read_log(baseline_log[-1]).splitlines()]
        summary = next((ln for ln in reversed(lines) if "passed" in ln and "failed" in ln), "")
        corpus["measurement"]["pytest_summary"] = summary
        corpus["measurement"]["pytest_log"] = baseline_log[-1].name
    for name, task_id in FROZEN_TASKS.items():
        revision, digest = stored_markdown_sha(task_id)
        corpus["tasks"][name] = {
            "task_id": task_id,
            "official_revision": revision,
            "stored_markdown_sha256": digest,
            "render": grader_summary(task_id, "--render"),
            "stored": grader_summary(task_id, "--stored"),
        }
    return corpus


def empty_measurements(corpus: dict[str, object]) -> list[str]:
    """A corpus full of nulls is not a corpus: it compares equal to itself and passes forever.

    MEASURED: the first freeze wrote exactly that, because a subprocess decode error emptied every reading.
    Freezing is therefore REFUSED unless the readings are real.
    """
    problems: list[str] = []
    if not str(corpus.get("measurement", {}).get("pytest_summary") or "").strip():
        problems.append("measurement.pytest_summary is empty")
    for name, task in (corpus.get("tasks") or {}).items():
        if not str(task.get("official_revision") or "").strip():
            problems.append(f"{name}.official_revision is empty")
        if not str(task.get("stored_markdown_sha256") or "").strip():
            problems.append(f"{name}.stored_markdown_sha256 is empty")
        for mode in ("render", "stored"):
            reading = task.get(mode) or {}
            if reading.get("criteria_passed") is None or reading.get("verdict") is None:
                problems.append(f"{name}.{mode} produced no verdict (the grader's output was not readable)")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not (args.freeze or args.check):
        parser.error("choose --freeze or --check")

    current = measure()
    if args.freeze:
        problems = empty_measurements(current)
        if problems:
            print("REFUSING TO FREEZE - the readings are not real:")
            for item in problems:
                print(f"  - {item}")
            print("\nA corpus of nulls compares equal to itself and would pass every future --check.")
            return 2
        CORPUS.parent.mkdir(parents=True, exist_ok=True)
        CORPUS.write_text(json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False))
        print(f"\nfrozen -> {CORPUS.relative_to(ROOT)}")
        return 0

    if not CORPUS.is_file():
        print(f"NO CORPUS at {CORPUS.relative_to(ROOT)} - run --freeze first; a missing corpus is not a pass")
        return 2

    # `utf-8-sig` tolerates a BOM an editor or a shell redirect may add. Without it a BOM raises
    # JSONDecodeError, which is a CRASH reported as a non-zero exit - indistinguishable from real drift to
    # anything that only checks the exit code. MEASURED while trying to can-fail this instrument.
    frozen = json.loads(CORPUS.read_text(encoding="utf-8-sig"))
    drift: list[str] = []
    for name, snapshot in frozen.get("tasks", {}).items():
        now = current["tasks"].get(name, {})
        for key in ("official_revision", "stored_markdown_sha256"):
            if snapshot.get(key) != now.get(key):
                drift.append(f"{name}.{key}: frozen={snapshot.get(key)!r} now={now.get(key)!r}")
        for mode in ("render", "stored"):
            was, is_now = snapshot.get(mode, {}), now.get(mode, {})
            for key in ("criteria_passed", "criteria_failed", "verdict"):
                if was.get(key) != is_now.get(key):
                    drift.append(f"{name}.{mode}.{key}: frozen={was.get(key)!r} now={is_now.get(key)!r}")

    if drift:
        print("PUBLISHED LAYER DRIFTED:")
        for item in drift:
            print(f"  - {item}")
        print(f"\n{len(drift)} difference(s). A structural move must not change these.")
        return 1
    print("published layer UNCHANGED on the frozen corpus")
    print(json.dumps({n: t["render"] for n, t in frozen["tasks"].items()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
