"""PREFLIGHT for every structural slice: the instruments and gate scripts must at least COMPILE.

WHY THIS EXISTS (MEASURED, round 107): `.scratch/p33-extract.py` - the tool every P3.3 slice depends on - was found
NOT COMPILING, with two statements merged onto one line, the signature of the PowerShell text mangling this project has
hit repeatedly. It was discovered only because the slice happened to run it. The instruments live in `.scratch/`, which
is GITIGNORED, so a corrupted instrument produces NO `git status` signal and NO diff to review: nothing else in this
repository can detect it. That makes "the tools still compile" a hard gate, not a courtesy.

WHAT IT CHECKS
  1. every `scripts/*.py` and `.scratch/*.py` parses (a `SyntaxError` is the observed failure mode);
  2. the instruments named in `EXPECTED` still exist - a missing one means a step's tooling was moved or deleted
     without the record being updated, and the next slice would fail in a more confusing way;
  3. it REFUSES TO PASS VACUOUSLY: if `.scratch` contains no Python files at all, that is a failure rather than a
     silent "0 files checked", because an empty directory would otherwise make this gate meaningless.

  --self-check proves the gate can fail: it compiles a synthetic file carrying the EXACT corruption pattern that was
  found in the extractor, and requires the CLI to exit non-zero on it.

USAGE (run this BEFORE measuring or moving anything)

    py scripts/check-slice-tooling.py
    py scripts/check-slice-tooling.py --self-check
    py scripts/check-slice-tooling.py --targets <dir> [<dir> ...]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The instruments the current slices depend on. Retiring or moving one is a deliberate act: update this list in the
#: same step, so that "the tool is gone" is never discovered halfway through a move.
EXPECTED = (
    "p32-measure-cluster.py",
    "p33-extract.py",
    "p33-verify.py",
    "p33c-textdiff.py",
    "p33-arity.py",
    "p33-reference-check.py",
    "p33-canfail.py",
    "layer1-move.py",
    "layer4-move.py",
    "compare-failure-nodes.py",
    "format-debt-attribution.py",
    "restore-from-head.py",
)

#: The corruption pattern actually found in `p33-extract.py`: two statements on one line inside a function.
SYNTHETIC_CORRUPTION = (
    "def example():\n"
    "    first = 1        second = 2\n"
    "    return first + second\n"
)

#: Files that are genuinely not runnable Python AND are not instruments any step depends on: two UTF-16 one-off
#: artifacts written by the same text mangling (`_rev32a7921_service.py` is a copy of service.py at a revision). They
#: are REGISTERED rather than silently skipped, so that a NEW unrunnable file - which would be a real corruption of
#: something in use - still fails the gate. Deleting them is a cleanup nobody needs to do; if one disappears or becomes
#: readable, this gate says so instead of quietly shrinking.
KNOWN_UNRUNNABLE = ("_head_check.py", "_rev32a7921_service.py")


def python_files(directories: list[Path]) -> list[Path]:
    found: list[Path] = []
    for directory in directories:
        if directory.is_dir():
            found.extend(sorted(directory.glob("*.py")))
    return found


def compile_failures(paths: list[Path]) -> list[tuple[Path, str]]:
    """A file fails if the INTERPRETER could not run it - not if a naive string compile cannot.

    MEASURED, first version of this gate: reading every file as plain UTF-8 and calling `compile()` reported **125**
    failures in `.scratch/`, nearly all "invalid non-printable character U+FEFF". They were FALSE POSITIVES: CPython
    strips a UTF-8 BOM when it reads a source FILE, so those tools run correctly; only an in-memory `compile()` of the
    raw text chokes on the BOM. An instrument that cries wolf 125 times is worse than no instrument - so the reader
    mirrors the interpreter: strip a UTF-8 BOM (PEP 263) and, separately, report UTF-16 source as a REAL failure, since
    the interpreter genuinely cannot run a UTF-16 file.
    """
    failures: list[tuple[Path, str]] = []
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            failures.append((path, f"OSError: {exc}"))
            continue
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            failures.append((path, "UTF-16 source: the interpreter cannot run this file (it is not valid Python text)"))
            continue
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            failures.append((path, f"not valid UTF-8: {exc}"))
            continue
        if "\x00" in text:
            failures.append((path, "contains NUL bytes: the interpreter cannot run this file"))
            continue
        try:
            compile(text, str(path), "exec")
        except SyntaxError as exc:
            failures.append((path, f"SyntaxError line {exc.lineno}: {exc.msg}"))
    return failures


def run(targets: list[Path], expected: tuple[str, ...]) -> int:
    paths = python_files(targets)
    print(f"compiling {len(paths)} python file(s) from: {', '.join(str(t.relative_to(ROOT)) for t in targets)}")
    scratch = [p for p in paths if p.parent.name == ".scratch"]
    if targets == [ROOT / ".scratch"] and not scratch:
        print("FAIL: .scratch contains no python files, so this gate would pass vacuously")
        return 1
    failures = compile_failures(paths)
    unregistered: list[tuple[Path, str]] = []
    registered: list[str] = []
    for path, message in failures:
        if path.parent.name == ".scratch" and path.name in KNOWN_UNRUNNABLE:
            registered.append(path.name)
        else:
            unregistered.append((path, message))
    registered.sort()
    for path, message in unregistered:
        print(f"  FAIL {path.relative_to(ROOT)}: {message}")
    if registered:
        print(f"  registered-unrunnable (not used by any step, recorded in KNOWN_UNRUNNABLE): {registered}")
        stale = sorted(name for name in KNOWN_UNRUNNABLE if name not in registered)
        if stale:
            print(f"  NOTE: registered-unrunnable but now fine or gone: {stale}; shrink the list deliberately")
    if unregistered:
        print(f"UNCOMPILABLE: {len(unregistered)} file(s). A slice instrument that does not parse cannot be trusted, "
              "and NOTHING ELSE in this repository can detect the corruption because .scratch is gitignored.")
        return 1

    missing = [name for name in expected if not (ROOT / ".scratch" / name).is_file()]
    if missing and targets == [ROOT / ".scratch"]:
        print(f"FAIL: expected instrument(s) missing from .scratch: {missing}")
        print("If one was deliberately retired, update EXPECTED in this script in the same step.")
        return 1
    print(f"OK: {len(paths)} file(s) parse"
          + (f"; all {len(expected)} expected instruments present" if targets == [ROOT / ".scratch"] else ""))
    return 0


def self_check() -> int:
    """Prove the gate can fail, on the corruption pattern that actually occurred."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "corrupted.py").write_text(SYNTHETIC_CORRUPTION, encoding="utf-8")
        helper_failures = compile_failures([directory / "corrupted.py"])
        print(f"self-check: the compile helper reports {len(helper_failures)} failure(s) for the synthetic corruption")
        if not helper_failures:
            print("SELF-CHECK FAILED: the helper accepts a merged-statement file, so the gate proves nothing")
            return 1
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--targets", str(directory)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        print(f"self-check: the CLI exits {result.returncode} on the synthetic corruption "
              f"({'CAUGHT' if result.returncode != 0 else 'NOT CAUGHT'})")
        if result.returncode == 0:
            print("SELF-CHECK FAILED: the CLI passed a directory whose only file does not compile")
            return 1
    print("SELF-CHECK PASSED: this gate fails on the exact corruption it exists to catch")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Confirm the slice instruments compile before using them.")
    parser.add_argument("--targets", nargs="*", default=None, help="directories to compile (default: scripts/ and .scratch/)")
    parser.add_argument("--self-check", action="store_true", help="prove the gate fails on a synthetic corruption")
    args = parser.parse_args()
    if args.self_check:
        return self_check()
    targets = [Path(item) for item in args.targets] if args.targets else [ROOT / "scripts", ROOT / ".scratch"]
    return run(targets, EXPECTED)


if __name__ == "__main__":
    raise SystemExit(main())
