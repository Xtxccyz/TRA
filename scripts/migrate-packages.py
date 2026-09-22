"""Move whole modules into domain sub-packages, leaving an identity-preserving shim at the old path.

Design constraints, each from a measured failure in this repo:

* **Never move a module that uses `__file__` to locate a resource.** `ghidra_adapter.py` finds
  `ghidra_scripts/` relative to itself and `simulation_adapters.py` does the same; a move would break the path
  at runtime, not at import. Those modules are REFUSED and reported, not moved.
  HONEST STATUS (adversarial audit): this guard currently fires on NOTHING - 0 of the 26 entries in MOVE_MAP
  contain `__file__`, and neither module named above is in MOVE_MAP at all (both are also gate-listed and
  deliberately excluded). It is kept as a guard for FUTURE additions to the map, but it must not be described as
  protecting anything today, and it cannot be relied on to catch a module that locates resources some other way:
  `prompts.py:25` uses `resources.files("threat_report_agent")` with no literal `__file__`, passes the guard,
  and survives a move only because it is anchored to the package root rather than the module.
* **Never move a module the deployment gate lists.** HISTORY AND CURRENT TRUTH: the original version of this
  script read a GITIGNORED copy (`.scratch/check-deployed-code-hashes.py`) that named a FIXED list of 14 modules,
  and a moved file would silently stop being compared - the "shim satisfies the gate" hazard. An adversarial audit
  of the report move found that this made the script CRASH in a fresh clone (`FileNotFoundError`) and that the
  stale copy it read still listed `analyst_report.py`, i.e. the guard was driven by a gate that no longer exists.
  The tracked gate now ENUMERATES every file under `src/threat_report_agent` from disk, so a moved file is
  compared at its new path automatically and the hazard is gone; consequently `gate_modules()` finds ZERO pinned
  names and this refusal class is INERT. That is stated rather than implied: the script reports the count it
  refused on, so nobody can read "0 refused" as "checked and safe".
* **Never create a package whose stem is the name of a module in this project.** A package directory SHADOWS a
  same-named module, so `from threat_report_agent.X import f` resolves to the package and loses everything the
  module exported. MEASURED: the first version shipped `investigation.py -> investigation` and
  `intake.py -> intake`; the full suite returned 145 ImportErrors (144 `investigation`, 1 `intake`), each naming
  the new `__init__.py`. The audit noted the round blamed the PLAN for this while shipping the same defect
  itself. Both entries are still in the map on purpose - the guard now refuses them, which is exactly the
  behaviour a rerun needs.
* **Never adopt a directory this script did not create.** `static/` already existed as an ASSET directory with no
  `__init__.py`; the first version treated it as new and a later cleanup deleted three TRACKED files.

Usage:  python .scratch/migrate-packages.py [--apply]
Without --apply it reports what it would do and changes nothing.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "threat_report_agent"
#: The TRACKED gate. MEASURED bug this fixes: it used to point at `.scratch/check-deployed-code-hashes.py`, which
#: is gitignored, so a fresh clone got `FileNotFoundError` instead of a decision.
GATE = ROOT / "scripts" / "check-deployed-code-hashes.py"

#: module -> sub-package. Only modules in NEITHER refusal class below are moved.
MOVE_MAP: dict[str, str] = {
    # facts: provenance-bearing predicates
    "dataflow.py": "facts",
    "decode_primitives.py": "facts",
    # investigation
    "investigation.py": "investigation",
    "investigation_protocol.py": "investigation",
    "investigation_ledger.py": "investigation",
    "behavior_catalog.py": "investigation",
    "persist_how.py": "investigation",
    "mechanism_completeness.py": "investigation",
    "mechanism_ready.py": "investigation",
    "semantic_predicates.py": "investigation",
    # static recovery (NOT static_analysis.py itself: the plan leaves it, and it is gate-listed)
    "function_similarity.py": "static",
    "function_simhash.py": "static",
    "evidence_recovery.py": "static",
    "evidence_index.py": "static",
    "static_simulation.py": "static",
    "pma_static_plan.py": "static",
    "literal_table.py": "static",
    # emulation (NOT simulation_adapters.py: it uses __file__)
    "emulation_plan.py": "emulation",
    "controlled_emulation.py": "emulation",
    "vb6_runtime_shim.py": "emulation",
    # model
    "agents.py": "model",
    "agent_runtime.py": "model",
    "prompts.py": "model",
    # tools / intake
    "tool_authoring.py": "tools",
    "intake.py": "intake",
    "content_store.py": "intake",
}

SHIM = '''"""Compatibility shim: this module MOVED to `threat_report_agent.{pkg}.{name}`.

Structural move only - no behaviour change. The shim rebinds `sys.modules` to the real module instead of
`import *`, so one module object serves both paths and PRIVATE names remain reachable (45 test files use them),
and patching either path affects the other.
"""
import sys as _sys

from threat_report_agent.{pkg} import {stem} as _real

_sys.modules[__name__] = _real
'''


def gate_modules() -> set[str]:
    """Modules the deployment gate names EXPLICITLY. MEASURED: the tracked gate enumerates from disk, so this
    returns an EMPTY set - the refusal class below is therefore inert, and `main` prints the count so the emptiness
    is visible rather than mistaken for a clean bill of health."""
    if not GATE.is_file():
        raise RuntimeError(
            f"BLOCKED: the deployment gate is missing at {GATE}, so the refusal rule cannot be evaluated"
        )
    text = GATE.read_text(encoding="utf-8")
    return set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*\.py)"', text))


def uses_dunder_file(path: Path) -> bool:
    return "__file__" in path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--package", default="", help="move only this sub-package (one package per run)")
    args = parser.parse_args()

    try:
        gated = gate_modules()
    except RuntimeError as exc:
        print(str(exc))
        return 2
    print(f"gate lists {len(gated)} module(s): {', '.join(sorted(gated)) or '(none)'}")
    if not gated:
        print(
            "  NOTE: the tracked gate enumerates src/ from disk, so it pins no module names and this refusal class "
            "protects nothing. The script does NOT claim a module is gate-safe on this basis.\n"
        )

    # TWO guards added after this script's first run destroyed the suite and three tracked files.
    #
    # 1. PATH OCCUPANCY. `static/` already existed as an ASSET directory (app.js, index.html, styles.css). The
    #    first version never checked, treated it as new, and a later `Remove-Item -Recurse` deleted tracked
    #    files. A package directory we did not create must be refused, not adopted.
    # 2. NAME SHADOWING. A package directory SHADOWS a same-named module, so building `investigation/` while
    #    `investigation/__init__.py` exists makes `from threat_report_agent.investigation import <function>`
    #    resolve to the PACKAGE and lose every name the module exported. That broke 145 test modules. If a
    #    module of the package's own name exists, refuse.
    packages_wanted = sorted({pkg for pkg in MOVE_MAP.values()})
    if args.package:
        if args.package not in packages_wanted:
            print(f"unknown or unused package: {args.package}; known: {', '.join(packages_wanted)}")
            return 2
        packages_wanted = [args.package]
    else:
        print("no --package given: defaulting to ONE package per run to keep the blast radius small")
        packages_wanted = packages_wanted[:1]

    package_problems: list[str] = []
    for package in packages_wanted:
        target = PKG / package
        if target.exists() and not (target / "__init__.py").is_file():
            contents = ", ".join(sorted(p.name for p in target.iterdir()))[:120]
            package_problems.append(f"{package}/ already exists and is NOT one of our packages ({contents})")
        if (PKG / f"{package}.py").is_file():
            package_problems.append(
                f"{package}/ would SHADOW the module {package}.py, which exports names imported as "
                f"`from threat_report_agent.{package} import ...`"
            )
    if package_problems:
        print("REFUSING - package-level problems:")
        for item in package_problems:
            print(f"  {item}")
        return 2

    refused: list[str] = []
    movable: list[tuple[str, str]] = []
    for name, package in sorted(MOVE_MAP.items()):
        if package not in packages_wanted:
            continue
        source = PKG / name
        if not source.is_file():
            refused.append(f"{name}: not present")
            continue
        if uses_dunder_file(source):
            refused.append(f"{name}: uses __file__ to locate a resource (a move breaks it at RUNTIME)")
            continue
        if name in gated:
            refused.append(f"{name}: listed by the deployment gate (a move would silently drop it from the gate)")
            continue
        movable.append((name, package))

    print(f"would move {len(movable)} module(s) into {', '.join(packages_wanted)}/:")
    for name, package in movable:
        print(f"  {name:32} -> {package}/")
    print(f"\nrefused {len(refused)}:")
    for item in refused:
        print(f"  {item}")

    if not args.apply:
        print("\n(dry run - pass --apply to perform)")
        return 0

    for package in sorted({pkg for _, pkg in movable}):
        target = PKG / package
        target.mkdir(exist_ok=True)
        init = target / "__init__.py"
        if not init.is_file():
            init.write_text('"""Domain sub-package (structural move; see .scratch/migrate-packages.py)."""\n', encoding="utf-8")

    for name, package in movable:
        source = PKG / name
        destination = PKG / package / name
        subprocess.run(["git", "mv", str(source.relative_to(ROOT)), str(destination.relative_to(ROOT))],
                       cwd=str(ROOT), check=True, capture_output=True)
        shim = SHIM.format(pkg=package, name=name, stem=name[:-3])
        source.write_text(shim, encoding="utf-8")
        print(f"moved {name} -> {package}/{name} (shim left at {name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
