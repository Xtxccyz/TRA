"""AST import graph: edges, forbidden directions, and cycle components. No `.scratch` dependency.

Plan section 4.3 requires a reproducible import check, and section 14.2 requires that a reverse dependency
cannot hide behind a re-export. This script therefore reads the SOURCE, not `sys.modules`: a shim that points an
old path at a canonical module is invisible to an import-time check but visible here.

Measured facts about this repository that shape the implementation:

* The package is flat today (58 modules) with `facts/` as the first sub-package, so edges are resolved against
  both `threat_report_agent.<name>` and `threat_report_agent.<pkg>.<name>`.
* `from __future__ import annotations` and `if TYPE_CHECKING:` blocks create edges that never execute at runtime.
  They are recorded separately rather than silently dropped - a hidden runtime edge is exactly what the plan
  wants to prevent, and so is pretending a type-only edge is a runtime cycle.
* Dynamic `importlib.import_module("threat_report_agent.X")` counts as an edge (plan section 3.2: "动态 import
  也算依赖").

Usage:

    python scripts/check-import-graph.py                     # report
    python scripts/check-import-graph.py --strict            # fail on an unallowed cycle or forbidden edge
    python scripts/check-import-graph.py --json              # machine-readable
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "threat_report_agent"
PACKAGE = "threat_report_agent"
POLICY = ROOT / "docs" / "import-policy.json"


def module_name(path: Path) -> str:
    """`src/threat_report_agent/facts/dataflow.py` -> `threat_report_agent.facts.dataflow`."""
    relative = path.relative_to(SOURCE).with_suffix("")
    parts = [PACKAGE, *relative.parts]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def is_type_only(node: ast.stmt) -> bool:
    """True when the statement sits inside `if TYPE_CHECKING:` - an edge that never runs."""
    return isinstance(node, ast.If) and any(
        (isinstance(t, ast.Name) and t.id == "TYPE_CHECKING") for t in ast.walk(node.test)
    )


def collect(path: Path) -> tuple[str, set[str], set[str]]:
    """Returns (module, runtime_edges, type_only_edges)."""
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    module = module_name(path)
    runtime: set[str] = set()
    typing: set[str] = set()

    def target(name: str, level: int, current: str) -> str | None:
        if level:
            base = current.split(".")
            base = base[: len(base) - level] if level <= len(base) else []
            prefix = ".".join(base)
            return f"{prefix}.{name}" if name else prefix
        return name or None

    for node in ast.walk(tree):
        record = typing if False else runtime
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(PACKAGE):
                    record.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            resolved = target(node.module or "", node.level, module)
            if resolved and resolved.startswith(PACKAGE):
                for alias in node.names:
                    record.add(f"{resolved}.{alias.name}")
                record.add(resolved)
        elif isinstance(node, ast.Call):
            # importlib.import_module("threat_report_agent.X")
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name == "import_module" and node.args and isinstance(node.args[0], ast.Constant):
                literal = str(node.args[0].value)
                if literal.startswith(PACKAGE):
                    runtime.add(literal)

    # Type-only edges: re-walk the TYPE_CHECKING blocks so they can be reported apart from real cycles.
    for node in ast.walk(tree):
        if is_type_only(node):
            for inner in ast.walk(node):
                if isinstance(inner, ast.ImportFrom):
                    resolved = target(inner.module or "", inner.level, module)
                    if resolved and resolved.startswith(PACKAGE):
                        typing.add(resolved)
                elif isinstance(inner, ast.Import):
                    for alias in inner.names:
                        if alias.name.startswith(PACKAGE):
                            typing.add(alias.name)
    return module, runtime - typing, typing


def short(name: str) -> str:
    return name[len(PACKAGE) + 1:] if name.startswith(PACKAGE + ".") else name


def resolve(edge: str, known: set[str]) -> str | None:
    """Map a possibly-submodule edge onto a known module, longest match first."""
    candidate = edge
    while candidate.startswith(PACKAGE):
        if candidate in known:
            return candidate
        if "." not in candidate:
            return None
        candidate = candidate.rsplit(".", 1)[0]
    return None


def components(nodes: list[str], edges: dict[str, set[str]]) -> list[list[str]]:
    """Tarjan SCC; returns only components larger than one node (real cycles)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    counter = [0]
    found: list[list[str]] = []

    def strong(node: str) -> None:
        index[node] = low[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for other in sorted(edges.get(node, ())):
            if other not in index:
                strong(other)
                low[node] = min(low[node], low[other])
            elif other in on_stack:
                low[node] = min(low[node], index[other])
        if low[node] == index[node]:
            group: list[str] = []
            while True:
                item = stack.pop()
                on_stack.discard(item)
                group.append(item)
                if item == node:
                    break
            if len(group) > 1:
                found.append(sorted(group))

    for node in nodes:
        if node not in index:
            strong(node)
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--dump-edges",
        action="store_true",
        help="print the runtime edge set as JSON pairs and exit (this is how `known_edges` is recorded)",
    )
    parser.add_argument(
        "--source",
        default="",
        help="measure another copy of the package instead of src/ (used by the structure-diff can-fail harness)",
    )
    parser.add_argument("--policy", default="", help="use another policy file")
    args = parser.parse_args()
    if args.source:
        global SOURCE  # noqa: PLW0603 - a single deliberate override for the can-fail harness
        SOURCE = Path(args.source).resolve()
    policy_path = Path(args.policy).resolve() if args.policy else POLICY

    files = sorted(path for path in SOURCE.rglob("*.py") if "__pycache__" not in path.parts)
    runtime: dict[str, set[str]] = {}
    typing: dict[str, set[str]] = {}
    for path in files:
        module, edges, types = collect(path)
        runtime[module] = edges
        typing[module] = types
    known = set(runtime)
    resolved = {node: {r for edge in edges if (r := resolve(edge, known)) and r != node} for node, edges in runtime.items()}

    cycles = components(sorted(known), resolved)
    # Compare on SHORT names throughout. MEASURED BUG: `components` returns fully-qualified module names while
    # the policy lists short ones, so every allowlisted cycle was reported as NEW and --strict failed on the
    # very cycles the policy had just recorded.
    cycles_short = [tuple(sorted(short(node) for node in group)) for group in cycles]

    policy: dict[str, object] = {}
    if policy_path.is_file():
        policy = json.loads(policy_path.read_text(encoding="utf-8"))

    # NORMALISE RENAMED MODULES BEFORE COMPARING ANYTHING (plan 7.1: a structural move changes WHERE a module
    # lives, not WHICH module it is). MEASURED why: moving `static_analysis.py` into `static/` made the recorded
    # cycle `controlled_emulation <-> emulation_plan <-> investigation <-> static_analysis` report as NEW, because
    # the graph spelled the member `static.static_analysis` while the allowlist spells it the old way. The cycle had
    # not changed; one member had been renamed.
    #
    # THE MAP IS APPLIED NEW -> OLD, deliberately: the whole policy (known_cycles, forbidden_edges,
    # known_violations) is written in FLAT names, and `_forbidden_edges_note` says why those flat names are listed -
    # "the migration leaves shims that keep both names alive; enforcing only the package names would let a reverse
    # edge survive under the old name". Normalising to the old name therefore keeps every direction rule applying
    # ACROSS a move instead of going blind the moment a module is relocated.
    renames = {}
    for item in policy.get("moved_paths", []):
        if not (isinstance(item, dict) and item.get("old") and item.get("new")):
            continue
        new = str(item["new"])
        old = str(item["old"])
        # Graph nodes are FULLY QUALIFIED (`threat_report_agent.static.static_analysis`) while the policy lists short
        # paths, so the map is built in the qualified form. MEASURED: keying it short made the normalisation a no-op
        # and the renamed cycle still reported as NEW.
        key = new if new.startswith(PACKAGE + ".") else f"{PACKAGE}.{new}"
        value = old if old.startswith(PACKAGE + ".") else f"{PACKAGE}.{old}"
        renames[key] = value

    def canonical(name: str) -> str:
        """Follow the rename chain (a moved path may itself move again) until it settles on the flat name."""
        seen: set[str] = set()
        while name in renames and name not in seen:
            seen.add(name)
            name = renames[name]
        return name

    # MERGE on collision rather than overwrite. MEASURED BUG: a rename makes TWO graph nodes canonicalise to the
    # same flat name (the shim `threat_report_agent.static_analysis` and the real
    # `threat_report_agent.static.static_analysis`), and a dict comprehension let the later one win - which silently
    # dropped the real module's out-edges and made `static_analysis` vanish from a recorded cycle it is still part of.
    merged: dict[str, set[str]] = {}
    for node, targets in resolved.items():
        key = canonical(node)
        for target in targets:
            canonical_target = canonical(target)
            if canonical_target != key:
                merged.setdefault(key, set()).add(canonical_target)
    for node in known:
        merged.setdefault(canonical(node), set())
    resolved = merged
    nodes = sorted(set(resolved))

    # --- EDGE REGISTRY (added after an adversarial review measured the blind spot three times) --------------------
    # Every runtime edge as a short `(source, target)` pair. The `moved_paths` normalisation above is already applied,
    # so a relocated module is policed under its recorded name rather than escaping under the new one.
    edges_short = sorted({(short(a), short(b)) for a, targets in resolved.items() for b in targets})
    if args.dump_edges:
        print(json.dumps([list(pair) for pair in edges_short], ensure_ascii=False, indent=1))
        return 0
    cycles = components(nodes, resolved)
    # Compare on SHORT names throughout. MEASURED BUG: `components` returns fully-qualified module names while
    # the policy lists short ones, so every allowlisted cycle was reported as NEW and --strict failed on the
    # very cycles the policy had just recorded.
    cycles_short = [tuple(sorted(short(node) for node in group)) for group in cycles]

    allowed_cycles = {tuple(sorted(item)) for item in policy.get("known_cycles", [])}
    forbidden = {(str(a), str(b)) for a, b in policy.get("forbidden_edges", [])}
    # Pre-existing violations are RECORDED, not fixed, in a structural step (plan P0.4: "发现现有循环先记录,
    # 不借搬家机会顺手重写业务"). Only a violation absent from this list fails --strict.
    known_violations = {(str(a), str(b)) for a, b in policy.get("known_violations", [])}

    # The EDGE allow-list: the recorded inventory plus the explicit decisions. MEASURED DEFECT this closes: with only
    # NODES registered and a flat deny-list, an edge between two registered modules that no `forbidden_edges` entry
    # names passes GREEN - which is why `recorded_allowed_edges` could be ignored by the gate while looking enforced.
    known_edges = {(str(a), str(b)) for a, b in policy.get("known_edges", [])}
    decision_edges = {(str(a), str(b)) for a, b in policy.get("recorded_allowed_edges", [])}
    allowed_edges = known_edges | decision_edges
    new_edges = [(a, b) for (a, b) in edges_short if (a, b) not in allowed_edges]
    stale_edges = [(a, b) for (a, b) in sorted(known_edges) if (a, b) not in set(edges_short)]

    new_cycles = [group for group in cycles_short if group not in allowed_cycles]
    all_violations = sorted(
        f"{short(a)} -> {short(b)}"
        for a, targets in resolved.items()
        for b in targets
        if (short(a), short(b)) in forbidden
    )
    new_violations = sorted(
        item for item in all_violations
        if tuple(item.split(" -> ")) not in known_violations
    )

    # --- KNOWN-MODULE REGISTRY (round 135) ------------------------------------------------------------------
    # MEASURED HOLE: a module created AFTER this policy was written appears in no policy entry, so no forbidden pair
    # can ever match it and the strict gate passes it whatever it imports. `emulation/coordinator.py` (the module plan
    # P3.5 creates) could import `report.reporting` and still print "no new cycles and no new reverse edges".
    # A module must therefore be REGISTERED: by any policy entry, or in `known_modules`. This mirrors what
    # `moved_paths` already does for RENAMED modules, extended to NEW ones.
    registered: set[str] = set(policy.get("known_modules", []))
    for pair in policy.get("forbidden_edges", []):
        registered.update(str(item) for item in pair)
    for pair in policy.get("known_violations", []):
        registered.update(str(item) for item in pair)
    for pair in policy.get("known_cycles", []):
        registered.update(str(item) for item in pair)
    for pair in policy.get("recorded_allowed_edges", []):
        registered.update(str(item) for item in pair)
    for entry in policy.get("moved_paths", []):
        registered.add(str(entry.get("old", "")))
        registered.add(str(entry.get("new", "")))
    unregistered = sorted(
        short(node) for node in nodes
        if short(node) not in registered
        and not any(short(node) == part or short(node).startswith(part + ".") for part in registered if part)
    )
    if unregistered:
        print(f"\nUNREGISTERED MODULES ({len(unregistered)}): {', '.join(unregistered)}")
        print("  A module absent from every policy entry cannot be policed: the deny-list is applied to the names it")
        print("  knows, so a direct forbidden import from here would pass GREEN. Register it in `known_modules`")
        print("  (with its layer) in the same commit that adds it.")

    if args.json:
        print(json.dumps({
            "modules": len(known),
            "edges": sum(len(v) for v in resolved.values()),
            "cycles": [list(group) for group in cycles_short],
            "new_cycles": [list(group) for group in new_cycles],
            "forbidden_violations": all_violations,
            "new_forbidden_violations": new_violations,
            "registered_edges": len(known_edges),
            "new_edges": [list(pair) for pair in new_edges],
            "stale_edges": [list(pair) for pair in stale_edges],
        }, indent=2, ensure_ascii=False))
    else:
        print(f"modules : {len(known)}")
        print(f"edges   : {sum(len(v) for v in resolved.values())} (runtime, same-package)")
        print(f"type-only edges (not runtime): {sum(len(v) for v in typing.values())}")
        print(f"cycles  : {len(cycles_short)} total, {len(new_cycles)} not in the allowlist")
        for group in cycles_short:
            marker = "KNOWN" if group in allowed_cycles else "NEW"
            print(f"  [{marker}] " + " <-> ".join(group)[:160])
        print(f"forbidden edges present: {len(all_violations)} ({len(new_violations)} not registered)")
        print(f"edges registered: {len(known_edges)} of {len(edges_short)} ({len(new_edges)} unregistered, {len(stale_edges)} stale)")
        for item in all_violations[:10]:
            tag = "NEW" if item in new_violations else "known"
            print(f"  [{tag}] {item}")

    if new_edges:
        print(f"\nUNREGISTERED EDGES ({len(new_edges)}): {', '.join(f'{a} -> {b}' for a, b in new_edges[:12])}")
        print("  An edge between two registered modules is invisible to a deny-list. Record it in `known_edges` in the")
        print("  same commit that adds it, or state the decision in `recorded_allowed_edges`.")
    if stale_edges:
        print(f"\nSTALE EDGE RECORDS ({len(stale_edges)}): "
              f"{', '.join(f'{a} -> {b}' for a, b in stale_edges[:12])}")
        print("  A recorded edge no longer exists in the tree. The record must match the measurement EXACTLY, so delete")
        print("  the entry deliberately in the same commit that removes the import.")
    if args.strict and (new_cycles or new_violations or unregistered or new_edges or stale_edges):
        print("\nSTRICT: import policy violated")
        return 1
    if args.strict:
        print("\nSTRICT: no new cycles and no new reverse edges")
    if not policy:
        print(f"\nnote: no policy file at {policy_path}, so nothing is enforced yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
