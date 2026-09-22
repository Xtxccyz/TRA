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
    args = parser.parse_args()

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
    if POLICY.is_file():
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
    allowed_cycles = {tuple(sorted(item)) for item in policy.get("known_cycles", [])}
    forbidden = {(str(a), str(b)) for a, b in policy.get("forbidden_edges", [])}
    # Pre-existing violations are RECORDED, not fixed, in a structural step (plan P0.4: "发现现有循环先记录,
    # 不借搬家机会顺手重写业务"). Only a violation absent from this list fails --strict.
    known_violations = {(str(a), str(b)) for a, b in policy.get("known_violations", [])}

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

    if args.json:
        print(json.dumps({
            "modules": len(known),
            "edges": sum(len(v) for v in resolved.values()),
            "cycles": [list(group) for group in cycles_short],
            "new_cycles": [list(group) for group in new_cycles],
            "forbidden_violations": all_violations,
            "new_forbidden_violations": new_violations,
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
        for item in all_violations[:10]:
            tag = "NEW" if item in new_violations else "known"
            print(f"  [{tag}] {item}")

    if args.strict and (new_cycles or new_violations):
        print("\nSTRICT: import policy violated")
        return 1
    if args.strict:
        print("\nSTRICT: no new cycles and no new reverse edges")
    if not policy:
        print("\nnote: no policy file at docs/import-policy.json, so nothing is enforced yet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
