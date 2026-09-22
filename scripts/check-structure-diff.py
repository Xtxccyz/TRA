"""Structure-diff gate: plan P1.3 (structural rules) and P1.4 (a structural step must not change behaviour).

TWO GATES, ONE SCRIPT, because the plan puts both on this file:

  `--structure`  P1.3. Rejects four things, each named by the plan:
                   1. a NEW reverse dependency                     -> delegated to check-import-graph.py --strict
                   2. a duplicate canonical implementation          -> an identical body in two modules
                   3. `getsource(X._y)` / `getattr(x, "_y")` in a PRODUCTION file (private reach by name)
                   4. an UNREGISTERED import of a path that already moved (the old-path shim's caller list)
                 Each is compared against `docs/import-policy.json`. Pre-existing instances are RECORDED there
                 with what they are, because P1.3's success criterion is that a PURE MOVE PASSES; a NEW instance
                 fails. That is the same discipline P0.4 used for cycles and for `persist_how -> reporting`.

  `--surface`    P1.4. Compares EIGHT recorded readings against `docs/structure-surface.json`: the six surfaces
                 the plan names (report schema, validator thresholds, state enums, prompt semantics, budget
                 constants, sample execution strategy) plus the compose gate's verdicts on the negative fixtures
                 and a recorded count of test-side `getsource` calls. MEASURED BY STATIC EXTRACTION KEYED BY
                 SYMBOL NAME - with ONE deliberate exception, `prompt_semantics`, which is keyed by file path
                 because a prompt's location is part of how it is loaded - so a pure move or rename passes, which
                 is the other half of P1.4's success criterion.
                 `--record-surface` writes the file deliberately and REFUSES to record an empty surface; a normal
                 run only compares.

  `--fixtures`   P1.4's negative controls, run against the real compose gate. Three deliberate behaviour changes
                 the plan names MUST be rejected: UNKNOWN -> CANDIDATE, a deleted limitation, a relaxed compose
                 gate (an unprovenanced endpoint accepted). A fourth reading - the plan's narrower
                 "heading kept, bullets dropped" case - is RECORDED, not asserted, because it is measured NOT to
                 be rejected today and P0.5-r2 recorded that gap; the reading lives in the surface file so a
                 change in it is visible instead of silent.

WHY NOT A UNIFIED DIFF OF TWO REVISIONS: a git diff of the source would flag every whitespace and import
reordering, and a diff of rendered output would need a database. The surfaces above are the things the plan
enumerates, and each is a value a structural step has no reason to touch.

    `--source DIR` points the extraction at another copy of the package instead of `src/`, which is how the
                 can-fail harness measures a mutated copy. NOTE: only the extraction moves. `POLICY_PATH` and
                 `SURFACE_PATH` stay the REPOSITORY's files, because a copy must be compared against the recorded
                 baseline and the recorded policy - comparing a copy against itself would prove nothing.

Usage:

    python scripts/check-structure-diff.py --all --strict
    python scripts/check-structure-diff.py --surface --record-surface
    python scripts/check-structure-diff.py --fixtures
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "threat_report_agent"
PACKAGE = "threat_report_agent"
POLICY_PATH = ROOT / "docs" / "import-policy.json"
SURFACE_PATH = ROOT / "docs" / "structure-surface.json"
IMPORT_GRAPH = ROOT / "scripts" / "check-import-graph.py"


def set_source(value: str) -> None:
    """Point the extraction at another copy of the package.

    WHY THIS EXISTS: P1.4's success criterion is "a pure rename/move PASSES while a behaviour change is
    rejected". That cannot be demonstrated on the real tree without moving real files, so `--source` lets a
    can-fail harness copy the package into `.scratch`, move a module inside the COPY, and measure both verdicts
    with no risk to the repository. The default is the real source.
    """
    global SOURCE  # noqa: PLW0603 - a deliberate single-point override
    SOURCE = Path(value).resolve()

#: A body shorter than this is not an implementation worth de-duplicating, and including tiny helpers would fill
#: the report with coincidences. MEASURED: at 120 chars the tree has exactly ONE duplicate group.
DUPLICATE_MIN_CHARS = 120

#: Paths that have ALREADY moved, with the canonical module that now holds the implementation. Kept as a FALLBACK:
#: the authoritative map is `moved_paths` in `docs/import-policy.json`, read by `legacy_paths()` below, so this rule
#: and the import-graph's rename normalisation share ONE source and a move no longer needs two hand edits.
LEGACY_PATHS: dict[str, str] = {
    "dataflow": "facts.dataflow",
    "decode_primitives": "facts.decode_primitives",
    "analyst_report": "report.analyst_report",
    "report_verification": "report.report_verification",
    "gold_output_bar": "report.gold_output_bar",
    # P2-S grew from round 73. Its registered importer list is empty because production moved to the new path
    # first (plan 7.1 step 5), so any future old-path use of these fails immediately.
    "function_simhash": "static.function_simhash",
    "evidence_index": "static.evidence_index",
    "function_similarity": "static.function_similarity",
    "literal_table": "static.literal_table",
    "static_simulation": "static.static_simulation",
    "evidence_recovery": "static.evidence_recovery",
    "pma_static_plan": "static.pma_static_plan",
    "static_analysis": "static.static_analysis",
}


def legacy_paths() -> dict[str, str]:
    """The rename map, from `docs/import-policy.json` when it is readable and from the constant otherwise.

    A root shim keeps an old path importable; the point of the rule is that the list of files still using it is
    explicit rather than discovered by grep during P4.

    ENTRIES MARKED `public_path_unchanged` ARE SKIPPED, for a measured reason: for a MODULE -> PACKAGE move the old
    dotted path IS the new public path (`threat_report_agent.investigation` is now the package), so a production
    importer of it is CORRECT and there is nothing to migrate. The import graph still uses those entries for rename
    normalisation; only this rule ignores them.
    """
    if POLICY_PATH.is_file():
        try:
            policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            policy = {}
        entries = {
            str(item["old"]): str(item["new"])
            for item in policy.get("moved_paths", [])
            if isinstance(item, dict)
            and item.get("old")
            and item.get("new")
            and not item.get("public_path_unchanged")
        }
        if entries:
            return entries
    return dict(LEGACY_PATHS)

#: The state vocabularies a structural step must not edit, ON TOP of every enum class discovered automatically.
#: WHY THE ENUM HALF IS AUTOMATIC (adversarial review of the previous revision): the tuple below is hand-written,
#: and `ToolRunStatus` - six members whose strings are persisted and SQL-compared in `service.py` - was simply not
#: in it, so editing `TIMED_OUT` to another value produced "no behaviour-surface change". A hand-written list
#: cannot stay complete, so EVERY `Enum`/`StrEnum`/`IntEnum` subclass in the package is recorded, and this tuple
#: adds the module-level frozensets that are not enum classes.
STATE_SYMBOLS: tuple[str, ...] = (
    "PLACEHOLDER_STATUSES",
    "TaskLifecycle",
    "ClaimStatus",
    "ActionType",
    "InvestigationThreadState",
    "TERMINAL_STATES",
    "LEDGER_TERMINAL",
    "LEDGER_ACTIVE",
    "_POLICY_OR_PLACEHOLDER_STATUSES",
    "CERTIFIED_PROFILES",
    "_BEHAVIOR_STATUS_VALUES",
    "_BEHAVIOR_SEVERITY_VALUES",
    "_IN_FLIGHT_TASK_LIFECYCLES",
    "_FRONTIER_CLOSED_STATUSES",
    "_NON_WORKER_STOP_REASONS",
    "_UNRESOLVED_STATUSES",
    "_PLAN_COMPLETED_STATUSES",
    "_PLAN_BLOCKED_STATUSES",
    "PERSIST_KEEP_ACTION_TYPES",
    "HOW_SEED_CATEGORIES",
    "SUPPORTING_SKIP_CATEGORIES",
    "NO_NEW_EVIDENCE_CATEGORIES",
    "INDEXED_EVIDENCE_KINDS",
    "STATIC_TOOL_ALLOWLIST",
    "SUPPORTED_MODEL_FAMILIES",
    "SPECIALIST_STATIC_TOOLS",
    "_REQUIRED_CHILD_TYPES",
)

#: Every surface that must be present in the result. MEASURED hole this closes (adversarial review): deleting a
#: line from `compute_surfaces()` removed that surface from the comparison entirely, because the comparison walked
#: the CURRENT keys only - so a structure step could stop measuring `budget_constants` and still be told
#: "no behaviour-surface change".
REQUIRED_SURFACES: tuple[str, ...] = (
    "report_schema",
    "validator_thresholds",
    "state_enums",
    "prompt_semantics",
    "budget_constants",
    "sample_execution_strategy",
    "threshold_comparisons",
    "compose_gate_fixture_verdicts",
    "test_getsource_count",
)

BUDGET_FIELD_PATTERN = (
    r"(?i)(max_|min_|budget|timeout|retention|_bytes|_seconds|_days|_tokens|allow_|mode|profile|environment|rounds|steps)"
)
STRATEGY_FIELD_PATTERN = r"(?i)(sample_execution|network_access|storage_access|max_cpu|max_memory|tool_execution_mode|simulation_)"


# ------------------------------------------------------------------------------------------------------------
# shared measurement
# ------------------------------------------------------------------------------------------------------------
def production_files() -> list[Path]:
    return sorted(path for path in SOURCE.rglob("*.py") if "__pycache__" not in path.parts)


def module_name(path: Path) -> str:
    relative = path.relative_to(SOURCE).with_suffix("")
    parts = [PACKAGE, *relative.parts]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8", errors="replace"))


def digests(items: object) -> str:
    payload = json.dumps(items, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------------------------------
# P1.3 rule 1 - a new reverse dependency (delegated, so there is ONE measurement of the graph)
# ------------------------------------------------------------------------------------------------------------
def reverse_dependency_check() -> tuple[bool, str]:
    command = [sys.executable, str(IMPORT_GRAPH), "--strict"]
    if SOURCE != ROOT / "src" / "threat_report_agent":
        command += ["--source", str(SOURCE)]
    done = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
    )
    tail = [line for line in (done.stdout or "").splitlines() if line.strip()][-2:]
    return done.returncode == 0, " | ".join(tail)


# ------------------------------------------------------------------------------------------------------------
# P1.3 rule 2 - a duplicate canonical implementation
# ------------------------------------------------------------------------------------------------------------
def normalised_body(node: ast.stmt) -> str:
    """Canonical text of a definition with its docstring removed, so a docstring edit is not a duplicate."""
    clone = ast.parse(ast.unparse(node)).body[0]
    body = getattr(clone, "body", [])
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            clone.body = body[1:]
    return ast.unparse(clone)


def duplicate_implementations() -> dict[str, list[str]]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for path in production_files():
        tree = parse(path)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            text = normalised_body(node)
            if len(text) < DUPLICATE_MIN_CHARS:
                continue
            groups[(node.name, hashlib.sha256(text.encode("utf-8")).hexdigest()[:16])].append(module_name(path))
    return {
        f"{name}::{body_hash}": sorted(set(modules))
        for (name, body_hash), modules in groups.items()
        if len(set(modules)) > 1
    }


# ------------------------------------------------------------------------------------------------------------
# P1.3 rule 3 - private reach by name in a production file
# ------------------------------------------------------------------------------------------------------------
def private_reach() -> dict[str, int]:
    """`getsource(<arg reaching ._x>)` and `getattr(<obj>, "_x")`, counted per module+expression.

    MEASURED FALSE POSITIVE AVOIDED: the first version flagged every `getsource(...)` call, which caught
    `simulation_adapters.py:302 inspect.getsource(handler)` - introspecting a third-party shim class's own
    method, with no private member anywhere. The rule is about reaching a PRIVATE member by name, so the argument
    must actually contain a `._` access.
    """
    found: dict[str, int] = defaultdict(int)
    for path in production_files():
        module = module_name(path)
        for node in ast.walk(parse(path)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "getsource" and node.args:
                argument = ast.unparse(node.args[0])
                if re.search(r"\._[A-Za-z]", argument):
                    found[f"{module}::getsource({argument})"] += 1
            if name == "getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                literal = node.args[1].value
                if isinstance(literal, str) and literal.startswith("_") and not literal.startswith("__"):
                    found[f"{module}::getattr({ast.unparse(node.args[0])}, {literal!r})"] += 1
    return dict(found)


# ------------------------------------------------------------------------------------------------------------
# P1.3 rule 4 - an unregistered import of an already-moved path
# ------------------------------------------------------------------------------------------------------------
def legacy_path_imports() -> list[dict[str, str]]:
    """Every import of a path that already moved, INCLUDING relative and alias forms.

    MEASURED BLIND SPOT this closes: the first version required `node.level == 0`, so `from . import dataflow` -
    a legal spelling inside the package, and the cheapest way to keep using a moved path - produced no finding at
    all. It also missed `from threat_report_agent import dataflow`, where the old name is the ALIAS rather than
    the module. Both are resolved here against the importing module's own package.
    """
    found: set[tuple[str, str]] = set()
    # The map comes from docs/import-policy.json (module `moved_paths`), so this rule and the import graph's
    # rename normalisation share ONE source; the LEGACY_PATHS constant is only a fallback.
    paths = legacy_paths()

    def resolve(node: ast.ImportFrom, module: str) -> str:
        if not node.level:
            return node.module or ""
        parts = module.split(".")
        keep = len(parts) - node.level
        base = ".".join(parts[:keep]) if keep > 0 else ""
        return f"{base}.{node.module}" if node.module else base

    for path in production_files():
        module = module_name(path)
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.ImportFrom):
                resolved = resolve(node, module)
                candidates = {resolved} | {f"{resolved}.{alias.name}" for alias in node.names}
                for old in paths:
                    if f"{PACKAGE}.{old}" in candidates:
                        found.add((old, module))
            elif isinstance(node, ast.Import):
                for old in paths:
                    if any(alias.name == f"{PACKAGE}.{old}" for alias in node.names):
                        found.add((old, module))
            elif isinstance(node, ast.Call):
                # `importlib.import_module("threat_report_agent.dataflow")`. MEASURED evasion the adversarial
                # review confirmed: the string form kept an old-path access alive without appearing in this
                # ledger (the import-graph's forbidden-edge rule DID see it, but the registered-importer list did
                # not, so the old path could stay in use unrecorded).
                func = node.func
                callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if callee in {"import_module", "__import__"} and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        for old in paths:
                            if first.value.startswith(f"{PACKAGE}.{old}"):
                                found.add((old, module))
    return [{"old": old, "new": paths[old], "importer": module} for old, module in sorted(found)]


# ------------------------------------------------------------------------------------------------------------
# P1.4 - the six behaviour surfaces, extracted by SYMBOL so a move is not a change
# ------------------------------------------------------------------------------------------------------------
def _docstring_nodes(tree: ast.Module) -> set[int]:
    """The `id()` of every docstring constant, so the report-schema scan can skip prose.

    MEASURED why: scanning ALL string constants included docstring lines that merely look like headings (the
    sample contained `## 2.`), so a docstring edit would read as a report-schema change. False failures in a gate
    that blocks commits are as damaging as false passes.
    """
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    skip.add(id(body[0].value))
    return skip


def surface_report_schema() -> dict[str, object]:
    """Every markdown heading literal in the package, sorted, DOCSTRINGS EXCLUDED. The rendered document is frozen
    byte-for-byte by `scripts/structure_behavior_probe.py` item 1; this is the move-proof half."""
    headings: set[str] = set()
    for path in production_files():
        tree = parse(path)
        skip = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if id(node) in skip:
                continue
            for line in node.value.splitlines():
                stripped = line.strip()
                # A heading is at least 8 characters and ENDS IN A WORD. MEASURED artifact this removes: the spec
                # review found `## 2.` frozen in the surface - the split delimiter in `reporting.py`'s
                # `.split("## 2.", 1)`, not a heading at all.
                if re.match(r"^#{1,3} \S", stripped) and len(stripped) >= 8 and stripped[-1].isalnum():
                    headings.add(stripped)
    return {"headings": sorted(headings), "count": len(headings)}


def _walk_top_level(tree: ast.Module) -> list[ast.stmt]:
    """Module-level statements, descending through `if`/`try` bodies.

    MEASURED GAP this closes (found by the standards review of this commit): reading only `tree.body` meant that
    wrapping a vocabulary in `if TYPE_CHECKING:` or `try: ... except ImportError:` dropped it from the surface -
    so the surface would read "no change" while the enum had disappeared. That is precisely the
    absence-read-as-clean-result failure this repository keeps producing.
    """
    out: list[ast.stmt] = []
    pending = list(tree.body)
    while pending:
        node = pending.pop(0)
        out.append(node)
        if isinstance(node, (ast.If, ast.Try)):
            pending.extend(getattr(node, "body", []))
            pending.extend(getattr(node, "orelse", []))
            for handler in getattr(node, "handlers", []):
                pending.extend(handler.body)
    return out


def _enum_classes(tree: ast.Module) -> list[ast.ClassDef]:
    """Every `Enum`/`StrEnum`/`IntEnum` subclass in a file, wherever it is defined."""
    found: list[ast.ClassDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in node.bases}
        if bases & {"Enum", "StrEnum", "IntEnum"}:
            found.append(node)
    return found


def surface_state_enums() -> dict[str, object]:
    """Every enum class in the package, plus the named module-level vocabularies, as NAME=VALUE source text.

    Keying by symbol rather than by module is the whole point: plan P1.4 requires a pure move to pass, and moving
    `status.py` into a package must not read as a change to the state vocabulary. Editing a member must.
    """
    found: dict[str, list[str]] = defaultdict(list)
    for path in production_files():
        tree = parse(path)
        for node in _enum_classes(tree):
            members: list[str] = []
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    members.append(ast.unparse(stmt))
                elif isinstance(stmt, ast.Assign) and stmt.targets and isinstance(stmt.targets[0], ast.Name):
                    members.append(ast.unparse(stmt))
            found[node.name].append(";".join(sorted(members)))
        for node in _walk_top_level(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in STATE_SYMBOLS:
                        found[target.id].append(ast.unparse(node.value))
            elif (
                isinstance(node, ast.ClassDef)
                and node.name in STATE_SYMBOLS
                and node.name not in found  # an enum class is already recorded above
            ):
                members = []
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        members.append(ast.unparse(stmt))
                    elif isinstance(stmt, ast.Assign) and stmt.targets and isinstance(stmt.targets[0], ast.Name):
                        members.append(ast.unparse(stmt))
                found[node.name].append(";".join(sorted(members)))
    return {name: sorted(set(texts)) for name, texts in sorted(found.items())}


def surface_threshold_comparisons() -> dict[str, object]:
    """Every COMPARISON whose operands mention a threshold-looking name, as source text.

    MEASURED hole this closes (adversarial review): the validator surface recorded only the CONSTANT's value, so
    changing `if len(payload) <= _PAYLOAD_STRIP_MIN_CHARS:` to `<` - a real behaviour change, and exactly the
    "change the operator rather than the threshold" evasion - left every surface identical. The comparison itself
    is the threshold's meaning, so it is recorded too.
    """
    matcher = re.compile(r"(?i)(THRESHOLD|_MIN|_MAX|TOLERANCE|_RATIO|_LIMIT|_CHARS|MIN_|MAX_)")
    found: set[str] = set()
    for path in production_files():
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.Compare) and matcher.search(ast.unparse(node)):
                found.add(ast.unparse(node))
    return {"comparisons": sorted(found), "count": len(found)}


def surface_prompt_semantics() -> dict[str, str]:
    """sha256 of every prompt and policy text file, LINE-ENDING NORMALISED. Keyed by PATH on purpose: a prompt's
    location is part of how it is loaded, so moving one is a visible change rather than a silent one.

    WHY THE NORMALISATION IS NOT OPTIONAL (measured by the standards review of this commit): the repository has no
    `.gitattributes` and `core.autocrlf=true`, so a fresh clone or a clean `git worktree` materialises these text
    files with CRLF while this working tree has LF. Hashing raw bytes therefore made the gate FAIL ON A CLEAN
    CHECKOUT - six files "changed" that nobody had touched - while passing here. A gate that only passes in the
    tree that recorded it is worse than no gate, because it looks green in exactly the case it was tested.
    """
    out: dict[str, str] = {}
    for path in sorted(SOURCE.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.parent.name in {"prompts", "policies"}:
            normalised = path.read_bytes().replace(b"\r\n", b"\n")
            out[path.relative_to(SOURCE).as_posix()] = hashlib.sha256(normalised).hexdigest()[:16]
    return out


class_field_collisions: list[str] = []


def class_field_defaults(class_name: str, pattern: str) -> dict[str, str]:
    """Annotated class fields whose DEFAULT matters, as source text. Works for a dataclass and for a pydantic
    model alike, and does not need the class to be importable - so a move cannot break it.

    A name defined by TWO classes in different modules is recorded as a collision and the value becomes a sorted
    list. MEASURED why: the first version wrote `out[name] = ...` per module, so the last module silently won and
    an edit to the LOSING definition would have been invisible.
    """
    matcher = re.compile(pattern)
    collected: dict[str, list[str]] = defaultdict(list)
    for path in production_files():
        for node in _walk_top_level(parse(path)):
            if not (isinstance(node, ast.ClassDef) and node.name == class_name):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    if matcher.search(stmt.target.id):
                        collected[stmt.target.id].append(
                            ast.unparse(stmt.value) if stmt.value is not None else "<required>"
                        )
    out: dict[str, str] = {}
    for name, values in collected.items():
        unique = sorted(set(values))
        out[name] = unique[0] if len(unique) == 1 else json.dumps(unique, ensure_ascii=False)
        if len(unique) > 1:
            class_field_collisions.append(f"{class_name}.{name} -> {unique}")
    return out


def surface_budget_constants() -> dict[str, str]:
    return class_field_defaults("Settings", BUDGET_FIELD_PATTERN)


def surface_sample_execution_strategy() -> dict[str, object]:
    """The switches that decide whether a sample may be executed and where. Plan P1.4 names this surface
    explicitly, and it is the one where an accidental change is worst."""
    return {
        "Settings": class_field_defaults("Settings", STRATEGY_FIELD_PATTERN),
        "ToolRunRequest": class_field_defaults("ToolRunRequest", STRATEGY_FIELD_PATTERN),
    }


def surface_validator_thresholds() -> dict[str, object]:
    """Constants whose NAME looks like a threshold, keyed by name with collisions kept.

    FUNCTION-LOCAL assignments are included. MEASURED gap the spec review of this commit found: reading only
    module-level statements missed nine function-local names matching this same filter, and a validator's real
    clamp is as often a local default argument or a local constant as a module constant.
    """
    matcher = re.compile(r"(?i)(THRESHOLD|_MIN_|_MAX|TOLERANCE|_RATIO|_LIMIT|MIN_CHARS|_CHARS)")
    collected: dict[str, list[str]] = defaultdict(list)
    for path in production_files():
        for node in ast.walk(parse(path)):
            targets: list[str] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
                value = node.value
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # A default argument is a threshold too (`def f(max_chars: int = 200)`), and it is invisible to a
                # body-only scan.
                for default, arg in zip(node.args.defaults, node.args.args[-len(node.args.defaults):] or []):
                    if matcher.search(arg.arg):
                        collected[arg.arg].append(ast.unparse(default))
            for name in targets:
                if matcher.search(name) and value is not None:
                    collected[name].append(ast.unparse(value))
    # Same reasoning as class_field_defaults: two modules may legitimately define the same constant name, and
    # letting the last one win would hide an edit to the other.
    return {
        name: sorted(set(values))[0] if len(set(values)) == 1
        else json.dumps(sorted(set(values)), ensure_ascii=False)
        for name, values in sorted(collected.items())
    }


def surface_test_getsource_count() -> dict[str, object]:
    """How many `getsource(...)` calls the TEST suite still makes, and how many of them reach a private member.

    RECORDED, NOT GATED, on purpose. P1.3's rule is about PRODUCTION files; plan P3.7 is the step that moves the
    test surface from private/`getsource` assertions to behavioural ones. Recording the count here makes that
    step's progress measurable instead of asserted, and makes an INCREASE visible immediately.
    """
    tests = ROOT / "tests"
    total = 0
    private = 0
    for path in sorted(tests.rglob("*.py")):
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name == "getsource":
                    total += 1
                    if node.args and re.search(r"\._[A-Za-z]", ast.unparse(node.args[0])):
                        private += 1
    return {"total": total, "reaching_a_private_member": private}


def compute_surfaces() -> dict[str, object]:
    """The six named surfaces PLUS the compose gate's verdicts on the negative fixtures.

    The fixture verdicts belong in the same file because they are the same kind of reading: `unknown_restated_as_
    verified` going from True to False means the gate was relaxed, which is exactly the P1.4 failure the plan
    names, and it must be visible in the diff rather than only in the `--fixtures` output.
    """
    surfaces: dict[str, object] = {
        "report_schema": surface_report_schema(),
        "validator_thresholds": surface_validator_thresholds(),
        "state_enums": surface_state_enums(),
        "prompt_semantics": surface_prompt_semantics(),
        "budget_constants": surface_budget_constants(),
        "sample_execution_strategy": surface_sample_execution_strategy(),
        "threshold_comparisons": surface_threshold_comparisons(),
    }
    surfaces["compose_gate_fixture_verdicts"] = {
        name: bool(item["rejected"]) for name, item in fixture_verdicts().items()
    }
    surfaces["test_getsource_count"] = surface_test_getsource_count()
    _require_every_surface(surfaces)
    return surfaces


def _require_every_surface(surfaces: dict[str, object]) -> None:
    """A missing surface is a hard error HERE, not a quietly shorter dict.

    MEASURED hole this closes: deleting one line from `compute_surfaces()` removed that surface from the
    comparison, because the comparison walked the current keys only.
    """
    missing = [name for name in REQUIRED_SURFACES if name not in surfaces]
    if missing:
        raise RuntimeError(f"compute_surfaces() omitted {missing}; every declared surface must be measured")


def compute_surfaces_resilient() -> dict[str, object]:
    """`compute_surfaces` with the one surface that IMPORTS the package made non-fatal.

    MEASURED why: the fixture verdicts need `analyst_report`, so a structural edit that breaks an import (e.g.
    renaming a class many modules import) made the whole gate CRASH - which reports as a traceback and hides the
    five surfaces that could still have been compared. The extraction failure is recorded as a value instead, so
    it becomes an ordinary CHANGED problem with a readable line.
    """
    try:
        return compute_surfaces()
    except Exception as exc:  # noqa: BLE001 - the point is to convert any import failure into a reading
        surfaces = {
            "report_schema": surface_report_schema(),
            "validator_thresholds": surface_validator_thresholds(),
            "state_enums": surface_state_enums(),
            "prompt_semantics": surface_prompt_semantics(),
            "budget_constants": surface_budget_constants(),
            "sample_execution_strategy": surface_sample_execution_strategy(),
            "threshold_comparisons": surface_threshold_comparisons(),
            "test_getsource_count": surface_test_getsource_count(),
        }
        surfaces["compose_gate_fixture_verdicts"] = {
            "extraction_failed": f"{type(exc).__name__}: {str(exc)[:200]}"
        }
        _require_every_surface(surfaces)
        return surfaces


# ------------------------------------------------------------------------------------------------------------
# P1.4 - the negative fixtures, run against the real compose gate
# ------------------------------------------------------------------------------------------------------------
def _gate():
    """Import the compose gate from the CURRENT SOURCE ROOT, so `--fixtures --source <copy>` measures the copy.

    This is what makes the "someone relaxed the compose gate" fixture a real can-fail test rather than a
    restatement: the harness relaxes the gate inside a copy and requires this script to notice.
    """
    if str(SOURCE.parent) not in sys.path:
        sys.path.insert(0, str(SOURCE.parent))
    from threat_report_agent.analyst_report import (
        OPERATIONAL_LIMITATIONS_HEADING,
        compose_gate_violations,
    )

    return OPERATIONAL_LIMITATIONS_HEADING, compose_gate_violations


def fixture_verdicts() -> dict[str, object]:
    """Each required fixture returns whether the gate REJECTED it. A fixture that passes clean is the failure.

    EACH FIXTURE MUST TRIP EXACTLY ONE CHECK, or it cannot detect the relaxation it exists for. MEASURED first
    version's flaw: the upgrade draft omitted the operational block as well, so it was rejected by the LIMITATION
    check - relaxing the upgrade check alone would still have looked "rejected". The drafts below therefore carry
    the limitation block wherever they are not the limitation fixture.
    """
    heading, gate = _gate()
    block = f"{heading}\n\n- [pipeline] Tool run x ended TIMED_OUT: T.\n"
    header = "# 静态分析报告\n\n## 分析结论\n\nClaim c1 状态 UNKNOWN(join)。\n"
    fragments = f"{header}\n{block}"
    with_block = f"{header}\n{block}"
    without_block = header

    upgrade_draft = with_block.replace("UNKNOWN(join)", "verified 已执行")
    upgrade_violations = gate(upgrade_draft, fragments)
    limitations_violations = gate(without_block, fragments)
    # A DOMAIN, not a bare IPv4, and no image filename: the endpoint check must be the ONLY check that can fire.
    # MEASURED why: with `http://203.0.113.9/payload.bin` the IPv4 check also rejected the draft, so removing the
    # URL check alone left the fixture still "rejected" - the can-fail harness reported exactly that.
    relaxed_draft = with_block + "\n端点 http://cdn.example.com/payload.bin\n"
    relaxed_violations = gate(relaxed_draft, fragments)
    # The plan's NARROWER case, which P0.5-r2 measured as NOT rejected. RECORDED, never asserted.
    narrow_draft = f"{without_block}\n{heading}\n"
    narrow_violations = gate(narrow_draft, fragments)

    return {
        "unknown_restated_as_verified": {
            "required": "REJECTED",
            "violations": upgrade_violations,
            "rejected": any("upgraded candidate/unknown" in item for item in upgrade_violations),
        },
        "limitation_block_deleted": {
            "required": "REJECTED",
            "violations": limitations_violations,
            "rejected": any("omits the pipeline's operational limitations" in item for item in limitations_violations),
        },
        "compose_gate_relaxed_unprovenanced_endpoint": {
            "required": "REJECTED",
            "violations": relaxed_violations,
            "rejected": any("endpoint not in composed fragments" in item for item in relaxed_violations),
        },
        "narrow_case_heading_kept_bullets_dropped": {
            "required": "RECORDED (measured NOT rejected today; P0.5-r2 known_behavior_gap)",
            "violations": narrow_violations,
            "rejected": any("omits the pipeline's operational limitations" in item for item in narrow_violations),
        },
    }


# ------------------------------------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------------------------------------
def structure_findings() -> tuple[list[str], dict[str, object], list[str]]:
    """Returns (blocking problems, detail, stale-allowlist notes).

    A STALE ENTRY IS NOT A FAILURE. MEASURED why this distinction matters: the first version compared the private
    reach count for exact equality, so DELETING one of the two recorded occurrences - an improvement, and the
    direction every later step moves in - would have failed the gate. The gate must block regressions (a new
    expression, or the same expression appearing MORE times), and merely REPORT that the allowlist has become
    stale, so the record is updated deliberately instead of the rule being loosened.
    """
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8")) if POLICY_PATH.is_file() else {}
    problems: list[str] = []
    stale: list[str] = []

    ok, detail = reverse_dependency_check()
    if not ok:
        problems.append(f"new reverse dependency: {detail}")

    known_duplicates = {
        (str(item["name"]), str(item.get("body_sha256", "")), tuple(sorted(item["modules"])))
        for item in policy.get("known_duplicate_implementations", [])
    }
    duplicates = duplicate_implementations()
    new_duplicates = [
        key for key, modules in duplicates.items()
        if (key.split("::")[0], key.split("::")[1], tuple(modules)) not in known_duplicates
    ]
    problems.extend(f"duplicate canonical implementation: {key} in {duplicates[key]}" for key in new_duplicates)
    # The recorded BODY HASH is gated too, not only the module pair. MEASURED gap the standards review found: with
    # only (name, modules) recorded, both copies could be rewritten identically - or one of them changed so the
    # pair stopped being measured at all - and the entry silently stopped meaning anything. A stale entry is
    # REPORTED (never a failure): removing a duplication is an improvement, and the record is then updated
    # deliberately.
    for name, body_hash, modules in sorted(known_duplicates):
        measured = {key for key in duplicates if key.startswith(f"{name}::")}
        if not measured:
            problems.append(
                f"duplicate record {name} [{body_hash}] is no longer measured; delete it deliberately"
            )
        elif f"{name}::{body_hash}" not in measured:
            problems.append(
                f"duplicate record {name} [{body_hash}] no longer matches: the tree now has {sorted(measured)}; "
                "the record must match exactly or be updated deliberately"
            )

    known_reach = {
        (str(item["module"]), str(item["expr"])): int(item.get("count", 1))
        for item in policy.get("known_private_reach", [])
    }
    reach = private_reach()
    new_reach: list[str] = []
    for key, count in reach.items():
        module, _, expr = key.partition("::")
        recorded = known_reach.get((module, expr))
        if recorded is None:
            new_reach.append(key)
        elif count != recorded:
            # EXACT, not `count > recorded`. MEASURED evasion the adversarial review confirmed: with `>` as the
            # guard, pre-registering the SAME expression with a huge count (`999999`) pre-approved unlimited
            # occurrences and the gate returned 0 with only a non-failing note. An allowlist that the policed step
            # can widen in its own commit is not an allowlist. A decrease is also a mismatch, and updating the
            # record for it is one deliberate line in the same commit.
            new_reach.append(f"{key} (recorded {recorded}, tree has {count}; the record must match exactly)")
    problems.extend(f"private reach in a production file: {key}" for key in new_reach)
    for (module, expr), recorded in known_reach.items():
        if not any(key.startswith(f"{module}::{expr}") for key in reach):
            problems.append(
                f"private reach record {module}::{expr} no longer exists (was {recorded}); delete it deliberately"
            )

    known_legacy = {
        (str(item["old"]), str(item["importer"])) for item in policy.get("legacy_path_imports", [])
    }
    legacy = legacy_path_imports()
    new_legacy = [item for item in legacy if (item["old"], item["importer"]) not in known_legacy]
    problems.extend(
        f"unregistered import of a moved path: {item['importer']} still imports {item['old']} "
        f"(canonical is {item['new']})"
        for item in new_legacy
    )
    current_legacy = {(item["old"], item["importer"]) for item in legacy}
    for old, importer in sorted(known_legacy - current_legacy):
        stale.append(f"legacy-import record {importer} -> {old} is no longer in the tree")

    return problems, {
        "reverse_dependency_ok": ok,
        "reverse_dependency_detail": detail,
        "duplicates_total": len(duplicates),
        "duplicates_new": new_duplicates,
        "private_reach_total": len(reach),
        "private_reach_new": new_reach,
        "legacy_imports_total": len(legacy),
        "legacy_imports_new": [f"{item['importer']}->{item['old']}" for item in new_legacy],
    }, stale


def surface_findings() -> tuple[list[str], dict[str, object]]:
    current = compute_surfaces_resilient()
    problems: list[str] = []
    # PRESENCE IS PART OF THE CONTRACT. Equality alone is not enough: if a vocabulary stops being extracted, the
    # surface silently SHRINKS and a reader sees "no change" for the one thing P1.4 exists to protect. Reviewing
    # this commit found exactly that hole (a symbol wrapped in `try:` or `if TYPE_CHECKING:` disappeared).
    missing_symbols = [name for name in STATE_SYMBOLS if name not in current.get("state_enums", {})]
    if missing_symbols:
        problems.append(
            f"state_enums no longer extracts {missing_symbols}; an absent vocabulary must never read as unchanged"
        )
    if not current.get("prompt_semantics"):
        problems.append("prompt_semantics extracted nothing, so a prompt edit could not be seen")
    if not current.get("report_schema", {}).get("headings"):
        # MEASURED hole in the first guard: it tested `not value`, and `{"headings": [], "count": 0}` is a
        # non-empty dict - so a filter that removed EVERY heading would have been recorded as a healthy surface.
        problems.append("report_schema extracted no headings, so the report schema is not being measured")
    if not SURFACE_PATH.is_file():
        return ["no docs/structure-surface.json; run --record-surface deliberately"], current
    recorded = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
    problems: list[str] = []
    # THE KEY SET IS PART OF THE COMPARISON. MEASURED hole this closes: iterating the CURRENT keys only meant a
    # surface that was deleted from `compute_surfaces()` was never compared at all - a structural step could stop
    # measuring `budget_constants` and still be told "no behaviour-surface change".
    for name in sorted(set(recorded) - set(current)):
        problems.append(f"surface {name} is recorded but no longer measured - a dropped surface is a regression")
    for name in sorted(set(current) - set(recorded)):
        problems.append(f"surface {name} is measured but not recorded")
    for name, value in sorted(current.items()):
        if name not in recorded:
            problems.append(f"surface {name} is not recorded")
        elif json.dumps(recorded[name], sort_keys=True, ensure_ascii=False) != json.dumps(
            value, sort_keys=True, ensure_ascii=False
        ):
            before = recorded[name]
            if isinstance(value, dict) and isinstance(before, dict):
                changed = sorted(
                    key for key in set(value) | set(before)
                    if json.dumps(before.get(key), sort_keys=True, ensure_ascii=False)
                    != json.dumps(value.get(key), sort_keys=True, ensure_ascii=False)
                )
                problems.append(
                    f"surface {name} CHANGED in {len(changed)} place(s): {', '.join(changed[:6])}"
                )
            else:
                problems.append(f"surface {name} CHANGED")
    return problems, current


def print_surface(current: dict[str, object]) -> None:
    for name, value in sorted(current.items()):
        size = len(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str))
        entries = len(value) if isinstance(value, dict) else "-"
        print(f"  {name:28} entries={entries:>4}  digest={digests(value)[:16]}  json={size}B")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--structure", action="store_true")
    parser.add_argument("--surface", action="store_true")
    parser.add_argument("--fixtures", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--record-surface", action="store_true")
    parser.add_argument("--source", default="", help="extract from another copy of the package (can-fail harness)")
    args = parser.parse_args()
    if args.source:
        set_source(args.source)
    if not any((args.structure, args.surface, args.fixtures, args.all, args.record_surface)):
        args.all = True

    problems: list[str] = []

    if args.structure or args.all:
        found, detail, stale = structure_findings()
        print("P1.3 STRUCTURE")
        for key, value in detail.items():
            print(f"  {key:28} {value}")
        for item in stale:
            print(f"  [stale record, not a failure] {item}")
        problems.extend(found)

    if args.record_surface:
        current = compute_surfaces_resilient()
        empty = [
            name for name, value in current.items()
            if not value and name != "compose_gate_fixture_verdicts"
        ]
        if not current.get("report_schema", {}).get("headings"):
            empty.append("report_schema (no headings extracted)")
        if any(isinstance(value, dict) and "extraction_failed" in value for value in current.values()):
            empty.append("compose_gate_fixture_verdicts (the compose gate could not be imported)")
        if empty:
            # A surface that extracted NOTHING must not be recorded as "no change": that is the failure mode this
            # repository keeps producing (absence read as a clean result). MEASURED: renaming `Settings`, or
            # emptying STATE_SYMBOLS, would otherwise have frozen an empty surface silently.
            print(f"\nREFUSING to record: these surfaces extracted nothing: {empty}")
            print("An empty surface cannot detect the change it exists for. Fix the extraction first.")
            return 2
        SURFACE_PATH.write_text(
            json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"\nrecorded surfaces -> {SURFACE_PATH.relative_to(ROOT)}")
        print_surface(current)
        if class_field_collisions:
            for item in sorted(set(class_field_collisions)):
                print(f"  [note] field name defined by two classes with different defaults: {item}")
        return 0

    if args.surface or args.all:
        found, current = surface_findings()
        print("\nP1.4 BEHAVIOUR SURFACES (static, keyed by symbol so a move passes)")
        print_surface(current)
        problems.extend(found)

    if args.fixtures or args.all:
        print("\nP1.4 NEGATIVE FIXTURES (must be rejected)")
        verdicts = fixture_verdicts()
        for name, item in verdicts.items():
            required = item["required"]
            rejected = bool(item["rejected"])
            if required == "REJECTED":
                mark = "REJECTED" if rejected else "ACCEPTED -> GATE IS TOO PERMISSIVE"
                if not rejected:
                    problems.append(f"fixture {name} was ACCEPTED but must be rejected")
            else:
                mark = "REJECTED" if rejected else "accepted (recorded gap)"
            print(f"  {name:48} {mark}")
            print(f"  {'':48} violations: {json.dumps(item['violations'], ensure_ascii=False)[:150]}")
        # The verdicts are also part of the recorded surface, so a relaxation is a visible DIFF and not only a
        # line of output nobody re-reads.
        if SURFACE_PATH.is_file() and not (args.surface or args.all):
            recorded = json.loads(SURFACE_PATH.read_text(encoding="utf-8"))
            now = {name: bool(item["rejected"]) for name, item in verdicts.items()}
            if recorded.get("compose_gate_fixture_verdicts") != now:
                problems.append(
                    "the compose gate's verdicts on the negative fixtures differ from the recorded readings: "
                    f"recorded={recorded.get('compose_gate_fixture_verdicts')} now={now}"
                )

    if problems:
        print(f"\n{len(problems)} STRUCTURE/SURFACE PROBLEM(S):")
        for item in problems:
            print(f"  - {item}")
        if args.strict:
            print("\nSTRICT: structure diff gate failed")
            return 1
        print("\n(not strict: report only)")
        return 0
    print("\nSTRUCTURE DIFF: no new structural violation, no behaviour-surface change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
