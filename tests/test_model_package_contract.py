"""P2-M contract: the model package (plan section 7.4).

Scope moved, one module at a time with a root `sys.modules` shim left behind: `model_gateway.py`, `agents.py`,
`agent_runtime.py`, `prompts.py` -> `threat_report_agent/model/`.

The plan's success criterion for this step is a BOUNDARY, not a mechanism: the model package may only return
structured planning/action proposals, and must not reach the investigation graph, the Case scope, the budget or
tool permissions. That boundary is pinned here by reading the package's actual imports, and the frozen provider
routing surface is pinned by value.

MEASURED REGRESSION THIS FILE ALSO PINS (found while verifying P2-M, and the reason for the last test here):
`tests/test_reason_control_note.py` read `src/threat_report_agent/model_gateway.py` BY PATH. After the move that
path is a five-line compatibility shim, so three assertions silently started reading shim text and failed with
"the note is not initialised at all" - a message that accuses the implementation while the real fault is the
reading method. The test was repaired to resolve through the import system, and the last test below generalises
the check so a future move cannot reintroduce it anywhere in `tests/`.

    python -m pytest -q tests/test_model_package_contract.py
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "threat_report_agent"

#: module -> symbols whose IDENTITY must be the same through both paths, read from the modules themselves.
MOVED = {
    "prompts": ("PromptRegistry", "PromptDefinition"),
    "agent_runtime": ("AgentRuntime", "AgentEvent"),
    "agents": ("TriageAgent", "StaticAnalysisAgent"),
    "model_gateway": ("ModelGateway", "supported_provider_contracts", "provider_contract"),
}

#: The boundary from plan 7.4: none of these may be imported BY the model package.
FORBIDDEN_IN_MODEL = (
    "threat_report_agent.service",
    "threat_report_agent.investigation",
    "threat_report_agent.report.reporting",
    "threat_report_agent.tools.tool_execution",
    "threat_report_agent.tool_authoring",
)


def load_gate_module():
    spec = importlib.util.spec_from_file_location(
        "check_structure_diff_for_model_tests",
        REPO / "scripts" / "check-structure-diff.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_each_moved_module_is_one_object_behind_two_paths() -> None:
    for name, symbols in MOVED.items():
        old = importlib.import_module(f"threat_report_agent.{name}")
        new = importlib.import_module(f"threat_report_agent.model.{name}")
        assert old is new, f"{name}: the shim did not rebind sys.modules, so there are two module objects"
        assert old.__file__ == new.__file__
        for symbol in symbols:
            assert hasattr(new, symbol), f"{name} no longer defines {symbol}; the contract test is stale"
            assert getattr(old, symbol) is getattr(new, symbol), f"{name}.{symbol} is not the same object"


def test_the_old_paths_are_shims_and_not_second_implementations() -> None:
    for name in MOVED:
        shim = PACKAGE / f"{name}.py"
        assert shim.is_file(), f"{name}.py is gone; the shim must stay until P4"
        source = shim.read_text(encoding="utf-8", errors="replace")
        assert len(source.encode("utf-8")) < 1500, f"{name}.py grew beyond a shim"
        definitions = [
            node.name
            for node in ast.parse(source).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        assert not definitions, f"{name}.py defines {definitions}; that would be a second implementation"
        assert "sys.modules[__name__] = _real" in source


def test_the_model_package_re_exports_nothing() -> None:
    source = (PACKAGE / "model" / "__init__.py").read_text(encoding="utf-8", errors="replace")
    imported = [
        node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))
    ]
    assert not imported, f"model/__init__.py imports {[ast.unparse(node) for node in imported]}"
    assert "__all__: tuple[str, ...] = ()" in source


def test_no_production_module_imports_a_moved_model_module_by_its_old_path() -> None:
    gate = load_gate_module()
    offenders = [item for item in gate.legacy_path_imports() if item["old"] in MOVED]
    assert not offenders, (
        f"production modules still import a moved model module by its old path: {offenders}; the canonical path "
        "is threat_report_agent.model.<module>"
    )


def test_the_model_package_does_not_reach_the_investigation_graph() -> None:
    """Plan 7.4's success criterion, read from the package's own imports rather than from documentation."""
    offenders: dict[str, list[str]] = {}
    for path in sorted((PACKAGE / "model").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module)
            elif isinstance(node, ast.Import):
                found.update(alias.name for alias in node.names)
        hits = sorted(m for m in found if m in FORBIDDEN_IN_MODEL)
        if hits:
            offenders[path.name] = hits
    assert not offenders, (
        f"the model package imports modules the plan's boundary forbids: {offenders}; plan 7.4 allows structured "
        "planning/action proposals only, so reaching the service/investigation layer here is a design change, "
        "not a structural move"
    )


def test_the_frozen_provider_routing_surface_is_unchanged() -> None:
    """Plan 7.4 lists provider routing and prompt semantics as must-not-change; pinned by value."""
    gateway = importlib.import_module("threat_report_agent.model.model_gateway")
    assert sorted(gateway.supported_provider_contracts()) == ["claude", "glm", "gpt", "kimi", "qwen"]
    settings = importlib.import_module("threat_report_agent.config").ModelProviderSettings(
        provider="custom", model="deepseek-flash", base_url="https://api.deepseek.com", api_key="k"
    )
    assert gateway.provider_contract(settings) == {
        "family": "custom",
        "protocol": "openai-chat-completions-v1",
        "endpoint_path": "/chat/completions",
        "auth_header": "Authorization",
        "default_base_url": "",
        "structured_output": "json_object",
    }


def test_the_prompts_module_still_wins_over_the_prompts_data_directory() -> None:
    """The package root keeps a `prompts/` DATA directory; the moved module must still be what `prompts` means."""
    module = importlib.import_module("threat_report_agent.prompts")
    assert Path(module.__file__).parent.name == "model", (
        f"threat_report_agent.prompts resolved to {module.__file__}; the data directory is shadowing the module"
    )
    assert not hasattr(module, "__path__"), "the data directory turned into a namespace package"


def test_no_test_reads_a_compatibility_shim_as_the_implementation() -> None:
    """The P2-M regression, generalised: a shim's text is never the implementation.

    Resolution rule, stated so its limits are visible: for every `X.read_text(...)` call in `tests/`, the string
    constants in the receiver are treated as path segments (each constant ending in `.py`, and all of them joined
    with `/`). A candidate that resolves from the repository root to an EXISTING file containing the shim marker
    is an offender, because the assertions around it would be checking shim text. Constants built at runtime are
    not resolvable and are therefore not covered - the rule catches the literal-path style this repository uses.
    """
    offenders: list[str] = []
    for test_path in sorted((REPO / "tests").glob("*.py")):
        tree = ast.parse(test_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "read_text":
                continue
            constants = [
                inner.value
                for inner in ast.walk(node.func.value)
                if isinstance(inner, ast.Constant) and isinstance(inner.value, str)
            ]
            candidates = {c for c in constants if c.endswith(".py")}
            if constants:
                candidates.add("/".join(constants))
            for candidate in candidates:
                resolved = REPO / candidate
                if not resolved.is_file():
                    continue
                text = resolved.read_text(encoding="utf-8", errors="replace")
                if "Compatibility shim" in text:
                    offenders.append(f"{test_path.name}: reads the shim {candidate} as if it were the module")
    assert not offenders, (
        f"{offenders}; resolve the module through the import system instead - e.g. "
        "`Path(importlib.import_module(name).__file__).read_text(...)` - so the check follows the module "
        "wherever the plan moves it"
    )
