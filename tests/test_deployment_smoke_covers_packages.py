"""The deployment gate's import-smoke list must not be hand-maintained.

WHY THIS TEST EXISTS (P2-M, round 79): `scripts/check-deployed-code-hashes.py` documents that its smoke list is
"ENUMERATED from disk exactly like the manifest", but only the modules INSIDE a package were enumerated - the
package list itself was a hand-written tuple of six names. `model/` was moved into place by plan step P2-M and was
NOT added to that tuple, so `--strict --import-smoke` would have printed `import smoke OK` for all eight services
while never importing one model module. A gate that reports success over an uncovered area is worse than no gate,
because it is read as evidence.

The package list is now derived. This test recomputes the rule INDEPENDENTLY of the function under test (a test
that calls the implementation to derive the expectation proves nothing), and it pins the measured set so a rule
that silently collapses to an empty tuple fails here instead of passing everywhere.

    python -m pytest -q tests/test_deployment_smoke_covers_packages.py
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "src" / "threat_report_agent"

#: The packages that existed, measured on disk, when this test was written. Present so the derived set cannot
#: become quietly empty; the equality check below is what actually keeps the list honest.
MEASURED = ("emulation", "facts", "intake", "investigation", "model", "report", "static")

#: Data directories that must NOT be smoked as packages: they have no `__init__.py`, so `import
#: threat_report_agent.<name>` would either fail or invent a namespace package.
DATA_DIRS = ("assets", "ghidra_scripts", "knowledge", "policies", "prompts")


def load_gate():
    spec = importlib.util.spec_from_file_location(
        "check_deployed_code_hashes_for_smoke_test",
        REPO / "scripts" / "check-deployed-code-hashes.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def expected_packages() -> tuple[str, ...]:
    """The rule, recomputed here: `__init__.py` plus at least one other module."""
    found = []
    for directory in sorted(SOURCE.iterdir()):
        if not directory.is_dir() or directory.name == "__pycache__":
            continue
        if not (directory / "__init__.py").is_file():
            continue
        if not any(p.name != "__init__.py" for p in directory.glob("*.py")):
            continue
        found.append(directory.name)
    return tuple(found)


def test_the_smoke_list_is_every_on_disk_package() -> None:
    gate = load_gate()
    assert tuple(gate.SMOKE_PACKAGES) == expected_packages(), (
        "SMOKE_PACKAGES has drifted from the packages on disk; the import-smoke result would claim coverage it "
        f"does not have. gate={tuple(gate.SMOKE_PACKAGES)} disk={expected_packages()}"
    )


def test_the_measured_packages_are_all_covered() -> None:
    gate = load_gate()
    missing = [name for name in MEASURED if name not in gate.SMOKE_PACKAGES]
    assert not missing, f"the import smoke does not cover {missing}; those packages exist on disk"


def test_data_directories_are_not_smoked_as_packages() -> None:
    gate = load_gate()
    wrong = [name for name in DATA_DIRS if name in gate.SMOKE_PACKAGES]
    assert not wrong, (
        f"{wrong} are data directories without an `__init__.py`; smoking them would test a namespace package "
        "rather than production code"
    )


def test_every_moved_module_is_named_in_the_smoke_set() -> None:
    """The modules P2-M moved must be import-smoked by name, not merely their package."""
    gate = load_gate()
    smoked = set(gate.smoke_modules())
    for name in ("model_gateway", "agents", "agent_runtime", "prompts"):
        dotted = f"threat_report_agent.model.{name}"
        assert dotted in smoked, f"{dotted} is not in the import-smoke set"
    assert "threat_report_agent.facts" in smoked
