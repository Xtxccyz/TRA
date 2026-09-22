"""Focused coverage for the static abstract-execution record guard.

The guard exists so a crafted or degenerate image cannot make the walk
unbounded; it is deliberately *not* an analysis quota.  The Ghidra exporter
stops one function at 10_000 instruction rows (ExportStaticFacts.java) and only
call-typed references add records, so ``DEFAULT_MAX_STEPS`` is far above
anything the pipeline can deliver and no real function is truncated.
"""

from __future__ import annotations

from dataclasses import replace
import inspect

import pytest

from threat_report_agent.config import Settings
from threat_report_agent.service import AnalysisService
from threat_report_agent.static_simulation import (
    DEFAULT_MAX_STEPS,
    StaticAbstractExecutor,
    simulation_evidence_from_function,
)

# The budget that produced the proven defect: 37 of 96 analysed functions in
# task 2fcc0fdc-ae32-4efd-83e6-a6c9fbc734db stopped at exactly this many steps
# and recorded "instruction budget exhausted after 128 records".
OLD_CAP = 128
# Worst case the current exporter can deliver for one function: 10_000
# instruction rows plus at most one call-typed reference per call instruction.
EXPORTER_CEILING = 20_000


def _function(*, instructions: int, calls: int = 0) -> dict[str, object]:
    instruction_rows = [
        {
            "address": f"0x{0x140001000 + index * 4:x}",
            "mnemonic": "MOV",
            "text": "MOV RCX, 0x1000",
        }
        for index in range(instructions)
    ]
    call_rows = [
        {
            "from": f"0x{0x140002000 + index * 4:x}",
            "to": "0x140003000",
            "type": "UNCONDITIONAL_CALL",
            "target_name": "VirtualAlloc",
        }
        for index in range(calls)
    ]
    return {
        "name": "FUN_large",
        "entry": "0x140001000",
        "instructions": instruction_rows,
        "references_from": call_rows,
    }


@pytest.mark.parametrize("records", [200, 4_481])
def test_trace_is_no_longer_truncated_at_the_old_cap(records: int) -> None:
    """The default guard analyses a whole function, not the first 128 records."""
    result = StaticAbstractExecutor().analyze(_function(instructions=records))

    assert len(result.steps) == records
    assert len(result.steps) > OLD_CAP
    assert not any("instruction budget exhausted" in item for item in result.unknowns)


def test_default_budget_is_a_guard_above_the_exporter_ceiling() -> None:
    assert DEFAULT_MAX_STEPS > EXPORTER_CEILING
    assert StaticAbstractExecutor().max_steps == DEFAULT_MAX_STEPS


def test_configured_budget_drives_the_default_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """STATIC_ABSTRACT_EXECUTION_MAX_STEPS is honoured, not just declared."""
    monkeypatch.setenv("STATIC_ABSTRACT_EXECUTION_MAX_STEPS", "37")

    assert Settings.from_environment().static_abstract_execution_max_steps == 37

    value = simulation_evidence_from_function(_function(instructions=64))

    assert len(value["steps"]) == 37
    assert any("budget" in item for item in value["unknowns"])


def test_explicit_small_budget_still_stops_the_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STATIC_ABSTRACT_EXECUTION_MAX_STEPS", raising=False)

    result = StaticAbstractExecutor(max_steps=5).analyze(_function(instructions=64))
    value = simulation_evidence_from_function(_function(instructions=64), max_steps=5)

    assert len(result.steps) == 5
    assert any("budget" in item for item in result.unknowns)
    assert len(value["steps"]) == 5
    assert any("budget" in item for item in value["unknowns"])


def test_setting_validation_stays_generous(test_settings: Settings) -> None:
    assert test_settings.static_abstract_execution_max_steps == DEFAULT_MAX_STEPS
    # A small explicit value stays legal, so the clamp is not a 4..128 window.
    assert (
        replace(test_settings, static_abstract_execution_max_steps=4)
        .static_abstract_execution_max_steps
        == 4
    )
    for invalid in (0, -1, 1_000_001):
        with pytest.raises(ValueError):
            replace(test_settings, static_abstract_execution_max_steps=invalid)


def test_pcode_slice_is_not_pinned_at_128_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    """The compact slice follows the same budget instead of a second 128 cap."""
    monkeypatch.delenv("STATIC_ABSTRACT_EXECUTION_MAX_STEPS", raising=False)
    function = _function(instructions=300)
    function["pcode_ops"] = [
        {
            "address": f"0x{0x140004000 + index * 4:x}",
            "opcode": "INT_ADD",
            "operation": "INT_ADD",
            "output": "unique",
            "inputs": [],
        }
        for index in range(300)
    ]

    derived = simulation_evidence_from_function(function)["pcode_slice"]
    assert derived["representation"] == "ghidra_native_pcode"
    assert len(derived["operations"]) == 300
    assert derived["bounded"] is False

    del function["pcode_ops"]
    instruction_derived = simulation_evidence_from_function(function)["pcode_slice"]
    assert instruction_derived["representation"] == "instruction_derived"
    assert len(instruction_derived["operations"]) == 300
    assert instruction_derived["bounded"] is False


def test_live_service_call_sites_use_the_setting() -> None:
    """Regression guard for the three live call sites named in the defect."""
    for method in (
        AnalysisService._derive_investigation_observations,
        AnalysisService._record_ghidra_evidence,
    ):
        source = inspect.getsource(method)
        assert "StaticAbstractExecutor(max_steps=128)" not in source
        assert "static_abstract_execution_max_steps" in source
