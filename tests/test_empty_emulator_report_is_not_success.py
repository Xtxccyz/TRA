"""An empty Speakeasy report is an EMULATOR FAULT, never a completed run.

MEASURED defect this pins (adversarial defect audit, finding 1). `_speakeasy_stop` fell through to
`return "SUCCEEDED", "END_ADDRESS", ""` whenever the report had no usable entry, and Speakeasy produces such a
report when it crashes inside its own unmapped-memory handler (the `get_peb_ldr` AttributeError on `None` that
`ctypes` prints and swallows). The result was then published as:

    - simulator=speakeasy status=**SUCCEEDED** stop=END_ADDRESS entry=
      overall=**SUCCEEDED** attempted=True   emulator=OVERALL_SUCCEEDED

with `nature=EMULATION_OBSERVED` and `limitations=[]`, while the observations held only
`{"event": "summary", "api_count": 0, "elapsed_ms": 70}` - nothing was observed at all. Evidence rows
`d8482e84-307a-40db-bf01-24484dd3e4df` and `5658b631-f652-4b9a-91fe-337e35e57eae` (task `87da6bd0-12fc-40ca-8d86-a7b0665d559e`).

The damage is not only the false label. `is_real_simulation_value` reads that status, so the CONTROLLED_EMULATE
gate was told "a real simulation landed" and the retry that would have recovered real evidence was suppressed:
absence converted into a clean result, and it cost the evidence that would have replaced it (EC-1).

A sibling test pins SUCCEEDED for a NON-empty report; `entry == []` had no test at all.

FAILS BEFORE THE FIX: `_speakeasy_stop([])` returned `("SUCCEEDED", "END_ADDRESS", "")`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.simulation_adapters import _speakeasy_stop  # noqa: E402


def test_an_empty_report_is_a_failure_not_a_success() -> None:
    status, stop_reason, _detail = _speakeasy_stop([], instruction_budget=64)
    assert status == "FAILED", (
        f"an emulator fault was published as a completed run (status={status!r}, stop={stop_reason!r}); "
        "nothing was observed, so absence must not become a clean result"
    )
    assert stop_reason == "EMULATOR_NO_REPORT", (
        f"the stop reason must name the emulator fault, not a normal end of run: {stop_reason!r}"
    )


def test_a_report_with_a_completed_entry_is_still_a_success() -> None:
    """NEGATIVE CONTROL: the fix must not turn every run into a failure."""
    status, stop_reason, _detail = _speakeasy_stop(
        [{"ret_val": 0, "instr_count": 3, "api_name": "kernel32.CreateFileW"}],
        instruction_budget=64,
    )
    assert status == "SUCCEEDED", f"a normal completed run regressed to {status!r}/{stop_reason!r}"


def test_an_error_report_still_wins_over_emptiness() -> None:
    """A report carrying a real error keeps its own diagnosis rather than the generic one."""
    status, stop_reason, detail = _speakeasy_stop(
        [{"error": {"type": "unsupported_api", "api_name": "MSVBVM60.ordinal_648"}}],
        instruction_budget=64,
    )
    assert (status, stop_reason) == ("FAILED", "EXECUTION_ERROR")
    assert "MSVBVM60.ordinal_648" in detail, "the blocking symbol must still be published"
