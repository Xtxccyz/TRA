"""The full-PE emulator must actually be reachable, not just configured.

MEASURED DEFECT. `SIMULATION_ALLOWED_SIMULATORS` is `('unicorn','speakeasy','qiling')` and
`"speakeasy" in policy.allowed_simulators` is **True** in the API, so `_run_controlled_emulator`
computes `speakeasy = True`. It is then discarded:

    granted_windows = unicorn_granted_windows_for_worker(
        controlled_emulation_windows(..., allow_speakeasy=False, ...)   # <- built WITHOUT speakeasy
    )
    parameters = {..., "allow_speakeasy": False if granted_windows else speakeasy}

`granted_windows` is never empty for a real PE - Unicorn always gets at least the PE-entry window
(`test_windows_grant_pe_entry_when_no_thread_start_is_recovered` asserts exactly that) - so
`allow_speakeasy` is **always False**. Every emulator run in this deployment passed
`allow_speakeasy: false`, which the evidence confirms for all three runs on the VB6 sample.

The cost, measured on the real Resume bytes in the isolated worker:

    Unicorn (granted bytes only, no loader/IAT)   stop=UNMAPPED_DATA after 3 instructions
    Speakeasy (full PE)                           reaches module entry 0x140001420 and executes
                                                  real code (0x140001030 -> 0x14000114c ->
                                                  0x140047358) before stopping on an
                                                  unimplemented CRT import

Those tests pin the DECISION rather than the already-correct helper: `controlled_emulation_windows`
provides both windows when asked (`test_speakeasy_window_is_kept_when_unique_threads_exist`), so the
bug is the call site choosing not to ask.
"""

from __future__ import annotations

import inspect
import re

from threat_report_agent.service import AnalysisService

SPEAKEASY_RESERVE_SOURCE = inspect.getsource(
    AnalysisService._run_controlled_emulator
)


def test_granted_window_planning_asks_for_speakeasy() -> None:
    """`granted_windows` must be planned WITH Speakeasy, or the request can never include it.

    Pins the actual mistake: planning the grant with `allow_speakeasy=False` means the full-PE
    window is not in the plan, so the request can never carry it.

    Matched on the argument itself rather than the substring, because `allow_speakeasy=False`
    appears legitimately elsewhere (an in-process snippet path, and a `(content, pe, ...)` helper
    call whose own default is False).
    """
    body = SPEAKEASY_RESERVE_SOURCE
    assert "granted_windows = unicorn_granted_windows_for_worker(" in body, (
        "the granted-window planning block was not found; this test needs updating"
    )
    planning_block = body.split("granted_windows = unicorn_granted_windows_for_worker(", 1)[1]
    planning_block = planning_block.split("max_windows=4,", 1)[0]
    assert "allow_speakeasy=speakeasy" in planning_block, (
        "the worker's window plan is not built with the operator's Speakeasy decision, so a "
        "full-PE window can never be requested. Block was:\n" + planning_block
    )


def test_operator_intent_is_not_overridden_by_having_any_unicorn_window() -> None:
    """A Unicorn window must not silently disable the full-PE emulator.

    The production expression is `False if granted_windows else speakeasy`. Since a real PE always
    yields at least a PE-entry Unicorn window, the operator's configured simulator is discarded in
    every case. The parameter must carry the operator's decision.
    """
    assert '"allow_speakeasy": False if granted_windows else speakeasy' not in (
        SPEAKEASY_RESERVE_SOURCE
    ), (
        "allow_speakeasy is still gated on granted_windows being empty; for any real PE that "
        "condition is never true and the full-PE emulator stays unreachable"
    )


def test_speakeasy_is_configured_as_an_allowed_simulator_by_default() -> None:
    """The premise: the deployment DOES allow Speakeasy, so the block is not a policy choice."""
    from threat_report_agent.config import Settings

    settings = Settings.from_environment()
    allowed = tuple(getattr(settings, "simulation_allowed_simulators", ()) or ())
    if not allowed:
        # An unset environment is the module default; assert the default allows it.
        from threat_report_agent.config import Settings as _Settings

        assert "speakeasy" in _Settings.model_fields["simulation_allowed_simulators"].default, (
            "speakeasy must be in the default allowed simulators"
        )
    else:
        assert "speakeasy" in {str(item).casefold() for item in allowed}, (
            f"speakeasy is not among the configured simulators: {allowed}"
        )
