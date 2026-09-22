"""Which address a Speakeasy full-PE run starts from - and what EVIDENCE has to justify leaving the entry.

Two measured extremes bracket this rule, and the rule is the one point between them:

  * requiring `caller_count > 0` ALONE destroyed the capability on the real Resume run. With the 64 functions
    production passes (`service.py` sends `functions[:64]`):
        total 64 -> is_entry 1 -> no_callers 63 -> candidates 0
    Zero candidates meant the window kept the sentinel `0x1000000`, the adapter's image guard rejected it, and
    the run collapsed to `run_module`.

  * removing the requirement ENTIRELY was measurably WORSE. Measured in the isolated worker on the same
    sample, same adapter, same budget:
        entry-driven (the old fallback) : 1 api call, 647 ms, stops at msvcrt.__iob_func
        0x140001d0d (no evidence)       : 0 api calls, 147 ms, UC_ERR_READ_UNMAPPED at 0x140001d16
    Nine bytes into the function, observing strictly LESS than the fallback it replaced.

So the requirement stays and the EVIDENCE is widened: a caller count OR runtime-driving behaviour qualifies a
candidate. With neither there is nothing to justify leaving the entry, and the bounded `run_module` fallback
is the honest choice.
"""
from __future__ import annotations

from threat_report_agent.emulation_plan import _speakeasy_entry_from_functions

IMAGE_BASE = 0x140000000
IMAGE_SPAN = 4 * 1024 * 1024
ENTRY_RVA = 0x1420


def _function(address: int, **extra: object) -> dict:
    row: dict = {"entry": hex(address)}
    row.update(extra)
    return row


def _runtime_driver(address: int, **extra: object) -> dict:
    """A row `_calls_vb6_runtime` recognises: it calls into the VB6 runtime."""
    row: dict = {"entry": hex(address), "call_targets": [{"target_name": "__vbaStrCopy"}]}
    row.update(extra)
    return row


def test_a_callerless_pool_without_runtime_evidence_keeps_the_bounded_fallback() -> None:
    """The measured Resume case, and the reason the requirement was NOT simply deleted.

    Every function lacks a caller count and none drives the runtime, so nothing justifies leaving the entry.
    Choosing an arbitrary in-image function here was measured to observe ZERO api calls and to fault nine
    bytes in - strictly worse than the entry fallback's one observation.
    """
    functions = [
        _function(IMAGE_BASE + 0x1420, caller_count=0, callee_count=0),   # the entry itself
        _function(IMAGE_BASE + 0x1DDD, caller_count=0, callee_count=3),
        _function(IMAGE_BASE + 0x2169, caller_count=0, callee_count=1),
        _function(IMAGE_BASE + 0x3885, caller_count=0, callee_count=7),
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address is None, (
        "an arbitrary in-image function was chosen with no evidence behind it; measured, that faults almost "
        "immediately and observes less than the entry fallback"
    )
    assert basis == "image_entry", "an unusable plan must be reported as the image-entry decision"


def test_a_runtime_driver_without_callers_is_still_a_valid_start() -> None:
    """The widening: runtime-driving behaviour is EVIDENCE, and a stronger one than a caller count.

    This is the case the whole mechanism exists for - the measured 1,031 modelled calls / 256 api observations
    came from a runtime driver. A pool whose only evidence is runtime-driving must not be discarded.
    """
    functions = [
        _function(IMAGE_BASE + 0x1DDD, caller_count=0, callee_count=9),   # no evidence at all
        _runtime_driver(IMAGE_BASE + 0x2C0, caller_count=0, callee_count=1),
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address == IMAGE_BASE + 0x2C0, "a runtime driver was not selected over an unevidenced function"
    assert basis == "recovered_runtime_driver", (
        f"the start was justified by runtime evidence but the basis does not say so (got {basis!r})"
    )


def test_runtime_driving_outranks_a_merely_called_function() -> None:
    """The documented order: runtime-driving first, then most callers, then most callees, then address.

    Pre-existing behaviour - the sort has always led with `drives_runtime` - pinned here because the widening
    changed WHO qualifies to be ranked, and the ranking should not have to be inferred from the sort key. An
    earlier version of this test asserted the opposite (caller-backed wins) and was simply wrong about the
    rule; the code was right.
    """
    functions = [
        _runtime_driver(IMAGE_BASE + 0x1DDD, caller_count=0, callee_count=9),
        _function(IMAGE_BASE + 0x2C0, caller_count=1, callee_count=0),
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address == IMAGE_BASE + 0x1DDD, "a runtime driver did not outrank a merely-called function"
    assert basis == "recovered_runtime_driver"


def test_the_baixiang_shape_still_selects_its_measured_start() -> None:
    """Non-regression on the case the capability was measured with: both signals on one function.

    `0x40d2c0` drives the runtime AND is called, so it leads on both of the first two keys - which is why the
    widening cannot displace it. This is the shape that produced 1,031 modelled calls / 256 api observations,
    and the red line requires it to keep winning.
    """
    functions = [
        _function(IMAGE_BASE + 0x1DDD, caller_count=9, callee_count=1),
        _runtime_driver(IMAGE_BASE + 0x2C0, caller_count=1, callee_count=3),
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address == IMAGE_BASE + 0x2C0, (
        "the both-signals candidate lost to one with callers only; 白象's measured start is no longer selected"
    )
    assert basis == "recovered_function_entry"


def test_the_image_entry_is_never_chosen() -> None:
    """Running from the image entry is what `run_module` already does, so choosing it means choosing nothing."""
    functions = [
        _function(IMAGE_BASE + ENTRY_RVA, caller_count=5, callee_count=5),
        _runtime_driver(IMAGE_BASE + 0x4000, caller_count=0),
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address == IMAGE_BASE + 0x4000
    assert basis == "recovered_runtime_driver"


def test_a_callerless_out_of_image_row_is_still_rejected() -> None:
    """Coverage gap the T1b audit found: the widened rule must not readmit rejected ADDRESSES.

    Every pre-existing test that pins the address filters uses caller-BEARING rows, so nothing checked that a
    callerless sentinel or out-of-image address is still refused. Widening what counts as evidence must not
    widen which addresses are acceptable - those are different questions.
    """
    functions = [
        _function(0x1000000, caller_count=0, callee_count=9),   # the historical sentinel
        _function(0x500000, caller_count=0, callee_count=9),    # above base + span
        _function(0x1000, caller_count=0, callee_count=9),      # below base
        _runtime_driver(0x1000000, caller_count=0),             # the sentinel, now WITH runtime evidence
    ]
    address, basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address is None, f"an out-of-image address was accepted as a start: {address!r}"
    assert basis == "image_entry"


def test_no_in_image_function_still_yields_the_image_entry_decision() -> None:
    """Non-regression: with nothing usable the caller must still be told to run from the image entry."""
    address, basis = _speakeasy_entry_from_functions(
        [_function(IMAGE_BASE + ENTRY_RVA)], image_base=IMAGE_BASE, image_span=IMAGE_SPAN, entry_rva=ENTRY_RVA
    )

    assert address is None
    assert basis == "image_entry", "an unusable plan must be reported as the image-entry decision"
