"""An unreadable emulator output must not be published as a claim about the SAMPLE.

MEASURED defect this pins (adversarial defect audit, item 5). `service.py`'s emulator collection swallowed the
content-store read failure:

    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        results = []

and `results == []` is indistinguishable from "the emulator genuinely found no window". The empty list then
drove a fabricated row asserting `NO_GRANTED_WINDOW` with the limitation

    static recovery did not yield a bounded start-routine window; isolated emulation was still attempted

When the READ failed, that sentence is false twice over: the emulation ran (so "isolated emulation was still
attempted" misdescribes the failure) and its unreadability says nothing about the sample's static recovery.
Reachable whenever the content store is unavailable — minio reported `InsufficientWriteQuorum` during this
session. Absence converted into a claim about the sample.

The decision is a pure function of the one input that distinguishes the cases, so it is testable at all.

FAILS BEFORE THE FIX: there was one row for both cases, asserting `NO_GRANTED_WINDOW`.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.service import AnalysisService  # noqa: E402

ROW = AnalysisService._emulation_fallback_payload


def test_an_unreadable_output_is_not_reported_as_the_samples_fault() -> None:
    payload = ROW("OSError: content store unavailable")

    assert payload["status"] == "EMULATION_OUTPUT_UNREADABLE", (
        f"an unreadable output was recorded as {payload['status']!r}, which reads as a property of the sample"
    )
    assert payload["stop_reason"] == "EMULATION_OUTPUT_UNREADABLE"
    limitation = str((payload["limitations"] or [""])[0])
    assert "content store unavailable" in limitation, (
        f"the real cause must be carried, not discarded: {limitation!r}"
    )
    assert "static recovery did not yield" not in limitation, (
        "the row still blames the sample's static recovery for a pipeline failure"
    )
    assert "not evidence about the sample" in limitation, (
        "the reader must be told this row is not evidence about the sample"
    )


def test_a_genuine_empty_result_keeps_its_original_row() -> None:
    """NEGATIVE CONTROL: with no read failure the existing wording must be unchanged."""
    payload = ROW(None)

    assert payload["status"] == "NO_GRANTED_WINDOW"
    assert payload["stop_reason"] == "NO_GRANTED_WINDOW"
    limitation = str((payload["limitations"] or [""])[0])
    assert "static recovery did not yield a bounded start-routine window" in limitation, (
        f"the genuine no-window case lost its diagnosis: {limitation!r}"
    )
    assert "EMULATION_OUTPUT_UNREADABLE" not in str(payload)
