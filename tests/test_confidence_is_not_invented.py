"""Absence must stay absent: a missing confidence is NOT a mid-strength claim.

MEASURED defect this pins (third review, standards axis). `model_gateway._coerce_confidence` coerced EVERY
unusable input to `"MEDIUM"`:

    value is None or value == ""  -> "MEDIUM"        # the provider said nothing
    ...unparseable text           -> "MEDIUM"        # the provider said something unusable
    numeric >= 0.8 / >= 0.4       -> "HIGH" / "MEDIUM"   # two cut points with NO provenance (G2)

That is the project's first-class error class: ABSENCE converted into a claim. A consumer reading
`confidence == "MEDIUM"` cannot tell "the model assessed this as medium" from "the model never said", and the
second is not evidence for the first. The schema default was the same bug one level down
(`confidence: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"`).

The numeric branch went too. `prompts/static-analysis-system-v1.md` asks only for
"`confidence` (LOW, MEDIUM, or HIGH)", so the cut points guarded a format the product never requests. They were
not replaced with different chosen numbers (G1/G4) - a value that is not one of the four labels is treated as
not-a-label.

`UNVERIFIED` is deliberately NOT a new token: `contracts.py` already ships
`Literal["UNVERIFIED", "LOW", "MEDIUM", "HIGH"] = "UNVERIFIED"` for exactly this meaning.

FAILS BEFORE THE FIX: every "absence" case below returned "MEDIUM", and every numeric case returned a label.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.model_gateway import AtomicClaimDraft, _coerce_confidence  # noqa: E402


@pytest.mark.parametrize(
    "value",
    [
        None,          # field absent
        "",            # empty string
        "   ",         # whitespace only
        "maybe",       # unparseable label
        "0.9",         # a numeric string the product never asks for
        0.9,           # ... and the numeric form of it
        0.95,
        0.2,
        0,
        1,
        True,          # a bool is not a confidence label
        [],            # wrong type entirely
        {"level": "high"},
    ],
)
def test_an_unusable_confidence_is_not_invented(value: object) -> None:
    assert _coerce_confidence(value) == "UNVERIFIED", (
        f"{value!r} was converted into a claim; absence or an unusable value must stay UNVERIFIED so a "
        "consumer cannot mistake it for an assessment"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [("HIGH", "HIGH"), ("high", "HIGH"), (" Medium ", "MEDIUM"), ("low", "LOW"), ("UNVERIFIED", "UNVERIFIED")],
)
def test_real_labels_pass_through(value: object, expected: str) -> None:
    assert _coerce_confidence(value) == expected


def test_the_schema_default_is_not_a_claim() -> None:
    """`confidence` omitted by the provider must not arrive as MEDIUM."""
    claim = AtomicClaimDraft.model_validate({"statement": "s", "module": "m"})
    assert claim.confidence == "UNVERIFIED", (
        "a claim drafted without a confidence is published as a mid-strength assessment"
    )


def test_a_provider_supplied_label_is_still_honoured() -> None:
    """The fix must not collapse a REAL label into UNVERIFIED."""
    claim = AtomicClaimDraft.model_validate(
        {"statement": "s", "module": "m", "confidence": "HIGH"}
    )
    assert claim.confidence == "HIGH"
