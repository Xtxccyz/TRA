"""An over-long list must be TRUNCATED AND ANNOUNCED, never used to discard the whole answer.

MEASURED defect this pins (third review, item 4). `DynamicPlanAction` bounded seven list fields with
`max_length=`, so a provider returning a VALID plan with one item too many got:

    REJECTED type=too_long loc=('alternatives',)
    msg=List should have at most 8 items after validation, not 9

and a `ValidationError` is NOT retryable - `ModelGateway._is_retryable` lists transport failures,
`http_status` in {408,425,429}, an optional-parameter 400, and `JSONDecodeError`/`ValueError`;
`"ValidationError"` is absent, and the module contains no repair prompt. So the single attempt failed and every
claim the model would have contributed was dropped, while `service.py` published "Model enrichment JSON did not
match the atomic-claim envelope" - blaming the model for a limit the product chose.

The fix bounds by truncating and RECORDING the truncation in `truncated_fields`, because this project's rule is
that a truncated set must say so: every surviving item can be true while an implicit claim of completeness is
false (analysis-verification EC-4).

FAILS BEFORE THE FIX: every truncation case below raised ValidationError instead of returning a plan.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent.model_gateway import DynamicPlanAction  # noqa: E402


def _plan(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "target_artifact_id": "artifact-1",
        "reason": "r",
        "question": "q",
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    ("field", "bound"),
    [
        ("alternatives", 8),
        ("missing_evidence", 16),
        ("evidence_ids", 32),
        ("expected_evidence", 32),
        ("expected_evidence_kinds", 32),
        ("analysis_focus", 32),
        ("depends_on", 32),
    ],
)
def test_an_oversized_list_is_truncated_and_announced(field: str, bound: int) -> None:
    action = DynamicPlanAction.model_validate(
        _plan(**{field: [f"item-{index}" for index in range(bound + 3)]})
    )
    assert len(getattr(action, field)) == bound, (
        f"{field} kept {len(getattr(action, field))} of {bound + 3}; the bound must truncate, not reject"
    )
    notice = f"{field}:{bound}/3"
    assert notice in action.truncated_fields, (
        f"the truncation was SILENT - a consumer reads a bounded list as complete. "
        f"notices={action.truncated_fields}, expected {notice!r}"
    )


@pytest.mark.parametrize(("field", "bound"), [("alternatives", 8), ("evidence_ids", 32)])
def test_an_exactly_full_list_is_not_announced(field: str, bound: int) -> None:
    """`dropped == 0` must stay silent - a notice for nothing would be a false claim."""
    action = DynamicPlanAction.model_validate(
        _plan(**{field: [f"item-{index}" for index in range(bound)]})
    )
    assert len(getattr(action, field)) == bound
    assert action.truncated_fields == [], f"claimed a truncation that did not happen: {action.truncated_fields}"


def test_a_real_schema_problem_is_still_rejected() -> None:
    """NEGATIVE CONTROL: the fix must not turn validation into a rubber stamp.

    Truncating an over-long list is the ONLY behaviour that changed. A payload that is genuinely malformed -
    here a required field is absent - must still raise, or the bound would have been "fixed" by removing the
    gate rather than by making it non-fatal.
    """
    with pytest.raises(ValidationError):
        DynamicPlanAction.model_validate({"reason": "r", "question": "q"})


def test_the_notice_survives_a_provider_that_supplied_one() -> None:
    """A provider-supplied notice is carried, not overwritten."""
    action = DynamicPlanAction.model_validate(
        _plan(alternatives=[f"a{index}" for index in range(10)], truncated_fields=["provider:note"])
    )
    assert "provider:note" in action.truncated_fields
    assert "alternatives:8/2" in action.truncated_fields
