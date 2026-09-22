"""A wrapped bare array must never displace a real envelope.

MEASURED defect this pins (found by review, reproduced against `AnalystReportPlanEnvelope`): the candidate pool
is resolved with `max(candidates, key=score)` and ties go to the FIRST element, so once a wrapped array entered
the same list it could win outright - an incidental example array plus the real envelope scored **17 vs 6** and
the real chapters were discarded. "Scores lower" was therefore not a defence; not competing at all is.

A second defect surfaced while writing this file and is pinned too: when the reply IS a bare array, each
element object parses on its own and - because every envelope model here defaults its fields and ignores
extras - validates as a DEFAULTS-ONLY envelope scoring 0. That empty shell is a non-empty candidate pool, so
`candidates or wrapped` handed back the shell and threw away the correctly-wrapped whole.

Four properties, each of which failed at some point:
  1. wrapping never competes with a substantive envelope;
  2. wrapping is attempted only when the reply ITSELF is a bare array;
  3. a bare array whose elements each look like an empty envelope is still recovered as a whole;
  4. the `actions` hint matches `DynamicPlanAction`'s real field names (`tool_name`/`action_type`), where the
     old hint `("action", "tool")` could never match.
"""
from __future__ import annotations

import json

from threat_report_agent.analyst_report import AnalystReportPlanEnvelope
from threat_report_agent.model_gateway import DynamicPlanEnvelope, ModelGateway

REAL_ENVELOPE = {
    "chapters": [
        {"catalog_id": "process-creation", "title": "进程创建", "evidence_anchors": ["CreateProcess"]}
    ],
    "limitations": ["no endpoint recovered"],
}
EXAMPLE_ARRAY = [{"slot": "loop", "value": "含循环", "evidence_substring": "Loop"}]


def _pool(schema, content: str):
    """The candidate pool, exactly as `_structured_output_candidates` returns it."""
    candidates, _error = ModelGateway._structured_output_candidates(schema, content)
    return candidates


def _parse(schema, content: str):
    """The value the GATEWAY would actually use.

    NOT `pool[0]`: `_structured_output_candidates` does not sort, and the real selection is
    `max(candidates, key=score)` performed by `_parse_structured_output`. Taking the first entry reads an
    arbitrary element - which is what made the first version of this test report a defect that was really a
    test bug.
    """
    pool = _pool(schema, content)
    if not pool:
        return None
    return max(pool, key=lambda item: item[0])[2]


def test_a_wrapped_array_never_beats_the_real_envelope() -> None:
    """The headline defect: the example array must not win, however it scores."""
    content = json.dumps(EXAMPLE_ARRAY, ensure_ascii=False) + "\n" + json.dumps(REAL_ENVELOPE, ensure_ascii=False)
    parsed = _parse(AnalystReportPlanEnvelope, content)
    assert parsed is not None, "nothing parsed at all"
    assert parsed.chapters, "a wrapped example array displaced the real envelope - the chapters are gone"
    assert parsed.chapters[0].catalog_id == "process-creation"


def test_the_real_envelope_wins_even_when_the_example_scores_higher() -> None:
    """Guard the mechanism, not just one fixture."""
    content = json.dumps(EXAMPLE_ARRAY * 3, ensure_ascii=False) + "\n" + json.dumps(REAL_ENVELOPE, ensure_ascii=False)
    pool = _pool(AnalystReportPlanEnvelope, content)
    assert not any(entry[1].get("recovered_by_wrapping") for entry in pool), (
        "a wrapped candidate is still competing in the main pool"
    )
    parsed = _parse(AnalystReportPlanEnvelope, content)
    assert parsed.chapters and parsed.chapters[0].catalog_id == "process-creation"


def test_a_reply_that_is_a_bare_array_is_still_recovered() -> None:
    """MEASURED shape from the ledger: the model returned the slots array as the whole reply.

    Also pins the empty-envelope trap: each element validates as a defaults-only envelope scoring 0, and
    those must not displace the wrapped whole.
    """
    content = json.dumps(EXAMPLE_ARRAY, ensure_ascii=False)
    pool = _pool(AnalystReportPlanEnvelope, content)
    assert pool, "a leading bare array was not recovered"
    assert all(entry[1].get("recovered_by_wrapping") for entry in pool), (
        "the element shells were kept as candidates and would displace the wrapped whole"
    )
    parsed = _parse(AnalystReportPlanEnvelope, content)
    assert [slot.slot for slot in parsed.slots] == ["loop"]


def test_a_prose_reply_with_an_embedded_array_is_not_wrapped() -> None:
    """Wrapping is for a reply that IS an array, not for any bracket the scanner happens to find."""
    content = "Here is an example:\n" + json.dumps(EXAMPLE_ARRAY, ensure_ascii=False) + "\nHope that helps."
    pool = _pool(AnalystReportPlanEnvelope, content)
    assert not any(entry[1].get("recovered_by_wrapping") for entry in pool), (
        "an incidental example array embedded in prose was wrapped into an envelope"
    )


def test_a_bare_array_of_plan_actions_is_recoverable() -> None:
    """The `actions` hint now matches `DynamicPlanAction`'s real fields."""
    actions = [
        {
            "tool_name": "ghidra-headless",
            "action_type": "decompile_function",
            "target_artifact_id": "artifact-1",
            "reason": "recover the call site",
        }
    ]
    parsed = _parse(DynamicPlanEnvelope, json.dumps(actions, ensure_ascii=False))
    assert parsed is not None, "a bare array of real plan actions was not recovered"
    assert len(parsed.actions) == 1
    assert parsed.actions[0].tool_name == "ghidra-headless"


def test_an_array_that_fits_nothing_is_not_wrapped() -> None:
    """The property is "not wrapped", not "not parsed".

    An element like `{"unrelated": "key"}` still validates as a DEFAULTS-ONLY envelope, because every envelope
    model here defaults its fields and ignores extras - and the module's own docstring records that incidental
    `{}` examples are tolerated. With no wrapped alternative it displaces nothing, so asserting outright
    rejection would be inventing a requirement. What must hold is that the array is never forced into a field
    whose elements do not fit it.
    """
    assert _parse(AnalystReportPlanEnvelope, json.dumps([1, 2, 3])) is None
    pool = _pool(AnalystReportPlanEnvelope, json.dumps([{"unrelated": "key"}]))
    assert not any(entry[1].get("recovered_by_wrapping") for entry in pool), (
        "an array whose elements fit no envelope field was wrapped anyway"
    )
    for entry in pool:
        parsed = entry[2]
        assert not parsed.slots and not parsed.chapters, "the unrelated array was forced into a field"
