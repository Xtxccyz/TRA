"""R4: a per-step constant must not be copied into every step of a trace.

Measured on the real ledger before this fix, one `abstract_execution_trace` payload for the
551KB Rust PE's `entry` function:

    serialized                        83,853,859 chars
    steps[].source_anchor             83,827,376   (99.97% of the payload)
    steps                             65,536
    distinct source_anchor values     65,535       (only `instruction_index` varies)
    anchor bytes each                 1,052
      of which source_evidence_ids    ~1,000       <- the SAME 24 UUIDs every step

`source_evidence_ids` is the function's evidence list, so it cannot vary per step and must not
be repeated per step. This is a pathological-cost defect (R4), not a quota question: the fix
removes duplication rather than dropping data, and these tests pin both halves - that the
payload shrinks, and that every step's anchor still reads back complete.
"""

from __future__ import annotations

import json

from threat_report_agent.static_simulation import (
    SimulationTraceStep,
    StaticSimulationResult,
    merged_source_anchor,
)

EVIDENCE_IDS = [f"aaaaaaaa-bbbb-cccc-dddd-{index:012d}" for index in range(24)]


def _result(step_count: int) -> StaticSimulationResult:
    steps = tuple(
        SimulationTraceStep(
            index=index,
            operation="MOV",
            api=None,
            inputs={"a": index},
            outputs={"b": index},
            path_condition=None,
            source_anchor={
                "function": "entry",
                "entry": "140001420",
                "instruction_index": index,
                "source_evidence_ids": list(EVIDENCE_IDS),
            },
        )
        for index in range(step_count)
    )
    return StaticSimulationResult(
        function="entry",
        entry="140001420",
        steps=steps,
        path_conditions=(),
        register_state={},
        memory_state={},
        mechanism_candidates=(),
        unknowns=(),
        limitations=(),
        confidence="LOW",
    )


def test_constant_anchor_fields_are_not_repeated_per_step() -> None:
    """The measured defect: 1,000 duplicated bytes x 65,536 steps."""
    payload = _result(200).as_dict()
    base = payload.get("source_anchor_base")
    assert isinstance(base, dict), (
        "the constant anchor fields were not hoisted; every step still carries its own copy "
        "of the 24 source_evidence_ids"
    )
    assert base.get("source_evidence_ids") == EVIDENCE_IDS
    assert "source_evidence_ids" not in json.dumps(payload["steps"]), (
        "the shared evidence ids are still serialized inside the per-step list"
    )
    # instruction_index varies, so it must stay per step.
    assert [step["source_anchor"]["instruction_index"] for step in payload["steps"]] == list(
        range(200)
    )


def test_every_step_anchor_still_reads_back_complete() -> None:
    """Hoisting must not delete information: the merged anchor equals the original."""
    payload = _result(50).as_dict()
    for index, step in enumerate(payload["steps"]):
        merged = merged_source_anchor(payload, step)
        assert merged == {
            "function": "entry",
            "entry": "140001420",
            "instruction_index": index,
            "source_evidence_ids": EVIDENCE_IDS,
        }, f"step {index} lost anchor information: {merged}"


def test_payload_is_substantially_smaller() -> None:
    """The point of the change, asserted as a ratio rather than an exact byte count."""
    naive = {
        "steps": [
            {
                "index": index,
                "source_anchor": {
                    "function": "entry",
                    "entry": "140001420",
                    "instruction_index": index,
                    "source_evidence_ids": list(EVIDENCE_IDS),
                },
            }
            for index in range(500)
        ]
    }
    fixed = _result(500).as_dict()
    naive_bytes = len(json.dumps(naive))
    fixed_bytes = len(json.dumps(fixed))
    assert fixed_bytes * 4 < naive_bytes, (
        f"expected a large reduction from removing a per-step constant, got "
        f"{naive_bytes:,} -> {fixed_bytes:,}"
    )


def test_a_single_step_payload_is_left_alone() -> None:
    """Hoisting one step saves nothing, so the shape must not change for it."""
    payload = _result(1).as_dict()
    assert "source_anchor_base" not in payload, (
        "a single-step payload gained a base key for no benefit, which changes the stored "
        "shape of every small trace"
    )
    assert payload["steps"][0]["source_anchor"]["source_evidence_ids"] == EVIDENCE_IDS


def test_varying_anchor_fields_are_never_hoisted() -> None:
    """A trace whose anchors genuinely differ keeps every distinction."""
    steps = tuple(
        SimulationTraceStep(
            index=index,
            operation="MOV",
            api=None,
            inputs={},
            outputs={},
            path_condition=None,
            source_anchor={"instruction_index": index, "call_site": f"14000{index:04x}"},
        )
        for index in range(10)
    )
    result = StaticSimulationResult(
        function="f",
        entry="0",
        steps=steps,
        path_conditions=(),
        register_state={},
        memory_state={},
        mechanism_candidates=(),
        unknowns=(),
        limitations=(),
        confidence="LOW",
    )
    payload = result.as_dict()
    assert payload.get("source_anchor_base") in (None, {}), (
        "fields that differ per step were hoisted, which would overwrite them with one value"
    )
    for index, step in enumerate(payload["steps"]):
        assert merged_source_anchor(payload, step)["call_site"] == f"14000{index:04x}"


def test_pre_hoist_payloads_still_read_correctly() -> None:
    """Rows written before this change have no base key and must be unaffected."""
    legacy_payload = {"steps": [{"source_anchor": {"function": "f", "entry": "0"}}]}
    assert merged_source_anchor(legacy_payload, legacy_payload["steps"][0]) == {
        "function": "f",
        "entry": "0",
    }
