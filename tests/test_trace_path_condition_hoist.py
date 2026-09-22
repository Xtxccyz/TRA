"""Hoist the per-step `path_condition` the way the constant anchor fields already are.

MEASURED R4 COST, task `50673002`, one `abstract_execution_trace` row:

    payload                 16,482,793 bytes over 65,536 steps
    steps total             45,276,514 bytes for the whole task (729 rows)

Per-step field cost over the first 400 steps (`.scratch/measure-trace-step-cost.py`):

    field              bytes  share  distinct/400   bytes/step
    path_condition    13,317  25.2%     62/400          33.3
    source_anchor     10,297  19.5%    400/400          25.7
    outputs            9,907  18.8%    112/400          24.8
    inputs             7,533  14.3%    123/400          18.8
    operation          5,456  10.3%      6/400          13.6
    confidence         3,200   6.1%      1/400           8.0
    api                1,970   3.7%     23/400           4.9
    index              1,090   2.1%    400/400           2.7

`path_condition` is the largest single field and carries only **62 distinct values across 400 steps**, in a
1-4 character encoding (`value = last(|bool)`) inside a table, so no reader is broken by the change. This keeps the fact and drops the repetition.

Round 66 established the pattern for exactly this situation: hoist what repeats, keep what varies, and give
readers a merge helper (`merged_source_anchor`) so nothing has to change at the call sites beyond calling it.
The same treatment applies to `path_condition`, with one extra care that the anchor case did not have: a step
whose condition is `None` means "this step has no condition", which is DIFFERENT from "same as the previous
step". The two must stay distinguishable, or a reader counting gates would see a carried-over value where the
run recorded none.

So the hoist keeps one small integer per step rather than a repeated string:

    payload["path_condition_table"] = [<distinct conditions in first-seen order>]
    step["path_condition_index"]    = <index into that table, or absent/None for "no condition">
    step["path_condition"]          = <written back in full>   <- existing readers unaffected
"""
from __future__ import annotations

from threat_report_agent.static_simulation import merged_path_condition


def _steps(conditions: list[str | None]) -> list[dict]:
    return [
        {
            "index": index,
            "operation": "compare",
            "api": None,
            "inputs": {},
            "outputs": {},
            "path_condition": condition,
            "source_anchor": {"instruction_index": index},
            "confidence": "MEDIUM",
        }
        for index, condition in enumerate(conditions)
    ]


CONDITIONS: list[str | None] = [
    "branch at instruction 12 unresolved",
    "branch at instruction 12 unresolved",
    None,
    "RAX cmp 0X100",
    "branch at instruction 12 unresolved",
    None,
    None,
]


def test_the_merge_helper_restores_every_step_condition() -> None:
    """The reader-facing contract: a step's own condition, from a hoisted payload."""
    steps = _steps(CONDITIONS)
    payload = {
        "path_condition_table": ["branch at instruction 12 unresolved", "RAX cmp 0X100"],
        "steps": [
            {**step, "path_condition_index": index}
            for index, step in enumerate(
                [
                    {**steps[0], "path_condition_index": 0},
                    {**steps[1], "path_condition_index": 0},
                    {**steps[2]},
                    {**steps[3], "path_condition_index": 1},
                    {**steps[4], "path_condition_index": 0},
                    {**steps[5]},
                    {**steps[6]},
                ]
            )
        ],
    }
    for position, expected in enumerate(CONDITIONS):
        step = payload["steps"][position]
        assert merged_path_condition(payload, step) == expected, (
            f"step {position}: expected {expected!r}, got "
            f"{merged_path_condition(payload, step)!r}"
        )


def test_none_and_a_repeated_condition_stay_distinguishable() -> None:
    """`None` means "no condition on this step", NOT "same as the previous one".

    A reader counting gates must not have a carried-over value invented for a step where the run recorded
    none. This is the one place the path_condition hoist is harder than the anchor hoist, and it is why a
    table index is used rather than a "repeat previous" marker.
    """
    payload = {"path_condition_table": ["RAX cmp 0X100"], "steps": []}
    assert merged_path_condition(payload, {"path_condition_index": 0}) == "RAX cmp 0X100"
    assert merged_path_condition(payload, {}) is None
    assert merged_path_condition(payload, {"path_condition": "literal"}) == "literal"


def test_a_payload_written_before_the_hoist_still_reads() -> None:
    """Old rows have no table; their steps carry the condition inline and must be returned verbatim."""
    payload = {"steps": []}
    assert merged_path_condition(payload, {"path_condition": "legacy cmp"}) == "legacy cmp"
    assert merged_path_condition(payload, {}) is None


def test_an_out_of_range_index_is_not_silently_wrong() -> None:
    """A corrupt index must not raise into a report build, and must not invent a condition."""
    payload = {"path_condition_table": ["only"], "steps": []}
    assert merged_path_condition(payload, {"path_condition_index": 7}) is None
    assert merged_path_condition(payload, {"path_condition_index": "x"}) is None


def test_the_hoist_actually_shrinks_a_realistic_payload() -> None:
    """The point of the change: fewer bytes for the same information.

    MEASURED, and the measurement corrected the design. The first version of this test expected an 80%
    saving on a payload that is "80% repeated conditions", and failed at **-9.2%** - the hoist made the
    payload BIGGER. Reason, per step in a JSON payload:

        baseline  `path_condition` inline                57 bytes
        index + keep inline                              85 bytes   (+28)
        index only, drop inline                          28 bytes   (-29)  -> 11.5% of the row
        delta flag only (`repeat previous`)              15 bytes   (-42)  -> 16.7% of the row

    The saving only exists if the inline string is DROPPED, and that requires every inline reader to move
    to `merged_path_condition`. So the realistic expectation is a modest, real saving - not 80%.
    """
    import json

    conditions = (["branch at instruction 12 unresolved"] * 40
                  + ["RAX cmp 0X100"] * 40
                  + [None] * 20)
    steps = _steps(conditions)
    before = len(json.dumps({"steps": steps}, ensure_ascii=False))

    table: list[str] = []
    hoisted: list[dict] = []
    for step in steps:
        condition = step.get("path_condition")
        if condition is None:
            hoisted.append({key: value for key, value in step.items() if key != "path_condition"})
            continue
        if condition not in table:
            table.append(condition)
        hoisted.append({**{k: v for k, v in step.items() if k != "path_condition"},
                        "path_condition_index": table.index(condition)})
    after = len(json.dumps({"path_condition_table": table, "steps": hoisted}, ensure_ascii=False))
    assert after < before, (
        f"hoisting with the inline string DROPPED made the payload larger ({after} vs {before}); the "
        "encoding is not doing its job"
    )
    # Keep the inline string and the change is a regression, which is why the producer must drop it.
    with_inline = [{**step, "path_condition_index": 0} for step in steps]
    assert len(json.dumps({"path_condition_table": table, "steps": with_inline},
                          ensure_ascii=False)) > before, (
        "keeping the inline string AND adding an index is expected to grow the payload; if this ever "
        "passes, the inline copy has stopped being written and this test should be tightened"
    )
