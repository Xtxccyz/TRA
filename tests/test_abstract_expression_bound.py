"""The abstract executor must not let a derived expression grow without bound.

Regression this pins: task ``5a2ff9e2`` produced 780 ``abstract_execution_trace``
rows totalling **42 MB**, the largest single row 2.16 MB.  The cause is
``StaticAbstractExecutor._instruction_state`` rendering a derived value as
``OP(previous.value,operand)`` and storing it back, so a long run of arithmetic on
one register grows the string linearly per step and the retained bytes
quadratically overall.  The old 128-step cap masked it; removing that cap
(correctly) exposed it.

The bound must not cost depth: every step is still visited and emitted.
"""

import json

from threat_report_agent.static_simulation import (
    MAX_ABSTRACT_EXPRESSION_DEPTH,
    AbstractMemoryState,
    AbstractRegisterState,
    StaticAbstractExecutor,
)


def _arith_function(count: int) -> dict[str, object]:
    return {
        "name": "FUN_arith",
        "entry": "1000",
        "instructions": [
            {"address": hex(0x1000 + i), "mnemonic": "ADD", "text": "ADD RAX,0x1"}
            for i in range(count)
        ],
    }


def _drive(texts: list[str]) -> AbstractRegisterState:
    registers = AbstractRegisterState()
    memory = AbstractMemoryState()
    conditions: list[object] = []
    for index, text in enumerate(texts):
        StaticAbstractExecutor._instruction_state(text, registers, memory, conditions, index)
    return registers


def test_long_arithmetic_run_keeps_the_expression_bounded() -> None:
    registers = _drive(["ADD RAX,0x1"] * 400)
    value = registers.get("RAX")
    assert value is not None
    assert len(str(value.value)) < 200, f"expression grew to {len(str(value.value))} chars"
    assert value.depth > MAX_ABSTRACT_EXPRESSION_DEPTH


def test_every_step_is_still_visited_and_emitted() -> None:
    result = StaticAbstractExecutor(max_steps=100_000).analyze(_arith_function(600))
    # Depth is preserved: nothing is skipped and no budget unknown appears.
    assert len(result.steps) == 600
    assert not any("budget exhausted" in item for item in result.unknowns)


def test_trace_payload_stays_small_for_a_long_function() -> None:
    result = StaticAbstractExecutor(max_steps=100_000).analyze(_arith_function(2000))
    payload = json.dumps(result.__dict__, default=str)
    assert len(payload) < 2_000_000, f"serialized trace is {len(payload)} bytes"


def test_short_expressions_are_unchanged() -> None:
    """Shallow nesting must render exactly as before the bound existed.

    ``MOV RAX,0x10`` is parsed to the integer 16 by ``_parse_int``, so the
    rendered expression carries the decimal form - that predates this change.
    """
    registers = _drive(["MOV RAX,0x10", "ADD RAX,0x1", "XOR RAX,0x2"])
    assert str(registers.get("RAX").value) == "XOR(ADD(16,1),2)"
