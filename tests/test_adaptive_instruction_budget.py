"""指令预算按样本大小自适应，而不是固定常量。

MEASURED 为什么固定值行不通：样本大小相差数量级，任何常量都会**对大样本太小、对小样本过于宽松**。
本项目实测到的具体失败：同一次 Speakeasy 运行在白象（160 KB）上需要 **900,000** 条指令才能驱动
**1,031 次建模 API 调用**，而固定默认值 100,000 让它在**第一次调用**后就停了
（`modelled_calls=1`、`elapsed_ms=24`）。把常量抬到 900,000 只是把悬崖挪到下一个更大的样本。

所以预算是**输入大小的函数**：`bytes * 20 + 500_000`，`settings.simulation_instruction_budget`
退化为**下限**（operator 仍可抬高下限），并保留一个**与 policy 最大输入相称**的绝对上限——
那是防止 crafted image 无限占用 worker 的护栏，不是分析配额。
"""
from __future__ import annotations

from threat_report_agent.simulation_adapters import (
    _SIMULATION_BUDGET_CEILING,
    _SIMULATION_BUDGET_FLOOR,
    _simulation_instruction_budget_for,
)


def test_the_measured_sample_gets_enough_budget() -> None:
    """The concrete case: 160 KB needed 900,000 instructions for 1,031 modelled calls."""
    budget = _simulation_instruction_budget_for(159_744, 100_000)
    assert budget >= 900_000, "the 白象 sample must not be cut off before it does real work"


def test_budget_grows_with_sample_size() -> None:
    small = _simulation_instruction_budget_for(1_024)
    medium = _simulation_instruction_budget_for(159_744)
    large = _simulation_instruction_budget_for(4_194_304)
    assert small < medium < large


def test_a_large_sample_is_not_starved() -> None:
    """The defect being removed: a fixed constant cannot serve a sample an order of magnitude larger."""
    assert _simulation_instruction_budget_for(4_194_304) > 20 * _simulation_instruction_budget_for(159_744)


def test_configured_value_is_a_floor_never_a_cap() -> None:
    """An operator may raise the floor; it must never shrink the derived budget back to a constant."""
    assert _simulation_instruction_budget_for(1024, 2_000_000) == 2_000_000
    assert _simulation_instruction_budget_for(4_194_304, 100_000) > 100_000


def test_floor_applies_to_degenerate_inputs() -> None:
    assert _simulation_instruction_budget_for(0) == _SIMULATION_BUDGET_FLOOR
    assert _simulation_instruction_budget_for(-5) == _SIMULATION_BUDGET_FLOOR
    assert _simulation_instruction_budget_for(10) == _SIMULATION_BUDGET_FLOOR + 200


def test_absolute_ceiling_still_protects_the_worker() -> None:
    """A crafted image must not occupy a worker indefinitely; the ceiling is the guard."""
    assert _simulation_instruction_budget_for(10**9) == _SIMULATION_BUDGET_CEILING
    # ...and the ceiling must not bite at the largest input the policy already accepts.
    assert _simulation_instruction_budget_for(4_194_304) < _SIMULATION_BUDGET_CEILING


def test_bad_configuration_cannot_remove_the_derived_budget() -> None:
    for configured in (0, -1, None):
        assert _simulation_instruction_budget_for(159_744, configured) >= 900_000
