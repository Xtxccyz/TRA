"""Speakeasy 从**指定地址**执行的守卫逻辑。

MEASURED 动机：白象样本的 PE 入口是引导跳板，撞上未实现的 `MSVBVM60.ordinal_100` 就死，
入口驱动的运行**什么都观测不到**（`1 modelled call(s) to ordinal_100`）。
改从已恢复的 VB6 字面量构造器（`0x40d2c0`）起执行，可跑出 1,028 次 `__vbaStrCopy`
并让 shim 解出参数（修好寄存器 ABI 后 `arguments_seen` 由 2 变 1028）。

但「从任意地址执行」本身就是风险：地址错了会把一个能跑的窗口变成死窗口。
所以 `_speakeasy_start_address` 必须**严格**，任何条件不满足都回退到 `run_module`——
这样既有窗口的行为完全不变。这些测试钉住的就是那些条件。
"""
from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.simulation_adapters import _speakeasy_start_address


def _request(entry: object) -> SimpleNamespace:
    return SimpleNamespace(entry_address=entry)


def _module(base: int = 0x400000, size: int = 0x23000, entry_points: object = ()) -> SimpleNamespace:
    return SimpleNamespace(base=base, image_size=size, entry_points=entry_points)


def test_returns_the_granted_function_entry() -> None:
    """The measured case: 0x40d2c0 inside the image, not the module entry."""
    assert _speakeasy_start_address(_request(0x40D2C0), _module()) == 0x40D2C0


def test_historical_shellcode_address_is_rejected() -> None:
    """0x1000000 is the hardcoded shellcode window address and is NOT in the image.

    Before the register-ABI work every speakeasy window carried this value; executing it would be a
    guaranteed dead run, so it must keep the default behaviour.
    """
    assert _speakeasy_start_address(_request(0x1000000), _module()) is None


def test_module_entry_point_falls_back_to_run_module() -> None:
    """Running from the entry is what `run_module` already does; returning it adds risk for nothing."""
    assert _speakeasy_start_address(_request(0x400000), _module()) is None
    entry_points = [{"start_addr": "0x401000"}]
    assert _speakeasy_start_address(_request(0x401000), _module(entry_points=entry_points)) is None


def test_address_outside_the_image_is_rejected() -> None:
    assert _speakeasy_start_address(_request(0x500000), _module()) is None
    assert _speakeasy_start_address(_request(0x1000), _module()) is None


def test_missing_or_odd_inputs_are_rejected() -> None:
    assert _speakeasy_start_address(_request(None), _module()) is None
    assert _speakeasy_start_address(_request("0x40d2c0"), _module()) is None
    assert _speakeasy_start_address(_request(0x40D2C0), SimpleNamespace(base=None)) is None
    assert _speakeasy_start_address(_request(0x40D2C0), SimpleNamespace()) is None


def test_without_a_size_only_lower_bound_is_enforced() -> None:
    """A module that reports no size must still refuse addresses below its base."""
    module = SimpleNamespace(base=0x400000, entry_points=())
    assert _speakeasy_start_address(_request(0x40D2C0), module) == 0x40D2C0
    assert _speakeasy_start_address(_request(0x1000000), module) is None


def test_entry_points_in_decimal_string_form_are_recognised() -> None:
    """`int(str(x), 0)` accepts both forms, so a decimal entry must still be treated as the entry."""
    entry_points = [{"start_addr": str(0x401000)}]
    assert _speakeasy_start_address(_request(0x401000), _module(entry_points=entry_points)) is None
