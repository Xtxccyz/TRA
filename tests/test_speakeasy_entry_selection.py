"""Speakeasy 起点的选择规则。

MEASURED 动机：白象样本的 PE 入口是引导跳板，撞上未实现的 `MSVBVM60.ordinal_100` 就死，
入口驱动的 Speakeasy 运行**什么都观测不到**（`1 modelled call`）。
改从**已恢复的函数入口**起执行，隔离 worker 实测产出：

    modelled_calls=1031   api observations=256   strings observed=1028

不选入口时窗口带着历史硬编码的 `0x1000000`，被适配器的映像守卫拒绝 → 能力整条不可达。
所以这里的规则必须**通用**（不得点名任何样本地址——`literal_table.py` 已写明
「a projection keyed to one sample's address is not a capability」）且**严格**。
"""
from __future__ import annotations

from threat_report_agent.emulation_plan import _speakeasy_entry_from_functions

IMAGE_BASE = 0x400000
# The 白象 image carries three sections up to ~0x26104, so allow realistic headroom. The first version
# of this file used 0x23000, which put the fixture address 0x423210 just OUTSIDE the image - the
# function correctly rejected it and the test was wrong, not the code.
SPAN = 0x40000
ENTRY_RVA = 0x2484  # -> 0x402484, the image entry itself


def _pick(functions: list[dict], *, entry_rva: int | None = ENTRY_RVA) -> int | None:
    """Address only.

    `_speakeasy_entry_from_functions` returns `(address, basis)`; the basis is asserted in
    `test_speakeasy_start_selection.py`. Unpacking here keeps every assertion in THIS file about the address
    exactly as it was, so the signature change cannot silently weaken the rules pinned below.
    """
    address, _basis = _speakeasy_entry_from_functions(
        functions, image_base=IMAGE_BASE, image_span=SPAN, entry_rva=entry_rva
    )
    return address


def test_picks_a_called_function_inside_the_image() -> None:
    functions = [
        {"entry": 0x40D2C0, "caller_count": 1, "callee_count": 3},
        {"entry": 0x423210, "caller_count": 2, "callee_count": 1},
    ]
    assert _pick(functions) == 0x423210  # more callers wins


def test_prefers_the_busiest_function_when_callers_tie() -> None:
    functions = [
        {"entry": 0x40D000, "caller_count": 1, "callee_count": 1},
        {"entry": 0x40E000, "caller_count": 1, "callee_count": 9},
    ]
    assert _pick(functions) == 0x40E000


def test_never_returns_the_image_entry() -> None:
    """Running from the entry is exactly what `run_module` already does."""
    functions = [{"entry": 0x402484, "caller_count": 5, "callee_count": 5}]
    assert _pick(functions) is None


def test_rejects_addresses_outside_the_image() -> None:
    functions = [
        {"entry": 0x1000000, "caller_count": 9},  # the historical sentinel
        {"entry": 0x500000, "caller_count": 9},   # above base + span
        {"entry": 0x1000, "caller_count": 9},     # below base
    ]
    assert _pick(functions) is None


def test_a_callerless_function_needs_other_evidence_to_be_a_start() -> None:
    """REPLACES `test_requires_a_caller`, which pinned a rule that was both too strict and, once removed, unsafe.

    Too strict: requiring a caller count silently destroyed the capability on the real Resume run - with the 64
    functions production passes, every candidate was discarded and the run collapsed to the image-entry
    fallback. Unsafe to simply delete: measured in the isolated worker, an unevidenced start (`0x140001d0d`)
    produced ZERO api calls and faulted nine bytes in, while the entry fallback produced one.

    So a callerless function is a start only when it carries OTHER evidence - here, driving the VB6 runtime.
    The padding argument from the old docstring survives in the last assertion: an unevidenced function is
    never preferred over an evidenced one.
    """
    # No caller count and no runtime evidence -> nothing justifies leaving the entry.
    address, basis = _speakeasy_entry_from_functions(
        [{"entry": 0x40D2C0, "caller_count": 0, "callee_count": 9}],
        image_base=IMAGE_BASE,
        image_span=SPAN,
        entry_rva=ENTRY_RVA,
    )
    assert address is None, "an unevidenced start was chosen; measured, that is worse than the entry fallback"
    assert basis == "image_entry"

    # Same, with no `caller_count` key at all.
    address_missing, basis_missing = _speakeasy_entry_from_functions(
        [{"entry": 0x40D2C0, "callee_count": 9}],
        image_base=IMAGE_BASE,
        image_span=SPAN,
        entry_rva=ENTRY_RVA,
    )
    assert address_missing is None
    assert basis_missing == "image_entry"

    # ...but runtime-driving evidence qualifies it, so a callerless pool is not discarded wholesale.
    runtime_driver = {"entry": 0x40D2C0, "caller_count": 0, "call_targets": [{"target_name": "__vbaStrCopy"}]}
    addressed, runtime_basis = _speakeasy_entry_from_functions(
        [runtime_driver], image_base=IMAGE_BASE, image_span=SPAN, entry_rva=ENTRY_RVA
    )
    assert addressed == 0x40D2C0
    assert runtime_basis == "recovered_runtime_driver"

    # ...and padding is never preferred over a called function.
    assert _pick([{"entry": 0x40D2C0, "caller_count": 0}, {"entry": 0x40E000, "caller_count": 1}]) == 0x40E000


def test_accepts_an_rva_and_normalises_it() -> None:
    """A recovered row may carry an RVA rather than a VA."""
    assert _pick([{"entry_rva": 0xD2C0, "caller_count": 1}]) == 0x40D2C0
    assert _pick([{"entry_rva": 0x2484, "caller_count": 1}]) is None  # normalises onto the entry


def test_ignores_malformed_rows() -> None:
    functions: list[object] = [
        "not-a-mapping",
        {"caller_count": 3},
        {"entry": None, "caller_count": 3},
        {"entry": "0xZZ", "caller_count": 3},
    ]
    assert _pick(functions) is None  # type: ignore[arg-type]


def test_no_functions_means_no_start_address() -> None:
    """The caller must keep the historical sentinel so the adapter's guard keeps failing safe."""
    assert _pick([]) is None
    address, basis = _speakeasy_entry_from_functions(
        None, image_base=IMAGE_BASE, image_span=SPAN, entry_rva=ENTRY_RVA
    )
    assert address is None
    assert basis == "image_entry", "an unusable plan must be reported as the image-entry decision"


def test_string_entry_values_are_accepted() -> None:
    functions = [{"entry": "0x40D2C0", "caller_count": 1}]
    assert _pick(functions) == 0x40D2C0


# --- runtime-driver detection ---------------------------------------------------------------------
#
# MEASURED: the first wired run picked an entry that produced `modelled_calls=1` because the detector
# looked only at the row's TOP-LEVEL fields, while the runtime target lives inside `data_references`.
# And the target appears as `PTR___vbaChkstk_00401058`, so a `startswith("__vba")` test misses it too.

from threat_report_agent.emulation_plan import _calls_vb6_runtime  # noqa: E402


def test_detects_a_nested_indirection_to_the_runtime() -> None:
    row = {
        "name": "__vbaChkstk",
        "entry": "004022c0",
        "caller_count": 6,
        "callee_count": 0,
        "call_targets": [],
        "data_references": [
            {"from": "004022c0", "to": "00401058", "type": "INDIRECTION",
             "target_name": "PTR___vbaChkstk_00401058"}
        ],
    }
    assert _calls_vb6_runtime(row) is True


def test_detects_a_nested_external_call() -> None:
    row = {"entry": 0x40D2C0, "call_targets": [{"target_name": "__vbaStrCopy"}]}
    assert _calls_vb6_runtime(row) is True


def test_ignores_functions_without_runtime_calls() -> None:
    row = {
        "entry": 0x401000,
        "data_references": [{"target_name": "DAT_00401130"}],
        "call_targets": [{"target_name": "FUN_00401000"}],
    }
    assert _calls_vb6_runtime(row) is False


def test_runtime_driver_outranks_a_mere_stack_probe() -> None:
    """The measured failure: a routine that only probes the stack looked as "called" as one that drives
    the runtime. With the signal detected, the runtime driver must win even with fewer callers."""
    probe = {
        "entry": 0x40A000,
        "caller_count": 9,
        "callee_count": 1,
        "data_references": [{"target_name": "DAT_00401130"}],
    }
    driver = {
        "entry": 0x40D2C0,
        "caller_count": 1,
        "callee_count": 3,
        "data_references": [{"target_name": "PTR___vbaChkstk_00401058"}],
    }
    assert _pick([probe, driver]) == 0x40D2C0


def test_detection_terminates_on_a_cyclic_record() -> None:
    """Records come from external tooling; a cycle must not hang the planner."""
    row: dict[str, object] = {"entry": 0x40D2C0, "caller_count": 1}
    row["self"] = row
    assert _calls_vb6_runtime(row) is False


def test_a_runtime_export_is_never_the_start_point() -> None:
    """MEASURED: `__vbaChkstk` was selected because a runtime import trivially "mentions the runtime".

    The observed effect was `entry_address=0x4022c0` (the stub's own entry) and the run ending after one
    call. A runtime export is the callee of real work, never the place to start.
    """
    functions = [
        {
            "name": "__vbaChkstk",
            "entry": 0x4022C0,
            "caller_count": 6,
            "callee_count": 0,
            "data_references": [{"target_name": "PTR___vbaChkstk_00401058"}],
        },
        {
            "name": "FUN_0040d2c0",
            "entry": 0x40D2C0,
            "caller_count": 1,
            "callee_count": 3,
            "data_references": [{"target_name": "PTR___vbaStrCopy_0040105c"}],
        },
    ]
    assert _pick(functions) == 0x40D2C0, "a runtime stub must not outrank the function that drives it"


def test_runtime_exports_are_recognised_by_name() -> None:
    from threat_report_agent.emulation_plan import _is_vb6_runtime_symbol

    for name in ("__vbaChkstk", "'__vbaStrCopy'", "Ordinal_100", "PTR___vbaNew2_004010c4"):
        assert _is_vb6_runtime_symbol(name) is True, name
    for name in ("FUN_0040d2c0", "entry", "", None, "CreateProcessW"):
        assert _is_vb6_runtime_symbol(name) is False, name
