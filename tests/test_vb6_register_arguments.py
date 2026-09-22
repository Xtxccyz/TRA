"""`__vbaStrCopy` 的参数来自寄存器 `EDX`，不是栈。

MEASURED 根因（第 21 轮）：shim 的 `_esp_arguments` 从栈读参数，而 `argc` 被刻意设为 0
（传真实计数会让 Speakeasy 弹出这些参数、破坏调用方栈帧——调用数从 1,031 掉到 9）。
argc=0 时栈上没有参数，所以读到的是返回地址之后的无关 dword。

实测寄存器（连续 `__vbaStrCopy` 调用）：

    call 0  EDX=0x402c08  prefix=40  '61636528227620626120'  -> 'ace("v ba '
    call 1  EDX=0x402c38  prefix=40  '696D2066736F2C20666F'  -> 'im fso, fo'
    call 2  EDX=0x402c68  prefix=40  '2C205265706C61636528'  -> ', Replace('

`EDX` 每次 +0x30 (48)，走过 hex 记录表——它就是源记录指针。

修复效果：`arguments_seen` 由 **2**（且为垃圾）变为 **1028**（全部为真实记录文本）。

这些测试用假 session 钉住取参逻辑与**类型解析**——`get_register_state` 返回的是十六进制
**字符串**（`'0x00402c08'`），只处理 int 会静默丢掉每一个寄存器（我在第 21 轮就这样错过一次）。
"""
from __future__ import annotations

from threat_report_agent.vb6_runtime_shim import _register_arguments


class FakeSession:
    def __init__(self, state: object) -> None:
        self._state = state

    def get_register_state(self) -> object:
        return self._state


def test_reads_edx_from_hex_strings() -> None:
    """The real shape: values are hex strings, which an isinstance(int) filter drops."""
    session = FakeSession({"eax": "0xffffffff", "edx": "0x00402c08", "ecx": "0x00000907"})
    assert _register_arguments(session) == [0x402C08]


def test_accepts_int_values_too() -> None:
    session = FakeSession({"edx": 0x402C38})
    assert _register_arguments(session) == [0x402C38]


def test_returns_empty_without_edx() -> None:
    """No EDX means no readable source; the caller must fall back, not invent a pointer."""
    assert _register_arguments(FakeSession({"eax": "0x1"})) == []


def test_survives_a_session_that_raises() -> None:
    class Exploding:
        def get_register_state(self) -> object:
            raise RuntimeError("no registers")

    assert _register_arguments(Exploding()) == []


def test_survives_a_session_without_the_method() -> None:
    assert _register_arguments(object()) == []


def test_ignores_unparseable_values() -> None:
    session = FakeSession({"edx": "not-a-number", "eax": "0x1"})
    assert _register_arguments(session) == []


def test_edx_is_the_first_argument_the_handler_uses() -> None:
    """The handler reads `args[0]` as the source; EDX must therefore be first in the list."""
    session = FakeSession({"edx": "0x00402c68"})
    args = _register_arguments(session)
    assert args and args[0] == 0x402C68
