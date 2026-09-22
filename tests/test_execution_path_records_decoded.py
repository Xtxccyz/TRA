"""执行路径读到的记录必须被解码并发布——这是第二套**独立**表示。

目标要求「还原 0x40cedc 描述符指向的字符串数组，与已还原的 4,750 字符互为校验」。两条路径：

  * `literal_table.py` —— 静态按 48 字节步长**扫描**镜像
  * shim —— 在真实执行中从寄存器 `EDX` **逐条读取**（每次 +0x30）

白象样本上两者一致（`.scratch/probe-cross-validation.py`）：

    literal_table : 'ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr new_down/"dataz, ...'
    shim 逐条解码 : 'ace("v ba ' + 'im fso, fo' + ', Replace(' + … + ' UsrPrf & ' + 'xtr = xtr '

一致本身就是交叉验证，所以解码文本要发布，而不是只报一个计数。
"""
from __future__ import annotations

from threat_report_agent.simulation_adapters import _decode_observed_records

REC_A = "61636528227620626120"  # "ace(\"v ba "
REC_B = "696D2066736F2C20666F"  # "im fso, fo"


def test_records_are_decoded_in_order() -> None:
    result = _decode_observed_records((REC_A, REC_B))

    assert result["decoded_preview"] == 'ace("v ba im fso, fo'
    assert result["decoded_chars"] == 20
    assert result["distinct_records"] == 2


def test_duplicates_are_counted_once_but_do_not_break_order() -> None:
    """The shim reads 1,028 records from a 623-record table, so repetition is expected."""
    result = _decode_observed_records((REC_A, REC_A, REC_B))

    assert result["distinct_records"] == 2
    assert result["decoded_preview"] == 'ace("v ba im fso, fo'


def test_unparseable_records_are_skipped_not_fatal() -> None:
    result = _decode_observed_records((REC_A, "zz", "", None, REC_B))

    assert result["decoded_records"] == 2
    assert result["decoded_preview"] == 'ace("v ba im fso, fo'


def test_nothing_decodable_returns_no_claim() -> None:
    """An empty result must stay empty rather than publish a zero-length 'recovery'."""
    assert _decode_observed_records(()) == {}
    assert _decode_observed_records(("zz", "not hex")) == {}


def test_preview_is_bounded() -> None:
    """600 chars is enough to show the two paths meet without duplicating the recovered script."""
    record = "41" * 400  # 400 'A' characters
    result = _decode_observed_records((record,))

    assert result["decoded_chars"] == 400
    assert len(str(result["decoded_preview"])) <= 600
