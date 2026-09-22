"""The compose gate must reject a draft that DENIES a fact the fragments contain.

This is the defect behind the delivered report
`reports/Resume.pdf.exe.VIR.分析报告.md`.  Its section 6.4 states that the sample's
static evidence contains no IPv4 address, no domain, no URL and no C2 endpoint, and
slot S4 concludes the same.  All of that is false for this sample: the task's own
evidence held 7 rows containing ``http://69.48.228.74/ComHost.exe`` recovered by the
XOR config decoder, and the deterministic fragments contain both C2 URLs.

`compose_gate_violations` had four failure classes, all of which police what a draft
ADDS (novel endpoints, novel images, novel flags, upgraded candidates).  None policed
what a draft DENIES, so a report could tell an analyst "there is no C2" while the
product's own fragments contained one - the most misleading thing an analyst report
can do, because the reader stops looking.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    absence_claim_violations,
    compose_gate_violations,
)

FRAGMENTS_WITH_C2 = """
### 恢复到的字符串事实

- 远程可执行文件 URL：`http://69.48.228.74/ComHost.exe`
- 远程 URL：`http://69.48.228.74/miaom-c.pdf`
- 解码得到的端点：`http://69.48.228.74/ComHost.exe`（C2 IPv4 `69.48.228.74`）
- 恢复到的调用序列：`CreateProcessW`、`WinHttpOpen`
"""

FRAGMENTS_NO_C2 = """
### 恢复到的字符串事实

- 恢复到的调用序列：`CreateProcessW`、`LoadLibrary`
- 注册表路径：`SOFTWARE\\Microsoft\\Windows Defender\\SpyNet`
"""

# The delivered report's own wording (section 6.4), with the C2 endpoints spelled out
# so the claim is about the class the fragments actually contain.
DELIVERED_FALSE_CLAIM = (
    "样本静态证据中**未出现**：IPv4 地址 69.48.228.74、域名、"
    "URL http://69.48.228.74/ComHost.exe、C2 端点。"
    "**这些一律不作为结论或 IOC 提供。**"
)

DELIVERED_SLOT_S4 = (
    "| **S4** | 是否存在网络下载 | 队列判 `STATIC_BOUNDARY` | "
    "与 §6.4 一致：未见 URL http://69.48.228.74/miaom-c.pdf。 |"
)

# The same class-level denial WITHOUT quoting a literal.  Used for the
# "fragments really lack it" case, because a claim that quotes a literal absent from
# the fragments is already (correctly) rejected by the pre-existing novel-endpoint
# class - a different rule from the one under test here.
CLASS_ONLY_DENIAL = (
    "样本静态证据中未出现：IPv4 地址、域名、URL、C2 端点。"
    "这些一律不作为结论或 IOC 提供。"
)


# --- the defect this closes -------------------------------------------------


def test_delivered_false_claim_is_now_rejected() -> None:
    """The delivered sentence must fail the gate when the C2 is present."""
    violations = compose_gate_violations(DELIVERED_FALSE_CLAIM, FRAGMENTS_WITH_C2)
    assert violations, "a draft denying a recovered C2 must not pass the gate"
    assert any("denies a fact" in item for item in violations), violations


def test_delivered_slot_claim_is_now_rejected() -> None:
    """The same denial in a table cell must also fail."""
    violations = absence_claim_violations(DELIVERED_SLOT_S4, FRAGMENTS_WITH_C2)
    assert violations, "a cell claiming the recovered URL is absent must not pass"


def test_a_bare_class_denial_is_rejected_when_the_class_is_present() -> None:
    """A denial naming only the class (no literal value) must still be caught.

    The delivered report never repeated the IP; it listed the fact CLASSES it claimed
    were absent.  The check must therefore also fire on a class-only denial sitting in
    a report whose fragments contain that class.
    """
    draft = "样本静态证据中未出现：IPv4 地址、URL、C2 端点。这些一律不作为 IOC 提供。"
    violations = absence_claim_violations(draft, FRAGMENTS_WITH_C2)
    assert violations, "a class-only denial must be judged against the fragments"


# --- the honest cases must still pass ---------------------------------------


def test_denial_passes_when_the_fragments_really_lack_the_fact() -> None:
    """A truthful absence claim is exactly what a good report should be able to make."""
    assert compose_gate_violations(CLASS_ONLY_DENIAL, FRAGMENTS_NO_C2) == []


def test_unrelated_absence_claim_about_present_endpoints_passes() -> None:
    """Only the fact class the claim is ABOUT may disqualify it.

    "no runtime egress was observed" next to a recovered URL is correct and
    important: the URL is present in the file, the connection was never observed.
    The gate must not reject it merely because a URL sits in the same sentence.
    """
    draft = (
        "已恢复 C2 端点 `http://69.48.228.74/ComHost.exe`。"
        "本次静态分析未观察到任何运行时外联或成功连接。"
    )
    assert compose_gate_violations(draft, FRAGMENTS_WITH_C2) == []


def test_absence_claim_about_an_unrelated_class_passes() -> None:
    """A denial about registry keys must not be judged by the endpoint class."""
    draft = "样本中未出现持久化注册表运行键。已恢复 URL `http://69.48.228.74/ComHost.exe`。"
    assert absence_claim_violations(draft, FRAGMENTS_WITH_C2) == []


def test_gate_is_unchanged_for_drafts_without_absence_claims() -> None:
    baseline = "本样本恢复了 `http://69.48.228.74/ComHost.exe` 与 `CreateProcessW`。"
    assert compose_gate_violations(baseline, FRAGMENTS_WITH_C2) == []


def test_absence_check_is_inert_on_empty_inputs() -> None:
    assert absence_claim_violations("", FRAGMENTS_WITH_C2) == []
    assert absence_claim_violations(DELIVERED_FALSE_CLAIM, "") == []


def test_novel_endpoint_is_still_rejected() -> None:
    """The pre-existing class must not regress."""
    draft = "外联 `http://evil.test/payload.exe`。"
    violations = compose_gate_violations(draft, FRAGMENTS_WITH_C2)
    assert any("not in composed fragments" in item for item in violations), violations
