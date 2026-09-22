"""A fact the analysis never produced must be RECORDED, not silently accepted.

Root cause (3) behind the benchmark-reading failure: nothing detected it. The compose gate
polices four endpoint-shaped classes, so a scheduled-task name, registry key, path or digest
lifted from another document passed unchanged and became indistinguishable from a recovered
fact. These tests pin the detection and its measured false-positive behaviour.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import (
    compose_gate_violations,
    unprovenanced_fact_tokens,
)

# A deterministic body containing the facts this analysis really produced.
FRAGMENTS = """
## 3. C2 / 网络
- 端点 `http://69.48.228.74/ComHost.exe`
- 端点 `http://69.48.228.74/miaom-c.pdf`
- IPv4 `69.48.228.74`
- SHA256 `6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145`
## 7. 持久化
- 注册表键 `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`
- 落盘路径 `C:\\Users\\Public\\ComHost.exe`
- 计划任务 `/tn ComHostUpdate`
"""


def test_registry_key_absent_from_the_analysis_is_recorded() -> None:
    """The exact class the gate cannot see: a registry key from another document."""
    draft = FRAGMENTS + "\n- 额外键 `HKLM\\Software\\Contoso\\Agent`\n"
    found = unprovenanced_fact_tokens(draft, FRAGMENTS)
    assert any("Contoso" in item for item in found), (
        f"a registry key absent from the analysis was not recorded: {found}"
    )


def test_scheduled_task_name_absent_from_the_analysis_is_recorded() -> None:
    """A benchmark-only task name is the concrete case that was grepped, not derived."""
    draft = FRAGMENTS + "\n- 计划任务 `schtasks /create /tn WindowsUpdateCheck /tr x.exe`\n"
    found = unprovenanced_fact_tokens(draft, FRAGMENTS)
    assert any("WindowsUpdateCheck" in item for item in found), (
        f"a scheduled-task name absent from the analysis was not recorded: {found}"
    )


def test_digest_absent_from_the_analysis_is_recorded() -> None:
    other = "a" * 64
    found = unprovenanced_fact_tokens(FRAGMENTS + f"\n- SHA256 `{other}`\n", FRAGMENTS)
    assert any(other in item for item in found), (
        f"an unknown digest was not recorded: {found}"
    )


def test_a_real_deterministic_body_is_quiet() -> None:
    """The measured false-positive rate must stay at zero on a genuine body.

    Measured on the published Resume body: 1 IPv4 backed, 3 SHA256 backed, 3 URLs of which
    2 backed - the single miss being a URL with a trailing `;` glued on by the sentence.
    Reporting noise here would make the signal worthless, so the punctuation trim is pinned.
    """
    assert unprovenanced_fact_tokens(FRAGMENTS, FRAGMENTS) == []


def test_trailing_sentence_punctuation_does_not_create_a_false_positive() -> None:
    """`http://x/miaom-c.pdf;` is the same fact as `http://x/miaom-c.pdf`."""
    draft = "- 端点 `http://69.48.228.74/miaom-c.pdf`；已恢复。\n"
    fragments = "- 端点 `http://69.48.228.74/miaom-c.pdf`\n"
    assert unprovenanced_fact_tokens(draft, fragments) == []


def test_detection_is_additive_and_does_not_change_the_gate() -> None:
    """The gate's verdict must be unchanged: this is a recorded signal, not a new refusal.

    Rejecting on these classes would risk defeating legitimate narrative for a signal that
    is meant to make a gap visible. If a future change makes the gate fail on a token that
    is merely unprovenanced, this test fails and forces that to be a deliberate decision.
    """
    draft = FRAGMENTS + "\n- 额外键 `HKLM\\Software\\Contoso\\Agent`\n"
    assert unprovenanced_fact_tokens(draft, FRAGMENTS), "precondition: the token is found"
    assert compose_gate_violations(draft, FRAGMENTS) == [], (
        "the compose gate started rejecting unprovenanced-but-not-endpoint facts; that is "
        "a behaviour change with a real risk of suppressing legitimate output"
    )
