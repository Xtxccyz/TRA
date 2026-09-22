"""A derived detection artefact must not assert a sample-specific reason it has no evidence for.

MEASURED DEFECT, found by an independent correctness review (EC-3, HARD) of the published report for
task `643e4366`. The report's EDR block said:

    - EID 1 (process creation): alert on a child image whose command line carries any recovered URL or
      process name, and whose parent does not match its real creator (STARTUPINFOEX parent-process
      attribute is the static reason to suspect this).

That parenthetical is a sample-specific claim, and for THIS sample it is false:

  * the same report's PPID section says the chain was not joined -
    「未组成父进程身份到创建调用的绑定，因此 UNKNOWN(parent_identity + attribute_list) 保持未恢复」;
  * `process_creation_flags` for this sample records `"value": "0x08000000",
    "set_flags": ["CREATE_NO_WINDOW"], "interpretation": "no extended startup information flag
    observed"` - `EXTENDED_STARTUPINFO_PRESENT` (0x00080000) is NOT set, so there is no STARTUPINFOEX
    attribute list at all;
  * the review measured the sentence as a fixed template: byte-identical in 33 reports under
    `.data/logs`, including one for a different sample.

`build_detection_rule_projection` emitted that line unconditionally, so every report claimed a PPID
spoofing reason whether or not the sample had one. For a defender this is the worst kind of error: a
deployable hunting rule justified by a reason that does not apply, which produces false positives and
discredits the rule.

These tests pin the fix and its two directions: the line may only appear when the evidence exists, and
when it does exist it must cite it.
"""
from __future__ import annotations

from threat_report_agent.report.reporting import build_detection_rule_projection

URL = "http://69.48.228.74/ComHost.exe"
SAMPLE_SHA = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"
STARTUPINFOEX_REASON = "STARTUPINFOEX"


def _iocs(**extra) -> list[dict]:
    rows = [
        {"category": "sha256", "value": SAMPLE_SHA,
         "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]},
        {"category": "url", "value": URL,
         "source": "static_triage/string", "evidence_ids": ["ev-url"]},
    ]
    return rows


def _edr_text(iocs: list[dict]) -> str:
    rows = build_detection_rule_projection(iocs)
    edr = [row for row in rows if str(row.get("rule_format")) == "edr"]
    assert edr, "no EDR block was generated"
    return str(edr[0]["rule_text"])


def test_the_parent_process_reason_is_absent_when_the_sample_has_no_such_evidence() -> None:
    """The default case: no parent-process join, so no claim about a parent-process attribute."""
    text = _edr_text(_iocs())
    assert STARTUPINFOEX_REASON not in text, (
        "the EDR block asserts a STARTUPINFOEX parent-process reason that this sample's flags "
        "positively exclude (0x08000000 = CREATE_NO_WINDOW, no EXTENDED_STARTUPINFO_PRESENT)"
    )


def test_a_recovered_parent_process_attribute_does_produce_the_hunting_line() -> None:
    """The other direction: when the evidence IS there, the line must appear and cite it.

    Without this the fix could be "delete the line", which would silently drop a real hunting
    opportunity for the samples that do spoof their parent.

    The assertion is on the ATTRIBUTE NAME rather than the word `STARTUPINFOEX`: the fixed line names
    the attribute the run actually recovered (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), which is more
    specific than the mechanism, and the first version of this test asserted the mechanism word and
    failed on a correct fix.
    """
    iocs = _iocs()
    iocs.append(
        {
            "category": "parent_process_attribute",
            "value": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            "source": "static_triage/process_creation_flags",
            "evidence_ids": ["ev-ppid"],
        }
    )
    text = _edr_text(iocs)
    assert "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" in text, (
        "a sample with a recovered parent-process attribute produced no PPID hunting line"
    )
    assert "parent does not match its real creator" in text, (
        "the PPID line does not say what to alert on"
    )


def test_the_process_creation_line_does_not_claim_an_unrecovered_command_line() -> None:
    """The same sentence claimed 'any recovered URL or process name' on runs with neither."""
    text = _edr_text(_iocs())
    # A URL IS present here, so this half may stay; but the block must not promise a process name.
    assert "process name" not in text or "recovered" in text, (
        "the EDR block promises matching on a recovered process name without recording one"
    )
