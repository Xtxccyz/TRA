"""The product's correctness verifier: it must catch the measured defect and stay quiet otherwise.

`.scratch/verify-report-correctness.py` proved the concept; `threat_report_agent.report_verification`
is the same checks living inside the product so a report can be verified where it is built, not only by
a human running a scratch script afterwards.

Both directions are pinned. A checker that fires on correct artefacts is worse than none: the first
EC-2 attempt produced twelve findings on a real body and all twelve were wrong, which trains the reader
to ignore the tool exactly when a real finding appears.
"""
from __future__ import annotations

from threat_report_agent.report_verification import (
    correctness_summary,
    verify_report_correctness,
)

SAMPLE_SHA = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"
RESOURCE_SHA = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6"
PROJECTION_SHA = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3"
URL = "http://69.48.228.74/ComHost.exe"


def _document() -> dict:
    """The shape a REPORT DOCUMENT really has.

    A report document carries the file hash as a projected IOC row
    (`{"type": "ioc", "category": "sha256", "source": "static_triage/file_identity"}`) and has NO row
    whose `type` is `file_identity`. The first version of this fixture invented a `file_identity` row,
    so the tests passed while the deployed verifier resolved no sample hash at all - and then reported
    the freshly-corrected rule as self-referential, which the pipeline recorded as `error_count: 1`.
    Every fixture here mirrors `.scratch/probe-report-correctness-record.py` output, not an idealised
    schema.
    """
    return {
        "modules": [
            {"rows": [
                {"type": "ioc", "category": "sha256", "value": SAMPLE_SHA,
                 "source": "static_triage/file_identity", "confidence": "HIGH"},
                {"type": "ioc", "category": "md5", "value": "be68ec2e1d56688ee411dd86e56b490c",
                 "source": "static_triage/file_identity"},
                {"type": "pe_basics", "sha256": SAMPLE_SHA},
            ]},
            {"rows": [{"type": "pe_resources", "entries": [
                {"type_id": 3, "name": "RT_ICON", "count": 9},
            ]}]},
            {"rows": [{"type": "pe_structure", "entries": [
                {"type": 3, "name": 5, "size": 16936, "sha256": RESOURCE_SHA},
            ]}]},
        ]
    }


BAD_RULE = f"""rule threat_static_{PROJECTION_SHA[:16]}
{{
    strings:
        $s0 = "{PROJECTION_SHA}"   // sha256
        $s1 = "{RESOURCE_SHA}"   // sha256
        $s2 = "{URL}"   // url
    condition:
        any of them
}}
"""

GOOD_RULE = f"""rule threat_static_6bb6bfcbe68de690
{{
    strings:
        $s0 = "{SAMPLE_SHA}"   // sha256
        $s1 = "{URL}"   // url
    condition:
        any of them
}}
"""


def test_it_flags_a_self_referential_sha256_indicator() -> None:
    findings = verify_report_correctness(BAD_RULE, _document())
    errors = [item for item in findings if item["severity"] == "ERROR"]
    assert errors, "a rule whose `sha256` indicator is its own name suffix was not flagged"
    text = " ".join(item["title"] + item["detail"] for item in findings)
    assert PROJECTION_SHA[:16] in text, "the self-referential digest was not named"


def test_it_names_a_resource_digest_as_the_internal_digest_it_is() -> None:
    findings = verify_report_correctness(BAD_RULE, _document())
    text = " ".join(item["title"] + item["detail"] + item["evidence"] for item in findings)
    assert RESOURCE_SHA[:22] in text, "the resource digest was not flagged"
    assert "pe_structure" in text, (
        "the finding does not say WHERE the digest came from, so the reader cannot trace it"
    )


def test_it_is_quiet_on_a_correct_rule() -> None:
    findings = verify_report_correctness(GOOD_RULE, _document(), sample_strings=URL)
    assert not [item for item in findings if item["severity"] == "ERROR"], (
        f"the verifier reported errors on a correct rule: {findings}"
    )
    assert not [item for item in findings if "sha256" in item["title"]], (
        f"the verifier questioned a correct file-hash indicator: {findings}"
    )


def test_it_resolves_the_sample_hash_from_a_real_document_shape() -> None:
    """The file hash lives in a projected `ioc` row, not in a `file_identity` row.

    Measured on the deployed verifier: keying the lookup on `type == "file_identity"` resolved
    nothing, so `sample_sha` was empty and the self-reference branch fired on the rule the projection
    fix had just corrected. The pipeline recorded `error_count: 1` on a verified-good report.
    """
    from threat_report_agent.report_verification import _document_identities

    sample, internal = _document_identities(_document())
    assert sample == SAMPLE_SHA, (
        f"the sample hash was not resolved from a real document shape (got {sample!r})"
    )
    assert RESOURCE_SHA.casefold() in internal, "the resource digest was not indexed as internal"


def test_a_rule_named_after_the_sample_hash_is_not_self_referential() -> None:
    """The projection derives the rule name FROM the sample hash, so name and hash coincide.

    Measured on the fixed revision: `rule threat_static_6bb6bfcbe68de690` with
    `$s0 = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"`. The first version of
    the self-reference check flagged exactly this - a false positive on the artefact the check exists
    to produce, and the pipeline recorded it as `error_count: 1` on a correct report.
    """
    findings = verify_report_correctness(GOOD_RULE, _document(), sample_strings=URL)
    assert not findings, (
        f"a rule legitimately named after the sample's own hash was reported: {findings}"
    )


def test_a_rule_named_after_a_projection_fingerprint_is_still_reported() -> None:
    """The defect is narrower than "name matches a digest": the digest must not be the sample hash."""
    body = f"""rule threat_static_{PROJECTION_SHA[:16]}
{{
    strings:
        $s0 = "{PROJECTION_SHA}"   // sha256
        $s1 = "{URL}"   // url
    condition:
        any of them
}}
"""
    findings = verify_report_correctness(body, _document(), sample_strings=URL)
    errors = [item for item in findings if item["severity"] == "ERROR"]
    assert errors, "a rule keyed on a projection fingerprint was not reported"
    # The digest appears in `evidence` (shortened to 24 chars) and the rule name is in `title`, so
    # collect all three fields - asserting on one field alone failed on a working verifier twice.
    text = " ".join(
        item["title"] + " " + item["detail"] + " " + item["evidence"] for item in errors
    )
    assert PROJECTION_SHA[:24] in text, f"the offending digest was not named: {text}"
    assert "OWN name suffix" in text, "the finding does not say what is wrong with the indicator"



def test_a_stated_boundary_is_not_a_truncation_finding() -> None:
    """EC-4 must accept the product's own honest boundary lines."""
    body = (
        "- 导入表模块清单（7 个）：`a.dll`（3）、`b.dll`（95）\n"
        "- 边界：以上为按模块归并后的行为相关导入 19 条，PE 导入表共 136 条（差额为 CRT/运行时符号）。\n"
    )
    findings = verify_report_correctness(body, {})
    assert not findings, f"a correctly stated boundary was reported: {findings}"


def test_a_completeness_claim_with_a_short_list_is_reported() -> None:
    findings = verify_report_correctness("完整清单，共 5 条：\n- `a`\n- `b`\n", {})
    assert findings, "a completeness claim with a shorter list was not reported"
    assert findings[0]["ec"] == "EC-4"


def test_a_literal_indicator_that_cannot_match_is_reported() -> None:
    body = """rule threat_static_x
{
    strings:
        $s0 = "http://10.0.0.1/not-in-sample.bin"   // url
    condition:
        any of them
}
"""
    findings = verify_report_correctness(body, {}, sample_strings=URL)
    assert [item for item in findings if item["ec"] == "EC-5"], (
        "a URL indicator that is not a substring of any recovered string was not reported"
    )


def test_yara_escapes_do_not_produce_a_false_finding() -> None:
    """`SOFTWARE\\\\Microsoft\\\\...` really exists in the sample as `SOFTWARE\\Microsoft\\...`."""
    body = """rule threat_static_x
{
    strings:
        $s0 = "SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\SpyNet"   // registry_subkey
    condition:
        any of them
}
"""
    findings = verify_report_correctness(
        body, {}, sample_strings=r"SOFTWARE\Microsoft\Windows Defender\SpyNet"
    )
    assert not findings, f"a correctly escaped indicator was reported as broken: {findings}"


def test_the_summary_states_what_was_not_checked() -> None:
    """A verifier must not let "no findings" read as "the report is correct"."""
    summary = correctness_summary(verify_report_correctness(GOOD_RULE, _document()))
    assert summary["error_count"] == 0
    assert set(summary["checked"]) == {"EC-4", "EC-5", "EC-6"}
    assert set(summary["not_checked"]) == {"EC-1", "EC-2", "EC-3"}, (
        "the summary claims more coverage than the mechanical checks provide"
    )
    assert summary["skill"] == "analysis-verification"
