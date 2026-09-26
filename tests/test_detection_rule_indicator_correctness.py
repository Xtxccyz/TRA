"""EC-5: a detection rule must be able to identify the sample it was written for.

MEASURED DEFECT, on the published revision of task `ce7e310e`. The body's YARA rule declared:

    $s0 = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3" // sha256
    $s5 = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6" // sha256
    sample file_identity.sha256 = 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145

`$s0` is the digest the rule NAME is derived from (`threat_static_0b05c0df699028e6`), so the rule's
first indicator identified the report rather than any file. `$s5` is the digest of PE resource payload
`RT_ICON[5]`. Neither can match the sample as a file hash, and the sample's real SHA-256 was absent
from the rule entirely.

Root cause, measured with `.scratch/probe-ioc-provenance.py`: `_named_digest_values` recursed the whole
Evidence payload, so `pe_structure.value.resources.entries[*].sha256` contributed ELEVEN resource
digests as `sha256` IOCs with `confidence: HIGH` and `source: static_triage/pe_structure` - eleven
values that cannot identify the file, published beside the one that can. The rule then took whichever
`sha256` sorted first.

The 24/24 existence check on this same body could not see any of it: both strings really are in the
text. These tests assert the values, not their presence.
"""
from __future__ import annotations

from threat_report_agent.report.report_verification import verify_report_correctness
from threat_report_agent.report.reporting import (
    _named_digest_values,
    build_detection_rule_projection,
)

SAMPLE_SHA = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"
RESOURCE_SHA = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6"
PROJECTION_SHA = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3"
URL = "http://69.48.228.74/ComHost.exe"


def _pe_value() -> dict:
    """The shape `pe_structure` really has: identity at the top, resource digests nested."""
    return {
        "format": "PE32+",
        "machine": "0x8664",
        "entry_rva": 5152,
        "resources": {
            "count": 11,
            "entries": [
                {"type": 3, "name": i, "size": 1128 * (i + 1), "sha256": RESOURCE_SHA}
                for i in range(1, 10)
            ],
        },
    }


def test_a_nested_resource_digest_is_not_a_file_digest_at_full_depth() -> None:
    """The traversal itself is the defect: demonstrate both behaviours explicitly."""
    full = _named_digest_values(_pe_value())
    shallow = _named_digest_values(_pe_value(), max_depth=1)
    assert full, "the full traversal used to reach the resource digests"
    assert all(value == RESOURCE_SHA for _category, value in full), (
        "fixture no longer reproduces the nested-digest case"
    )
    assert shallow == [], (
        "a digest nested inside `resources.entries[*]` must not be reported as a file digest"
    )


def test_the_rule_carries_the_sample_hash_when_one_was_recovered() -> None:
    iocs = [
        {"category": "sha256", "value": RESOURCE_SHA,
         "source": "static_triage/pe_structure", "evidence_ids": ["ev-pe"]},
        {"category": "sha256", "value": SAMPLE_SHA,
         "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]},
        {"category": "url", "value": URL,
         "source": "static_triage/string", "evidence_ids": ["ev-url"]},
    ]
    rows = build_detection_rule_projection(iocs)
    assert rows, "no rule was generated for a run that recovered a URL"
    rule = str(rows[0]["rule_text"])
    assert SAMPLE_SHA in rule, (
        "the rule does not carry the sample's own SHA-256, so no `sha256` indicator in it can "
        "identify the file"
    )


def test_an_indicator_that_self_references_the_rule_name_is_removed() -> None:
    """The rule name must never collide with a digest the rule lists.

    Two earlier fixtures reached this branch in ways that no longer exist, and each taught something:

    * the first leaked a `pe_structure` digest into the file-hash slot, which `_is_file_hash_source` now
      blocks upstream;
    * the second supplied a file-identity digest that prefixed the name - and the correct behaviour there
      is to KEEP the hash and rename the rule, because dropping a sample's own file hash to protect a
      name inverts the priority.

    Names are now built from descriptive values, never from digests, so the collision cannot arise for a
    digest at all. The invariant that remains, and that this asserts, is the one a reader depends on: no
    `sha256` entry in the block begins the rule's own name suffix.
    """
    iocs = [
        {"category": "sha256", "value": SAMPLE_SHA,
         "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]},
        {"category": "sha256", "value": RESOURCE_SHA,
         "source": "investigation/embedded_object", "evidence_ids": ["ev-child"]},
        {"category": "url", "value": URL,
         "source": "static_triage/string", "evidence_ids": ["ev-url"]},
    ]
    rows = build_detection_rule_projection(iocs)
    assert rows
    rule = str(rows[0]["rule_text"])
    name_suffix = str(rows[0]["rule_name"]).rsplit("_", 1)[-1].casefold()
    declared = [
        line.split('"')[1] for line in rule.splitlines() if "// sha256" in line and '"' in line
    ]
    assert not [value for value in declared if value.casefold().startswith(name_suffix)], (
        "a `sha256` entry begins the rule's own name suffix, so the name describes the rule rather "
        "than the sample"
    )
    assert SAMPLE_SHA in declared, "the sample's file hash is missing from the rule"
    assert URL in rule, "the URL pivot was dropped"


def test_a_resource_digest_never_reaches_the_rule_as_sha256() -> None:
    """End-to-end: what the projection publishes must not be a resource digest labelled sha256."""
    iocs = [
        {"category": "sha256", "value": RESOURCE_SHA,
         "source": "static_triage/pe_structure", "evidence_ids": ["ev-pe"]},
        {"category": "sha256", "value": SAMPLE_SHA,
         "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]},
    ]
    rows = build_detection_rule_projection(iocs)
    rule = str(rows[0]["rule_text"])
    declared = [
        line.split('"')[1]
        for line in rule.splitlines()
        if "// sha256" in line and '"' in line
    ]
    assert RESOURCE_SHA not in declared, (
        "a PE resource-payload digest is declared as a `sha256` rule indicator"
    )
    assert SAMPLE_SHA in declared, "the sample's file hash is missing from the rule"


# ------------------------------------------------------------------------------------------------
# The verifier itself.  A checker is only worth having if it catches the defect it was written for
# and stays quiet on a correct artefact, so both directions are pinned here.
#
# THESE FOUR TESTS USED TO LOAD `.scratch/verify-report-correctness.py` AND CALL ITS `check_broken_indicators`,
# which reached Postgres through `docker exec psql`. That made a tracked test depend on (a) a GITIGNORED file - absent
# from any fresh checkout - and (b) a running container stack, and it graded the product with an oracle copy rather
# than with the shipped checker. They now call `report.report_verification.verify_report_correctness`, which is the
# module `report/revision_writer.py` actually runs, and every original assertion is kept.
# ------------------------------------------------------------------------------------------------

SAMPLE_IDENTITY_IOC = {
    "type": "ioc",
    "category": "sha256",
    "value": SAMPLE_SHA,
    "source": "static_triage/file_identity",
    "confidence": "HIGH",
}


BAD_RULE_BODY = f"""
### 检测规则建议

rule threat_static_{PROJECTION_SHA[:16]}
{{
    strings:
        $s0 = "{PROJECTION_SHA}"   // sha256
        $s5 = "{RESOURCE_SHA}"   // sha256
        $s1 = "http://69.48.228.74/ComHost.exe"   // url
    condition:
        any of them
}}
"""

GOOD_RULE_BODY = f"""
### 检测规则建议

rule threat_static_comhost
{{
    strings:
        $s0 = "{SAMPLE_SHA}"   // sha256
        $s1 = "http://69.48.228.74/ComHost.exe"   // url
    condition:
        any of them
}}
"""


def test_the_verifier_flags_a_self_referential_and_resource_digest_indicator() -> None:
    # The fixture mirrors the real document: the sample identity as the product projects it (an IOC row whose source is
    # a file hash) AND the resource tree that owns the resource digest. Without the resource entry the verifier cannot
    # know the digest is internal - which is exactly why the real capture flagged `$s0` as ERROR and `$s5` as WARN.
    document = {
        "modules": [
            {"rows": [SAMPLE_IDENTITY_IOC,
                      {"type": "pe_basics", "sha256": SAMPLE_SHA,
                       "md5": "be68ec2e1d56688ee411dd86e56b490c"}]},
            {"rows": [{"type": "pe_resources", "entries": [
                {"type_id": 3, "name": "RT_ICON", "count": 9, "total_size": 172865,
                 "max_entropy": 7.93893},
            ]}]},
            {"rows": [{"type": "pe_structure", "entries": [
                {"type": 3, "name": 5, "size": 16936, "sha256": RESOURCE_SHA},
            ]}]},
        ]
    }
    findings = verify_report_correctness(BAD_RULE_BODY, document)
    errors = [item for item in findings if item["severity"] == "ERROR"]
    assert errors, "the verifier did not flag a rule whose `sha256` indicator is its own name suffix"
    joined = " ".join(item["title"] + item["detail"] + item["evidence"] for item in findings)
    assert PROJECTION_SHA[:16] in joined, "the self-referential indicator was not named"
    # The finding quotes the digest truncated (`168d16f912e21ee7d521f5d0...`), so match on the head
    # rather than the full value - the first version of this assertion failed on a working verifier.
    assert RESOURCE_SHA[:22] in joined, "the resource digest was not flagged"
    assert "pe_structure" in joined, (
        "the finding does not say WHERE the digest came from, so the reader cannot trace it"
    )


def test_the_verifier_is_quiet_on_a_correct_rule() -> None:
    """A verifier that always fires trains the reader to ignore it - the EC-2 lesson."""
    document = {"modules": [{"rows": [SAMPLE_IDENTITY_IOC,
                                      {"type": "pe_basics", "sha256": SAMPLE_SHA,
                                       "md5": "be68ec2e1d56688ee411dd86e56b490c"}]}]}
    findings = verify_report_correctness(GOOD_RULE_BODY, document)
    assert not [item for item in findings if item["severity"] == "ERROR"], (
        f"the verifier reported errors on a correct rule: {findings}"
    )
    assert not any(
        "sha256" in item["title"] for item in findings
    ), f"the verifier questioned a correct file-hash indicator: {findings}"


def test_the_sample_identity_is_read_from_the_pe_header_row_when_there_is_no_ioc_row() -> None:
    """MEASURED (2026-09-26): the identity used to be resolved ONLY from an IOC row with a file-hash source.

    A document that carries it on the `pe_basics` row - the shape this file's fixtures use, and the shape of any
    document written before the IOC projection existed - resolved NOTHING, so the row's own digest landed in `internal`
    and the check reported a rule built from the SAMPLE'S OWN HASH as an ERROR. A gate that fires on a correct rule is
    the EC-2 failure mode, and the plan's M06 makes this check a gate. The digest must also never be listed as an
    internal object once it IS the sample identity.
    """
    without_ioc = {"modules": [{"rows": [{"type": "pe_basics", "sha256": SAMPLE_SHA}]}]}
    findings = verify_report_correctness(GOOD_RULE_BODY, without_ioc)
    assert not [item for item in findings if item["severity"] == "ERROR"], (
        f"a rule built from the sample's own digest was flagged when the identity came from pe_basics: {findings}"
    )
    # The direction that must NOT change: a digest the document records for an INTERNAL object is still an error.
    internal_only = {"modules": [{"rows": [
        {"type": "pe_basics", "sha256": SAMPLE_SHA},
        {"type": "pe_structure", "entries": [{"type": 3, "name": 5, "size": 16936, "sha256": RESOURCE_SHA}]},
    ]}]}
    body = f'rule r\n{{\n    strings:\n        $s5 = "{RESOURCE_SHA}"   // sha256\n    condition:\n        any of them\n}}'
    assert [item for item in verify_report_correctness(body, internal_only) if item["severity"] == "ERROR"], (
        "an internal object digest must still be reported"
    )


def test_the_verifier_accepts_a_stated_boundary_as_a_boundary() -> None:
    """EC-4 must not fire on the product's own honest boundary lines.

    The first version of the count check flagged
    `边界：以上为…19 条，PE 导入表共 136 条（差额为 …）` - a line that declares 136 and lists nothing,
    and is exactly right. Reporting it is the same defect the check exists to find.
    """
    findings = verify_report_correctness(
        "- 导入表模块清单（7 个）：`a.dll`（3）、`b.dll`（95）\n"
        "- 边界：以上为按模块归并后的行为相关导入 19 条，PE 导入表共 136 条（差额为 CRT/运行时符号）。\n"
    )
    assert not findings, f"a correctly stated boundary was reported: {findings}"


def test_the_verifier_flags_a_completeness_claim_with_a_short_list() -> None:
    """The other direction: claiming a total while listing fewer, with no boundary, is EC-4."""
    findings = verify_report_correctness("完整清单，共 5 条：\n- `a`\n- `b`\n")
    assert [item for item in findings if item["ec"] == "EC-4"], (
        "a completeness claim with a short list was not reported"
    )
