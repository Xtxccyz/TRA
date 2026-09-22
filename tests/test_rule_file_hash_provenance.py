"""A file-hash indicator must come from a FILE identity, not from any nested object digest.

MEASURED, task `50673002` (a fresh run of the Resume sample through the current pipeline). The
published YARA rule was:

    rule threat_static_0b05c0df699028e6
        $s0 = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3" // sha256
        $s5 = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6" // sha256

Both are PE resource-payload digests, and the sample's own hash
(`6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145`) is not in the rule at all.

WHY THE ROUND-80 FIX DID NOT CATCH THIS. That fix added `_named_digest_values(..., max_depth=1)`, which
does work - called on the same payload it returns 0 digests where the default returns 11. But the
resource digests reach the document through a DIFFERENT path: the product materialises each PE resource
as a child artifact and records `investigation/embedded_object` and `investigation/bytes_read` evidence
rows carrying their own `sha256`. So there are (at least) three producers of `sha256`-labelled IOCs:

    static_triage/file_identity        the sample            <- the only one that IS a file hash
    static_triage/pe_structure         fixed in round 80      <- resource payload digests
    investigation/embedded_object      NOT fixed              <- child artifact digests
    investigation/bytes_read           NOT fixed              <- extracted-buffer digests

Fixing one producer at a time is the patch-per-instance habit the objective forbids. The durable rule is
at the CONSUMER: a rule's `sha256` slot is a FILE hash, so it may only take a value whose provenance says
file identity. This pins that rule and the projections it depends on.
"""
from __future__ import annotations

from threat_report_agent.reporting import build_detection_rule_projection

SAMPLE_SHA = "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145"
RESOURCE_SHA = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3"
CHILD_SHA = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6"
URL = "http://69.48.228.74/ComHost.exe"


def _iocs() -> list[dict]:
    """The real mixture the current pipeline produces, in the order it sorts them.

    Category order puts every `sha256` first, sorted by value, so `0b05c0df` beats `6bb6bfcb` and wins
    the rule's file-hash slot. That is exactly how a resource digest ended up as the file indicator.
    """
    return [
        {"category": "sha256", "value": RESOURCE_SHA,
         "source": "static_triage/pe_structure", "evidence_ids": ["ev-pe"]},
        {"category": "sha256", "value": CHILD_SHA,
         "source": "investigation/embedded_object", "evidence_ids": ["ev-child"]},
        {"category": "sha256", "value": SAMPLE_SHA,
         "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]},
        {"category": "url", "value": URL,
         "source": "static_triage/string", "evidence_ids": ["ev-url"]},
    ]


def _rule_text(iocs: list[dict]) -> str:
    rows = build_detection_rule_projection(iocs)
    assert rows, "no rule was generated"
    return str(rows[0]["rule_text"])


def test_a_child_object_digest_never_takes_the_file_hash_slot() -> None:
    """The round-80 fix covered `pe_structure`; a child artifact digest reached the same slot."""
    rule = _rule_text(_iocs())
    declared = [
        line.split('"')[1] for line in rule.splitlines() if "// sha256" in line and '"' in line
    ]
    assert CHILD_SHA not in declared, (
        "a child-artifact digest (`investigation/embedded_object`) is declared as the rule's `sha256`"
    )
    assert RESOURCE_SHA not in declared, (
        "a PE resource-payload digest (`static_triage/pe_structure`) is declared as the rule's `sha256`"
    )
    assert SAMPLE_SHA in declared, (
        "the sample's own file hash is missing from the rule, so no `sha256` indicator in it can "
        "identify the file"
    )


def test_the_rule_name_is_not_derived_from_a_resource_digest() -> None:
    """The name is what an analyst greps for; naming a rule after a decoy digest is misleading.

    Observed behaviour after the provenance filter: with a descriptive value available the name comes
    from that (`threat_static_http_69_48_228_74_ComHost_exe`); with only a file hash it becomes
    `threat_static_bounded_<hash>` rather than `threat_static_<hash16>`. Either way the name never
    carries a resource or child digest.
    """
    rows = build_detection_rule_projection(_iocs())
    name = str(rows[0]["rule_name"])
    assert RESOURCE_SHA[:16] not in name, (
        "the rule is named after a PE resource-payload digest rather than the sample"
    )
    assert CHILD_SHA[:16] not in name, "the rule is named after a child-artifact digest"


def test_a_file_hash_with_no_descriptive_value_still_produces_a_rule() -> None:
    """MEASURED: this shape emitted NO rule at all.

    `{"category": "sha256", "value": <sample>, "source": "static_triage/file_identity"}` alone produced
    zero rows while the same input plus a URL produced one. Cause: the fallback rule name WAS the digest,
    the collision filter then dropped that digest, and the re-add guard refused it because
    `sample.casefold().startswith(name_suffix)` is trivially true when the name is derived from the
    sample. A detection artefact silently disappeared for a shape that had a perfectly good file hash.

    The invariant is that the artefact exists and its `sha256` entry is the file hash. The defensive name
    in this shape is `threat_static_bounded_<hash>` - a LABEL that deliberately cannot collide with the
    pre-filter name, and the digest is present in `strings:` where it does the work. An earlier version of
    this test asserted the name does not end with the digest, which failed on a correct fix: the point is
    that the digest is a matchable string, not that it is absent from the label.
    """
    iocs = [{"category": "sha256", "value": SAMPLE_SHA,
             "source": "static_triage/file_identity", "evidence_ids": ["ev-id"]}]
    rows = build_detection_rule_projection(iocs)
    assert rows, "a sample whose only recovered indicator is its own hash produced no rule"
    rule = str(rows[0]["rule_text"])
    declared = [
        line.split('"')[1] for line in rule.splitlines() if "// sha256" in line and '"' in line
    ]
    assert declared == [SAMPLE_SHA], (
        f"the rule's `sha256` entry is not the sample's file hash: {declared}"
    )
    assert "condition:" in rule and "any of them" in rule, "the rule has no usable condition"
    assert str(rows[0]["rule_name"]).startswith("threat_static_"), "the rule name shape changed"
