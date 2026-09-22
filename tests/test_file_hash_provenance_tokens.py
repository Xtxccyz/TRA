"""A digest is a file hash only when its provenance says the FILE, not an object inside it.

MEASURED DEFECT. `_is_file_hash_source` tested markers as SUBSTRINGS with the marker `"artifact"`, so
`investigation/decoded_artifact` was classified as a file identity. On task `b482617e` (白象 sample
`64da3378`, MD5 `0D466E84…`) the published detection rule therefore contained:

    rule threat_static_bounded_2d3915cdc82e9093 {
      strings:
      $s0 = "2d3915cdc82e909357d44c4de1b8890bd753605c28df11b10299e3fd09d930b9" // sha256
      $s1 = "46dc088910439dad6a0d69da5e64227d04a640845fd1c31e90a7d4340c539fe0" // sha256
      ...
      $s2 = "64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14" // sha256   <- the real one
      condition: any of them
    }

Five of the six values are decoded-payload digests from `investigation/decoded_artifact`, yet every one was
labelled `// sha256`, i.e. published as a file hash a defender would paste into a blocklist. The rule still
fired because the sample's own hash was present, which is why the error was invisible to a "does it work"
check - the same shape as the round-80 defect, one token over.

The fix is a TOKEN comparison: split the source on separators and require a file-identity token, with an
object-digest token vetoing first. Substring matching cannot express the difference between `artifact` and
`decoded_artifact`.
"""
from __future__ import annotations

import pytest

from threat_report_agent.report.reporting import (
    _OBJECT_DIGEST_TOKENS,
    _is_file_hash_source,
    build_detection_rule_projection,
)

SAMPLE = "64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
PAYLOAD_A = "2d3915cdc82e909357d44c4de1b8890bd753605c28df11b10299e3fd09d930b9"
PAYLOAD_B = "46dc088910439dad6a0d69da5e64227d04a640845fd1c31e90a7d4340c539fe0"


@pytest.mark.parametrize(
    "source",
    ["static_triage/file_identity", "file_identity", "artifact/content_sha256"],
)
def test_a_file_identity_source_is_a_file_hash(source: str) -> None:
    assert _is_file_hash_source(source)


@pytest.mark.parametrize(
    "source",
    [
        "investigation/decoded_artifact",
        "investigation/embedded_object",
        "investigation/bytes_read",
        "static_triage/pe_structure",
        "decoded_artifact",
        "embedded_object",
        "",
        "unknown",
    ],
)
def test_an_object_digest_source_is_not_a_file_hash(source: str) -> None:
    assert not _is_file_hash_source(source)


def test_the_artifact_token_does_not_swallow_decoded_artifact() -> None:
    """The exact regression: 'artifact' is a substring of 'decoded_artifact'."""
    assert "artifact" not in _OBJECT_DIGEST_TOKENS or "decoded_artifact" in _OBJECT_DIGEST_TOKENS
    assert not _is_file_hash_source("investigation/decoded_artifact")


def test_the_published_rule_does_not_label_a_payload_digest_as_sha256() -> None:
    """The rule may only carry the file's own hash in a `sha256` slot."""
    iocs = [
        {"category": "sha256", "value": SAMPLE, "source": "static_triage/file_identity"},
        {"category": "sha256", "value": PAYLOAD_A, "source": "investigation/decoded_artifact"},
        {"category": "sha256", "value": PAYLOAD_B, "source": "investigation/decoded_artifact"},
    ]
    projection = build_detection_rule_projection(iocs)
    rule = str(projection[0].get("rule") or projection[0].get("yara") or projection[0])
    sha_lines = [line for line in rule.splitlines() if "// sha256" in line]
    assert sha_lines, "the rule lost every sha256 indicator"
    assert SAMPLE in rule, "the sample's own hash must stay in the rule"
    assert PAYLOAD_A not in rule, "a decoded-payload digest is published as a file hash"
    assert PAYLOAD_B not in rule, "a decoded-payload digest is published as a file hash"
