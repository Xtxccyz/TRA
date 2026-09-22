"""The decode chapter must publish the cross-table completeness verdict - and only when it was measured.

Why this file exists: the sentence "本节的恢复文本没有因只解主表而低报样本" is a COMPLETENESS claim, and
completeness claims are the ones this project keeps getting wrong (every individual fact is true; the false
part is the assertion of wholeness). It may only be printed when the run actually performed the check.

Three states must stay distinct and are each pinned below:

    second_table_check absent          -> say NOTHING about truncation (not checked is not "clean")
    verdict == no_extra_markers        -> publish the measured completeness sentence
    verdict == secondary_adds_markers  -> publish the opposite: the text is NOT the whole picture

The edit that introduced this block also, briefly, turned a neighbouring `elif` into an unconditional
`append`, which would have printed "存在编码/解密线索，但算法、密钥与输出消费者未恢复。" on every sample
that HAS a decode - the exact inverted claim. The last test here guards that boundary.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import (
    AnalystTopic,
    _second_table_check,
    _topic_body,
)


SCRIPT = 'Set fso = CreateObject("Scripting.FileSystemObject") : http://example.invalid/p.php'


def _row(check: dict | None) -> dict:
    """A minimal decode_result row shaped the way the pipeline emits one.

    The URL is not decoration: the chapter's `blob` is built by `_blob`, which reads only the keys
    `what/how/finding/statement/mechanism/transformation_or_control/inputs/outputs/consumers`, and
    `plaintext` is then derived from that blob with `_URL_RE` as the last fallback. A fixture that puts the
    text anywhere else (e.g. in `recovered_text`) renders the "no decode recovered" branch and the test would
    silently stop covering the block it exists for.
    """
    verification: dict = {
        "encoding": "utf16le-asciihex-record-table",
        "decode_chain": ["read 20 UTF-16LE chars at a 48-byte stride"],
        "recovered_chars": 5881,
        "marker_classes": ["filesystem"],
    }
    if check is not None:
        verification["second_table_check"] = check
    return {
        "type": "decode_result",
        # The chapter only sees rows whose catalog_id matches the topic (or whose mechanism maps to it),
        # so without this the fixture renders the "no decode recovered" branch instead of the decoded one.
        "catalog_id": "config-and-crypto",
        "module": "decryption",
        "verification": verification,
        "verification_status": "DECODED_STATIC",
        "how": SCRIPT,
        "outputs": SCRIPT,
        "recovered_text": SCRIPT,
        "decoded_text": SCRIPT,
        "plaintext": SCRIPT,
    }


CLEAN = {
    "tables_found": 2,
    "primary_table_va": "0x00402c08",
    "secondary_table_vas": ["0x0040bb98"],
    "secondary_chars": 770,
    "markers_only_in_secondary": [],
    "verdict": "no_extra_markers",
}

DIRTY = dict(CLEAN, markers_only_in_secondary=["http_transport"], verdict="secondary_adds_markers")


TOPIC = AnalystTopic(
    catalog_id="config-and-crypto",
    title="编码、解密与配置还原",
    status="observed",
    reason="decode result present",
    anchors=("config-and-crypto", "decryption"),
)


def _render(rows: list[dict]) -> str:
    """`_topic_body` returns a LIST of lines, so membership tests must run on the joined text."""
    body = _topic_body(TOPIC, rows, None)
    return "\n".join(str(line) for line in body)


def test_the_check_is_read_out_of_the_verification_projection() -> None:
    assert _second_table_check([_row(CLEAN)]) == CLEAN
    assert _second_table_check([_row(None)]) is None


def test_a_measured_clean_check_publishes_the_completeness_sentence() -> None:
    body = _render([_row(CLEAN)])
    assert "恢复文本的完整性已实测" in body
    assert "0x0040bb98" in body, "the secondary table's address must be named, not alluded to"
    # The sentence must state what it does NOT claim. "not truncated" is not "identical".
    assert "不是「两处内容相同」" in body


def test_a_clean_check_does_not_turn_into_an_absence_claim_about_the_sample() -> None:
    """EC-1 shape: the check answers a question about OUR text, not about the sample's capabilities."""
    body = _render([_row(CLEAN)])
    assert "不代表" in body or "不是" in body, "the sentence must bound itself"
    assert "样本不具备" not in body, "the completeness check must not be read as an absence claim"


def test_a_dirty_check_says_the_text_is_not_the_whole_picture() -> None:
    body = _render([_row(DIRTY)])
    assert "恢复文本不是全集" in body
    assert "恢复文本的完整性已实测" not in body, (
        "both verdicts were published at once, so the reader cannot tell which one holds"
    )


def test_no_check_means_no_claim_at_all() -> None:
    """Silence, not reassurance: an unrun check must not be rendered as a passing check."""
    body = _render([_row(None)])
    assert "完整性已实测" not in body
    assert "不是全集" not in body
    assert "0x0040bb98" not in body


def test_the_verdict_survives_the_real_document_projection() -> None:
    """Integration test across the seam that actually broke.

    MEASURED failure on task `cc6a822b`: the check ran, `evidence.value.verification.second_table_check`
    held `no_extra_markers`, and the snapshot's `object_versions` contained it - but the REVISION DOCUMENT
    contained it **zero** times, because `reporting.build_decode_result_projections` builds a FLAT row and
    did not copy the key. The chapter therefore had nothing to read and stayed silent.

    The unit tests above build their row by hand, which is exactly why they stayed green while the real
    pipeline published nothing: a hand-made fixture asserts the shape I ASSUMED, not the shape the pipeline
    produces. This test goes through `build_decode_result_projections` so the seam is covered.
    """
    from threat_report_agent.report.reporting import build_decode_result_projections

    rows = build_decode_result_projections(
        {
            "e1": {
                "kind": "decode_result",
                "artifact_id": "a1",
                "value": {
                    "source_kind": "encoded_blob",
                    "verification": {
                        "encoding": "utf16le-asciihex-record-table",
                        "decoded_preview": SCRIPT,
                        "second_table_check": CLEAN,
                    },
                    "candidate": {},
                },
            }
        }
    )
    assert rows, "the projector produced no decode_result row"
    assert "second_table_check" in rows[0], (
        "the document projection dropped the completeness verdict again, so the chapter cannot see it"
    )
    assert _second_table_check(rows) == CLEAN

    body = _render([dict(rows[0], catalog_id="config-and-crypto")])
    assert "恢复文本的完整性已实测" in body
    assert "0x0040bb98" in body


def test_the_projection_leaves_the_verdict_absent_when_it_did_not_run() -> None:
    """An absent key must stay absent - not become an empty dict that reads as a passing check."""
    from threat_report_agent.report.reporting import build_decode_result_projections

    rows = build_decode_result_projections(
        {
            "e1": {
                "kind": "decode_result",
                "value": {"verification": {"decoded_preview": SCRIPT}, "candidate": {}},
            }
        }
    )
    assert rows
    assert rows[0].get("second_table_check") is None
    assert _second_table_check(rows) is None
    body = _render([dict(rows[0], catalog_id="config-and-crypto")])
    assert "完整性已实测" not in body


def test_a_sample_with_a_decode_does_not_get_the_no_decode_sentence() -> None:
    """Regression guard for the `elif` that was briefly flattened into an unconditional append.

    "存在编码/解密线索，但算法、密钥与输出消费者未恢复。" is the sentence for a sample where NOTHING was
    decoded. Printing it alongside a 5,881-character recovery inverts the finding.
    """
    body = _render([_row(CLEAN)])
    assert "完整性已实测" in body, (
        "the fixture did not reach the decoded branch, so this test no longer guards the boundary"
    )
    assert "存在编码/解密线索，但算法、密钥与输出消费者未恢复。" not in body
