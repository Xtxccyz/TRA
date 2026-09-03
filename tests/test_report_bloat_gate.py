from threat_report_agent.reporting import REPORT_MAX_MARKDOWN_BYTES, report_bloat_violations


def test_report_bloat_gate_rejects_oversized_and_raw_dump_documents() -> None:
    violations = report_bloat_violations("## 完整 Strings\n" + ("x" * REPORT_MAX_MARKDOWN_BYTES))
    assert any("exceeds" in item for item in violations)
    assert any("raw-dump" in item for item in violations)


def test_report_bloat_gate_accepts_compact_analyst_document() -> None:
    assert report_bloat_violations("# Report\n\nA concise evidence-backed finding.\n") == []
