"""Recovered string facts must reach the published body, verbatim and bounded.

Regression this pins.  Four benchmark facts live in the sample's string layer and
NOWHERE else:

    :Zone.Identifier                 mark-of-the-web alternate data stream
    schtasks/create/tn/tr/sc...      scheduled-task create + self-clean blob
    .tmp                             temp staging name
    Mozilla/5.0 ... Firefox/125.0    HTTP user-agent

Measured on task `1359f2a6` before this fix:

* the evidence ledger holds all four as clean single-value `string` rows, and all
  four evidence ids ARE present in the report document's `trace.evidence_ids`, so
  the bounded evidence view is NOT what drops them;
* `_summarize_evidence_rows` groups by (artifact, module, kind, nature), so all
  2,926 `string` rows collapse into ONE group whose `samples` list takes
  `group[:1]` - exactly one arbitrary string out of 2,926;
* the renderer had no contract for raw string evidence at all, so nothing printed.

The whole lesson of this defect is the same one the environment-gate suite records:
the fact was in the ledger, the projection dropped it, and only the published body
is graded.  These tests therefore assert on `render_official_markdown` output.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    _summarize_evidence_rows,
    build_detection_rule_projection,
    build_string_fact_projection,
)

ZONE_ID = "ev-zone"
TASK_BLOB_ID = "ev-schtasks"
TMP_ID = "ev-tmp"
UA_ID = "ev-ua"

# Verbatim values as the parser stored them for the real sample.
ZONE_ID_VALUE = ":Zone.Identifier"
TASK_BLOB_VALUE = "schtasks/create/tn/tr/sconce/st00:00/fschtasks create failed/run/delete"
TMP_VALUE = ".tmp"
UA_VALUE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0GET"
)


def _string_evidence_row(evidence_id: str, text: str) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "artifact_id": "artifact-1",
        "tool_run_id": "run-1",
        "module": "static_triage",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"encoding": "ascii", "text": text},
        "anchor": {"type": "string", "rva": 1},
    }


def _document(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-strings",
        "task_id": "task-strings",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": rows,
            }
        ],
        "trace": {},
    }


# --- ledger sampling -------------------------------------------------------


def test_string_group_sampling_keeps_operationally_significant_strings() -> None:
    """A 2,926-row string group must not show one arbitrary, low-signal string.

    The pre-fix sampler took ``group[:1]``, which is why fixing every other layer
    still produced a report with no `:Zone.Identifier`.  Noise is placed FIRST and
    the four real facts last, so a fix that merely samples more rows in order
    still fails this test.
    """
    rows = [_string_evidence_row(f"noise-{index}", f"L$@{index}H") for index in range(120)]
    rows += [
        _string_evidence_row(ZONE_ID, ZONE_ID_VALUE),
        _string_evidence_row(TASK_BLOB_ID, TASK_BLOB_VALUE),
        _string_evidence_row(TMP_ID, TMP_VALUE),
        _string_evidence_row(UA_ID, UA_VALUE),
    ]

    summary = _summarize_evidence_rows(rows)
    string_groups = [item for item in summary if item.get("kind") == "string"]
    assert len(string_groups) == 1, "string rows must still collapse to one ledger group"

    samples = string_groups[0]["samples"]
    sampled_ids = {item.get("evidence_id") for item in samples}
    assert {ZONE_ID, TASK_BLOB_ID, TMP_ID, UA_ID} <= sampled_ids, (
        "operationally significant strings were out-sampled by disassembly noise"
    )
    # The group still reports its true size; sampling must not look like the whole set.
    assert string_groups[0]["count"] == len(rows)


# --- published body --------------------------------------------------------


def _published(rows: list[dict[str, object]]) -> str:
    return render_official_markdown(_document(rows))


def test_published_body_carries_motw_zone_identifier() -> None:
    text = _published([_string_evidence_row(ZONE_ID, ZONE_ID_VALUE)])
    assert "Zone.Identifier" in text


def test_published_body_carries_full_scheduled_task_blob_verbatim() -> None:
    """The whole blob must survive: a re-shaped fragment loses /sc, once and /st.

    The old indicator regex matched ``schtasks(?:\\s+...)?`` and, because the blob
    has no whitespace, published the mangled tail
    ``schtasks create failed/run/delete`` - dropping exactly the tokens an analyst
    needs.  Publishing a fragment that no longer exists in the binary is worse
    than publishing the recovered blob verbatim.
    """
    text = _published([_string_evidence_row(TASK_BLOB_ID, TASK_BLOB_VALUE)])
    assert TASK_BLOB_VALUE in text, "the recovered scheduled-task blob must appear verbatim"


def test_published_body_carries_temp_staging_name() -> None:
    text = _published([_string_evidence_row(TMP_ID, TMP_VALUE)])
    assert ".tmp" in text


def test_published_body_carries_recovered_user_agent() -> None:
    text = _published([_string_evidence_row(UA_ID, UA_VALUE)])
    assert "Firefox/125.0" in text


def test_published_body_states_string_facts_are_static_only() -> None:
    """A string in the binary is not evidence the behaviour ran."""
    text = _published(
        [
            _string_evidence_row(ZONE_ID, ZONE_ID_VALUE),
            _string_evidence_row(TASK_BLOB_ID, TASK_BLOB_VALUE),
        ]
    )
    assert "未观察" in text or "static" in text.casefold()


# --- explicit projection ---------------------------------------------------


def test_string_fact_projection_prefers_the_untruncated_variant() -> None:
    """A clipped prefix of a real blob must never win over the blob itself.

    Both of these are genuinely present in the document for the real sample: the
    IOC projection clips a matched run at the first whitespace, so
    ``schtasks/create/tn/tr/sconce/st00:00/fschtasks`` is published as a
    scheduled-task indicator next to the parser's
    ``schtasks/create/tn/tr/sconce/st00:00/fschtasks create failed/run/delete``.
    The first version of this fix kept whichever variant it met first, and the
    report asserted the clipped one - a string that exists nowhere in the binary.
    """
    projection = build_string_fact_projection(
        [
            _string_evidence_row("clipped", "schtasks/create/tn/tr/sconce/st00:00/fschtasks"),
            _string_evidence_row(TASK_BLOB_ID, TASK_BLOB_VALUE),
        ]
    )
    values = [str(item["value"]) for item in projection]
    assert TASK_BLOB_VALUE in values, "the complete blob must be the published variant"
    assert "schtasks/create/tn/tr/sconce/st00:00/fschtasks" not in values, (
        "the clipped prefix must not be published alongside the real blob"
    )


def test_string_fact_projection_carries_evidence_ids_and_boundary() -> None:
    projection = build_string_fact_projection([_string_evidence_row(ZONE_ID, ZONE_ID_VALUE)])
    assert projection, "a MOTW marker must produce a string fact"
    row = projection[0]
    assert row["fact_class"] == "motw"
    assert row["value"] == ZONE_ID_VALUE
    assert row["evidence_ids"] == [ZONE_ID]
    assert row["static_only"] is True
    assert row["boundary"]


def test_published_body_reads_the_explicit_projection() -> None:
    """The document's own projection is authoritative for the published body."""
    document = _document([])
    document["string_facts"] = build_string_fact_projection(
        [
            _string_evidence_row(ZONE_ID, ZONE_ID_VALUE),
            _string_evidence_row(TMP_ID, TMP_VALUE),
        ]
    )
    text = render_official_markdown(document)
    assert "Zone.Identifier" in text
    assert ".tmp" in text


def _detection_rule_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return [row for row in rows if row.get("type") == "detection_rule"]


# --- detection rule --------------------------------------------------------


def _ioc_row(category: str, value: str) -> dict[str, object]:
    return {
        "type": "ioc",
        "classification": "STATIC_DERIVED",
        "category": category,
        "value": value,
        "source": "static_triage/string",
        "evidence_ids": ["ev-1"],
        "anchors": [],
        "static_only": True,
        "confidence": "HIGH",
    }


def test_detection_rule_projection_emits_yara_from_recovered_indicators() -> None:
    """An analyst deliverable needs a detection artefact, not just observations."""
    rules = build_detection_rule_projection(
        [
            _ioc_row("url", "http://69.48.228.74/ComHost.exe"),
            _ioc_row("ipv4", "69.48.228.74"),
            _ioc_row(
                "sha256",
                "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145",
            ),
        ]
    )
    assert rules, "recovered indicators must yield at least one detection artefact"
    yara = [row for row in rules if row.get("rule_format") == "yara"]
    assert yara, "a YARA candidate is expected when a URL and a digest are recovered"
    assert all(row.get("derived_only") is True for row in rules)
    assert all(row.get("evidence_ids") for row in rules)
    body = "\n".join(str(row.get("rule_text") or "") for row in rules)
    assert "rule " in body and "{" in body


def test_detection_rule_projection_is_empty_without_indicators() -> None:
    """No indicators means no rule: never invent detection content."""
    assert build_detection_rule_projection([]) == []


def test_published_body_carries_a_detection_rule_block() -> None:
    document = _document([])
    document["modules"].append(
        {
            "id": "behavior_attack",
            "title": "Behavior / ATT&CK",
            "summary": "",
            "rows": build_detection_rule_projection(
                [
                    _ioc_row("url", "http://69.48.228.74/ComHost.exe"),
                    _ioc_row(
                        "sha256",
                        "6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145",
                    ),
                ]
            ),
        }
    )
    text = render_official_markdown(document)
    assert "rule " in text and "{" in text
