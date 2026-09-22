"""The version block's own claim about the file must reach the body, with its boundary stated.

MEASURED GAP. The PE `RT_VERSION` block of the 白象 sample `64da3378` records:

    OriginalFilename  ss3advd.exe
    InternalName      ss3advd
    ProductName       DndndnD          <- a keyboard mash
    CompanyName       None
    FileVersion       1.01

Both keys and values are already recorded as `string` Evidence rows (the parser reads the block as
UTF-16LE), and the published body mentioned none of them. `OriginalFilename` is the only string in the
binary that links it to the reference document's `http://zolipas.info/advd` path, so its absence cost the
reader the one identifier that matters most for matching this file to a campaign.

The values are published as the sample's CLAIM, never as fact: a version block is written by whoever built
the file and is trivially forged. Pairing is offset-based, so a block that was only partly recovered yields
fewer fields rather than a guessed filename.
"""
from __future__ import annotations

from threat_report_agent.report.reporting import extract_versioninfo_fields


def _string_row(offset: int, text: str, encoding: str = "utf-16le", ident: str = "") -> dict:
    return {
        "id": ident or f"ev-{offset}",
        "kind": "string",
        "value": {"text": text, "encoding": encoding},
        "anchor": {"offset": offset},
    }


def test_the_version_block_is_paired_by_offset() -> None:
    evidence = [
        _string_row(9402, "CompanyName"),
        _string_row(9414, "None"),
        _string_row(9832, "InternalName"),
        _string_row(9844, "ss3advd"),
        _string_row(9852, "OriginalFilename"),
        _string_row(9869, "ss3advd.exe"),
    ]
    fields = extract_versioninfo_fields(evidence)
    assert fields["OriginalFilename"] == "ss3advd.exe"
    assert fields["InternalName"] == "ss3advd"
    assert fields["CompanyName"] == "None"


def test_deliberately_out_of_order_evidence_still_pairs_correctly() -> None:
    """The tuple order is not the file order, so pairing must sort by the recorded offset."""
    evidence = [
        _string_row(9869, "ss3advd.exe"),
        _string_row(9852, "OriginalFilename"),
        _string_row(9844, "ss3advd"),
        _string_row(9832, "InternalName"),
    ]
    fields = extract_versioninfo_fields(evidence)
    assert fields["OriginalFilename"] == "ss3advd.exe"
    assert fields["InternalName"] == "ss3advd"


def test_a_key_without_a_recovered_value_yields_nothing_for_that_key() -> None:
    """A substring must never become the filename: an absent value beats a guessed one."""
    evidence = [
        _string_row(100, "OriginalFilename"),
        _string_row(120, "ProductName"),
        _string_row(140, "DndndnD"),
    ]
    fields = extract_versioninfo_fields(evidence)
    assert "OriginalFilename" not in fields, "a value was taken from a different key"
    assert fields.get("ProductName") == "DndndnD"


def test_a_key_is_never_used_as_another_keys_value() -> None:
    evidence = [
        _string_row(10, "OriginalFilename"),
        _string_row(30, "InternalName"),
        _string_row(50, "ss3advd"),
    ]
    fields = extract_versioninfo_fields(evidence)
    assert "OriginalFilename" not in fields
    assert fields.get("InternalName") == "ss3advd"


def test_rows_without_offsets_are_skipped_rather_than_guessed() -> None:
    evidence = [
        {"kind": "string", "value": {"text": "OriginalFilename", "encoding": "utf-16le"}},
        {"kind": "string", "value": {"text": "ss3advd.exe", "encoding": "utf-16le"}},
    ]
    assert extract_versioninfo_fields(evidence) == {}


def test_the_published_body_states_the_claim_and_its_boundary() -> None:
    document = {
        "report_version": "3.0",
        "case_id": "case-ver",
        "task_id": "task-ver",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 0, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": [
                    {
                        "type": "pe_basics",
                        "format": "PE32",
                        "machine": "0x014c",
                        "entry_rva": 9348,
                        "subsystem": 2,
                        "section_names": [".text", ".data", ".rsrc"],
                    },
                    {
                        "type": "pe_version_info",
                        "fields": {
                            "OriginalFilename": "ss3advd.exe",
                            "InternalName": "ss3advd",
                            "ProductName": "DndndnD",
                            "CompanyName": "None",
                            "FileVersion": "1.01",
                        },
                    },
                ],
            }
        ],
        "trace": {},
    }
    from threat_report_agent.analyst_report import render_official_markdown

    body = render_official_markdown(document)
    assert "ss3advd.exe" in body, "the file's own original filename is not published"
    assert "OriginalFilename" in body
    assert "样本自述" in body, "the version block is not marked as the sample's own claim"
    assert "可伪造" in body, "the reader is not warned that a version block is forgeable"
