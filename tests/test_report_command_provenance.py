"""A string-derived image name must not be published as a recovered command line.

Regression this pins.  On task ``45cbd992`` the published report's conclusion said:

    静态已恢复：…；恢复到的进程命令行 `FoxitPDFReader.exe`（运行时未观察）。

That claim was false.  Measured over all 38,407 evidence rows of that run:

* all **30** ``api_argument_trace`` rows for ``CreateProcessW`` carry ``command: null``;
* the only row yielding a command at all is a bare string literal
  ``{"encoding": "utf-16le", "text": "FoxitPDFReader.exe"}``, reached through
  ``_process_command_text``'s ``value["text"]`` fallback;
* all 12 command-bearing mechanism strings read
  ``creation_flags=UNKNOWN(creation_flags)``, with **zero** occurrences of
  ``creation_flags=0x``.

Important nuance that shapes the fix: minting a HOW row from flags plus an image
string is **deliberate, tested** product behaviour - three tests named after the
sample's own string assert it
(``test_persist_how_claim_specs_mint_process_from_flags_and_image_string``,
``test_process_seed_stamp_and_emu_from_flags_and_foxit_string``,
``test_persist_how_prefers_recovered_flags_over_specialist_token``).  An earlier
attempt suppressed the minting and was reverted.  What is *not* acceptable is the
**wording**: an inferred image name must not be asserted as a recovered command line,
because that is an operational IOC an analyst would act on.

The discriminator used is carried by the mechanism string itself: when the command
came from a typed process-creation argument trace, the same string also carries the
recovered flag word.  No document-wide scan is involved - that approach was tried and
reverted for bypassing the product's own evidence contracts.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS


def _document(*rows: dict[str, object]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-cmd",
        "task_id": "task-cmd",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {"id": "execution", "title": "Execution", "summary": "", "rows": list(rows)}
        ],
        "trace": {},
    }


def _process_row(mechanism: str) -> dict[str, object]:
    """The row shape the renderer actually reads.

    The real document nests the prose under ``findings`` (``_blob`` reads a row's
    ``how``/``transformation_or_control``, and chapter rows carry ``findings``), so the
    fixture mirrors that rather than putting the string only at the top level.
    """
    finding = {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "finding_status": "CANDIDATE",
        "what": f"child-process construction `{mechanism}`",
        "how": [mechanism],
        "transformation_or_control": [mechanism],
    }
    return {
        "type": "behavior_finding",
        "catalog_id": "process-creation",
        "finding_status": "CANDIDATE",
        "what": f"child-process construction `{mechanism}`",
        "how": [mechanism],
        "transformation_or_control": [mechanism],
        "findings": [finding],
    }


def test_string_derived_image_is_not_published_as_a_recovered_command() -> None:
    """The exact shape task 45cbd992 stored: a command with UNKNOWN flags."""
    official = render_official_markdown(
        _document(
            _process_row(
                "CreateProcessW command=FoxitPDFReader.exe; "
                "creation_flags=UNKNOWN(creation_flags); fallback=UNKNOWN(fallback)"
            )
        )
    )
    assert "恢复到的进程命令行" not in official, (
        "a command minted without a typed trace must not be called recovered"
    )
    # The observation is still reported, as an inference, and is labelled as one.
    assert "FoxitPDFReader.exe" in official
    assert "进程创建相关镜像名" in official


def test_typed_command_with_recovered_flags_is_still_called_recovered() -> None:
    """Positive control: a real typed command with recovered flags keeps the stronger wording.

    Note the command used here is an image path, not the sample's URL payload.  That is
    deliberate and it records a separate known limitation: ``_looks_like_a_process_command``
    returns **False** for ``http://69.48.228.74/ComHost.exe``, which is the command the
    benchmark report actually recovered for this sample.  A URL-shaped command is
    therefore dropped from the conclusion line entirely - a real gap, tracked separately,
    and NOT something this fix may paper over.
    """
    official = render_official_markdown(
        _document(
            _process_row(
                "CreateProcessW command=C:\\Users\\u\\AppData\\Local\\Temp\\ComHost.exe; "
                "creation_flags=0x09080008; fallback=UNKNOWN(fallback)"
            )
        )
    )
    assert "恢复到的进程命令行" in official
    assert "ComHost.exe" in official
    assert "进程创建相关镜像名" not in official


def test_no_command_means_no_command_claim_at_all() -> None:
    """UNKNOWN(command) must not be dressed up as either wording."""
    official = render_official_markdown(
        _document(
            _process_row(
                "CreateProcessW command=UNKNOWN(command); "
                "creation_flags=UNKNOWN(creation_flags); fallback=UNKNOWN(fallback)"
            )
        )
    )
    assert "恢复到的进程命令行" not in official
    assert "进程创建相关镜像名" not in official
