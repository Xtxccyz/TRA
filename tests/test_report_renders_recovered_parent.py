"""The published body must state the parent identity the run actually recovered.

The chapter for 父进程伪装（PPID） used to decide whether a parent identity was
recovered by looking for a ``Process32``/``CreateToolhelp32Snapshot`` enumeration
chain *inside the chapter's prose blob*.  That is not how this sample (or the
recovery it feeds) works: ``recover_parent_process_attribute`` names the parent
from a typed ``parent_selection`` on the ``CreateProcessW`` argument trace after
``OpenProcess`` -> ``UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)``
resolved inside one function, and there is no toolhelp enumeration anywhere.

Consequence, on the stored document for task ``1359f2a6`` (which does carry
``parent_selection: explorer.exe``): the published body printed
``UNKNOWN(parent identity)`` -- and the appendix tickets next to it said
"missing evidence: process enumeration, parent identity" -- while the mechanism
claim in the same document read ``parent=explorer.exe``.  The product asserted it
lacked a fact it held.

These tests assert on ``render_official_markdown`` output, not on a helper: the
defect was that helper-level behaviour looked right while the published body was
wrong.  The other half of the contract is just as important: a document that
merely *carries* ``explorer.exe`` as a string must keep printing
``UNKNOWN(parent identity)``.
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS


def _document(*rows: dict[str, object]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-ppid",
        "task_id": "task-ppid",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {"id": "static_triage", "title": "Static Triage", "summary": "", "rows": list(rows)}
        ],
        "trace": {},
    }


def _ppid_chapter(official: str) -> str:
    if "### 父进程伪装（PPID）" not in official:
        return ""
    return official.split("### 父进程伪装（PPID）", 1)[1].split("\n### ", 1)[0]


def _typed_chain_row(parent: str = "explorer.exe") -> dict[str, object]:
    """The claim shape task 1359f2a6 actually stored for the recovered chain."""
    return {
        "type": "behavior_finding",
        "catalog_id": "parent-process-spoofing",
        "finding_status": "CANDIDATE",
        "what": (
            "Resume.pdf.exe.VIR statically recovers a parent-process attribute chain "
            f"`CreateProcessW; attribute=0x00020000; parent={parent}`; "
            "runtime parent identity is unverified."
        ),
        "how": [f"CreateProcessW; attribute=0x00020000; parent={parent}"],
        "transformation_or_control": [f"CreateProcessW; attribute=0x00020000; parent={parent}"],
        "outputs": [parent],
    }


def test_typed_parent_chain_reaches_the_published_body() -> None:
    """The typed chain the run recovered must be named in the published body."""
    official = render_official_markdown(_document(_typed_chain_row()))

    assert "explorer.exe" in official
    assert "UNKNOWN(parent identity)" not in official
    # The appendix slot rewrite must not put the UNKNOWN back either.
    assert "parent=UNKNOWN(parent identity)" not in official


def test_typed_parent_chain_is_named_in_the_ppid_chapter() -> None:
    official = render_official_markdown(_document(_typed_chain_row()))
    chapter = _ppid_chapter(official)

    assert chapter, "expected the PPID chapter to be planned"
    assert "explorer.exe" in chapter
    assert "UNKNOWN(parent identity)" not in chapter


def test_a_bare_image_name_string_is_still_not_parent_identity() -> None:
    """Merely carrying the literal is not proof: keep the UNKNOWN, print no name."""
    official = render_official_markdown(
        _document(
            {
                "type": "string",
                "text": (
                    "explorer.exeInitializeProcThreadAttributeList failed"
                    "UpdateProcThreadAttribute failedCreateProcessW failed"
                    "OpenProcess failedexplorer not foundsnapshot failed"
                ),
                "anchor": {"type": "file_offset", "offset": 306251},
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "parent-process-spoofing Resume.pdf.exe.VIR",
                "how": ["UpdateProcThreadAttribute; attribute=0x00020000; parent=UNKNOWN(parent identity)"],
            },
        )
    )

    assert "UNKNOWN(parent identity)" in official
    assert "explorer.exe" not in official.casefold()


def test_an_untyped_parent_assignment_without_the_attribute_is_not_proof() -> None:
    """``parent=explorer.exe`` with no PARENT_PROCESS attribute stays UNKNOWN."""
    official = render_official_markdown(
        _document(
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "Parent attribute API without a recovered attribute value.",
                "how": "UpdateProcThreadAttribute parent=explorer.exe",
            }
        )
    )

    assert "UNKNOWN(parent identity)" in official
    assert "explorer.exe" not in official.casefold()


def test_the_attribute_and_the_parent_must_come_from_the_same_row() -> None:
    """A parent name in one row plus the attribute in another is not one chain."""
    official = render_official_markdown(
        _document(
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "how": "UpdateProcThreadAttribute attribute=0x00020000 parent=UNKNOWN(parent identity)",
            },
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "how": "string explorer.exe is not parent identity",
            },
        )
    )

    assert "UNKNOWN(parent identity)" in official
    assert "explorer.exe" not in official.casefold()


def test_a_typed_parent_selection_evidence_sample_is_proof() -> None:
    """The join's typed ``parent_selection`` is the discriminator, wherever it sits."""
    official = render_official_markdown(
        _document(
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "Recovered parent-process attribute chain.",
                "how": ["CreateProcessW; attribute=0x00020000"],
                "evidence_samples": [
                    {
                        "kind": "api_argument_trace",
                        "nature": "STATIC_OBSERVED",
                        "value": {
                            "api": "CreateProcessW",
                            "parent_selection": "services.exe",
                            "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                        },
                    }
                ],
            }
        )
    )

    assert "services.exe" in official
    assert "UNKNOWN(parent identity)" not in official


def test_symbolic_parent_process_attribute_reaches_the_published_body() -> None:
    """The name a detection rule targets must be published, not just the immediate.

    ``reporting`` verifies the chain from the recovered *immediate*
    (``attribute=0x00020000``), and that is what the chapter used to print, so a
    reader had to know the mapping.  The symbolic constant lived on a separate
    process-creation row under a different ``catalog_id``, so the PPID chapter
    could not name it.  ``persist_how`` now carries both in one field
    (``attribute=0x00020000 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS``), which is the
    shape asserted here.
    """
    mechanism = (
        "CreateProcessW -> OpenProcess -> UpdateProcThreadAttribute"
        "; attribute=0x00020000 PROC_THREAD_ATTRIBUTE_PARENT_PROCESS; parent=explorer.exe"
    )
    official = render_official_markdown(
        _document(
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": f"Recovered parent-process attribute chain `{mechanism}`.",
                "how": [mechanism],
                "transformation_or_control": [mechanism],
                "outputs": ["explorer.exe"],
            }
        )
    )
    assert "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" in official
    assert "0x00020000" in official
    assert "explorer.exe" in official
    assert "UNKNOWN(parent identity)" not in official


def test_symbolic_name_is_never_inferred_from_the_immediate() -> None:
    """A row carrying only the immediate must NOT gain the symbolic name."""
    official = render_official_markdown(
        _document(
            {
                "type": "behavior_finding",
                "catalog_id": "parent-process-spoofing",
                "finding_status": "CANDIDATE",
                "what": "Recovered parent-process attribute chain.",
                "how": ["CreateProcessW; attribute=0x00020000; parent=explorer.exe"],
                "transformation_or_control": [
                    "CreateProcessW; attribute=0x00020000; parent=explorer.exe"
                ],
                "outputs": ["explorer.exe"],
            }
        )
    )
    assert "0x00020000" in official
    assert "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" not in official
