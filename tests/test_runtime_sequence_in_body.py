"""The published body must carry the static runtime sequence.

MEASURED GAP against the named depth benchmark. `D:\\test\\20260730_Resume_恶意样本分析报告.md` weighs
section 二、还原完整程序运行时序链路 most heavily (2.1 启动加载 / 2.2 CRT 初始化 / 2.3 用户主逻辑初始化 /
2.4 核心恶意逻辑完整时序 / 2.5 关键跳转逻辑), and the published body had **no equivalent section at all**.

The data is not missing - it is in the document and unreachable from the body. Measured on task
`50673002`'s stored document: 16 `runtime_phase` rows, each carrying
`{type, id, title, status, how, catalog_ids, runtime_observed}`, forming an ordered chain:

    Phase 1 — startup / loader            SUPPORTED
    Phase 2 — environment / anti-analysis CANDIDATE
    Phase 3 — decode / config             CANDIDATE
    Phase 4 — download / transport        CANDIDATE
    Phase 5 — process creation / PPID     CANDIDATE
    Phase 6 — failure fallback            UNKNOWN
    Phase 7 — unique OS thread / callback SUPPORTED
    Phase 8 — loop / repeat               CANDIDATE

Cause: two renderers exist and publishing uses the one without this section.
`reporting._document_to_v3_markdown` -> `_append_v3_gold_flow` renders
`### Runtime sequence (static reconstruction)`, but `analyst_report.render_official_markdown` - the
Chinese analyst body that `_create_report_revision` actually publishes - calls only
`render_analyst_chapters`, which never emits it. This is the round-77 import-module defect in a new
place: a complete deterministic projection that the published renderer has no contract for.

Assertions are on the PUBLISHED body, because that is what the objective grades.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown

PHASES = [
    {
        "type": "runtime_phase", "id": "startup", "status": "SUPPORTED", "runtime_observed": False,
        "title": "Phase 1 — startup / loader",
        "catalog_ids": ["loader-and-api-resolution", "memory-and-mapping"],
        "how": "statically recovers a dynamic API resolution: `kernel32!GetTempPath2W` consumed by `JMP R8`",
    },
    {
        "type": "runtime_phase", "id": "anti_analysis", "status": "CANDIDATE", "runtime_observed": False,
        "title": "Phase 2 — environment / anti-analysis",
        "catalog_ids": ["environment-guard"],
        "how": "environment-guard FUN_140038910@140038910; threshold=static observed evidence",
    },
    {
        "type": "runtime_phase", "id": "thread_and_callback", "status": "SUPPORTED",
        "runtime_observed": False,
        "title": "Phase 7 — unique OS thread / callback",
        "catalog_ids": ["thread-and-callback"],
        "how": "thread-and-callback FUN_140038ae0@140038ae0: TlsGetValue(dword ptr ...)",
    },
    {
        "type": "runtime_phase", "id": "failure_fallback", "status": "UNKNOWN",
        "runtime_observed": False,
        "title": "Phase 6 — failure fallback", "catalog_ids": [],
        "how": "UNKNOWN(phase not recovered statically)",
    },
]


def _document(phases: list[dict]) -> dict:
    """The shape the real document has: phases nested inside a findings row."""
    return {
        "report_version": "3.0",
        "case_id": "case-runtime",
        "task_id": "task-runtime",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": [
            {
                "id": "executive_summary",
                "title": "Executive Summary",
                "summary": "",
                "rows": [
                    {
                        "type": "assessment",
                        "findings": [{"runtime_sequence": phases}],
                    }
                ],
            }
        ],
        "trace": {},
    }


def test_the_body_carries_the_ordered_runtime_sequence() -> None:
    """The named benchmark's heaviest section must exist in the published body."""
    body = render_official_markdown(_document(PHASES))
    assert "运行时序" in body or "Runtime sequence" in body, (
        "the published body has no runtime-sequence section, so the ordered reconstruction that the "
        "benchmark report weighs most heavily is unreachable from the report a reader receives"
    )
    for phase in PHASES:
        assert phase["title"] in body, f"phase {phase['title']!r} is missing from the body"


def test_a_phase_states_its_status_and_its_static_boundary() -> None:
    """A phase is a static reconstruction; the body must not read it as observed execution."""
    body = render_official_markdown(_document(PHASES))
    assert "SUPPORTED" in body and "CANDIDATE" in body, (
        "the body does not carry the phases' statuses, so a reader cannot tell a supported phase from "
        "a candidate one"
    )
    assert "CANDIDATE" in body.split("运行时序")[-1] if "运行时序" in body else True
    # The boundary must be stated, because every phase here has runtime_observed=false.
    assert "未" in body or "not observed" in body.lower(), "no static boundary is stated"


def test_an_unrecovered_phase_keeps_its_unknown_marker() -> None:
    """Phase 6 is `UNKNOWN(phase not recovered statically)`; that must survive into the body."""
    body = render_official_markdown(_document(PHASES))
    assert "UNKNOWN" in body, "the unrecovered phase lost its UNKNOWN marker"


def test_no_runtime_section_when_no_phases_were_recovered() -> None:
    """The section must not be invented for a run that recovered no sequence."""
    body = render_official_markdown(_document([]))
    assert "Phase 1" not in body and "运行时序" not in body, (
        "a runtime-sequence section was emitted for a document with no phases"
    )


def test_duplicate_phase_ids_are_rendered_once() -> None:
    """The real document carries the same phases twice (two sequence copies); the body must not."""
    body = render_official_markdown(_document(PHASES + PHASES))
    for phase in PHASES:
        title = str(phase["title"])
        assert body.count(title) == 1, (
            f"phase {title!r} appears {body.count(title)} times; the phases are duplicated in the "
            "document and the renderer must de-duplicate them by id"
        )


def test_ledger_identifiers_do_not_leave_empty_fields_behind() -> None:
    """Stripping `FUN_140038910@140038910` from `function=...; parameters=RBX` must not leave `function=`.

    Measured on the published body after the first version of this section:

        - 输入/变换/输出：memory-and-mapping ; function=; parameters=RBX; threshold=static observed evidence

    `function=` asserts nothing and makes a complete record look truncated, which is the opposite of what
    a section titled 静态重建 is for.
    """
    phases = [dict(PHASES[1], how=(
        "memory-and-mapping ; function=FUN_140038910@140038910; parameters=RBX; "
        "threshold=static observed evidence; consumer=VirtualQuery"
    ))]
    body = render_official_markdown(_document(phases))
    assert "function=;" not in body and "function= " not in body, (
        "a removed ledger identifier left an empty `function=` field in the body"
    )
    assert "FUN_" not in body, "a FUN_ identifier reached the primary body"
    # The surviving fields must still be there.
    assert "parameters=RBX" in body, "cleaning the empty field removed a real one"
    assert "consumer=VirtualQuery" in body, "cleaning removed a real trailing field"


def test_a_phase_whose_text_was_only_a_function_dump_says_so() -> None:
    """With the function name gone the phase may have no description left; that must be stated."""
    phases = [dict(PHASES[1], how="FUN_140038910@140038910")]
    body = render_official_markdown(_document(phases))
    assert PHASES[1]["title"] in body, "the phase disappeared entirely"
    assert "Evidence Explorer" in body or "UNKNOWN(how" in body, (
        "a phase emptied by ledger stripping is rendered as a blank description"
    )
