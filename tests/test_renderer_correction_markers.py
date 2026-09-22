"""A published revision must record WHICH renderer corrections it carries.

MEASURED GAP. Every fix from rounds 77-88 changes what a NEW revision says, and
`report_revisions.markdown` is written once at row creation. So the fixes help only future revisions, and
the deployment's own population shows the scale:

    342 of 345 tasks have a newest published revision that lacks a section added since round 77
    20 published revisions still carry a `rule threat_static_<16-hex>` named after a digest      <- EC-5
    only 5 carry the IOC quick-reference, only 8 carry the runtime sequence

A reader of those reports has no way to know they predate corrections that would change their content. The
product therefore needs a **staleness marker**: at creation time a revision records which correction markers
its body satisfies, so a consumer can answer "is this report still current, and if not, which correction is
missing" without re-rendering every document.

Design constraints, each from something measured in this work:

* the marker must be derived from the BODY, never from a hand-maintained integer. A counter bumped by hand
  drifts the first time a fix ships without someone remembering to bump it - a failure mode this project has
  hit repeatedly with version strings that were written once and never updated.
* each marker is an assertion the report either satisfies or does not, so the record is actionable: "missing
  `runtime_sequence`" tells a reviewer which regeneration would change the body.
* a missing marker is not an error. Some sections are legitimately absent (a sample with no TLS callbacks
  has no TLS section), which is why the record names what is PRESENT rather than claiming completeness.
"""
from __future__ import annotations

from threat_report_agent.report_verification import (
    CORRECTION_MARKERS,
    renderer_corrections,
)


def test_the_marker_set_covers_the_corrections_that_change_a_body() -> None:
    """Each correction that altered published text must be represented."""
    ids = {marker.id for marker in CORRECTION_MARKERS}
    for expected in (
        "import_module_list",
        "resource_directory",
        "runtime_sequence",
        "ioc_quick_reference",
        "tls_callbacks",
        "file_hash_provenance",
    ):
        assert expected in ids, f"correction {expected!r} has no marker, so staleness cannot be detected"


def test_a_body_carrying_the_new_sections_reports_them() -> None:
    """A body rendered by the current renderer satisfies the additive markers."""
    body = (
        "### 运行时序（静态重建）\n"
        "### IOC / 指标速查\n"
        "### TLS 回调入口（静态恢复）\n"
        "- 导入表模块清单（3 个）：`a.dll`（1）\n"
        "- 资源目录：共 11 项 —— `RT_ICON`（9 项）\n"
        'rule threat_static_comhost\n$s0 = "6bb6bfcb..." // sha256\n'
    )
    corrections = renderer_corrections(body)
    for marker_id in ("runtime_sequence", "ioc_quick_reference", "tls_callbacks",
                      "import_module_list", "resource_directory", "file_hash_provenance"):
        assert corrections[marker_id] is True, f"{marker_id} not detected in a body that carries it"


def test_a_body_with_a_digest_named_rule_fails_the_provenance_marker() -> None:
    """The EC-5 defect is a NEGATIVE marker: its presence means the correction is absent."""
    body = "rule threat_static_0b05c0df699028e6\n$s0 = \"0b05c0df...\" // sha256\n"
    corrections = renderer_corrections(body)
    assert corrections["file_hash_provenance"] is False, (
        "a rule named after a digest still satisfied the file-hash provenance marker"
    )


def test_an_old_body_reports_all_additive_corrections_missing() -> None:
    """A 2,325-character pre-fix body must not appear current."""
    old = "# 静态分析报告\n\n## 分析结论\n\n本次没有形成可选题的行为证据。\n"
    corrections = renderer_corrections(old)
    additive = [
        marker.id for marker in CORRECTION_MARKERS if not marker.negative
    ]
    assert not any(corrections[marker_id] for marker_id in additive), (
        "a pre-fix body satisfied an additive correction marker"
    )


def test_the_marker_record_is_serialisable_and_names_the_missing_ones() -> None:
    """Consumers need "what is missing" without re-deriving it."""
    from threat_report_agent.report_verification import stale_corrections

    old = "# 静态分析报告\n\n## 分析结论\n\n本次没有形成可选题的行为证据。\n"
    missing = stale_corrections(old)
    assert "runtime_sequence" in missing and "ioc_quick_reference" in missing
    assert all(isinstance(item, str) for item in missing)
    current = (
        "### 运行时序（静态重建）\n### IOC / 指标速查\n### TLS 回调入口（静态恢复）\n"
        "导入表模块清单（1 个）\n资源目录：共 1 项\nrule threat_static_x\n"
    )
    assert stale_corrections(current) == [], (
        f"a body carrying every additive section still reported stale: {stale_corrections(current)}"
    )
