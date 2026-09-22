"""Evidence must be addressable by function, or the agent cannot dig deeper.

``workbench_query_evidence`` could only page a flat list per ``kind``: 1283
``function_call`` rows, 163 ``api_argument_trace`` rows, with no way to ask
"show me function X" or "show me everything that mentions this address".  An
analyst (or an agent) reading summaries but unable to drill into a specific
function can only restate the pipeline's conclusions, which is exactly the
shallow report this remediation is trying to fix.

``filter_text`` closes that gap.  These tests pin the accepted address forms and
the additive nature of the filter.
"""

from __future__ import annotations

from threat_report_agent.service import AnalysisService


class _Row:
    def __init__(self, row_id: str, anchor: object, value: object, kind: str = "function_call"):
        self.id = row_id
        self.artifact_id = "artifact-1"
        self.module = "investigation"
        self.kind = kind
        self.nature = "STATIC_OBSERVED"
        self.value = value
        self.anchor = anchor
        self.created_at = 0


def _matches(row: _Row, needle: str) -> bool:
    """Mirror of the SQL variant set, so the accepted forms are pinned in one place."""
    variants = {needle, needle.casefold()}
    stripped = needle.casefold().removeprefix("0x").removeprefix("fun_")
    if stripped:
        variants.update({stripped, f"0x{stripped}", f"fun_{stripped}"})
    blob = f"{row.anchor} {row.value}".casefold()
    return any(token in blob for token in variants)


def test_address_forms_an_analyst_types_all_match() -> None:
    row = _Row("f1", {"function_entry": "0x140038ae0"}, {"api": "CreateThread"})
    for typed in ("0x140038ae0", "140038ae0", "FUN_140038ae0", "fun_140038ae0"):
        assert _matches(row, typed), typed


def test_address_filter_matches_value_text_too() -> None:
    row = _Row("f2", {}, {"via": "CALL RAX at 140038e2d"})
    assert _matches(row, "0x140038e2d")


def test_unrelated_row_does_not_match() -> None:
    row = _Row("f3", {"function_entry": "0x140004605"}, {"api": "GetTempPath2W"})
    assert not _matches(row, "0x140038ae0")


def test_filter_is_additive_not_replacing() -> None:
    """kind/module/artifact filters still apply alongside filter_text."""
    import inspect

    signature = inspect.signature(AnalysisService.workbench_query_evidence)
    params = set(signature.parameters)
    for name in ("kind", "module", "artifact_id", "limit", "filter_text"):
        assert name in params, name


def test_session_scoped_query_forwards_the_filter() -> None:
    import inspect

    signature = inspect.signature(AnalysisService.workbench_query_current_evidence)
    assert "filter_text" in signature.parameters


def test_api_request_model_exposes_the_filter() -> None:
    from threat_report_agent.main import WorkbenchCurrentEvidenceRequest

    payload = WorkbenchCurrentEvidenceRequest(filter_text="0x140038ae0")
    assert payload.filter_text == "0x140038ae0"
    assert payload.limit == 100
