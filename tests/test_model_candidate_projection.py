"""The published body must carry the model's synthesized candidates - without promoting them.

MEASURED GAP. `reporting._document_to_v3_markdown` emits `### Model-Synthesized Candidates` from rows
whose `analysis_source` is `model`, but the published revision is the Chinese analyst body produced by
`analyst_report.render_official_markdown`, which had no contract for those rows at all.

Measured on the W4 acceptance run (task with `model_calls_enabled`): the document carried three
model-sourced `analytical_claim` rows - two shaped as `modules[].rows[].findings[]` and one as
`modules[].rows[]` - each holding `mechanism` / `status` / `confidence` / `evidence_ids` / `model_call_id`.
The published body was 3969 characters and contained **none** of those four facts:

    mechanism chain "Input -> Transformation/Control -> ..."   document: 3 rows   body: 0
    action          "may_execute"                              document: 3 rows   body: 0
    status          "CANDIDATE"                                document: 3 rows   body: 0
    evidence anchors                                            document: 3 rows   body: 0

A model's contribution was therefore invisible to the reader, and the model's own claim that a mechanism
exists was neither shown nor marked unproven. This is R2 (a fact exists, the body lacks it) with the
additional hazard that a candidate printed without its verifier boundary reads like a conclusion.

The fix prints the candidates as candidates: the claim, the mechanism chain the model asserted, the
subject/action/object, how many evidence rows anchor it, and an explicit statement that it has not passed
the verifier. The body strips ledger UUIDs from the primary section by design, so anchors are counted
rather than printed - publishing them produced "证据锚点：," which reads as a present-but-empty field.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown

CHAIN = "Input -> Transformation/Control -> Condition -> Output -> Consumer -> Side Effect"
EVIDENCE_A = "2adf2755-f96f-420f-8d2a-b7310fbcf990"
EVIDENCE_B = "2b52ed5f-4d6e-4c2e-abc4-1132b1c1f1a4"

SECTION = "### 模型合成候选"


def _model_row(**overrides: object) -> dict:
    row = {
        "type": "analytical_claim",
        "claim_id": "claim-model-1",
        "what": "Static evidence links process input to a bounded consumer.",
        "subject": "sample.py",
        "action": "may_execute",
        "object": "a process or command",
        "mechanism": CHAIN,
        "condition": "static evidence only",
        "status": "CANDIDATE",
        "confidence": "MEDIUM",
        "analysis_source": "model",
        "model_call_id": "call-model-1",
        "evidence_ids": [EVIDENCE_A, EVIDENCE_B],
    }
    row.update(overrides)
    return row


def _document(rows: list[dict], modules: list[dict] | None = None) -> dict:
    return {
        "report_version": "3.0",
        "case_id": "case-model",
        "task_id": "task-model",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "analyst_topics": [],
        "modules": modules
        or [
            {
                "id": "execution",
                "title": "Execution",
                "summary": "",
                "rows": rows,
            }
        ],
        "trace": {},
    }


def test_a_model_candidate_reaches_the_published_body() -> None:
    """The four facts that were in the document and absent from the body, asserted individually."""
    body = render_official_markdown(_document([_model_row()]))
    assert SECTION in body, "the published body has no model-candidate section"
    assert CHAIN in body, "the candidate's mechanism chain is in the document and absent from the body"
    assert "may_execute" in body, "the candidate's action is in the document and absent from the body"
    assert "CANDIDATE" in body, "the candidate's status is in the document and absent from the body"
    assert "2 条已登记证据" in body, "the candidate's evidence anchoring is not stated"


def test_a_candidate_is_never_presented_as_a_verified_finding() -> None:
    """A candidate that reads like a conclusion is worse than no candidate."""
    body = render_official_markdown(_document([_model_row()]))
    section = body[body.find(SECTION):]
    assert "未过验证器" in section, "the candidate section does not state the verifier boundary"
    assert "CANDIDATE" in section
    assert "不作为结论" in section, "the section does not tell the reader how to use a candidate"


def test_a_candidate_shaped_as_a_nested_finding_is_also_published() -> None:
    """Measured shape: two of the three rows lived at `modules[].rows[].findings[]`, not `rows[]`."""
    module = {
        "id": "static_triage",
        "title": "Static Triage",
        "summary": "",
        "rows": [{"type": "pe", "findings": [_model_row(claim_id="claim-nested")]}],
    }
    body = render_official_markdown(_document([], modules=[module]))
    assert SECTION in body, "a candidate nested under rows[].findings[] is invisible to the reader"
    assert CHAIN in body


def test_an_unanchored_candidate_is_marked_as_unanchored() -> None:
    """No evidence must be visible as no evidence, not as a candidate with silent support."""
    body = render_official_markdown(_document([_model_row(evidence_ids=[])]))
    section = body[body.find(SECTION):]
    assert "0 条" in section, "a candidate with no evidence anchors is presented without saying so"
    assert "不得作为结论" in section


def test_deterministic_claims_are_not_published_as_model_candidates() -> None:
    """The section must not claim model authorship for a deterministic projection."""
    body = render_official_markdown(
        _document([_model_row(analysis_source="deterministic_static_rules")])
    )
    assert SECTION not in body, (
        "a deterministic claim is presented as a model-synthesized candidate"
    )


def test_the_section_is_absent_when_there_are_no_candidates() -> None:
    """An empty section would imply the model contributed nothing when it may simply not have run."""
    body = render_official_markdown(_document([{"type": "pe", "path": "sample.exe"}]))
    assert SECTION not in body


def test_the_candidate_list_is_bounded_and_says_so() -> None:
    """A run with many candidates must state the bound rather than print them all silently."""
    rows = [_model_row(claim_id=f"claim-{index}") for index in range(40)]
    body = render_official_markdown(_document(rows))
    outside = body[body.find(SECTION):]
    assert outside.count("候选 ") < 40, "every candidate was printed; the section must be bounded"
    assert "未在此列出" in outside, "the section truncated silently"
