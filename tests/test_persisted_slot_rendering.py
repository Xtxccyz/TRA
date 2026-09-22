"""A persisted slot proposal fills its slot - and nothing else can.

The split being tested: promotion happens at PERSISTENCE time (`service.py`, during revision creation, where
the evidence is at hand and the Claim Gate can see it) and the renderer only READS the recorded decision.
Filling a slot at render time from anything else would be the render-time promotion the behavior plan forbids
(§5:157) - the mistake `creation_flags_from_callsite` already made once, which "improves" a report and
fabricates one indistinguishably.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import AnalystTopic, _project_topic_slots

TOPIC = AnalystTopic(
    catalog_id="process-creation",
    title="进程创建",
    status="observed",
    reason="finding present",
    anchors=("process-creation",),
)


def _finding(**extra) -> dict:
    row = {
        "catalog_id": "process-creation",
        "type": "behavior_finding",
        "how": "CreateProcess 调用点已恢复，creation_flags 未恢复。",
        "unknowns": ["UNKNOWN(creation_flags)"],
    }
    row.update(extra)
    return row


def _document(supported: list[dict] | None) -> dict:
    if supported is None:
        return {}
    return {
        "analyst_slot_proposals": {
            "supported": supported,
            "rejected": [],
            "boundary": "持久化期写入；CANDIDATE。",
        }
    }


PROPOSAL = {
    "slot": "failure_fallback",
    "value": "恢复文本含 On Error Resume Next",
    "evidence_source": "recovered_script",
    "evidence_substring": "On Error Resume Next",
    "support": "substring_matched",
    "boundary": "该构造逐字存在于恢复出的脚本文本中；不证明该路径在目标主机上执行过。",
}


def _render(document: dict) -> str:
    return "\n".join(str(line) for line in _project_topic_slots(TOPIC, [_finding()], document))


def test_a_persisted_proposal_fills_its_slot_with_its_boundary() -> None:
    body = _render(_document([PROPOSAL]))
    assert "恢复文本含 On Error Resume Next" in body
    assert "On Error Resume Next" in body, "the substring must be shown, not just asserted"
    assert "子串字面匹配" in body, (
        "the render must state the support kind in analyst wording, not as a machine identifier"
    )
    assert "substring_matched" not in body, (
        "a machine identifier leaked into the analyst-facing body"
    )
    assert "不证明该路径在目标主机上执行过" in body, "the boundary must travel with the value"


def test_without_a_persisted_record_the_slot_stays_unknown() -> None:
    """No record means nothing was verified - the renderer must not invent a fill."""
    for document in ({}, _document([]), _document(None)):
        body = _render(document)
        assert "On Error Resume Next" not in body
        assert "UNKNOWN" in body, "the slot must still report that it is unresolved"


def test_a_slot_name_the_schema_never_asked_for_is_still_rendered() -> None:
    """The eight official slots are a FLOOR. A sample may answer a question this schema never asked.

    This path had its OWN render site, and the A3 rename missed it - the body still printed a Claim status
    for a non-Claim proposal. Pinned per site, not once for the file, because "the other branch" is exactly
    where the first fix stopped.
    """
    extra = dict(PROPOSAL, slot="staging_directory", value="脚本写入 new_down 子目录")
    body = _render(_document([extra]))
    assert "staging_directory" in body
    assert "脚本写入 new_down 子目录" in body
    assert "子串字面匹配" in body, "the extra-slot path did not print the support kind"
    assert "substring_matched" not in body, (
        "the extra-slot path leaked a machine identifier into the body"
    )
    assert "CANDIDATE" not in body, (
        "the extra-slot path still stamps a Claim status on a non-Claim proposal"
    )


def test_a_proposal_for_an_officially_covered_slot_is_not_rendered_twice() -> None:
    body = _render(_document([PROPOSAL]))
    assert body.count("恢复文本含 On Error Resume Next") == 1


def test_a_malformed_record_degrades_to_no_fill_rather_than_raising() -> None:
    """A renderer must not crash on a document written by an older or newer version."""
    for record in ("not a mapping", {"supported": "not a list"}, {"supported": [None, 3, "x"]}):
        body = _render({"analyst_slot_proposals": record})
        assert "On Error Resume Next" not in body


def test_two_proposals_for_the_same_slot_are_both_published() -> None:
    """MEASURED defect (plan T5 / F15): a second proposal for the same slot SILENTLY REPLACED the first.

    `analyst_report._persisted_slot_proposals` builds `keyed[slot.casefold()] = dict(item)`, so with several
    verified proposals sharing a slot name only the LAST one survived to the body. Measured on the real 白象
    run `e4d13733`: 19 supported proposals, and 4 true values never reached the published report -
    `WScript.CreateObje`, `MSXML2.XM`, `HttpRequests` and `GET` were all dropped because a later proposal
    carried the same slot name.

    Nothing about this is visible in the output: the body simply shows one value where the evidence holds two,
    which is the "silently drops verified facts" class the whole review is about. The values are distinct
    facts, not restatements - three different component literals recovered from the same script.

    The criterion is deliberately at the RENDER level (the values must appear in the body), not at the level of
    "the grader now says PASS": a one-line change to the internal key would satisfy the latter while the values
    were still lost.
    """
    first = dict(
        PROPOSAL,
        slot="staging_directory",
        value="脚本写入 new_down 子目录",
        evidence_substring="new_down",
    )
    second = dict(
        PROPOSAL,
        slot="staging_directory",
        value="脚本另行写入 temp_stage 子目录",
        evidence_substring="temp_stage",
    )
    body = _render(_document([first, second]))

    assert "new_down" in body, (
        "the FIRST proposal for a slot was dropped when a later proposal reused the slot name - "
        "its supporting substring is absent from the body"
    )
    assert "temp_stage" in body, "the later proposal must still be published"
    assert "脚本写入 new_down 子目录" in body, "the first value must be published, not only its substring"
    assert "脚本另行写入 temp_stage 子目录" in body, "the later value must be published"


def test_the_official_slot_branch_also_publishes_every_proposal() -> None:
    """The fix rewrote TWO loops; the other duplicate test covers only one of them.

    MEASURED gap (T5 audit): `test_two_proposals_for_the_same_slot_are_both_published` uses
    `staging_directory`, which is NOT one of the official slots, so it exercises only the extra-slot loop. The
    OFFICIAL-slot loop was rewritten by the same change and had no duplicate coverage - reverting just that
    branch to a single proposal would have left the whole suite green.

    `what` is an official slot that the fixture finding leaves unfilled, so the official branch is the one that
    renders it.
    """
    first = dict(
        PROPOSAL,
        slot="what",
        value="脚本先构造 WScript.CreateObje 形式的后期绑定对象创建",
        evidence_substring="WScript.CreateObje",
    )
    second = dict(
        PROPOSAL,
        slot="what",
        value="脚本随后引用 MSXML2.XM 组件字面量",
        evidence_substring="MSXML2.XM",
    )
    body = _render(_document([first, second]))

    carried = [line for line in body.splitlines() if "CreateObje" in line or "MSXML2.XM" in line]
    assert len(carried) == 4, (
        "the OFFICIAL-slot branch did not publish both proposals (expected a value line and a support line "
        f"for each): {carried}"
    )
    # ORDER: the record is read in the order it was written, so the first proposal is printed first. Asserted
    # because membership alone cannot tell "both published" from "both published, reordered".
    assert body.index("WScript.CreateObje") < body.index("MSXML2.XM"), (
        "the official-slot branch published the proposals out of their recorded order"
    )


def test_a_single_proposal_renders_exactly_as_before() -> None:
    """E3: the fix must not change the output when no slot repeats.

    Two assertions, but they are NOT equal in strength:

      1. the exact 12-line body is pinned;
      2. the additive label introduced by the fix (「同槽位第 N 条已记录提案」) must be ABSENT when no slot
         repeats.

    CORRECTION (T5 audit, and it corrects this docstring's own earlier wording): an earlier version claimed
    assertion 2 was "the one that is NOT circular" and that the pin only proves stability. That was
    overstated. The pin SUBSUMES assertion 2 - a body containing 「同槽位第」 could not equal the pinned text -
    so assertion 2 cannot fail while the pin passes. It is kept because it names the property in one line and
    would survive a future loosening of the pin, but it is the WEAKER of the two: a differently worded
    duplicate label (say 「（第 2 条提案）」) would satisfy it while duplicates still leaked.

    Why the pinned text equals the PRE-FIX output: the old code emitted
    `- {label}: {value}` followed by the support line; the new `_slot_proposal_lines` emits exactly those same
    two appends for `index == 0` and only diverges from the second proposal onward. That equivalence is why a
    byte comparison is meaningful here at all - and why it is done on a FIXTURE rather than a live run, whose
    body also carries model prose that varies between runs and would make the comparison unjudgeable.
    """
    body = _render(_document([PROPOSAL]))
    assert body == (
        "**进程创建（observed）**\n"
        "\n"
        "- What: UNKNOWN(what)\n"
        "- How: CreateProcess 调用点已恢复，creation_flags 未恢复。\n"
        "- Target: UNKNOWN(target)\n"
        "- Condition: UNKNOWN(condition)\n"
        "- Output: UNKNOWN(output)\n"
        "- Consumer: UNKNOWN(consumer)\n"
        "- Loop: UNKNOWN(loop)\n"
        "- Failure/fallback: 恢复文本含 On Error Resume Next\n"
        "  - 子串证据 `On Error Resume Next`（来源 recovered_script，支撑方式 子串字面匹配（未核对含义））。"
        "该构造逐字存在于恢复出的脚本文本中；不证明该路径在目标主机上执行过。\n"
        "- Unknown: UNKNOWN(creation_flags)\n"
    ), "the single-proposal rendering changed; the duplicate fix was supposed to be additive"
    assert "同槽位第" not in body, (
        "the duplicate-only label leaked into a body that has no duplicate proposals"
    )
