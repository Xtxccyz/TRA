"""A malformed action must be SKIPPED and recorded, never fatal to the analysis.

MEASURED DEFECT (task `0291d4b1`, 1,636 evidence rows, 2026-09-18 08:04:16). The run died with:

    failure_code     STATIC_WORKFLOW_ACTIVITY_FAILED
    failed_component controlled-emulator
    message          GET_DECOMPILE parameters must equal its target selector
    report_available false
    retryable        false

The message comes from `InvestigationCatalog.validate`, which `InvestigationLoopDriver.run`
calls at investigation.py:7805 with **no exception handling**:

    stamped = self._stamp_method_plan(proposed)
    self.catalog.validate(stamped)          # <- a ValueError here ends the whole analysis

So ONE action whose parameters do not equal its selector discarded 1,636 rows of recovered
evidence and produced no report at all - the "有证据但分析不完全" complaint in its most extreme
form. The same unguarded call is at :7837 for investigator-proposed actions, which are the ones a
model actually supplies.

A catalog contract violation is a fact about that action, not about the sample: it belongs in the
audit trail as a rejected method, and the loop must keep working the remaining frontier.
"""

from __future__ import annotations

from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    InvestigationLoopDriver,
    InvestigationThreadState,
)


def _evidence() -> dict[str, object]:
    return {
        "id": "e0",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "entry", "entry": "0x1000"},
        "anchor": {"function_entry": "0x1000"},
    }


def test_a_catalog_rejected_action_does_not_abort_the_investigation() -> None:
    """The measured defect: one bad action ended a 1,636-evidence run with no report.

    A valid action is proposed alongside an invalid one, so the test detects both halves: the run
    must reach a decision AND the valid action must still have executed. A fix that merely
    swallowed the exception without continuing would leave `executed` empty and fail.
    """
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type.value)
        return [
            {
                "kind": "function_context",
                "value": {"name": "entry", "entry": "0x1000"},
                "anchor": {"function_entry": "0x1000"},
            }
        ]

    valid = ActionSpec(
        id="valid",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="artifact-1",
        parameters={"target": "0x1000"},
        target_selector={"target": "0x1000"},
        expected_evidence_kinds=("xref",),
    )
    invalid = ActionSpec(
        id="invalid",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="artifact-1",
        parameters={"target": "0x1000"},
        target_selector={"target": "0x1000"},
        expected_evidence_kinds=("function_context",),
    )
    # Bypass the immutable contract the way an attacker-ish caller could: make parameters disagree
    # with the selector after construction, which is exactly the state the validator rejects.
    object.__setattr__(invalid, "parameters", {"function_entry": "0xDEAD"})

    result = InvestigationLoopDriver(max_steps=6).run(
        thread_id="t1",
        artifact_id="artifact-1",
        question="What does the entry function reference?",
        hypothesis_id="h1",
        hypothesis_statement="The entry function resolves further targets.",
        initial_evidence=(_evidence(),),
        execute=execute,
        proposed_actions=(invalid, valid),
        allow_investigator_actions=False,
    )

    assert "GET_XREFS_TO" in executed, (
        "the valid action was not executed, so the run did not continue past the rejected one; "
        f"executed={executed}"
    )
    assert result.thread_state in {
        InvestigationThreadState.CLAIM_READY,
        InvestigationThreadState.UNKNOWN,
    }, f"the loop did not reach a decision: {result.thread_state}"


def test_the_rejected_action_is_recorded_rather_than_silently_dropped() -> None:
    """Skipping must be auditable: a silently ignored contract violation looks like no attempt."""
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.action_type.value)
        return []

    invalid = ActionSpec(
        id="invalid",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="t1",
        hypothesis_id="h1",
        artifact_id="artifact-1",
        parameters={"target": "0x1000"},
        target_selector={"target": "0x1000"},
        expected_evidence_kinds=("function_context",),
    )
    object.__setattr__(invalid, "parameters", {"function_entry": "0xDEAD"})

    result = InvestigationLoopDriver(max_steps=4).run(
        thread_id="t1",
        artifact_id="artifact-1",
        question="What does the entry function reference?",
        hypothesis_id="h1",
        hypothesis_statement="The entry function resolves further targets.",
        initial_evidence=(_evidence(),),
        execute=execute,
        proposed_actions=(invalid,),
        allow_investigator_actions=False,
    )

    rejected = [
        row
        for row in result.evidence
        if "rejected" in str(row.get("kind") or "").casefold()
        or "rejected" in str(row.get("value") or "").casefold()
    ]
    assert rejected, (
        "a catalog-rejected action left no trace in the result; a reviewer cannot tell a "
        "deliberate skip from a method that was never proposed"
    )
