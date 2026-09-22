"""Focused coverage for the deep-investigation step budget.

The budget exists so one investigation round for one seed thread can work the
frontier the planner actually queued for it.  It is deliberately *not* an
analysis quota.  The former 4..128 window capped the whole deep pass at 32
actions by default and could not be raised from the environment, and
``investigation_step_budget`` was clipped twice more: ``max_sample_files // 2``
(a sample-*count* setting governing analysis depth) and an eight-action
per-seed total for every seed that matched a mechanism playbook.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from threat_report_agent import service as service_module
from threat_report_agent.config import Settings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    InvestigationLoopDriver,
)
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
from threat_report_agent.service import (
    AnalysisService,
    investigation_seed_step_budget,
)

# The budget that produced the proven defect: every deep investigation pass for
# task 2fcc0fdc-ae32-4efd-83e6-a6c9fbc734db (551KB Rust PE, 703 recovered
# functions) was capped at 32 actions, and no environment value could exceed
# 128.
OLD_DEFAULT = 32
OLD_CEILING = 128
# A complete five-facet deep contract over the function corpora that have
# actually been observed: 703 (the defect sample) and 3455 (largest seen live).
OBSERVED_SAMPLE_ACTIONS = 703 * 5
LARGEST_OBSERVED_ACTIONS = 3_455 * 5
# The per-seed slot total that used to bind before the configured budget could.
OLD_SLOT_CAP = 8


def test_default_budget_is_generous_and_not_a_quota(test_settings: Settings) -> None:
    """The default must clear every real frontier, not page it."""
    default = test_settings.investigation_max_steps

    assert default > OLD_CEILING
    assert default > OBSERVED_SAMPLE_ACTIONS
    assert default > LARGEST_OBSERVED_ACTIONS


def test_configured_budget_is_honoured_above_the_old_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INVESTIGATION_MAX_STEPS can now raise the budget past 128."""
    monkeypatch.setenv("INVESTIGATION_MAX_STEPS", "4096")

    configured = Settings.from_environment().investigation_max_steps

    assert configured == 4096
    assert configured > OLD_CEILING
    assert configured > OLD_DEFAULT


def test_setting_validation_stays_generous(test_settings: Settings) -> None:
    for value in (4, 512, 4096, 65_536):
        assert (
            replace(test_settings, investigation_max_steps=value).investigation_max_steps
            == value
        )
    # Only a value that could not be walked is rejected.
    for invalid in (0, -1, 1_000_001):
        with pytest.raises(ValueError):
            replace(test_settings, investigation_max_steps=invalid)


def test_environment_default_matches_the_class_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("INVESTIGATION_MAX_STEPS", raising=False)

    assert (
        Settings.from_environment().investigation_max_steps
        == Settings.__dataclass_fields__["investigation_max_steps"].default
    )


class _RecordingDriver(InvestigationLoopDriver):
    """Record the budgets the service hands the loop, then run for real."""

    calls: list[dict[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        _RecordingDriver.calls.append({"init": dict(kwargs)})
        super().__init__(**kwargs)

    def run_until_converged(self, **kwargs: object):
        _RecordingDriver.calls.append({"run": dict(kwargs)})
        return super().run_until_converged(**kwargs)


def _seed_task(service: AnalysisService, *, category: str = "process") -> str:
    """Persist one high-value seed cluster and return its task id."""
    case = service.create_case(f"{category} step budget seed")
    with service.database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="d" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key=f"sha256/{category}-step-budget-seed",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path=f"{category}-step-budget.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        context_id = f"{category}-context"
        call_id = f"{category}-call"
        session.add_all(
            [
                Evidence(
                    id=context_id,
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_context",
                    nature="STATIC_OBSERVED",
                    value={"name": "FUN_seed", "entry": "0x1000"},
                    anchor={"function_entry": "0x1000"},
                ),
                Evidence(
                    id=call_id,
                    task_id=task.id,
                    artifact_id=artifact.id,
                    tool_run_id=run.id,
                    module="static",
                    kind="function_call",
                    nature="STATIC_OBSERVED",
                    value={"api": "CreateProcessW", "function_entry": "0x1000"},
                    anchor={"function_entry": "0x1000"},
                ),
            ]
        )
        task.strategy_snapshot = {
            "investigation": {
                "threads": [],
                "seed_maps": {
                    artifact.id: {
                        "clusters": [
                            {
                                "id": f"{category}-cluster",
                                "category": category,
                                "priority": 1,
                                "question": f"Which {category} path is used?",
                                "evidence_ids": [context_id, call_id],
                                "function": "0x1000",
                            }
                        ]
                    }
                },
            }
        }
        return task.id


def test_live_budget_comes_from_the_setting_not_from_max_sample_files(
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard for both removed clips, measured at the driver seam.

    ``max_sample_files=2`` under the old expression produced
    ``min(4096, max(8, 2 // 2)) == 8`` for the round budget and
    ``min(remaining, 8) == 8`` for the seed total, so the configured budget
    never reached the loop and no seed could attempt more than eight actions.
    """
    settings = replace(
        test_settings,
        max_sample_files=2,
        investigation_max_steps=4096,
    )
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    task_id = _seed_task(service)

    # The two numbers the pre-fix expression could produce for this task.
    assert min(4096, max(8, 2 // 2)) == OLD_SLOT_CAP
    assert min(settings.investigation_task_max_actions, OLD_SLOT_CAP) == OLD_SLOT_CAP

    _RecordingDriver.calls = []
    monkeypatch.setattr(service_module, "InvestigationLoopDriver", _RecordingDriver)
    service._run_investigation_loop(task_id)

    assert _RecordingDriver.calls, "the investigation loop never reached the driver"
    assert {call["init"]["max_steps"] for call in _RecordingDriver.calls if "init" in call} == {
        4096
    }
    planner_calls = [
        call["run"]
        for call in _RecordingDriver.calls
        if "run" in call and call["run"].get("max_rounds") != 1
    ]
    assert planner_calls, "the seeded thread did not take the planner path"
    assert {item["max_total_steps"] for item in planner_calls} == {
        settings.investigation_task_max_actions
    }


def test_seed_total_is_not_clipped_to_the_old_eight_action_slot() -> None:
    """The whole configured budget reaches a seed, not a fair-share slot cap."""
    assert investigation_seed_step_budget(remaining=64, slot_cap=0) == 64
    assert investigation_seed_step_budget(remaining=64) == OLD_SLOT_CAP

    # Read the module text directly: ``inspect.getsource`` on a 180k-character
    # method depends on a line cache that concurrent edits invalidate.
    text = Path(service_module.__file__).read_text(encoding="utf-8")
    # Regression guards for the two truncated expressions named in the defect.
    assert "max(8, self.settings.max_sample_files // 2)" not in text
    assert "slot_cap=0," in text
    assert "slot_cap=_PER_SLOT_TRACE_CAP" not in text


def test_kept_bounds_still_bound() -> None:
    """What deliberately stays bounded: loop protection and an explicit budget."""
    initial = {
        "id": "e0",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {"name": "entry", "entry": "0x1000"},
        "anchor": {"function_entry": "0x1000"},
    }
    executed: list[str] = []

    def execute(action: ActionSpec) -> list[dict[str, object]]:
        executed.append(action.id)
        return [
            {
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": action.action_type.value},
                "anchor": {"function_entry": "0x1000"},
            }
        ]

    result = InvestigationLoopDriver(max_steps=4096).run_until_converged(
        thread_id="kept-bound-thread",
        artifact_id="kept-bound-artifact",
        question="Which static path is present?",
        hypothesis_id="kept-bound-hypothesis",
        hypothesis_statement="The artifact may expose a static mechanism.",
        initial_evidence=(initial,),
        execute=execute,
        max_rounds=4,
        max_total_steps=2,
    )

    assert len(executed) == 2
    assert any(event.phase == "budget_exhausted" for event in result.events)

    # An explicitly pinned small step budget still bounds one round.
    tiny_executed: list[str] = []

    def tiny_execute(action: ActionSpec) -> tuple[()]:
        tiny_executed.append(action.id)
        return ()

    tiny = InvestigationLoopDriver(max_steps=1).run(
        thread_id="tiny-thread",
        artifact_id="tiny-artifact",
        question="Which static path is present?",
        hypothesis_id="tiny-hypothesis",
        hypothesis_statement="The artifact may expose a static mechanism.",
        initial_evidence=(initial,),
        execute=tiny_execute,
        proposed_actions=(
            ActionSpec(
                id="tiny-action",
                action_type=ActionType.GET_FUNCTION,
                thread_id="tiny-thread",
                hypothesis_id="tiny-hypothesis",
                artifact_id="tiny-artifact",
                parameters={"target": "0x1000"},
                expected_evidence_kinds=("function_context",),
            ),
        ),
        allow_investigator_actions=False,
    )

    assert len(tiny_executed) == 1
    assert len(tiny.actions) == 1


def test_round_and_invocation_guards_stay_loop_protection(test_settings: Settings) -> None:
    """The retained guards are finite by design, and env can raise the total."""
    assert replace(test_settings, investigation_max_rounds=1).investigation_max_rounds == 1
    for invalid_rounds in (0, 9):
        with pytest.raises(ValueError):
            replace(test_settings, investigation_max_rounds=invalid_rounds)

    # The per-invocation scheduling bound is raisable past its old 1024 ceiling
    # and no longer rejects a deliberately tiny value.
    assert (
        replace(test_settings, investigation_task_max_actions=4096)
        .investigation_task_max_actions
        == 4096
    )
    assert (
        replace(test_settings, investigation_task_max_actions=1).investigation_task_max_actions
        == 1
    )
    for invalid_actions in (0, -1, 1_000_001):
        with pytest.raises(ValueError):
            replace(test_settings, investigation_task_max_actions=invalid_actions)
