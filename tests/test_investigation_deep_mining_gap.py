from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.database import Database
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.investigation import (
    ActionSpec,
    ActionType,
    DeepMiningPlanner,
    InvestigationLoopDriver,
)
from threat_report_agent.service import AnalysisService


def _function_rows() -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            id="ctx-launch",
            artifact_id="artifact-decompile",
            kind="function_context",
            value={
                "name": "launch_stage",
                "entry": "0x401000",
                "call_targets": [
                    {"target_name": "CreateProcessW", "from": "0x40100a"},
                    {"target_name": "ReadFile", "from": "0x401018"},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="ins-launch",
            artifact_id="artifact-decompile",
            kind="function_instruction_window",
            value={
                "entry": "0x401000",
                "instructions": [
                    {"address": "0x401000", "text": 'LEA RCX,[cmdline]'},
                    {"address": "0x401005", "text": "MOV RDX,0x08000000"},
                    {"address": "0x40100a", "text": "CALL CreateProcessW"},
                    {"address": "0x401010", "text": "TEST EAX,EAX"},
                    {"address": "0x401012", "text": "JZ 0x401030"},
                    {"address": "0x401018", "text": "CALL ReadFile"},
                ],
            },
            anchor={"function_entry": "0x401000"},
        ),
        SimpleNamespace(
            id="call-create",
            artifact_id="artifact-decompile",
            kind="function_call",
            value={"api": "CreateProcessW", "from": "0x40100a"},
            anchor={"function_entry": "0x401000", "callsite": "0x40100a"},
        ),
        SimpleNamespace(
            id="call-read",
            artifact_id="artifact-decompile",
            kind="function_call",
            value={"api": "ReadFile", "from": "0x401018"},
            anchor={"function_entry": "0x401000", "callsite": "0x401018"},
        ),
    ]


def test_decompile_action_emits_ordered_semantic_summary(test_settings) -> None:
    """Deep decompile work must produce analyst-facing semantics, not only a slice."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    action = ActionSpec(
        id="decompile-launch",
        action_type=ActionType.GET_DECOMPILE,
        thread_id="thread-decompile",
        hypothesis_id="hypothesis-decompile",
        artifact_id="artifact-decompile",
        target_selector={"target": "0x401000"},
        source_evidence_ids=("ctx-launch", "ins-launch", "call-create", "call-read"),
        expected_evidence_kinds=("abstract_execution_trace", "function_context"),
    )

    observations = service.derive_investigation_observations(_function_rows(), action)

    summary_row = next(
        item for item in observations if item["kind"] == "function_semantic_summary"
    )
    summary = summary_row["value"]
    assert [item["api"] for item in summary["call_sequence"]] == [
        "CreateProcessW",
        "ReadFile",
    ]
    assert any(item["value"] == "0x08000000" for item in summary["inputs"])
    assert summary["conditions"]
    assert summary["consumers"]
    assert summary["static_only"] is True
    assert "runtime execution is unobserved" in summary["boundary"]
    assert summary_row["nature"] == "STATIC_INFERRED"
    decompile_row = next(item for item in observations if item["kind"] == "decompile_slice")
    assert decompile_row["nature"] == "STATIC_INFERRED"
    assert set(summary_row["value"]["source_evidence_ids"]) >= {
        "ctx-launch",
        "ins-launch",
        "call-create",
        "call-read",
    }


def test_function_deep_frontier_admits_decompile_before_optional_navigation() -> None:
    rows = [
        {
            "id": row.id,
            "kind": row.kind,
            "value": row.value,
            "anchor": row.anchor,
        }
        for row in _function_rows()
    ]

    actions = DeepMiningPlanner.plan_actions(rows, scheduled=set(), max_actions=8)

    assert any(
        action.action_type == ActionType.GET_DECOMPILE
        and action.parameters.get("target") == "0x401000"
        for action in actions
    )


def test_qualified_api_xref_is_productive_after_symbol_normalization(test_settings) -> None:
    """A DLL-qualified model target must match plain Ghidra call symbols."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="import-create",
            artifact_id="artifact-qualified",
            kind="import_symbol",
            value={"name": "CreateProcessW", "library": "KERNEL32.dll"},
            anchor={"type": "pe_import"},
        ),
        SimpleNamespace(
            id="ctx-create",
            artifact_id="artifact-qualified",
            kind="function_context",
            value={
                "name": "spawn_worker",
                "entry": "0x401000",
                "call_targets": [{"target_name": "CreateProcessW", "from": "0x40100a"}],
            },
            anchor={"function_entry": "0x401000"},
        ),
    ]
    action = ActionSpec(
        id="qualified-xref",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="qualified-thread",
        hypothesis_id="qualified-hypothesis",
        artifact_id="artifact-qualified",
        target_selector={"target": "KERNEL32.dll!CreateProcessW"},
        source_evidence_ids=("import-create",),
        expected_evidence_kinds=("xref", "function_call"),
    )

    observations = service.derive_investigation_observations(rows, action)
    assert any(item["kind"] == "function_call" for item in observations)

    result = InvestigationLoopDriver(max_steps=2, max_consecutive_no_gain=1).run(
        thread_id="qualified-thread",
        artifact_id="artifact-qualified",
        question="Where is the process API referenced?",
        hypothesis_id="qualified-hypothesis",
        hypothesis_statement="The qualified process API has a local callsite.",
        initial_evidence=[
            {"id": row.id, "artifact_id": row.artifact_id, "kind": row.kind, "value": row.value, "anchor": row.anchor}
            for row in rows
        ],
        proposed_actions=(action,),
        allow_investigator_actions=False,
        execute=lambda _action: observations,
    )
    assert any(event.phase == "action_completed" and event.evidence_ids for event in result.events)
    assert not any(event.phase == "action_output_rejected" for event in result.events)


def test_qualified_api_argument_trace_is_productive_after_symbol_normalization(test_settings) -> None:
    """Parameter tracing must use the same exact API identity bridge as Xrefs."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = _function_rows()
    action = ActionSpec(
        id="qualified-args",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="qualified-args-thread",
        hypothesis_id="qualified-args-hypothesis",
        artifact_id="artifact-decompile",
        target_selector={"target": "KERNEL32.dll!CreateProcessW"},
        source_evidence_ids=("ctx-launch", "ins-launch", "call-create"),
        expected_evidence_kinds=("api_argument_trace",),
    )

    observations = service.derive_investigation_observations(rows, action)

    assert any(item["kind"] == "api_argument_trace" for item in observations)


def test_function_scoped_argument_trace_does_not_filter_out_calls_by_rva(test_settings) -> None:
    """A function target scopes the rows; it is not itself an API name."""
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    action = ActionSpec(
        id="function-args",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="function-args-thread",
        hypothesis_id="function-args-hypothesis",
        artifact_id="artifact-decompile",
        target_selector={"target": "0x401000"},
        source_evidence_ids=("ctx-launch", "ins-launch", "call-create"),
        expected_evidence_kinds=("api_argument_trace",),
    )

    observations = service.derive_investigation_observations(_function_rows(), action)

    assert any(item["kind"] == "api_argument_trace" for item in observations)


def test_workbench_decompile_projection_exposes_semantic_summary() -> None:
    """Workbench consumers receive mechanism semantics without parsing raw rows."""
    value = {
        "function": {"name": "launch_stage", "entry": "0x401000"},
        "call_sequence": [{"api": "CreateProcessW", "callsite": "0x40100a"}],
        "inputs": [{"value": "0x08000000", "source": "MOV RDX,0x08000000"}],
        "conditions": [{"text": "TEST EAX,EAX; JZ 0x401030"}],
        "consumers": [{"api": "ReadFile", "callsite": "0x401018"}],
        "static_only": True,
        "boundary": "runtime execution is unobserved",
        "source_evidence_ids": ["ctx-launch", "ins-launch"],
    }
    from threat_report_agent.models import Evidence

    row = Evidence(
        id="semantic-summary",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="tool",
        module="investigation",
        kind="function_semantic_summary",
        nature="STATIC_INFERRED",
        value=value,
        anchor={"function_entry": "0x401000"},
    )
    projection = AnalysisService.semantic_action_result(ActionType.GET_DECOMPILE.value, [row])
    assert projection["kind"] == "function_semantic_summary"
    assert projection["summaries"][0]["call_sequence"][0]["api"] == "CreateProcessW"
    assert projection["summaries"][0]["boundary"] == "runtime execution is unobserved"
