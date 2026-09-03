from __future__ import annotations

from types import SimpleNamespace

from benchmarks.comhost_differential import evaluate_task_view
from threat_report_agent.investigation import (
    verify_mechanism,
    derive_static_mechanism_links,
)


def _row(evidence_id: str, kind: str, value: object, entry: str = "0x1000") -> dict[str, object]:
    return {
        "id": evidence_id,
        "kind": kind,
        "value": value,
        "anchor": {"function_entry": entry, "rva": entry},
    }


def test_static_facts_form_evaluator_addressable_comhost_links() -> None:
    """Typed Ghidra facts must become linked mechanism evidence, not a field list."""
    rows = [
        _row("gpa", "function_call", {"target_function": "GetProcAddress", "type": "COMPUTED_CALL"}),
        _row("load", "function_call", {"target_function": "LoadLibraryW", "type": "COMPUTED_CALL"}),
        _row("winhttp-open", "function_call", {"target_function": "WinHttpOpen", "type": "COMPUTED_CALL"}),
        _row("winhttp-send", "function_call", {"target_function": "WinHttpSendRequest", "type": "COMPUTED_CALL"}),
        _row("winhttp-recv", "function_call", {"target_function": "WinHttpReceiveResponse", "type": "COMPUTED_CALL"}),
        _row("url", "string", {"text": "https://example.invalid/checkin"}),
        _row("pipe", "function_call", {"target_function": "CreatePipe", "type": "COMPUTED_CALL"}, "0x2000"),
        _row("proc", "function_call", {"target_function": "CreateProcessW", "type": "COMPUTED_CALL"}, "0x2000"),
        _row("read", "function_call", {"target_function": "ReadFile", "type": "COMPUTED_CALL"}, "0x2000"),
        _row("peek", "function_call", {"target_function": "PeekNamedPipe", "type": "COMPUTED_CALL"}, "0x2000"),
        _row("vp", "function_call", {"target_function": "VirtualProtect", "type": "COMPUTED_CALL"}, "0x3000"),
        _row("etw", "function_call", {"target_function": "EtwEventWrite", "type": "COMPUTED_CALL"}, "0x3000"),
        _row("flush", "function_call", {"target_function": "FlushInstructionCache", "type": "COMPUTED_CALL"}, "0x3000"),
        _row("patch", "function_instruction_window", {"bytes": "33 C0 C3"}, "0x3000"),
    ]

    links = derive_static_mechanism_links(rows)
    assert {item["kind"] for item in links} >= {
        "mechanism_dynamic_api_link",
        "mechanism_http_transport_link",
        "mechanism_shell_output_link",
        "mechanism_etw_patch_link",
    }
    linked = rows + links
    task_view = {
        "id": "comhost-static-link-fixture",
        "evidence": linked,
        "evidence_delivery": {"records": []},
        "claims": [],
        "claim_evidence": [],
        "investigation": {"actions": [{"id": "model-action", "outcome": "PRODUCTIVE"}]},
        "limitations": [],
    }
    score = evaluate_task_view(task_view)
    critical = {
        item["mechanism_id"]: item["status"]
        for item in score["mechanisms"]
        if item["mechanism_id"] in {
            "comhost-dynamic-api",
            "comhost-c2-transport",
            "comhost-shell",
            "comhost-etw-patch",
        }
    }
    assert critical == {
        "comhost-dynamic-api": "SUPPORTED",
        "comhost-c2-transport": "SUPPORTED",
        "comhost-shell": "SUPPORTED",
        "comhost-etw-patch": "SUPPORTED",
    }
    assert verify_mechanism("DYNAMIC_API_RESOLUTION", linked).accepted
    assert verify_mechanism("HTTP_DOWNLOAD", linked).accepted
    assert verify_mechanism("SHELL_OUTPUT", linked).accepted
    assert verify_mechanism("ETW_PATCH", linked).accepted

    # This is the same seam used by the DSH ActionProposal executor: a
    # planner-attributed action must materialize at least one new derived
    # Evidence row, with an auditable planner turn and source IDs.
    from threat_report_agent.config import ModelProviderSettings, Settings
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.service import AnalysisService
    from threat_report_agent.investigation import ActionSpec, ActionType

    settings = Settings(
        environment="test",
        database_url="sqlite://",
        object_store_endpoint="http://object-store",
        object_store_bucket="test",
        object_store_access_key="test",
        object_store_secret_key="test",
        content_store_backend="local",
        content_store_path=".tmp/comhost-links",
        temporal_address="temporal:7233",
        ghidra_home="",
        java_home="",
        max_sample_files=100,
        max_sample_bytes=16 * 1024 * 1024,
        max_archive_depth=3,
        primary_model=ModelProviderSettings("test-provider", "http://model.invalid/v1", "test-model", "test-key"),
        fallback_model=ModelProviderSettings("fallback", "", "", ""),
        gate_secret_key="test-gate-secret",
    )
    service = AnalysisService(settings, Database(settings.database_url), LocalContentStore(settings.content_store_path))
    action = ActionSpec(
        id="dsh-action",
        action_type=ActionType.GET_XREFS_TO,
        thread_id="thread",
        hypothesis_id="hypothesis",
        artifact_id="artifact",
        target_selector={"target": "GetProcAddress"},
        source_evidence_ids=("gpa",),
        planner_turn_id="dsh-turn-1",
        expected_evidence_kinds=("function_call",),
    )
    derived = service._derive_investigation_observations(
        [SimpleNamespace(**item) for item in rows], action
    )
    assert any(item["kind"] == "mechanism_dynamic_api_link" for item in derived)
    assert all(item["value"]["source_evidence_ids"] for item in derived)


def test_static_mechanism_links_reject_isolated_or_cross_function_leads() -> None:
    """A lead in one function cannot be combined with an unrelated function."""
    rows = [
        _row("load", "function_call", {"target_function": "LoadLibraryW", "type": "COMPUTED_CALL"}, "0x1000"),
        _row("gpa", "function_call", {"target_function": "GetProcAddress", "type": "COMPUTED_CALL"}, "0x1000"),
        _row("send", "function_call", {"target_function": "WinHttpSendRequest", "type": "COMPUTED_CALL"}, "0x2000"),
        _row("recv", "function_call", {"target_function": "WinHttpReceiveResponse", "type": "COMPUTED_CALL"}, "0x3000"),
        _row("url", "string", {"text": "https://example.invalid/checkin"}, "0x3000"),
        _row("vp", "function_call", {"target_function": "VirtualProtect", "type": "COMPUTED_CALL"}, "0x4000"),
        _row("etw", "function_call", {"target_function": "EtwEventWrite", "type": "COMPUTED_CALL"}, "0x4000"),
        _row("patch", "function_instruction_window", {"bytes": "33 C0 C3"}, "0x4000"),
    ]

    assert derive_static_mechanism_links(rows) == []


def test_static_mechanism_links_reject_mz_bytes_and_incomplete_etw_chain() -> None:
    """Header/patch-looking bytes alone are never a closed static mechanism."""
    rows = [
        _row("mz", "string", {"text": "MZ PE"}, "0x5000"),
        _row("vp", "function_call", {"target_function": "VirtualProtect", "type": "COMPUTED_CALL"}, "0x5000"),
        _row("etw", "function_call", {"target_function": "EtwEventWrite", "type": "COMPUTED_CALL"}, "0x5000"),
        _row("patch", "function_instruction_window", {"bytes": "33 C0 C3"}, "0x5000"),
    ]

    assert derive_static_mechanism_links(rows) == []


def test_static_mechanism_links_do_not_call_shell_apis_dynamic_resolver_consumers() -> None:
    """CreateProcess/ReadFile are shell evidence, not proof of resolved API use."""
    rows = [
        _row("gpa", "function_call", {"target_function": "GetProcAddress", "type": "COMPUTED_CALL"}, "0x6000"),
        _row("proc", "function_call", {"target_function": "CreateProcessW", "type": "COMPUTED_CALL"}, "0x6000"),
        _row("read", "function_call", {"target_function": "ReadFile", "type": "COMPUTED_CALL"}, "0x6000"),
        _row("pipe", "function_call", {"target_function": "CreatePipe", "type": "COMPUTED_CALL"}, "0x6000"),
    ]
    links = derive_static_mechanism_links(rows)
    assert not any(item["kind"] == "mechanism_dynamic_api_link" for item in links)
    assert any(item["kind"] == "mechanism_shell_output_link" for item in links)


def _context_row(evidence_id: str, entry: str, *targets: str) -> dict[str, object]:
    """Minimal exporter-shaped call-graph context for interprocedural tests."""
    return _row(
        evidence_id,
        "function_context",
        {
            "name": f"FUN_{entry}",
            "call_targets": [
                {"to": target, "target_function": f"FUN_{target}"}
                for target in targets
            ],
        },
        entry,
    )


def test_static_mechanism_links_follow_bounded_cross_function_call_graph() -> None:
    """Mechanisms may span helper functions when the static call graph joins them."""
    rows = [
        _row("resolver", "function_call", {"target_function": "GetProcAddress"}, "0x1000"),
        _row("consumer", "function_call", {"target_function": "WinHttpOpen"}, "0x2000"),
        _context_row("edge-resolver-consumer", "0x1000", "0x2000"),
    ]

    links = derive_static_mechanism_links(rows)

    dynamic = [item for item in links if item["kind"] == "mechanism_dynamic_api_link"]
    assert dynamic
    value = dynamic[0]["value"]
    assert value["linkage"] == "bounded_call_graph_static_facts"
    assert {"resolver", "consumer"} <= set(value["path_roles"])
    assert {"resolver", "consumer", "edge-resolver-consumer"} <= set(value["source_evidence_ids"])


def test_static_mechanism_links_follow_cross_function_transport_and_patch_paths() -> None:
    """Transport and ETW patch components are correlated through explicit edges."""
    rows = [
        _row("open", "function_call", {"target_function": "WinHttpOpen"}, "0x1100"),
        _row("send", "function_call", {"target_function": "WinHttpSendRequest"}, "0x1200"),
        _row("recv", "function_call", {"target_function": "WinHttpReceiveResponse"}, "0x1300"),
        _row("url", "string", {"text": "https://example.invalid/checkin"}, "0x1100"),
        _context_row("edge-open-send", "0x1100", "0x1200"),
        _context_row("edge-send-recv", "0x1200", "0x1300"),
        _row("etw", "function_call", {"target_function": "EtwEventWrite"}, "0x2100"),
        _row("vp", "function_call", {"target_function": "VirtualProtect"}, "0x2200"),
        _row("patch", "function_instruction_window", {"bytes": "33 C0 C3"}, "0x2200"),
        _row("flush", "function_call", {"target_function": "FlushInstructionCache"}, "0x2300"),
        _context_row("edge-etw-vp", "0x2100", "0x2200"),
        _context_row("edge-vp-flush", "0x2200", "0x2300"),
    ]

    links = derive_static_mechanism_links(rows)
    by_kind = {item["kind"]: item for item in links}

    assert by_kind["mechanism_http_transport_link"]["value"]["linkage"] == "bounded_call_graph_static_facts"
    assert by_kind["mechanism_etw_patch_link"]["value"]["linkage"] == "bounded_call_graph_static_facts"


def test_static_mechanism_links_do_not_join_disconnected_function_contexts() -> None:
    """A context row is not evidence of an edge unless it names a known target."""
    rows = [
        _row("resolver", "function_call", {"target_function": "GetProcAddress"}, "0x1000"),
        _row("consumer", "function_call", {"target_function": "WinHttpOpen"}, "0x2000"),
        _context_row("unrelated", "0x3000", "0x4000"),
    ]

    assert derive_static_mechanism_links(rows) == []


def test_static_mechanism_links_accept_explicit_pointer_table_consumer_edge() -> None:
    """An explicit pointer-table consumer edge can close a resolver path."""
    rows = [
        _row("resolver", "function_call", {"target_function": "GetProcAddress"}, "0x1000"),
        _row(
            "pointer-table",
            "indirect_function_pointer_link",
            {"consumer_function": "0x2000", "storage": "PTR_140030000"},
            "0x1000",
        ),
        _row("consumer", "function_call", {"target_function": "WinHttpOpen"}, "0x2000"),
    ]

    links = derive_static_mechanism_links(rows)

    assert any(item["kind"] == "mechanism_dynamic_api_link" for item in links)
