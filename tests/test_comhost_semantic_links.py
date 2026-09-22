from __future__ import annotations

from types import SimpleNamespace

from benchmarks.comhost_differential import evaluate_task_view
from threat_report_agent.investigation import (
    verify_mechanism,
    derive_static_mechanism_links,
    _link_function_key,
    DeepMiningPlanner,
)
from uuid import UUID


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
    assert all(item["nature"] == "STATIC_DERIVED" for item in links)
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


def test_capstone_fallback_calls_join_a_bounded_shell_mechanism_region() -> None:
    """Fallback RVA signals should still produce a candidate mechanism path."""
    rows = [
        {
            "id": "proc",
            "kind": "code_api_call",
            "value": {"api": "KERNEL32.dll!CreateProcessW", "rva": 0x1240},
            "anchor": {"type": "rva_call_site", "rva": 0x1240},
        },
        {
            "id": "pipe",
            "kind": "code_api_call",
            "value": {"api": "KERNEL32.dll!CreatePipe", "rva": 0x12A0},
            "anchor": {"type": "rva_call_site", "rva": 0x12A0},
        },
        {
            "id": "read",
            "kind": "code_api_call",
            "value": {"api": "KERNEL32.dll!ReadFile", "rva": 0x1310},
            "anchor": {"type": "rva_call_site", "rva": 0x1310},
        },
    ]

    links = derive_static_mechanism_links(rows)

    shell = next(item for item in links if item["kind"] == "mechanism_shell_output_link")
    assert shell["value"]["mechanism_type"] == "SHELL_OUTPUT"
    assert shell["value"]["source_evidence_ids"] == ["proc", "pipe", "read"]
    assert shell["anchor"]["function_entry"] == "fallback_region@0x1000"


def test_static_mechanism_link_identity_is_stable_when_evidence_order_changes() -> None:
    """Equivalent extractor ordering must not create a second mechanism link."""
    rows = [
        _row("gpa", "function_call", {"target_function": "GetProcAddress"}),
        _row("load", "function_call", {"target_function": "LoadLibraryW"}),
        _row("consumer", "function_call", {"target_function": "WinHttpOpen"}),
    ]

    forward = {
        item["kind"]: item["id"]
        for item in derive_static_mechanism_links(rows)
    }
    reverse = {
        item["kind"]: item["id"]
        for item in derive_static_mechanism_links(list(reversed(rows)))
    }

    assert forward == reverse

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


def test_relationship_fields_without_a_function_anchor_stay_global() -> None:
    """A callee name is not the enclosing function identity."""
    row = {
        "id": "unanchored-call",
        "kind": "function_call",
        "value": {"target_function": "GetProcAddress"},
        "anchor": {"offset": 128},
    }

    assert _link_function_key(row) == "__global__"


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


def test_exporter_shaped_fields_close_cross_function_dynamic_api_path() -> None:
    """Ghidra-shaped callee/resolved-api fields remain provenance scoped."""
    rows = [
        _row(
            "resolver-fact",
            "resolved_api",
            {
                "resolver": "GetProcAddress",
                "api_name": "WinHttpOpen",
                "string_address": "0x4000",
            },
            "0x1000",
        ),
        _row(
            "resolver-context",
            "function_context",
            {
                "name": "FUN_1000",
                "entry": "0x1000",
                "callees": [{"callee": "0x2000", "edge_type": "CALL"}],
            },
            "0x1000",
        ),
        _row(
            "consumer-context",
            "function_context",
            {
                "name": "FUN_2000",
                "entry": "0x2000",
                "calls": [{"callee": "WinHttpOpen", "referenced_target": "WinHttpOpen"}],
            },
            "0x2000",
        ),
    ]

    links = derive_static_mechanism_links(rows)
    dynamic = [item for item in links if item["kind"] == "mechanism_dynamic_api_link"]
    assert dynamic
    assert any(
        item["value"]["linkage"] == "bounded_call_graph_static_facts"
        for item in dynamic
    )
    verified = verify_mechanism(
        "DYNAMIC_API_RESOLUTION", rows + dynamic
    )
    assert verified.accepted


def test_exporter_shaped_fields_close_winhttp_transport_path() -> None:
    """Structured callee fields and a same-function URL form a transport path."""
    rows = [
        _row(
            "open",
            "function_call",
            {"callee": "WinHttpOpen", "api_name": "WinHttpOpen"},
            "0x3000",
        ),
        _row(
            "send",
            "function_call",
            {"callee": "WinHttpSendRequest", "referenced_target": "WinHttpSendRequest"},
            "0x3000",
        ),
        _row(
            "recv",
            "function_call",
            {"callee": "WinHttpReceiveResponse", "api_name": "WinHttpReceiveResponse"},
            "0x3000",
        ),
        _row("url", "string", {"text": "https://example.invalid/checkin"}, "0x3000"),
    ]

    links = derive_static_mechanism_links(rows)
    transport = [item for item in links if item["kind"] == "mechanism_http_transport_link"]
    assert transport
    assert verify_mechanism("HTTP_DOWNLOAD", rows + transport).accepted


def test_structured_patch_bytes_are_required_for_etw_verification() -> None:
    """Only exact opcode bytes, not a length or field name, close ETW patching."""
    rows = [
        _row("etw", "function_call", {"api_name": "EtwEventWrite"}, "0x5000"),
        _row("vp", "function_call", {"callee": "VirtualProtect"}, "0x5000"),
        _row("flush", "function_call", {"referenced_target": "FlushInstructionCache"}, "0x5000"),
        _row(
            "patch",
            "function_instruction_window",
            {"opcode_bytes": [0x33, 0xC0, 0xC3], "length": 3},
            "0x5000",
        ),
    ]

    links = derive_static_mechanism_links(rows)
    patch_links = [item for item in links if item["kind"] == "mechanism_etw_patch_link"]
    assert patch_links
    assert verify_mechanism("ETW_PATCH", rows + patch_links).accepted

    wrong = [
        *rows[:3],
        _row(
            "wrong-patch",
            "function_instruction_window",
            {"opcode_bytes": [0x90, 0x90, 0x90], "length": 3},
            "0x5000",
        ),
    ]
    assert derive_static_mechanism_links(wrong) == []
    assert not verify_mechanism("ETW_PATCH", wrong).accepted


def test_structured_patch_hex_mapping_is_supported() -> None:
    """Exporter byte wrappers should still close an exact ETW patch path."""
    rows = [
        _row("etw", "function_call", {"api_name": "EtwEventWrite"}, "0x5100"),
        _row("vp", "function_call", {"callee": "VirtualProtect"}, "0x5100"),
        _row("flush", "function_call", {"referenced_target": "FlushInstructionCache"}, "0x5100"),
        _row(
            "patch",
            "function_instruction_window",
            {"bytes": {"hex": "33 c0 c3"}},
            "0x5100",
        ),
    ]

    links = derive_static_mechanism_links(rows)
    assert any(item["kind"] == "mechanism_etw_patch_link" for item in links)


def test_deep_mining_extracts_resolved_and_nested_api_fields() -> None:
    """All supported exporter API spellings must create one deep target."""
    rows = [
        _row(
            "resolved",
            "resolved_api",
            {"resolved_api": "KERNEL32!CreateProcessW", "symbol": {"name": "VirtualProtect"}},
            "0x5200",
        ),
        _row(
            "context",
            "function_context",
            {"entry": "0x5200", "call_targets": [{"target": "WinHttpOpen"}]},
            "0x5200",
        ),
    ]

    targets = DeepMiningPlanner.build_frontier(rows, max_targets=32)
    categories = {item.category for item in targets if item.selector.get("function_entry") == "0x5200"}
    assert {"network", "process", "evasion_or_memory"} <= categories


def test_static_mechanism_link_ids_are_invariant_to_evidence_order() -> None:
    """Replayed evidence with a different row order must reuse the same link.

    Evidence retrieval may be paginated or return rows in a different order
    after a restart.  Mechanism identity is set-based provenance, so changing
    that order must not create a second derived link.
    """
    rows = [
        _row("resolver", "function_call", {"target_function": "GetProcAddress"}, "0x1000"),
        _row("consumer", "function_call", {"target_function": "WinHttpOpen"}, "0x1000"),
    ]

    first = derive_static_mechanism_links(rows)
    replay = derive_static_mechanism_links(list(reversed(rows)))

    first_links = [item for item in first if item["kind"] == "mechanism_dynamic_api_link"]
    replay_links = [item for item in replay if item["kind"] == "mechanism_dynamic_api_link"]
    assert len(first_links) == len(replay_links) == 1
    assert first_links[0]["id"] == replay_links[0]["id"]
    # Evidence IDs use the shared UUID-shaped primary-key contract.  Derived
    # links must remain deterministic without overflowing PostgreSQL's
    # varchar(36) column.
    assert len(first_links[0]["id"]) == 36
    UUID(first_links[0]["id"])
    assert set(first_links[0]["value"]["source_evidence_ids"]) == set(
        replay_links[0]["value"]["source_evidence_ids"]
    )


def test_cross_function_links_prioritize_required_rows_under_evidence_budget() -> None:
    """C1/C2 links must survive the bounded 24-row action evidence window."""
    rows = []
    for index in range(30):
        rows.append(
            _row(f"noise-resolver-{index}", "string", {"text": f"noise-{index}"}, "0x1000")
        )
    rows.extend(
        [
            _row("resolver", "function_call", {"target_function": "GetProcAddress"}, "0x1000"),
            _row("edge", "function_context", {"call_targets": [{"to": "0x2000"}]}, "0x1000"),
        ]
    )
    for index in range(30):
        rows.append(
            _row(f"noise-consumer-{index}", "string", {"text": f"noise-{index}"}, "0x2000")
        )
    rows.extend(
        [
            _row("open", "function_call", {"target_function": "WinHttpOpen"}, "0x2000"),
            _row("send", "function_call", {"target_function": "WinHttpSendRequest"}, "0x2000"),
            _row("recv", "function_call", {"target_function": "WinHttpReceiveResponse"}, "0x2000"),
            _row("url", "string", {"text": "https://example.invalid/checkin"}, "0x2000"),
        ]
    )

    links = derive_static_mechanism_links(rows)
    dynamic = next(item for item in links if item["kind"] == "mechanism_dynamic_api_link")
    transport = next(item for item in links if item["kind"] == "mechanism_http_transport_link")

    # This mirrors the bounded source-row materialization used by action
    # execution: only cited source IDs are selected from the artifact, then
    # the 24-row limit is applied.  Required semantic rows must remain.
    dynamic_rows = [
        item for item in rows if item["id"] in dynamic["value"]["source_evidence_ids"]
    ][:24]
    transport_rows = [
        item for item in rows if item["id"] in transport["value"]["source_evidence_ids"]
    ][:24]
    assert {"resolver", "open"} <= {item["id"] for item in dynamic_rows}
    assert {"send", "recv", "url"} <= {item["id"] for item in transport_rows}
    assert verify_mechanism("DYNAMIC_API_RESOLUTION", dynamic_rows + [dynamic]).accepted
    assert verify_mechanism("HTTP_DOWNLOAD", transport_rows + [transport]).accepted
