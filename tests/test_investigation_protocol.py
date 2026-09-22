from threat_report_agent.investigation import ActionSpec, ActionType, InvestigationLoopDriver
from threat_report_agent.investigation.investigation_protocol import (
    fill_protocol,
    is_empty_marker,
    may_record_static_boundary,
    s_ladder,
)


def test_empty_and_unknown_tokens_are_markers() -> None:
    assert is_empty_marker("UNKNOWN")
    assert is_empty_marker("UNKNOWN(api not recovered)")
    assert is_empty_marker("n/a")
    assert is_empty_marker("")
    assert is_empty_marker("   ")
    assert not is_empty_marker("LoadLibraryW")


def test_empty_text_does_not_fill_a_ten_question_slot() -> None:
    blank = fill_protocol(
        [{"id": "e1", "kind": "function_context", "value": {"name": ""}}]
    )
    assert blank["initiator"]["status"] != "ANSWERED"
    whitespace = fill_protocol(
        [{"id": "e1", "kind": "function_context", "value": {"name": "   "}}]
    )
    assert whitespace["initiator"]["status"] != "ANSWERED"
    unknown = fill_protocol(
        [{"id": "e1", "kind": "function_context", "value": {"name": "UNKNOWN"}}]
    )
    assert unknown["initiator"]["status"] != "ANSWERED"


def test_protocol_fills_answered_slots_and_keeps_structured_unknowns() -> None:
    protocol = fill_protocol(
        [
            {
                "id": "e1",
                "kind": "function_context",
                "value": {"name": "decode_config"},
            },
            {
                "id": "e2",
                "kind": "api_argument_trace",
                "value": {"resolved": True, "api": "LoadLibraryW"},
            },
        ]
    )
    assert protocol["initiator"]["status"] == "ANSWERED"
    assert protocol["initiator"]["value"] == "decode_config"
    assert protocol["loop"]["status"] == "UNKNOWN"
    assert protocol["loop"]["reason"]
    assert protocol["failure_fallback"]["status"] == "UNKNOWN"


def test_protocol_fills_persist_how_command_named_api_and_decode() -> None:
    """Kunglao DISPATCH_VERIFIER: persist HOW fills slots without leftover TRACE."""
    protocol = fill_protocol(
        [
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateProcessW",
                    "command": "cmd.exe /c FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                    "return_branch": "JZ 0x140004780",
                },
            },
            {
                "id": "resolved-1",
                "kind": "resolved_api",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "SetThreadDescription",
                    "consumer": "JMP R8",
                },
            },
            {
                "id": "decode-1",
                "kind": "decode_result",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "plaintext": "MZ",
                    "consumer": "FUN_140004605",
                },
            },
        ]
    )
    assert protocol["initiator"]["value"] == "CreateProcessW"
    assert "FoxitPDFReader.exe" in str(protocol["input"]["value"])
    assert protocol["condition"]["value"] == "0x000f4240"
    assert protocol["output"]["value"] in {"SetThreadDescription", "MZ"}
    assert protocol["consumer"]["status"] == "ANSWERED"
    assert protocol["transformation"]["status"] == "ANSWERED"
    assert "kernel32.dll" not in str(protocol)
    persist_source = __import__("inspect").getsource(
        __import__("threat_report_agent.service", fromlist=["AnalysisService"]).AnalysisService._persist_time_seed_result
    )
    assert '"protocol": fill_protocol(rows)' in persist_source or "fill_protocol(rows)" in persist_source


def test_protocol_fills_unique_thread_start_without_inventing() -> None:
    protocol = fill_protocol(
        [
            {
                "id": "trace-thread",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "0x140038ae0",
                            "resolved": True,
                        },
                        {
                            "index": 3,
                            "name": "lpParameter",
                            "value": "0x8",
                            "resolved": True,
                        },
                    ],
                },
            }
        ]
    )
    assert protocol["initiator"]["value"] == "CreateThread"
    assert protocol["output"]["value"] == "0x140038ae0"
    assert protocol["consumer"]["value"] == "0x140038ae0"
    assert protocol["input"]["value"] == "0x8"
    assert protocol["transformation"]["value"] == "CreateThread"
    missing = fill_protocol(
        [
            {
                "id": "trace-unknown",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "UNKNOWN",
                            "resolved": False,
                        }
                    ],
                },
            }
        ]
    )
    assert missing["output"]["status"] == "UNKNOWN"


def test_protocol_fills_unique_thread_loop_from_fun_body_not_process_prologue() -> None:
    """Kunglao leftover remainder: Unique OS loop is persist body, not leftover TRACE."""
    protocol = fill_protocol(
        [
            {
                "id": "trace-thread",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "0x140038ae0",
                            "resolved": True,
                        }
                    ],
                },
            },
            {
                "id": "body-thread",
                "kind": "function_context",
                "value": {
                    "name": "FUN_140038ae0",
                    "call_targets": [
                        {"target_name": "WaitForSingleObject"},
                        {"target_name": "ExitThread"},
                    ],
                    "data_references": [{"text": "work_item"}],
                },
            },
        ]
    )
    assert protocol["loop"]["status"] == "ANSWERED"
    assert "WaitForSingleObject" in str(protocol["loop"]["value"])
    assert protocol["failure_fallback"]["status"] == "ANSWERED"
    assert "ExitThread" in str(protocol["failure_fallback"]["value"])
    prologue = fill_protocol(
        [
            {
                "id": "caller",
                "kind": "function_context",
                "value": {
                    "name": "FUN_140004605",
                    "call_targets": [
                        {"target_name": "GetConsoleWindow"},
                        {"target_name": "CreateProcessW"},
                    ],
                },
            }
        ]
    )
    assert prologue["loop"]["status"] == "UNKNOWN"


def test_s_ladder_vacuous_empty_required_and_attempted_does_not_close_s4() -> None:
    ladder = s_ladder(attempted_action_types=(), required_action_types=())
    assert ladder["attempted_action_types"] == []
    assert ladder["required_action_types"] == []
    assert ladder["s4_orchestration"] != "CLOSED"
    assert may_record_static_boundary(ladder) is False


def test_s_ladder_closes_when_required_set_makes_s1_s3_explicitly_not_applicable() -> None:
    ladder = s_ladder(
        attempted_action_types=(),
        required_action_types=("DECODE_STRING",),
    )
    assert ladder["attempted_action_types"] == []
    assert ladder["required_action_types"] == ["DECODE_STRING"]
    assert ladder["s1_context"] == "NOT_APPLICABLE"
    assert ladder["s2_dataflow"] == "NOT_APPLICABLE"
    assert ladder["s3_consumer"] == "NOT_APPLICABLE"
    assert ladder["s4_orchestration"] == "CLOSED"
    assert may_record_static_boundary(ladder) is True


def test_s_ladder_blocks_static_boundary_until_s1_s3_are_attempted() -> None:
    missing = s_ladder(
        attempted_action_types=("GET_FUNCTION",),
        required_action_types=(
            "GET_FUNCTION",
            "TRACE_API_ARGUMENT",
            "TRACE_RETURN_VALUE",
        ),
        pending_action_types=("TRACE_API_ARGUMENT", "TRACE_RETURN_VALUE"),
    )
    assert missing["s1_context"] == "ATTEMPTED"
    assert missing["s2_dataflow"] == "MISSING"
    assert missing["s3_consumer"] == "MISSING"
    assert missing["s4_orchestration"] == "OPEN"
    assert may_record_static_boundary(missing) is False

    complete = s_ladder(
        attempted_action_types=(
            "GET_FUNCTION",
            "TRACE_API_ARGUMENT",
            "GET_PCODE_SLICE",
            "TRACE_RETURN_VALUE",
        ),
        required_action_types=(
            "GET_FUNCTION",
            "TRACE_API_ARGUMENT",
            "TRACE_RETURN_VALUE",
        ),
    )
    assert complete["s4_orchestration"] == "CLOSED"
    assert may_record_static_boundary(complete) is True


def test_may_record_static_boundary_rejects_closed_ladder_with_empty_attempts() -> None:
    forged = {
        "s1_context": "NOT_APPLICABLE",
        "s2_dataflow": "NOT_APPLICABLE",
        "s3_consumer": "NOT_APPLICABLE",
        "s4_orchestration": "CLOSED",
        "attempted_action_types": [],
        "required_action_types": [],
    }
    assert may_record_static_boundary(forged) is False


def _contract_action(action_id: str, action_type: ActionType, required: tuple[str, ...]) -> ActionSpec:
    return ActionSpec(
        id=action_id,
        action_type=action_type,
        thread_id="thread-1",
        hypothesis_id="h1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x1000"},
        plan={
            "deep_investigation_contract": {
                "id": "deep-static-v1",
                "category": "api",
                "required_action_types": list(required),
                "evidence_kinds_by_action": {},
            }
        },
    )


def test_coverage_empty_required_and_attempted_leaves_s4_open() -> None:
    coverage = InvestigationLoopDriver._coverage_snapshot([], [], set(), set())
    assert coverage["s_ladder"]["attempted_action_types"] == []
    assert coverage["s_ladder"]["required_action_types"] == []
    assert coverage["s_ladder"]["s4_orchestration"] != "CLOSED"
    assert coverage["s_ladder"]["s1_context"] == "NOT_APPLICABLE"
    assert may_record_static_boundary(coverage["s_ladder"]) is False
    assert all(item.get("evidence_status") != "STATIC_BOUNDARY" for item in coverage["targets"])


def test_coverage_does_not_close_on_one_no_new_evidence_action() -> None:
    required = ("GET_FUNCTION",)
    action = _contract_action("a1", ActionType.GET_FUNCTION, required)
    coverage = InvestigationLoopDriver._coverage_snapshot(
        [action],
        [],
        {"a1"},
        set(),
    )
    assert coverage["targets"][0]["evidence_status"] == "EVIDENCE_GAP"
    assert coverage["protocol"]["initiator"]["status"] == "UNKNOWN"
    assert coverage["s_ladder"]["s4_orchestration"] != "CLOSED"
    assert may_record_static_boundary(coverage["s_ladder"]) is False


def test_coverage_records_static_boundary_after_s1_s3_attempts() -> None:
    required = ("GET_FUNCTION", "TRACE_API_ARGUMENT", "GET_CALLEES")
    actions = [
        _contract_action("a1", ActionType.GET_FUNCTION, required),
        _contract_action("a2", ActionType.TRACE_API_ARGUMENT, required),
        _contract_action("a3", ActionType.GET_CALLEES, required),
    ]
    coverage = InvestigationLoopDriver._coverage_snapshot(
        actions,
        [],
        {"a1", "a2", "a3"},
        set(),
    )
    assert coverage["targets"][0]["evidence_status"] == "STATIC_BOUNDARY"
    assert coverage["s_ladder"]["s4_orchestration"] == "CLOSED"
    assert coverage["claim_eligible"] is False
