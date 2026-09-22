from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.investigation import (
    ActionType,
    MechanismPlaybookRegistry,
    apply_emulation_reverification,
    how_timebox_disposition,
    recovery_actions_for_gap,
    verify_mechanism,
)
from threat_report_agent.product_certification import mechanism_coverage_metrics
from threat_report_agent.service import AnalysisService


def test_how_timebox_defers_controlled_emulate_instead_of_static_boundary() -> None:
    disposition, method = how_timebox_disposition(ActionType.CONTROLLED_EMULATE.value)
    assert disposition == "defer"
    assert method == ActionType.CONTROLLED_EMULATE.value

    placeholder = [
        {
            "kind": "simulation_result",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        }
    ]
    disposition, method = how_timebox_disposition(
        "STATIC_BOUNDARY",
        attempted=["GET_DECOMPILE", "CONTROLLED_EMULATE"],
        evidence=placeholder,
    )
    assert disposition == "defer"
    assert method == ActionType.CONTROLLED_EMULATE.value

    real = [
        {
            "kind": "simulation_result",
            "value": {"status": "SUCCEEDED", "simulator": "unicorn", "function_entry": "0x1800011c0"},
        }
    ]
    disposition, method = how_timebox_disposition(
        "STATIC_BOUNDARY",
        attempted=["GET_DECOMPILE", "CONTROLLED_EMULATE"],
        evidence=real,
    )
    assert disposition == "terminate"
    assert method == "STATIC_BOUNDARY"


def test_decode_gap_still_queues_trace_after_candidate() -> None:
    actions = recovery_actions_for_gap(
        "DECODE_CONFIG",
        ("cipher/data",),
        attempted=["GET_PCODE_SLICE", "DECODE_CANDIDATE"],
    )
    assert ActionType.TRACE_API_ARGUMENT.value in actions
    assert ActionType.CONTROLLED_EMULATE.value in actions
    assert actions[0] == ActionType.TRACE_API_ARGUMENT.value


def test_process_execution_without_createprocess_is_not_applicable() -> None:
    listing = [
        {
            "id": "imp",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW"},
            "anchor": {"type": "pe_import"},
        }
    ]
    result = verify_mechanism("PROCESS_EXECUTION", listing)
    assert result.accepted is False
    assert result.status == "NOT_APPLICABLE"
    assert recovery_actions_for_gap("PROCESS_EXECUTION", ("creation_flags",), evidence=listing) == ()
    metrics = mechanism_coverage_metrics(
        [
            {"mechanism_type": "PROCESS_EXECUTION", "status": "NOT_APPLICABLE"},
            {
                "mechanism_type": "DYNAMIC_API_RESOLUTION",
                "status": "VERIFIED",
                "target": "resolver",
                "inputs": ["kernel32"],
                "transformation_or_control": ["GetProcAddress"],
                "outputs": ["pointer"],
                "consumers": ["call rax"],
                "side_effects": ["resolves API"],
                "evidence_ids": ["e1", "e2"],
                "verifier": {"status": "VERIFIED"},
            },
        ]
    )
    assert metrics["mechanism_count"] == 1
    assert metrics["verified_mechanism_count"] == 1


def test_cryptdecrypt_does_not_fail_xor_counter_checklist() -> None:
    incomplete = [
        {
            "id": "decrypt",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CryptDecrypt"},
            "anchor": {"function_entry": "0x180001000"},
        }
    ]
    result = verify_mechanism("DECODE_CONFIG", incomplete)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert "counter" not in result.missing
    assert "step" not in result.missing
    assert "cipher/data" in result.missing

    closed = [
        {
            "id": "import-key",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CryptImportKey",
                "key_blob": {"address": "0x18000a000", "length": 16},
                "arguments": [
                    {"index": 1, "name": "pbData", "value": "0x18000a000", "resolved": True},
                ],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "id": "decrypt",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CryptDecrypt",
                "algorithm": "CALG_RC4",
                "pbData": {"address": "0x18000b000", "length": 64},
                "arguments": [
                    {"index": 1, "name": "pbData", "value": "0x18000b000", "resolved": True},
                ],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "id": "flow",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "output_to_consumer",
                "consumer": "CreateThread lpParameter",
                "source_evidence_ids": ["decrypt", "import-key"],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
    ]
    verified = verify_mechanism("DECODE_CONFIG", closed)
    assert verified.accepted is True
    assert verified.status == "VERIFIED"
    assert not verified.missing


def test_real_simulation_result_reverifies_mechanisms() -> None:
    mechanisms = [
        {
            "mechanism_type": "DECODE_CONFIG",
            "status": "CANDIDATE",
            "target": "CryptDecrypt",
        }
    ]
    placeholder = [
        {
            "kind": "simulation_result",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        }
    ]
    unchanged = apply_emulation_reverification(mechanisms, placeholder)
    assert unchanged[0]["status"] == "CANDIDATE"

    evidence = [
        {
            "id": "decrypt",
            "kind": "function_call",
            "value": {"api": "CryptDecrypt"},
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "kind": "simulation_result",
            "value": {
                "status": "SUCCEEDED",
                "simulator": "speakeasy",
                "function_entry": "0x180001000",
            },
        },
    ]
    updated = apply_emulation_reverification(mechanisms, evidence)
    assert updated[0]["status"] != "VERIFIED"
    assert updated[0]["next_method"] == ActionType.TRACE_API_ARGUMENT.value
    assert "counter" not in (updated[0].get("verifier") or {}).get("missing", ())


def test_xor_config_playbook_includes_trace_and_emulate() -> None:
    playbook = MechanismPlaybookRegistry().by_id("xor-config-recovery")
    names = {item.value for item in playbook.preferred_actions}
    assert ActionType.TRACE_API_ARGUMENT.value in names
    assert ActionType.GET_DECOMPILE.value in names
    assert ActionType.CONTROLLED_EMULATE.value in names


def test_persist_skip_keeps_argument_trace_and_emulate() -> None:
    from threat_report_agent.investigation import ActionSpec

    trace = ActionSpec(
        id="queued-trace",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    recover = ActionSpec(
        id="queued-arg",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"api": "CryptDecrypt"},
    )
    emu = ActionSpec(
        id="queued-emu",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    kept = AnalysisService._keep_emulation_after_persist_skip((trace, recover, emu))
    assert [item.id for item in kept] == ["queued-arg", "queued-emu"]

    queued_trace = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.GET_CALLEES.value,
        error=None,
        finished_at=None,
    )
    queued_arg = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.TRACE_API_ARGUMENT.value,
        error=None,
        finished_at=None,
    )
    queued_emu = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.CONTROLLED_EMULATE.value,
        error=None,
        finished_at=None,
    )
    AnalysisService._supersede_queued_trace_after_persist_skip(
        (queued_trace, queued_arg, queued_emu),
        thread_id="thread-decode",
    )
    assert queued_trace.status == "CANCELLED"
    assert queued_arg.status == "QUEUED"
    assert queued_emu.status == "QUEUED"


def test_gap_driven_rounds_are_not_skipped_only_because_dsh_owns_chat() -> None:
    import inspect

    from threat_report_agent.task.analysis_task_orchestration import (
        run_emulation_informed_investigation,
    )

    source = inspect.getsource(AnalysisService._run_gap_driven_model_rounds)
    early = source.split("limitations: list[str] = []", 1)[0]
    assert "dsh_conversation_owns_planning" not in early
    loop_source = inspect.getsource(AnalysisService._run_investigation_loop)
    assert "how_timebox_disposition" in loop_source
    emu_source = inspect.getsource(run_emulation_informed_investigation)
    assert "_reverify_how_after_emulation" in emu_source
    assert "apply_emulation_reverification" in inspect.getsource(
        AnalysisService._reverify_how_after_emulation
    )


def test_consumer_gap_schedules_argument_trace_first() -> None:
    """G0 §4.4：对象级消费者是「解码输出缓冲进了哪个 API 参数」。

    缺 consumer 时必须先跑 TRACE_API_ARGUMENT。只跑 GET_CALLEES /
    TRACE_RETURN_VALUE / GET_DECOMPILE 补不上这条边，预算会烧在反编译上。
    """
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("consumer",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions
    assert actions[0] == ActionType.TRACE_API_ARGUMENT.value
    assert ActionType.GET_DECOMPILE.value in actions
    assert ActionType.CONTROLLED_EMULATE.value in actions


def test_unknown_wrapped_consumer_gap_still_schedules_argument_trace() -> None:
    """G0 §4.3：verifier 缺口可能写成 unknown(consumer)，不能因此漏掉恢复动作。"""
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("unknown(consumer)",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions


def test_join_gap_schedules_argument_trace() -> None:
    """G0 §4.3：join 也是镜像内可恢复槽，必须继续 TRACE，不能静态收工。"""
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("join",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions


def test_parent_identity_gap_schedules_object_chain_recovery() -> None:
    """G0 §4.3：parent identity 要靠镜像内的枚举/名称使用链，不是再反编译一遍。"""
    actions = recovery_actions_for_gap("PPID_SPOOFING", ("parent identity",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions
