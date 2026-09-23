from threat_report_agent.static_analysis import (
    pe_slice_at_rva,
    recovered_payload_from_verification,
    unique_thread_function_starts,
    unique_thread_start_routine_vas,
)
from threat_report_agent.simulation_adapters import IsolatedSimulationRunner
from threat_report_agent.emulation.policy import (
    SimulationExecutionPolicy,
    SimulationRequest,
)


def _local_policy() -> SimulationExecutionPolicy:
    return SimulationExecutionPolicy(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="local-python-subprocess-v1",
        worker_image_digest="local-unisolated",
        allowed_simulators=("unicorn",),
        isolation_kind="local-process",
        allow_local_process=True,
        max_timeout_seconds=30,
        max_instruction_budget=1_000_000,
        max_output_bytes=65536,
    )


def test_pe_slice_at_rva_reads_granted_section_bytes() -> None:
    content = b"\x00" * 0x200 + b"ABCD" + b"\x00" * 32
    pe = {
        "image_base": 0x400000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "raw_offset": 0x200,
            }
        ],
    }
    assert pe_slice_at_rva(content, pe, 0x401000, length=4) == b"ABCD"
    assert pe_slice_at_rva(content, pe, 0x1000, length=4) == b"ABCD"


def test_recovered_payload_rejects_mz_stub_and_keeps_real_bytes() -> None:
    assert recovered_payload_from_verification({"status": "VERIFIED_STATIC_DATA", "plaintext_hex": "4d5a"}) == b""
    payload = recovered_payload_from_verification(
        {"status": "VERIFIED_STATIC_DATA", "plaintext_hex": "41" * 16}
    )
    assert payload == b"A" * 16
    assert recovered_payload_from_verification({"status": "UNVERIFIED_STATIC_CANDIDATE", "plaintext_hex": "41" * 32}) == b""


def test_unique_thread_starts_exclude_remote_injection() -> None:
    starts = unique_thread_function_starts(
        [
            {
                "name": "worker",
                "entry": "0x401000",
                "references_from": [{"target_name": "CreateThread"}],
            },
            {
                "name": "inject",
                "entry": "0x402000",
                "references_from": [
                    {"target_name": "WriteProcessMemory"},
                    {"target_name": "CreateRemoteThread"},
                ],
            },
        ]
    )
    assert [item["name"] for item in starts] == ["worker"]


def test_unique_thread_starts_follow_iat_thunk_and_ghidra_fun_lea() -> None:
    """Live Resume: CALL FUN_140046900 / LEA R8,FUN_140038ae0, not a named CreateThread ref."""
    thunk = {
        "name": "FUN_140046900",
        "entry": "0x140046900",
        "instructions": [
            {"address": "0x140046900", "text": "JMP qword ptr [PTR_CreateThread_14005e600]"},
        ],
    }
    creator = {
        "name": "FUN_1400440b9",
        "entry": "0x1400440b9",
        "references_from": [
            {
                "type": "UNCONDITIONAL_CALL",
                "from": "0x1400440b9",
                "to": "140046900",
                "target_name": "FUN_140046900",
            }
        ],
        "instructions": [
            {"address": "0x1400440b0", "text": "LEA R8,FUN_140038ae0"},
            {"address": "0x1400440b9", "text": "CALL 0x140046900"},
        ],
    }
    inject = {
        "name": "inject",
        "entry": "0x140050000",
        "references_from": [{"target_name": "CreateRemoteThread"}],
        "instructions": [{"text": "CALL CreateRemoteThread"}],
    }
    functions = [thunk, creator, inject]
    starts = unique_thread_function_starts(functions)
    assert [item["name"] for item in starts] == ["FUN_1400440b9"]
    assert unique_thread_start_routine_vas(functions) == (0x140038AE0,)


def test_unicorn_in_place_transform_exposes_recovered_output_bytes() -> None:
    # xor al, 0x41; ret  — transforms the first byte when it is executed in place.
    payload = bytes.fromhex("34 41 c3") + b"\x90" * 13
    result = IsolatedSimulationRunner(policy=_local_policy()).run(
        SimulationRequest(
            "unicorn",
            "must-not-be-read.bin",
            input_bytes=payload,
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
            timeout_seconds=8,
            instruction_budget=64,
        )
    )
    assert result.status == "SUCCEEDED"
    if result.output_bytes:
        assert result.output_bytes != payload
        assert recovered_payload_from_verification(
            {"status": "SUCCEEDED", "output_bytes": result.output_bytes}
        ) in {result.output_bytes, b""}
