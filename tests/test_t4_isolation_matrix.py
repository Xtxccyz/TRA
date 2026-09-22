"""T4 isolation/authenticity matrix: IsolatedSimulationRunner, policy, tool_execution.

These tests exercise real adapters with benign granted bytes. They do not
contact sample domains and they do not treat a mock adapter as acceptance.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.simulation_adapters import (
    IsolatedSimulationRunner,
    SimulationExecutionPolicy,
    SimulationRequest,
    benign_pe32_ret,
    default_simulation_runner,
    linux_x86_64_exit_elf,
)
from threat_report_agent.static_analysis import recovered_payload_from_verification
from threat_report_agent.tools.tool_execution import StaticToolActivities, ToolRunRequest


def _local_policy(**overrides: object) -> SimulationExecutionPolicy:
    values = dict(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="local-python-subprocess-v1",
        worker_image_digest="local-unisolated",
        allowed_simulators=("unicorn", "speakeasy", "qiling", "flare-emu"),
        isolation_kind="local-process",
        allow_local_process=True,
        network_access=False,
        max_timeout_seconds=8,
        max_instruction_budget=100_000,
        max_output_bytes=65536,
    )
    values.update(overrides)
    return SimulationExecutionPolicy(**values)


def _request(
    simulator: str,
    *,
    input_bytes: bytes | None = b"\x90\xc3",
    **overrides: object,
) -> SimulationRequest:
    values: dict[str, object] = dict(
        simulator=simulator,
        sample_path="must-not-be-read.bin",
        input_bytes=input_bytes,
        worker_identity="local-python-subprocess-v1",
        worker_image_digest="local-unisolated",
        timeout_seconds=8,
        instruction_budget=64,
    )
    values.update(overrides)
    return SimulationRequest(**values)  # type: ignore[arg-type]


def _emu_settings(test_settings, tmp_path, **overrides: object):
    values = dict(
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy", "qiling"),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    values.update(overrides)
    return replace(test_settings, **values)


def _emulator_request(source, **overrides: object) -> ToolRunRequest:
    values = dict(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-t4",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "entry_address": 0x1000000,
                    "role": "os_thread_start_routine",
                }
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    values.update(overrides)
    return ToolRunRequest(**values)  # type: ignore[arg-type]


def test_missing_input_bytes_are_an_honest_stop_not_succeeded() -> None:
    runner = default_simulation_runner(_local_policy())
    for simulator in ("unicorn", "speakeasy", "qiling"):
        result = runner.run(_request(simulator, input_bytes=None))
        assert result.status != "SUCCEEDED", simulator
        assert result.status == "INPUT_REQUIRED"
        assert result.stop_reason in {"MISSING_INPUT", "NO_GRANTED_WINDOW"}
        assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_empty_granted_bytes_are_an_honest_stop_not_succeeded() -> None:
    runner = default_simulation_runner(_local_policy())
    for simulator in ("unicorn", "speakeasy", "qiling"):
        result = runner.run(_request(simulator, input_bytes=b""))
        assert result.status != "SUCCEEDED", simulator
        assert result.status == "INPUT_REQUIRED"
        assert result.stop_reason in {"MISSING_INPUT", "NO_GRANTED_WINDOW"}
        assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_worker_without_granted_window_records_no_granted_window(
    test_settings, tmp_path
) -> None:
    settings = _emu_settings(test_settings, tmp_path)
    store = LocalContentStore(settings.content_store_path)
    source = store.put(b"not-a-pe-or-elf")
    result = StaticToolActivities(settings, store)._execute(
        _emulator_request(source, parameters={"granted_windows": []})
    )
    assert result["status"] == "FAILED"
    assert result["error"] == "NO_GRANTED_WINDOW"
    payload = json.loads(store.read(str(result["output_storage_key"])))
    assert payload["status"] != "SUCCEEDED"
    assert any(
        item.get("stop_reason") == "NO_GRANTED_WINDOW" for item in payload.get("results") or []
    )


def test_unicorn_instruction_budget_stops_a_tight_loop() -> None:
    started = time.monotonic()
    result = default_simulation_runner(_local_policy()).run(
        _request("unicorn", input_bytes=bytes.fromhex("ebfe"), instruction_budget=32)
    )
    elapsed = time.monotonic() - started
    assert elapsed < 2.0
    assert result.status == "TIMED_OUT"
    assert result.stop_reason == "INSTRUCTION_BUDGET"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_speakeasy_instruction_budget_stops_a_tight_loop() -> None:
    started = time.monotonic()
    result = default_simulation_runner(_local_policy()).run(
        _request(
            "speakeasy",
            input_bytes=benign_pe32_ret(code=bytes.fromhex("ebfe")),
            instruction_budget=16,
            timeout_seconds=2,
        )
    )
    elapsed = time.monotonic() - started
    assert elapsed < 5.0
    assert result.status in {"TIMED_OUT", "FAILED"}
    assert result.status != "SUCCEEDED"
    assert result.stop_reason in {"INSTRUCTION_BUDGET", "TIMEOUT", "EXECUTION_ERROR"}
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_cancelled_unicorn_loop_returns_cancelled_not_succeeded() -> None:
    cancel = threading.Event()
    started = threading.Event()

    def on_cancel() -> bool:
        if not started.is_set():
            started.set()
        return cancel.is_set()

    results: list[object] = []

    def run() -> None:
        results.append(
            IsolatedSimulationRunner(
                policy=_local_policy(max_instruction_budget=2_000_000)
            ).run(
                _request(
                    "unicorn",
                    input_bytes=bytes.fromhex("ebfe"),
                    instruction_budget=2_000_000,
                    timeout_seconds=8,
                    cancellation_requested=on_cancel,
                )
            )
        )

    worker = threading.Thread(target=run)
    worker.start()
    assert started.wait(2)
    cancel.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    result = results[0]
    assert result.status == "CANCELLED"
    assert result.stop_reason == "ACTIVITY_CANCELLED"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_network_access_request_is_rejected_by_policy() -> None:
    result = default_simulation_runner(_local_policy()).run(
        _request("unicorn", network_access=True)
    )
    assert result.status == "REJECTED"
    assert result.stop_reason == "POLICY_DENIED"
    assert "network" in result.limitations[0].casefold()


def test_local_process_disabled_does_not_execute_granted_bytes() -> None:
    policy = _local_policy(allow_local_process=False)
    result = IsolatedSimulationRunner(policy=policy).run(_request("unicorn"))
    assert result.status == "REJECTED"
    assert result.stop_reason == "POLICY_DENIED"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_adapters_do_not_open_sample_path_or_make_outbound_connects(monkeypatch) -> None:
    sentinel = Path("must-not-be-read.bin")
    opened: list[str] = []
    connects: list[object] = []
    real_open = open

    def guarded_open(path, *args, **kwargs):
        text = str(path)
        if "must-not-be-read" in text:
            opened.append(text)
            raise AssertionError(f"sample_path opened: {text}")
        return real_open(path, *args, **kwargs)

    def record_connect(self, address, *args, **kwargs):
        connects.append(address)
        raise AssertionError(f"outbound connect: {address}")

    monkeypatch.setattr("builtins.open", guarded_open)
    monkeypatch.setattr(socket.socket, "connect", record_connect)
    runner = default_simulation_runner(_local_policy())
    unicorn = runner.run(_request("unicorn", input_bytes=bytes.fromhex("48c7c001000000c3")))
    speakeasy = runner.run(
        _request("speakeasy", input_bytes=benign_pe32_ret(), instruction_budget=64)
    )
    qiling = runner.run(
        _request("qiling", input_bytes=linux_x86_64_exit_elf()),
    )
    assert opened == []
    assert connects == []
    assert unicorn.status == "SUCCEEDED"
    assert speakeasy.status in {"SUCCEEDED", "FAILED", "UNAVAILABLE", "TIMED_OUT"}
    assert qiling.status != "SUCCEEDED" or "linux" in " ".join(qiling.assumptions).casefold()
    assert sentinel.exists() is False


def test_unicorn_benign_snippet_records_stop_reason_and_assumptions() -> None:
    result = default_simulation_runner(_local_policy()).run(
        _request("unicorn", input_bytes=bytes.fromhex("48c7c001000000c3"))
    )
    payload = result.as_dict()
    assert result.status == "SUCCEEDED"
    assert result.stop_reason in {"END_ADDRESS", "UNMAPPED_RETURN"}
    assert result.registers.get("RAX") == 1
    assert payload["input_sha256"]
    assert payload["evidence_nature"] == "EMULATION_OBSERVED"
    folded = " ".join(result.assumptions).casefold()
    assert "network" in folded
    assert "sample_path" not in folded or "not" in folded


def test_unicorn_benign_xor_transform_is_emulation_observed() -> None:
    """C6 T4: Unicorn must actually transform granted bytes; not a mock EMULATION_OBSERVED."""
    # xor byte ptr [rip+1], 0x55; ret; db 0x12  →  0x12 ^ 0x55 == 0x47
    snippet = bytes.fromhex("80350100000055c312")
    result = default_simulation_runner(_local_policy()).run(
        _request("unicorn", input_bytes=snippet, instruction_budget=16)
    )
    payload = result.as_dict()
    assert result.status == "SUCCEEDED"
    assert payload["evidence_nature"] == "EMULATION_OBSERVED"
    assert result.output_bytes.endswith(b"\x47")
    assert result.output_bytes != snippet
    assert payload["output_sha256"] != payload["input_sha256"]
    assert payload["input_sha256"]
    assert payload["decoded_buffers"]
    assert payload["decoded_buffers"][0]["event"] == "buffer_output"
    assert "DYNAMIC" not in str(payload)
    assert "already ran" not in " ".join(result.assumptions).casefold()


def test_speakeasy_benign_pe_is_user_mode_stub_not_host_loader() -> None:
    result = default_simulation_runner(_local_policy()).run(
        _request("speakeasy", input_bytes=benign_pe32_ret(), instruction_budget=256)
    )
    payload = result.as_dict()
    assert result.stop_reason not in {"NOT_PE", "MISSING_INPUT"}
    assert result.status in {"SUCCEEDED", "FAILED", "TIMED_OUT", "UNAVAILABLE"}
    folded = " ".join([*result.assumptions, *result.limitations]).casefold()
    assert "sample_path" in folded or "user-mode" in folded or "stub" in folded
    if result.status == "SUCCEEDED":
        assert payload["evidence_nature"] == "EMULATION_OBSERVED"
        assert "host execution" in folded or "not host" in folded
    else:
        assert payload["evidence_nature"] != "EMULATION_OBSERVED"


def test_qiling_windows_pe_is_not_linux_elf() -> None:
    result = default_simulation_runner(
        _local_policy(qiling_rootfs=str(Path(".").resolve()))
    ).run(_request("qiling", input_bytes=benign_pe32_ret()))
    assert result.status == "UNSUPPORTED"
    assert result.stop_reason == "NOT_LINUX_ELF"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_qiling_linux_elf_does_not_fake_succeeded_on_host_unicorn_1_0_2(
    tmp_path,
) -> None:
    root = tmp_path / "qiling-rootfs"
    for name in ("bin", "lib", "lib64", "usr/lib", "tmp", "proc", "dev", "etc"):
        (root / name).mkdir(parents=True)
    result = default_simulation_runner(_local_policy(qiling_rootfs=str(root))).run(
        _request(
            "qiling",
            input_bytes=linux_x86_64_exit_elf(),
            architecture="x86_64",
            instruction_budget=64,
        )
    )
    payload = result.as_dict()
    assert result.stop_reason != "ROOTFS_REQUIRED"
    assert result.status != "SUCCEEDED" or payload["evidence_nature"] == "EMULATION_OBSERVED"
    explained = " ".join([*result.assumptions, *result.limitations]).casefold()
    assert "linux" in explained
    assert all(len(item) > 3 for item in result.limitations)
    if result.status == "SUCCEEDED":
        return
    assert result.status in {"FAILED", "UNAVAILABLE"}
    assert payload["evidence_nature"] != "EMULATION_OBSERVED"
    pytest.skip(
        "host unicorn 1.0.2 cannot run Qiling Linux user-mode "
        f"(status={result.status}, stop_reason={result.stop_reason}, "
        f"limitations={list(result.limitations)[:2]}); live emu-worker remains a 3080 hole"
    )


def test_worker_recovers_transformed_child_bytes(test_settings, tmp_path) -> None:
    settings = _emu_settings(test_settings, tmp_path)
    store = LocalContentStore(settings.content_store_path)
    snippet = bytes.fromhex("48 8d 05 f9 ff ff ff c6 00 42 c3") + b"\x90" * 8
    source = store.put(snippet)
    result = StaticToolActivities(settings, store)._execute(_emulator_request(source))
    payload = json.loads(store.read(str(result["output_storage_key"])))
    unicorn = [item for item in payload["results"] if item.get("simulator") == "unicorn"]
    assert unicorn
    assert unicorn[0]["status"] == "SUCCEEDED"
    recovered = recovered_payload_from_verification(unicorn[0])
    assert recovered
    assert recovered != snippet
    assert unicorn[0]["stop_reason"] in {"END_ADDRESS", "UNMAPPED_RETURN"}


def test_unsafe_network_tool_request_is_rejected_before_emulator(
    test_settings, tmp_path
) -> None:
    import asyncio

    settings = _emu_settings(test_settings, tmp_path)
    store = LocalContentStore(settings.content_store_path)
    source = store.put(b"\x90\xc3")
    request = _emulator_request(source, network_access=True)
    result = asyncio.run(
        StaticToolActivities(settings, store).execute_static_tool(request.model_dump(mode="json"))
    )
    assert result["status"] == "FAILED"
    assert result["error"] == "UNSAFE_TOOL_REQUEST"


def test_emu_worker_compose_is_read_only_dropped_caps_and_internal_network() -> None:
    """C6 isolation contract from compose. Does not start Docker or claim C10."""
    import yaml

    payload = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    worker = payload["services"]["emu-worker"]
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in (worker.get("security_opt") or [])
    assert str(worker["environment"]["SIMULATION_ALLOW_LOCAL_PROCESS"]).lower() == "false"
    assert worker["networks"] == ["control-plane"]
    assert "edge" not in worker["networks"]
    assert payload["networks"]["control-plane"]["internal"] is True
    assert worker["environment"]["TOOL_ALLOWED_TOOLS"] == "controlled-emulator"
