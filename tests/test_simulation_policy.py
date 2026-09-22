from threat_report_agent.simulation_adapters import (
    IsolatedSimulationRunner,
    SimulationExecutionPolicy,
    SimulationRequest,
    SimulationResult,
    default_simulation_runner,
    detect_simulation_capabilities,
    linux_x86_64_exit_elf,
    qiling_unavailable_observation,
    speakeasy_capability_matrix,
)


def test_request_flags_cannot_self_authorize_execution() -> None:
    runner = IsolatedSimulationRunner(
        {"unicorn": lambda request: SimulationResult("SUCCEEDED", "unicorn")}
    )

    result = runner.run(
        SimulationRequest(
            "unicorn",
            "sample.bin",
            allow_execution=True,
            worker_isolated=True,
            worker_identity="isolated-worker-v1",
            worker_image_digest="sha256:trusted",
        )
    )

    assert result.status == "REJECTED"
    assert result.stop_reason == "POLICY_DENIED"


def test_trusted_policy_authorizes_only_matching_worker_and_budget() -> None:
    calls: list[str] = []

    def adapter(request: SimulationRequest) -> SimulationResult:
        calls.append(request.simulator)
        return SimulationResult("SUCCEEDED", request.simulator)

    policy = SimulationExecutionPolicy(
        enabled=True,
        profile="controlled-worker-v1",
        worker_identity="worker-a",
        worker_image_digest="sha256:trusted",
        allowed_simulators=("unicorn",),
        max_timeout_seconds=10,
        max_instruction_budget=100,
        max_output_bytes=128,
    )
    runner = IsolatedSimulationRunner({"unicorn": adapter}, policy=policy)

    authorized = runner.run(
        SimulationRequest(
            "unicorn",
            "sample.bin",
            # These request flags are deliberately false: the trusted policy,
            # not model/user input, is what authorizes the worker.
            allow_execution=False,
            worker_isolated=False,
            worker_identity="worker-a",
            worker_image_digest="sha256:trusted",
            timeout_seconds=10,
            instruction_budget=100,
            max_output_bytes=128,
        )
    )
    assert authorized.status == "SUCCEEDED"
    assert calls == ["unicorn"]

    wrong_image = runner.run(
        SimulationRequest(
            "unicorn",
            "sample.bin",
            worker_identity="worker-a",
            worker_image_digest="sha256:other",
        )
    )
    assert wrong_image.status == "REJECTED"
    assert "image digest" in wrong_image.limitations[0]

    over_budget = runner.run(
        SimulationRequest(
            "unicorn",
            "sample.bin",
            worker_identity="worker-a",
            worker_image_digest="sha256:trusted",
            timeout_seconds=11,
        )
    )
    assert over_budget.status == "REJECTED"
    assert "timeout" in over_budget.limitations[0]


def test_controlled_result_normalizes_observation_buckets_and_worker_identity() -> None:
    def adapter(request: SimulationRequest) -> SimulationResult:
        return SimulationResult(
            "SUCCEEDED",
            request.simulator,
            observations=({"event": "api_call", "name": "VirtualAlloc"},),
            input_sha256="input-digest",
            tool_version="worker-tool-1",
            stop_reason="END_ADDRESS",
        )

    policy = SimulationExecutionPolicy(
        enabled=True,
        profile="controlled-worker-v1",
        worker_identity="worker-a",
        worker_image_digest="sha256:trusted",
        allowed_simulators=("unicorn",),
    )
    result = IsolatedSimulationRunner({"unicorn": adapter}, policy=policy).run(
        SimulationRequest(
            "unicorn",
            "not-read-by-runner.bin",
            worker_identity="worker-a",
            worker_image_digest="sha256:trusted",
            input_bytes=b"\x90",
            architecture="x86_64",
            entry_address=0x401000,
            stubbed_apis=("VirtualAlloc",),
        )
    )

    payload = result.as_dict()
    assert payload["evidence_nature"] == "EMULATION_OBSERVED"
    assert payload["worker_identity"] == "worker-a"
    assert payload["worker_image_digest"] == "sha256:trusted"
    assert payload["architecture"] == "x86_64"
    assert payload["entry_address"] == "0x401000"
    assert payload["hooked_or_stubbed_apis"] == ["VirtualAlloc"]
    for key in (
        "attempted_apis",
        "file_operations",
        "registry_operations",
        "network_intents",
        "process_thread_operations",
        "memory_operations",
        "decoded_buffers",
        "control_flow_observations",
        "unsupported_apis",
    ):
        assert key in payload
        assert isinstance(payload[key], list)


def _local_policy(**overrides: object) -> SimulationExecutionPolicy:
    values = dict(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="local-python-subprocess-v1",
        worker_image_digest="local-unisolated",
        allowed_simulators=("unicorn", "speakeasy", "qiling", "flare-emu"),
        isolation_kind="local-process",
        allow_local_process=True,
        max_timeout_seconds=30,
        max_instruction_budget=1_000_000,
        max_output_bytes=65536,
    )
    values.update(overrides)
    return SimulationExecutionPolicy(**values)


def test_local_profile_cannot_self_authorize_without_allow_local_process() -> None:
    policy = _local_policy(allow_local_process=False)
    result = IsolatedSimulationRunner(policy=policy).run(
        SimulationRequest(
            "unicorn",
            "must-not-be-read.bin",
            input_bytes=b"\x90\xc3",
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
        )
    )
    assert result.status == "REJECTED"
    assert result.stop_reason == "POLICY_DENIED"


def test_unicorn_adapter_executes_granted_bytes_under_local_profile() -> None:
    policy = _local_policy()
    result = IsolatedSimulationRunner(policy=policy).run(
        SimulationRequest(
            "unicorn",
            "must-not-be-read.bin",
            input_bytes=b"\x48\xc7\xc0\x01\x00\x00\x00\xc3",
            input_sha256=None,
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
            timeout_seconds=8,
            instruction_budget=64,
        )
    )
    assert result.status == "SUCCEEDED"
    assert result.as_dict()["evidence_nature"] == "EMULATION_OBSERVED"
    assert result.registers.get("RAX") == 1
    assert all("sample" not in item.casefold() for item in result.limitations)


def test_qiling_without_rootfs_is_explicitly_unsupported() -> None:
    policy = _local_policy()
    result = default_simulation_runner(policy).run(
        SimulationRequest(
            "qiling",
            "must-not-be-read.bin",
            input_bytes=b"\x90\xc3",
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
        )
    )
    assert result.status == "UNSUPPORTED"
    assert result.stop_reason == "ROOTFS_REQUIRED"


def test_speakeasy_rejects_non_pe_granted_bytes() -> None:
    policy = _local_policy()
    result = default_simulation_runner(policy).run(
        SimulationRequest(
            "speakeasy",
            "must-not-be-read.bin",
            input_bytes=b"not-a-pe",
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
        )
    )
    assert result.status == "UNSUPPORTED"
    assert result.stop_reason == "NOT_PE"


def test_flare_emu_stays_unavailable_without_ghidra_plugin() -> None:
    policy = _local_policy()
    result = default_simulation_runner(policy).run(
        SimulationRequest(
            "flare-emu",
            "must-not-be-read.bin",
            input_bytes=b"\x90\xc3",
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
        )
    )
    assert result.status in {"UNAVAILABLE", "UNSUPPORTED"}
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_capability_probe_detects_installed_emulators_without_claiming_runtime() -> None:
    capabilities = {item.name: item for item in detect_simulation_capabilities()}
    assert capabilities["unicorn"].installed is True
    assert capabilities["speakeasy"].installed is True
    assert capabilities["qiling"].installed is True
    assert capabilities["unicorn"].allowed is False


def test_speakeasy_capability_matrix_does_not_claim_full_cryptodecrypt() -> None:
    matrix = speakeasy_capability_matrix()
    assert matrix["inspected_without_sample"] is True
    assert matrix["status"] in {"INSPECTED", "UNAVAILABLE"}
    assert any("AES" in item or "aes" in item.casefold() for item in matrix["cannot_claim"])
    if matrix["status"] == "INSPECTED":
        crypt = matrix["apis"]["CryptDecrypt"]
        assert crypt["hooked"] is True
        assert crypt["support"] == "PARTIAL"
        assert "RC4" in str(crypt["limitation"])
        bcrypt = matrix["apis"]["BCryptDecrypt"]
        assert bcrypt["support"] == "ABSENT"


def test_failed_simulation_serializes_static_inferred_nature() -> None:
    result = SimulationResult("FAILED", "unicorn", stop_reason="NO_GRANTED_WINDOW")
    assert result.as_dict()["evidence_nature"] == "STATIC_INFERRED"


def test_worker_unmapped_failure_is_emulation_observed() -> None:
    result = SimulationResult("FAILED", "unicorn", stop_reason="UNMAPPED_RETURN")
    assert result.as_dict()["evidence_nature"] == "EMULATION_OBSERVED"
    assert result.as_dict()["stop_reason"] == "UNMAPPED_RETURN"
    executed = SimulationResult("FAILED", "unicorn", stop_reason="EXECUTION_ERROR")
    assert executed.as_dict()["evidence_nature"] == "EMULATION_OBSERVED"


def test_qiling_without_rootfs_is_recorded_as_unsupported() -> None:
    row = qiling_unavailable_observation(
        SimulationExecutionPolicy(
            enabled=True,
            profile="static-first-controlled-emulation",
            worker_identity="controlled-emu-worker-v1",
            worker_image_digest="sha256:emu-worker-v1",
            allowed_simulators=("unicorn", "qiling"),
            qiling_rootfs="",
        )
    )
    assert row is not None
    assert row["status"] == "UNSUPPORTED"
    assert row["stop_reason"] == "ROOTFS_REQUIRED"
    assert row["evidence_nature"] == "STATIC_INFERRED"
    assert row["anchor"]["type"] == "qiling_policy"


def test_qiling_pe_with_linux_rootfs_is_os_mismatch(tmp_path) -> None:
    """T4/B09: Windows PE is not the applicable Qiling path once a Linux rootfs exists."""
    root = tmp_path / "qiling-rootfs"
    (root / "bin").mkdir(parents=True)
    policy = _local_policy(qiling_rootfs=str(root))
    result = default_simulation_runner(policy).run(
        SimulationRequest(
            "qiling",
            "must-not-be-read.bin",
            input_bytes=b"MZ" + b"\x00" * 64,
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
        )
    )
    assert result.status == "UNSUPPORTED"
    assert result.stop_reason == "NOT_LINUX_ELF"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_qiling_linux_elf_with_rootfs_is_not_rootfs_required(tmp_path) -> None:
    """T4/B09: a tiny Linux ELF with a pinned rootfs must actually invoke Qiling."""
    root = tmp_path / "qiling-rootfs"
    for name in ("bin", "lib", "lib64", "usr/lib", "tmp", "proc", "dev", "etc"):
        (root / name).mkdir(parents=True)
    policy = _local_policy(qiling_rootfs=str(root))
    result = default_simulation_runner(policy).run(
        SimulationRequest(
            "qiling",
            "must-not-be-read.bin",
            input_bytes=linux_x86_64_exit_elf(),
            architecture="x86_64",
            worker_identity="local-python-subprocess-v1",
            worker_image_digest="local-unisolated",
            timeout_seconds=8,
            instruction_budget=64,
        )
    )
    payload = result.as_dict()
    assert result.stop_reason != "ROOTFS_REQUIRED"
    assert result.status in {"SUCCEEDED", "FAILED", "UNAVAILABLE"}
    explained = " ".join([*result.assumptions, *result.limitations]).casefold()
    assert "linux" in explained
    assert payload["evidence_nature"] != "EMULATION_OBSERVED" or result.status == "SUCCEEDED"


