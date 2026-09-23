from threat_report_agent.simulation_adapters import (
    IsolatedSimulationRunner,
    SimulationResult,
    default_simulation_runner,
    detect_simulation_capabilities,
    linux_x86_64_exit_elf,
    qiling_unavailable_observation,
    speakeasy_capability_matrix,
)
from threat_report_agent.emulation.policy import (
    SimulationExecutionPolicy,
    SimulationRequest,
)


def test_the_policy_seam_is_pure_and_has_one_implementation() -> None:
    """P3.3 layer item 2, pinned: `emulation/policy.py` is the pure seam `investigation/` may import.

    WHY THIS EXISTS: plan section 3.2 lets `investigation/` import "static/emulation/tools 的接口", and
    `simulation_adapters` is an IMPLEMENTATION module (it owns the qiling adapter, the isolated runner and the builtin
    adapter table), so `investigation -> simulation_adapters` is an unlisted edge. MEASURED: five of the seven
    simulation-policy names P3.3e needs reach no implementation at all, so they and their closure moved here. This pin
    asserts the property that makes the seam legitimate - importing it must NOT drag the implementation in - plus the
    one-implementation rule the plan states at line 142.
    """
    import ast
    import subprocess
    import sys
    from pathlib import Path

    policy_path = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent" / "emulation" / "policy.py"
    tree = ast.parse(policy_path.read_text(encoding="utf-8"))
    # MODULE-LEVEL imports only: this is the property that decides whether importing the seam drags anything in.
    # MEASURED, and it corrected this pin's first version: a moved BODY imports `emulation.emulation_plan` lazily
    # (inside `request_for_granted_window`), which is allowed - it is a sibling emulation module made of facts/static,
    # both of which `investigation/` may import - but it is NOT a module-level import, so it does not make the seam
    # impure. What matters is that nothing at module level reaches the implementation, and that the lazy import does
    # not name it either.
    module_level: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_level |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            module_level.add(node.module.split(".")[0])
    assert module_level <= {"hashlib", "dataclasses", "pathlib", "typing", "__future__"}, (
        f"the policy seam must stay pure at module level; it imports {sorted(module_level)}"
    )
    lazy_targets = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and node not in tree.body
    }
    assert "threat_report_agent.simulation_adapters" not in lazy_targets, (
        f"a moved body imports the implementation lazily: {sorted(lazy_targets)}; the seam may not depend on it"
    )

    # importing the seam must not pull the implementation (a fresh interpreter, so nothing else can have cached it)
    code = (
        "import sys\n"
        "import threat_report_agent.emulation.policy as policy\n"
        "leaked = sorted(name for name in sys.modules if 'simulation_adapters' in name)\n"
        "assert not leaked, f'the policy seam imported the implementation: {leaked}'\n"
        "print(policy.__name__)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(policy_path.parents[3]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr[-600:]

    # ONE implementation: the moved names are defined in the seam and merely re-exported by the implementation module
    from threat_report_agent import simulation_adapters as adapters
    from threat_report_agent.emulation import policy

    for name in (
        "evidence_nature_for_simulation_status",
        "may_execute_in_process",
        "request_for_granted_window",
        "simulation_policy_from_settings",
        "worker_defers_simulation",
        "SimulationExecutionPolicy",
        "SimulationRequest",
        "resolve_qiling_rootfs",
        "CERTIFIED_PROFILES",
        "PINNED_QILING_ROOTFS",
        # the two PRIVATE constants the cluster closes over: this pin's first version omitted them, which a review
        # caught - they are re-exported like the rest, so the old path must keep working for them too.
        "_POLICY_OR_PLACEHOLDER_STATUSES",
        "_NON_WORKER_STOP_REASONS",
    ):
        assert getattr(adapters, name) is getattr(policy, name), f"{name} is not one object behind both paths"
    definitions = [
        node.name
        for node in ast.walk(ast.parse(
            (Path(__file__).resolve().parents[1] / "src" / "threat_report_agent" / "simulation_adapters.py")
            .read_text(encoding="utf-8")
        ))
        if isinstance(node, ast.ClassDef) and node.name in {"SimulationExecutionPolicy", "SimulationRequest"}
    ]
    assert not definitions, f"the implementation module defines {definitions} again; the seam owns them now"


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


