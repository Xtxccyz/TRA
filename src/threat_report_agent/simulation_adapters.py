"""Capability probes and bounded adapters for controlled user-mode emulation.

The default product profile remains static-only.  Adapters accept *granted
bytes* only: they never open ``sample_path`` and never execute a sample through
the host Windows loader.  Speakeasy, Qiling, and flare-emu are registered here
so a certified profile can invoke them; they stay disabled until server
policy enables ``static-first-controlled-emulation`` or ``controlled-worker-v1``.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import binascii
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, Mapping


@dataclass(frozen=True)
class SimulationCapability:
    name: str
    installed: bool
    import_name: str
    allowed: bool = False
    limitation: str = "Dynamic simulation is disabled in the static-only phase."
    version: str | None = None
    execution_contract: str = "controlled-worker-v1"

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "installed": self.installed,
            "import_name": self.import_name,
            "allowed": self.allowed,
            "limitation": self.limitation,
            "version": self.version,
            "execution_contract": self.execution_contract,
        }


SIMULATOR_IMPORTS = {
    "unicorn": "unicorn",
    "flare-emu": "flare_emu",
    "qiling": "qiling",
    "speakeasy": "speakeasy",
}

SIMULATOR_DISTRIBUTIONS = {
    "unicorn": ("unicorn",),
    "flare-emu": ("flare-emu", "flare_emu"),
    "qiling": ("qiling",),
    "speakeasy": ("speakeasy-emulator", "speakeasy"),
}

CERTIFIED_PROFILES = frozenset({"controlled-worker-v1", "static-first-controlled-emulation"})

PINNED_QILING_ROOTFS = Path("/opt/qiling-rootfs")
QILING_VENV_PYTHON = Path("/opt/qiling-venv/bin/python")
QILING_LINUX_RUNNER = Path("/opt/qiling_linux_runner.py")


def benign_pe32_ret(code: bytes = b"\xc3") -> bytes:
    """Tiny PE32 EXE whose entry immediately runs ``code`` (default: RET).

    This is the applicable T4 Speakeasy input: a real PE image in granted
    bytes, not a host-executed sample and not a path open. The default
    program is a no-op return; tests may pass a two-byte ``jmp $`` to
    exercise the instruction budget.
    """
    payload = bytes(code or b"\xc3")
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    data[optional + 28 : optional + 32] = (0x400000).to_bytes(4, "little")
    data[optional + 36 : optional + 40] = (0x200).to_bytes(4, "little")
    data[optional + 32 : optional + 36] = (0x1000).to_bytes(4, "little")
    data[optional + 40 : optional + 42] = (4).to_bytes(2, "little")
    data[optional + 48 : optional + 50] = (4).to_bytes(2, "little")
    data[optional + 56 : optional + 60] = (0x2000).to_bytes(4, "little")
    data[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    data[optional + 68 : optional + 70] = (3).to_bytes(2, "little")
    data[optional + 72 : optional + 76] = (0x100000).to_bytes(4, "little")
    data[optional + 76 : optional + 80] = (0x1000).to_bytes(4, "little")
    data[optional + 80 : optional + 84] = (0x100000).to_bytes(4, "little")
    data[optional + 84 : optional + 88] = (0x1000).to_bytes(4, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x200).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x200).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[section + 36 : section + 40] = (0x60000020).to_bytes(4, "little")
    data[0x200 : 0x200 + len(payload)] = payload
    return bytes(data)


def linux_x86_64_exit_elf() -> bytes:
    """Tiny static x86-64 Linux ELF that issues ``sys_exit(0)``.

    This is the applicable T4/B09 Qiling input: a real ELF, not a Windows PE
    and not host-executed shellcode. The program is the ELF equivalent of a
    NOP;RET snippet — it terminates without filesystem or network side effects.
    """
    code = bytes.fromhex("31ffb83c0000000f05")  # xor edi, edi; mov eax, 60; syscall
    e_phoff = 64
    phdr_size = 56
    code_off = e_phoff + phdr_size
    file_size = code_off + len(code)
    load_base = 0x400000
    e_entry = load_base + code_off
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2  # ELFCLASS64
    eh[5] = 1  # ELFDATA2LSB
    eh[6] = 1  # EV_CURRENT
    eh[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    eh[18:20] = (62).to_bytes(2, "little")  # EM_X86_64
    eh[20:24] = (1).to_bytes(4, "little")
    eh[24:32] = e_entry.to_bytes(8, "little")
    eh[32:40] = e_phoff.to_bytes(8, "little")
    eh[52:54] = (64).to_bytes(2, "little")
    eh[54:56] = phdr_size.to_bytes(2, "little")
    eh[56:58] = (1).to_bytes(2, "little")
    ph = bytearray(phdr_size)
    ph[0:4] = (1).to_bytes(4, "little")  # PT_LOAD
    ph[4:8] = (7).to_bytes(4, "little")  # PF_R|PF_W|PF_X
    ph[16:24] = load_base.to_bytes(8, "little")
    ph[24:32] = load_base.to_bytes(8, "little")
    ph[32:40] = file_size.to_bytes(8, "little")
    ph[40:48] = file_size.to_bytes(8, "little")
    ph[48:56] = (0x1000).to_bytes(8, "little")
    return bytes(eh + ph + code)


def resolve_qiling_rootfs(configured: str = "") -> str:
    """Prefer an explicit grant, then the pinned emu-worker Linux rootfs."""
    text = str(configured or "").strip()
    if text and Path(text).is_dir():
        return text
    if PINNED_QILING_ROOTFS.is_dir():
        return str(PINNED_QILING_ROOTFS)
    return text


def linux_elf_identity(payload: bytes) -> tuple[str, str] | None:
    """Return ``(os, architecture)`` for a Linux ELF, otherwise ``None``."""
    if len(payload) < 20 or payload[:4] != b"\x7fELF":
        return None
    elf_class = payload[4]
    machine = int.from_bytes(payload[18:20], "little")
    if elf_class == 2 and machine == 62:
        return ("linux", "x86_64")
    if elf_class == 1 and machine == 3:
        return ("linux", "x86")
    return None


def _distribution_version(names: tuple[str, ...]) -> str | None:
    for name in names:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return None


def detect_simulation_capabilities(
    *,
    allowed_simulators: Iterable[str] | None = None,
) -> tuple[SimulationCapability, ...]:
    """Detect optional libraries without executing sample code."""
    allow = {str(item) for item in (allowed_simulators or ())}
    capabilities: list[SimulationCapability] = []
    for name, module in SIMULATOR_IMPORTS.items():
        installed = importlib.util.find_spec(module) is not None
        if name == "speakeasy" and installed:
            try:
                spec_mod = importlib.import_module("speakeasy")
                installed = hasattr(spec_mod, "Speakeasy")
            except Exception:
                installed = False
        if name == "qiling" and not installed:
            installed = _qiling_python() is not None
        version = _distribution_version(SIMULATOR_DISTRIBUTIONS[name]) if installed else None
        allowed = bool(allow) and name in allow and installed
        if name == "unicorn":
            limitation = (
                "Unicorn adapter is available only for explicit bounded bytes in an isolated worker."
            )
        elif name == "speakeasy":
            limitation = (
                "Mandiant Speakeasy adapter loads granted PE bytes only; sample_path is never opened."
                if installed
                else "Mandiant Speakeasy is not installed (package speakeasy-emulator)."
            )
        elif name == "qiling":
            root = resolve_qiling_rootfs("")
            limitation = (
                "Qiling Linux user-mode ELF adapter uses the pinned rootfs; Windows PE is NOT_LINUX_ELF."
                if root and Path(root).is_dir()
                else "Qiling requires a pinned Linux user-mode rootfs; without it the adapter is UNSUPPORTED."
            )
        else:
            limitation = (
                "flare-emu is a Ghidra plugin; this Python process cannot import it, so the adapter stays UNAVAILABLE."
            )
        capabilities.append(
            SimulationCapability(
                name=name,
                import_name=module,
                installed=installed,
                allowed=allowed,
                version=version,
                limitation=limitation,
            )
        )
    return tuple(capabilities)


_SPEAKEASY_MATRIX_APIS = (
    ("advapi32", "CryptDecrypt"),
    ("advapi32", "CryptEncrypt"),
    ("advapi32", "CryptImportKey"),
    ("advapi32", "CryptAcquireContext"),
    ("advapi32", "CryptUnprotectData"),
    ("bcrypt", "BCryptDecrypt"),
    ("kernel32", "FindResource"),
    ("kernel32", "LoadResource"),
    ("kernel32", "CreateThread"),
    ("kernel32", "VirtualAlloc"),
)


def speakeasy_capability_matrix() -> dict[str, object]:
    """Inspect installed Speakeasy Win32 hooks without loading a sample.

    This is not a malware run and must not be cited as decryption evidence.
    CryptDecrypt is RC4-only in Speakeasy 1.5.x; BCryptDecrypt is absent.
    """
    version = _distribution_version(SIMULATOR_DISTRIBUTIONS["speakeasy"])
    try:
        import speakeasy  # noqa: F401
    except Exception as exc:
        return {
            "simulator": "speakeasy",
            "package": "speakeasy-emulator",
            "version": version,
            "inspected_without_sample": True,
            "status": "UNAVAILABLE",
            "limitation": f"Speakeasy import unavailable: {type(exc).__name__}",
            "apis": {},
            "cannot_claim": (
                "AES or resource-payload decryption from CryptoAPI presence",
                "real network or host execution",
            ),
        }
    import inspect
    import importlib

    apis: dict[str, dict[str, object]] = {}
    for module_name, api_name in _SPEAKEASY_MATRIX_APIS:
        record: dict[str, object] = {
            "module": module_name,
            "hooked": False,
            "support": "ABSENT",
            "limitation": "No Speakeasy hook in this package version",
        }
        try:
            module = importlib.import_module(f"speakeasy.winenv.api.usermode.{module_name}")
        except Exception as exc:
            record["limitation"] = f"module import failed: {type(exc).__name__}"
            apis[api_name] = record
            continue
        handler = getattr(module, api_name, None)
        if handler is None:
            for cls in vars(module).values():
                if inspect.isclass(cls):
                    handler = getattr(cls, api_name, None)
                    if handler is not None:
                        break
        if handler is None:
            apis[api_name] = record
            continue
        source = ""
        try:
            source = inspect.getsource(handler)
        except (OSError, TypeError):
            source = ""
        folded = source.casefold()
        record["hooked"] = True
        if "only rc4" in folded or "algid != 0x6801" in folded:
            record["support"] = "PARTIAL"
            record["limitation"] = "RC4 (CALG_RC4) only; other algorithms return 0; hashing not supported"
        elif "not supported" in folded or "hashing not supported" in folded:
            record["support"] = "PARTIAL"
            record["limitation"] = "Hook exists but documents an unsupported path"
        else:
            record["support"] = "HOOKED"
            record["limitation"] = "Speakeasy user-mode stub/hook, not host CryptoAPI"
        apis[api_name] = record
    return {
        "simulator": "speakeasy",
        "package": "speakeasy-emulator",
        "version": version,
        "inspected_without_sample": True,
        "status": "INSPECTED",
        "apis": apis,
        "cannot_claim": (
            "AES or resource-payload decryption from CryptDecrypt/CryptImportKey presence",
            "BCryptDecrypt (hook absent in this package)",
            "real network traffic or host Windows loader execution",
        ),
    }


def static_phase_simulation_evidence(
    policy: SimulationExecutionPolicy | None = None,
    *,
    worker_owned: bool = False,
) -> dict[str, object]:
    """Return an auditable capability result suitable for Evidence.value.

    ``worker_owned`` says the emulators run in the isolated emu-worker rather than in this
    process.  It changes what "installed" may claim, and the distinction was a measured defect:
    this function imports the adapters HERE, and the API process legitimately does not have them -
    the emu-worker image does:

        container     unicorn   speakeasy   qiling   pefile
        api           MISSING   MISSING     MISSING  MISSING
        emu-worker    1.0.2     present     MISSING  2024.8.26

    so the capability row published `status: UNAVAILABLE` with every simulator
    `installed: false, allowed: false`, and the report told the analyst that no emulator exists
    while the Temporal worker was executing them.  With ``worker_owned`` the configured
    simulators are reported as `allowed` and the limitation names the boundary instead of
    claiming absence: a capability that runs elsewhere is not an unavailable capability.
    """
    policy = policy or SimulationExecutionPolicy()
    capabilities = [
        item.as_dict()
        for item in detect_simulation_capabilities(allowed_simulators=policy.allowed_simulators if policy.enabled else ())
    ]
    configured = {str(item).casefold() for item in policy.allowed_simulators}
    for row in capabilities:
        name = str(row.get("name") or "")
        if not policy.enabled:
            continue
        if row["installed"]:
            row["allowed"] = name in set(policy.allowed_simulators)
            row["limitation"] = (
                f"Adapter registered under {policy.profile}; isolation={policy.isolation_kind}."
            )
        elif worker_owned and name.casefold() in configured:
            # Not importable here BY DESIGN: the API process is not the emulator.  Reporting it as
            # unavailable would contradict the worker that actually runs it.
            row["allowed"] = True
            row["worker_owned"] = True
            row["limitation"] = (
                f"{name} executes in the isolated {policy.isolation_kind} worker, not in this "
                "process; this row's `installed` reflects only the API image."
            )
    status = "DISABLED_BY_POLICY"
    available = [
        item for item in capabilities
        if item.get("installed") or item.get("worker_owned")
    ]
    if not available:
        status = "UNAVAILABLE"
    elif policy.enabled:
        status = "POLICY_ENABLED"
    return {
        "phase": policy.profile,
        "sample_execution": False,
        "network_access": False,
        "capabilities": capabilities,
        "status": status,
        "isolation_kind": policy.isolation_kind,
        "limitation": (
            "Emulator output is static EMULATION_OBSERVED, not sandbox/dynamic sample execution."
            if policy.enabled
            else "Optional emulators are static analysis on an isolated worker; this product does not run the sample in a sandbox."
        ),
    }


@dataclass(frozen=True)
class SimulationRequest:
    """Explicit request for a future isolated emulator worker.

    ``allow_execution`` and ``worker_isolated`` are both required.  The
    service never sets these for the static-only preset; this object exists so
    a Phase 2 worker can use the same auditable seam without bypassing policy.
    """

    simulator: str
    sample_path: str
    timeout_seconds: int = 30
    instruction_budget: int = 1_000_000
    allow_execution: bool = False
    worker_isolated: bool = False
    network_access: bool = False
    # Controlled experiments must receive bytes from the worker input grant;
    # the runner intentionally never reads ``sample_path`` itself.
    input_bytes: bytes | None = None
    input_sha256: str | None = None
    architecture: str = "x86_64"
    entry_address: int = 0x1000000
    max_output_bytes: int = 65536
    worker_identity: str | None = None
    worker_image_digest: str | None = None
    stubbed_apis: tuple[str, ...] = ()
    memory_maps: tuple[tuple[int, bytes], ...] = ()
    cancellation_requested: Callable[[], bool] | None = field(
        default=None, compare=False, hash=False, repr=False
    )


@dataclass(frozen=True)
class SimulationExecutionPolicy:
    """Trusted server-side grant for one controlled simulation profile.

    The request flags are untrusted model/user input.  A worker may execute
    only when this policy was constructed by the service configuration with a
    fixed identity, image digest and simulator allow-list.
    """

    enabled: bool = False
    profile: str = "static-only"
    worker_identity: str | None = None
    worker_image_digest: str | None = None
    allowed_simulators: tuple[str, ...] = ()
    network_access: bool = False
    max_timeout_seconds: int = 30
    max_instruction_budget: int = 1_000_000
    max_output_bytes: int = 65536
    isolation_kind: str = "none"
    allow_local_process: bool = False
    qiling_rootfs: str = ""
    max_input_bytes: int = 4_194_304

    def allows(self, request: SimulationRequest) -> tuple[bool, str]:
        if not self.enabled:
            return False, "simulation profile is disabled by server policy"
        if self.profile not in CERTIFIED_PROFILES:
            return False, "simulation profile is not a certified controlled worker"
        if self.profile == "controlled-worker-v1" and (
            not self.worker_identity or not self.worker_image_digest
        ):
            return False, "trusted worker identity and image digest are required"
        if self.profile == "static-first-controlled-emulation":
            if not self.worker_identity:
                return False, "trusted worker identity is required"
            if self.isolation_kind in {"none", "local-process"} and not self.allow_local_process:
                return False, "local-process emulation is disabled by server policy"
            if self.isolation_kind == "docker" and (
                not self.worker_image_digest or not str(self.worker_image_digest).startswith("sha256:")
            ):
                return False, "trusted worker identity and image digest are required"
        if request.simulator not in set(self.allowed_simulators):
            return False, "simulator is not allowed by server policy"
        if request.network_access or self.network_access:
            return False, "network access is disabled by policy"
        if request.worker_identity != self.worker_identity:
            return False, "worker identity does not match the trusted grant"
        if self.worker_image_digest and request.worker_image_digest != self.worker_image_digest:
            return False, "worker image digest does not match the trusted grant"
        if request.timeout_seconds < 1 or request.timeout_seconds > self.max_timeout_seconds:
            return False, "simulation timeout exceeds the trusted budget"
        if request.instruction_budget < 1 or request.instruction_budget > self.max_instruction_budget:
            return False, "instruction budget exceeds the trusted budget"
        if request.max_output_bytes < 0 or request.max_output_bytes > self.max_output_bytes:
            return False, "output budget exceeds the trusted budget"
        if request.input_bytes is not None and len(request.input_bytes) > self.max_input_bytes:
            return False, "granted input exceeds the trusted byte budget"
        return True, f"authorized by trusted {self.profile} policy"


_POLICY_OR_PLACEHOLDER_STATUSES = frozenset(
    {
        "DISABLED_BY_POLICY",
        "DEFERRED_TO_WORKER",
        "WORKER_REQUIRED",
        "NO_GRANTED_WINDOW",
        "UNSUPPORTED",
        "UNAVAILABLE",
        "SUPERSEDED_BY_WORKER",
        "INPUT_REQUIRED",
    }
)
_NON_WORKER_STOP_REASONS = frozenset(
    {
        "NO_GRANTED_WINDOW",
        "DISABLED_BY_POLICY",
        "DEFERRED_TO_WORKER",
        "WORKER_REQUIRED",
        "ROOTFS_REQUIRED",
        "NOT_PE",
        "NOT_LINUX_ELF",
        "ARCHITECTURE_UNSUPPORTED",
        "INPUT_REQUIRED",
        "INPUT_HASH_MISMATCH",
    }
)


def evidence_nature_for_simulation_status(
    status: object,
    *,
    stop_reason: object | None = None,
) -> str:
    """Worker-executed SUCCEEDED/FAILED/UNMAPPED is EMULATION_OBSERVED.

    Policy deferrals, missing rootfs, and granted-window refusals stay
    STATIC_INFERRED. Never DYNAMIC_OBSERVED.
    """
    upper = str(status or "").upper()
    reason = str(stop_reason or "").upper()
    if upper in _POLICY_OR_PLACEHOLDER_STATUSES:
        return "STATIC_INFERRED"
    if reason in _NON_WORKER_STOP_REASONS and upper != "SUCCEEDED":
        return "STATIC_INFERRED"
    if upper in {"SUCCEEDED", "FAILED"}:
        return "EMULATION_OBSERVED"
    if "UNMAPPED" in upper or "UNMAPPED" in reason:
        return "EMULATION_OBSERVED"
    return "STATIC_INFERRED"


def qiling_unavailable_observation(policy: SimulationExecutionPolicy) -> dict[str, object] | None:
    """Record honest UNSUPPORTED when Qiling is allowed but has no pinned rootfs."""
    if "qiling" not in {str(item).casefold() for item in policy.allowed_simulators}:
        return None
    resolved = resolve_qiling_rootfs(policy.qiling_rootfs)
    root = Path(resolved) if resolved else None
    if root is not None and root.is_dir():
        return None
    result = _qiling_adapter(
        SimulationRequest(
            "qiling",
            "",
            timeout_seconds=1,
            instruction_budget=1,
            input_bytes=b"\x90",
            worker_identity=policy.worker_identity,
            worker_image_digest=policy.worker_image_digest,
        ),
        rootfs=resolved,
    )
    payload = result.as_dict()
    payload["anchor"] = {"type": "qiling_policy", "simulator": "qiling"}
    return payload


@dataclass(frozen=True)
class SimulationResult:
    status: str
    simulator: str
    observations: tuple[dict[str, object], ...] = ()
    limitations: tuple[str, ...] = ()
    input_sha256: str | None = None
    tool_version: str | None = None
    stop_reason: str | None = None
    assumptions: tuple[str, ...] = ()
    output_bytes: bytes = b""
    registers: Mapping[str, int] = field(default_factory=dict)
    worker_identity: str | None = None
    worker_image_digest: str | None = None
    architecture: str | None = None
    entry_address: int | None = None
    hooked_or_stubbed_apis: tuple[str, ...] = ()

    @staticmethod
    def _observation_buckets(
        observations: tuple[dict[str, object], ...],
    ) -> dict[str, list[dict[str, object]]]:
        """Classify worker observations without inventing a semantic event.

        The worker retains the raw events, while this stable projection keeps
        report and audit consumers from interpreting arbitrary adapter text as
        a confirmed file, network, or process operation. An empty list means
        that this worker reported no observation in that category.
        """
        buckets: dict[str, list[dict[str, object]]] = {
            "attempted_apis": [],
            "file_operations": [],
            "registry_operations": [],
            "network_intents": [],
            "process_thread_operations": [],
            "memory_operations": [],
            "decoded_buffers": [],
            "control_flow_observations": [],
            "unsupported_apis": [],
        }
        terms = {
            "attempted_apis": ("api", "syscall", "import_call"),
            "file_operations": ("file", "filesystem", "path", "directory"),
            "registry_operations": ("registry", "reg_"),
            "network_intents": ("network", "socket", "dns", "http", "connect", "send", "receive"),
            "process_thread_operations": ("process", "thread", "apc", "spawn", "createprocess"),
            "memory_operations": ("memory", "alloc", "protect", "write_memory", "map_", "unmap"),
            "decoded_buffers": ("decode", "decrypt", "decompress", "plaintext", "buffer_output"),
            "control_flow_observations": ("instruction", "branch", "jump", "call", "return", "control_flow"),
            "unsupported_apis": ("unsupported", "unimplemented", "not_implemented"),
        }
        for item in observations:
            row = dict(item)
            label = " ".join(
                str(row.get(key, ""))
                for key in ("event", "kind", "category", "operation", "name", "api")
            ).casefold()
            matched = {
                bucket
                for bucket, markers in terms.items()
                if any(marker in label for marker in markers)
            }
            # A call the emulator could NOT model was never EXECUTED, so it is not an observed behaviour and
            # must not be counted as one. MEASURED defect: the T2 observation carries `event="unsupported_api"`
            # and `kind="unsupported"`, whose label contains BOTH "api" and "unsupported", so it landed in
            # `attempted_apis` AND `unsupported_apis` - a call that was never attempted was published as
            # attempted. The same naive substring match would also drop such a row into a behavioural bucket
            # whenever its NAME happens to contain a marker (e.g. an ordinal called `..._http_...` landing in
            # `network_intents`), which is the EC-2 error: a string read as observed behaviour.
            #
            # The rule is therefore general rather than a patch for one bucket: a row classified as
            # unsupported contributes to `unsupported_apis` ONLY. It is recorded as the blocking dependency,
            # which is what it is, and to nothing else.
            if "unsupported_apis" in matched:
                matched = {"unsupported_apis"}
            for bucket in matched:
                buckets[bucket].append(row)
        return buckets

    def as_dict(self) -> dict[str, object]:
        """Serialize an auditable result without embedding arbitrary bytes."""
        observation_buckets = self._observation_buckets(self.observations)
        return {
            "status": self.status,
            "simulator": self.simulator,
            "observations": [dict(item) for item in self.observations],
            "limitations": list(self.limitations),
            "input_sha256": self.input_sha256,
            "tool_version": self.tool_version,
            "stop_reason": self.stop_reason,
            "assumptions": list(self.assumptions),
            "output_sha256": hashlib.sha256(self.output_bytes).hexdigest()
            if self.output_bytes
            else None,
            "output_size": len(self.output_bytes),
            "registers": dict(self.registers),
            "worker_identity": self.worker_identity,
            "worker_image_digest": self.worker_image_digest,
            "architecture": self.architecture,
            "entry_address": hex(self.entry_address) if self.entry_address is not None else None,
            "hooked_or_stubbed_apis": list(self.hooked_or_stubbed_apis),
            **observation_buckets,
            "evidence_nature": evidence_nature_for_simulation_status(
                self.status, stop_reason=self.stop_reason
            ),
        }


def _unicorn_mode(architecture: object) -> tuple[str, bool]:
    """Map a sample architecture to (canonical name, is_64_bit) for Unicorn setup.

    `"x86_64"` was previously the ONLY accepted answer, and `Uc(UC_ARCH_X86, UC_MODE_64)` was
    hardcoded regardless - so a 32-bit sample was either rejected outright or, when the window
    omitted its architecture and the caller defaulted it to `x86_64`, executed as 64-bit code.
    Measured on task `0291d4b1` (PE machine 0x014c): the decoder reported a single "instruction"
    of size 4,059,165,169 and errno 10 (`UC_ERR_EXCEPTION`) - a real CPU exception on the first
    instruction - surfaced as `EMULATOR_ERROR`.
    """
    token = str(architecture or "").strip().casefold()
    if token in {"x86", "i386", "i486", "i586", "i686", "x86_32", "x86-32", "ia32"}:
        return "x86", False
    if token in {"x86_64", "x86-64", "amd64", "x64"}:
        return "x86_64", True
    return "", False


def _unicorn_adapter(request: SimulationRequest) -> SimulationResult:
    """Execute one bounded x86 or x86-64 byte block with Unicorn, when installed.

    This deliberately supports no PE loader, imports, syscalls, filesystem or
    network.  It is useful for deterministic decoder/hash snippets only.  A
    missing byte input is a hard ``INPUT_REQUIRED`` result rather than a zero
    filled guess.
    """
    guarded = _input_guard(request, "unicorn")
    if guarded is not None:
        return guarded
    canonical_arch, is_64_bit = _unicorn_mode(request.architecture)
    if not canonical_arch:
        return SimulationResult(
            "UNSUPPORTED",
            "unicorn",
            limitations=(f"unsupported architecture: {request.architecture}",),
            stop_reason="ARCHITECTURE_UNSUPPORTED",
        )
    expected = hashlib.sha256(request.input_bytes).hexdigest()
    if request.input_sha256 and request.input_sha256 != expected:
        return SimulationResult(
            "FAILED",
            "unicorn",
            input_sha256=expected,
            limitations=("input_sha256 does not match input_bytes",),
            stop_reason="INPUT_HASH_MISMATCH",
        )
    try:
        from unicorn import (
            Uc,
            UcError,
            UC_ARCH_X86,
            UC_ERR_FETCH_UNMAPPED,
            UC_ERR_READ_UNMAPPED,
            UC_ERR_WRITE_UNMAPPED,
            UC_HOOK_CODE,
            UC_MODE_32,
            UC_MODE_64,
        )
        from unicorn.x86_const import (
            UC_X86_REG_EAX,
            UC_X86_REG_EBX,
            UC_X86_REG_ECX,
            UC_X86_REG_EDX,
            UC_X86_REG_EIP,
            UC_X86_REG_ESP,
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSP,
        )
    except (ImportError, AttributeError) as exc:
        return SimulationResult(
            "UNAVAILABLE",
            "unicorn",
            input_sha256=expected,
            limitations=(f"Unicorn import unavailable: {type(exc).__name__}",),
            stop_reason="IMPORT_UNAVAILABLE",
        )
    # The mode and the register names must match the SAMPLE, not the host.  32-bit code decoded
    # in 64-bit mode raises a CPU exception on its first instruction.
    uc_mode = UC_MODE_64 if is_64_bit else UC_MODE_32
    register_names = (
        {
            "RAX": UC_X86_REG_RAX,
            "RBX": UC_X86_REG_RBX,
            "RCX": UC_X86_REG_RCX,
            "RDX": UC_X86_REG_RDX,
            "RIP": UC_X86_REG_RIP,
            "RSP": UC_X86_REG_RSP,
        }
        if is_64_bit
        else {
            "EAX": UC_X86_REG_EAX,
            "EBX": UC_X86_REG_EBX,
            "ECX": UC_X86_REG_ECX,
            "EDX": UC_X86_REG_EDX,
            "EIP": UC_X86_REG_EIP,
            "ESP": UC_X86_REG_ESP,
        }
    )

    # Page-align and keep a small fixed map.  The bytes are copied into an
    # anonymous emulated page; no host file descriptor is exposed to Unicorn.
    page = request.entry_address & ~0xFFF
    offset = request.entry_address - page
    map_size = ((offset + len(request.input_bytes) + 0xFFF) // 0x1000) * 0x1000
    map_size = max(0x1000, min(map_size, 0x100000))
    if (
        not request.memory_maps
        and offset + len(request.input_bytes) > map_size
    ):
        return SimulationResult(
            "INPUT_TOO_LARGE",
            "unicorn",
            input_sha256=expected,
            limitations=("input exceeds bounded emulated memory",),
            stop_reason="MEMORY_LIMIT",
        )
    observations: list[dict[str, object]] = []
    executed = 0
    cancelled = False
    started = time.monotonic()
    if request.cancellation_requested is not None and request.cancellation_requested():
        return SimulationResult(
            "CANCELLED",
            "unicorn",
            input_sha256=expected,
            limitations=("activity cancelled before Unicorn start",),
            stop_reason="ACTIVITY_CANCELLED",
        )
    mapped_pages: set[int] = set()
    stack_page = 0x200000

    def map_write(uc: object, address: int, payload: bytes) -> None:
        if not payload:
            return
        start = int(address) & ~0xFFF
        end = int(address) + len(payload)
        page_addr = start
        while page_addr < end:
            if page_addr not in mapped_pages:
                getattr(uc, "mem_map")(page_addr, 0x1000)
                mapped_pages.add(page_addr)
            page_addr += 0x1000
        getattr(uc, "mem_write")(int(address), payload)

    try:
        uc = Uc(UC_ARCH_X86, uc_mode)
        for map_address, map_bytes in request.memory_maps:
            if map_bytes:
                map_write(uc, int(map_address), map_bytes)
        map_write(uc, request.entry_address, request.input_bytes)
        if stack_page not in mapped_pages:
            uc.mem_map(stack_page, 0x2000)
            mapped_pages.add(stack_page)
            mapped_pages.add(stack_page + 0x1000)
        uc.reg_write(UC_X86_REG_RSP, stack_page + 0x1FF0)
    except Exception as exc:
        return SimulationResult(
            "FAILED",
            "unicorn",
            observations=(),
            input_sha256=expected,
            limitations=(f"bounded Unicorn setup failed: {type(exc).__name__}",),
            stop_reason="EXECUTION_ERROR",
        )

    def on_code(_uc: object, address: int, size: int, _user_data: object) -> None:
        nonlocal executed, cancelled
        checker = request.cancellation_requested
        if checker is not None and checker():
            cancelled = True
            getattr(_uc, "emu_stop")()
            return
        executed += 1
        if len(observations) < 256:
            observations.append(
                {"event": "instruction", "address": hex(address), "size": size}
            )

    uc.hook_add(UC_HOOK_CODE, on_code)
    stop_reason = "END_ADDRESS"
    status = "SUCCEEDED"
    try:
        uc.emu_start(
            request.entry_address,
            request.entry_address + len(request.input_bytes),
            timeout=max(1, request.timeout_seconds) * 1_000_000,
            count=max(1, request.instruction_budget),
        )
    except UcError as exc:
        errno = getattr(exc, "errno", None)
        observations.append({"event": "error", "type": type(exc).__name__, "errno": errno})
        if executed and errno in {
            UC_ERR_FETCH_UNMAPPED,
            UC_ERR_READ_UNMAPPED,
            UC_ERR_WRITE_UNMAPPED,
        }:
            stop_reason = (
                "UNMAPPED_RETURN" if errno == UC_ERR_FETCH_UNMAPPED else "UNMAPPED_DATA"
            )
            status = "SUCCEEDED"
        else:
            stop_reason = "EMULATOR_ERROR"
            status = "FAILED"
    if cancelled:
        stop_reason = "ACTIVITY_CANCELLED"
        status = "CANCELLED"
    registers: dict[str, int] = {}
    try:
        # Read the register set that matches the emulated mode; the 64-bit names do not exist in
        # a 32-bit Unicorn instance and vice versa.
        registers = {
            name: int(uc.reg_read(constant))
            for name, constant in register_names.items()
        }
    except Exception:
        registers = {}
    elapsed_ms = int((time.monotonic() - started) * 1000)
    observations.append({"event": "summary", "instructions": executed, "elapsed_ms": elapsed_ms})
    if status != "CANCELLED" and executed >= request.instruction_budget:
        stop_reason = "INSTRUCTION_BUDGET"
        status = "TIMED_OUT"
    output_bytes = b""
    try:
        mapped = bytes(uc.mem_read(request.entry_address, len(request.input_bytes)))
        if mapped != request.input_bytes:
            output_bytes = mapped
            observations.append(
                {
                    "event": "buffer_output",
                    "output_sha256": hashlib.sha256(mapped).hexdigest(),
                    "output_size": len(mapped),
                }
            )
    except Exception:
        output_bytes = b""
    return SimulationResult(
        status,
        "unicorn",
        observations=tuple(observations),
        input_sha256=expected,
        tool_version=str(getattr(__import__("unicorn"), "__version__", "unknown")),
        stop_reason=stop_reason,
        assumptions=(
            "anonymous x86-64 memory only",
            "no Windows API/loader/syscall semantics",
            "no network or host filesystem access",
        ),
        registers=registers,
        output_bytes=output_bytes,
    )


def _input_guard(request: SimulationRequest, simulator: str) -> SimulationResult | None:
    if request.input_bytes is None or len(request.input_bytes) == 0:
        return SimulationResult(
            "INPUT_REQUIRED",
            simulator,
            limitations=("explicit input_bytes are required; sample_path is never read",),
            stop_reason="MISSING_INPUT",
        )
    expected = hashlib.sha256(request.input_bytes).hexdigest()
    if request.input_sha256 and request.input_sha256 != expected:
        return SimulationResult(
            "FAILED",
            simulator,
            input_sha256=expected,
            limitations=("input_sha256 does not match input_bytes",),
            stop_reason="INPUT_HASH_MISMATCH",
        )
    return None


@contextmanager
def _unicorn_compat_mem_write():
    """Unicorn 1.0.2 ctypes mem_write rejects memoryview/bytearray from Speakeasy."""
    try:
        from unicorn import Uc
    except ImportError:
        yield
        return
    original = Uc.mem_write

    def patched(self: object, address: int, data: object) -> object:
        if not isinstance(data, bytes):
            data = bytes(data)
        return original(self, address, data)

    Uc.mem_write = patched  # type: ignore[method-assign]
    try:
        yield
    finally:
        Uc.mem_write = original  # type: ignore[method-assign]


def _simulator_error_detail(error: object) -> str:
    """Render a simulator's entry error so the report can name the blocking symbol.

    MEASURED on the 白象 sample `64da3378`: `_speakeasy_stop` returned FAILED/EXECUTION_ERROR and the
    report could only say "EXECUTION_ERROR", because the entry's structured `error` was used as a
    yes/no flag and then dropped. The value it was throwing away is the entire diagnosis:

        {'type': 'unsupported_api', 'api_name': 'MSVBVM60.ordinal_100',
         'pc': '0xfeedf0f0', 'instr': 'disasm_failed'}

    That single field is the difference between "the emulator is broken" and "the VB6 runtime ordinal
    `MSVBVM60.ordinal_100` is not implemented, so execution jumped to the unmapped sentinel
    0xfeedf0f0". Never collapse it to a class name.
    """
    if isinstance(error, Mapping):
        parts: list[str] = []
        error_type = str(error.get("type") or "").strip()
        api_name = str(error.get("api_name") or "").strip()
        pc = str(error.get("pc") or error.get("address") or "").strip()
        instruction = str(error.get("instr") or "").strip()
        if error_type:
            parts.append(error_type)
        if api_name:
            parts.append(f"api={api_name}")
        if pc:
            parts.append(f"pc={pc}")
        if instruction:
            parts.append(f"instr={instruction}")
        if parts:
            return " ".join(parts)
        # Structured but with no field we recognise: keep the keys so it is still diagnosable.
        return "unmapped:" + ",".join(sorted(str(key) for key in error)[:8])
    text = str(error).strip()
    return text[:200] or "unnamed emulator error"


#: Upper bound used when a module does not report its own size, so an address far above the image (for
#: example the historical hardcoded shellcode base `0x1000000`) cannot be mistaken for an image address.
#: MEASURED: the 白象 image is ~0x23000 bytes, so 4 MiB is already two orders of magnitude of headroom
#: while still excluding that sentinel, whose offset is 0xC00000 from a 0x400000 base.
_SPEAKEASY_DEFAULT_IMAGE_SPAN = 0x00400000


def _speakeasy_start_address(request: SimulationRequest, module: Any) -> int | None:
    """The granted function entry to run from, or None to keep the default PE-entry behaviour.

    Deliberately strict, because a wrong start address turns a working run into a dead one:

      * `entry_address` must be set AND lie inside the loaded image, so the historical hardcoded
        `0x1000000` (used for shellcode windows) can never be mistaken for an image address;
      * it must NOT be the module's own entry point, since running from the entry is exactly what
        `run_module` already does - returning it would be a no-op change with extra risk;
      * the module must expose a usable base.

    When any of these fail the caller keeps `run_module`, so behaviour for every existing window is
    unchanged. That containment is the whole point: the 白象 literal-table constructor is the measured
    case, not a general licence to execute arbitrary addresses.
    """
    requested = getattr(request, "entry_address", None)
    base = getattr(module, "base", None)
    if not isinstance(requested, int) or not isinstance(base, int) or not base:
        return None
    if requested == base:
        return None
    # The loaded image spans at least one page; require the target to fall inside it.
    image_size = 0
    for attribute in ("image_size", "size", "image_len"):
        value = getattr(module, attribute, None)
        if isinstance(value, int) and value > 0:
            image_size = value
            break
    if not image_size:
        # MEASURED: with only a lower bound, the historical hardcoded `0x1000000` (the shellcode window
        # address) passes every check and would be executed as though it were an image address. A
        # bounded default closes that without rejecting real PE images, which are far smaller than this.
        image_size = _SPEAKEASY_DEFAULT_IMAGE_SPAN
    if not (base <= requested < base + image_size):
        return None
    entry_points = getattr(module, "entry_points", None) or ()
    for entry in entry_points:
        if isinstance(entry, Mapping):
            candidate = entry.get("start_addr") or entry.get("addr")
            try:
                if candidate is not None and int(str(candidate), 0) == requested:
                    return None
            except (TypeError, ValueError):
                continue
    return requested


def _speakeasy_run_from_address(se: Any, module: Any, start_address: int) -> None:
    """Execute starting at `start_address` instead of the PE entry point.

    MEASURED interface (`.scratch/probe-add-run-interface.py`, `.scratch/probe-run-from-function.py`):
    `Run` lives in `speakeasy.profiler`, takes no constructor arguments, and carries `start_addr`.
    `emu.add_run(run)` + `emu.start()` then executes the run queue from that address. `emu` has no
    `emu_start`, and `se.get_arch()` returns an int, so this is the supported route.

    Raises on failure so the caller's `except` produces the honest FAILED result rather than a silent
    fallback to the entry point (which would misreport what was actually executed).
    """
    from speakeasy.profiler import Run  # deferred: only needed when a start address is granted

    run = Run()
    run.start_addr = start_address
    run.type = "ep"
    try:
        run.args = []
    except Exception:  # noqa: BLE001 - optional attribute on this Speakeasy build
        pass
    se.emu.add_run(run)
    se.emu.start()


def _decode_observed_records(records: Iterable[object]) -> dict[str, object]:
    """Decode the hex records the shim read during execution, in the order it read them.

    MEASURED purpose - this is the second, INDEPENDENT representation the objective asks for. The
    published report carried the recovered script from `literal_table.py`, which finds the table by
    SCANNING the image at a 48-byte stride. The shim instead reads records through the actual execution
    path (register `EDX`, advancing 0x30 per call). Measured on the 白象 sample, the two agree:

        literal_table : 'ace("v ba im fso, fo, Replace( UsrPrf & xtr = xtr new_down/"dataz, ...'
        shim reads    :  'ace("v ba ' + 'im fso, fo' + ', Replace(' + ... + ' UsrPrf & ' + 'xtr = xtr '

    Agreement between a static scan and an execution-driven read is real cross-validation, so the decoded
    text is published rather than left as a count. Only the first `max_chars` are carried: the point is
    to show the two paths meet, not to duplicate the recovered script.
    """
    parts: list[str] = []
    decoded_records = 0
    seen: set[str] = set()
    for item in records:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        try:
            parts.append(binascii.unhexlify(text).decode("latin-1"))
            decoded_records += 1
        except (binascii.Error, ValueError):
            continue
    decoded = "".join(parts)
    if not decoded:
        return {}
    max_chars = 600
    return {
        "distinct_records": len(seen),
        "decoded_records": decoded_records,
        "decoded_chars": len(decoded),
        "decoded_preview": decoded[:max_chars],
    }


def _speakeasy_unsupported_api_names(entry: list[object]) -> list[str]:
    """The API names Speakeasy reported as unsupported, in order and deduplicated.

    MEASURED why this exists (plan T2): the blocking symbol was written ONLY into the prose `detail`
    (`stopping at unsupported_api api=MSVBVM60.ordinal_648 pc=0xfeedf0cc`), while
    `SimulationResult.unsupported_apis` - the STRUCTURED field a consumer should read - is filled by a
    keyword classifier over `observations`, which never sees the report's `error` entries. So the field stayed
    EMPTY on the very run whose limitation named the symbol, and a reader had to parse prose to learn what
    blocked it. The names are lifted here so the caller can emit them as observations and let the EXISTING
    classifier bucket them, rather than adding a second classification path.
    """
    names: list[str] = []
    for item in entry:
        if not isinstance(item, Mapping):
            continue
        error = item.get("error")
        if not isinstance(error, Mapping):
            continue
        name = str(error.get("api_name") or error.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _speakeasy_stop(entry: list[object], *, instruction_budget: int) -> tuple[str, str, str]:
    """Map Speakeasy's report to an honest bounded stop, never a fake success.

    Returns `(status, stop_reason, detail)`; `detail` names the blocking symbol when the emulator
    reported an error, so callers can publish it instead of a bare status code.
    """
    if not entry:
        # An EMPTY report is an emulator-side fault, NEVER a completed run. MEASURED (adversarial defect
        # audit): when Speakeasy crashes inside its own unmapped-memory handler (the ctypes-swallowed
        # `get_peb_ldr` AttributeError) it returns a report with no `entry_points`, and the fall-through below
        # returned `SUCCEEDED / END_ADDRESS`, so the result was published as
        # `speakeasy status=SUCCEEDED stop=END_ADDRESS` with nature `EMULATION_OBSERVED`.
        #
        # The damage is not only the false label: `is_real_simulation_value` then reports "a real simulation
        # landed" to the CONTROLLED_EMULATE gate, which SUPPRESSES the retry that would have recovered real
        # evidence. Absence converted into a clean result, and it costs the evidence that would have replaced
        # it. Evidence this was reachable: ids d8482e84-307a-40db-bf01-24484dd3e4df, 5658b631-f652-4b9a-91fe-
        # 337e35e57eae (task 87da6bd0-12fc-40ca-8d86-a7b0665d559e) carry `api_count: 0` with `limitations: []`.
        return "FAILED", "EMULATOR_NO_REPORT", "Speakeasy reported no entry points"
    ret_vals: list[object] = []
    errors: list[object] = []
    counts: list[int] = []
    for item in entry:
        if not isinstance(item, Mapping):
            continue
        error = item.get("error")
        if error:
            errors.append(error)
        ret_vals.append(item.get("ret_val"))
        raw_count = item.get("instr_count")
        if isinstance(raw_count, int):
            counts.append(raw_count)
    if errors:
        return "FAILED", "EXECUTION_ERROR", _simulator_error_detail(errors[0])
    if counts and max(counts) >= max(1, instruction_budget):
        return "TIMED_OUT", "INSTRUCTION_BUDGET", ""
    if entry and ret_vals and all(value is None for value in ret_vals):
        return "TIMED_OUT", "INSTRUCTION_BUDGET", ""
    return "SUCCEEDED", "END_ADDRESS", ""


#: Instruction budget is derived from the sample's size rather than fixed.
#:
#: MEASURED why a fixed value cannot work: sample sizes differ by orders of magnitude, so any constant is
#: simultaneously too small for a large sample and needlessly generous for a small one. The concrete
#: failure observed here: the same Speakeasy run needed 900,000 instructions to drive 1,031 modelled API
#: calls on a 160 KB sample, while the fixed default of 100,000 stopped it after ONE call
#: (`modelled_calls=1`, `elapsed_ms=24`). Raising the constant to 900,000 merely moves the cliff to the
#: next larger sample.
#:
#: `_simulation_instruction_budget_for(payload)` replaces the constant with a function of the input size.
#: The absolute ceiling still exists - a crafted image must not occupy a worker indefinitely - but it is
#: sized to admit the largest input the policy already accepts (`simulation_max_input_bytes`, 4 MiB),
#: not to cap a typical sample.
_SIMULATION_BUDGET_BYTES_FACTOR = 20
_SIMULATION_BUDGET_FLOOR = 500_000
#: Guard against a pathological input size, not an analysis quota: this bound is reached only at the
#: maximum accepted input. Beyond it, `simulation_timeout_seconds` remains the real stop.
_SIMULATION_BUDGET_CEILING = 250_000_000


def _simulation_instruction_budget_for(payload_size: int, configured: int = 0) -> int:
    """Instruction budget derived from the granted byte count.

    `configured` (the `simulation_instruction_budget` setting) acts as a LOWER bound so an operator can
    still raise the floor for their environment; it can never shrink the derived budget back to a fixed
    constant, which is the defect this function exists to remove.
    """
    size = max(0, int(payload_size or 0))
    derived = size * _SIMULATION_BUDGET_BYTES_FACTOR + _SIMULATION_BUDGET_FLOOR
    return max(int(configured or 0), min(derived, _SIMULATION_BUDGET_CEILING))


def _speakeasy_adapter(request: SimulationRequest) -> SimulationResult:
    """Emulate granted PE bytes with Mandiant Speakeasy. Never opens sample_path."""
    guarded = _input_guard(request, "speakeasy")
    if guarded is not None:
        return guarded
    payload = request.input_bytes or b""
    expected = hashlib.sha256(payload).hexdigest()
    if payload[:2] != b"MZ":
        return SimulationResult(
            "UNSUPPORTED",
            "speakeasy",
            input_sha256=expected,
            limitations=("Speakeasy requires a PE image in granted input_bytes",),
            stop_reason="NOT_PE",
        )
    try:
        from speakeasy import Speakeasy
    except ImportError as exc:
        return SimulationResult(
            "UNAVAILABLE",
            "speakeasy",
            input_sha256=expected,
            limitations=(f"Speakeasy import unavailable: {type(exc).__name__}",),
            stop_reason="IMPORT_UNAVAILABLE",
        )
    config: dict[str, object] = {}
    try:
        config_path = Path(Speakeasy.__module__ and __import__("speakeasy").__file__ or "").parent / "configs" / "default.json"
        if config_path.is_file():
            config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        config = {}
    # Budget derived from the granted byte count, NOT the request's fixed constant: sample sizes differ
    # by orders of magnitude, so a constant is too small for a large sample and needlessly generous for
    # a small one. MEASURED: 900,000 instructions were needed for 1,031 modelled API calls on a 160 KB
    # sample, while the fixed 100,000 default stopped it after ONE call.
    effective_budget = _simulation_instruction_budget_for(
        len(payload), request.instruction_budget
    )
    config["timeout"] = max(1, request.timeout_seconds)
    config["max_instructions"] = max(1, effective_budget)
    config["emu_engine"] = "unicorn"
    started = time.monotonic()
    observations: list[dict[str, object]] = []
    # Record the request shape so two runs can be compared instead of guessed at. Lengths only: the payload
    # itself is not evidence about the request.
    #
    # CORRECTED (plan R9): this comment used to claim that "with the SAME entry address and budget, a direct
    # probe produced `modelled_calls=1031 / api=256` while the worker path produced `1 / 1 / 29`", and concluded
    # the difference "must lie in the remaining request fields". THAT DISCREPANCY DOES NOT EXIST. R9 re-ran the
    # product's own `_speakeasy_adapter` inside the emu-worker with the exact parameters recorded in the
    # evidence (`entry=0x40d2c0 bytes=159744 budget=3694880 timeout=8`) and reproduced
    # `api=256 / registered=132 / modelled_calls=1031 / strings_observed=1028`,
    # stopping at `unsupported_api api=MSVBVM60.ordinal_648` - i.e. the worker path IS the 1031/256/1028 path.
    # The old "1 / 1 / 29" figure is not reproducible on the deployed code, so the inference drawn from it is
    # withdrawn rather than left for a later reader to chase. Reproduce with
    # `.scratch/probe-r9-worker-reproduces-1031.py`.
    observations.append(
        {
            "event": "request",
            "entry_address": hex(int(request.entry_address or 0)),
            "architecture": str(request.architecture or ""),
            "input_bytes": len(payload),
            "requested_budget": int(request.instruction_budget or 0),
            "effective_budget": int(effective_budget),
            "timeout_seconds": int(request.timeout_seconds or 0),
            "max_output_bytes": int(request.max_output_bytes or 0),
            "stubbed_apis": list(request.stubbed_apis or ()),
            "memory_maps": len(request.memory_maps or ()),
            "allow_execution": bool(request.allow_execution),
            "worker_isolated": bool(request.worker_isolated),
        }
    )
    if request.cancellation_requested is not None and request.cancellation_requested():
        return SimulationResult(
            "CANCELLED",
            "speakeasy",
            input_sha256=expected,
            limitations=("activity cancelled before Speakeasy start",),
            stop_reason="ACTIVITY_CANCELLED",
            assumptions=(
                "user-mode Speakeasy model, not host execution",
                "network/DNS are Speakeasy stubs, not real traffic",
                "sample_path was not opened",
            ),
        )
    try:
        with _unicorn_compat_mem_write():
            se = Speakeasy(config=config, logger=None)
            module = se.load_module(data=payload)
            # VB6 runtime stubs MUST be registered AFTER load_module - measured: load_module rebuilds the
            # emulator's hook registry and discards hooks added before it, so a pre-load registration
            # silently never fires.
            #
            # MEASURED why this is needed at all: the 白象 sample's entry thunk is `jmp [0x4010e4]` ->
            # `MSVBVM60.ordinal_100`. Speakeasy cannot resolve that ordinal, installs its unmapped
            # sentinel 0xfeedf0f0, and the run dies on the first fetch - so the whole Speakeasy path
            # observed NOTHING (`api_count: 0`) and the report could only say EXECUTION_ERROR. Without
            # this the "three independent simulator paths" are not independent: Unicorn stops at the
            # entry trampoline and Qiling declines a Windows PE by design.
            shim_state = None
            shim_registered: list[str] = []
            try:
                from threat_report_agent.vb6_runtime_shim import (
                    ARGUMENT_PAIRS_CAP,
                    SAMPLE_STRINGS_CAP,
                    install_vb6_shim,
                    register_vb6_shim,
                )

                shim_state, shim_handlers = install_vb6_shim(se)
                shim_registered = register_vb6_shim(se, shim_handlers)
            except Exception as exc:  # noqa: BLE001
                # A shim that cannot install must not fail the emulation; it degrades to the
                # unshimmed result, which is exactly what the run reported before this existed.
                observations.append(
                    {"event": "shim_unavailable", "reason": f"{type(exc).__name__}: {exc}"[:200]}
                )
            # Run from a granted function entry when one was supplied, otherwise from the PE entry.
            # MEASURED why this matters: on the 白象 sample the PE entry is a bootstrap trampoline that
            # dies on the unimplemented `MSVBVM60.ordinal_100`, so an entry-driven run observes NOTHING
            # (`1 modelled call(s) to ordinal_100`). Starting instead at the recovered VB6 literal-table
            # constructor (`0x40d2c0`) executes 1,028 `__vbaStrCopy` calls whose arguments the shim can
            # now decode (`arguments_seen` 2 -> 1028 once the register ABI was fixed).
            start_address = _speakeasy_start_address(request, module)
            if start_address is not None:
                _speakeasy_run_from_address(se, module, start_address)
            else:
                se.run_module(module)
            report = se.get_report() if hasattr(se, "get_report") else {}
        report = report if isinstance(report, Mapping) else {}
        apis = []
        entry = report.get("entry_points") if isinstance(report.get("entry_points"), list) else []
        # NAMED, and their provenance stated honestly (G2/G4): these are bounds on how much of a Speakeasy
        # report becomes observations, and bounding it is defensible because the Temporal payload limit is a
        # measured 2 MiB (plan R8). But the VALUES 64 and 256 are NOT derived from that measurement - they are
        # pre-existing literals. They are named here, and what they DROP is now recorded, because a silent
        # bound whose result is rendered as a total is the defect this fixes.
        #
        # MEASURED: 102 evidence rows over 34 tasks hold exactly 256 api names and none holds 257, so the cap
        # saturates in production while the report publishes "已观测 API 调用：256 次" as if it were a total.
        entry_point_cap = 64
        api_cap = 256
        dropped_apis = 0
        for item in entry[:entry_point_cap]:
            if isinstance(item, Mapping):
                for api in item.get("apis", []) if isinstance(item.get("apis"), list) else []:
                    if not isinstance(api, Mapping):
                        continue
                    if len(apis) >= api_cap:
                        # Count what the cap removes instead of letting it vanish; the reader is told further
                        # down the pipeline, and an unstated bound reads as completeness.
                        dropped_apis += 1
                        continue
                    name = str(api.get("api_name") or api.get("name") or "")
                    observations.append({"event": "api", "name": name, "kind": "api_call"})
                    if name:
                        apis.append(name)
        entries_dropped = max(0, len(entry) - entry_point_cap)
        if dropped_apis or entries_dropped:
            observations.append(
                {
                    "event": "api_truncated",
                    "kept": len(apis),
                    "dropped": dropped_apis,
                    "entry_points_dropped": entries_dropped,
                    "api_cap": api_cap,
                    "entry_point_cap": entry_point_cap,
                }
            )
        status, stop_reason, detail = _speakeasy_stop(
            list(entry), instruction_budget=effective_budget
        )
        # Publish the blocking symbol as an OBSERVATION so the existing classifier buckets it into
        # `unsupported_apis`. MEASURED: without this the structured field was empty on the very run whose
        # prose limitation named `MSVBVM60.ordinal_648`, so the fact existed only in text a consumer would
        # have to parse (plan T2).
        for unsupported_name in _speakeasy_unsupported_api_names(list(entry)):
            observations.append(
                {"event": "unsupported_api", "name": unsupported_name, "kind": "unsupported"}
            )
        assumptions = (
            "user-mode Speakeasy model, not host execution",
            "network/DNS are Speakeasy stubs, not real traffic",
            "sample_path was not opened",
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        observations.append({"event": "summary", "elapsed_ms": elapsed_ms, "api_count": len(apis)})
        # Publish what the VB6 shim actually did, so a reader can tell a shimmed run from an unshimmed
        # one. Without this the shim's effect is invisible and its absence looks identical to a sample
        # that never called a runtime API.
        if shim_state is not None:
            shim_calls = int(sum(shim_state.calls.values())) if getattr(shim_state, "calls", None) else 0
            # C1/C2 carry the shim's LIMITS and its ARGUMENT PAIRS on the event that is actually published.
            #
            # MEASURED root cause (round 80): `destination_observable` and `argument_pairs` had been added to
            # `Vb6ShimState.as_evidence()`, and at that time NO production module called that method - `src/`
            # contained no caller at all; only host probes called it. So both fields were unreachable from
            # every evidence row and every report, while the shim itself was running fine (1,031 modelled
            # calls). The symptom read as "the shim never ran" because the check looked for a NAME that had no
            # writer instead of the CARRIER that holds the fact. The call below IS the fix, and
            # `test_the_carrier_reads_the_shims_own_evidence_method` pins it.
            #
            # The published path has three hops, and a field added at one hop but not the others is dropped
            # in silence:
            #     1. this observation event            (simulation_adapters.py)
            #     2. `shim_summary` projection         (reporting.py)
            #     3. the published Chinese body        (analyst_report.py)
            # `tests/test_vb6_shim_evidence_reaches_the_body.py` asserts the key sets of all three, so a
            # field can no longer be added at one hop alone.
            #
            # Read through `as_evidence()` so the limits cannot drift from the numbers, and default to the
            # HONEST direction if it is ever unavailable: under-claiming what was observed is safe,
            # over-claiming is not. The cap defaults are the shim's OWN constants, not a third copy of the
            # literals - a third copy is exactly how a published cap drifts from the slice it bounds.
            try:
                shim_evidence = shim_state.as_evidence()
            except Exception:  # noqa: BLE001
                shim_evidence = {}
            if not isinstance(shim_evidence, Mapping):
                shim_evidence = {}
            observations.append(
                {
                    "event": "vb6_shim",
                    "registered": len(shim_registered),
                    "modelled_calls": shim_calls,
                    "distinct_symbols": len(getattr(shim_state, "calls", {}) or {}),
                    "strings_observed": len(getattr(shim_state, "arguments_seen", []) or []),
                    **_decode_observed_records(getattr(shim_state, "arguments_seen", ()) or ()),
                    "destination_observable": shim_evidence.get("destination_observable", False),
                    "sample_strings_cap": shim_evidence.get("sample_strings_cap", SAMPLE_STRINGS_CAP),
                    "argument_pairs": shim_evidence.get("argument_pairs") or [],
                    "argument_pairs_cap": shim_evidence.get("argument_pairs_cap", ARGUMENT_PAIRS_CAP),
                    "argument_pairs_recorded": shim_evidence.get("argument_pairs_recorded", 0),
                }
            )
        limitations: tuple[str, ...] = ()
        # Publish what was actually observed, and only then what stopped it.
        #
        # MEASURED inconsistency this fixes: the wording used to be unconditionally "stopped before
        # observing any API call", which was true when the entry-driven run produced `api_count=0`. After
        # after the entry and budget fixes the SAME sentence was still printed while the run had observed
        # **256 API calls** and made **1,031 modelled runtime calls** - i.e. the report denied evidence it
        # was simultaneously carrying. A FAILED stop reason does not mean nothing was observed.
        observed_calls = int(sum(getattr(shim_state, "calls", {}).values() or [0])) if shim_state else 0
        observed_apis = len(apis)
        if detail and (observed_apis or observed_calls):
            observed_clause = (
                f"Speakeasy observed {observed_apis} API call(s)"
                + (f" and {observed_calls} modelled VB6 runtime call(s)" if observed_calls else "")
                + f" before stopping at {detail}"
            )
            if observed_apis and observed_apis <= 6:
                observed_clause += f" (observed: {', '.join(sorted(set(apis)))})"
        elif detail:
            observed_clause = f"Speakeasy stopped before observing any API call: {detail}"
        else:
            observed_clause = ""
        if observed_clause and shim_state is not None and observed_calls:
            limitations = (
                f"{observed_clause}; VB6 runtime stubs from `vb6_runtime_shim` were installed "
                f"({len(shim_registered)} hooks, {observed_calls} modelled call(s) to "
                f"{', '.join(sorted(shim_state.calls))}); the remaining gap is VB6 runtime semantics "
                "that `ordinal_648` needs, not a simulator fault",
            )
        elif observed_clause:
            limitations = (observed_clause,)
        return SimulationResult(
            status,
            "speakeasy",
            observations=tuple(observations),
            limitations=limitations,
            input_sha256=expected,
            tool_version=_distribution_version(SIMULATOR_DISTRIBUTIONS["speakeasy"]),
            stop_reason=stop_reason,
            assumptions=assumptions,
            hooked_or_stubbed_apis=tuple(dict.fromkeys(apis)),
        )
    except Exception as exc:
        # Keep the message: on a PE whose entry thunk targets an unimplemented runtime ordinal this
        # string is the only thing that distinguishes a wiring fault from a missing symbol.
        detail = f"{type(exc).__name__}: {exc}".strip()
        return SimulationResult(
            "FAILED",
            "speakeasy",
            observations=tuple(observations),
            input_sha256=expected,
            limitations=(f"Speakeasy execution failed: {detail[:300]}",),
            stop_reason="EXECUTION_ERROR",
        )


def _qiling_linux_assumptions(root: Path) -> tuple[str, ...]:
    return (
        f"Qiling linux user-mode rootfs={root.name}",
        "pinned linux rootfs; not a Windows rootfs",
        "no host filesystem or network access is granted beyond the pinned rootfs",
        "sample_path was not opened",
    )


def _qiling_python() -> Path | None:
    env = str(os.environ.get("QILING_PYTHON") or "").strip()
    candidates = [Path(env)] if env else []
    candidates.append(QILING_VENV_PYTHON)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _qiling_runner_path() -> Path | None:
    env = str(os.environ.get("QILING_LINUX_RUNNER") or "").strip()
    candidates = [Path(env)] if env else []
    candidates.append(QILING_LINUX_RUNNER)
    candidates.append(Path(__file__).resolve().parents[2] / "tool-worker" / "qiling_linux_runner.py")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _qiling_adapter(request: SimulationRequest, *, rootfs: str = "") -> SimulationResult:
    """Run a Linux ELF in Qiling when a pinned Linux user-mode rootfs exists."""
    guarded = _input_guard(request, "qiling")
    if guarded is not None:
        return guarded
    payload = request.input_bytes or b""
    expected = hashlib.sha256(payload).hexdigest()
    resolved = resolve_qiling_rootfs(rootfs)
    root = Path(resolved) if resolved else None
    if root is None or not root.is_dir():
        return SimulationResult(
            "UNSUPPORTED",
            "qiling",
            input_sha256=expected,
            limitations=(
                "Qiling requires a pinned Linux user-mode rootfs at "
                "SIMULATION_QILING_ROOTFS or /opt/qiling-rootfs",
            ),
            stop_reason="ROOTFS_REQUIRED",
        )
    if request.cancellation_requested is not None and request.cancellation_requested():
        return SimulationResult(
            "CANCELLED",
            "qiling",
            input_sha256=expected,
            limitations=("activity cancelled before Qiling start",),
            stop_reason="ACTIVITY_CANCELLED",
            assumptions=_qiling_linux_assumptions(root) if root is not None else (),
        )
    identity = linux_elf_identity(payload)
    if identity is None:
        if payload[:2] == b"MZ":
            limitation = (
                "Qiling applicable path is Linux user-mode ELF; "
                "Windows PE is an OS/architecture mismatch"
            )
        else:
            limitation = (
                "Qiling applicable path is Linux user-mode ELF; granted bytes are not an ELF"
            )
        return SimulationResult(
            "UNSUPPORTED",
            "qiling",
            input_sha256=expected,
            limitations=(limitation,),
            stop_reason="NOT_LINUX_ELF",
            assumptions=_qiling_linux_assumptions(root),
        )
    _ostype, arch = identity
    return _run_qiling_linux(request, payload=payload, root=root, arch=arch, input_sha256=expected)


def _try_qiling_linux_in_process(
    elf_path: Path,
    root: Path,
    *,
    arch: str,
    timeout_us: int,
    count: int,
) -> SimulationResult | None:
    """Return a result when this process can import Qiling's Linux OS module."""
    try:
        from qiling import Qiling
        from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
        import qiling.os.linux.linux  # noqa: F401
    except Exception:
        return None
    archtype = QL_ARCH.X8664 if arch in {"x86_64", "amd64"} else QL_ARCH.X86
    started = time.monotonic()
    try:
        ql = Qiling(
            [str(elf_path)],
            str(root),
            ostype=QL_OS.LINUX,
            archtype=archtype,
            verbose=QL_VERBOSE.OFF,
            console=False,
        )
        ql.run(timeout=timeout_us, count=count)
        return SimulationResult(
            "SUCCEEDED",
            "qiling",
            observations=(
                {
                    "event": "summary",
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "kind": "control_flow",
                },
            ),
            tool_version=_distribution_version(SIMULATOR_DISTRIBUTIONS["qiling"]),
            stop_reason="END_ADDRESS",
            assumptions=_qiling_linux_assumptions(root),
        )
    except Exception as exc:
        return SimulationResult(
            "FAILED",
            "qiling",
            limitations=(f"Qiling linux execution failed: {type(exc).__name__}",),
            stop_reason="EXECUTION_ERROR",
            assumptions=_qiling_linux_assumptions(root),
        )


def _run_qiling_linux_subprocess(
    elf_path: Path,
    root: Path,
    *,
    arch: str,
    timeout_us: int,
    count: int,
    timeout_seconds: int,
) -> SimulationResult:
    python = _qiling_python()
    runner = _qiling_runner_path()
    if python is None or runner is None:
        return SimulationResult(
            "UNAVAILABLE",
            "qiling",
            limitations=(
                "Qiling linux runner is not installed in this process; "
                "emu-worker pins qiling in /opt/qiling-venv with unicorn 2",
            ),
            stop_reason="IMPORT_UNAVAILABLE",
            assumptions=_qiling_linux_assumptions(root),
        )
    try:
        completed = subprocess.run(
            [str(python), str(runner)],
            input=json.dumps(
                {
                    "elf_path": str(elf_path),
                    "rootfs": str(root),
                    "arch": arch,
                    "timeout_us": timeout_us,
                    "count": count,
                }
            ),
            capture_output=True,
            text=True,
            timeout=max(2, timeout_seconds + 2),
            check=False,
        )
    except Exception as exc:
        return SimulationResult(
            "FAILED",
            "qiling",
            limitations=(f"Qiling linux runner failed: {type(exc).__name__}",),
            stop_reason="EXECUTION_ERROR",
            assumptions=_qiling_linux_assumptions(root),
        )
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict) or not payload.get("status"):
        err = (completed.stderr or completed.stdout or "no runner output")[:300]
        return SimulationResult(
            "FAILED",
            "qiling",
            limitations=(f"Qiling linux runner failed: {err}",),
            stop_reason="EXECUTION_ERROR",
            assumptions=_qiling_linux_assumptions(root),
        )
    observations = payload.get("observations") or []
    limitations = payload.get("limitations") or []
    return SimulationResult(
        str(payload.get("status") or "FAILED"),
        "qiling",
        observations=tuple(item for item in observations if isinstance(item, dict)),
        limitations=tuple(str(item) for item in limitations),
        tool_version=str(payload.get("tool_version") or "") or None,
        stop_reason=str(payload.get("stop_reason") or "EXECUTION_ERROR"),
        assumptions=_qiling_linux_assumptions(root),
    )


def _run_qiling_linux(
    request: SimulationRequest,
    *,
    payload: bytes,
    root: Path,
    arch: str,
    input_sha256: str,
) -> SimulationResult:
    timeout_us = max(1, request.timeout_seconds) * 1_000_000
    count = max(1, request.instruction_budget)
    with tempfile.TemporaryDirectory(prefix="qiling-granted-") as tmp:
        elf_path = Path(tmp) / "granted.elf"
        elf_path.write_bytes(payload)
        in_process = _try_qiling_linux_in_process(
            elf_path, root, arch=arch, timeout_us=timeout_us, count=count
        )
        if in_process is not None:
            return SimulationResult(
                in_process.status,
                in_process.simulator,
                observations=in_process.observations,
                limitations=in_process.limitations,
                input_sha256=input_sha256,
                tool_version=in_process.tool_version,
                stop_reason=in_process.stop_reason,
                assumptions=in_process.assumptions,
            )
        result = _run_qiling_linux_subprocess(
            elf_path,
            root,
            arch=arch,
            timeout_us=timeout_us,
            count=count,
            timeout_seconds=max(1, request.timeout_seconds),
        )
        return SimulationResult(
            result.status,
            result.simulator,
            observations=result.observations,
            limitations=result.limitations,
            input_sha256=input_sha256,
            tool_version=result.tool_version,
            stop_reason=result.stop_reason,
            assumptions=result.assumptions,
        )


def _flare_emu_adapter(request: SimulationRequest) -> SimulationResult:
    """flare-emu is a Ghidra plugin; do not claim Unicorn results as flare-emu."""
    guarded = _input_guard(request, "flare-emu")
    if guarded is not None:
        return guarded
    expected = hashlib.sha256(request.input_bytes or b"").hexdigest()
    if importlib.util.find_spec("flare_emu") is None:
        return SimulationResult(
            "UNAVAILABLE",
            "flare-emu",
            input_sha256=expected,
            limitations=(
                "flare-emu is a Ghidra plugin and is not importable in this Python process; "
                "use the Unicorn adapter for bounded snippets",
            ),
            stop_reason="PLUGIN_UNAVAILABLE",
        )
    return SimulationResult(
        "UNSUPPORTED",
        "flare-emu",
        input_sha256=expected,
        limitations=("flare-emu Python import exists but a Ghidra-backed worker is not registered",),
        stop_reason="WORKER_UNAVAILABLE",
    )


BUILTIN_ADAPTERS: dict[str, Callable[[SimulationRequest], SimulationResult]] = {
    "unicorn": _unicorn_adapter,
    "speakeasy": _speakeasy_adapter,
    "flare-emu": _flare_emu_adapter,
}


def simulation_policy_from_settings(settings: object) -> SimulationExecutionPolicy:
    """Build a server-side grant from Settings. Default remains static-only."""
    profile = str(getattr(settings, "simulation_profile", "static-only") or "static-only")
    allowed = tuple(getattr(settings, "simulation_allowed_simulators", ()) or ())
    identity = str(getattr(settings, "simulation_worker_identity", "") or "") or None
    digest = str(getattr(settings, "simulation_worker_image_digest", "") or "") or None
    allow_local = bool(getattr(settings, "simulation_allow_local_process", False))
    isolation = "none"
    enabled = False
    if profile == "controlled-worker-v1" and identity and digest:
        enabled = True
        isolation = "docker"
    elif profile == "static-first-controlled-emulation" and identity:
        isolation = "docker" if digest and str(digest).startswith("sha256:") and not allow_local else "local-process"
        enabled = isolation == "docker" or allow_local
    return SimulationExecutionPolicy(
        enabled=enabled,
        profile=profile,
        worker_identity=identity,
        worker_image_digest=digest,
        allowed_simulators=allowed,
        isolation_kind=isolation,
        allow_local_process=allow_local,
        qiling_rootfs=resolve_qiling_rootfs(
            str(getattr(settings, "simulation_qiling_rootfs", "") or "")
        ),
        max_timeout_seconds=int(getattr(settings, "simulation_timeout_seconds", 8) or 8),
        max_instruction_budget=int(getattr(settings, "simulation_instruction_budget", 100_000) or 100_000),
        max_output_bytes=int(getattr(settings, "simulation_max_output_bytes", 65536) or 65536),
        max_input_bytes=int(getattr(settings, "simulation_max_input_bytes", 4_194_304) or 4_194_304),
    )


def worker_defers_simulation(policy: SimulationExecutionPolicy | None = None) -> bool:
    """True when this run is committed to the isolated worker (docker isolation, no local process).

    The predicate behind both questions this codebase asks about isolation:
      * "may THIS process run the bytes?" - `may_execute_in_process`, which adds the production veto; and
      * "may we make a host-side statement at all, or must we record a deferred observation?" - the four
        `simulation_result` sites in `service.py`.

    MEASURED before this existed: the same expression was written out FIVE times in `service.py`
    (7092, 18408, 18457, 18895 plus the execution site). A test that greps for the duplicated condition
    found them; five copies of one rule is how the original `True`-vs-computed divergence happened.
    """
    policy = policy or SimulationExecutionPolicy()
    return policy.isolation_kind == "docker" and not bool(policy.allow_local_process)


def may_execute_in_process(
    policy: SimulationExecutionPolicy | None = None,
    *,
    environment: str = "",
) -> bool:
    """Whether THIS process may run isolated-emulation bytes itself. One definition, three call sites.

    Why a single definition exists: the answer was computed at `service.py:7048` but HARDCODED `True` at
    `service.py:18386` and `service.py:18838`. Both hardcoded sites happened to be correct, but only because
    of guards far away from them:

      * `18386` sits after the early return at `18377` (`isolation_kind == "docker" and not
        allow_local_process` -> return), so reaching it implies the computed condition already holds;
      * `18838` sits under the `elif` at `18833`, which adds `environment in {test, demo, development}`.

    A reader at either site sees `True` and cannot tell what makes it safe, and a refactor that moves the
    guard silently makes the host execute sample bytes. That is the failure this function removes: the
    value is now computed where it is used.

    Two conditions, BOTH required:
      * the run is not committed to the worker - i.e. isolation is not `docker`, OR the policy explicitly
        permits a local process (the "docker API + host worker" development topology `allow_local_process`
        exists to express); and
      * the environment is not `production`. This is the absolute standard ("宿主不执行样本") made explicit
        rather than left to `config.py`'s separate production check.

    MEASURED state of the flag when this was written: not live. `.env` sets `SIMULATION_PROFILE=static-only`,
    `config.py` forbids local-process in production, and compose sets
    `SIMULATION_ALLOW_LOCAL_PROCESS="false"` in three services. So this is a latent fragility, not an active
    violation - and the fix must NOT change the legitimate development topology, which is why the condition
    is an OR on isolation rather than a blanket "docker implies worker".
    """
    policy = policy or SimulationExecutionPolicy()
    if str(environment or "").strip().casefold() == "production":
        return False
    return not worker_defers_simulation(policy)


def default_simulation_runner(
    policy: SimulationExecutionPolicy | None = None,
    *,
    execute_in_process: bool | None = None,
    environment: str = "",
) -> IsolatedSimulationRunner:
    policy = policy or SimulationExecutionPolicy()

    def qiling(request: SimulationRequest) -> SimulationResult:
        return _qiling_adapter(request, rootfs=policy.qiling_rootfs)

    adapters = {**BUILTIN_ADAPTERS, "qiling": qiling}
    return IsolatedSimulationRunner(
        adapters,
        policy=policy,
        execute_in_process=execute_in_process,
        environment=environment,
    )


def request_for_granted_window(
    policy: SimulationExecutionPolicy,
    window: Mapping[str, object],
) -> SimulationRequest:
    """Build a granted-bytes request. ``sample_path`` is never a host sample."""
    granted = window.get("input_bytes")
    granted_bytes = granted if isinstance(granted, (bytes, bytearray)) else b""
    from threat_report_agent.emulation_plan import _as_int_address

    entry_address = _as_int_address(window.get("entry_address", window.get("function_entry", 0x1000000)))
    if entry_address is None:
        entry_address = 0x1000000
    maps: list[tuple[int, bytes]] = []
    for item in window.get("memory_maps") or ():
        if not isinstance(item, Mapping):
            continue
        mapped_at = _as_int_address(item.get("address"))
        region = item.get("bytes")
        if mapped_at is None:
            continue
        if isinstance(region, (bytes, bytearray)) and region and mapped_at >= 0:
            maps.append((mapped_at, bytes(region)))
    return SimulationRequest(
        str(window.get("simulator") or "unicorn"),
        "",
        timeout_seconds=max(1, policy.max_timeout_seconds),
        instruction_budget=max(1, policy.max_instruction_budget),
        input_bytes=bytes(granted_bytes),
        input_sha256=hashlib.sha256(bytes(granted_bytes)).hexdigest() if granted_bytes else None,
        worker_identity=policy.worker_identity,
        worker_image_digest=policy.worker_image_digest,
        architecture=str(window.get("architecture") or "x86_64"),
        entry_address=entry_address,
        max_output_bytes=policy.max_output_bytes,
        memory_maps=tuple(maps),
    )


class IsolatedSimulationRunner:
    """Safe seam for flare-emu/Qiling/Speakeasy adapters.

    The callable adapter is injected by a dedicated worker.  Without both
    explicit execution and worker isolation this runner returns a truthful
    denial and never imports or executes untrusted sample code.
    """

    def __init__(
        self,
        adapters: Mapping[str, Callable[[SimulationRequest], SimulationResult]] | None = None,
        *,
        policy: SimulationExecutionPolicy | None = None,
        execute_in_process: bool | None = None,
        environment: str = "",
    ) -> None:
        self.adapters = dict(adapters or {})
        self.policy = policy or SimulationExecutionPolicy()
        self.environment = str(environment or "")
        if execute_in_process is None:
            # ONE definition. This line used to read `self.policy.isolation_kind != "docker"` - a SECOND
            # rule that ignored BOTH `allow_local_process` and the production veto, so the two answers
            # disagreed precisely on the topology `allow_local_process` exists to express. MEASURED before
            # this fix: docker + allow_local -> here False, `may_execute_in_process` True; production +
            # local-process -> here True, `may_execute_in_process` False. Two independent reviewers found it
            # while the guard test passed, because that test grepped for a spelling this line does not use.
            execute_in_process = may_execute_in_process(self.policy, environment=self.environment)
        self.execute_in_process = bool(execute_in_process)

    def run(
        self,
        request: SimulationRequest,
        *,
        cancellation_requested: Callable[[], bool] | None = None,
    ) -> SimulationResult:
        if cancellation_requested is not None and request.cancellation_requested is not cancellation_requested:
            request = replace(request, cancellation_requested=cancellation_requested)
        def with_request_context(result: SimulationResult) -> SimulationResult:
            """Keep the request boundary attached to every worker outcome."""
            return SimulationResult(
                result.status,
                result.simulator,
                observations=tuple(result.observations),
                limitations=tuple(result.limitations),
                input_sha256=result.input_sha256
                or (hashlib.sha256(request.input_bytes).hexdigest() if request.input_bytes is not None else None),
                tool_version=result.tool_version,
                stop_reason=result.stop_reason,
                assumptions=tuple(result.assumptions),
                output_bytes=result.output_bytes[: max(0, request.max_output_bytes)],
                registers=dict(result.registers),
                worker_identity=request.worker_identity,
                worker_image_digest=request.worker_image_digest,
                architecture=request.architecture,
                entry_address=request.entry_address,
                hooked_or_stubbed_apis=tuple(dict.fromkeys((*result.hooked_or_stubbed_apis, *request.stubbed_apis))),
            )

        if request.simulator not in SIMULATOR_IMPORTS:
            return with_request_context(SimulationResult("UNAVAILABLE", request.simulator, limitations=("unknown simulator",)))
        allowed, reason = self.policy.allows(request)
        if not allowed:
            # A caller asking for execution cannot grant itself permission.
            # Preserve a useful distinction between the normal static-only
            # state and a rejected forged/invalid execution request.
            status = "DISABLED_BY_POLICY" if not self.policy.enabled and not request.allow_execution else "REJECTED"
            return with_request_context(SimulationResult(status, request.simulator, limitations=(reason,), stop_reason="POLICY_DENIED"))
        if not self.execute_in_process:
            return with_request_context(
                SimulationResult(
                    "WORKER_REQUIRED",
                    request.simulator,
                    limitations=(
                        "docker-isolated emulation must run in the dedicated Temporal worker",
                    ),
                    stop_reason="WORKER_REQUIRED",
                )
            )
        if request.cancellation_requested is not None and request.cancellation_requested():
            return with_request_context(
                SimulationResult(
                    "CANCELLED",
                    request.simulator,
                    limitations=("activity cancelled before adapter start",),
                    stop_reason="ACTIVITY_CANCELLED",
                )
            )
        adapter = self.adapters.get(request.simulator)
        if adapter is None and request.simulator == "qiling":
            def qiling_adapter(item: SimulationRequest) -> SimulationResult:
                return _qiling_adapter(item, rootfs=self.policy.qiling_rootfs)

            adapter = qiling_adapter
        if adapter is None:
            adapter = BUILTIN_ADAPTERS.get(request.simulator)
        if adapter is None:
            installed = importlib.util.find_spec(SIMULATOR_IMPORTS[request.simulator]) is not None
            return with_request_context(SimulationResult(
                "READY" if installed else "UNAVAILABLE",
                request.simulator,
                limitations=("worker adapter is not configured",),
            ))
        try:
            result = adapter(request)
        except Exception as exc:
            return with_request_context(SimulationResult(
                "FAILED",
                request.simulator,
                input_sha256=(
                    hashlib.sha256(request.input_bytes).hexdigest()
                    if request.input_bytes is not None
                    else None
                ),
                limitations=(f"adapter failed: {type(exc).__name__}",),
                stop_reason="ADAPTER_ERROR",
            ))
        # All adapter outputs carry a bounded, auditable nature marker.  The
        # marker is serialized rather than inferred by downstream reports.
        assumptions = tuple(result.assumptions)
        if request.stubbed_apis:
            assumptions += ("stubbed APIs: " + ", ".join(request.stubbed_apis),)
        return SimulationResult(
            result.status,
            result.simulator,
            observations=tuple(result.observations),
            limitations=tuple(result.limitations),
            input_sha256=result.input_sha256
            or (hashlib.sha256(request.input_bytes).hexdigest() if request.input_bytes is not None else None),
            tool_version=result.tool_version,
            stop_reason=result.stop_reason or "ADAPTER_RETURNED",
            assumptions=assumptions,
            output_bytes=result.output_bytes[: max(0, request.max_output_bytes)],
            registers=dict(result.registers),
            worker_identity=request.worker_identity,
            worker_image_digest=request.worker_image_digest,
            architecture=request.architecture,
            entry_address=request.entry_address,
            hooked_or_stubbed_apis=tuple(dict.fromkeys((*result.hooked_or_stubbed_apis, *request.stubbed_apis))),
        )
