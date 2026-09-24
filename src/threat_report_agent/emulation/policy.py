"""P3.3 layer item 2: the PURE simulation policy, in a module `investigation/` may import.

WHY THIS MODULE EXISTS: plan section 3.2 lets `investigation/` import "static/emulation/tools 的接口", and
`simulation_adapters` is an IMPLEMENTATION module (it owns the qiling adapter, the isolated runner and the builtin
adapter table), so `investigation -> simulation_adapters` is an unlisted edge - forbidden by default. MEASURED: five of
the seven simulation-policy names P3.3e needs reach NO implementation at all, so they (and the types and constants they
mention - 12 module-level names / 262 lines) live here instead. The two that do reach implementation - `default_simulation_runner` and
`qiling_unavailable_observation` - deliberately stay behind, which is why this module is a policy seam and not a general
emulation interface.

`simulation_adapters.py` re-exports every name below, so its surface and its callers are unchanged and
`simulation_adapters.<name> is emulation.policy.<name>` stays true.

MOVED VERBATIM from that module; the only changes are this header, the imports it needs, and the blank lines between
items.
"""
from __future__ import annotations

import hashlib
from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path
from typing import (
    Callable,
    Mapping,
)
from typing import Protocol

CERTIFIED_PROFILES = frozenset({"controlled-worker-v1", "static-first-controlled-emulation"})

PINNED_QILING_ROOTFS = Path("/opt/qiling-rootfs")


def resolve_qiling_rootfs(configured: str = "") -> str:
    """Prefer an explicit grant, then the pinned emu-worker Linux rootfs."""
    text = str(configured or "").strip()
    if text and Path(text).is_dir():
        return text
    if PINNED_QILING_ROOTFS.is_dir():
        return str(PINNED_QILING_ROOTFS)
    return text


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


def request_for_granted_window(
    policy: SimulationExecutionPolicy,
    window: Mapping[str, object],
) -> SimulationRequest:
    """Build a granted-bytes request. ``sample_path`` is never a host sample."""
    granted = window.get("input_bytes")
    granted_bytes = granted if isinstance(granted, (bytes, bytearray)) else b""
    from threat_report_agent.emulation.emulation_plan import _as_int_address

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


class SimulationWindowOutcome(Protocol):
    """What running ONE granted window through the host's isolated runner reports back.

    DECLARED HERE, WHERE IT IS CONSUMED - a deliberate deviation from the P3.3e design document, which places it "in
    the coordinator". The reason it cannot go there is measurable: `coordinator.py`'s contract test asserts that its
    `INVESTIGATION_HOST_MEMBERS` pin equals EXACTLY the receiver references its own moved bodies make, so widening that
    pin for a member the coordinator never calls would fail a gate that exists to keep pins honest. This type is the
    return of the host member `_run_simulation_window`, and it is what the GIANT's body will consume next step: that
    body reads `status`, `stop_reason` and `output_bytes` and calls `as_dict()` - which is why all four are declared,
    even though the seam member itself only forwards the object.

    The four members are exactly what that body touches (MEASURED in the giant's `CONTROLLED_EMULATE` branch), and
    their types are those of the object the host really returns (`simulation_adapters.SimulationResult`): `status: str`,
    `stop_reason: str | None`, `output_bytes: bytes`. A narrower or wider shape here would be a lie only a type checker
    could catch - and `tests/test_investigation_derivation_seam.py` pins the shape against a real outcome.

    THE HOST PIN WAS DECLARED WITH THE GIANT'S BODY, not with this type. When this Protocol was written (the execution
    seam) the giant was still on the host, and a pin must name exactly what this module's own bodies read - declaring
    seven host members for a module that read none of them would have been the aspirational-pin defect this phase has
    already recorded once. The step that moved the giant declared the pin in the same change, and
    `tests/test_investigation_derivation_contract.py` asserts the equality the coordinator's contract test asserts.
    """

    status: str
    stop_reason: str | None
    output_bytes: bytes

    def as_dict(self) -> dict[str, object]: ...
