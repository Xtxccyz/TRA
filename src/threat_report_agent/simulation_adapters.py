"""Capability probes for optional, isolated user-mode emulation.

The first phase does not execute samples. This module intentionally exposes a
probe and a policy object only; a future worker adapter can implement the
actual emulation behind the same contract.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from typing import Callable, Mapping


@dataclass(frozen=True)
class SimulationCapability:
    name: str
    installed: bool
    import_name: str
    allowed: bool = False
    limitation: str = "Dynamic simulation is disabled in the static-only phase."

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "installed": self.installed,
            "import_name": self.import_name,
            "allowed": self.allowed,
            "limitation": self.limitation,
        }


SIMULATOR_IMPORTS = {
    "flare-emu": "flare_emu",
    "qiling": "qiling",
    "speakeasy": "speakeasy",
}


def detect_simulation_capabilities() -> tuple[SimulationCapability, ...]:
    """Detect optional libraries without importing or executing sample code."""
    return tuple(
        SimulationCapability(
            name=name,
            import_name=module,
            installed=importlib.util.find_spec(module) is not None,
        )
        for name, module in SIMULATOR_IMPORTS.items()
    )


def static_phase_simulation_evidence() -> dict[str, object]:
    """Return an auditable capability result suitable for Evidence.value."""
    capabilities = [item.as_dict() for item in detect_simulation_capabilities()]
    return {
        "phase": "static-only",
        "sample_execution": False,
        "network_access": False,
        "capabilities": capabilities,
        "status": "UNAVAILABLE" if not any(item["installed"] for item in capabilities) else "DISABLED_BY_POLICY",
        "limitation": "No dynamic observation is claimed; optional emulators require a dedicated isolated worker and explicit policy.",
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


@dataclass(frozen=True)
class SimulationResult:
    status: str
    simulator: str
    observations: tuple[dict[str, object], ...] = ()
    limitations: tuple[str, ...] = ()


class IsolatedSimulationRunner:
    """Safe seam for flare-emu/Qiling/Speakeasy adapters.

    The callable adapter is injected by a dedicated worker.  Without both
    explicit execution and worker isolation this runner returns a truthful
    denial and never imports or executes untrusted sample code.
    """

    def __init__(self, adapters: Mapping[str, Callable[[SimulationRequest], SimulationResult]] | None = None) -> None:
        self.adapters = dict(adapters or {})

    def run(self, request: SimulationRequest) -> SimulationResult:
        if request.simulator not in SIMULATOR_IMPORTS:
            return SimulationResult("UNAVAILABLE", request.simulator, limitations=("unknown simulator",))
        if not request.allow_execution:
            return SimulationResult("DISABLED_BY_POLICY", request.simulator, limitations=("sample execution is disabled by policy",))
        if not request.worker_isolated:
            return SimulationResult("REJECTED", request.simulator, limitations=("simulation requires an isolated worker",))
        if request.network_access:
            return SimulationResult("REJECTED", request.simulator, limitations=("network access is disabled",))
        adapter = self.adapters.get(request.simulator)
        if adapter is None:
            installed = importlib.util.find_spec(SIMULATOR_IMPORTS[request.simulator]) is not None
            return SimulationResult(
                "READY" if installed else "UNAVAILABLE",
                request.simulator,
                limitations=("worker adapter is not configured",),
            )
        return adapter(request)
