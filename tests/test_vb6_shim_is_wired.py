"""The VB6 shim must be WIRED INTO the production adapter, not merely present.

MEASURED gap this pins: `src/threat_report_agent/vb6_runtime_shim.py` had a complete, tested API but was
imported by NO production module - only by its own test file. So the object leaked into no adapter, the
"three independent simulator paths" were not independent, and the Speakeasy path observed nothing on a
VB6 sample because its entry thunk targets `MSVBVM60.ordinal_100`, which Speakeasy cannot resolve.

Measured after wiring (isolated emu-worker, real sample):

    unshimmed : hooks=0    apis=0  error=unsupported_api MSVBVM60.ordinal_100 @0xfeedf0f0
    shimmed   : hooks=132  apis=1  error=invalid_read @0x40248e, shim modelled calls=1

These tests fail if the wiring is removed or if the registration is moved before `load_module`, which was
measured to silently discard every hook.

P3.7 CONVERSION: the assertions used to read `inspect.getsource(_speakeasy_adapter)` and slice that text
(`source.index("load_module")`, a 400-character window before `install_vb6_shim`, substring tests for
`"vb6_shim"` / `"modelled_calls"`). A mention of a name satisfied those; reformatting broke them. Every test
below now RUNS the adapter against a fake Speakeasy that records the calls it receives, so the assertions are
about what the adapter DOES - install, register AFTER `load_module`, survive a shim that cannot install, and
publish the shim's contribution.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from threat_report_agent import simulation_adapters
from threat_report_agent.emulation.policy import SimulationRequest
from threat_report_agent.simulation_adapters import _speakeasy_adapter

#: A structurally valid PE32: `_speakeasy_adapter` refuses anything that does not start with `MZ`.
PE_BYTES = b"MZ" + b"\x00" * 0x3C + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 0x200


class _FakeSpeakeasy:
    """Models the two measured Speakeasy properties these tests depend on.

    * `load_module` REBUILDS the hook registry, so any hook registered before it is silently discarded - the
      trap `test_registration_happens_after_load_module` exists for.
    * a run records which API hooks fired, which is what the shim's `modelled_calls` is counted from.
    """

    instances: list["_FakeSpeakeasy"] = []

    def __init__(self, config: object = None, logger: object = None) -> None:
        self.calls: list[str] = []
        self.registered_before_load: list[str] = []
        self.registered_after_load: list[str] = []
        self.loaded = False
        _FakeSpeakeasy.instances.append(self)

    def load_module(self, data: bytes = b"") -> SimpleNamespace:
        self.calls.append("load_module")
        self.loaded = True
        return SimpleNamespace(base=None, entry_points=())

    def run_module(self, module: object) -> None:
        self.calls.append("run_module")

    def get_report(self) -> dict[str, object]:
        return {"entry_points": []}

    def add_api_hook(self, handler, module: str = "", api_name: str = "", argc: int = 0, call_conv=None):  # noqa: ANN001
        key = f"{module}:{api_name}"
        self.calls.append(f"add_api_hook:{key}")
        if not self.loaded:
            # The measured trap: a registration made before `load_module` does not survive.
            self.registered_before_load.append(key)
            return None
        self.registered_after_load.append(key)
        return handler


@pytest.fixture
def fake_speakeasy(monkeypatch: pytest.MonkeyPatch):
    """Install a fake `speakeasy` module (and a fake `speakeasy.profiler`) for the adapter to import."""

    def _install() -> ModuleType:
        _FakeSpeakeasy.instances = []
        module = ModuleType("speakeasy")
        module.__file__ = str(Path(__file__))  # no `configs/default.json` next to it
        module.Speakeasy = _FakeSpeakeasy  # type: ignore[attr-defined]
        profiler = ModuleType("speakeasy.profiler")

        class _Run:
            def __init__(self) -> None:
                self.start_addr = 0
                self.type = "ep"
                self.args: list[object] = []

        profiler.Run = _Run  # type: ignore[attr-defined]
        module.profiler = profiler  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "speakeasy", module)
        monkeypatch.setitem(sys.modules, "speakeasy.profiler", profiler)
        return module

    return _install


def _run_adapter():
    return _speakeasy_adapter(
        SimulationRequest(
            "speakeasy",
            "must-not-be-read.exe",
            input_bytes=PE_BYTES,
            timeout_seconds=8,
            instruction_budget=10_000,
            allow_execution=True,
            entry_address=0x401000,
        )
    )


def test_adapter_installs_and_registers_the_shim(fake_speakeasy, monkeypatch) -> None:
    """The production adapter must install the shim AND register its handlers.

    BEHAVIOURAL: the shim's own functions are spied on, so a body that merely MENTIONS `install_vb6_shim`
    fails - the call has to happen.
    """
    fake_speakeasy()
    from threat_report_agent.emulation import vb6_runtime_shim

    installed: list[object] = []
    registered: list[object] = []

    def _install(se: object) -> tuple[object, dict[str, object]]:
        installed.append(se)
        return SimpleNamespace(calls={"msvbvm60:__vbastrcopy": 3}, arguments_seen=[]), {
            "msvbvm60:__vbastrcopy": object()
        }

    def _register(se: object, handlers: object) -> list[str]:
        registered.append(handlers)
        return ["msvbvm60:__vbastrcopy"]

    monkeypatch.setattr(vb6_runtime_shim, "install_vb6_shim", _install)
    monkeypatch.setattr(vb6_runtime_shim, "register_vb6_shim", _register)

    _run_adapter()

    assert installed, "the shim is not installed by the production adapter"
    assert registered, "the shim handlers are never registered"


def test_registration_happens_after_load_module(fake_speakeasy, monkeypatch) -> None:
    """Measured: load_module rebuilds the hook registry and discards earlier hooks.

    BEHAVIOURAL: the shim's `register_vb6_shim` is replaced by one that registers through the real
    `add_api_hook` of the fake emulator, which DROPS any registration made before `load_module` exactly as
    Speakeasy does. The assertion is therefore about surviving hooks (the production effect), not about the
    order of two names in a source file. A shim registered before `load_module` produces NO surviving hook.
    """
    fake_speakeasy()
    from threat_report_agent.emulation import vb6_runtime_shim

    def _install(se: object) -> tuple[object, dict[str, object]]:
        return SimpleNamespace(calls={}, arguments_seen=[]), {"msvbvm60:thing": object()}

    def _register(se: object, handlers: object) -> list[str]:
        for handler in handlers:
            se.add_api_hook(handler, "MSVBVM60.DLL", "thing")  # type: ignore[attr-defined]
        return ["msvbvm60:thing"]

    monkeypatch.setattr(vb6_runtime_shim, "install_vb6_shim", _install)
    monkeypatch.setattr(vb6_runtime_shim, "register_vb6_shim", _register)

    _run_adapter()

    assert _FakeSpeakeasy.instances, "the adapter never constructed a Speakeasy instance"
    emulator = _FakeSpeakeasy.instances[-1]
    assert "load_module" in emulator.calls, "the adapter never loaded the module"
    assert emulator.registered_after_load, (
        "register_vb6_shim must come AFTER load_module; registering earlier silently never fires, and no hook "
        f"survived this run (call order: {emulator.calls})"
    )
    assert not emulator.registered_before_load, (
        "a hook was registered before load_module, so the emulator's registry rebuild discarded it: "
        f"{emulator.registered_before_load}"
    )
    assert emulator.calls.index("load_module") < emulator.calls.index(
        "add_api_hook:MSVBVM60.DLL:thing"
    ), f"registration preceded load_module in the observed call order: {emulator.calls}"


def test_shim_failure_cannot_break_the_emulation(fake_speakeasy, monkeypatch) -> None:
    """A shim that cannot install must degrade to the unshimmed result, not raise."""
    fake_speakeasy()
    from threat_report_agent.emulation import vb6_runtime_shim

    def _explode(se: object) -> tuple[object, dict[str, object]]:
        raise RuntimeError("shim exploded")

    monkeypatch.setattr(vb6_runtime_shim, "install_vb6_shim", _explode)

    result = _run_adapter()

    assert result.status != "FAILED" or "shim exploded" not in str(result.limitations), (
        "a shim that cannot install took the whole emulation down instead of degrading to the unshimmed run: "
        f"status={result.status} limitations={result.limitations}"
    )
    events = [item.get("event") for item in result.observations]
    assert "shim_unavailable" in events, (
        "the shim's failure was not recorded as `shim_unavailable`, so an unshimmed run is indistinguishable "
        f"from a run where the shim was never attempted: {events}"
    )


def test_no_production_module_is_left_importing_the_shim_only_from_tests() -> None:
    """The original defect: the shim existed but nothing in `src/` imported it."""
    package = Path(simulation_adapters.__file__).parent
    importers = [
        path.name
        for path in package.glob("*.py")
        if "vb6_runtime_shim" in path.read_text(encoding="utf-8") and path.name != "vb6_runtime_shim.py"
    ]
    assert importers, "no production module imports the shim"


def test_shim_reports_its_own_contribution(fake_speakeasy, monkeypatch) -> None:
    """The run must publish what was modelled, so a shimmed run is distinguishable from an unshimmed one.

    BEHAVIOURAL: the shim spy reports THREE modelled calls, and the published `vb6_shim` observation must carry
    that number and the registered hook count. A body that merely names `modelled_calls` cannot satisfy this.
    """
    fake_speakeasy()
    from threat_report_agent.emulation import vb6_runtime_shim

    def _install(se: object) -> tuple[object, dict[str, object]]:
        return (
            SimpleNamespace(calls={"msvbvm60:__vbastrcopy": 2, "msvbvm60:__vbachkstk": 1}, arguments_seen=[]),
            {"msvbvm60:__vbastrcopy": object(), "msvbvm60:__vbachkstk": object()},
        )

    def _register(se: object, handlers: object) -> list[str]:
        return ["msvbvm60:__vbastrcopy", "msvbvm60:__vbachkstk"]

    monkeypatch.setattr(vb6_runtime_shim, "install_vb6_shim", _install)
    monkeypatch.setattr(vb6_runtime_shim, "register_vb6_shim", _register)

    result = _run_adapter()

    published = [item for item in result.observations if item.get("event") == "vb6_shim"]
    assert published, (
        "the run did not publish a `vb6_shim` observation, so a shimmed run cannot be told from an unshimmed "
        f"one: {[item.get('event') for item in result.observations]}"
    )
    assert published[0]["modelled_calls"] == 3, (
        f"the published shim contribution does not count the modelled calls: {published[0]}"
    )
    assert published[0]["registered"] == 2, (
        f"the published hook count does not match what registration returned: {published[0]}"
    )
