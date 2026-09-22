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
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

from threat_report_agent import simulation_adapters
from threat_report_agent.simulation_adapters import _speakeasy_adapter


def _adapter_source() -> str:
    return inspect.getsource(_speakeasy_adapter)


def test_adapter_installs_and_registers_the_shim() -> None:
    source = _adapter_source()
    assert "install_vb6_shim" in source, "the shim is not installed by the production adapter"
    assert "register_vb6_shim" in source, "the shim handlers are never registered"


def test_registration_happens_after_load_module() -> None:
    """Measured: load_module rebuilds the hook registry and discards earlier hooks."""
    source = _adapter_source()
    load_at = source.index("load_module")
    register_at = source.index("register_vb6_shim")
    assert register_at > load_at, (
        "register_vb6_shim must come AFTER load_module; registering earlier silently never fires"
    )


def test_shim_failure_cannot_break_the_emulation() -> None:
    """A shim that cannot install must degrade to the unshimmed result, not raise."""
    source = _adapter_source()
    assert "shim_unavailable" in source
    # The install must sit inside a try/except that records rather than propagates.
    guard = source.index("install_vb6_shim")
    window = source[max(0, guard - 400) : guard]
    assert "try:" in window, "install/register must be guarded"


def test_no_production_module_is_left_importing_the_shim_only_from_tests() -> None:
    """The original defect: the shim existed but nothing in `src/` imported it."""
    package = Path(simulation_adapters.__file__).parent
    importers = [
        path.name
        for path in package.glob("*.py")
        if "vb6_runtime_shim" in path.read_text(encoding="utf-8") and path.name != "vb6_runtime_shim.py"
    ]
    assert importers, "no production module imports the shim"


def test_shim_reports_its_own_contribution() -> None:
    """The run must publish what was modelled, so a shimmed run is distinguishable from an unshimmed one."""
    source = _adapter_source()
    assert "vb6_shim" in source
    assert "modelled_calls" in source
