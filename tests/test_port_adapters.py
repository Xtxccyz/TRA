"""Contract test for the production adapter that exists (P1.2's "至少一个 adapter").

`tests/test_ports.py` proves all six ports are satisfiable by DETERMINISTIC TEST adapters. This file proves the
one PRODUCTION adapter satisfies its port against the real machinery, on inputs whose outcome is fixed:

  * `analyze` runs the real deterministic parser on a deliberately truncated PE. Its outcome is pinned by the
    parser's own behaviour: `detected_type == "pe"` and a `PE parsing incomplete: invalid PE signature`
    limitation. A byte string that is NOT a valid PE and needs no fixture file and no network.
  * `disassemble` runs the real runner with a `ghidra_home` that does not exist, so the tool-missing branch is
    taken. That branch is deterministic on every machine and asserts the port's stated contract: absence is a
    STATUS, not an exception (`ghidra_adapter.py:141-142`).

Nothing here executes a sample or contacts an endpoint. The PE is 202 bytes of `MZ` plus zeros.

    python -m pytest -q tests/test_port_adapters.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import ports  # noqa: E402
from threat_report_agent.port_adapters import StaticEvidenceAdapter  # noqa: E402

#: A truncated PE: enough for the format detector, not enough for a valid signature. MEASURED outcome is pinned
#: in the assertions below.
TRUNCATED_PE = b"MZ" + bytes(200)


def adapter() -> StaticEvidenceAdapter:
    return StaticEvidenceAdapter(ghidra_home=str(Path("definitely-not-a-ghidra-install")))


def test_the_production_adapter_satisfies_its_port() -> None:
    assert isinstance(adapter(), ports.StaticEvidencePort), (
        "the production adapter does not satisfy the port it implements, so consumers written against the seam "
        "would fail at the point of use"
    )


def test_analyze_returns_the_port_view_over_the_real_parser() -> None:
    view = adapter().analyze(TRUNCATED_PE, "truncated.exe")

    assert isinstance(view, ports.StaticEvidenceView)
    assert view.detected_type == "pe", f"format detection changed: {view.detected_type!r}"
    assert isinstance(view.facts, tuple), "facts must be an ordered tuple, not a list"
    assert isinstance(view.limitations, tuple), "limitations must be an ordered tuple, not a list"
    assert any("PE parsing incomplete" in item for item in view.limitations), (
        "a truncated PE must carry its parser limitation, not pass silently: "
        f"{list(view.limitations)}"
    )
    assert view.pe is None or isinstance(view.pe, dict), (
        "`pe` is the lifted summary['pe'] and must be a mapping or absent, never a half-parsed object"
    )


def test_analyze_does_not_raise_on_a_malformed_artifact() -> None:
    """The port's error clause: a malformed artifact becomes a limitation, and whatever was recovered is kept."""
    view = adapter().analyze(b"not a PE at all", "garbage.bin")

    assert isinstance(view.detected_type, str) and view.detected_type, "the detector must name something"
    assert isinstance(view.limitations, tuple)


def test_disassemble_reports_absence_as_a_status_not_an_exception() -> None:
    view = adapter().disassemble(TRUNCATED_PE, "truncated.exe", budget_seconds=30)

    assert isinstance(view, ports.StaticDisassemblyView)
    assert view.status == "FAILED", f"a missing toolchain must be FAILED, got {view.status!r}"
    assert view.error == "GHIDRA_HEADLESS_UNAVAILABLE", (
        f"the reason must be the stable code callers branch on, got {view.error!r}"
    )
    assert view.output == {}, f"an unavailable tool produces no output, got {view.output!r}"


def test_the_adapter_does_not_project_the_dead_fields() -> None:
    """Pins the deliberate exclusions, so a later edit cannot silently widen the port by projecting them.

    MEASURED: no production caller reads `GhidraRun.stdout`/`stderr` content - the only reads merely re-carry them
    into a replacement run (`service.py:17206-17216`). Projecting them would forward a dead field, which is how a
    seam turns into a façade.
    """
    view = adapter().disassemble(TRUNCATED_PE, "truncated.exe", budget_seconds=30)

    assert not hasattr(view, "stdout"), "stdout is not part of StaticDisassemblyView"
    assert not hasattr(view, "stderr"), "stderr is not part of StaticDisassemblyView"
