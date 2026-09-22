"""Production adapters for the P1.2 ports. Started with the ONE port whose machinery is reachable in-process.

WHY THERE IS ONLY ONE ADAPTER HERE, and why that is the honest state rather than a shortcut:

The plan's P1.2 success criterion reads "至少一个 adapter 和一份 deterministic test adapter". The deterministic
test adapters live in `tests/test_ports.py` for all six ports. A PRODUCTION adapter can only be written for a seam
whose implementation can be called without a database, a worker or a running service, and only four of the six
qualify today at all - and of those, this one is the only pair whose both methods are already in-process:

  * `StaticEvidencePort` -> `static_analysis.analyze_bytes` and `ghidra_adapter.GhidraHeadlessRunner`, both plain
    in-process calls. WRITTEN HERE.
  * `ToolExecutionPort` -> `temporalio` workflows and `ToolRunRequest`; the port is `async` and its two methods are
    already implemented by `TemporalToolExecutor`. An adapter would be a one-line forward, which is the forwarding
    shape P1.2's deletion test exists to reject; the real work is the consumer move in P3.
  * `EmulationPort` -> the outcome view has NO producer in the tree (`ports.py`'s own note), so an adapter would
    have to invent it. That is P3.5's step, with its own verification.
  * `ModelPlanningPort` -> the canonical path needs a configured provider. An adapter whose every call returns
    `MODEL_NOT_CONFIGURED` proves nothing about the seam.

`ReportRevisionWriter` and `WorkbenchQueryReader` are analysis-service-bound and arrive with P3.4/P3.6.

No consumer uses this adapter yet, so it changes no behaviour: `--strict` deployment comparison and the behaviour
probe are both unaffected by a module nothing imports. That is stated so this file is not read as a decoupling.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from threat_report_agent.ghidra_adapter import GhidraHeadlessRunner
from threat_report_agent.static.static_analysis import analyze_bytes


class _ParserEvidenceView:
    """`StaticEvidenceView` over a `StaticResult`. Lifts `pe` out of `summary`, which is the one flattening
    `tests/test_ports.py::FLATTENED_FIELDS` records for this view."""

    def __init__(self, detected_type: str, facts: tuple[Any, ...], pe: Any, limitations: tuple[str, ...]) -> None:
        self.detected_type = detected_type
        self.facts = facts
        self.pe = pe
        self.limitations = limitations


class _DisassemblyView:
    """`StaticDisassemblyView` over a `GhidraRun`. `stdout`/`stderr` are deliberately not projected: measured,
    no caller reads their content, only `error`."""

    def __init__(self, status: str, error: str | None, output: Any) -> None:
        self.status = status
        self.error = error
        self.output = output


class StaticEvidenceAdapter:
    """`StaticEvidencePort` over the real deterministic parser and the real Ghidra runner.

    Neither method executes the sample: `analyze_bytes` parses bytes, and `GhidraHeadlessRunner` runs a static
    exporter over a copy. `ghidra_home` is required because the runner cannot discover one; an unavailable
    installation is reported as `status="FAILED"`, `error="GHIDRA_HEADLESS_UNAVAILABLE"` rather than raised, which
    is the contract the port states (`ghidra_adapter.py:141-142`).
    """

    def __init__(self, ghidra_home: str, java_home: str = "", *, runner: Any = None) -> None:
        self._ghidra_home = ghidra_home
        self._java_home = java_home
        self._runner = runner

    def _resolve_runner(self) -> Any:
        if self._runner is None:
            self._runner = GhidraHeadlessRunner(self._ghidra_home, self._java_home)
        return self._runner

    def analyze(self, content: bytes, logical_path: str) -> _ParserEvidenceView:
        result = analyze_bytes(content, logical_path)
        summary = result.summary if isinstance(result.summary, dict) else {}
        pe = summary.get("pe")
        return _ParserEvidenceView(
            str(result.detected_type),
            tuple(result.facts),
            pe if isinstance(pe, dict) else None,
            tuple(str(item) for item in result.limitations),
        )

    def disassemble(
        self,
        content: bytes,
        logical_path: str,
        *,
        budget_seconds: int,
        cancelled: Callable[[], bool] | None = None,
        processor: str | None = None,
    ) -> _DisassemblyView:
        run = self._resolve_runner().analyze(
            content,
            logical_path,
            timeout_seconds=int(budget_seconds),
            cancellation_requested=cancelled,
            processor=processor,
        )
        return _DisassemblyView(str(run.status), run.error, run.output)
