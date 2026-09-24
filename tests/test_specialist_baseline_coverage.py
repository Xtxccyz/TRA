"""Every PE-appropriate specialist tool must be scheduled WITHOUT a model proposal.

MEASURED gap this pins: `_build_execution_queue` seeds from `_baseline_tools_for_artifact` and is first
called with `model_actions=[]` (the planner turn deliberately runs only after the baseline commits). So a
tool absent from the baseline can only arrive via a later model replan. Across 474 tasks in the database
that left three declared tools with ZERO runs ever:

    crypto-pattern-scanner   0 runs
    build-metadata-scanner   0 runs
    knowledge-fact-matcher   0 runs

and the rest of the PE specialists barely present, so their findings could never reach a report. These
tests fail if the baseline regresses to model-dependent coverage.
"""
from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.models import Artifact
from threat_report_agent.service import SPECIALIST_STATIC_TOOLS, AnalysisService


def _artifact(detected_type: str = "pe") -> Artifact:
    return Artifact(
        task_id="task",
        content_sha256="a" * 64,
        logical_path="sample.exe",
        detected_type=detected_type,
        role="EXECUTABLE",
        obligation="REQUIRED",
    )


def _service() -> AnalysisService:
    """A bare instance: only `settings` is read by the baseline helper."""
    service = object.__new__(AnalysisService)
    service.settings = SimpleNamespace(simulation_enabled=True)
    return service


def test_baseline_specialists_cover_the_pe_declared_tools() -> None:
    """The three tools that never ran in 474 tasks must be in the deterministic baseline."""
    artifact = _artifact("pe")
    queued = AnalysisService.baseline_specialist_tools(artifact, already=set())

    for required in (
        "knowledge-fact-matcher",
        "crypto-pattern-scanner",
        "build-metadata-scanner",
    ):
        assert required in queued, f"{required} must be scheduled deterministically, not by the model"


def test_baseline_specialists_are_compatible_tools_only() -> None:
    """Never schedule a tool the compatibility gate would reject."""
    artifact = _artifact("pe")
    compatible = AnalysisService._compatible_static_tools(artifact)
    queued = AnalysisService.baseline_specialist_tools(artifact, already=set())

    assert set(queued) <= compatible
    assert "signal-extractor" not in queued, (
        "signal-extractor already runs unconditionally at the end of the deterministic route; "
        "including it here would execute it twice"
    )


def test_baseline_specialists_exclude_already_queued() -> None:
    artifact = _artifact("pe")
    already = {"knowledge-fact-matcher"}
    queued = AnalysisService.baseline_specialist_tools(artifact, already=already)

    assert "knowledge-fact-matcher" not in queued


def test_non_pe_artifacts_get_no_specialists() -> None:
    """A script/zip artifact must not be handed PE-only scanners."""
    artifact = _artifact("script")
    queued = AnalysisService.baseline_specialist_tools(artifact, already=set())
    assert "build-metadata-scanner" not in queued
    assert "crypto-pattern-scanner" not in queued


def test_pe_baseline_includes_parser_ghidra_emulator_and_specialists() -> None:
    """End-to-end shape of the PE baseline queue."""
    service = _service()
    baseline = service._baseline_tools_for_artifact(_artifact("pe"))

    assert baseline[0] == "pe-parser"
    assert "ghidra-headless" in baseline
    # Specialists come after the core coverage so a queue-budget cut drops the cheapest work first.
    for specialist in ("knowledge-fact-matcher", "crypto-pattern-scanner", "build-metadata-scanner"):
        assert specialist in baseline
        assert baseline.index(specialist) > baseline.index("ghidra-headless")

    assert set(baseline) <= AnalysisService._compatible_static_tools(_artifact("pe"))


def test_every_specialist_is_either_baseline_or_run_deterministically() -> None:
    """No member of SPECIALIST_STATIC_TOOLS may be reachable only through a model proposal.

    `signal-extractor` is the documented exception: it runs unconditionally after the queue drains.
    Everything else must be in the PE baseline.
    """
    service = _service()
    baseline = set(service._baseline_tools_for_artifact(_artifact("pe")))
    deterministic_post_queue = {"signal-extractor"}

    orphans = {
        name
        for name in SPECIALIST_STATIC_TOOLS
        if name not in baseline and name not in deterministic_post_queue
    }
    assert not orphans, f"specialists scheduled only by the model: {sorted(orphans)}"
