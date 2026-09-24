"""The full-PE emulator must actually be reachable, not just configured.

MEASURED DEFECT. `SIMULATION_ALLOWED_SIMULATORS` is `('unicorn','speakeasy','qiling')` and
`"speakeasy" in policy.allowed_simulators` is **True** in the API, so `_run_controlled_emulator`
computes `speakeasy = True`. It is then discarded:

    granted_windows = unicorn_granted_windows_for_worker(
        controlled_emulation_windows(..., allow_speakeasy=False, ...)   # <- built WITHOUT speakeasy
    )
    parameters = {..., "allow_speakeasy": False if granted_windows else speakeasy}

`granted_windows` is never empty for a real PE - Unicorn always gets at least the PE-entry window
(`test_windows_grant_pe_entry_when_no_thread_start_is_recovered` asserts exactly that) - so
`allow_speakeasy` is **always False**. Every emulator run in this deployment passed
`allow_speakeasy: false`, which the evidence confirms for all three runs on the VB6 sample.

The cost, measured on the real Resume bytes in the isolated worker:

    Unicorn (granted bytes only, no loader/IAT)   stop=UNMAPPED_DATA after 3 instructions
    Speakeasy (full PE)                           reaches module entry 0x140001420 and executes
                                                  real code (0x140001030 -> 0x14000114c ->
                                                  0x140047358) before stopping on an
                                                  unimplemented CRT import

P3.7 CONVERSION: this file used to read `inspect.getsource(AnalysisService._run_controlled_emulator)`
and slice/parse that text (`source.index(...)`, `body.split(...)`). That pinned the SHAPE of an argument
rather than the decision the worker receives, and it broke on reformatting. These tests now run the real
decision path - policy, simulator decision, window plan - and read the `ToolRunRequest` the Temporal
worker is actually handed.
"""

from __future__ import annotations

from dataclasses import replace

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.emulation.policy import simulation_policy_from_settings
from threat_report_agent.emulation_plan import controlled_emulation_windows
from threat_report_agent.intake import PackageEntry
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob
from threat_report_agent.service import AnalysisService
from threat_report_agent.tools.tool_execution import ToolRunResult


def _minimal_pe() -> bytes:
    """A tiny but STRUCTURALLY VALID PE32 whose paragraph-aligned export gives it a real entry.

    MEASURED: `b"MZ" + zeros` is NOT enough - `analyze_bytes` returns no PE summary for it, so
    `controlled_emulation_windows` plans no PE-entry window and the grant comes back empty. With this body the
    real planner emits `unicorn/pe_entry` plus a Speakeasy window, which is the production shape these tests
    depend on.
    """
    data = bytearray(0x500)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    data[optional + 96 : optional + 100] = (0x1100).to_bytes(4, "little")
    data[optional + 100 : optional + 104] = (0x80).to_bytes(4, "little")
    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x400).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x400).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[0x400:0x401] = b"\xc3"
    return bytes(data)


def _emulator_settings(test_settings, **overrides: object):
    values: dict[str, object] = {
        "simulation_profile": "static-first-controlled-emulation",
        "simulation_worker_identity": "controlled-emu-worker-v1",
        "simulation_worker_image_digest": "sha256:emu-worker-v1",
        "simulation_allowed_simulators": ("unicorn", "speakeasy"),
        "simulation_allow_local_process": False,
        "tool_execution_mode": "temporal",
        "simulation_timeout_seconds": 8,
        "simulation_instruction_budget": 100_000,
        "simulation_max_output_bytes": 65536,
        "simulation_max_input_bytes": 4_194_304,
    }
    values.update(overrides)
    return replace(test_settings, **values)


def _captured_request(test_settings, monkeypatch, **overrides: object):
    """Run the REAL decision path; return the `ToolRunRequest` handed to the Temporal worker.

    Only the Temporal client is replaced (by a recorder that never starts a workflow). The policy, the
    `speakeasy` decision, the grant plan and the `parameters` dict are all production code.
    """
    from threat_report_agent import service as service_module

    settings = _emulator_settings(test_settings, **overrides)
    database = Database(settings.database_url)
    store = LocalContentStore(settings.content_store_path)
    service = AnalysisService(settings, database, store)
    database.create_schema()
    case = service.create_case("speakeasy reachability")
    payload = _minimal_pe()
    stored = store.put(payload)
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="full-pe.dll",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        task_id = task.id
        artifact_id = artifact.id

    captured: list[object] = []

    class _ExecutorRecorder:
        def __init__(self, temporal_address: str) -> None:
            self.temporal_address = temporal_address

        async def execute(self, request: object) -> ToolRunResult:
            captured.append(request)
            return ToolRunResult(
                status="FAILED", error="RECORDED_NOT_EXECUTED", worker_metadata={}
            )

    monkeypatch.setattr(service_module, "TemporalToolExecutor", _ExecutorRecorder)

    service._run_controlled_emulator(
        task_id,
        artifact_id,
        PackageEntry(
            logical_path="full-pe.dll",
            content=payload,
            parent_path=None,
            discovery="submitted",
            detected_type="pe",
        ),
    )
    assert captured, (
        "the emulator decision path did not reach the tool executor at all, so this test observes nothing"
    )
    return captured[0], settings


def test_granted_window_planning_asks_for_speakeasy(test_settings, monkeypatch) -> None:
    """`granted_windows` must be planned WITH Speakeasy, or the request can never include it.

    Pins the actual mistake behaviourally: the decision the worker receives must carry the operator's
    Speakeasy decision even though a Unicorn (PE-entry) window was granted. The old source-text form split the
    body on `max_windows=4,` and looked for `allow_speakeasy=speakeasy` inside that slice; this asserts the same
    requirement at the only place that matters - the request.
    """
    request, _settings = _captured_request(test_settings, monkeypatch)
    parameters = request.parameters  # type: ignore[attr-defined]

    # The production shape this test depends on: a real PE DOES grant a Unicorn window.
    assert parameters.get("granted_windows"), (
        "the fixture no longer produces a granted Unicorn window, so this test cannot distinguish the defect "
        "from the fix"
    )
    assert parameters["allow_speakeasy"] is True, (
        "the worker's request carries allow_speakeasy=False even though the operator allows Speakeasy and a "
        "full-PE window can be requested; the full-PE emulator is unreachable"
    )


def test_operator_intent_is_not_overridden_by_having_any_unicorn_window(
    test_settings, monkeypatch
) -> None:
    """A Unicorn window must not silently disable the full-PE emulator.

    The production expression was `False if granted_windows else speakeasy`. Since a real PE always yields at
    least a PE-entry Unicorn window, the operator's configured simulator was discarded in every case.
    """
    request, _settings = _captured_request(test_settings, monkeypatch)
    parameters = request.parameters  # type: ignore[attr-defined]
    assert parameters.get("granted_windows"), "the fixture must grant a Unicorn window for this guard to bite"
    assert parameters["allow_speakeasy"] is not False, (
        "allow_speakeasy is still gated on granted_windows being empty; for any real PE that condition is never "
        "true and the full-PE emulator stays unreachable"
    )


def test_speakeasy_is_configured_as_an_allowed_simulator_by_default() -> None:
    """The premise: the deployment DOES allow Speakeasy, so the block is not a policy choice.

    This is also checked end to end: the decision path builds its policy through
    `simulation_policy_from_settings`, which must report Speakeasy as allowed for these settings.
    """
    from threat_report_agent.config import Settings
    from threat_report_agent.emulation.policy import simulation_policy_from_settings

    settings = Settings.from_environment()
    allowed = tuple(getattr(settings, "simulation_allowed_simulators", ()) or ())
    if not allowed:
        # An unset environment is the module default; assert the default allows it.
        from threat_report_agent.config import Settings as _Settings

        assert "speakeasy" in _Settings.model_fields["simulation_allowed_simulators"].default, (
            "speakeasy must be in the default allowed simulators"
        )
    else:
        assert "speakeasy" in {str(item).casefold() for item in allowed}, (
            f"speakeasy is not among the configured simulators: {allowed}"
        )

    policy = simulation_policy_from_settings(
        replace(
            Settings.from_environment(),
            simulation_profile="static-first-controlled-emulation",
            simulation_worker_identity="controlled-emu-worker-v1",
            simulation_allowed_simulators=("unicorn", "speakeasy"),
        )
    )
    assert "speakeasy" in policy.allowed_simulators, (
        "the decision path's own policy no longer reports Speakeasy as allowed"
    )
