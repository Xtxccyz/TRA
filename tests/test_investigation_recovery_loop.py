from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.investigation import (
    ActionType,
    MechanismPlaybookRegistry,
    apply_emulation_reverification,
    how_timebox_disposition,
    recovery_actions_for_gap,
    verify_mechanism,
)
from threat_report_agent.product_certification import mechanism_coverage_metrics
from threat_report_agent.service import AnalysisService


def test_how_timebox_defers_controlled_emulate_instead_of_static_boundary() -> None:
    disposition, method = how_timebox_disposition(ActionType.CONTROLLED_EMULATE.value)
    assert disposition == "defer"
    assert method == ActionType.CONTROLLED_EMULATE.value

    placeholder = [
        {
            "kind": "simulation_result",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        }
    ]
    disposition, method = how_timebox_disposition(
        "STATIC_BOUNDARY",
        attempted=["GET_DECOMPILE", "CONTROLLED_EMULATE"],
        evidence=placeholder,
    )
    assert disposition == "defer"
    assert method == ActionType.CONTROLLED_EMULATE.value

    real = [
        {
            "kind": "simulation_result",
            "value": {"status": "SUCCEEDED", "simulator": "unicorn", "function_entry": "0x1800011c0"},
        }
    ]
    disposition, method = how_timebox_disposition(
        "STATIC_BOUNDARY",
        attempted=["GET_DECOMPILE", "CONTROLLED_EMULATE"],
        evidence=real,
    )
    assert disposition == "terminate"
    assert method == "STATIC_BOUNDARY"


def test_investigation_loop_consults_the_timebox_disposition() -> None:
    """P3.7, LEFT PENDING: the loop body must consult `how_timebox_disposition`.

    This is the one `getsource` guard in this file that P3.7 did NOT convert, and the reason is recorded
    rather than hidden. The behaviour it protects is "a timeboxed HOW seed is DEFERRED (next_method kept)
    instead of being closed as STATIC_BOUNDARY", which is decided inside the loop's nested `park_unfinished`
    in `investigation/derivation.py`. No test in this suite drives the loop to that call: reaching it needs a
    seed cluster that resolves to a HOW playbook AND a `_persist_time_static_boundary` result whose gate
    still has recoverable `missing` tokens, i.e. a new persist-time boundary fixture. The PREDICATE itself is
    covered behaviourally by `test_how_timebox_defers_controlled_emulate_instead_of_static_boundary` above,
    so this guard keeps only the wiring claim until that fixture exists (`docs/p37-getsource-conversion-plan-20260922.md`
    §4.3: build the fixture first; a source guard may not simply be dropped).
    """
    import inspect

    from threat_report_agent.investigation.derivation import _run_investigation_loop

    loop_source = inspect.getsource(_run_investigation_loop)
    assert "how_timebox_disposition" in loop_source, (
        "the investigation loop no longer consults the timebox disposition, so a timeboxed HOW seed can be "
        "closed as STATIC_BOUNDARY while recoverable slots remain"
    )


def test_decode_gap_still_queues_trace_after_candidate() -> None:
    actions = recovery_actions_for_gap(
        "DECODE_CONFIG",
        ("cipher/data",),
        attempted=["GET_PCODE_SLICE", "DECODE_CANDIDATE"],
    )
    assert ActionType.TRACE_API_ARGUMENT.value in actions
    assert ActionType.CONTROLLED_EMULATE.value in actions
    assert actions[0] == ActionType.TRACE_API_ARGUMENT.value


def test_process_execution_without_createprocess_is_not_applicable() -> None:
    listing = [
        {
            "id": "imp",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW"},
            "anchor": {"type": "pe_import"},
        }
    ]
    result = verify_mechanism("PROCESS_EXECUTION", listing)
    assert result.accepted is False
    assert result.status == "NOT_APPLICABLE"
    assert recovery_actions_for_gap("PROCESS_EXECUTION", ("creation_flags",), evidence=listing) == ()
    metrics = mechanism_coverage_metrics(
        [
            {"mechanism_type": "PROCESS_EXECUTION", "status": "NOT_APPLICABLE"},
            {
                "mechanism_type": "DYNAMIC_API_RESOLUTION",
                "status": "VERIFIED",
                "target": "resolver",
                "inputs": ["kernel32"],
                "transformation_or_control": ["GetProcAddress"],
                "outputs": ["pointer"],
                "consumers": ["call rax"],
                "side_effects": ["resolves API"],
                "evidence_ids": ["e1", "e2"],
                "verifier": {"status": "VERIFIED"},
            },
        ]
    )
    assert metrics["mechanism_count"] == 1
    assert metrics["verified_mechanism_count"] == 1


def test_cryptdecrypt_does_not_fail_xor_counter_checklist() -> None:
    incomplete = [
        {
            "id": "decrypt",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CryptDecrypt"},
            "anchor": {"function_entry": "0x180001000"},
        }
    ]
    result = verify_mechanism("DECODE_CONFIG", incomplete)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert "counter" not in result.missing
    assert "step" not in result.missing
    assert "cipher/data" in result.missing

    closed = [
        {
            "id": "import-key",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CryptImportKey",
                "key_blob": {"address": "0x18000a000", "length": 16},
                "arguments": [
                    {"index": 1, "name": "pbData", "value": "0x18000a000", "resolved": True},
                ],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "id": "decrypt",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CryptDecrypt",
                "algorithm": "CALG_RC4",
                "pbData": {"address": "0x18000b000", "length": 64},
                "arguments": [
                    {"index": 1, "name": "pbData", "value": "0x18000b000", "resolved": True},
                ],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "id": "flow",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "output_to_consumer",
                "consumer": "CreateThread lpParameter",
                "source_evidence_ids": ["decrypt", "import-key"],
            },
            "anchor": {"function_entry": "0x180001000"},
        },
    ]
    verified = verify_mechanism("DECODE_CONFIG", closed)
    assert verified.accepted is True
    assert verified.status == "VERIFIED"
    assert not verified.missing


def test_real_simulation_result_reverifies_mechanisms() -> None:
    mechanisms = [
        {
            "mechanism_type": "DECODE_CONFIG",
            "status": "CANDIDATE",
            "target": "CryptDecrypt",
        }
    ]
    placeholder = [
        {
            "kind": "simulation_result",
            "value": {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"},
        }
    ]
    unchanged = apply_emulation_reverification(mechanisms, placeholder)
    assert unchanged[0]["status"] == "CANDIDATE"

    evidence = [
        {
            "id": "decrypt",
            "kind": "function_call",
            "value": {"api": "CryptDecrypt"},
            "anchor": {"function_entry": "0x180001000"},
        },
        {
            "kind": "simulation_result",
            "value": {
                "status": "SUCCEEDED",
                "simulator": "speakeasy",
                "function_entry": "0x180001000",
            },
        },
    ]
    updated = apply_emulation_reverification(mechanisms, evidence)
    assert updated[0]["status"] != "VERIFIED"
    assert updated[0]["next_method"] == ActionType.TRACE_API_ARGUMENT.value
    assert "counter" not in (updated[0].get("verifier") or {}).get("missing", ())


def test_xor_config_playbook_includes_trace_and_emulate() -> None:
    playbook = MechanismPlaybookRegistry().by_id("xor-config-recovery")
    names = {item.value for item in playbook.preferred_actions}
    assert ActionType.TRACE_API_ARGUMENT.value in names
    assert ActionType.GET_DECOMPILE.value in names
    assert ActionType.CONTROLLED_EMULATE.value in names


def test_persist_skip_keeps_argument_trace_and_emulate() -> None:
    from threat_report_agent.investigation import ActionSpec

    trace = ActionSpec(
        id="queued-trace",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    recover = ActionSpec(
        id="queued-arg",
        action_type=ActionType.TRACE_API_ARGUMENT,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"api": "CryptDecrypt"},
    )
    emu = ActionSpec(
        id="queued-emu",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-decode",
        hypothesis_id="hyp-decode",
        artifact_id="artifact-dll",
        target_selector={"function_entry": "0x180001000"},
    )
    kept = AnalysisService._keep_emulation_after_persist_skip((trace, recover, emu))
    assert [item.id for item in kept] == ["queued-arg", "queued-emu"]

    queued_trace = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.GET_CALLEES.value,
        error=None,
        finished_at=None,
    )
    queued_arg = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.TRACE_API_ARGUMENT.value,
        error=None,
        finished_at=None,
    )
    queued_emu = SimpleNamespace(
        status="QUEUED",
        action_type=ActionType.CONTROLLED_EMULATE.value,
        error=None,
        finished_at=None,
    )
    AnalysisService._supersede_queued_trace_after_persist_skip(
        (queued_trace, queued_arg, queued_emu),
        thread_id="thread-decode",
    )
    assert queued_trace.status == "CANCELLED"
    assert queued_arg.status == "QUEUED"
    assert queued_emu.status == "QUEUED"


def test_gap_driven_rounds_are_not_skipped_only_because_dsh_owns_chat(
    test_settings, monkeypatch
) -> None:
    """With DSH owning the conversation, a backend gap-driven round must still RUN.

    P3.7: this used to be a `getsource` NEGATIVE guard (`"dsh_conversation_owns_planning" not in` the
    function's early section). The retired shortcut was `if settings.dsh_conversation_owns_planning: return []`,
    which skipped the gap-driven rounds entirely. The premise is asserted (`dsh_conversation_owns_planning`
    is the default), and the observable is that a round is planned AND recorded durably on the task - which
    no early return can produce.
    """
    from dataclasses import replace

    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.contracts import DynamicPlanAction
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob

    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    assert settings.dsh_conversation_owns_planning is True, (
        "this test measures the DSH-owned-planning configuration, so that default must hold"
    )
    database = Database(settings.database_url)
    service = AnalysisService(
        settings, database, LocalContentStore(settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("gap rounds under DSH-owned planning")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="8" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/gap-rounds",
            )
        )
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "work_ledger": [
                        {
                            "id": "thread-how",
                            "thread_id": "thread-how",
                            "status": "DEFERRED",
                            "next_method": ActionType.CONTROLLED_EMULATE.value,
                        }
                    ]
                }
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-gap-rounds",
            task_id=task.id,
            content_sha256="8" * 64,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        task_id = task.id
        artifact_id = artifact.id

    proposal = DynamicPlanAction(
        target_artifact_id=artifact_id,
        action_type=ActionType.GET_XREFS_TO.value,
        reason="close the deferred controlled-emulate seed from inside the image",
        question="Which call sites reach the deferred seed?",
        target_selector={"target": "GetProcAddress"},
    )
    planned_phases: list[str] = []

    def record_planning(task_id: str, artifacts, artifact_ids, **kwargs):  # noqa: ANN001, ANN202
        del task_id, artifacts, artifact_ids
        planned_phases.append(str(kwargs.get("phase") or ""))
        return [proposal], []

    # The planner and the executor are the two hops this test is NOT about; the early-return guard is.
    monkeypatch.setattr(service, "_run_model_planning", record_planning)
    monkeypatch.setattr(service, "_run_investigation_loop", lambda task_id, **kwargs: [])

    service._run_gap_driven_model_rounds(task_id)

    assert planned_phases == ["post_investigation_gap_1"], (
        "no gap-driven model round was planned while DSH owned the conversation: the retired "
        "`dsh_conversation_owns_planning` shortcut is back"
    )
    with database.session_factory() as session:
        planning = dict(
            (session.get(AnalysisTask, task_id).strategy_snapshot or {}).get("dynamic_planning") or {}
        )
    assert planning.get("post_investigation_rounds") == 1, (
        f"the round was planned but never recorded durably: {planning!r}"
    )


def test_emulation_informed_path_reverifies_how_on_the_rows_that_just_landed(
    test_settings, monkeypatch
) -> None:
    """The emulation-informed path must REVERIFY HOW, and the reverification is the service's own hop.

    P3.7: replaces two `getsource` PRESENCE guards - `"_reverify_how_after_emulation" in
    getsource(run_emulation_informed_investigation)` and `"apply_emulation_reverification" in
    getsource(AnalysisService._reverify_how_after_emulation)`. Both are read as behaviour here: the public
    entry point is run against a real database with one real `simulation_result` row landing in between, and
    the recorded call shows WHICH rows were handed to the reverification and that its verdict was persisted.
    """
    from dataclasses import replace

    import threat_report_agent.service as service_module
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import (
        AnalysisTask,
        Artifact,
        ContentBlob,
        Evidence,
        ToolRun,
    )
    from threat_report_agent.task.analysis_task_orchestration import (
        run_emulation_informed_investigation,
    )

    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("emulation-informed reverification")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="7" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/informed-reverify",
            )
        )
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={
                "investigation": {
                    "mechanisms": [
                        {
                            "id": "mech-exec",
                            "mechanism_type": "PROCESS_EXECUTION",
                            "status": "CANDIDATE",
                        }
                    ]
                }
            },
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-informed-reverify",
            task_id=task.id,
            content_sha256="7" * 64,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="controlled-emulator",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        task_id = task.id
        artifact_id = artifact.id
        run_id = run.id

    def dispatch_post_static_emulation(inner_task_id: str) -> list[str]:
        with database.session_factory.begin() as session:
            session.add(
                Evidence(
                    id="sim-informed",
                    task_id=inner_task_id,
                    artifact_id=artifact_id,
                    tool_run_id=run_id,
                    module="emulation",
                    kind="simulation_result",
                    nature="EMULATION_OBSERVED",
                    value={"status": "SUCCEEDED", "simulator": "unicorn"},
                    anchor={},
                )
            )
        return ["dispatched"]

    recorded: list[tuple[list[dict[str, object]], list[dict[str, object]]]] = []
    real_reverification = service_module.apply_emulation_reverification

    def spy_reverification(mechanisms, evidence):  # noqa: ANN001, ANN202 - mirrors the real signature
        recorded.append(([dict(item) for item in mechanisms], [dict(item) for item in evidence]))
        return real_reverification(mechanisms, evidence)

    monkeypatch.setattr(service, "_run_post_static_emulation", dispatch_post_static_emulation)
    monkeypatch.setattr(service, "_run_investigation_loop", lambda task_id, **kwargs: [])
    monkeypatch.setattr(service_module, "apply_emulation_reverification", spy_reverification)

    run_emulation_informed_investigation(service, task_id, saturated=False)

    assert len(recorded) == 1, (
        "the emulation-informed path did not reverify HOW exactly once; a worker row that changes nothing "
        "is exactly the regression these guards exist for"
    )
    mechanisms_arg, evidence_arg = recorded[0]
    assert [item.get("id") for item in mechanisms_arg] == ["mech-exec"], mechanisms_arg
    assert any(
        row.get("kind") == "simulation_result"
        and str((row.get("value") or {}).get("status") or "").upper() == "SUCCEEDED"
        for row in evidence_arg
    ), f"the reverification did not receive the simulation rows that just landed: {evidence_arg!r}"
    with database.session_factory() as session:
        stored = dict(
            (session.get(AnalysisTask, task_id).strategy_snapshot or {}).get("investigation") or {}
        )
    assert (stored.get("mechanisms") or [{}])[0].get("verifier"), (
        f"the reverification verdict was not written back to the task: {stored.get('mechanisms')!r}"
    )


def test_consumer_gap_schedules_argument_trace_first() -> None:
    """G0 §4.4：对象级消费者是「解码输出缓冲进了哪个 API 参数」。

    缺 consumer 时必须先跑 TRACE_API_ARGUMENT。只跑 GET_CALLEES /
    TRACE_RETURN_VALUE / GET_DECOMPILE 补不上这条边，预算会烧在反编译上。
    """
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("consumer",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions
    assert actions[0] == ActionType.TRACE_API_ARGUMENT.value
    assert ActionType.GET_DECOMPILE.value in actions
    assert ActionType.CONTROLLED_EMULATE.value in actions


def test_unknown_wrapped_consumer_gap_still_schedules_argument_trace() -> None:
    """G0 §4.3：verifier 缺口可能写成 unknown(consumer)，不能因此漏掉恢复动作。"""
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("unknown(consumer)",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions


def test_join_gap_schedules_argument_trace() -> None:
    """G0 §4.3：join 也是镜像内可恢复槽，必须继续 TRACE，不能静态收工。"""
    actions = recovery_actions_for_gap("DECODE_CONFIG", ("join",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions


def test_parent_identity_gap_schedules_object_chain_recovery() -> None:
    """G0 §4.3：parent identity 要靠镜像内的枚举/名称使用链，不是再反编译一遍。"""
    actions = recovery_actions_for_gap("PPID_SPOOFING", ("parent identity",))
    assert ActionType.TRACE_API_ARGUMENT.value in actions
