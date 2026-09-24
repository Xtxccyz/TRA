from __future__ import annotations

from threat_report_agent.investigation.persist_how import (
    persist_how_claim_specs,
    persist_partial_how_ready,
    stage_persist_how_claims,
)
from threat_report_agent.dataflow import catalog_decode_output_to_process_command_relation


def test_process_verifiers_are_wired_into_the_live_mechanism_path() -> None:
    """§7.5: the three verifiers must be reachable from the live path, not merely registered.

    A verifier that is registered but never called is not implemented. This asserts
    both halves: dispatching each mechanism type reaches that specific function, and
    the live post-emulation path actually goes through ``verify_mechanism``.

    P3.7: the two `getsource` guards that used to close this test - `"verify_mechanism" in
    getsource(apply_emulation_reverification)` and `"apply_emulation_reverification" in
    getsource(AnalysisService._reverify_how_after_emulation)` - are gone. Their subject (does the LIVE
    post-emulation path arrive at `verify_mechanism`?) is asserted below by RUNNING it end to end, through
    the public orchestration entry point, and reading the row it writes back; a grep could be satisfied by
    a mention in a comment, which is exactly the failure mode measured in this family.
    """
    from threat_report_agent.investigation import (
        verify_mechanism,
        verify_ppid_mechanism,
        verify_process_execution_mechanism,
        verify_thread_callback_mechanism,
    )

    rows: list[dict[str, object]] = []
    for mechanism_type, direct in (
        ("PROCESS_EXECUTION", verify_process_execution_mechanism),
        ("PROCESS_CREATION", verify_process_execution_mechanism),
        ("PPID_SPOOFING", verify_ppid_mechanism),
        ("THREAD_CALLBACK", verify_thread_callback_mechanism),
    ):
        dispatched = verify_mechanism(mechanism_type, rows)
        expected = direct(rows)
        assert dispatched.status == expected.status, mechanism_type
        assert dispatched.accepted == expected.accepted, mechanism_type
        assert dispatched.missing == expected.missing, mechanism_type


def test_live_post_emulation_path_reaches_verify_mechanism_and_persists_its_verdict(
    test_settings, monkeypatch
) -> None:
    """§7.5, as behaviour: a real simulation result must reach `verify_mechanism` and be written back.

    Replacement for the two source guards in the test above. The public entry point
    (`run_emulation_informed_investigation`) is run against a real database; the only stand-ins are the two
    hops this test is NOT about - the emulator dispatch (made to land one real `simulation_result` row) and
    the follow-up loop (recorded, not run). The observables are then the recorded dispatch into
    `verify_mechanism` and the persisted mechanism row, so a broken hop fails here whatever the source says.
    """
    from dataclasses import replace

    import threat_report_agent.investigation.investigation as investigation_module
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
    from threat_report_agent.service import AnalysisService
    from threat_report_agent.task.analysis_task_orchestration import (
        run_emulation_informed_investigation,
    )

    settings = replace(test_settings, environment="development", model_calls_enabled=True)
    database = Database(settings.database_url)
    service = AnalysisService(settings, database, LocalContentStore(settings.content_store_path))
    database.create_schema()
    case = service.create_case("live post-emulation reverification")
    mechanism = {"id": "mech-exec", "mechanism_type": "PROCESS_EXECUTION", "status": "CANDIDATE"}
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256="9" * 64,
                size=1,
                media_type="application/octet-stream",
                storage_key="sha256/live-reverification",
            )
        )
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"investigation": {"mechanisms": [dict(mechanism)]}},
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            id="artifact-live-reverify",
            task_id=task.id,
            content_sha256="9" * 64,
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
        """The worker's real rows would land here; one SUCCEEDED simulation_result is what matters."""
        with database.session_factory.begin() as session:
            session.add(
                Evidence(
                    id="sim-real",
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

    dispatched_mechanisms: list[str] = []
    real_verify_mechanism = investigation_module.verify_mechanism

    def spy_verify_mechanism(mechanism_type, evidence):  # noqa: ANN001, ANN202 - mirrors the real signature
        dispatched_mechanisms.append(str(mechanism_type).upper())
        return real_verify_mechanism(mechanism_type, evidence)

    monkeypatch.setattr(service, "_run_post_static_emulation", dispatch_post_static_emulation)
    monkeypatch.setattr(service, "_run_investigation_loop", lambda task_id, **kwargs: [])
    monkeypatch.setattr(investigation_module, "verify_mechanism", spy_verify_mechanism)

    run_emulation_informed_investigation(service, task_id, saturated=False)

    assert dispatched_mechanisms == ["PROCESS_EXECUTION"], (
        "the live post-emulation path never dispatched the mechanism to `verify_mechanism`; the verifier is "
        "registered but unreachable, which §7.5 counts as not implemented"
    )
    with database.session_factory() as session:
        persisted = dict(session.get(AnalysisTask, task_id).strategy_snapshot or {})
    stored = dict(persisted.get("investigation") or {}).get("mechanisms") or []
    assert stored and stored[0].get("verifier"), (
        "the live path reached `apply_emulation_reverification` but the verdict it produced was not written "
        f"back to the task: {stored!r}"
    )


def test_persist_how_mints_named_api_without_module_input() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "resolved-1",
                "kind": "resolved_api",
                "nature": "STATIC_DERIVED",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "SetThreadDescription",
                    "consumer": "JMP R8",
                    "function_entry": "140038dd0",
                },
                "anchor": {"function_entry": "140038dd0"},
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_resolve_api_dynamically" in by_action
    assert "SetThreadDescription" in str(by_action["may_resolve_api_dynamically"]["object"])
    assert "JMP R8" in str(by_action["may_resolve_api_dynamically"]["mechanism"])
    assert "kernel32.dll" not in str(by_action["may_resolve_api_dynamically"]["object"])

    pending: list[tuple[object, object, object, object]] = []
    stage_persist_how_claims(
        pending,
        specs,
        task_id="task-named-api",
        subject="Resume.pdf.exe",
    )
    named = [item[0] for item in pending]
    assert len(named) == 1
    assert named[0].claim_type == "INVESTIGATED_MECHANISM"
    assert named[0].status == "CANDIDATE"
    assert named[0].module == "loader"
    assert pending[0][3]["claim_kind"] == "persist_time_investigated_mechanism"


def test_persist_partial_how_ready_rejects_openprocess_only_ppid() -> None:
    assert not persist_partial_how_ready(
        "ppid-process-chain",
        [
            {
                "id": "call-open",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "OpenProcess"},
            }
        ],
    )


def test_emit_ranked_symbols_then_stage_sees_process32_before_claim_specs() -> None:
    from types import SimpleNamespace

    from threat_report_agent.investigation.persist_how import PersistHow

    order: list[str] = []
    emitted: list[object] = []
    original = PersistHow._persist_how_claim_specs

    @classmethod
    def spy(cls, *, artifact_path: str, evidence):
        order.append("specs")
        names = []
        for item in evidence:
            value = getattr(item, "value", None) or (item.get("value") if isinstance(item, dict) else None)
            if isinstance(value, dict) and value.get("name"):
                names.append(str(value.get("name")))
        order.extend(names)
        return original(artifact_path=artifact_path, evidence=evidence)

    def emit(kind: str, value: dict[str, object], anchor: dict[str, object], **_kwargs):
        order.append(f"emit:{value.get('name')}")
        row = SimpleNamespace(id=f"ev-{len(emitted)}", kind=kind, value=value, nature="STATIC_OBSERVED")
        emitted.append(row)
        return row

    PersistHow._persist_how_claim_specs = spy
    try:
        PersistHow.emit_ranked_symbols_then_stage(
            {
                "symbols": [
                    {"name": "internal", "external": False, "address": "140001000"},
                    {"name": "Process32FirstW", "external": True, "address": "140046000"},
                ]
            },
            emit=emit,
            extra_evidence=[],
            emitted_evidence=emitted,
            artifact_path="Resume.pdf.exe",
            pending_claims=[],
            task_id="task-symbols",
            subject="Resume.pdf.exe",
        )
    finally:
        PersistHow._persist_how_claim_specs = original

    assert order.index("emit:Process32FirstW") < order.index("specs")
    assert order.index("emit:Process32FirstW") < order.index("emit:internal")
    assert "Process32FirstW" in order[order.index("specs") :]


def test_persist_how_decode_without_consumer_stays_unknown() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://69.48.228.74/miaom-c.pdf",
                    "consumer_status": "NOT_IDENTIFIED",
                },
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action["may_decode_configuration"]
    assert "UNKNOWN(consumer)" in str(claim["mechanism"])
    assert "consumer=UNKNOWN(consumer)" in str(claim["mechanism"])
    assert "decoded output consumer" not in str(claim["mechanism"])
    assert "管线已坐实" not in str(claim["statement"])
    assert "plaintext=`http://69.48.228.74/miaom-c.pdf`" in str(claim["mechanism"])


def test_persist_how_decode_and_process_without_buffer_join_stay_unknown() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "FoxitPDFReader.exe",
                },
            },
            {
                "id": "proc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "UNKNOWN(join)" in blobs
    assert "JOINED_STATIC" not in blobs
    assert "plaintext=`FoxitPDFReader.exe`" in blobs
    assert "consumer=UNKNOWN(consumer)" in blobs


def test_persist_how_same_buffer_decode_process_is_joined_static() -> None:
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 24,
    }
    relation = catalog_decode_output_to_process_command_relation(
        decode_id="decode-1",
        process_id="proc-1",
        output_buffer=buffer,
        command_buffer=dict(buffer),
        plaintext="FoxitPDFReader.exe",
        command="FoxitPDFReader.exe",
    )
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "FoxitPDFReader.exe",
                    "output_buffer": dict(buffer),
                },
            },
            {
                "id": "proc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                    "command_buffer": dict(buffer),
                },
            },
            {
                "id": "join-1",
                "kind": "value_flow",
                "nature": "STATIC_INFERRED",
                "value": relation,
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" in blobs
    assert "UNKNOWN(join)" not in blobs
    assert "consumer=CreateProcessW" in blobs or "consumer=CreateProcess" in blobs


def test_persist_how_matching_buffers_catalog_join_without_premined_value_flow() -> None:
    """Persist must mint decode→process Join from same-buffer identities, not a pre-staged value_flow."""
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 24,
    }
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "FoxitPDFReader.exe",
                    "output_buffer": dict(buffer),
                },
            },
            {
                "id": "proc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                    "command_buffer": dict(buffer),
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" in blobs
    assert "UNKNOWN(join)" not in blobs
    assert "consumer=CreateProcessW" in blobs or "consumer=CreateProcess" in blobs


def test_persist_how_process_source_buffer_on_non_command_arg_is_not_a_join() -> None:
    """A CreateProcess flags/source_buffer co-location is not lpCommandLine Join."""
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 24,
    }
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "FoxitPDFReader.exe",
                    "output_buffer": dict(buffer),
                },
            },
            {
                "id": "proc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                    "argument_index": 5,
                    "source_role": "decoded_output",
                    "source_buffer": dict(buffer),
                    "input_buffer": dict(buffer),
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "UNKNOWN(join)" in blobs
    assert "JOINED_STATIC" not in blobs


def test_persist_how_process_without_flags_stays_unknown() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                },
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_create_process" in by_action
    claim = by_action["may_create_process"]
    assert "UNKNOWN(creation_flags)" in str(claim["mechanism"])
    assert "recovered creation flags" not in str(claim["mechanism"])
    assert "CREATE_SUSPENDED" not in str(claim["mechanism"])
    assert "CREATE_SUSPENDED" not in str(claim["statement"])
    assert "UNKNOWN(fallback)" in str(claim["mechanism"])
    assert "schtasks" not in str(claim["mechanism"]).casefold()


def test_persist_how_createprocess_import_is_not_process_execution() -> None:
    """C2: an IAT name is not a CreateProcess call and must not mint process HOW."""
    specs = persist_how_claim_specs(
        artifact_path="loader.dll",
        evidence=[
            {
                "id": "imp-1",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "CreateProcessW", "dll": "KERNEL32.dll"},
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_create_process" not in by_action
    blob = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "CREATE_SUSPENDED" not in blob
    assert "0x00000004" not in blob


def test_persist_how_schtasks_string_is_not_a_process_fallback() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                },
            },
            {
                "id": "task-1",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "schtasks /create /sc once"},
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action["may_create_process"]
    assert "UNKNOWN(fallback)" in str(claim["mechanism"])
    assert "fallback=schtasks" not in str(claim["mechanism"]).casefold()


def test_persist_how_ppid_without_enumeration_does_not_invent_explorer() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "attr-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "UpdateProcThreadAttribute",
                    "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                },
            },
            {
                "id": "name-1",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "explorer.exe"},
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "parent=explorer.exe" not in blobs.casefold()
    if "may_spoof_parent_process" in blobs:
        assert "UNKNOWN(parent identity)" in blobs


def test_persist_how_ppid_import_listing_does_not_make_explorer_parent() -> None:
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "imp-1",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "Process32FirstW"},
            },
            {
                "id": "attr-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "UpdateProcThreadAttribute",
                    "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                },
            },
            {
                "id": "name-1",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "explorer.exe"},
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "parent=explorer.exe" not in blobs.casefold()
    if "may_spoof_parent_process" in blobs:
        assert "UNKNOWN(parent identity)" in blobs


def test_persist_how_winhttpopen_without_request_rebuild_stays_unknown() -> None:
    """C4: a transport API listing is not a reconstructed HTTP request or a live C2."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "http-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "WinHttpOpen"},
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action.get("may_download_over_http")
    if claim is None:
        return
    blob = str(claim["mechanism"])
    assert "UNKNOWN(request)" in blob
    assert "UNKNOWN(endpoint)" in blob
    assert "live c2" not in blob.casefold()
    assert "live c2" not in str(claim["statement"]).casefold()


def test_persist_how_gettickcount_without_threshold_stays_unknown() -> None:
    """C4: a probe API listing is not a proven anti-analysis gate."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "tick-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "GetTickCount64"},
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action.get("may_probe_environment")
    assert claim is not None
    blob = str(claim["mechanism"])
    assert "UNKNOWN(threshold)" in blob
    assert "GetTickCount64" in blob
    assert "anti-sandbox" not in blob.casefold()
    assert "bypassed" not in str(claim["statement"]).casefold()


def test_persist_how_gettickcount_import_listing_is_not_a_gate() -> None:
    """C4: an IAT listing of GetTickCount64 is not an environment-guard HOW."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "imp-tick",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "GetTickCount64"},
            }
        ],
    )
    actions = {str(fields["action"]) for _playbook, fields, _ids in specs}
    assert "may_probe_environment" not in actions


def test_persist_how_gettickcount_comparison_constant_is_threshold() -> None:
    """C4: a recovered CMP immediate is the threshold slot, not UNKNOWN(threshold)."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "tick-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "GetTickCount64"},
            },
            {
                "id": "cmp-1",
                "kind": "constant",
                "nature": "STATIC_DERIVED",
                "value": {
                    "name": "threshold",
                    "api": "GetTickCount64",
                    "comparison": "0x493e1",
                    "threshold": "0x493e1",
                    "return_branch": "JBE 0x401080",
                },
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action["may_probe_environment"]
    blob = str(claim["mechanism"])
    assert "threshold=0x493e1" in blob.casefold() or "threshold=0x0493e1" in blob.casefold()
    assert "UNKNOWN(threshold)" not in blob
    assert "JBE 0x401080" in blob or "UNKNOWN(exit)" not in blob


def test_persist_how_sleep_is_not_an_environment_gate() -> None:
    """C4: Sleep is not persist-time environment-guard HOW."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "sleep-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "Sleep", "dwMilliseconds": 1000},
            }
        ],
    )
    actions = {str(fields["action"]) for _playbook, fields, _ids in specs}
    assert "may_probe_environment" not in actions


def test_persist_how_environment_cfg_exit_is_not_unknown() -> None:
    """C4: persist projects a typed fail/exit cfg_block onto the environment HOW."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "tick-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "GetTickCount64"},
            },
            {
                "id": "cmp-1",
                "kind": "constant",
                "nature": "STATIC_DERIVED",
                "value": {
                    "name": "threshold",
                    "api": "GetTickCount64",
                    "threshold": "0x493e1",
                    "comparison": "0x493e1",
                },
            },
            {
                "id": "cfg-1",
                "kind": "cfg_block",
                "nature": "STATIC_DERIVED",
                "value": {
                    "return_branch": "fail",
                    "gated_behavior": "exit",
                    "exit": "ExitProcess",
                },
            },
        ],
    )
    claim = {str(fields["action"]): fields for _playbook, fields, _ids in specs}[
        "may_probe_environment"
    ]
    blob = str(claim["mechanism"])
    assert "threshold=0x493e1" in blob.casefold()
    assert "UNKNOWN(threshold)" not in blob
    assert "ExitProcess" in blob or "exit" in blob.casefold()
    assert "UNKNOWN(exit)" not in blob


_BUFFER_URL = {
    "artifact_id": "artifact-resume",
    "address_space": "image",
    "address": 0x14004C900,
    "length": 40,
}


def test_persist_how_same_buffer_xor_url_to_winhttp_is_joined_static() -> None:
    """C3: XOR URL and WinHttpOpen sharing a buffer mint JOINED_STATIC, not live C2."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-url",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://example.invalid/gate",
                    "output_buffer": dict(_BUFFER_URL),
                },
            },
            {
                "id": "http-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "WinHttpOpen",
                    "source_role": "decoded_output",
                    "source_buffer": dict(_BUFFER_URL),
                    "input_buffer": dict(_BUFFER_URL),
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" in blobs
    assert "UNKNOWN(join)" not in blobs
    assert "WinHttpOpen" in blobs
    assert "UNKNOWN(consumer)" not in blobs
    assert "live c2" not in blobs.casefold()


def test_persist_how_xor_url_and_winhttp_on_different_buffers_is_not_joined() -> None:
    """C3 T1: two buffers / matching URL text is UNKNOWN(join), not JOINED_STATIC."""
    other = {**_BUFFER_URL, "address": 0x140010000}
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-url",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://example.invalid/gate",
                    "output_buffer": dict(_BUFFER_URL),
                },
            },
            {
                "id": "http-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "WinHttpOpen",
                    "source_role": "decoded_output",
                    "source_buffer": other,
                    "input_buffer": other,
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" not in blobs
    assert "UNKNOWN(join)" in blobs or "UNKNOWN(consumer)" in blobs


def test_persist_how_winhttp_import_is_not_a_decode_join() -> None:
    """C3 T1: an IAT listing is not a typed URL→WinHTTP Join."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-url",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://example.invalid/gate",
                    "output_buffer": dict(_BUFFER_URL),
                },
            },
            {
                "id": "iat-1",
                "kind": "import_symbol",
                "nature": "STATIC_OBSERVED",
                "value": {"name": "WinHttpOpen"},
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" not in blobs
    assert "UNKNOWN(consumer)" in blobs or "UNKNOWN(join)" in blobs


def test_persist_how_unknown_join_records_only_real_attempted_actions() -> None:
    """C3: UNKNOWN(join) may list attempted GET_DECOMPILE/TRACE/EMU only when evidence has them."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-url",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://example.invalid/gate",
                    "output_buffer": dict(_BUFFER_URL),
                },
            },
            {
                "id": "http-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "WinHttpOpen",
                    "source_role": "decoded_output",
                    "source_buffer": {**_BUFFER_URL, "address": 0x140010000},
                },
            },
            {
                "id": "attempt-1",
                "kind": "investigation_attempt",
                "nature": "STATIC_DERIVED",
                "value": {
                    "attempted_action_types": [
                        "GET_DECOMPILE",
                        "TRACE_API_ARGUMENT",
                    ]
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" not in blobs
    assert "UNKNOWN(join)" in blobs
    assert "attempted=GET_DECOMPILE,TRACE_API_ARGUMENT" in blobs
    assert "CONTROLLED_EMULATE" not in blobs


def test_persist_how_unknown_join_does_not_invent_attempts() -> None:
    """C3: missing attempt rows must not claim GET_DECOMPILE/TRACE/EMU were tried."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-url",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "http://example.invalid/gate",
                    "output_buffer": dict(_BUFFER_URL),
                },
            },
            {
                "id": "http-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "WinHttpOpen",
                    "source_role": "decoded_output",
                    "source_buffer": {**_BUFFER_URL, "address": 0x140010000},
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "UNKNOWN(join)" in blobs or "UNKNOWN(consumer)" in blobs
    assert "attempted=GET_DECOMPILE" not in blobs
    assert "attempted=CONTROLLED_EMULATE" not in blobs


def test_persist_how_same_buffer_crypto_to_virtualalloc_is_joined_static() -> None:
    """C3: CryptoAPI output and VirtualAlloc sharing a buffer is JOINED_STATIC, not executed."""
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14005A000,
        "length": 0x1000,
    }
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-crypt",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "CryptDecrypt",
                    "algorithm": "CryptDecrypt",
                    "output_buffer": dict(buffer),
                },
            },
            {
                "id": "alloc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "VirtualAlloc",
                    "source_role": "decoded_output",
                    "source_buffer": dict(buffer),
                    "input_buffer": dict(buffer),
                },
            },
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "JOINED_STATIC" in blobs
    assert "VirtualAlloc" in blobs
    assert "UNKNOWN(join)" not in blobs
    assert "executed" not in blobs.casefold()
    assert "DYNAMIC" not in blobs


def test_persist_how_sleep_without_back_edge_is_unknown_loop() -> None:
    """C4: Sleep is a delay HOW with UNKNOWN(loop), not C2 tasking."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "sleep-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "Sleep", "dwMilliseconds": 1000},
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_probe_environment" not in by_action
    claim = by_action.get("may_delay_or_poll")
    assert claim is not None
    blob = str(claim["mechanism"])
    assert "UNKNOWN(loop)" in blob
    assert "Sleep" in blob
    assert "live c2" not in blob.casefold()
    assert "not c2 tasking" in str(claim["statement"]).casefold()


def test_persist_how_defender_key_without_dword_is_unknown_value() -> None:
    """C4: a Defender registry key without DWORD stays UNKNOWN(value)."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "reg-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "RegSetValueExW",
                    "key": r"SOFTWARE\Microsoft\Windows Defender",
                },
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action.get("may_modify_defender")
    assert claim is not None
    blob = str(claim["mechanism"])
    assert "UNKNOWN(value)" in blob
    assert "永不扫描" not in blob
    assert "关闭整个" not in str(claim["statement"])


def test_persist_how_tmp_mz_without_size_is_unknown_size() -> None:
    """C4: .tmp + MZ without 0x1000 stays UNKNOWN(size); filename is not dropped."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "file-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "CreateFileW",
                    "path": "stage.tmp",
                    "magic": "MZ",
                },
            }
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action.get("may_write_file")
    assert claim is not None
    blob = str(claim["mechanism"])
    assert "UNKNOWN(size)" in blob
    assert "size=0x1000" not in blob.casefold()
    assert "已落地" not in str(claim["statement"])


def test_persist_how_does_not_invent_phase_shell() -> None:
    """C4: persist must not invent Phase 1–8 empty attack-chain shells."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "tick-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "GetTickCount64"},
            }
        ],
    )
    blobs = " ".join(str(fields) for _playbook, fields, _ids in specs)
    assert "Phase 1" not in blobs
    assert "Phase 8" not in blobs
    assert "阶段 1" not in blobs


def test_persist_how_sleep_with_back_edge_is_not_unknown_loop() -> None:
    """C4: a recovered CFG back-edge fills the loop slot; still not C2 tasking."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "sleep-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"api": "Sleep", "dwMilliseconds": 1000},
            },
            {
                "id": "cfg-1",
                "kind": "cfg_block",
                "nature": "STATIC_DERIVED",
                "value": {"back_edge": "0x140001abc"},
            },
        ],
    )
    claim = {str(fields["action"]): fields for _playbook, fields, _ids in specs}[
        "may_delay_or_poll"
    ]
    blob = str(claim["mechanism"])
    assert "back_edge=0x140001abc" in blob
    assert "UNKNOWN(loop)" not in blob
    assert "not c2 tasking" in str(claim["statement"]).casefold()


def test_persist_how_defender_dword_is_not_unknown_value() -> None:
    """C4: a recovered DWORD is visible; the product is not claimed off."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "reg-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "RegSetValueExW",
                    "key": r"SOFTWARE\Microsoft\Windows Defender",
                    "data": "0x1",
                },
            }
        ],
    )
    claim = {str(fields["action"]): fields for _playbook, fields, _ids in specs}[
        "may_modify_defender"
    ]
    blob = str(claim["mechanism"])
    assert "value=0x1" in blob.casefold()
    assert "UNKNOWN(value)" not in blob
    assert "永不扫描" not in blob
    assert "关闭整个" not in str(claim["statement"])


def test_persist_how_tmp_mz_with_size_threshold_is_visible() -> None:
    """C4: recovered 0x1000 is visible; a .tmp name is not already written to disk."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "file-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "api": "CreateFileW",
                    "path": "stage.tmp",
                    "magic": "MZ",
                    "size": "0x1000",
                },
            }
        ],
    )
    claim = {str(fields["action"]): fields for _playbook, fields, _ids in specs}[
        "may_write_file"
    ]
    blob = str(claim["mechanism"])
    assert "size=0x1000" in blob.casefold()
    assert "UNKNOWN(size)" not in blob
    assert "已落地" not in str(claim["statement"])


def test_persist_how_relation_chain_is_timing_without_phase_shell() -> None:
    """C4: two catalog Relations are an ordered static chain, not invented Phase 1–8."""
    buffer = {
        "artifact_id": "artifact-resume",
        "address_space": "image",
        "address": 0x14004C8E1,
        "length": 24,
    }
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "decode-1",
                "kind": "decode_result",
                "nature": "STATIC_DERIVED",
                "value": {
                    "formula": "key_table_modulo_xor_counter",
                    "decoded_text": "FoxitPDFReader.exe",
                    "output_buffer": dict(buffer),
                },
            },
            {
                "id": "proc-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                    "command_buffer": dict(buffer),
                },
            },
            {
                "id": "flow-http",
                "kind": "value_flow",
                "nature": "STATIC_INFERRED",
                "value": {
                    "relation": "output_to_consumer",
                    "api": "WinHttpOpen",
                    "output_buffer": {
                        "artifact_id": "artifact-resume",
                        "address": 0x14004C900,
                        "length": 40,
                    },
                    "input_buffer": {
                        "artifact_id": "artifact-resume",
                        "address": 0x14004C900,
                        "length": 40,
                    },
                },
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    claim = by_action.get("may_order_static_stages")
    assert claim is not None
    blob = str(claim["mechanism"])
    assert "decode_output_to_process_command" in blob or "output_to_consumer" in blob
    assert "->" in blob or "→" in blob
    assert "Phase 1" not in blob
    assert "Phase 8" not in str(claim["statement"])
    assert "阶段 1" not in str(claim["statement"])


def test_persist_how_single_relation_is_not_a_timing_chain() -> None:
    """C4: one Relation is not an attack-chain timeline."""
    specs = persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "flow-1",
                "kind": "value_flow",
                "nature": "STATIC_INFERRED",
                "value": {"relation": "output_to_consumer", "api": "LoadLibraryW"},
            }
        ],
    )
    actions = {str(fields["action"]) for _playbook, fields, _ids in specs}
    assert "may_order_static_stages" not in actions
