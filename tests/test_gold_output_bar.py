"""Simulated gold-bar: dialect, investigation queues, and official markdown depth."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from fastapi.testclient import TestClient

from threat_report_agent.gold_output_bar import (
    GOLD_BAR_PASS_SCORE,
    evaluate_t5_sample_bar,
    format_gold_bar,
    score_official_markdown,
)
from threat_report_agent.investigation import ActionType, DeepMiningPlanner
from threat_report_agent.main import create_app
from threat_report_agent.report.reporting import build_report_document, document_to_markdown


def _ns(**kwargs: object) -> SimpleNamespace:
    return SimpleNamespace(**kwargs)


def _evidence(
    evidence_id: str,
    kind: str,
    value: dict[str, object],
    *,
    module: str = "static_triage",
    nature: str = "STATIC_INFERRED",
    anchor: dict[str, object] | None = None,
) -> SimpleNamespace:
    return _ns(
        id=evidence_id,
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module=module,
        kind=kind,
        nature=nature,
        value=value,
        anchor=anchor or {},
    )


def _claim(
    claim_id: str,
    *,
    module: str,
    catalog_id: str,
    statement: str,
    mechanism: str,
    status: str = "CANDIDATE",
) -> SimpleNamespace:
    return _ns(
        id=claim_id,
        module=module,
        claim_type="BEHAVIOR",
        subject="sample.exe",
        action="recovers_static_behavior",
        object="recovered mechanism",
        mechanism=mechanism,
        condition="static evidence only",
        statement=statement,
        status=status,
        confidence="MEDIUM",
        attack_mapping={},
        model_call_id=None,
        catalog_id=catalog_id,
    )


def _arg(index: int, name: str, value: str) -> dict[str, object]:
    return {"argument_index": index, "name": name, "value": value, "source_kind": "immediate"}


def _rich_ledger() -> tuple[list[SimpleNamespace], list[SimpleNamespace], list[SimpleNamespace]]:
    pe = _evidence(
        "e-pe",
        "pe_structure",
        {
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": 0x1420,
            "image_base": 0x140000000,
            "subsystem": 3,
            "sections": [{"name": ".text"}, {"name": ".rdata"}, {"name": ".data"}],
            "imports": [
                {"dll": "kernel32", "functions": [
                    "CreateThread", "CreateProcessW", "CreateToolhelp32Snapshot",
                    "OpenProcess", "LoadLibraryW", "GetProcAddress", "Sleep",
                    "GetTickCount64", "GlobalMemoryStatus",
                ]},
                {"dll": "winhttp", "functions": [
                    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
                    "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
                ]},
                {"dll": "advapi32", "functions": [
                    "CryptGenKey", "CryptEncrypt", "RegSetValueExW", "RegOpenKeyExW",
                ]},
            ],
        },
        nature="STATIC_OBSERVED",
    )
    summaries = [
        _evidence(
            "e-anti",
            "function_semantic_summary",
            {
                "function": "FUN_140009ccb",
                "function_entry": "0x140009ccb",
                "call_sequence": [
                    {"api": "GetTickCount64", "callsite": "0x140009d10", "arguments": [_arg(0, "unused", "0")]},
                    {"api": "GlobalMemoryStatus", "callsite": "0x140009d40", "arguments": [_arg(0, "lpBuffer", "0x14004d000")]},
                ],
                "conditions": [{"address": "0x140009d20", "text": "GetTickCount64() < 0x493e1"}],
                "consumers": ["exit_path"],
                "unknowns": ["sandbox vs ordinary startup is not proven"],
            },
            module="anti_analysis",
            anchor={"function_entry": "0x140009ccb"},
        ),
        _evidence(
            "e-net",
            "function_semantic_summary",
            {
                "function": "FUN_140031f00",
                "function_entry": "0x140031f00",
                "call_sequence": [
                    {"api": "WinHttpOpen", "callsite": "0x140031f10", "arguments": [_arg(0, "pszAgentW", "Mozilla/5.0")]},
                    {"api": "WinHttpConnect", "callsite": "0x140031f40", "arguments": [
                        _arg(1, "pswzServerName", "203.0.113.10"),
                        _arg(2, "nServerPort", "80"),
                    ]},
                    {"api": "WinHttpSendRequest", "callsite": "0x140031f80", "arguments": [_arg(1, "lpszHeaders", "Cache-Control: no-cache")]},
                    {"api": "WinHttpReadData", "callsite": "0x140031fc0", "arguments": [_arg(2, "dwNumberOfBytesToRead", "0x1000")]},
                ],
                "consumers": ["payload_buffer"],
                "unknowns": ["response is not observed C2 tasking"],
            },
            module="c2_network",
            anchor={"function_entry": "0x140031f00"},
        ),
        _evidence(
            "e-crypto",
            "function_semantic_summary",
            {
                "function": "FUN_140001490",
                "function_entry": "0x140001490",
                "call_sequence": [
                    {"api": "CryptGenKey", "callsite": "0x1400014a0", "arguments": [_arg(1, "Algid", "0x6801")]},
                    {"api": "CryptEncrypt", "callsite": "0x1400014c0", "arguments": [
                        _arg(4, "pbData", "byte_14004c900"),
                        _arg(5, "pdwDataLen", "31"),
                    ]},
                ],
                "consumers": ["decoded_config_buffer"],
                "unknowns": ["runtime decrypt success is unobserved"],
            },
            module="decryption",
            anchor={"function_entry": "0x140001490"},
        ),
        _evidence(
            "e-persist",
            "function_semantic_summary",
            {
                "function": "FUN_140004605",
                "function_entry": "0x140004605",
                "call_sequence": [
                    {"api": "RegOpenKeyExW", "callsite": "0x140004620", "arguments": [
                        _arg(1, "lpSubKey", r"SOFTWARE\Microsoft\Windows Defender\SpyNet"),
                    ]},
                    {"api": "RegSetValueExW", "callsite": "0x140004650", "arguments": [
                        _arg(1, "lpValueName", "MAPSReporting"),
                        _arg(4, "lpData", "0"),
                    ]},
                    {"api": "ShellExecuteW", "callsite": "0x1400046a0", "arguments": [
                        _arg(2, "lpFile", "schtasks"),
                        _arg(3, "lpParameters", "/create /f /sc once"),
                    ]},
                ],
                "consumers": ["fallback_path"],
                "unknowns": ["single-run task is not proven durable persistence"],
            },
            module="behavior_attack",
            anchor={"function_entry": "0x140004605"},
        ),
        _evidence(
            "e-proc",
            "function_semantic_summary",
            {
                "function": "FUN_140009da0",
                "function_entry": "0x140009da0",
                "call_sequence": [
                    {"api": "OpenProcess", "callsite": "0x140009e20", "arguments": [_arg(0, "dwDesiredAccess", "0x80")]},
                    {"api": "UpdateProcThreadAttribute", "callsite": "0x140009e60", "arguments": [
                        _arg(1, "Attribute", "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"),
                    ]},
                    {"api": "CreateProcessW", "callsite": "0x140009ea0", "arguments": [
                        _arg(5, "dwCreationFlags", "0x08000004"),
                    ]},
                ],
                "consumers": ["child_process"],
                "unknowns": ["PPID spoof is not remote injection"],
            },
            module="behavior_attack",
            anchor={"function_entry": "0x140009da0"},
        ),
        _evidence(
            "e-thread",
            "function_semantic_summary",
            {
                "function": "FUN_14000a000",
                "function_entry": "0x14000a000",
                "call_sequence": [
                    {"api": "CreateThread", "callsite": "0x14000a040", "arguments": [
                        _arg(2, "lpStartAddress", "0x14000a100"),
                        _arg(3, "lpParameter", "0x14004d100"),
                    ]},
                ],
                "consumers": ["worker_loop"],
                "unknowns": ["worker loop exit is UNKNOWN"],
            },
            module="behavior_attack",
            anchor={"function_entry": "0x14000a000"},
        ),
    ]
    decode = _evidence(
        "e-decode",
        "decode_result",
        {
            "verification_status": "VERIFIED_STATIC_DATA",
            "formula": "xor_counter_window",
            "decoded_preview": "http://203.0.113.10/stage.bin",
            "decoded_strings": ["http://203.0.113.10/stage.bin"],
            "consumer_status": "LINKED_STATIC",
            "function_entry": "0x140001490",
        },
        module="decryption",
        nature="STATIC_DERIVED",
        anchor={"function_entry": "0x140001490"},
    )
    emu = _evidence(
        "e-emu",
        "simulation_result",
        {
            "status": "DEFERRED_TO_WORKER",
            "simulator": "unicorn",
            "stop_reason": "DEFERRED_TO_WORKER",
            "function_entry": "0x14000a100",
            "limitations": ["isolated emu-worker"],
        },
        nature="STATIC_INFERRED",
        anchor={"function_entry": "0x14000a100"},
    )
    evidence = [pe, *summaries, decode, emu]
    claims = [
        _claim("c-net", module="c2_network", catalog_id="network-transport",
               statement="The sample constructs a WinHTTP request to a recovered host.",
               mechanism="WinHttpOpen -> WinHttpConnect(pswzServerName=203.0.113.10, nServerPort=80) -> WinHttpSendRequest -> WinHttpReadData(dwNumberOfBytesToRead=0x1000)"),
        _claim("c-crypto", module="decryption", catalog_id="config-and-crypto",
               statement="The sample derives an RC4 key and transforms a bounded config window.",
               mechanism="CryptGenKey(Algid=0x6801 (CALG_RC4)) -> CryptEncrypt(pbData=byte_14004c900, pdwDataLen=31)"),
        _claim("c-persist", module="behavior_attack", catalog_id="persistence",
               statement="The sample writes Defender SpyNet values and may create a one-shot task.",
               mechanism="RegSetValueExW(lpValueName=MAPSReporting) and ShellExecuteW(lpFile=schtasks, lpParameters=/create /f /sc once)"),
        _claim("c-proc", module="behavior_attack", catalog_id="parent-process-spoofing",
               statement="The sample may spoof a parent process attribute before CreateProcessW.",
               mechanism="OpenProcess(dwDesiredAccess=0x80) -> UpdateProcThreadAttribute(Attribute=PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) -> CreateProcessW(dwCreationFlags=0x08000004)"),
        _claim("c-thread", module="behavior_attack", catalog_id="thread-and-callback",
               statement="The sample creates an OS thread with a recovered start routine.",
               mechanism="CreateThread(lpStartAddress=0x14000a100, lpParameter=0x14004d100)"),
        _claim("c-guard", module="anti_analysis", catalog_id="environment-guard",
               statement="The sample compares tick-count and memory against constants before continuing.",
               mechanism="GetTickCount64 compared with 0x493e1; GlobalMemoryStatus reads lpBuffer"),
    ]
    links = [
        _ns(claim_id=claim.id, evidence_id=evidence_id, stance="SUPPORTS")
        for claim, evidence_id in (
            (claims[0], "e-net"),
            (claims[1], "e-crypto"),
            (claims[2], "e-persist"),
            (claims[3], "e-proc"),
            (claims[4], "e-thread"),
            (claims[5], "e-anti"),
        )
    ]
    return evidence, claims, links


def _document(evidence, claims, links):
    return build_report_document(
        case=_ns(id="case-gold-bar"),
        task=_ns(
            id="task-gold-bar",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static-only"],
            analysis_class="STATIC_DEEP",
            coverage={"behavior_flow_present": True, "semantic_flow_nodes": 12, "semantic_flow_edges": 8},
        ),
        artifacts=[_ns(
            id="artifact-1",
            logical_path="sample.exe",
            content_sha256="a" * 64,
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
            parent_artifact_id=None,
        )],
        tool_runs=[],
        evidence=evidence,
        claims=claims,
        claim_evidence=links,
        relations=[],
        gates=[],
        model_calls=[],
        selected_modules=["executive_summary", "static_triage", "behavior_attack", "c2_network", "decryption", "anti_analysis"],
    )


def test_rich_recovered_ledger_meets_simulated_gold_bar() -> None:
    evidence, claims, links = _rich_ledger()
    markdown = document_to_markdown(_document(evidence, claims, links))
    result = score_official_markdown(markdown, rich_ledger=True)
    assert result.passed, format_gold_bar(result)
    assert result.score >= GOLD_BAR_PASS_SCORE
    assert "CALG_RC4" in markdown
    assert "0x14000a100" in markdown
    assert "DEFERRED_TO_WORKER" in markdown
    assert "Module deep-dives (static reconstruction)" in markdown


def test_thin_ledger_stays_honest_and_still_projects_pe_and_emu() -> None:
    pe = _evidence(
        "e-pe",
        "pe_structure",
        {"format": "PE32", "machine": "0x14c", "entry_rva": 0x1000, "image_base": 0x400000, "imports": []},
        nature="STATIC_OBSERVED",
    )
    markdown = document_to_markdown(_document([pe], [], []))
    result = score_official_markdown(markdown, rich_ledger=False)
    assert "PE basics (static header)" in markdown
    assert "Controlled emulation (isolated worker" in markdown
    assert "NOT_ATTEMPTED" in markdown
    assert "CALG_RC4" not in markdown
    assert "DYNAMIC_OBSERVED" not in markdown
    assert result.checks  # scorer still runs


def test_decode_and_loader_queues_include_decompile_and_emulate() -> None:
    decode_rows = [
        {
            "id": "ctx-decode",
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "decode_config", "entry": "0x402000", "call_targets": [{"target_name": "CryptDecrypt"}]},
            "anchor": {"function_entry": "0x402000"},
        },
        {
            "id": "decode-window",
            "kind": "mechanism_decode_window",
            "nature": "STATIC_DERIVED",
            "value": {"function_entry": "0x402000", "transformation": "xor"},
            "anchor": {"function_entry": "0x402000"},
        },
    ]
    types = {item.action_type for item in DeepMiningPlanner.plan_actions(decode_rows, scheduled=set(), max_actions=24)}
    assert ActionType.GET_DECOMPILE in types
    assert ActionType.CONTROLLED_EMULATE in types


def test_session_action_dialect_is_accepted(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "Gold bar dialect"}).json()
        submitted = client.post(
            f"/api/v1/cases/{case['id']}/tasks",
            files={"sample": ("sample.py", b"print('static')\n", "text/x-python")},
        )
        assert submitted.status_code == 202, submitted.text
        task_id = submitted.json()["task_id"]
        task_view = client.get(f"/api/v1/workbench/tasks/{task_id}").json()
        task_detail = client.get(f"/api/v1/tasks/{task_id}").json()
        artifact_id = task_view["artifacts"][0]["id"]
        hypothesis_id = task_view["threads"][0]["hypothesis_ids"][0]
        evidence_id = next(item["id"] for item in task_detail["evidence"] if item["artifact_id"] == artifact_id)
        linked = client.post(
            f"/api/v1/workbench/tasks/{task_id}/session",
            json={"dsh_session_id": "gold-bar-dialect", "profile": "threat-static"},
        )
        assert linked.status_code == 201, linked.text
        response = client.post(
            "/api/v1/workbench/sessions/gold-bar-dialect/analysis/actions",
            json={
                "action_type": "READ_BYTES",
                "target_artifact_id": artifact_id,
                "hypothesis_id": hypothesis_id,
                "reason": "Read a bounded encoded window.",
                "question": "What bytes sit at the selected window?",
                "hypothesis": "The window may be a decode input.",
                "alternatives": ["The window is padding."],
                "missing_evidence": ["bytes_read"],
                "failure_meaning": "The window remains unread.",
                "success_condition": "x" * 180,
                "evidence_ids": [evidence_id],
                "target_selector": {"function_name": "FUN_180001000", "length": 64, "mystery": "drop"},
                "expected_evidence_kinds": ["bytes_read"],
                "origin": "model",
                "planner_turn_id": "gold-bar-dialect-1",
            },
        )
        assert response.status_code == 202, submitted.text if False else response.text
        body = client.get(f"/api/v1/workbench/actions/{response.json()['id']}").json()
        assert body["target_selector"]["function"] == "FUN_180001000"
        assert body["target_selector"]["length"] == 64
        assert "function_name" not in body["target_selector"]
        assert len(body["success_condition"]) <= 160


def _call(from_addr: str, api: str, to_addr: str = "0x140070000") -> dict[str, object]:
    return {
        "from": from_addr,
        "to": to_addr,
        "type": "UNCONDITIONAL_CALL",
        "target_name": api,
        "target_function": api,
    }


def _insn(address: str, text: str) -> dict[str, object]:
    mnemonic = text.split()[0]
    return {"address": address, "mnemonic": mnemonic, "text": text}


def _ghidra_function(
    *,
    function_id: str,
    name: str,
    entry: str,
    calls: list[tuple[str, str]],
    instructions: list[dict[str, object]],
) -> list[SimpleNamespace]:
    """Persist the Ghidra split model: context without instructions, plus a window."""
    rva = int(entry, 16) & 0xFFFF
    call_targets = [_call(from_addr, api) for from_addr, api in calls]
    context = _evidence(
        f"{function_id}-ctx",
        "function_context",
        {
            "name": name,
            "entry": entry,
            "entry_rva": rva,
            "architecture": "x86-64",
            "instruction_count": len(instructions),
            "call_targets": call_targets,
        },
        nature="STATIC_OBSERVED",
        anchor={"type": "function_context", "entry": entry, "rva": rva},
    )
    window = _evidence(
        f"{function_id}-win",
        "function_instruction_window",
        {
            "name": name,
            "entry": entry,
            "entry_rva": rva,
            "instructions": instructions,
        },
        nature="STATIC_OBSERVED",
        anchor={"type": "instruction_window", "entry": entry, "rva": rva},
    )
    return [context, window]


def _ghidra_shaped_static_rows() -> list[SimpleNamespace]:
    pe = _evidence(
        "e-pe",
        "pe_structure",
        {
            "format": "PE32+",
            "machine": "0x8664",
            "entry_rva": 0x1420,
            "image_base": 0x140000000,
            "subsystem": 3,
            "sections": [{"name": ".text"}, {"name": ".rdata"}, {"name": ".data"}],
            "imports": [
                {"dll": "kernel32", "functions": [
                    "CreateThread", "CreateProcessW", "CreateToolhelp32Snapshot",
                    "OpenProcess", "LoadLibraryW", "GetProcAddress", "Sleep",
                    "GetTickCount64", "GlobalMemoryStatus", "VirtualProtect",
                ]},
                {"dll": "winhttp", "functions": [
                    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
                    "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
                ]},
                {"dll": "advapi32", "functions": [
                    "CryptGenKey", "CryptEncrypt", "RegSetValueExW", "RegOpenKeyExW",
                ]},
            ],
        },
        nature="STATIC_OBSERVED",
    )
    functions = [
        *_ghidra_function(
            function_id="anti",
            name="FUN_140009ccb",
            entry="0x140009ccb",
            calls=[("0x140009d18", "GetTickCount64"), ("0x140009d48", "GlobalMemoryStatus")],
            instructions=[
                _insn("0x140009d10", "CALL GetTickCount64"),
                _insn("0x140009d14", "CMP RAX, 0x493e1"),
                _insn("0x140009d18", "CALL qword ptr [GetTickCount64]"),
                _insn("0x140009d40", "LEA RCX, [0x14004d000]"),
                _insn("0x140009d48", "CALL qword ptr [GlobalMemoryStatus]"),
            ],
        ),
        *_ghidra_function(
            function_id="net",
            name="FUN_140031f00",
            entry="0x140031f00",
            calls=[
                ("0x140031f18", "WinHttpOpen"),
                ("0x140031f48", "WinHttpConnect"),
                ("0x140031f88", "WinHttpSendRequest"),
                ("0x140031fc8", "WinHttpReadData"),
            ],
            instructions=[
                _insn("0x140031f10", "LEA RCX, [\"Mozilla/5.0\"]"),
                _insn("0x140031f18", "CALL qword ptr [WinHttpOpen]"),
                _insn("0x140031f40", "LEA RDX, [\"203.0.113.10\"]"),
                _insn("0x140031f44", "MOV R8, 80"),
                _insn("0x140031f48", "CALL qword ptr [WinHttpConnect]"),
                _insn("0x140031f80", "LEA RDX, [\"Cache-Control: no-cache\"]"),
                _insn("0x140031f88", "CALL qword ptr [WinHttpSendRequest]"),
                _insn("0x140031fc0", "MOV R8, 0x1000"),
                _insn("0x140031fc8", "CALL qword ptr [WinHttpReadData]"),
            ],
        ),
        *_ghidra_function(
            function_id="crypto",
            name="FUN_140001490",
            entry="0x140001490",
            calls=[("0x1400014a8", "CryptGenKey"), ("0x1400014c8", "CryptEncrypt")],
            instructions=[
                _insn("0x1400014a0", "MOV EDX, 0x6801"),
                _insn("0x1400014a8", "CALL qword ptr [CryptGenKey]"),
                _insn("0x1400014c0", "LEA R8, [byte_14004c900]"),
                _insn("0x1400014c4", "MOV R9, 31"),
                _insn("0x1400014c8", "CALL qword ptr [CryptEncrypt]"),
            ],
        ),
        *_ghidra_function(
            function_id="persist",
            name="FUN_140004605",
            entry="0x140004605",
            calls=[("0x140004628", "RegOpenKeyExW"), ("0x140004658", "RegSetValueExW")],
            instructions=[
                _insn("0x140004620", "LEA RDX, [\"SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\SpyNet\"]"),
                _insn("0x140004628", "CALL qword ptr [RegOpenKeyExW]"),
                _insn("0x140004650", "LEA RDX, [\"MAPSReporting\"]"),
                _insn("0x140004658", "CALL qword ptr [RegSetValueExW]"),
            ],
        ),
        *_ghidra_function(
            function_id="proc",
            name="FUN_140009da0",
            entry="0x140009da0",
            calls=[
                ("0x140009e28", "OpenProcess"),
                ("0x140009e68", "UpdateProcThreadAttribute"),
                ("0x140009ea8", "CreateProcessW"),
            ],
            instructions=[
                _insn("0x140009e20", "MOV ECX, 0x80"),
                _insn("0x140009e28", "CALL qword ptr [OpenProcess]"),
                _insn("0x140009e60", "MOV EDX, 0x00020000"),
                _insn("0x140009e68", "CALL qword ptr [UpdateProcThreadAttribute]"),
                _insn("0x140009ea0", "MOV ECX, 0x08000004"),
                _insn("0x140009ea8", "CALL qword ptr [CreateProcessW]"),
            ],
        ),
        *_ghidra_function(
            function_id="thread",
            name="FUN_14000a000",
            entry="0x14000a000",
            calls=[("0x14000a048", "CreateThread")],
            instructions=[
                _insn("0x14000a040", "MOV R8, 0x14000a100"),
                _insn("0x14000a044", "MOV R9, 0x14004d100"),
                _insn("0x14000a048", "CALL qword ptr [CreateThread]"),
            ],
        ),
        *_ghidra_function(
            function_id="protect",
            name="FUN_14000b000",
            entry="0x14000b000",
            calls=[("0x14000b018", "VirtualProtect")],
            instructions=[
                _insn("0x14000b010", "MOV R8D, 0x40"),
                _insn("0x14000b018", "CALL qword ptr [VirtualProtect]"),
            ],
        ),
    ]
    return [pe, *functions]


def _observations_to_evidence(observations: list[dict[str, object]]) -> list[SimpleNamespace]:
    rows: list[SimpleNamespace] = []
    for index, item in enumerate(observations):
        kind = str(item.get("kind") or "")
        if kind not in {
            "function_semantic_summary",
            "decompile_slice",
            "simulation_result",
            "api_argument_trace",
            "abstract_execution_trace",
        }:
            continue
        rows.append(
            _ns(
                id=f"obs-{index}-{kind}",
                artifact_id="artifact-1",
                tool_run_id="tool-1",
                module="investigation",
                kind=kind,
                nature=item.get("nature") or "STATIC_INFERRED",
                value=item.get("value") or {},
                anchor=item.get("anchor") or {},
            )
        )
    return rows


def test_ghidra_shaped_pipeline_meets_simulated_gold_bar(test_settings) -> None:
    """Official markdown must reach ≥90 from Ghidra-shaped rows, not a hand-built ledger."""
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.investigation import ActionSpec
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "qiling"),
        simulation_allow_local_process=False,
    )
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    static_rows = _ghidra_shaped_static_rows()
    observations: list[dict[str, object]] = []
    for entry in (
        "0x140009ccb",
        "0x140031f00",
        "0x140001490",
        "0x140004605",
        "0x140009da0",
        "0x14000a000",
        "0x14000b000",
    ):
        observations.extend(
            service._derive_investigation_observations(
                static_rows,
                ActionSpec(
                    id=f"decompile-{entry}",
                    action_type=ActionType.GET_DECOMPILE,
                    thread_id="thread-1",
                    hypothesis_id="hypothesis-1",
                    artifact_id="artifact-1",
                    target_selector={"function_entry": entry},
                ),
                artifact_content=b"MZ" + b"\x00" * 64,
                pe_summary={"image_base": 0x140000000, "entry_rva": 0x1420},
            )
        )
    observations.extend(
        service._derive_investigation_observations(
            static_rows,
            ActionSpec(
                id="emu-start",
                action_type=ActionType.CONTROLLED_EMULATE,
                thread_id="thread-1",
                hypothesis_id="hypothesis-1",
                artifact_id="artifact-1",
                target_selector={"function_entry": "0x14000a100"},
            ),
            artifact_content=b"MZ" + b"\x00" * 64,
            pe_summary={"image_base": 0x140000000},
        )
    )
    evidence = [*static_rows, *_observations_to_evidence(observations)]
    markdown = document_to_markdown(_document(evidence, [], []))
    result = score_official_markdown(markdown, rich_ledger=True)
    assert result.passed, format_gold_bar(result) + "\n\n--- markdown head ---\n" + markdown[:4000]
    assert result.score >= GOLD_BAR_PASS_SCORE
    assert "CALG_RC4" in markdown
    assert "0x14000a100" in markdown
    assert "DEFERRED_TO_WORKER" in markdown or "UNSUPPORTED" in markdown
    assert "CryptEncrypt(hHash=0x6801" not in markdown
    assert "What: no evidence-backed behavior was closed" not in markdown


def _strip_decoded_constants(markdown: str) -> str:
    text = markdown
    for token in (
        "CALG_RC4",
        "CALG_AES",
        "PAGE_EXECUTE_READWRITE",
        "CREATE_SUSPENDED",
        "STILL_ACTIVE",
        "EXTENDED_STARTUPINFO_PRESENT",
    ):
        text = text.replace(token, "UNDECODED_FLAG")
    return text


def test_benign_t5_bar_allows_decoded_constants_miss_without_weakening_scorer() -> None:
    evidence, claims, links = _rich_ledger()
    markdown = _strip_decoded_constants(document_to_markdown(_document(evidence, claims, links)))
    gold = score_official_markdown(markdown, rich_ledger=True)
    assert not gold.passed
    assert [item.check_id for item in gold.blocking_failures] == ["decoded_constants"]
    assert gold.score >= GOLD_BAR_PASS_SCORE
    malware = evaluate_t5_sample_bar(markdown, sample_kind="malware")
    assert malware.accepted is False
    assert malware.policy == "strict"
    benign = evaluate_t5_sample_bar(markdown, sample_kind="benign")
    assert benign.gold.passed is False
    assert benign.accepted is True
    assert benign.policy == "benign_unresolved_constants"


def test_benign_t5_bar_rejects_false_malicious_claim() -> None:
    evidence, claims, links = _rich_ledger()
    markdown = (
        document_to_markdown(_document(evidence, claims, links))
        + "\nseverity: HIGH. verdict: malicious. confirmed C2.\n"
    )
    gold = score_official_markdown(markdown, rich_ledger=True)
    assert gold.passed, format_gold_bar(gold)
    decision = evaluate_t5_sample_bar(markdown, sample_kind="benign")
    assert decision.gold.passed is True
    assert decision.accepted is False
    assert "false-malicious" in decision.reason


def test_thin_v3_summary_fails_rich_gold_bar() -> None:
    markdown = (
        "# 威胁分析报告\n\n## 1. Executive Summary\n"
        "样本具有网络与执行相关导入，未形成机制级 HOW。\n"
    )
    result = score_official_markdown(markdown, rich_ledger=True)
    assert not result.passed
    assert result.blocking_failures


def test_docker_controlled_emulate_persists_visible_simulation_result(test_settings) -> None:
    from threat_report_agent.database import Database
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.investigation import ActionSpec
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "qiling"),
        simulation_allow_local_process=False,
    )
    service = AnalysisService(settings, Database(settings.database_url), LocalContentStore(settings.content_store_path))
    rows = [
        SimpleNamespace(
            id="ctx-start",
            artifact_id="artifact-1",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={"name": "spawn_worker", "entry": "0x401000", "call_targets": [{"target_name": "CreateThread"}]},
            anchor={"function_entry": "0x401000"},
        )
    ]
    action = ActionSpec(
        id="emu-1",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x401000"},
    )
    observations = service._derive_investigation_observations(
        rows,
        action,
        artifact_content=b"MZ" + b"\x00" * 64,
        pe_summary={"image_base": 0x400000},
    )
    sim = [item for item in observations if item["kind"] == "simulation_result"]
    statuses = {str((item.get("value") or {}).get("status")) for item in sim}
    assert "DEFERRED_TO_WORKER" in statuses or "UNSUPPORTED" in statuses
