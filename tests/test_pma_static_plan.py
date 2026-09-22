from __future__ import annotations

from threat_report_agent.investigation import (
    ActionType,
    DeepMiningPlanner,
    Investigator,
    verify_mechanism,
)
from threat_report_agent.pma_static_plan import (
    PAYLOAD_BEHAVIOR_CATEGORIES,
    build_pma_static_plan,
    packer_latch_active,
    static_analysis_plan_snapshot,
)


def _packed_stub_facts() -> list[dict[str, object]]:
    return [
        {
            "id": "id-hash",
            "kind": "file_identity",
            "nature": "STATIC_OBSERVED",
            "value": {
                "md5": "0123456789abcdef0123456789abcdef",
                "sha1": "0123456789abcdef0123456789abcdef01234567",
                "sha256": "ab" * 32,
            },
            "anchor": {"type": "file"},
        },
        {
            "id": "pe-packed",
            "kind": "pe_structure",
            "nature": "STATIC_OBSERVED",
            "value": {
                "entry_rva": 0x1000,
                "imports": [
                    {
                        "module": "KERNEL32.dll",
                        "functions": [
                            "LoadLibraryA",
                            "GetProcAddress",
                            "VirtualAlloc",
                            "VirtualProtect",
                        ],
                    }
                ],
                "sections": [
                    {
                        "name": "UPX0",
                        "virtual_size": 0x20000,
                        "raw_size": 0,
                        "virtual_address": 0x1000,
                        "raw_offset": 0,
                    },
                    {
                        "name": "UPX1",
                        "virtual_size": 0x4000,
                        "raw_size": 0x4000,
                        "virtual_address": 0x21000,
                        "raw_offset": 0x200,
                    },
                ],
            },
            "anchor": {"type": "file_offset", "offset": 0x80},
        },
        {
            "id": "imp-ll",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "LoadLibraryA", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "imp-gpa",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "GetProcAddress", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "imp-va",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "VirtualAlloc", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "imp-vp",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "VirtualProtect", "library": "KERNEL32.dll"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "str-few",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "GetProcAddress", "encoding": "ascii"},
            "anchor": {"type": "file_offset", "offset": 12},
        },
    ]


def test_packed_iat_plans_unpack_and_does_not_seed_payload_behavior() -> None:
    facts = _packed_stub_facts()
    assert packer_latch_active(facts) is True

    plan = build_pma_static_plan(facts)
    assert any(item.investigation_category == "unpack" for item in plan)
    unpack = next(item for item in plan if item.investigation_category == "unpack")
    assert unpack.forbids_stub_iat_payload is True
    assert "CONTROLLED_EMULATE" in unpack.next_static_actions
    assert "GET_DECOMPILE" in unpack.next_static_actions
    assert not any(item.investigation_category in {"windows_object", "covert_launch"} for item in plan)

    frontier = DeepMiningPlanner.build_frontier(facts, max_targets=32)
    categories = {item.category for item in frontier}
    assert "unpack" in categories
    assert not (categories & PAYLOAD_BEHAVIOR_CATEGORIES)

    planned = DeepMiningPlanner.plan_actions(facts, scheduled=set(), max_actions=16)
    targets = {str(item.parameters.get("target") or "") for item in planned}
    assert "LoadLibraryA" not in targets
    assert "GetProcAddress" not in targets
    assert "VirtualAlloc" not in targets
    assert any(
        item.action_type in {ActionType.GET_DECOMPILE, ActionType.CONTROLLED_EMULATE}
        and str(item.plan.get("deep_investigation_contract", {}).get("category") or item.plan.get("category") or "")
        == "unpack"
        or str(item.parameters.get("target") or "") == "0x1000"
        for item in planned
    )

    suggestions = Investigator().propose(evidence=facts, scheduled=set())
    propose_targets = {str(item.parameters.get("target") or "") for item in suggestions}
    assert "LoadLibraryA" not in propose_targets
    assert "GetProcAddress" not in propose_targets


def test_packed_snapshot_is_unknown_unpack_not_payload_how() -> None:
    snapshot = static_analysis_plan_snapshot(_packed_stub_facts())
    assert snapshot["schema_version"] == "1"
    assert snapshot["packer_latch"] is True
    by_id = {item["id"]: item for item in snapshot["items"]}
    unpack = by_id["pma-packer-latch-unpack"]
    assert unpack["status"] == "UNKNOWN"
    assert unpack["packer_latch"] is True
    assert unpack["kind"] == "unpack"
    assert unpack["next_method"] in {"GET_DECOMPILE", "CONTROLLED_EMULATE"}
    assert "OEP after unpack" in unpack["unknowns"]
    assert by_id["pma-hash-fingerprint"]["status"] == "COMPLETED"
    assert "pma-iat-hypotheses" not in by_id
    assert "pma-windows-object-graph" not in by_id
    assert "pma-covert-launch" not in by_id


def test_unpacked_payload_completes_unpack_and_plans_reconstructed_iat() -> None:
    facts = [
        *_packed_stub_facts(),
        {
            "id": "unpacked",
            "kind": "unpacked_payload",
            "nature": "EMULATION_OBSERVED",
            "value": {
                "child_artifact_id": "child-1",
                "oep": "0x401000",
                "reconstructed_iat": ["CreateProcessW", "WinHttpOpen", "WinHttpConnect"],
                "child_detected_type": "pe",
                "source": "controlled_emulation",
            },
            "anchor": {"type": "unpacked_payload"},
        },
    ]
    from threat_report_agent.pma_static_plan import unpack_completed

    assert unpack_completed(facts) is True
    snapshot = static_analysis_plan_snapshot(facts)
    unpack = next(item for item in snapshot["items"] if item["kind"] == "unpack")
    assert unpack["status"] == "COMPLETED"
    assert unpack["unknowns"] == []
    assert any(item["kind"] == "iat" for item in snapshot["items"])
    assert any(item["kind"] == "covert_launch" for item in snapshot["items"])
    planned = DeepMiningPlanner.plan_actions(facts, scheduled=set(), max_actions=16)
    targets = {str(item.parameters.get("target") or "") for item in planned}
    assert "LoadLibraryA" not in targets


def test_createprocess_without_flags_fails_process_execution_verifier() -> None:
    evidence = [
        {
            "id": "call",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    result = verify_mechanism("PROCESS_EXECUTION", evidence)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert result.missing == ("creation_flags",)


def test_createprocess_ffffffff_and_api_listing_cannot_pass() -> None:
    listing = [
        {
            "id": "imp",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateProcessW"},
            "anchor": {"type": "pe_import"},
        },
        {
            "id": "txt",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "CreateProcessW explorer.exe CREATE_SUSPENDED"},
            "anchor": {"function_entry": "0x401000"},
        },
    ]
    listed = verify_mechanism("PROCESS_EXECUTION", listing)
    assert listed.accepted is False
    assert listed.status == "NOT_APPLICABLE"

    soup = [
        {
            "id": "call",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW", "creation_flags": 0xFFFFFFFF},
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    invalid = verify_mechanism("PROCESS_EXECUTION", soup)
    assert invalid.accepted is False
    assert "creation_flags" in invalid.missing


def test_createprocess_call_and_flags_verified_without_decode_join() -> None:
    """C3 Join is a separate slot; process VERIFIED is still call + flags.

    G3 §7.2: the flag word must be a credible dwCreationFlags immediate. The
    previous example here was ``0x000F4240`` (1,000,000 ms, a WaitForSingleObject
    timeout); that value can no longer close the process HOW and is covered by
    ``test_timeout_immediate_cannot_close_process_execution_how``.
    """
    evidence = [
        {
            "id": "call",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateProcessW",
                "creation_flags": 0x00080000,
                "command": "FoxitPDFReader.exe",
            },
            "anchor": {"function_entry": "0x401000"},
        },
        {
            "id": "decode",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "plaintext": "FoxitPDFReader.exe",
                "decoded_text": "FoxitPDFReader.exe",
            },
            "anchor": {"function_entry": "0x401000"},
        },
    ]
    result = verify_mechanism("PROCESS_EXECUTION", evidence)
    assert result.accepted is True
    assert result.status == "VERIFIED"
    assert result.missing == ()
    names = [str(item["name"]) for item in result.checks]
    assert names == ["CreateProcess call", "creation_flags"]


def test_timeout_immediate_cannot_close_process_execution_how() -> None:
    """G3 §7.2：0x000f4240 是超时常量，不是 dwCreationFlags，不得让进程 HOW 过门。

    它的 bit19 与 EXTENDED_STARTUPINFO_PRESENT 撞位，粗粒度 plausibility 会放行；
    可信度门必须拦下，调用方应保持 UNKNOWN(creation_flags)。
    """
    evidence = [
        {
            "id": "call",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateProcessW",
                "creation_flags": 0x000F4240,
                "command": "FoxitPDFReader.exe",
            },
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    result = verify_mechanism("PROCESS_EXECUTION", evidence)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert result.missing == ("creation_flags",)


def test_createthread_with_start_rva_accepts_thread_callback() -> None:
    evidence = [
        {
            "id": "trace-createthread",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateThread",
                "function_entry": "0x401000",
                "arguments": [
                    {"index": 0, "register": "RCX", "value": "0x0", "resolved": True},
                    {"index": 1, "register": "RDX", "value": "0x0", "resolved": True},
                    {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    {"index": 3, "register": "R9", "value": "0x40a000", "resolved": True},
                ],
            },
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    result = verify_mechanism("THREAD_CALLBACK", evidence)
    assert result.accepted is True
    assert result.status == "VERIFIED"
    assert not result.missing


def test_createthread_api_listing_missing_start_routine() -> None:
    evidence = [
        {
            "id": "imp-thread",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "CreateThread"},
            "anchor": {"type": "pe_import"},
        }
    ]
    result = verify_mechanism("THREAD_CALLBACK", evidence)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert result.missing == ("start_routine",)


def test_createthread_call_without_start_routine_is_unknown() -> None:
    evidence = [
        {
            "id": "call-thread",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateThread"},
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    result = verify_mechanism("THREAD_CALLBACK", evidence)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert result.missing == ("start_routine",)
    assert "missing start_routine" in result.reason


def test_environment_api_without_threshold_is_unknown_guard() -> None:
    """Import or a probe call without a recovered comparison cannot verify anti-analysis."""
    import_only = [
        {
            "id": "imp-tick",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "GetTickCount"},
            "anchor": {"type": "pe_import"},
        }
    ]
    call_only = [
        {
            "id": "call-dbg",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "IsDebuggerPresent"},
            "anchor": {"function_entry": "0x401000"},
        }
    ]
    for evidence in (import_only, call_only):
        result = verify_mechanism("ENVIRONMENT_GUARD", evidence)
        assert result.accepted is False
        assert result.status == "UNKNOWN"
        missing = " ".join(result.missing).casefold()
        assert "threshold" in missing or "comparison" in missing
        assert "specialized_verifier_not_available" not in missing


def test_gettickcount64_threshold_and_exit_may_verify_environment_guard() -> None:
    """VERIFIED only when probe, threshold, fail/exit branch, and gated behavior are all typed."""
    incomplete = [
        {
            "id": "call-tick",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "GetTickCount64"},
            "anchor": {"function_entry": "0x140009ccb"},
        },
        {
            "id": "const-tick",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "threshold", "threshold": "0x493e1"},
            "anchor": {"function_entry": "0x140009ccb"},
        },
    ]
    incomplete_result = verify_mechanism("ENVIRONMENT_GUARD", incomplete)
    assert incomplete_result.accepted is False
    assert incomplete_result.status == "UNKNOWN"
    missing = " ".join(incomplete_result.missing).casefold()
    assert "branch" in missing or "gated" in missing

    complete = [
        *incomplete,
        {
            "id": "cfg-exit",
            "kind": "cfg_block",
            "nature": "STATIC_OBSERVED",
            "value": {
                "return_branch": "fail",
                "gated_behavior": "exit",
                "exit": "ExitProcess",
            },
            "anchor": {"function_entry": "0x140009ccb"},
        },
    ]
    result = verify_mechanism("ENVIRONMENT_GUARD", complete)
    assert result.accepted is True
    assert result.status == "VERIFIED"
    assert result.missing == ()
    names = [str(item["name"]) for item in result.checks]
    assert names == ["probe", "threshold", "branch", "gated behavior"]


def test_sleep_is_not_an_environment_guard() -> None:
    """Sleep delay is not an anti-sandbox probe or threshold."""
    evidence = [
        {
            "id": "call-sleep",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "Sleep", "timeout": 1000, "dwMilliseconds": 1000},
            "anchor": {"function_entry": "0x401000"},
        },
        {
            "id": "const-sleep",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "timeout", "value": 1000},
            "anchor": {"function_entry": "0x401000"},
        },
    ]
    result = verify_mechanism("ENVIRONMENT_GUARD", evidence)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert "probe" in result.missing
    assert "threshold" in result.missing
