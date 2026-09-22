from threat_report_agent.static_analysis import (
    analyze_xor_decode_window,
    build_cross_function_chains,
    build_function_semantic_summary,
    build_pcode_slice,
    classify_pe_semantics,
    resolve_export_hashes,
    track_indirect_function_pointers,
    trace_static_api_arguments,
)


def test_semantic_summary_rejects_pointer_and_navigation_labels_from_call_targets() -> None:
    function = {
        "name": "FUN_transport",
        "entry": "0x401000",
        "call_targets": [
            {"from": "0x401002", "to": "0x5000", "target_name": "PTR_CreatePipe_5000"},
            {"from": "0x401004", "to": "0x401010", "target_name": "LAB_401010"},
            {"from": "0x401006", "to": "0x6000", "target_name": "DAT_6000"},
            {"from": "0x401020", "to": "EXTERNAL:1", "target_name": "CreatePipe"},
        ],
        "references_from": [
            {"from": "0x401020", "target_name": "CreatePipe", "type": "COMPUTED_CALL"},
        ],
        "instructions": [
            {"address": "0x401000", "text": "PUSH R15"},
            {"address": "0x401010", "text": "MOV RCX,0x20"},
            {"address": "0x401020", "text": "CALL CreatePipe"},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert [item["api"] for item in summary["call_sequence"]] == ["CreatePipe"]
    assert summary["recovered_argument_count"] >= 1
    assert summary["inputs"][0]["value"] == "0x20"


def test_argument_trace_does_not_treat_x64_register_save_pushes_as_arguments() -> None:
    function = {
        "name": "FUN_x64",
        "instructions": [
            {"address": "0x1000", "text": "PUSH R15"},
            {"address": "0x1001", "text": "PUSH RBX"},
            {"address": "0x1010", "text": "MOV RCX,0x40"},
            {"address": "0x1014", "text": "CALL CreateFileA"},
        ],
        "references_from": [
            {"from": "0x1014", "target_name": "CreateFileA", "type": "COMPUTED_CALL"},
        ],
    }

    args = trace_static_api_arguments(function, "CreateFileA")

    assert args[0]["source_kind"] == "constant"
    assert args[0]["value"] == "0x40"
    assert args[0]["source_instruction"] == "MOV RCX,0x40"


def test_argument_trace_deduplicates_context_and_function_call_rows() -> None:
    function = {
        "name": "FUN_duplicate_projection",
        "instructions": [
            {"address": "0x1000", "text": "MOV RCX,0x2"},
            {"address": "0x1004", "text": "CALL CreatePipe"},
        ],
        "references_from": [
            {"from": "0x1004", "target_name": "CreatePipe", "type": "CALL"},
            {"from": "0x1004", "target_name": "CreatePipe", "type": "COMPUTED_CALL"},
        ],
    }

    rows = trace_static_api_arguments(function, "CreatePipe")

    assert len(rows) == 4
    assert [row["argument_index"] for row in rows] == [0, 1, 2, 3]


def test_semantic_summary_collapses_qualified_api_aliases_at_one_callsite() -> None:
    """Import-qualified and unqualified rows describe one machine call."""
    function = {
        "name": "FUN_aliases",
        "entry": "0x401000",
        "instructions": [{"address": "0x401020", "text": "CALL VirtualQuery"}],
        "references_from": [
            {"from": "0x401020", "target_name": "KERNEL32!VirtualQuery", "type": "CALL"},
            {"from": "0x401020", "target_name": "VirtualQuery", "type": "COMPUTED_CALL"},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert len(summary["call_sequence"]) == 1
    assert summary["call_sequence"][0]["callsite"] == "0x401020"


def test_semantic_summary_keeps_late_high_signal_calls_in_long_functions() -> None:
    """A long helper must not hide its security-relevant tail behind a cap."""
    calls = [
        {
            "from": hex(0x401000 + index * 4),
            "to": "0x5000",
            "target_name": "FUN_helper",
            "type": "UNCONDITIONAL_CALL",
        }
        for index in range(80)
    ]
    calls.extend(
        [
            {
                "from": "0x401200",
                "to": "0x6000",
                "target_name": "VirtualProtect",
                "type": "COMPUTED_CALL",
            },
            {
                "from": "0x401210",
                "to": "0x6010",
                "target_name": "FlushInstructionCache",
                "type": "COMPUTED_CALL",
            },
        ]
    )
    function = {
        "name": "FUN_long_helper",
        "entry": "0x401000",
        "references_from": calls,
        "instructions": [
            {"address": row["from"], "text": f"CALL {row['target_name']}"}
            for row in calls
        ],
    }

    summary = build_function_semantic_summary(function, max_calls=48)
    apis = [item["api"] for item in summary["call_sequence"]]

    assert "VirtualProtect" in apis
    assert "FlushInstructionCache" in apis
    assert summary["call_sequence"] == sorted(
        summary["call_sequence"], key=lambda item: int(item["callsite"], 16)
    )


def test_straight_line_xor_sequence_is_not_a_decoder() -> None:
    rows = [{"mnemonic": "XOR", "text": "XOR EAX,EDX"} for _ in range(8)]
    assert analyze_xor_decode_window(rows) is None


def test_import_resolver_requires_iat_evidence_and_mapper_requires_transfer() -> None:
    importer = classify_pe_semantics(
        {
            "name": "imports",
            "instructions": [
                {"text": "MOV RAX,[FirstThunk]"},
                {"text": "MOV RCX,[Import Directory]"},
                {"text": "CALL GetProcAddress"},
            ],
            "references_from": [],
        }
    )
    assert importer[0]["role"] == "IMPORT_RESOLVER"
    validator = classify_pe_semantics(
        {
            "name": "validator",
            "instructions": [
                {"text": "MOV EAX,[PE Header]"},
                {"text": "VirtualAlloc"},
                {"text": "VirtualProtect"},
            ],
            "references_from": [],
        }
    )
    assert all(item["role"] != "MANUAL_MAPPER" for item in validator)


def test_forwarded_export_match_preserves_target_metadata() -> None:
    digest = 5381
    for byte in b"Sleep":
        digest = (digest * 33 + byte) & 0xFFFFFFFF
    rows = resolve_export_hashes(
        [digest],
        [{"name": "Sleep", "rva": 0x1000, "forwarder": "KERNELBASE.Sleep"}],
        algorithms=("DJB2",),
    )
    match = rows[0]["matches"][0]
    assert match["forwarded"] is True
    assert match["forwarded_module"] == "KERNELBASE"


def test_indirect_pointer_and_global_dispatch_path_is_explicit() -> None:
    links = track_indirect_function_pointers(
        {
            "name": "resolver",
            "instructions": [
                {"address": "0x100", "text": "CALL GetProcAddress"},
                {"address": "0x105", "text": "MOV [g_api],RAX"},
                {"address": "0x110", "text": "CALL [g_api]"},
            ],
            "references_from": [{"from": "0x100", "target_name": "GetProcAddress", "type": "CALL"}],
        }
    )
    assert links and links[0]["storage"] == "g_api"
    chains = build_cross_function_chains(
        [
            {
                "name": "resolver",
                "references_from": [
                    {"target_name": "GetProcAddress", "type": "CALL"},
                    {"resolved_target": "consumer", "type": "INDIRECT_CALL"},
                ],
            },
            {"name": "consumer", "references_from": [{"target_name": "CreateProcessW", "type": "CALL"}]},
        ]
    )
    assert chains and chains[0]["edge_provenance"][0]["kind"] == "indirect_or_global_dispatch"


def test_x86_arguments_and_pcode_slice_are_semantic() -> None:
    function = {
        "name": "x86_call",
        "architecture": "x86",
        "instructions": [
            {"address": "0x10", "text": "PUSH [global_host]"},
            {"address": "0x11", "text": "PUSH 0x2"},
            {"address": "0x12", "text": "CALL WinHttpConnect"},
            {"address": "0x13", "text": "CMP EAX,0"},
        ],
        "references_from": [{"from": "0x12", "target_name": "WinHttpConnect", "type": "CALL"}],
    }
    args = trace_static_api_arguments(function, "WinHttpConnect")
    assert args[0]["source_kind"] == "constant"
    assert args[1]["source_kind"] == "global"
    pcode = build_pcode_slice(function, source_evidence_ids=("e1",))
    assert pcode["conditions"] and pcode["sinks"]
    assert pcode["source"]["source_evidence_ids"] == ["e1"]


def test_argument_trace_resets_registers_after_prior_call() -> None:
    """A later API must not inherit immediates consumed by an earlier CALL."""
    function = {
        "name": "FUN_crypto",
        "architecture": "x86-64",
        "instructions": [
            {"address": "0x1400014a0", "text": "MOV EDX, 0x6801"},
            {"address": "0x1400014a8", "text": "CALL qword ptr [CryptGenKey]"},
            {"address": "0x1400014c0", "text": "LEA R8, [byte_14004c900]"},
            {"address": "0x1400014c8", "text": "CALL qword ptr [CryptEncrypt]"},
        ],
        "references_from": [
            {"from": "0x1400014a8", "target_name": "CryptGenKey", "type": "UNCONDITIONAL_CALL"},
            {"from": "0x1400014c8", "target_name": "CryptEncrypt", "type": "UNCONDITIONAL_CALL"},
        ],
    }
    genkey = trace_static_api_arguments(function, "CryptGenKey", callsite="0x1400014a8")
    encrypt = trace_static_api_arguments(function, "CryptEncrypt", callsite="0x1400014c8")
    assert any(row.get("value") == "0x6801" for row in genkey)
    assert not any(row.get("value") == "0x6801" for row in encrypt)
    assert any(str(row.get("value") or "") == "byte_14004c900" for row in encrypt)
