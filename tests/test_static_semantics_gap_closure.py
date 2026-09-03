from threat_report_agent.static_analysis import (
    analyze_xor_decode_window,
    build_cross_function_chains,
    build_pcode_slice,
    classify_pe_semantics,
    resolve_export_hashes,
    track_indirect_function_pointers,
    trace_static_api_arguments,
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
