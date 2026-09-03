from types import SimpleNamespace

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.investigation import ActionSpec, ActionType
from threat_report_agent.service import AnalysisService
from threat_report_agent.static_analysis import (
    analyze_bytes,
    analyze_xor_decode_window,
    classify_pe_semantics,
    classify_static_string,
    cluster_static_seeds,
    build_investigation_seed_map,
    recognize_hash_algorithm,
    resolve_export_hashes,
    track_indirect_function_pointers,
    trace_static_api_arguments,
)


def test_register_zeroing_xor_is_not_a_decode_candidate() -> None:
    window = [
        {"mnemonic": "XOR", "text": "XOR EAX,EAX"},
        {"mnemonic": "XOR", "text": "XOR R15D,R15D"},
        {"mnemonic": "JNZ", "text": "JNZ 0x1000"},
    ]
    assert analyze_xor_decode_window(window) is None


def test_xor_candidate_exposes_semantic_requirements() -> None:
    window = [
        {"mnemonic": "MOV", "text": "MOV ECX,0x1f"},
        {"mnemonic": "XOR", "text": "XOR DL,BL"},
        {"mnemonic": "ADD", "text": "ADD RAX,0x1"},
        {"mnemonic": "XOR", "text": "XOR DL,0x7"},
        {"mnemonic": "JNZ", "text": "JNZ 0x14001020"},
    ]
    result = analyze_xor_decode_window(window)
    assert result is not None
    assert result["data_transform_present"] is True
    assert result["semantic_requirements"]["non_zeroing_transform"] is True
    assert result["register_zeroing_xor_count"] == 0


def test_string_classifier_marks_code_noise_and_semantic_iocs() -> None:
    assert classify_static_string("L$HH", "ascii")["semantic_class"] == "CODE_BYTE_FALSE_POSITIVE"
    url = classify_static_string("https://example.invalid/gate", "ascii")
    assert url["semantic_class"] == "URL"
    assert url["quality"] == "HIGH"
    assert classify_static_string("HKCU\\Software\\Run\\Updater")["semantic_class"] == "REGISTRY"


def test_analyze_bytes_emits_quality_rows_without_changing_raw_strings() -> None:
    result = analyze_bytes(b"L$HH\x00https://example.invalid/gate\x00", "sample.bin")
    raw = [row for row in result.facts if row.kind == "string"]
    quality = [row for row in result.facts if row.kind == "string_semantics"]
    assert len(raw) == 2
    assert len(quality) == 2
    assert any(row.value["semantic_class"] == "URL" for row in quality)


def test_seed_clustering_bounds_duplicate_import_frontier() -> None:
    rows = [
        {"id": f"i-{index}", "kind": "import_symbol", "value": {"api": "GetProcAddress"}, "anchor": {}}
        for index in range(40)
    ]
    clusters = cluster_static_seeds(rows, max_clusters=12)
    assert len(clusters) == 1
    assert clusters[0]["category"] == "dynamic_api"
    assert len(clusters[0]["evidence_ids"]) == 32
    assert clusters[0]["hypotheses"]


def test_seed_map_is_bounded_and_serializable() -> None:
    result = build_investigation_seed_map(
        [
            {"id": "a", "kind": "string", "value": {"text": "https://example.invalid"}, "anchor": {}},
            {"id": "b", "kind": "import_symbol", "value": {"api": "GetProcAddress"}, "anchor": {}},
        ],
        max_clusters=2,
    )
    assert result["cluster_count"] <= 2
    assert result["visible_candidate_budget"] == 2
    assert all(item["static_only"] for item in result["clusters"])


def test_hash_resolver_recognizes_djb2_and_matches_exports() -> None:
    info = recognize_hash_algorithm([
        {"text": "MOV EAX,0x1505"},
        {"text": "IMUL EAX,EAX,33"},
        {"text": "ADD EAX,EDX"},
        {"text": "JNZ 0x401000"},
    ])
    assert info["algorithm"] == "DJB2"
    expected = 5381
    for byte in b"WinHttpOpen":
        expected = (expected * 33 + byte) & 0xFFFFFFFF
    resolved = resolve_export_hashes([expected], [{"name": "WinHttpOpen", "rva": 0x1234}])
    assert resolved[0]["status"] == "RESOLVED"
    assert resolved[0]["matches"][0]["name"] == "WinHttpOpen"


def test_pe_semantic_classifier_does_not_call_header_parse_a_mapper() -> None:
    function = {
        "name": "FUN_export_resolver",
        "instructions": [
            {"text": "MOV ECX,[NumberOfNames]"},
            {"text": "MOV RDX,[AddressOfNames]"},
            {"text": "MOV R8,[AddressOfNameOrdinals]"},
            {"text": "MOV R9,[AddressOfFunctions]"},
            {"text": "MOV EAX,0x1505"},
            {"text": "IMUL EAX,EAX,33"},
            {"text": "JNZ 0x1000"},
        ],
        "references_from": [],
    }
    roles = classify_pe_semantics(function)
    assert roles[0]["role"] == "EXPORT_RESOLVER"
    assert all(role["role"] != "MANUAL_MAPPER" for role in roles)
    assert roles[0]["hash_resolver"]["algorithm"] == "DJB2"


def test_pe_semantic_classifier_attaches_static_export_hash_matches() -> None:
    digest = 5381
    for byte in b"WinHttpOpen":
        digest = (digest * 33 + byte) & 0xFFFFFFFF
    function = {
        "name": "FUN_export_resolver",
        "instructions": [
            {"text": "MOV EAX,0x1505"},
            {"text": "IMUL EAX,EAX,33"},
            {"text": "ADD EAX,EDX"},
            {"text": "CMP EAX,0x%08x" % digest},
            {"text": "CMP ECX,[NumberOfNames]"},
            {"text": "JNZ 0x1000"},
        ],
        "references_from": [],
    }
    roles = classify_pe_semantics(
        function,
        {"exports": {"functions": [{"name": "WinHttpOpen", "rva": 0x1234}] }},
    )
    resolved = roles[0]["resolved_exports"]
    assert any(item["status"] == "RESOLVED" for item in resolved)
    assert any(match["name"] == "WinHttpOpen" for item in resolved for match in item["matches"])


def test_static_argument_trace_recovers_x64_constant_and_global() -> None:
    function = {
        "name": "FUN_http",
        "instructions": [
            {"address": "0x1000", "text": "LEA RCX,[global_host]"},
            {"address": "0x1005", "text": "MOV RDX,0x1f90"},
            {"address": "0x100a", "text": "CALL WinHttpConnect"},
        ],
        "references_from": [{"from": "0x100a", "target_name": "WinHttpConnect", "type": "CALL"}],
    }
    rows = trace_static_api_arguments(function, "WinHttpConnect")
    assert rows[0]["source_kind"] == "global"
    assert rows[1]["source_kind"] == "constant"
    assert rows[1]["value"] == "0x1f90"


def test_indirect_pointer_tracking_requires_resolver_storage_and_consumer() -> None:
    function = {
        "name": "resolve_and_dispatch",
        "instructions": [
            {"address": "0x1000", "text": "CALL GetProcAddress"},
            {"address": "0x1005", "text": "MOV [global_slot], RAX"},
            {"address": "0x100a", "text": "CALL [global_slot]"},
        ],
        "references_from": [
            {"from": "0x1000", "target_name": "GetProcAddress", "type": "CALL"},
        ],
    }
    links = track_indirect_function_pointers(function)
    assert links and links[0]["indirect"] is True
    assert links[0]["storage"] == "global_slot"
    assert links[0]["consumer_callsite"] == "0x100a"


def test_indirect_pointer_tracking_recovers_context_level_global_table() -> None:
    """Function-context exports can recover a pointer table without instructions."""
    function = {
        "name": "resolve_table_dispatch",
        "references_from": [
            {"from": "0x2000", "target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
        ],
        "data_references": [
            {"from": "0x2008", "to": "PTR_RESOLVED_API", "target_name": "PTR_RESOLVED_API", "type": "WRITE"},
        ],
        "call_targets": [
            {"from": "0x2010", "to": "PTR_RESOLVED_API", "target_name": "PTR_RESOLVED_API", "type": "COMPUTED_CALL"},
        ],
    }
    links = track_indirect_function_pointers(function)
    assert links
    assert links[0]["storage"] == "PTR_RESOLVED_API"
    assert links[0]["consumer_callsite"] == "0x2010"
    assert links[0]["evidence_source"] == "function_context_data_references"
    assert links[0]["static_only"] is True


def test_indirect_pointer_tracking_does_not_promote_global_write_without_consumer() -> None:
    function = {
        "name": "resolve_only",
        "references_from": [
            {"from": "0x3000", "target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
        ],
        "data_references": [
            {"from": "0x3008", "to": "PTR_RESOLVED_API", "target_name": "PTR_RESOLVED_API", "type": "WRITE"},
        ],
    }
    assert track_indirect_function_pointers(function) == ()


def test_indirect_pointer_tracking_recovers_import_slot_call_and_return_jump() -> None:
    """Ghidra's PE form loads an import pointer, calls the register, then jumps to RAX."""
    function = {
        "name": "resolve_and_jump",
        "instructions": [
            {"address": "0x2000", "text": "MOV RBX,qword ptr [0x140102588]"},
            {"address": "0x2008", "text": "CALL RBX"},
            {"address": "0x2010", "text": "MOV qword ptr [0x1400d0320],RAX"},
            {"address": "0x2018", "text": "JMP RAX"},
        ],
        "references_from": [
            {
                "from": "0x2008",
                "to": "EXTERNAL:0000001c",
                "target_name": "GetProcAddress",
                "type": "COMPUTED_CALL",
            },
        ],
    }
    links = track_indirect_function_pointers(function)
    assert links
    assert links[0]["resolver"] == "GetProcAddress"
    assert links[0]["storage"] == "0x1400d0320"
    assert links[0]["consumer_callsite"] == "0x2018"
    assert links[0]["consumer_kind"] == "JUMP"


def test_indirect_pointer_tracking_keeps_import_call_without_return_consumer_unresolved() -> None:
    """An import-pointer call alone must not imply a resolved API consumer."""
    function = {
        "name": "resolver_only",
        "instructions": [
            {"address": "0x2100", "text": "MOV RBX,qword ptr [0x140102588]"},
            {"address": "0x2108", "text": "CALL RBX"},
        ],
        "references_from": [
            {"from": "0x2108", "target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
        ],
    }
    assert track_indirect_function_pointers(function) == ()


def test_service_pcode_action_recovers_context_level_pointer_link(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-resolver",
            kind="function_context",
            value={
                "name": "resolve_table_dispatch",
                "entry": "0x2000",
                "call_targets": [
                    {"from": "0x2000", "target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
                    {"from": "0x2010", "to": "PTR_RESOLVED_API", "target_name": "PTR_RESOLVED_API", "type": "COMPUTED_CALL"},
                ],
                "data_references": [
                    {"from": "0x2008", "to": "PTR_RESOLVED_API", "target_name": "PTR_RESOLVED_API", "type": "WRITE"},
                ],
            },
            anchor={"function_entry": "0x2000"},
        )
    ]
    action = ActionSpec(
        id="pcode-context",
        action_type=ActionType.GET_PCODE_SLICE,
        thread_id="thread-1",
        hypothesis_id="hyp-1",
        artifact_id="artifact-1",
        target_selector={"target": "resolve_table_dispatch"},
    )
    observations = service._derive_investigation_observations(rows, action)
    links = [item for item in observations if item["kind"] == "indirect_function_pointer_link"]
    assert links
    assert links[0]["value"]["storage"] == "PTR_RESOLVED_API"
    assert links[0]["nature"] == "STATIC_DERIVED"


def test_forwarded_export_match_is_explicit() -> None:
    resolved = resolve_export_hashes(
        [5381],
        [{"name": "Forwarded", "rva": 0x20, "forwarder": "KERNELBASE!Forwarded"}],
    )
    # The arbitrary hash is intentionally unresolved; the contract must never
    # infer a forwarded API from metadata alone.
    assert resolved[0]["status"] == "UNRESOLVED"
    expected = 5381
    for byte in b"Forwarded":
        expected = (expected * 33 + byte) & 0xFFFFFFFF
    matched = resolve_export_hashes(
        [expected],
        [{"name": "Forwarded", "rva": 0x20, "forwarder": "KERNELBASE!Forwarded"}],
    )[0]
    assert matched["status"] == "RESOLVED"
    assert matched["matches"][0]["forwarded"] is True
    assert matched["matches"][0]["forwarded_module"] == "KERNELBASE"
