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
    recover_dynamic_api_resolutions,
    recover_parent_process_attribute,
    recover_process_creation_arguments,
    process_import_thunks,
    import_api_thunks,
    select_instruction_window_indices,
    track_indirect_function_pointers,
    trace_static_api_arguments,
    build_function_semantic_summary,
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
    assert "intended security-relevant behavior" in clusters[0]["hypotheses"]
    assert "intended capability" not in clusters[0]["hypotheses"]


def test_seed_clustering_preserves_all_high_value_mechanism_dimensions() -> None:
    """A resolver for a transport API is both resolver and transport work.

    The scheduler must not discard the transport question merely because
    ``GetProcAddress`` happens to sort before ``WinHttp*`` in a fact value.
    """
    rows = [
        {
            "id": "resolver-transport",
            "kind": "function_context",
            "value": {
                "entry": "0x401000",
                "call_targets": [
                    {"target_name": "GetProcAddress"},
                    {"target_name": "WinHttpSendRequest"},
                    {"target_name": "WinHttpReceiveResponse"},
                ],
            },
            "anchor": {"function_entry": "0x401000"},
        }
    ]

    clusters = cluster_static_seeds(rows, max_clusters=8)
    by_category = {str(item["category"]): item for item in clusters}

    assert {"dynamic_api", "network"} <= set(by_category)
    assert by_category["dynamic_api"]["playbook_id"] == "dynamic-api-resolution"
    assert by_category["network"]["playbook_id"] == "http-download"
    assert by_category["network"]["mechanism_type"] == "HTTP_DOWNLOAD"
    assert by_category["dynamic_api"]["evidence_ids"] == ["resolver-transport"]
    assert by_category["network"]["evidence_ids"] == ["resolver-transport"]


def test_seed_clustering_opens_ppid_from_attribute_api_not_openprocess_alone() -> None:
    """OpenProcess is not PPID. UpdateProcThreadAttribute opens one artifact-wide seed."""
    open_only = cluster_static_seeds(
        [
            {
                "id": "open-1",
                "kind": "function_call",
                "value": {"api": "OpenProcess"},
                "anchor": {"function_entry": "0x140004605"},
            }
        ],
        max_clusters=8,
    )
    assert all(item["category"] != "ppid" for item in open_only)

    rows = [
        {
            "id": "ppid-attr",
            "kind": "function_call",
            "value": {"api": "UpdateProcThreadAttribute"},
            "anchor": {"function_entry": "0x140004605"},
        },
        {
            "id": "ppid-create",
            "kind": "api_argument_trace",
            "value": {
                "api": "CreateProcessW",
                "command": "FoxitPDFReader.exe",
                "creation_flags": "0x000f4240",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            },
            "anchor": {"function_entry": "0x140004605"},
        },
        {
            "id": "ppid-relation",
            "kind": "value_flow",
            "value": {"relation": "parent_handle_to_attribute"},
            "anchor": {"function_entry": "0x140004605"},
        },
        {
            "id": "ppid-other-fn",
            "kind": "function_call",
            "value": {"api": "UpdateProcThreadAttribute"},
            "anchor": {"function_entry": "0x140009000"},
        },
    ]
    clusters = cluster_static_seeds(rows, max_clusters=8)
    by_category = {str(item["category"]): item for item in clusters}
    assert {"ppid", "execution"} <= set(by_category)
    assert by_category["ppid"]["playbook_id"] == "ppid-process-chain"
    assert by_category["execution"]["playbook_id"] == "process-execution"
    assert by_category["ppid"]["function"] is None
    assert "ppid-attr" in by_category["ppid"]["evidence_ids"]
    assert "ppid-relation" in by_category["ppid"]["evidence_ids"]
    assert "ppid-other-fn" in by_category["ppid"]["evidence_ids"]


def test_seed_clustering_merges_resolver_functions_into_one_dimension() -> None:
    """Twelve GetProcAddress functions must not fill the admission window alone."""
    rows = [
        {
            "id": f"resolver-{index}",
            "kind": "function_context",
            "value": {"api": "GetProcAddress"},
            "anchor": {"function_entry": hex(0x401000 + index * 0x20)},
        }
        for index in range(12)
    ]
    rows.append(
        {
            "id": "decode-1",
            "kind": "decode_result",
            "value": {"decoded_text": "http://203.0.113.9/stage.bin", "algorithm": "xor"},
            "anchor": {"function_entry": "0x402000"},
        }
    )
    clusters = cluster_static_seeds(rows, max_clusters=12)
    by_category = {str(item["category"]): item for item in clusters}
    assert by_category["dynamic_api"]["function"] is None
    assert len(by_category["dynamic_api"]["evidence_ids"]) == 12
    assert "decode" in by_category


def test_seed_clustering_does_not_open_http_from_missing_export_or_url() -> None:
    """Resume 'WinHTTP export not found' and a decoded http:// URL are not transport APIs."""
    clusters = cluster_static_seeds(
        [
            {
                "id": "missing-export",
                "kind": "string",
                "value": {"text": "WinHTTP export not found"},
                "anchor": {},
            },
            {
                "id": "decoded-url",
                "kind": "decode_result",
                "value": {"decoded_text": "http://69.48.228.74/miaom-c.pdf", "algorithm": "xor"},
                "anchor": {"function_entry": "0x401000"},
            },
        ],
        max_clusters=8,
    )
    assert all(item["category"] != "network" for item in clusters)
    assert any(item["category"] == "decode" for item in clusters)


def test_seed_clustering_opens_unique_os_thread_from_recovered_start() -> None:
    """Kunglao leftover remainder: CreateThread with lpStartAddress is a HOW seed."""
    clusters = cluster_static_seeds(
        [
            {
                "id": "trace-thread",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "0x140038ae0",
                            "resolved": True,
                        }
                    ],
                },
                "anchor": {"function_entry": "1400440b9"},
            },
            {
                "id": "trace-remote",
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateRemoteThread",
                    "arguments": [
                        {
                            "index": 3,
                            "name": "lpStartAddress",
                            "value": "0x140010000",
                            "resolved": True,
                        }
                    ],
                },
                "anchor": {"function_entry": "140010100"},
            },
        ],
        max_clusters=8,
    )
    by_category = {str(item["category"]): item for item in clusters}
    assert "thread" in by_category
    assert by_category["thread"]["evidence_ids"] == ["trace-thread"]
    assert by_category["thread"]["playbook_id"] == ""
    assert by_category["thread"]["mechanism_type"] == "THREAD_CALLBACK"


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
    assert result["total_cluster_count"] >= result["cluster_count"]
    assert result["deferred_cluster_count"] == result["total_cluster_count"] - result["cluster_count"]
    assert all(item["static_only"] for item in result["clusters"])


def test_seed_clustering_recovers_function_from_derived_source_anchor() -> None:
    """Derived links must retain their concrete function deep-mining target."""
    clusters = cluster_static_seeds(
        [
            {
                "id": "derived-link",
                "kind": "mechanism_dynamic_api_link",
                "value": {"relationship": "resolver -> consumer"},
                "anchor": {
                    "type": "investigation_action",
                    "source_anchors": [{"type": "function", "function_entry": "0x401000"}],
                },
            }
        ],
        max_clusters=8,
    )

    assert clusters
    assert clusters[0]["function"] == "0x401000"


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


def test_function_semantic_summary_reconstructs_ordered_path_arguments_and_boundary() -> None:
    function = {
        "name": "launch_stage",
        "entry": "0x401000",
        "entry_rva": "0x1000",
        "instructions": [
            {"address": "0x401000", "text": "LEA RCX,[cmdline]"},
            {"address": "0x401005", "text": "MOV RDX,0x08000000"},
            {"address": "0x40100a", "text": "CALL CreateProcessW"},
            {"address": "0x401010", "text": "TEST EAX,EAX"},
            {"address": "0x401012", "text": "JZ 0x401030"},
            {"address": "0x401018", "text": "CALL ReadFile"},
        ],
        "references_from": [
            {"from": "0x40100a", "target_name": "CreateProcessW", "type": "CALL"},
            {"from": "0x401018", "target_name": "ReadFile", "type": "CALL"},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert summary["static_only"] is True
    assert summary["function_entry"] == "0x401000"
    assert [row["api"] for row in summary["call_sequence"]] == ["CreateProcessW", "ReadFile"]
    assert summary["call_sequence"][0]["category"] == "execution"
    assert summary["arguments"][0]["recovered_argument_count"] >= 1
    assert any(item["value"] == "0x08000000" for item in summary["inputs"])
    assert summary["conditions"]
    assert summary["consumers"]
    assert "runtime execution is unobserved" in summary["boundary"]


def test_function_semantic_summary_excludes_non_call_references() -> None:
    """Data and CFG references must not be rendered as API calls."""
    function = {
        "name": "mixed_refs",
        "entry": "0x401000",
        "instructions": [],
        "references_from": [
            {"from": "0x401000", "target_name": "DAT_foo", "type": "DATA"},
            {"from": "0x401004", "target_name": "flag", "type": "READ"},
            {
                "from": "0x401008",
                "target_name": "LAB_401020",
                "type": "CONDITIONAL_JUMP",
            },
            {"from": "0x40100c", "target_name": "WriteFile", "type": "CALL"},
            {"from": "0x401010", "target_name": "GetProcAddress", "type": "COMPUTED_CALL"},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert [row["api"] for row in summary["call_sequence"]] == [
        "WriteFile",
        "GetProcAddress",
    ]


def test_function_semantic_summary_accepts_explicit_call_flag_without_type() -> None:
    """New exporters may provide a boolean call marker instead of a type."""
    function = {
        "name": "flagged_call",
        "entry": "0x401000",
        "instructions": [],
        "references_from": [
            {"target_name": "ReadFile", "is_call": True},
            {"target_name": "DAT_foo", "is_call": False},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert [row["api"] for row in summary["call_sequence"]] == ["ReadFile"]


def test_function_semantic_summary_rejects_legacy_navigation_labels_without_type() -> None:
    """Legacy call-target projections must not promote LAB/DAT labels to calls."""
    function = {
        "name": "legacy_projection",
        "entry": "0x401000",
        "instructions": [],
        "call_targets": [
            {"target_name": "LAB_401020"},
            {"target_name": "DAT_1401016A0"},
            {"target_name": "PTR_DAT_1400D9BF0"},
            {"target_name": "CreateProcessW"},
        ],
    }

    summary = build_function_semantic_summary(function)

    assert [row["api"] for row in summary["call_sequence"]] == ["CreateProcessW"]


def test_function_semantic_summary_keeps_repeated_api_call_arguments_scoped() -> None:
    """Repeated API invocations must retain their own producer and callsite."""
    function = {
        "name": "connect_twice",
        "entry": "0x401000",
        "instructions": [
            {"address": "0x401000", "text": "MOV RCX,0x1"},
            {"address": "0x401005", "text": "MOV RDX,0x1111"},
            {"address": "0x40100a", "text": "CALL WinHttpConnect"},
            {"address": "0x401010", "text": "MOV RCX,0x2"},
            {"address": "0x401015", "text": "MOV RDX,0x2222"},
            {"address": "0x40101a", "text": "CALL WinHttpConnect"},
        ],
        "references_from": [
            {"from": "0x40100a", "target_name": "WinHttpConnect", "type": "CALL"},
            {"from": "0x40101a", "target_name": "WinHttpConnect", "type": "CALL"},
        ],
    }

    summary = build_function_semantic_summary(function)

    calls = summary["call_sequence"]
    assert len(calls) == 2
    assert [
        [item["value"] for item in call["arguments"] if item["argument_index"] == 1]
        for call in calls
    ] == [["0x1111"], ["0x2222"]]
    assert [
        [item["register"] for item in call["arguments"] if item["argument_index"] == 1]
        for call in calls
    ] == [["RDX"], ["RDX"]]


def test_function_semantic_summary_keeps_unresolved_function_explicit() -> None:
    summary = build_function_semantic_summary(
        {"name": "empty", "entry": "0x5000", "instructions": [], "references_from": []}
    )

    assert summary["call_sequence"] == []
    assert summary["confidence"] == "LOW"
    assert summary["unknowns"]


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


def test_dynamic_api_resolution_recovers_rdx_string_and_indirect_consumer() -> None:
    function = {
        "name": "resolve_winhttp",
        "instructions": [
            {"address": "0x1000", "text": "LEA RDX,[0x14002000]"},
            {"address": "0x1008", "text": "CALL GetProcAddress"},
            {"address": "0x1010", "text": "MOV [0x14003000], RAX"},
            {"address": "0x1018", "text": "CALL [0x14003000]"},
        ],
        "references_from": [
            {"from": "0x1008", "target_name": "GetProcAddress", "type": "CALL"},
        ],
    }
    rows = recover_dynamic_api_resolutions(function, {"0x14002000": "WinHttpOpen"})
    assert len(rows) == 1
    assert rows[0]["api_name"] == "WinHttpOpen"
    assert rows[0]["string_address"] == "0x14002000"
    assert rows[0]["resolver_callsite"] == "0x1008"
    assert rows[0]["consumer_callsite"] == "0x1018"
    assert rows[0]["static_only"] is True


def test_dynamic_api_resolution_follows_return_register_copy_to_consumer() -> None:
    """Optimized x64 code may copy RAX before the indirect call/jump."""
    function = {
        "name": "resolve_and_call_saved",
        "instructions": [
            {"address": "0x1100", "text": "LEA RDX,[0x14002000]"},
            {"address": "0x1108", "text": "CALL GetProcAddress"},
            {"address": "0x1110", "text": "MOV R12,RAX"},
            {"address": "0x1118", "text": "TEST R12,R12"},
            {"address": "0x1120", "text": "CALL R12"},
        ],
        "references_from": [
            {"from": "0x1108", "target_name": "GetProcAddress", "type": "CALL"},
        ],
    }
    rows = recover_dynamic_api_resolutions(function, {"0x14002000": "WinHttpOpen"})
    assert len(rows) == 1
    assert rows[0]["consumer_callsite"] == "0x1120"
    assert rows[0]["consumer"] == "CALL R12"
    assert rows[0]["consumer_kind"] == "CALL"


def test_dynamic_api_resolution_rejects_unmapped_or_non_api_string() -> None:
    function = {
        "name": "resolve_unknown",
        "instructions": [
            {"address": "0x2000", "text": "MOV EDX,0x14002000"},
            {"address": "0x2008", "text": "CALL GetProcAddress"},
        ],
        "references_from": [
            {"from": "0x2008", "target_name": "GetProcAddress", "type": "CALL"},
        ],
    }
    assert recover_dynamic_api_resolutions(function, {"14002000": "not a procedure name"}) == ()


def test_dynamic_api_resolution_uses_same_instruction_data_reference_for_symbolic_operand() -> None:
    function = {
        "name": "resolve_symbolic",
        "instructions": [
            {"address": "0x3000", "text": "LEA EDX,[s_CreateFileA_14004000]"},
            {"address": "0x3008", "text": "CALL GetProcAddress"},
        ],
        "references_from": [
            {"from": "0x3000", "to": "0x14004000", "target_name": "s_CreateFileA_14004000", "type": "DATA"},
            {"from": "0x3008", "target_name": "GetProcAddress", "type": "CALL"},
        ],
    }
    rows = recover_dynamic_api_resolutions(function, {"14004000": "CreateFileA"})
    assert rows and rows[0]["api_name"] == "CreateFileA"
    assert rows[0]["argument_register"] == "EDX"
    assert rows[0]["argument_source_kind"] == "data_reference"


def test_dynamic_api_resolution_recovers_qword_ptr_import_slot_call() -> None:
    """Ghidra emits CALL qword ptr [PTR_GetProcAddress_...], not CALL GetProcAddress."""
    function = {
        "name": "resolve_import_slot",
        "instructions": [
            {"address": "0x1000", "text": "LEA RDX,[0x14002000]"},
            {"address": "0x1008", "text": "CALL qword ptr [PTR_GetProcAddress_14005e688]"},
            {"address": "0x1010", "text": "JMP RAX"},
        ],
        "references_from": [
            {
                "from": "0x1008",
                "to": "0x14005e688",
                "target_name": "PTR_GetProcAddress_14005e688",
                "type": "CALL",
            },
        ],
    }
    rows = recover_dynamic_api_resolutions(function, {"0x14002000": "WinHttpOpen"})
    assert len(rows) == 1
    assert rows[0]["api_name"] == "WinHttpOpen"
    assert rows[0]["resolver"].casefold() == "getprocaddress"
    assert rows[0]["consumer_callsite"] == "0x1010"


def test_dynamic_api_resolution_recovers_register_call_after_ptr_load() -> None:
    function = {
        "name": "resolve_via_rbx",
        "instructions": [
            {"address": "0x1000", "text": "LEA RDX,[0x14002000]"},
            {"address": "0x1008", "text": "MOV RBX,qword ptr [PTR_GetProcAddress_14005e688]"},
            {"address": "0x1010", "text": "CALL RBX"},
            {"address": "0x1018", "text": "CALL RAX"},
        ],
        "references_from": [
            {
                "from": "0x1008",
                "to": "0x14005e688",
                "target_name": "PTR_GetProcAddress_14005e688",
                "type": "DATA",
            },
        ],
    }
    rows = recover_dynamic_api_resolutions(function, {"0x14002000": "WinHttpSendRequest"})
    assert len(rows) == 1
    assert rows[0]["api_name"] == "WinHttpSendRequest"
    assert rows[0]["resolver_callsite"] == "0x1010"


def test_dynamic_api_joins_module_handle_and_late_thunk_call() -> None:
    """Resume FUN_140038dd0: GetModuleHandleA(kernel32) then GetProcAddress thunk."""
    thunks = import_api_thunks(
        (
            {
                "name": "GetModuleHandleA",
                "entry": "140046888",
                "instructions": [
                    {"address": "140046888", "text": "JMP qword ptr [0x14005e698]"},
                ],
            },
            {
                "name": "GetProcAddress",
                "entry": "140046878",
                "instructions": [
                    {"address": "140046878", "text": "JMP qword ptr [0x14005e688]"},
                ],
            },
        )
    )
    rows = recover_dynamic_api_resolutions(
        {
            "name": "FUN_140038dd0",
            "instructions": [
                {"address": "140038de2", "text": "LEA RCX,[0x140054d58]"},
                {"address": "140038de9", "text": "CALL 0x140046888"},
                {"address": "140038dee", "text": "TEST RAX,RAX"},
                {"address": "140038df1", "text": "JZ 0x140038e12"},
                {"address": "140038df3", "text": "LEA RDX,[0x140054f8a]"},
                {"address": "140038dfa", "text": "MOV RCX,RAX"},
                {"address": "140038dfd", "text": "CALL 0x140046878"},
                {"address": "140038e02", "text": "TEST RAX,RAX"},
                {"address": "140038e08", "text": "MOV R8,RAX"},
                {"address": "140038e2d", "text": "JMP R8"},
            ],
            "references_from": [
                {
                    "from": "140038de2",
                    "to": "140054d58",
                    "target_name": "s_kernel32_140054d58",
                    "type": "DATA",
                },
                {
                    "from": "140038de9",
                    "to": "140046888",
                    "target_name": "GetModuleHandleA",
                    "type": "UNCONDITIONAL_CALL",
                },
                {
                    "from": "140038df3",
                    "to": "140054f8a",
                    "target_name": "s_SetThreadDescription_140054f8a",
                    "type": "DATA",
                },
                {
                    "from": "140038dfd",
                    "to": "140046878",
                    "target_name": "GetProcAddress",
                    "type": "UNCONDITIONAL_CALL",
                },
            ],
        },
        {
            "0x140054d58": "kernel32.dll",
            "0x140054f8a": "SetThreadDescription",
        },
        thunks=thunks,
    )
    assert len(rows) == 1
    assert rows[0]["api_name"] == "SetThreadDescription"
    assert rows[0]["module_input"] == "kernel32.dll"
    assert rows[0]["resolver"] == "GetProcAddress"
    assert rows[0]["consumer_kind"] == "JUMP"


def test_process_creation_recovers_command_flags_and_return_branch() -> None:
    """Resume-shaped CreateProcessW keeps cmd.exe and EXTENDED_STARTUPINFO_PRESENT."""
    function = {
        "name": "FUN_140004605",
        "instructions": [
            {"address": "0x140004700", "text": "LEA RDX,[0x14005000]"},
            {"address": "0x140004708", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
            {"address": "0x140004710", "text": "CALL CreateProcessW"},
            {"address": "0x140004716", "text": "TEST EAX, EAX"},
            {"address": "0x140004718", "text": "JZ 0x140004780"},
        ],
        "references_from": [
            {"from": "0x140004710", "target_name": "CreateProcessW", "type": "CALL"},
        ],
    }
    rows = recover_process_creation_arguments(
        function,
        {"0x14005000": "cmd.exe /c FoxitPDFReader.exe"},
    )
    assert len(rows) == 1
    assert rows[0]["api"] == "CreateProcessW"
    assert rows[0]["command"] == "cmd.exe /c FoxitPDFReader.exe"
    assert rows[0]["creation_flags"] == "0x000f4240"
    assert rows[0]["return_branch"] == "JZ 0x140004780"


def test_process_creation_recovers_ptr_import_slot_and_rejects_stack_locator() -> None:
    function = {
        "name": "spawn_via_rbx",
        "instructions": [
            {"address": "0x14001000", "text": "LEA RDX,[0x14006000]"},
            {"address": "0x14001008", "text": "MOV RBX,qword ptr [PTR_CreateProcessW_14005e5b8]"},
            {"address": "0x14001010", "text": "MOV dword ptr [RSP + 0x28], 0x09080008"},
            {"address": "0x14001018", "text": "CALL RBX"},
            {"address": "0x14001020", "text": "TEST EAX, EAX"},
            {"address": "0x14001022", "text": "JNZ 0x14001080"},
        ],
        "references_from": [
            {
                "from": "0x14001008",
                "target_name": "PTR_CreateProcessW_14005e5b8",
                "type": "DATA",
            },
        ],
    }
    rows = recover_process_creation_arguments(
        function,
        {"0x14006000": "cmd.exe /c start"},
    )
    assert rows and rows[0]["command"] == "cmd.exe /c start"
    assert rows[0]["creation_flags"] == "0x09080008"
    stacked = recover_process_creation_arguments(
        {
            "name": "unresolved",
            "instructions": [
                {"address": "0x401000", "text": "LEA RDX,[RSP + 0x78]"},
                {"address": "0x401008", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x401008", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {},
    )
    assert stacked == ()


def test_process_creation_joins_late_thunk_call_without_0x_or_rdx() -> None:
    """Resume FUN_140004605: CreateProcessW is a late IAT thunk, RDX is empty, flag is not in the last 12 ops."""
    instructions = [
        {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
        *[{"address": hex(0x140008c08 + index * 4), "text": "NOP"} for index in range(20)],
        {"address": "0x140008dc0", "text": "LEA R15,[0x14005000]"},
        {"address": "0x140008dc3", "text": "MOV RCX,R14"},
        {"address": "0x140008dce", "text": "CALL 0x140046948"},
        {"address": "0x140008dd4", "text": "TEST EAX, EAX"},
        {"address": "0x140008dd6", "text": "JZ 0x140008e00"},
    ]
    thunks = process_import_thunks(
        (
            {
                "name": "CreateProcessW",
                "entry": "140046948",
                "instructions": [
                    {"address": "140046948", "text": "JMP qword ptr [0x14005e5b8]"},
                ],
            },
        )
    )
    rows = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": instructions,
            "references_from": [
                {
                    "from": "140008dce",
                    "to": "140046948",
                    "target_name": "CreateProcessW",
                    "type": "UNCONDITIONAL_CALL",
                }
            ],
        },
        {"0x14005000": "FoxitPDFReader.exe"},
        thunks=thunks,
    )
    assert len(rows) == 1
    assert rows[0]["api"] == "CreateProcessW"
    assert rows[0]["command"] == "FoxitPDFReader.exe"
    assert rows[0]["creation_flags"] == "0x000f4240"
    assert rows[0]["return_branch"] == "JZ 0x140008e00"


def test_process_creation_keeps_nearest_flag_when_window_is_not_unique() -> None:
    """Resume FUN_140004605 has several plausible immediates; keep the one nearest CreateProcess."""
    instructions = [
        {"address": "0x140008b00", "text": "MOV dword ptr [RSP + 0x28], 0x08000000"},
        {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
        *[{"address": hex(0x140008c08 + index * 4), "text": "NOP"} for index in range(20)],
        {"address": "0x140008dc0", "text": "LEA R15,[0x14005000]"},
        {"address": "0x140008dc3", "text": "MOV RCX,R14"},
        {"address": "0x140008dce", "text": "CALL CreateProcessW"},
        {"address": "0x140008dd4", "text": "TEST EAX, EAX"},
        {"address": "0x140008dd6", "text": "JZ 0x140008e00"},
    ]
    rows = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": instructions,
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14005000": "FoxitPDFReader.exe"},
    )
    assert len(rows) == 1
    assert rows[0]["command"] == "FoxitPDFReader.exe"
    assert rows[0]["creation_flags"] == "0x000f4240"


def test_process_creation_ignores_specialist_token_not_in_abi_slot() -> None:
    """0x09080008 in the same window is not dwCreationFlags unless it is [RSP+0x28]."""
    rows = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x140008dc0", "text": "LEA R15,[0x14005000]"},
                {"address": "0x140008dc8", "text": "MOV EAX, 0x09080008"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14005000": "FoxitPDFReader.exe"},
    )
    assert len(rows) == 1
    assert rows[0]["command"] == "FoxitPDFReader.exe"
    assert rows[0]["creation_flags"] == "0x000f4240"
    assert rows[0]["creation_flags"] != "0x09080008"


def test_process_creation_emits_flags_when_command_stays_on_the_stack() -> None:
    rows = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008dc0", "text": "LEA RDX,[RSP + 0x78]"},
                {"address": "0x140008dc8", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {},
    )
    assert len(rows) == 1
    assert rows[0]["creation_flags"] == "0x000f4240"
    assert not rows[0].get("command")


def test_process_creation_skips_flags_only_specialist_token() -> None:
    """HOW6: ABI-slot 0x09080008 without a command is PPID remainder, not process HOW."""
    rows = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008dc0", "text": "LEA RDX,[RSP + 0x78]"},
                {"address": "0x140008dc8", "text": "MOV dword ptr [RSP + 0x28], 0x09080008"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {},
    )
    assert rows == ()


def test_process_creation_rejects_rust_path_and_not_found_template() -> None:
    rust = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x140008dc0", "text": "LEA RDX,[0x14005000]"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14005000": "src/iat.rs"},
    )
    assert rust and rust[0]["creation_flags"] == "0x000f4240"
    assert not rust[0].get("command")
    missing = recover_process_creation_arguments(
        {
            "name": "FUN_14003c550",
            "instructions": [
                {"address": "0x140040050", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x140040058", "text": "LEA RDX,[0x14006000]"},
                {"address": "0x140040060", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140040060", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14006000": ".exeprogram not found"},
    )
    assert missing and not missing[0].get("command")


def test_process_creation_rejects_registry_key_and_unslotted_specialist_token() -> None:
    """HOW4 overlay: SOFTWARE\\Windows Defen + 0x09080008 is not CreateProcess ABI."""
    registry = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x140008dc0", "text": "LEA RDX,[0x14007000]"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14007000": r"SOFTWARE\Microsoft\Windows Defender"},
    )
    assert registry and registry[0]["creation_flags"] == "0x000f4240"
    assert not registry[0].get("command")
    unslotted = recover_process_creation_arguments(
        {
            "name": "FUN_140004605",
            "instructions": [
                {"address": "0x140008dc0", "text": "LEA RDX,[0x14005000]"},
                {"address": "0x140008dc8", "text": "MOV EAX, 0x09080008"},
                {"address": "0x140008dce", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x140008dce", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x14005000": "FoxitPDFReader.exe"},
    )
    assert unslotted and unslotted[0]["command"] == "FoxitPDFReader.exe"
    assert not unslotted[0].get("creation_flags")


def test_parent_attribute_joins_openprocess_update_and_createprocess() -> None:
    """Resume FUN_140004605: OpenProcess + UpdateProcThreadAttribute + CreateProcessW."""
    thunks = import_api_thunks(
        (
            {
                "name": "OpenProcess",
                "entry": "140046800",
                "instructions": [{"address": "140046800", "text": "JMP qword ptr [0x14005e500]"}],
            },
            {
                "name": "UpdateProcThreadAttribute",
                "entry": "140046810",
                "instructions": [{"address": "140046810", "text": "JMP qword ptr [0x14005e508]"}],
            },
            {
                "name": "CreateProcessW",
                "entry": "140046948",
                "instructions": [{"address": "140046948", "text": "JMP qword ptr [0x14005e5b8]"}],
            },
        )
    )
    function = {
        "name": "FUN_140004605",
        "instructions": [
            {"address": "0x140008b00", "text": "MOV ECX, 0x80"},
            {"address": "0x140008b08", "text": "LEA RDX,[0x140054000]"},
            {"address": "0x140008b10", "text": "CALL 0x140046800"},
            {"address": "0x140008b20", "text": "MOV EDX, 0x00020000"},
            {"address": "0x140008b28", "text": "CALL 0x140046810"},
            {"address": "0x140008c00", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
            {"address": "0x140008dce", "text": "CALL 0x140046948"},
        ],
        "references_from": [
            {"from": "0x140008b10", "to": "140046800", "target_name": "OpenProcess", "type": "UNCONDITIONAL_CALL"},
            {"from": "0x140008b28", "to": "140046810", "target_name": "UpdateProcThreadAttribute", "type": "UNCONDITIONAL_CALL"},
            {"from": "0x140008dce", "to": "140046948", "target_name": "CreateProcessW", "type": "UNCONDITIONAL_CALL"},
        ],
        "data_references": [
            {"from": "0x140008b08", "to": "0x140054000", "type": "DATA"},
        ],
    }
    recovered = recover_parent_process_attribute(
        function,
        {"0x140054000": "explorer.exe", "0x140060000": "unrelated.bin"},
        thunks=thunks,
    )
    assert recovered is not None
    assert recovered["parent_selection"] == "explorer.exe"
    assert recovered["access_mask"] == "PROCESS_CREATE_PROCESS"
    assert recovered["attribute"] == "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"
    assert recovered["startup_info"] == "STARTUPINFOEX"
    assert recovered["creation_flags"] == "0x000f4240"
    assert recovered["open_process"] == "OpenProcess"
    assert recovered["create_process"] == "CreateProcessW"
    assert "0x09080008" not in str(recovered)

    open_only = recover_parent_process_attribute(
        {
            "name": "open_only",
            "instructions": [{"address": "0x401000", "text": "CALL OpenProcess"}],
            "references_from": [
                {"from": "0x401000", "target_name": "OpenProcess", "type": "CALL"},
            ],
        },
        {"0x140054000": "explorer.exe"},
    )
    assert open_only is None

    foreign_explorer = recover_parent_process_attribute(
        {
            "name": "no_local_parent",
            "instructions": [
                {"address": "0x401000", "text": "CALL OpenProcess"},
                {"address": "0x401008", "text": "MOV EDX, 0x00020000"},
                {"address": "0x401010", "text": "CALL UpdateProcThreadAttribute"},
                {"address": "0x401018", "text": "MOV dword ptr [RSP + 0x28], 0x000f4240"},
                {"address": "0x401020", "text": "CALL CreateProcessW"},
            ],
            "references_from": [
                {"from": "0x401000", "target_name": "OpenProcess", "type": "CALL"},
                {"from": "0x401010", "target_name": "UpdateProcThreadAttribute", "type": "CALL"},
                {"from": "0x401020", "target_name": "CreateProcessW", "type": "CALL"},
            ],
        },
        {"0x140099999": "explorer.exe"},
    )
    assert foreign_explorer is not None
    assert "parent_selection" not in foreign_explorer


def test_instruction_window_covers_late_consumer_in_long_function() -> None:
    rows = [{"address": hex(0x1000 + index * 4), "text": "NOP"} for index in range(600)]
    rows[571] = {"address": hex(0x1000 + 571 * 4), "text": "CALL [resolved_slot]"}
    indexes = select_instruction_window_indices(rows, max_items=64, context=2)
    assert len(indexes) == 64
    assert 571 in indexes
    assert any(index >= 569 for index in indexes)


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
