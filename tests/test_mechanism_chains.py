from threat_report_agent.agents import StaticAnalysisAgent
from threat_report_agent.prompts import PromptRegistry
from threat_report_agent.static_analysis import (
    analyze_xor_decode_window,
    build_cross_function_chains,
    correlate_data_references,
    derive_function_mechanism_facts,
    resolve_static_data_strings,
    verify_xor_decode_candidate,
    decode_windows_process_creation_flags,
)
from threat_report_agent.simulation_adapters import static_phase_simulation_evidence


def _function(*names: str) -> dict[str, object]:
    return {
        "name": "FUN_test",
        "entry": "140001000",
        "entry_rva": 4096,
        "references_from": [
            {"from": f"1400010{i:02x}", "to": "EXTERNAL", "target_name": name, "type": "CALL"}
            for i, name in enumerate(names)
        ],
        "instructions": [],
    }


def test_function_chain_requires_related_ordered_observations() -> None:
    facts = derive_function_mechanism_facts(
        _function("InitializeProcThreadAttributeList", "UpdateProcThreadAttribute", "CreateProcessW"),
        subject="sample.exe",
    )

    assert any(item.value["chain_type"] == "process_execution" for item in facts)
    chain = next(item for item in facts if item.value["chain_type"] == "process_execution")
    assert chain.value["entry_rva"] == 4096
    assert [step["name"] for step in chain.value["steps"]] == [
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "CreateProcessW",
    ]


def test_isolated_api_does_not_become_a_mechanism_chain() -> None:
    facts = derive_function_mechanism_facts(_function("CreateProcessW"), subject="sample.exe")
    assert facts == ()


def test_chain_claim_is_mechanism_finding_with_static_limit() -> None:
    prompts = PromptRegistry.load_builtin()
    agent = StaticAnalysisAgent(prompts, "test")
    facts = derive_function_mechanism_facts(
        _function("GetProcAddress", "WinHttpOpen", "WriteFile", "CreateProcessW"),
        subject="sample.exe",
    )

    claims = agent.propose_claims(facts, "sample.exe")
    assert claims
    claim = next(item for item in claims if item.action == "exhibits_mechanism_chain")
    assert claim.fact_indexes
    assert "runtime execution" in claim.condition


def test_xor_window_records_loop_shape_without_decoding_sample_code() -> None:
    window = [
        {"mnemonic": "MOV", "text": "MOV ECX,0x1f"},
        {"mnemonic": "XOR", "text": "XOR DL,BL"},
        {"mnemonic": "ADD", "text": "ADD RAX,0x1"},
        {"mnemonic": "XOR", "text": "XOR DL,0x7"},
        {"mnemonic": "JNZ", "text": "JNZ 0x14001020"},
    ]
    result = analyze_xor_decode_window(window)
    assert result is not None
    assert result["algorithm"] == "xor_loop_candidate"
    assert result["verification"].startswith("structural_only")
    assert 31 in result["immediate_constants"]


def test_data_references_are_correlated_only_when_address_is_known() -> None:
    result = correlate_data_references(
        {
            "references_from": [
                {"from": "1000", "to": "2000", "type": "DATA"},
                {"from": "1001", "to": "API", "type": "CALL", "target_name": "HttpSend"},
            ]
        },
        {"2000": "https://example.invalid/gate"},
    )
    assert result == ({
        "from": "1000",
        "to": "2000",
        "reference_type": "DATA",
        "target_name": None,
        "resolved_string": "https://example.invalid/gate",
    },)


def test_cross_function_chains_require_multiple_function_categories() -> None:
    functions = [
        _function("GetProcAddress", "WinHttpOpen"),
        {
            **_function("CreateProcessW", "RegSetValueExW"),
            "name": "FUN_child",
        },
    ]
    functions[0]["references_from"].append({
        "from": "1002", "to": "1003", "type": "CALL", "target_function": "FUN_child",
    })
    chains = build_cross_function_chains(functions)
    assert chains
    assert chains[0]["functions"] == ["FUN_test", "FUN_child"]
    assert "network" in chains[0]["categories"]
    assert "execution" in chains[0]["categories"]


def test_static_data_string_resolution_uses_pe_section_mapping() -> None:
    content = b"\x00" * 0x20 + b"https://example.invalid/gate\x00"
    summary = {
        "image_base": 0x400000,
        "sections": [{"virtual_address": 0x1000, "virtual_size": 0x100, "raw_offset": 0x20, "raw_size": 0x100}],
    }
    assert resolve_static_data_strings(content, ["0x401000"], summary)["0x401000"].startswith("https://")


def test_simulation_probe_is_honest_and_never_allows_execution() -> None:
    evidence = static_phase_simulation_evidence()
    assert evidence["sample_execution"] is False
    assert evidence["network_access"] is False
    assert all(item["allowed"] is False for item in evidence["capabilities"])


def test_xor_key_table_counter_formula_is_replayed_without_execution() -> None:
    key_table = [0xB6, 0x90, 0x01, 0x6A]
    plaintext = b"http://x.example/gate"
    counter_initial = 3
    counter_step = 7
    ciphertext = bytes(
        value ^ key_table[index % len(key_table)] ^ ((counter_initial + index * counter_step) & 0xFF)
        for index, value in enumerate(plaintext)
    )
    result = verify_xor_decode_candidate(
        {
            "memory_addresses": [0],
            "key_table_candidates": [key_table],
            "counter_initial": counter_initial,
            "counter_step": counter_step,
        },
        ciphertext,
        {},
        max_bytes=len(ciphertext),
    )
    assert result["status"] == "VERIFIED_STATIC_DATA"
    assert result["formula"] == "key_table_modulo_xor_counter"
    assert result["decoded_preview"].startswith("http://")


def test_process_creation_flags_do_not_overclaim_suspended_or_console_modes() -> None:
    result = decode_windows_process_creation_flags(0x09080008)
    assert result["set_flags"] == ["DETACHED_PROCESS", "EXTENDED_STARTUPINFO_PRESENT", "CREATE_NO_WINDOW"]
    assert result["contains_create_suspended"] is False
    assert result["contains_create_new_console"] is False
    assert result["runtime_effect_proven"] is False


def test_function_mechanism_facts_capture_process_flag_semantics() -> None:
    function = _function("CreateProcessW")
    function["instructions"] = [{"mnemonic": "MOV", "text": "CreateProcessW flags=0x09080008"}]
    facts = derive_function_mechanism_facts(function, subject="sample.exe")
    flag_fact = next(item for item in facts if item.kind == "process_creation_flags")
    decoded = flag_fact.value["flags"][0]
    assert "EXTENDED_STARTUPINFO_PRESENT" in decoded["set_flags"]
    assert decoded["contains_create_suspended"] is False


def test_execution_claim_includes_process_flag_semantics() -> None:
    prompts = PromptRegistry.load_builtin()
    agent = StaticAnalysisAgent(prompts, "test")
    function = _function("CreateProcessW")
    function["instructions"] = [{"mnemonic": "MOV", "text": "CreateProcessW flags=0x09080008"}]
    facts = derive_function_mechanism_facts(function, subject="sample.exe")
    claims = agent.propose_claims(facts, "sample.exe")
    execution = next(item for item in claims if item.module == "execution")
    assert "0x09080008" in execution.statement
    assert "runtime execution is not proven" in execution.statement
