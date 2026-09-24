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
    unique_plausible_creation_flag,
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


def test_credible_creation_flags_rejects_timeout_and_infinite_immediates() -> None:
    """G1 §5.4: only a credible dwCreationFlags immediate may become HOW.

    ``0x000f4240`` is 1,000,000 ms (a WaitForSingleObject timeout). Its bit 19
    coincides with EXTENDED_STARTUPINFO_PRESENT, so the coarse plausibility table
    accepts it; the credibility gate must not.
    """
    from threat_report_agent.static_analysis import (
        credible_windows_process_creation_flags,
        plausible_windows_process_creation_flags,
    )

    assert credible_windows_process_creation_flags(0x00080000)
    assert credible_windows_process_creation_flags(0x09080008)
    assert not credible_windows_process_creation_flags(0x000F4240)
    assert not credible_windows_process_creation_flags(0xFFFFFFFF)
    assert not credible_windows_process_creation_flags(0)
    # The coarse predicate is deliberately unchanged (callers still rely on it).
    assert plausible_windows_process_creation_flags(0x000F4240)


def test_trace_path_does_not_stamp_timeout_immediate_as_creation_flags(test_settings) -> None:
    """G1 §5.4: the TRACE_API_ARGUMENT add-site must consult the credibility gate.

    MIGRATED in P3.3e's giant move to the add-site's NEW home, then CONVERTED to a BEHAVIOURAL assertion in P3.7
    (the source-text form asserted `"plausible_traced_creation_flags(parsed_flags)" in source`, which read the
    CLASS the add-site used to live in and broke the moment the giant moved out - exactly the hazard the P3.3e
    design documents under "no test uses getsource on it" being a weaker mitigation than it reads; this site is
    listed as NEGATIVE in `docs/p37-getsource-conversion-plan-20260922.md`).

    Behavioural form: run the trace add-site and check what it PUBLISHES. The old exclusion only rejected
    `0xFFFFFFFF`/`0xFFFFFFFE`, so `0x000f4240` - a WaitForSingleObject timeout whose bit 19 coincides with
    EXTENDED_STARTUPINFO_PRESENT - used to become a `process_creation_flags` row. The assertion below is that a
    timeout immediate is NOT stamped, while a credible `dwCreationFlags` immediate still is.
    """
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.investigation.derivation import (
        _derive_investigation_observations,
        plausible_traced_creation_flags,
    )
    from threat_report_agent.investigation import ActionSpec, ActionType
    from threat_report_agent.service import AnalysisService
    from types import SimpleNamespace

    assert plausible_traced_creation_flags(0x00080000) == 0x00080000
    assert plausible_traced_creation_flags(0x000F4240) is None
    assert plausible_traced_creation_flags(0xFFFFFFFF) is None
    assert plausible_traced_creation_flags(None) is None

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )

    def _rows(instructions: list[dict[str, object]]) -> list[SimpleNamespace]:
        return [
            SimpleNamespace(
                id="ctx-1",
                artifact_id="artifact-1",
                kind="function_context",
                value={
                    "name": "FUN_spawn",
                    "entry": "0x401000",
                    "call_targets": [{"target_name": "CreateProcessW", "from": "0x401020"}],
                },
                anchor={"function_entry": "0x401000"},
            ),
            SimpleNamespace(
                id="ins-1",
                artifact_id="artifact-1",
                kind="function_instruction_window",
                value={"entry": "0x401000", "instructions": instructions},
                anchor={"function_entry": "0x401000"},
            ),
            SimpleNamespace(
                id="call-1",
                artifact_id="artifact-1",
                kind="function_call",
                value={"api": "CreateProcessW", "from": "0x401020"},
                anchor={"function_entry": "0x401000", "callsite": "0x401020"},
            ),
        ]

    def _flags(instructions: list[dict[str, object]]) -> list[str]:
        action = ActionSpec(
            id="trace-create-flags",
            action_type=ActionType.TRACE_API_ARGUMENT,
            thread_id="thread-1",
            hypothesis_id="hyp-1",
            artifact_id="artifact-1",
            target_selector={"target": "CreateProcessW"},
            source_evidence_ids=("ctx-1", "ins-1", "call-1"),
        )
        observations = _derive_investigation_observations(service, _rows(instructions), action)
        return [
            str(item["value"].get("creation_flags"))
            for item in observations
            if item["kind"] == "process_creation_flags"
        ]

    # A credible dwCreationFlags immediate (0x08000008) IS stamped at the add-site.
    credible = _flags(
        [
            {"address": "0x401014", "text": "MOV dword ptr [RSP+0x28], 0x08000008"},
            {"address": "0x401020", "text": "CALL CreateProcessW"},
        ]
    )
    assert credible, (
        "the add-site no longer stamps a credible dwCreationFlags immediate: " f"{credible}"
    )
    assert set(credible) == {"0x08000008"}, (
        "a credible dwCreationFlags immediate was not the only value stamped at the add-site: " f"{credible}"
    )
    # A 1,000,000 ms WaitForSingleObject timeout is NOT stamped, even though bit 19 is set in it.
    assert _flags(
        [
            {"address": "0x401014", "text": "MOV dword ptr [RSP+0x28], 0x000f4240"},
            {"address": "0x401020", "text": "CALL CreateProcessW"},
        ]
    ) == [], (
        "a WaitForSingleObject timeout immediate was stamped as dwCreationFlags at the TRACE add-site, so the "
        "credibility gate is not consulted there"
    )
    # INFINITE must not be stamped either.
    assert _flags(
        [
            {"address": "0x401014", "text": "MOV dword ptr [RSP+0x28], 0xffffffff"},
            {"address": "0x401020", "text": "CALL CreateProcessW"},
        ]
    ) == []


def test_unique_plausible_creation_flag_ignores_timeouts_and_mixed_immediates() -> None:
    assert unique_plausible_creation_flag(
        ("PUSH 0x09080008", "CALL CreateProcessW"),
    ) == "0x09080008"
    assert unique_plausible_creation_flag(
        ("MOV ECX, 0xffffffff", "PUSH 0x09080008", "CALL CreateProcessW"),
    ) == "0x09080008"
    assert unique_plausible_creation_flag(
        ("PUSH 0x08000008", "PUSH 0x09080008", "CALL CreateProcessW"),
    ) is None


def test_function_mechanism_facts_decode_createprocess_flags_from_push_immediates() -> None:
    """Ghidra keeps the flag immediate on PUSH/MOV, not on the CALL line."""
    function = _function("CreateProcessW")
    function["instructions"] = [
        {"address": "140001010", "text": "PUSH 0x09080008"},
        {"address": "140001012", "text": "PUSH 0x0"},
        {"address": "140001014", "text": "CALL dword ptr [CreateProcessW]"},
    ]
    facts = derive_function_mechanism_facts(function, subject="sample.exe")
    flag_fact = next(item for item in facts if item.kind == "process_creation_flags")
    decoded = flag_fact.value["flags"][0]
    assert decoded["value"] == "0x09080008"
    assert "CREATE_NO_WINDOW" in decoded["set_flags"]
    assert "EXTENDED_STARTUPINFO_PRESENT" in decoded["set_flags"]
    assert decoded["contains_create_suspended"] is False
    assert decoded["contains_create_new_console"] is False


def test_function_mechanism_facts_do_not_decode_infinite_as_create_suspended() -> None:
    """WaitForSingleObject(0xffffffff) is not dwCreationFlags=CREATE_SUSPENDED."""
    function = _function("CreateProcessW")
    function["instructions"] = [
        {"address": "140001010", "text": "PUSH 0x09080008"},
        {"address": "140001012", "text": "CALL WaitForSingleObject"},
        {"address": "140001018", "text": "MOV ECX, 0xffffffff"},
        {"address": "14000101e", "text": "CALL dword ptr [CreateProcessW]"},
    ]
    facts = derive_function_mechanism_facts(function, subject="sample.exe")
    flag_fact = next(item for item in facts if item.kind == "process_creation_flags")
    values = [str(item.get("value")) for item in flag_fact.value["flags"] if isinstance(item, dict)]
    assert "0x09080008" in values
    assert "0xffffffff" not in values
    assert all(item.get("contains_create_suspended") is False for item in flag_fact.value["flags"])


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
