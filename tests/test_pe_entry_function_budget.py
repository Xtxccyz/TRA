from types import SimpleNamespace

from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog
from threat_report_agent.dataflow import (
    catalog_output_consumer_relation,
    catalog_parent_handle_identity,
    catalog_relation_from_api_fields,
    catalog_relation_from_parent_attribute,
    catalog_relation_from_resolved_api,
    catalog_resolved_pointer_identity,
)
from threat_report_agent.investigation import (
    ActionType,
    GateDecision,
    InvestigationEvent,
    InvestigationResult,
    InvestigationThreadState,
    MechanismPlaybookRegistry,
    Verifier,
    verify_xor_mechanism,
)
from threat_report_agent.models import Evidence
from threat_report_agent.service import (
    AnalysisService,
    _HOW_SEED_CATEGORIES,
    _seed_context_rows,
    _seed_playbook,
    scoped_investigation_action_key,
)


def test_ghidra_function_budget_pins_pe_entry_without_api_signal() -> None:
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "CreateProcessW"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, *noise],
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=96,
    )
    assert len(selected) == 96
    assert any(item.get("name") == "CRTStartup" for item in selected)


def test_ghidra_function_budget_pins_unique_thread_start_routine() -> None:
    """Resume FUN_140038ae0 is the CreateThread target; WaitForSingleObject must stay in budget."""
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    creator = {
        "name": "FUN_1400440b9",
        "entry": "0x1400440b9",
        "entry_rva": 0x440b9,
        "references_from": [{"type": "call", "target_name": "CreateThread"}],
        "xrefs_to_entry": [1],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["lea", "call"],
        "instructions": [
            {"address": "0x1400440b0", "text": "LEA R8,[0x140038ae0]"},
            {"address": "0x1400440b9", "text": "CALL CreateThread"},
        ],
    }
    start = {
        "name": "FUN_140038ae0",
        "entry": "0x140038ae0",
        "entry_rva": 0x38ae0,
        "references_from": [
            {"type": "call", "target_name": "WaitForSingleObject"},
            {"type": "call", "target_name": "ExitThread"},
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["call"],
        "instructions": [
            {"text": "CALL WaitForSingleObject"},
            {"text": "CALL ExitThread"},
        ],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "CreateProcessW"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, creator, start, *noise],
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=96,
    )
    names = {str(item.get("name")) for item in selected}
    assert "FUN_140038ae0" in names
    assert "FUN_1400440b9" in names


def test_ghidra_function_budget_pins_unique_thread_start_via_iat_thunk() -> None:
    """HOW4 missed FUN_140038ae0 because CreateThread was an unnamed IAT JMP thunk."""
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    thunk = {
        "name": "FUN_140046900",
        "entry": "0x140046900",
        "entry_rva": 0x46900,
        "references_from": [],
        "xrefs_to_entry": [],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["jmp"],
        "instructions": [
            {"address": "0x140046900", "text": "JMP qword ptr [PTR_CreateThread_14005e600]"},
        ],
    }
    creator = {
        "name": "FUN_1400440b9",
        "entry": "0x1400440b9",
        "entry_rva": 0x440b9,
        "references_from": [
            {
                "type": "UNCONDITIONAL_CALL",
                "from": "0x1400440b9",
                "to": "140046900",
                "target_name": "FUN_140046900",
            }
        ],
        "xrefs_to_entry": [1],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["lea", "call"],
        "instructions": [
            {"address": "0x1400440b0", "text": "LEA R8,FUN_140038ae0"},
            {"address": "0x1400440b9", "text": "CALL 0x140046900"},
        ],
    }
    start = {
        "name": "FUN_140038ae0",
        "entry": "0x140038ae0",
        "entry_rva": 0x38ae0,
        "references_from": [
            {"type": "call", "target_name": "WaitForSingleObject"},
            {"type": "call", "target_name": "ExitThread"},
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["call"],
        "instructions": [
            {"text": "CALL WaitForSingleObject"},
            {"text": "CALL ExitThread"},
        ],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "CreateProcessW"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, thunk, creator, start, *noise],
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=96,
    )
    names = {str(item.get("name")) for item in selected}
    assert "FUN_140038ae0" in names
    assert "CRTStartup" in names


def test_ghidra_function_budget_pins_thread_start_from_pe_code_signals() -> None:
    """HOW5: Capstone recovered lpStartAddress=0x140038ae0; Ghidra rows had no CreateThread LEA."""
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    start = {
        "name": "FUN_140038ae0",
        "entry": "0x140038ae0",
        "entry_rva": 0x38ae0,
        "references_from": [
            {"type": "call", "target_name": "WaitForSingleObject"},
            {"type": "call", "target_name": "ExitThread"},
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["call"],
        "instructions": [
            {"text": "CALL WaitForSingleObject"},
            {"text": "CALL ExitThread"},
        ],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "CreateProcessW"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, start, *noise],
        {
            "entry_rva": 0x1420,
            "image_base": 0x140000000,
            "code_signals": {
                "api_calls": [
                    {
                        "api": "kernel32.dll!CreateThread",
                        "address": 0x440B9,
                        "arguments": [
                            {
                                "index": 2,
                                "name": "lpStartAddress",
                                "value": "0x140038ae0",
                                "resolved": True,
                            }
                        ],
                    }
                ]
            },
        },
        limit=96,
    )
    names = {str(item.get("name")) for item in selected}
    assert "FUN_140038ae0" in names
    assert "CRTStartup" in names


def test_ghidra_function_budget_pins_functions_that_xref_recovered_xor_vas() -> None:
    """Resume-shaped .rdata XOR consumers must not fall out of the 96-function page."""
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    consumer = {
        "name": "use_decoded_url",
        "entry": "0x140003000",
        "entry_rva": 0x3000,
        "references_from": [
            {"type": "DATA", "from": "0x140003010", "to": "0x14004c8e1", "target_name": "DAT_14004c8e1"}
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["lea", "call"],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "CreateProcessW"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, consumer, *noise],
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=96,
        pin_data_addresses=(0x14004C8E1,),
    )
    assert any(item.get("name") == "CRTStartup" for item in selected)
    assert any(item.get("name") == "use_decoded_url" for item in selected)


def test_ghidra_function_budget_pins_createprocess_thunk_callers() -> None:
    """Resume FUN_140004605 calls IAT thunk FUN_140046948, not a named CreateProcessW import."""
    crt = {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }
    wrapper = {
        "name": "FUN_140004605",
        "entry": "0x140004605",
        "entry_rva": 0x4605,
        "references_from": [
            {
                "type": "UNCONDITIONAL_CALL",
                "from": "140008dce",
                "to": "140046948",
                "target_name": "FUN_140046948",
            }
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["lea", "call"],
        "instructions": [{"address": "140008dce", "text": "CALL 0x140046948"}],
    }
    noise = [
        {
            "name": f"helper_{index}",
            "entry": hex(0x2000 + index),
            "entry_rva": 0x2000 + index,
            "references_from": [{"type": "call", "target_name": "printf"}],
            "xrefs_to_entry": [1],
            "cfg_blocks": [{"id": 1}],
            "mnemonics": ["mov", "call"],
        }
        for index in range(200)
    ]
    selected = AnalysisService.select_ghidra_function_rows(
        [crt, wrapper, *noise],
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=96,
        pin_data_addresses=(0x140046948,),
    )
    assert any(item.get("name") == "FUN_140004605" for item in selected)
    assert AnalysisService._is_process_creation_call_row(
        wrapper["references_from"][0],
        {0x140046948: "CreateProcessW"},
    )


def test_recovered_config_xrefs_are_collected_outside_the_function_page() -> None:
    consumer = {
        "name": "FUN_140004605",
        "entry": "140004605",
        "references_from": [
            {"type": "DATA", "from": "14000552b", "to": "14004c8e1", "target_name": "DAT_14004c8e1"},
            {"type": "UNCONDITIONAL_CALL", "from": "140005540", "to": "140001000", "target_name": "FUN_140001000"},
        ],
    }
    noise = {
        "name": "helper",
        "entry": "140002000",
        "references_from": [{"type": "DATA", "from": "140002010", "to": "140010000"}],
    }
    rows = AnalysisService._collect_recovered_config_xrefs(
        [noise, consumer],
        (0x14004C8E1,),
        image_base=0x140000000,
    )
    assert len(rows) == 1
    assert rows[0]["function"] == "FUN_140004605"
    assert rows[0]["from"] == "14000552b"
    assert rows[0]["link_kind"] == "decoded_va_reference"


def test_function_context_keeps_late_xor_data_refs_inside_the_48_slot_page() -> None:
    early = [
        {"from": hex(0x140003000 + index), "to": hex(0x140010000 + index), "type": "DATA"}
        for index in range(80)
    ]
    xor_ref = {"from": "14000552b", "to": "14004c8e1", "type": "DATA", "target_name": "DAT_14004c8e1"}
    ranked = AnalysisService._prioritize_config_data_references(
        [*early, xor_ref],
        (0x14004C8E1,),
        image_base=0x140000000,
        limit=48,
    )
    assert ranked[0]["to"] == "14004c8e1"
    assert len(ranked) == 48


def test_instruction_window_keeps_late_xor_lea_inside_the_256_op_budget() -> None:
    instructions = [
        {"address": hex(0x140004605 + index), "mnemonic": "CALL", "text": "CALL 0x140001000"}
        for index in range(300)
    ]
    instructions[280] = {
        "address": "14000783a",
        "mnemonic": "LEA",
        "text": "LEA R14,[0x14004c8e1]",
    }
    selected = AnalysisService.instruction_indices_referencing_addresses(
        instructions,
        (0x14004C8E1,),
        ({"from": "14000783a", "to": "14004c8e1"},),
        image_base=0x140000000,
    )
    assert 280 in selected
    window = set(range(16)) | set(range(284, 300)) | selected
    assert 280 in window


def test_instruction_window_keeps_late_createprocess_callsite() -> None:
    instructions = [
        {"address": hex(0x140004605 + index), "mnemonic": "NOP", "text": "NOP"}
        for index in range(300)
    ]
    instructions[270] = {
        "address": "140008dce",
        "mnemonic": "CALL",
        "text": "CALL 0x140046948",
    }
    selected = AnalysisService.instruction_indices_referencing_addresses(
        instructions,
        (),
        ({"from": "140008dce", "to": "140046948", "target_name": "CreateProcessW"},),
        image_base=0x140000000,
    )
    assert 270 in selected


def test_instruction_window_keeps_createprocess_flag_and_command_lookback() -> None:
    """Resume FUN_140004605: flags and command LEA sit well before the IAT thunk CALL."""
    instructions = [
        {"address": hex(0x140004605 + index), "mnemonic": "NOP", "text": "NOP"}
        for index in range(300)
    ]
    instructions[150] = {
        "address": "140008c00",
        "mnemonic": "MOV",
        "text": "MOV dword ptr [RSP + 0x28], 0x00080000",
    }
    instructions[250] = {
        "address": "140008dc0",
        "mnemonic": "LEA",
        "text": "LEA R15,[0x14005000]",
    }
    instructions[270] = {
        "address": "140008dce",
        "mnemonic": "CALL",
        "text": "CALL 0x140046948",
    }
    nearby = AnalysisService.instruction_indices_referencing_addresses(
        instructions,
        (0x140046948,),
        ({"from": "140008dce", "to": "140046948", "target_name": "CreateProcessW"},),
        image_base=0x140000000,
    )
    assert 270 in nearby
    assert 150 not in nearby
    selected = AnalysisService.instruction_indices_referencing_addresses(
        instructions,
        (0x140046948,),
        ({"from": "140008dce", "to": "140046948", "target_name": "CreateProcessW"},),
        image_base=0x140000000,
        lookback=128,
    )
    assert {150, 250, 270} <= selected


def test_ghidra_xor_xref_emits_decode_config_catalog_contract() -> None:
    """Resume-shaped XOR + DATA xref must close config-and-crypto without DECODE_CANDIDATE."""
    hit = {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": 0x14004C8E1,
        "length": 31,
        "formula": "key_table_modulo_xor_counter",
        "key_table": [182, 144, 1, 106],
        "counter_initial": 3,
        "counter_step": 7,
        "ciphertext_hex": "aa" * 31,
        "plaintext_hex": "687474703a2f2f36392e34382e3232382e37342f6d69616f6d2d632e706466",
        "decoded_text": "http://69.48.228.74/miaom-c.pdf",
        "output_buffer": {
            "address_space": "image",
            "address": 0x14004C8E1,
            "length": 31,
        },
    }
    xrefs = [
        {
            "from": "14000552b",
            "to": "14004c8e1",
            "type": "DATA",
            "target_name": "DAT_14004c8e1",
            "function": "FUN_140004605",
            "entry": "140004605",
            "link_kind": "decoded_va_reference",
        }
    ]
    links = AnalysisService.recovered_config_consumer_links(
        [hit],
        xrefs,
        artifact_id="artifact-resume",
        image_base=0x140000000,
    )
    assert len(links) == 1
    producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {**links[0]["fields"], "consumer_status": "LINKED_STATIC"},
    }
    consumer = {
        "id": "xref-1",
        "kind": "data_reference",
        "nature": "STATIC_OBSERVED",
        "value": links[0]["consumer"],
    }
    relation = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="xref-1",
        output_buffer=links[0]["output_buffer"],
        consumer_api="FUN_140004605",
    )
    assert relation is not None
    evaluation = BehaviorCatalog().evaluate(
        "config-and-crypto",
        [
            producer,
            consumer,
            {
                "id": "flow-1",
                "kind": "value_flow",
                "nature": "STATIC_INFERRED",
                "value": relation,
            },
        ],
    )
    assert evaluation.accepted
    assert evaluation.status == "SUPPORTED_STATIC"
    assert AnalysisService.recovered_config_consumer_links(
        [hit],
        [{"from": "140001000", "to": "140010000", "type": "DATA"}],
        artifact_id="artifact-resume",
        image_base=0x140000000,
    ) == []


def test_config_consumer_seed_rows_survive_export_symbol_window() -> None:
    from types import SimpleNamespace

    noise = [
        SimpleNamespace(id=f"export-{index}", kind="export_symbol", value={"name": f"sym{index}"}, anchor={})
        for index in range(800)
    ]
    keep = [
        SimpleNamespace(
            id="decode-linked",
            kind="decode_result",
            value={"consumer_status": "LINKED_STATIC", "algorithm": "xor"},
            anchor={"type": "decoded_config_consumer"},
        ),
        SimpleNamespace(
            id="flow-linked",
            kind="value_flow",
            value={"relation": "output_to_consumer"},
            anchor={"type": "decoded_config_consumer"},
        ),
        SimpleNamespace(
            id="xref-linked",
            kind="data_reference",
            value={"link_kind": "decoded_va_reference", "to": "14004c8e1"},
            anchor={"type": "decoded_config_xref"},
        ),
        SimpleNamespace(
            id="decode-unlinked",
            kind="decode_result",
            value={"consumer_status": "NOT_IDENTIFIED"},
            anchor={},
        ),
    ]
    selected = AnalysisService.select_config_consumer_seed_rows([*noise, *keep], limit=128)
    ids = {item.id for item in selected}
    assert ids == {"decode-linked", "flow-linked", "xref-linked"}


def test_config_consumer_candidates_keep_early_links_when_later_data_refs_flood() -> None:
    """Resume had 426 data_reference rows; a mixed newest-256 window dropped all XOR xrefs."""
    from types import SimpleNamespace

    early = [
        SimpleNamespace(
            id="decode-linked",
            kind="decode_result",
            created_at=1,
            value={"consumer_status": "LINKED_STATIC"},
            anchor={"type": "decoded_config_consumer"},
        ),
        SimpleNamespace(
            id="flow-linked",
            kind="value_flow",
            created_at=1,
            value={"relation": "output_to_consumer"},
            anchor={"type": "decoded_config_consumer"},
        ),
        SimpleNamespace(
            id="xref-linked",
            kind="data_reference",
            created_at=1,
            value={"link_kind": "decoded_va_reference"},
            anchor={"type": "decoded_config_xref"},
        ),
    ]
    later_refs = [
        SimpleNamespace(
            id=f"ref-{index}",
            kind="data_reference",
            created_at=2,
            value={"to": hex(index)},
            anchor={"type": "ordinary_xref"},
        )
        for index in range(400)
    ]
    mixed_newest_256 = sorted(
        [*early, *later_refs],
        key=lambda row: (row.created_at, row.id),
        reverse=True,
    )[:256]
    mixed_ids = {item.id for item in AnalysisService.select_config_consumer_seed_rows(mixed_newest_256)}
    assert "xref-linked" not in mixed_ids

    per_kind = AnalysisService._newest_config_consumer_candidates([*early, *later_refs])
    ids = {item.id for item in AnalysisService.select_config_consumer_seed_rows(per_kind)}
    assert ids == {"decode-linked", "flow-linked", "xref-linked"}
    assert AnalysisService._CONFIG_CONSUMER_SEED_KIND_LIMITS["data_reference"] >= 512
    assert AnalysisService._CONFIG_CONSUMER_SEED_KIND_LIMITS["process_creation_flags"] >= 8


def test_config_consumer_rows_are_pinned_after_unrelated_seed_cluster_filter() -> None:
    """A WinHttp seed cluster must not drop persist-time XOR consumer links from ClaimGate."""
    seed = Evidence(
        id="seed-winhttp",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="import_symbol",
        nature="STATIC_OBSERVED",
        value={"name": "WinHttpOpen"},
        anchor={"function_entry": "0x140001000"},
    )
    decode = Evidence(
        id="decode-linked",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="decode_result",
        nature="STATIC_OBSERVED",
        value={"consumer_status": "LINKED_STATIC", "algorithm": "xor", "input_bytes": "aa"},
        anchor={"type": "decoded_config_consumer", "virtual_address": "0x14004c8e1"},
    )
    flow = Evidence(
        id="flow-linked",
        task_id="task",
        artifact_id="artifact",
        tool_run_id="run",
        module="static",
        kind="value_flow",
        nature="STATIC_INFERRED",
        value={
            "relation": "output_to_consumer",
            "source_evidence_ids": [decode.id],
            "target_evidence_ids": ["xref-linked"],
        },
        anchor={"type": "decoded_config_consumer"},
    )
    clustered = _seed_context_rows(
        [seed, decode, flow],
        {"evidence_ids": [seed.id], "category": "network", "function": "0x140001000"},
        limit=160,
    )
    clustered_ids = {row.id for row in clustered}
    assert seed.id in clustered_ids
    # The relation ClaimGate needs is dropped: its source IDs point at the
    # decoder, not at the WinHttp seed cluster.
    assert flow.id not in clustered_ids

    pinned = AnalysisService.pin_config_consumer_seed_rows(
        clustered,
        AnalysisService.select_config_consumer_seed_rows([decode, flow]),
    )
    assert {row.id for row in pinned} >= {seed.id, decode.id, flow.id}


def test_seed_playbook_claim_gate_keeps_decode_contract_when_imports_dominate() -> None:
    """A decode seed must not be ClaimGated as dynamic-api just because GetProcAddress is nearby."""
    hit = {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": 0x14004C8E1,
        "length": 31,
        "formula": "key_table_modulo_xor_counter",
        "key_table": [182, 144, 1, 106],
        "counter_initial": 3,
        "counter_step": 7,
        "ciphertext_hex": "aa" * 31,
        "plaintext_hex": "687474703a2f2f36392e34382e3232382e37342f6d69616f6d2d632e706466",
        "decoded_text": "http://69.48.228.74/miaom-c.pdf",
        "output_buffer": {
            "address_space": "image",
            "address": 0x14004C8E1,
            "length": 31,
        },
    }
    xrefs = [
        {
            "from": "14000552b",
            "to": "14004c8e1",
            "type": "DATA",
            "target_name": "DAT_14004c8e1",
            "function": "FUN_140004605",
            "entry": "140004605",
            "link_kind": "decoded_va_reference",
        }
    ]
    links = AnalysisService.recovered_config_consumer_links(
        [hit],
        xrefs,
        artifact_id="artifact-resume",
        image_base=0x140000000,
    )
    producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {**links[0]["fields"], "consumer_status": "LINKED_STATIC"},
    }
    consumer = {
        "id": "xref-1",
        "kind": "data_reference",
        "nature": "STATIC_OBSERVED",
        "value": links[0]["consumer"],
    }
    relation = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="xref-1",
        output_buffer=links[0]["output_buffer"],
        consumer_api="FUN_140004605",
    )
    evidence = [
        {
            "id": "imp-getproc",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "GetProcAddress"},
        },
        producer,
        consumer,
        {
            "id": "flow-1",
            "kind": "value_flow",
            "nature": "STATIC_INFERRED",
            "value": relation,
        },
    ]
    drifted = Verifier().evaluate(
        evidence,
        "Which encoded input, transform, decoded output, and downstream consumer form the static decode path?",
        "The artifact may contain a recoverable XOR configuration.",
    )
    assert "fact:module_input" in drifted.missing or "fact:resolver" in drifted.missing

    playbook = MechanismPlaybookRegistry().by_id("xor-config-recovery")
    seed_gate = AnalysisService.gate_for_seed_playbook(playbook, evidence)
    assert seed_gate is not None
    assert "fact:module_input" not in seed_gate.missing
    assert "fact:resolver" not in seed_gate.missing


def test_recovered_xor_fields_satisfy_decode_config_specialist() -> None:
    """Persist-time XOR fields must close DECODE_CONFIG without keyword stuffing."""
    hit = {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": 0x14004C8E1,
        "length": 31,
        "formula": "key_table_modulo_xor_counter",
        "key_table": [182, 144, 1, 106],
        "counter_initial": 3,
        "counter_step": 7,
        "ciphertext_hex": "aa" * 31,
        "plaintext_hex": "687474703a2f2f36392e34382e3232382e37342f6d69616f6d2d632e706466",
        "decoded_text": "http://69.48.228.74/miaom-c.pdf",
        "output_buffer": {
            "address_space": "image",
            "address": 0x14004C8E1,
            "length": 31,
        },
    }
    xrefs = [
        {
            "from": "14000552b",
            "to": "14004c8e1",
            "type": "DATA",
            "target_name": "DAT_14004c8e1",
            "function": "FUN_140004605",
            "entry": "140004605",
            "link_kind": "decoded_va_reference",
        }
    ]
    links = AnalysisService.recovered_config_consumer_links(
        [hit],
        xrefs,
        artifact_id="artifact-resume",
        image_base=0x140000000,
    )
    producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {**links[0]["fields"], "consumer_status": "LINKED_STATIC"},
        "anchor": {"type": "decoded_config_consumer", "entry": "140004605"},
    }
    consumer = {
        "id": "xref-1",
        "kind": "data_reference",
        "nature": "STATIC_OBSERVED",
        "value": links[0]["consumer"],
        "anchor": {"type": "decoded_config_xref", "entry": "140004605", "function": "FUN_140004605"},
    }
    relation = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="xref-1",
        output_buffer=links[0]["output_buffer"],
        consumer_api="FUN_140004605",
    )
    flow = {
        "id": "flow-1",
        "kind": "value_flow",
        "nature": "STATIC_INFERRED",
        "value": relation,
        "anchor": {"type": "decoded_config_consumer", "entry": "140004605"},
    }
    encoded = {
        "id": "blob-1",
        "kind": "encoded_blob",
        "nature": "STATIC_OBSERVED",
        "value": {"label": "encoded config block"},
        "anchor": {"entry": "140004605"},
    }
    verification = verify_xor_mechanism([encoded, producer, consumer, flow])
    assert verification.accepted is False
    assert "consumer" in verification.missing


def test_named_api_same_buffer_consumer_satisfies_decode_config_specialist() -> None:
    hit = {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": 0x14004C8E1,
        "length": 31,
        "formula": "key_table_modulo_xor_counter",
        "key_table": [182, 144, 1, 106],
        "counter_initial": 3,
        "counter_step": 7,
        "ciphertext_hex": "aa" * 31,
        "plaintext_hex": "687474703a2f2f36392e34382e3232382e37342f6d69616f6d2d632e706466",
        "decoded_text": "http://69.48.228.74/miaom-c.pdf",
        "output_buffer": {
            "address_space": "image",
            "address": 0x14004C8E1,
            "length": 31,
        },
    }
    producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {
            **hit,
            "consumer_status": "LINKED_STATIC",
        },
        "anchor": {"type": "decoded_config_consumer", "entry": "140004605"},
    }
    consumer = {
        "id": "api-1",
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "LoadLibraryW"},
        "anchor": {"type": "decoded_config_call", "entry": "140004605"},
    }
    flow = {
        "id": "flow-1",
        "kind": "value_flow",
        "nature": "STATIC_INFERRED",
        "value": catalog_output_consumer_relation(
            producer_id="decode-1",
            consumer_id="api-1",
            output_buffer={
                "artifact_id": "artifact-resume",
                "address_space": "image",
                "address": 0x14004C8E1,
                "length": 31,
            },
            consumer_api="LoadLibraryW",
        ),
        "anchor": {"type": "decoded_config_consumer", "entry": "140004605"},
    }
    encoded = {
        "id": "blob-1",
        "kind": "encoded_blob",
        "nature": "STATIC_OBSERVED",
        "value": {"label": "encoded config block"},
        "anchor": {"entry": "140004605"},
    }
    verification = verify_xor_mechanism([encoded, producer, consumer, flow])
    assert verification.accepted, verification.missing


def test_process_creation_seed_rows_survive_cluster_filter_and_export_symbol_window() -> None:
    """Persist-time CreateProcess catalog facts must not drown in export_symbol."""
    call = Evidence(
        id="call-1",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="function_call",
        nature="STATIC_OBSERVED",
        value={"api": "CreateProcessW"},
        anchor={"function_entry": "140004605"},
    )
    trace = Evidence(
        id="trace-1",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "cmd.exe /c FoxitPDFReader.exe",
            "command_line": "cmd.exe /c FoxitPDFReader.exe",
            "creation_flags": "0x00080000",
            "return_branch": "JZ 0x140004780",
        },
        anchor={"function_entry": "140004605"},
    )
    relation = catalog_relation_from_api_fields(
        "CreateProcessW",
        trace.value,
        artifact_id="artifact-resume",
        callsite="0x140004710",
        source_evidence_id="trace-1",
        target_evidence_id="call-1",
    )
    flow = Evidence(
        id="flow-proc",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value=relation,
        anchor={"function_entry": "140004605"},
    )
    exports = [
        Evidence(
            id=f"exp-{index}",
            task_id="t",
            artifact_id="a",
            tool_run_id="r",
            module="static_triage",
            kind="export_symbol",
            nature="STATIC_OBSERVED",
            value={"name": f"export_{index}"},
            anchor={},
        )
        for index in range(40)
    ]
    selected_cluster = {
        "category": "execution",
        "playbook_id": "process-execution",
        "evidence_ids": ["call-1"],
    }
    clustered = _seed_context_rows(
        [*exports, call, trace, flow],
        selected_cluster,
        limit=16,
    )
    assert call.id in {row.id for row in clustered}
    pinned = AnalysisService.pin_config_consumer_seed_rows(
        clustered,
        AnalysisService.select_process_creation_seed_rows([call, trace, flow]),
    )
    assert {row.id for row in pinned} >= {call.id, trace.id, flow.id}

    playbook = MechanismPlaybookRegistry().by_id("process-execution")
    seed_gate = AnalysisService.gate_for_seed_playbook(
        playbook,
        [
            {
                "id": call.id,
                "kind": call.kind,
                "nature": call.nature,
                "value": call.value,
            },
            {
                "id": trace.id,
                "kind": trace.kind,
                "nature": trace.nature,
                "value": trace.value,
            },
            {
                "id": flow.id,
                "kind": flow.kind,
                "nature": flow.nature,
                "value": flow.value,
            },
        ],
    )
    assert seed_gate is not None
    assert seed_gate.accepted
    assert "fact:image_or_command" not in seed_gate.missing
    assert "creation_flags" not in seed_gate.missing
    assert "command_to_process_sink" not in seed_gate.missing

    persist_ready = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=[
            {"id": call.id, "kind": call.kind, "nature": call.nature, "value": call.value},
            {"id": trace.id, "kind": trace.kind, "nature": trace.nature, "value": trace.value},
            {"id": flow.id, "kind": flow.kind, "nature": flow.nature, "value": flow.value},
        ],
        thread_id="thread-process",
        artifact_id="artifact-resume",
    )
    assert persist_ready is not None
    assert persist_ready.thread_state == InvestigationThreadState.CLAIM_READY
    assert persist_ready.actions == ()
    assert persist_ready.gate.accepted
    assert persist_ready.events[0].phase == "persist_time_claim_ready"
    assert persist_ready.coverage.get("claim_eligible") is True

    incomplete = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=[
            {
                "id": call.id,
                "kind": call.kind,
                "nature": call.nature,
                "value": call.value,
            }
        ],
        thread_id="thread-process",
        artifact_id="artifact-resume",
    )
    assert incomplete is None


def test_seed_playbook_gate_closes_when_persist_facts_exist_even_if_contract_incomplete() -> None:
    """Catalog-accepted persist facts must not wait for TRACE claim_eligible."""
    playbook = MechanismPlaybookRegistry().by_id("process-execution")
    evidence = (
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
        },
        {
            "id": "trace-1",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateProcessW",
                "command": "cmd.exe /c FoxitPDFReader.exe",
                "command_line": "cmd.exe /c FoxitPDFReader.exe",
                "creation_flags": "0x00080000",
                "return_branch": "JZ 0x140004780",
            },
        },
        {
            "id": "flow-proc",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": catalog_relation_from_api_fields(
                "CreateProcessW",
                {
                    "api": "CreateProcessW",
                    "command": "cmd.exe /c FoxitPDFReader.exe",
                    "command_line": "cmd.exe /c FoxitPDFReader.exe",
                    "creation_flags": "0x00080000",
                },
                artifact_id="artifact-resume",
                callsite="0x140004710",
                source_evidence_id="trace-1",
                target_evidence_id="call-1",
            ),
        },
    )
    result = InvestigationResult(
        thread_id="thread-process",
        artifact_id="artifact-resume",
        thread_state=InvestigationThreadState.INVESTIGATING,
        hypothesis_status="UNKNOWN",
        evidence=evidence,
        events=(),
        actions=(),
        gate=GateDecision(
            accepted=False,
            status="UNKNOWN",
            reason="placeholder",
            evidence_ids=(),
        ),
        coverage={"claim_eligible": False},
    )
    updated = AnalysisService._apply_seed_playbook_gate(result, playbook)
    assert updated.thread_state == InvestigationThreadState.CLAIM_READY
    assert updated.gate.accepted
    assert updated.hypothesis_status in {"CANDIDATE", "SUPPORTED", "VERIFIED"}


def test_process_creation_seed_rows_survive_early_empty_trace_flood() -> None:
    """Oldest-128 would keep prologue CreateProcess traces and drop recovered command/flags."""
    empty = [
        Evidence(
            id=f"empty-{index}",
            task_id="t",
            artifact_id="a",
            tool_run_id="r",
            module="static_triage",
            kind="api_argument_trace",
            nature="STATIC_OBSERVED",
            value={"api": "CreateProcessW", "function": f"FUN_{index}"},
            anchor={},
        )
        for index in range(200)
    ]
    recovered = Evidence(
        id="trace-recovered",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x00080000",
            "function": "FUN_140004605",
        },
        anchor={"function_entry": "140004605"},
    )
    flow = Evidence(
        id="flow-recovered",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value={"relation": "command_to_process_sink"},
        anchor={"type": "command_to_process_sink"},
    )
    parent = Evidence(
        id="ppid-flow",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value={"relation": "parent_handle_to_attribute"},
        anchor={"type": "parent_handle_to_attribute"},
    )
    selected = AnalysisService.select_process_creation_seed_rows([*empty, recovered, flow, parent])
    assert {row.id for row in selected} >= {recovered.id, flow.id}
    assert "empty-0" not in {row.id for row in selected}
    assert AnalysisService.select_parent_attribute_seed_rows([*empty, parent])[0].id == parent.id
    assert AnalysisService._CATALOG_HOW_SEED_SCAN_LIMIT >= 2048


def test_resolved_api_seed_rows_are_pinned_with_catalog_identity() -> None:
    pointer = catalog_resolved_pointer_identity(
        artifact_id="artifact-resume",
        callsite="140038dfd",
    )
    resolved = Evidence(
        id="resolved-1",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="resolved_api",
        nature="STATIC_DERIVED",
        value={
            "resolver": "GetProcAddress",
            "api_name": "SetThreadDescription",
            "api_identity": "SetThreadDescription",
            "module_input": "kernel32.dll",
            "consumer": "JMP R8",
            "consumer_callsite": "140038e2d",
            "consumer_kind": "JUMP",
            "string_address": "0x140054f8a",
            "resolved_pointer": pointer,
            "output_buffer": pointer,
            "consumer_pointer": pointer,
            "input_buffer": pointer,
        },
        anchor={"function_entry": "140038dd0"},
    )
    relation = catalog_relation_from_resolved_api(
        resolved.value,
        artifact_id="artifact-resume",
        source_evidence_id="resolved-1",
        target_evidence_id="resolved-1",
    )
    flow = Evidence(
        id="flow-resolved",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value=relation,
        anchor={"function_entry": "140038dd0"},
    )
    noise = [
        Evidence(
            id=f"exp-{index}",
            task_id="t",
            artifact_id="a",
            tool_run_id="r",
            module="static_triage",
            kind="export_symbol",
            nature="STATIC_OBSERVED",
            value={"name": f"export_{index}"},
            anchor={},
        )
        for index in range(40)
    ]
    clustered = _seed_context_rows(
        [*noise, resolved, flow],
        {"category": "dynamic_api", "playbook_id": "dynamic-api-resolution", "evidence_ids": []},
        limit=8,
    )
    pinned = AnalysisService.pin_config_consumer_seed_rows(
        clustered,
        AnalysisService.select_dynamic_api_seed_rows([resolved, flow]),
    )
    assert {row.id for row in pinned} >= {resolved.id, flow.id}

    playbook = MechanismPlaybookRegistry().by_id("dynamic-api-resolution")
    seed_gate = AnalysisService.gate_for_seed_playbook(
        playbook,
        [
            {
                "id": resolved.id,
                "kind": resolved.kind,
                "nature": resolved.nature,
                "value": resolved.value,
                "anchor": resolved.anchor,
            },
            {
                "id": flow.id,
                "kind": flow.kind,
                "nature": flow.nature,
                "value": flow.value,
                "anchor": flow.anchor,
            },
        ],
    )
    assert seed_gate is not None
    assert seed_gate.accepted
    assert "resolved_pointer_to_call" not in seed_gate.missing
    assert "module_input" not in seed_gate.missing
    assert "resolver identity" not in seed_gate.missing


def test_callees_and_function_failures_alternate_to_decompile_then_emulate() -> None:
    assert AnalysisService.convergence_alternate_type(ActionType.GET_CALLEES) == ActionType.GET_DECOMPILE
    assert AnalysisService.convergence_alternate_type(ActionType.GET_FUNCTION) == ActionType.GET_DECOMPILE
    assert AnalysisService.convergence_alternate_type(ActionType.GET_DECOMPILE) == ActionType.CONTROLLED_EMULATE


def test_parent_attribute_seed_rows_are_pinned_and_process_playbook_stays_bound() -> None:
    """PPID persist rows survive the seed window; execution cluster keeps process-execution."""
    parent_handle = catalog_parent_handle_identity(
        artifact_id="artifact-resume",
        handle_id="openprocess:0x140008b10",
    )
    attribute_handle = catalog_parent_handle_identity(
        artifact_id="artifact-resume",
        handle_id="updateprocthreadattribute:0x140008b28",
    )
    trace = Evidence(
        id="trace-ppid",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "FoxitPDFReader.exe",
            "creation_flags": "0x00080000",
            "parent_selection": "explorer.exe",
            "access_mask": "PROCESS_CREATE_PROCESS",
            "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            "startup_info": "STARTUPINFOEX",
            "open_process": "OpenProcess",
            "parent_handle": parent_handle,
            "attribute_handle": attribute_handle,
        },
        anchor={"function_entry": "140004605"},
    )
    relation = catalog_relation_from_parent_attribute(
        trace.value,
        artifact_id="artifact-resume",
        source_evidence_id="trace-ppid",
        target_evidence_id="trace-ppid",
        callsite="0x140008b28",
    )
    flow = Evidence(
        id="flow-ppid",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="value_flow",
        nature="STATIC_DERIVED",
        value=relation,
        anchor={"function_entry": "140004605"},
    )
    noise = [
        Evidence(
            id=f"noise-{index}",
            task_id="t",
            artifact_id="a",
            tool_run_id="r",
            module="static_triage",
            kind="export_symbol",
            nature="STATIC_OBSERVED",
            value={"name": f"export_{index}"},
            anchor={},
        )
        for index in range(40)
    ]
    clustered = _seed_context_rows(
        [*noise, trace, flow],
        {"category": "ppid", "playbook_id": "ppid-process-chain", "evidence_ids": ["trace-ppid"]},
        limit=8,
    )
    pinned = AnalysisService.pin_config_consumer_seed_rows(
        clustered,
        AnalysisService.select_parent_attribute_seed_rows([trace, flow]),
    )
    assert {row.id for row in pinned} >= {trace.id, flow.id}

    catalog = BehaviorCatalog()
    contract = catalog.evaluate(
        "parent-process-spoofing",
        [
            {"id": trace.id, "kind": trace.kind, "nature": trace.nature, "value": trace.value},
            {"id": flow.id, "kind": flow.kind, "nature": flow.nature, "value": flow.value},
        ],
    )
    assert contract.accepted
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    seed_gate = AnalysisService.gate_for_seed_playbook(
        playbook,
        [
            {"id": trace.id, "kind": trace.kind, "nature": trace.nature, "value": trace.value, "anchor": trace.anchor},
            {"id": flow.id, "kind": flow.kind, "nature": flow.nature, "value": flow.value, "anchor": flow.anchor},
        ],
    )
    assert seed_gate is not None
    assert seed_gate.accepted is False
    assert "0x09080008" not in str(trace.value)
    ppid_rows = [
        {"id": trace.id, "kind": trace.kind, "nature": trace.nature, "value": trace.value, "anchor": trace.anchor},
        {"id": flow.id, "kind": flow.kind, "nature": flow.nature, "value": flow.value, "anchor": flow.anchor},
    ]
    persist_ready = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=ppid_rows,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert persist_ready is not None
    assert persist_ready.thread_state == InvestigationThreadState.CLAIM_READY
    assert persist_ready.hypothesis_status == "CANDIDATE"
    assert persist_ready.actions == ()
    persist_boundary = AnalysisService.persist_time_static_boundary(
        playbook=playbook,
        evidence=ppid_rows,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert persist_boundary is not None
    assert persist_boundary.thread_state == InvestigationThreadState.UNKNOWN
    assert persist_boundary.actions == ()
    assert persist_boundary.events[0].phase == "persist_time_static_boundary"
    assert persist_boundary.coverage.get("claim_eligible") is False
    registry = MechanismPlaybookRegistry()
    execution_playbook = _seed_playbook(
        registry,
        {"category": "execution", "playbook_id": "process-execution"},
    )
    assert execution_playbook is not None
    assert execution_playbook.id == "process-execution"


def test_ppid_how_seed_claim_ready_from_parent_attribute_immediate() -> None:
    """HOW9 leftover recovered Attribute=0x20000; PPID thread stayed empty UNKNOWN."""
    open_only = {
        "id": "call-open",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "OpenProcess"},
    }
    update = {
        "id": "call-update",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
    }
    summary = {
        "id": "sem-1",
        "kind": "function_semantic_summary",
        "nature": "STATIC_DERIVED",
        "value": {
            "text": "UpdateProcThreadAttribute(Attribute=0x20000) -> CreateProcessW",
            "function_entry": "140004605",
        },
    }
    flags = {
        "id": "flags-1",
        "kind": "process_creation_flags",
        "nature": "STATIC_DERIVED",
        "value": {"flags": [{"value": "0x00080000"}]},
    }
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    assert not AnalysisService._persist_partial_how_ready("ppid-process-chain", [open_only])
    assert not AnalysisService._persist_partial_how_ready("ppid-process-chain", [flags])
    evidence = [open_only, update, summary, flags]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert result is not None
    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-ppid",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
        )
    )
    assert row["status"] == "CANDIDATE"
    assert "0x00020000" in blob or "0x20000" in blob.replace(" ", "")
    assert "0x09080008" not in blob.replace(" ", "")
    assert "UNKNOWN(parent" in blob or "UNKNOWN(parent identity)" in str(row.get("inputs"))


def test_ppid_how_uses_explorer_parent_not_openprocess_handle_dict() -> None:
    """HOW11 leftover printed parent={'artifact_id': ..., 'handle_id': 'openprocess:...'}."""
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    evidence = [
        {
            "id": "call-update",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
        },
        {
            "id": "flow-handle",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "parent_handle_to_attribute",
                "parent_handle": {
                    "artifact_id": "b8437ca0-f4df-4cec-aed3-9bd801cf79d1",
                    "handle_id": "openprocess:140008cfb",
                },
            },
        },
        {
            "id": "trace-parent",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "0x20000",
                "parent_selection": "explorer.exe",
            },
        },
    ]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert result is not None
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-ppid",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
            row.get("outputs") or [],
        )
    )
    assert "explorer.exe" in blob.casefold()
    assert "UNKNOWN(parent" not in blob
    assert "artifact_id" not in blob
    assert "openprocess:" not in blob.casefold()


def test_ppid_how_joins_explorer_string_with_process32_enumeration() -> None:
    """HOW12 leftover had Attribute=0x20000 but never printed explorer.exe."""
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    evidence = [
        {
            "id": "call-update",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
        },
        {
            "id": "flow-handle",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "parent_handle_to_attribute",
                "parent_handle": {
                    "artifact_id": "b8437ca0-f4df-4cec-aed3-9bd801cf79d1",
                    "handle_id": "openprocess:140008cfb",
                },
            },
        },
        {
            "id": "str-explorer",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
        },
        {
            "id": "call-enum",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "Process32FirstW"},
        },
    ]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert result is not None
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-ppid",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
            row.get("outputs") or [],
        )
    )
    assert "explorer.exe" in blob.casefold()
    assert "UNKNOWN(parent" not in blob
    assert "artifact_id" not in blob
    assert "openprocess:" not in blob.casefold()
    assert "0x09080008" not in blob.replace(" ", "")


def test_ppid_how_ignores_explorer_string_without_process_enumeration() -> None:
    """A lone explorer.exe string is not parent identity without Process32 enumeration."""
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    evidence = [
        {
            "id": "call-update",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
        },
        {
            "id": "str-explorer",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
        },
    ]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert result is not None
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-ppid",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
            row.get("outputs") or [],
        )
    )
    assert "UNKNOWN(parent" in blob or "UNKNOWN(parent identity)" in str(row.get("inputs"))
    assert "artifact_id" not in blob


def test_ppid_how_does_not_treat_process32_import_listing_as_enumeration() -> None:
    """IAT Process32FirstW is not a snapshot-enum chain; explorer.exe stays unproven."""
    playbook = MechanismPlaybookRegistry().by_id("ppid-process-chain")
    evidence = [
        {
            "id": "call-update",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute", "attribute": "0x20000"},
        },
        {
            "id": "str-explorer",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe"},
        },
        {
            "id": "sym-enum",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "Process32FirstW", "external": True, "address": "140046000"},
        },
    ]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-ppid",
        artifact_id="artifact-resume",
    )
    assert result is not None
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-ppid",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
            row.get("outputs") or [],
        )
    )
    assert "UNKNOWN(parent" in blob
    assert "explorer.exe" not in blob.casefold()
    assert "0x09080008" not in blob.replace(" ", "")


def _record_ghidra_evidence_rows(
    test_settings, output: dict[str, object]
) -> list[object]:
    """Run the real Ghidra evidence recording over a minimal task; return the persisted rows."""
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database
    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, ToolRun

    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("ghidra ranked symbols")
    stored = store.put(b"MZ static fixture")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="fixture.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
            parameters={},
            environment={"sample_execution": False},
            output=output,
        )
        session.add(tool_run)
        session.flush()
        service.record_ghidra_evidence(session, task, artifact, tool_run, output)
        session.flush()
        rows = list(
            session.query(Evidence).filter(Evidence.task_id == task.id).all()
        )
    return rows


def test_record_ghidra_evidence_emits_symbols_before_persist_how_claims(
    test_settings, monkeypatch
) -> None:
    """The ranking helper runs first, and persist HOW sees what it emitted.

    Behavioural replacement for the former `getsource` ordering checks: the recorded evidence
    handed to `_persist_how_claim_specs` must already contain the ranked symbol rows, the staged
    claims must come after, and symbols must be emitted through the ranking helper (external
    symbols first, non-dict entries ignored) rather than read straight out of `output["symbols"]`.
    """
    from threat_report_agent.investigation.persist_how import PersistHow

    ranked = PersistHow.ranked_symbol_emissions(
        {
            "symbols": [
                {"name": "internal", "external": False, "address": "140001000"},
                {"name": "Process32FirstW", "external": True, "address": "140046000"},
            ]
        }
    )
    assert [kind for kind, _value, _anchor in ranked] == ["import_symbol", "export_symbol"]
    assert ranked[0][1]["name"] == "Process32FirstW"
    assert ranked[0][2] == {"type": "symbol_address", "address": "140046000"}

    order: list[str] = []
    symbol_kinds_seen_by_specs: list[str] = []
    original_specs = PersistHow._persist_how_claim_specs
    original_stage = PersistHow._stage_persist_how_claims

    @classmethod
    def spy_specs(cls, *, artifact_path: str, evidence):  # noqa: ANN001 - mirrors the real signature
        order.append("specs")
        symbol_kinds_seen_by_specs.extend(
            str(getattr(item, "kind", ""))
            for item in evidence
            if str(getattr(item, "kind", "")) in {"import_symbol", "export_symbol"}
        )
        return original_specs(artifact_path=artifact_path, evidence=evidence)

    @classmethod
    def spy_stage(cls, pending_claims, how_specs, *, task_id: str, subject: str):  # noqa: ANN001
        order.append("stage")
        return original_stage(
            pending_claims, how_specs, task_id=task_id, subject=subject
        )

    monkeypatch.setattr(PersistHow, "_persist_how_claim_specs", spy_specs)
    monkeypatch.setattr(PersistHow, "_stage_persist_how_claims", spy_stage)

    rows = _record_ghidra_evidence_rows(
        test_settings,
        {
            "functions": [],
            "symbols": [
                {"name": "internal", "external": False, "address": "140001000"},
                "not-a-symbol",
                {"name": "Process32FirstW", "external": True, "address": "140046000"},
            ],
        },
    )

    assert order == ["specs", "stage"], (
        "ranked symbols must be emitted before the persist HOW specs are computed, and the "
        f"claims staged after: {order}"
    )
    assert symbol_kinds_seen_by_specs == ["import_symbol", "export_symbol"], (
        "the persist HOW specs did not see the emitted ranked symbols: "
        f"{symbol_kinds_seen_by_specs}"
    )
    emitted = [row for row in rows if str(row.kind) in {"import_symbol", "export_symbol"}]
    assert [str(row.kind) for row in emitted] == ["import_symbol", "export_symbol"], (
        "symbols must be emitted through the ranking helper (external first, non-dict entries "
        f"dropped), not read straight from output['symbols']: {[row.kind for row in emitted]}"
    )
    assert emitted[0].value["name"] == "Process32FirstW"


def test_ghidra_ranked_symbol_emissions_keep_process32_import() -> None:
    rows = AnalysisService._ghidra_ranked_symbol_emissions(
        {
            "symbols": [
                {"name": "internal", "external": False, "address": "140001000"},
                {"name": "Process32FirstW", "external": True, "address": "140046000"},
            ]
        }
    )
    names = [value.get("name") for _, value, _ in rows]
    kinds = [kind for kind, _, _ in rows]
    assert "Process32FirstW" in names
    assert "import_symbol" in kinds
    assert names.index("Process32FirstW") < names.index("internal")


def test_entrypoint_playbook_skips_trace_without_typed_catalog_contract() -> None:
    """Entrypoint-timeline has no catalogue entry; leftover TRACE cannot close it."""
    playbook = MechanismPlaybookRegistry().by_id("entrypoint-timeline")
    evidence = [
        {
            "id": "pe-1",
            "kind": "pe_structure",
            "nature": "STATIC_OBSERVED",
            "value": {"entry_point": "0x140001000"},
        },
        {
            "id": "fn-1",
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {"name": "entry", "entry": "0x140001000"},
        },
    ]
    assert AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-entry",
        artifact_id="artifact-resume",
    ) is None
    boundary = AnalysisService.persist_time_static_boundary(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-entry",
        artifact_id="artifact-resume",
    )
    assert boundary is not None
    assert boundary.thread_state == InvestigationThreadState.UNKNOWN
    assert boundary.actions == ()
    assert "typed_behavior_contract" in boundary.gate.missing


def test_supporting_persistence_seed_does_not_inherit_how_trace_budget() -> None:
    registry = MechanismPlaybookRegistry()
    cluster = {
        "category": "persistence",
        "playbook_id": "",
        "question": "Which persistence-relevant path is prepared?",
    }
    assert _seed_playbook(registry, cluster) is None
    assert "persistence" not in _HOW_SEED_CATEGORIES
    result = AnalysisService._supporting_seed_static_boundary(
        evidence=[
            {
                "id": "str-1",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"text": "schtasks"},
            }
        ],
        thread_id="thread-persist",
        artifact_id="artifact-resume",
        category="persistence",
    )
    assert result.actions == ()
    assert result.thread_state == InvestigationThreadState.UNKNOWN
    assert result.events[0].phase == "persist_time_static_boundary"


def test_process_persist_claim_uses_command_flags_not_ppid_keywords() -> None:
    """The persist claim must use the recovered command + flags, not PPID keywords.

    §2 #3 / §7.2: the flag word must be a credible dwCreationFlags immediate. This
    fixture previously used ``0x00080000`` (1,000,000 ms timeout, bit 19 collides
    with EXTENDED_STARTUPINFO_PRESENT) and asserted it as the recovered flags; a
    timeout constant must not close the process HOW, so the fixture now carries a
    credible value and the assertion follows it.
    """
    playbook = MechanismPlaybookRegistry().by_id("process-execution")
    evidence = [
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
        },
        {
            "id": "trace-1",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateProcessW",
                "command": "cmd.exe /c FoxitPDFReader.exe",
                "creation_flags": "0x00080000",
                "open_process": "OpenProcess",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                "parent_selection": "explorer.exe",
            },
        },
    ]
    how = AnalysisService.recovered_process_how_fields(evidence)
    assert how["command"] == "cmd.exe /c FoxitPDFReader.exe"
    assert how["flags"] == "0x00080000"
    fields = AnalysisService._investigated_mechanism_claim_fields(
        playbook, evidence, "Resume.pdf.exe"
    )
    assert fields["action"] == "may_create_process"
    assert "FoxitPDFReader.exe" in str(fields["object"])
    assert "0x00080000" in str(fields["mechanism"])
    assert fields["action"] != "may_spoof_parent_process"
    stamped = AnalysisService.catalog_candidate_mechanism_fields(
        playbook, evidence, "Resume.pdf.exe"
    )
    assert stamped["inputs"] == ["cmd.exe /c FoxitPDFReader.exe"]
    assert "0x00080000" in stamped["transformation_or_control"][0]
    assert "FoxitPDFReader.exe" in stamped["transformation_or_control"][0]
    assert "command=" in stamped["transformation_or_control"][0]
    from threat_report_agent.report.reporting import _finding_has_recovered_how, _module_how_from_finding

    finding = {
        "how": stamped["transformation_or_control"],
        "inputs": stamped["inputs"],
        "consumers": stamped["consumers"],
        "transformation_or_control": stamped["transformation_or_control"],
    }
    assert _finding_has_recovered_how(finding)
    assert "FoxitPDFReader.exe" in _module_how_from_finding(finding)


def test_persist_how_claim_specs_mint_process_dynamic_api_and_decode(monkeypatch) -> None:
    """Kunglao DISPATCH_VERIFIER: recovered HOW facts become claims at persist."""
    process_trace = {
        "id": "trace-1",
        "kind": "api_argument_trace",
        "nature": "STATIC_DERIVED",
        "value": {
            "api": "CreateProcessW",
            "command": "cmd.exe /c FoxitPDFReader.exe",
            "command_line": "cmd.exe /c FoxitPDFReader.exe",
            "creation_flags": "0x00080000",
            "return_branch": "JZ 0x140004780",
        },
    }
    process_call = {
        "id": "call-1",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "CreateProcessW"},
    }
    process_flow = {
        "id": "flow-proc",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": catalog_relation_from_api_fields(
            "CreateProcessW",
            process_trace["value"],
            artifact_id="artifact-resume",
            callsite="0x140004710",
            source_evidence_id="trace-1",
            target_evidence_id="call-1",
        ),
    }
    pointer = catalog_resolved_pointer_identity(
        artifact_id="artifact-resume",
        callsite="140038dfd",
    )
    resolved = {
        "id": "resolved-1",
        "kind": "resolved_api",
        "nature": "STATIC_DERIVED",
        "value": {
            "resolver": "GetProcAddress",
            "api_name": "SetThreadDescription",
            "api_identity": "SetThreadDescription",
            "module_input": "kernel32.dll",
            "consumer": "JMP R8",
            "consumer_callsite": "140038e2d",
            "resolved_pointer": pointer,
            "output_buffer": pointer,
            "consumer_pointer": pointer,
            "input_buffer": pointer,
        },
    }
    resolved_flow = {
        "id": "flow-resolved",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": catalog_relation_from_resolved_api(
            resolved["value"],
            artifact_id="artifact-resume",
            source_evidence_id="resolved-1",
            target_evidence_id="resolved-1",
        ),
    }
    hit = {
        "status": "VERIFIED_STATIC_DATA",
        "virtual_address": 0x14004C8E1,
        "length": 31,
        "formula": "key_table_modulo_xor_counter",
        "key_table": [182, 144, 1, 106],
        "counter_initial": 3,
        "counter_step": 7,
        "ciphertext_hex": "aa" * 31,
        "plaintext_hex": "687474703a2f2f36392e34382e3232382e37342f6d69616f6d2d632e706466",
        "decoded_text": "http://69.48.228.74/miaom-c.pdf",
        "output_buffer": {
            "address_space": "image",
            "address": 0x14004C8E1,
            "length": 31,
        },
    }
    xrefs = [
        {
            "from": "14000552b",
            "to": "14004c8e1",
            "type": "DATA",
            "function": "FUN_140004605",
            "entry": "140004605",
            "link_kind": "decoded_va_reference",
        }
    ]
    links = AnalysisService.recovered_config_consumer_links(
        [hit],
        xrefs,
        artifact_id="artifact-resume",
        image_base=0x140000000,
    )
    decode = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {
            **links[0]["fields"],
            "formula": "key_table_modulo_xor_counter",
            "decoded_text": "http://69.48.228.74/miaom-c.pdf",
            "consumer_status": "LINKED_STATIC",
        },
    }
    decode_consumer = {
        "id": "xref-1",
        "kind": "data_reference",
        "nature": "STATIC_OBSERVED",
        "value": links[0]["consumer"],
    }
    encoded = {
        "id": "blob-1",
        "kind": "encoded_blob",
        "nature": "STATIC_OBSERVED",
        "value": {"label": "encoded config block"},
    }
    decode_flow = {
        "id": "flow-decode",
        "kind": "value_flow",
        "nature": "STATIC_INFERRED",
        "value": catalog_output_consumer_relation(
            producer_id="decode-1",
            consumer_id="xref-1",
            output_buffer=links[0]["output_buffer"],
            consumer_api="FUN_140004605",
        ),
    }
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            process_call,
            process_trace,
            process_flow,
            resolved,
            resolved_flow,
            decode,
            decode_consumer,
            encoded,
            decode_flow,
        ],
    )
    actions = {str(fields["action"]) for _playbook, fields, _ids in specs}
    assert "may_create_process" in actions
    assert "may_resolve_api_dynamically" in actions
    assert "may_decode_configuration" in actions
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "FoxitPDFReader.exe" in str(by_action["may_create_process"]["object"])
    assert "0x00080000" in str(by_action["may_create_process"]["mechanism"])
    assert "kernel32.dll!SetThreadDescription" in str(
        by_action["may_resolve_api_dynamically"]["object"]
    )
    assert "JMP R8" in str(by_action["may_resolve_api_dynamically"]["mechanism"])
    assert "key_table_modulo_xor_counter" in str(
        by_action["may_decode_configuration"]["mechanism"]
    )
    from threat_report_agent.investigation.persist_how import (
        PersistHow,
        emit_ranked_symbols_then_stage,
        stage_persist_how_claims,
    )

    # The staging helper must mint INVESTIGATED_MECHANISM CANDIDATEs - observed on the staged
    # rows rather than read out of its body.
    pending: list[tuple[object, object, object, object]] = []
    stage_persist_how_claims(
        pending, specs, task_id="task-symbols", subject="Resume.pdf.exe"
    )
    assert pending
    assert {str(item[3]["claim_kind"]) for item in pending} == {
        "persist_time_investigated_mechanism"
    }, "the staged claims lost their persist-time claim kind"

    # `emit_ranked_symbols_then_stage` must emit the ranked symbols first, compute the claim specs
    # from that evidence, then stage the claims. All three steps are recorded on collaborators.
    order: list[str] = []
    emitted: list[object] = []
    specs_evidence: list[object] = []
    original_specs = PersistHow._persist_how_claim_specs
    original_stage = PersistHow._stage_persist_how_claims

    @classmethod
    def spy_specs(cls, *, artifact_path: str, evidence):  # noqa: ANN001 - real signature
        order.append("specs")
        specs_evidence.extend(evidence)
        return original_specs(artifact_path=artifact_path, evidence=evidence)

    @classmethod
    def spy_stage(cls, pending_claims, how_specs, *, task_id: str, subject: str):  # noqa: ANN001
        order.append("stage")
        return original_stage(
            pending_claims, how_specs, task_id=task_id, subject=subject
        )

    def emit(
        kind: str, value: dict[str, object], anchor: dict[str, object], **_kwargs: object
    ) -> object:
        order.append(f"emit:{kind}")
        row = SimpleNamespace(id=f"ev-{len(emitted)}", kind=kind, value=value, anchor=anchor)
        emitted.append(row)
        return row

    monkeypatch.setattr(PersistHow, "_persist_how_claim_specs", spy_specs)
    monkeypatch.setattr(PersistHow, "_stage_persist_how_claims", spy_stage)
    emit_ranked_symbols_then_stage(
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
    assert order == ["emit:import_symbol", "emit:export_symbol", "specs", "stage"], order
    assert [str(getattr(item, "kind", "")) for item in specs_evidence] == [
        "import_symbol",
        "export_symbol",
    ], "the claim specs were computed before the ranked symbols were emitted"
    # `_record_ghidra_evidence` must route through this helper rather than read `output["symbols"]`
    # itself; that collaboration is asserted behaviourally (persisted import_symbol rows, external
    # first, non-dict entries dropped) by
    # `test_record_ghidra_evidence_emits_symbols_before_persist_how_claims` above.


def test_persist_how_claim_specs_mint_named_api_without_module_input() -> None:
    """Kunglao DISPATCH_VERIFIER: named API + consumer is a CANDIDATE, not TRACE bait."""
    specs = AnalysisService.persist_how_claim_specs(
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


def test_persist_how_claim_specs_named_api_without_invented_resolver() -> None:
    """Kunglao SUMMARY_FAKE: do not invent GetProcAddress when the row has none."""
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "resolved-1",
                "kind": "resolved_api",
                "nature": "STATIC_DERIVED",
                "value": {
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
    mechanism = str(by_action["may_resolve_api_dynamically"]["mechanism"])
    assert "SetThreadDescription" in mechanism
    assert "JMP R8" in mechanism
    assert "GetProcAddress" not in mechanism


def test_persist_how_claim_specs_mint_unique_thread_start() -> None:
    """Kunglao DISPATCH_VERIFIER: recovered lpStartAddress is a claim, not TRACE bait."""
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "trace-thread",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "0x14000a100",
                            "resolved": True,
                        },
                        {
                            "index": 3,
                            "name": "lpParameter",
                            "value": "0x14004d100",
                            "resolved": True,
                        },
                    ],
                },
                "anchor": {"function_entry": "140001000"},
            },
            {
                "id": "trace-unknown",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "UNKNOWN",
                            "resolved": False,
                        }
                    ],
                },
            },
            {
                "id": "body-thread",
                "kind": "function_context",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "name": "FUN_14000a100",
                    "call_targets": [
                        {"target_name": "WaitForSingleObject"},
                        {"target_name": "ExitThread"},
                    ],
                },
                "anchor": {},
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_start_os_thread" in by_action
    assert "0x14000a100" in str(by_action["may_start_os_thread"]["object"])
    assert "lpStartAddress=0x14000a100" in str(by_action["may_start_os_thread"]["mechanism"])
    assert "WaitForSingleObject" in str(by_action["may_start_os_thread"]["mechanism"])
    ids = next(ids for _playbook, fields, ids in specs if fields["action"] == "may_start_os_thread")
    assert "trace-thread" in ids
    assert "body-thread" in ids
    entries = AnalysisService._persist_how_function_entries(
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
                            "value": "0x14000a100",
                            "resolved": True,
                        }
                    ],
                },
            }
        ]
    )
    assert "0x14000a100" in entries


def test_persist_unique_thread_seed_closes_without_trace() -> None:
    """Recovered lpStartAddress is CLAIM_READY; missing start stays honest UNKNOWN."""
    recovered = [
        {
            "id": "trace-thread",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateThread",
                "arguments": [
                    {
                        "index": 2,
                        "name": "lpStartAddress",
                        "value": "0x14000a100",
                        "resolved": True,
                    }
                ],
            },
            "anchor": {"function_entry": "140001000"},
        }
    ]
    ready = AnalysisService._persist_time_unique_thread_result(
        evidence=recovered,
        thread_id="thread-os",
        artifact_id="artifact-resume",
    )
    assert ready is not None
    assert ready.thread_state == InvestigationThreadState.CLAIM_READY
    assert ready.hypothesis_status == "CANDIDATE"
    assert ready.actions == ()
    assert ready.events[0].phase == "persist_time_claim_ready"
    missing = AnalysisService._persist_time_unique_thread_result(
        evidence=[
            {
                "id": "trace-unknown",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {
                            "index": 2,
                            "name": "lpStartAddress",
                            "value": "UNKNOWN",
                            "resolved": False,
                        }
                    ],
                },
            }
        ],
        thread_id="thread-os",
        artifact_id="artifact-resume",
    )
    assert missing is None


def test_unique_thread_seed_rows_exclude_process_how() -> None:
    """Kunglao leftover remainder: Unique OS protocol must not inherit Foxit command."""
    from threat_report_agent.investigation.investigation_protocol import fill_protocol

    thread = Evidence(
        id="trace-thread",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateThread",
            "arguments": [
                {
                    "index": 2,
                    "name": "lpStartAddress",
                    "value": "0x140038ae0",
                    "resolved": True,
                },
                {
                    "index": 3,
                    "name": "lpParameter",
                    "value": "0x8",
                    "resolved": True,
                },
            ],
        },
        anchor={"function_entry": "1400440b9"},
    )
    body = Evidence(
        id="body-thread",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="function_context",
        nature="STATIC_OBSERVED",
        value={"name": "FUN_140038ae0", "loop": "poll until named event"},
        anchor={},
    )
    process = Evidence(
        id="trace-process",
        task_id="t",
        artifact_id="a",
        tool_run_id="r",
        module="static_triage",
        kind="api_argument_trace",
        nature="STATIC_DERIVED",
        value={
            "api": "CreateProcessW",
            "command": "cmd.exe /c FoxitPDFReader.exe",
            "creation_flags": "0x00080000",
        },
        anchor={"function_entry": "140004605"},
    )
    selected = AnalysisService.select_unique_thread_seed_rows([process, thread, body])
    assert {row.id for row in selected} == {"trace-thread", "body-thread"}
    protocol = fill_protocol(
        [
            {"id": row.id, "kind": row.kind, "value": row.value, "anchor": row.anchor}
            for row in selected
        ]
    )
    blob = " ".join(str(slot.get("value") or "") for slot in protocol.values())
    assert "0x140038ae0" in blob
    assert "FoxitPDFReader.exe" not in blob
    assert protocol["loop"]["status"] == "ANSWERED"
    assert "poll until named event" in str(protocol["loop"]["value"])


def test_persist_how_claim_specs_mint_process_from_flags_and_image_string() -> None:
    """Live Resume: empty CreateProcess traces still mint HOW from flags + Foxit image."""
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "call-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "from": "140046948",
                    "api": "CreateProcessW",
                    "target_name": "CreateProcessW",
                    "type": "COMPUTED_JUMP",
                },
            },
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "callsite": "140008dce",
                    "register": "RCX",
                    "value": "R14",
                    "function": "FUN_140004605",
                },
            },
            {
                "id": "flags-1",
                "kind": "process_creation_flags",
                "nature": "STATIC_DERIVED",
                "value": {
                    "function": "FUN_140004605",
                    "flags": [
                        {
                            "value": "0x00080000",
                            "set_flags": [
                                "CREATE_NEW_PROCESS_GROUP",
                                "CREATE_PROTECTED_PROCESS",
                                "EXTENDED_STARTUPINFO_PRESENT",
                            ],
                        },
                        {
                            "value": "0x08000000",
                            "set_flags": ["CREATE_NO_WINDOW"],
                        },
                    ],
                    "runtime_effect_proven": False,
                },
            },
            {
                "id": "str-foxit",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"encoding": "utf-16le", "text": "FoxitPDFReader.exe"},
            },
            {
                "id": "str-mash",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "text": (
                        "explorer.exeInitializeProcThreadAttributeList failed"
                        "CreateProcessW failed"
                    )
                },
            },
            {
                "id": "str-error",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "text": 'cmd.exe /e:ON /v:OFF /d /c "batch file arguments are invalid'
                },
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert "may_create_process" in by_action
    assert by_action["may_create_process"]["object"] == "FoxitPDFReader.exe"
    assert "0x00080000" in str(by_action["may_create_process"]["mechanism"])
    assert "explorer.exeInitialize" not in str(by_action["may_create_process"]["object"])
    assert "invalid" not in str(by_action["may_create_process"]["object"]).casefold()


def test_persist_how_prefers_recovered_flags_over_specialist_token() -> None:
    """A credible recovered flag word wins over the specialist PPID token.

    The specialist remainder token is not a dwCreationFlags argument on its own
    (``static_analysis.is_specialist_ppid_creation_flag``), so the persist HOW must
    prefer the other credible candidate. The fixture carries a credible value
    (``0x00080000``) because a timeout constant must not close the process HOW.
    """
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "callsite": "140008dce",
                    "function": "FUN_140004605",
                    "creation_flags": "0x09080008",
                    "flags": "0x09080008",
                },
            },
            {
                "id": "flags-1",
                "kind": "process_creation_flags",
                "nature": "STATIC_DERIVED",
                "value": {
                    "function": "FUN_140004605",
                    "flags": [
                        {
                            "value": "0x00080000",
                            "set_flags": [
                                "CREATE_NEW_PROCESS_GROUP",
                                "CREATE_PROTECTED_PROCESS",
                                "EXTENDED_STARTUPINFO_PRESENT",
                            ],
                        },
                        {
                            "value": "0x09080008",
                            "set_flags": [
                                "DETACHED_PROCESS",
                                "EXTENDED_STARTUPINFO_PRESENT",
                                "CREATE_BREAKAWAY_FROM_JOB",
                                "CREATE_NO_WINDOW",
                            ],
                        },
                    ],
                },
            },
            {
                "id": "str-foxit",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"encoding": "utf-16le", "text": "FoxitPDFReader.exe"},
            },
        ],
    )
    by_action = {str(fields["action"]): fields for _playbook, fields, _ids in specs}
    assert by_action["may_create_process"]["object"] == "FoxitPDFReader.exe"
    assert "0x00080000" in str(by_action["may_create_process"]["mechanism"])
    assert "0x09080008" not in str(by_action["may_create_process"]["mechanism"])


def test_persist_how_claim_specs_mint_each_named_api() -> None:
    """Kunglao DISPATCH_VERIFIER: each recovered named API is its own claim."""
    specs = AnalysisService.persist_how_claim_specs(
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
                },
            },
            {
                "id": "resolved-2",
                "kind": "resolved_api",
                "nature": "STATIC_DERIVED",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "GetTempPath2W",
                    "consumer": "JMP R8",
                },
            },
        ],
    )
    objects = [
        str(fields["object"])
        for playbook, fields, _ids in specs
        if str(getattr(playbook, "id", "")) == "dynamic-api-resolution"
    ]
    assert any("SetThreadDescription" in item for item in objects)
    assert any("GetTempPath2W" in item for item in objects)
    assert len(objects) == 2
    pending: list[tuple[object, object, object, object]] = []
    AnalysisService.stage_persist_how_claims(
        pending,
        specs,
        task_id="task-named-api",
        subject="Resume.pdf.exe",
    )
    named = [
        item[0]
        for item in pending
        if str(getattr(item[0], "action", "")) == "may_resolve_api_dynamically"
    ]
    assert len(named) == 2
    assert {str(item.module) for item in named} == {"loader"}
    assert {str(item.object) for item in named} == {
        "SetThreadDescription",
        "GetTempPath2W",
    }


def test_persist_how_claim_specs_skip_ghidra_function_symbol_as_api() -> None:
    """HOW7: FUN_140001ddd is a start routine, not kernel32.dll!FUN_140001ddd."""
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe",
        evidence=[
            {
                "id": "resolved-fun",
                "kind": "resolved_api",
                "nature": "STATIC_DERIVED",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "FUN_140001ddd",
                    "module_input": "kernel32.dll",
                    "consumer": "FUN_140001ddd",
                },
            },
            {
                "id": "resolved-1",
                "kind": "resolved_api",
                "nature": "STATIC_DERIVED",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "SetThreadDescription",
                    "consumer": "JMP R8",
                },
            },
        ],
    )
    objects = [
        str(fields["object"])
        for playbook, fields, _ids in specs
        if str(getattr(playbook, "id", "")) == "dynamic-api-resolution"
    ]
    assert objects == ["SetThreadDescription"]
    assert not any("FUN_140001ddd" in item for item in objects)


def test_dynamic_api_how_does_not_steal_iat_name_from_mixed_ppid_trace() -> None:
    """HOW8: UpdateProcThreadAttribute IAT trace is not a GetProcAddress export."""
    mixed = [
        {
            "id": "iat-ppid",
            "kind": "api_argument_trace",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            },
        },
        {
            "id": "resolved-setthread",
            "kind": "resolved_api",
            "value": {
                "resolver": "GetProcAddress",
                "api_name": "SetThreadDescription",
                "module_input": "kernel32.dll",
                "consumer": "JMP R8",
            },
        },
        {
            "id": "flow-ppid",
            "kind": "value_flow",
            "value": {
                "relation": "parent_handle_to_attribute",
                "api": "UpdateProcThreadAttribute",
                "consumer": "FUN_140001ddd",
            },
        },
    ]
    how = AnalysisService.recovered_dynamic_api_how_fields(mixed)
    assert how["api_name"] == "SetThreadDescription"
    assert how["consumer"] == "JMP R8"
    assert "UpdateProcThreadAttribute" not in how["api_name"]

    playbook = MechanismPlaybookRegistry().by_id("dynamic-api-resolution")
    snapshot = AnalysisService.catalog_candidate_mechanism_fields(
        playbook,
        mixed,
        "Resume.pdf.exe.VIR",
    )
    blob = " ".join(str(item) for item in (snapshot.get("transformation_or_control") or []))
    consumers = " ".join(str(item) for item in (snapshot.get("consumers") or []))
    assert "SetThreadDescription" in blob
    assert "UpdateProcThreadAttribute" not in blob
    assert "FUN_140001ddd" not in consumers


def test_persist_time_seed_result_claim_ready_without_module_input() -> None:
    """Named API + consumer skips leftover TRACE even when catalog tokens fail."""
    playbook = MechanismPlaybookRegistry().by_id("dynamic-api-resolution")
    evidence = [
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
    ]
    seed_gate = AnalysisService.gate_for_seed_playbook(playbook, evidence)
    assert seed_gate is None or seed_gate.accepted is False
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-dyn",
        artifact_id="artifact-resume",
    )
    assert result is not None
    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    assert result.hypothesis_status == "CANDIDATE"
    assert result.actions == ()
    assert result.events[0].phase == "persist_time_claim_ready"


def test_http_how_seed_skips_trace_without_transport_api() -> None:
    """Leftover TRACE cannot invent WinHttpSendRequest from a missing-export string."""
    playbook = MechanismPlaybookRegistry().by_id("http-download")
    evidence = [
        {
            "id": "str-1",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "WinHTTP export not found"},
        }
    ]
    assert AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-http",
        artifact_id="artifact-resume",
    ) is None
    boundary = AnalysisService.persist_time_static_boundary(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-http",
        artifact_id="artifact-resume",
    )
    assert boundary is not None
    assert boundary.thread_state == InvestigationThreadState.UNKNOWN
    assert boundary.actions == ()
    assert boundary.events[0].phase == "persist_time_static_boundary"


def test_http_how_seed_claim_ready_from_decoded_winhttp_and_url() -> None:
    """HOW9 leftover decoded WinHttp* + URL; HTTP thread How was the DOS stub."""
    dos = {
        "id": "str-dos",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"text": "!This program cannot be run in DOS mode."},
    }
    missing = {
        "id": "str-missing",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"text": "WinHTTP export not found"},
    }
    send = {
        "id": "decode-send",
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "formula": "single_key_plus_step_xor_const",
            "decoded_preview": "WinHttpSendRequest",
            "decoded_strings": ["WinHttpSendRequest"],
            "status": "VERIFIED_STATIC_DATA",
        },
    }
    open_request = {
        "id": "decode-open",
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "formula": "single_key_plus_step_xor_const",
            "decoded_preview": "WinHttpOpenRequest",
            "decoded_strings": ["WinHttpOpenRequest"],
            "status": "VERIFIED_STATIC_DATA",
        },
    }
    url = {
        "id": "decode-url",
        "kind": "decode_result",
        "nature": "STATIC_DERIVED",
        "value": {
            "formula": "key_table_modulo_xor_counter",
            "decoded_preview": "http://203.0.113.10/ComHost.exe",
            "decoded_strings": ["http://203.0.113.10/ComHost.exe"],
            "status": "VERIFIED_STATIC_DATA",
        },
    }
    assert not AnalysisService.is_http_transport_seed_row(dos)
    assert not AnalysisService.is_http_transport_seed_row(missing)
    assert AnalysisService.is_http_transport_seed_row(send)
    assert AnalysisService.is_http_transport_seed_row(url)
    playbook = MechanismPlaybookRegistry().by_id("http-download")
    evidence = [dos, missing, send, open_request, url]
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=evidence,
        thread_id="thread-http",
        artifact_id="artifact-resume",
    )
    assert result is not None
    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    assert result.hypothesis_status == "CANDIDATE"
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-http",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(
        str(item)
        for item in (
            row.get("transformation_or_control") or [],
            row.get("inputs") or [],
            row.get("consumers") or [],
        )
    )
    assert row["status"] == "CANDIDATE"
    assert row["mechanism_type"] == "HTTP_DOWNLOAD"
    assert "WinHttpSendRequest" in blob
    assert "http://203.0.113.10/ComHost.exe" in blob
    assert "cannot be run in dos mode" not in blob.casefold()
    assert "export not found" not in blob.casefold()
    specs = AnalysisService.persist_how_claim_specs(
        artifact_path="Resume.pdf.exe.VIR",
        evidence=evidence,
    )
    http_specs = [
        item for item in specs if str(getattr(item[0], "id", "") or "") == "http-download"
    ]
    assert http_specs
    assert "WinHttpSendRequest" in str(http_specs[0][1]["mechanism"])
    assert http_specs[0][1]["action"] == "may_download_over_http"


def test_process_execution_seed_claim_ready_from_flags_and_image_string() -> None:
    """HOW8: process thread stays OPEN unless flags/Foxit rows are seed-visible."""
    flags = {
        "id": "flags-1",
        "kind": "process_creation_flags",
        "nature": "STATIC_DERIVED",
        "value": {"flags": [{"value": "0x00080000"}]},
    }
    image = {
        "id": "str-foxit",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"encoding": "utf-16le", "text": "FoxitPDFReader.exe"},
    }
    assert AnalysisService._is_process_creation_seed_row(flags)
    assert AnalysisService._is_process_creation_seed_row(image)
    playbook = MechanismPlaybookRegistry().by_id("process-execution")
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=[flags, image],
        thread_id="thread-process",
        artifact_id="artifact-resume",
    )
    assert result is not None
    assert result.thread_state == InvestigationThreadState.CLAIM_READY
    assert result.hypothesis_status == "CANDIDATE"
    assert result.actions == ()


def test_persist_ready_emulation_actions_target_how_function_entry() -> None:
    actions = AnalysisService.persist_ready_emulation_actions(
        evidence=[
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "cmd.exe /c FoxitPDFReader.exe",
                    "creation_flags": "0x00080000",
                    "function_entry": "140004605",
                },
                "anchor": {"function_entry": "140004605"},
            }
        ],
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
    )
    assert len(actions) == 1
    assert actions[0].action_type == ActionType.CONTROLLED_EMULATE
    assert actions[0].target_selector["function_entry"] == "0x140004605"
    skipped = AnalysisService.persist_ready_emulation_actions(
        evidence=[
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "140004605"},
                "anchor": {"function_entry": "140004605"},
            }
        ],
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
        scheduled_keys={
            scoped_investigation_action_key(
                ActionType.CONTROLLED_EMULATE.value,
                {"function_entry": "0x140004605", "target": "0x140004605"},
                {},
            )
        },
    )
    assert skipped == ()


def test_persist_ready_emulation_skips_prologue_without_recovered_how() -> None:
    """Kunglao leftover remainder must corroborate recovered HOW, not seed flood."""
    actions = AnalysisService.persist_ready_emulation_actions(
        evidence=[
            {
                "id": "prologue",
                "kind": "function_instruction_window",
                "nature": "STATIC_DERIVED",
                "value": {"function_entry": "140001000"},
                "anchor": {"function_entry": "140001000"},
            },
            {
                "id": "empty-createprocess",
                "kind": "function_call",
                "nature": "STATIC_DERIVED",
                "value": {"api": "CreateProcessW", "function_entry": "140046948"},
                "anchor": {"function_entry": "140046948"},
            },
            {
                "id": "trace-1",
                "kind": "api_argument_trace",
                "nature": "STATIC_DERIVED",
                "value": {
                    "api": "CreateProcessW",
                    "command": "cmd.exe /c FoxitPDFReader.exe",
                    "creation_flags": "0x00080000",
                    "function_entry": "140004605",
                },
                "anchor": {"function_entry": "140004605"},
            },
        ],
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
    )
    assert [item.target_selector["function_entry"] for item in actions] == ["0x140004605"]


def test_persist_skip_survives_queued_trace_and_keeps_isolated_emu() -> None:
    """DSH-queued TRACE must not block persist HOW skip or leftover emu."""
    from types import SimpleNamespace

    from threat_report_agent.investigation import ActionSpec

    trace = ActionSpec(
        id="queued-trace",
        action_type=ActionType.GET_CALLEES,
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
        target_selector={"function_entry": "140004605"},
    )
    emu = ActionSpec(
        id="queued-emu",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
        target_selector={"function_entry": "140004605"},
    )
    kept = AnalysisService._keep_emulation_after_persist_skip((trace, emu))
    assert [item.id for item in kept] == ["queued-emu"]

    queued_trace = SimpleNamespace(
        thread_id="thread-other",
        status="QUEUED",
        action_type=ActionType.GET_CALLEES.value,
        error=None,
        finished_at=None,
    )
    queued_emu = SimpleNamespace(
        thread_id="thread-process",
        status="QUEUED",
        action_type=ActionType.CONTROLLED_EMULATE.value,
        error=None,
        finished_at=None,
    )
    AnalysisService._supersede_queued_trace_after_persist_skip(
        (queued_trace, queued_emu),
        thread_id="thread-process",
    )
    assert queued_trace.status == "CANCELLED"
    assert queued_trace.error == AnalysisService._PERSIST_SKIP_TRACE_ERROR
    assert queued_emu.status == "QUEUED"


def test_stamp_persist_how_snapshot_keeps_named_api_when_specialist_fails() -> None:
    """Kunglao DISPATCH_VERIFIER: persist CANDIDATE is snapshot content, not UNKNOWN."""
    playbook = MechanismPlaybookRegistry().by_id("dynamic-api-resolution")
    result = InvestigationResult(
        thread_id="thread-api",
        artifact_id="artifact-resume",
        thread_state=InvestigationThreadState.CLAIM_READY,
        hypothesis_status="CANDIDATE",
        evidence=(
            {
                "id": "resolved-1",
                "kind": "resolved_api",
                "value": {
                    "resolver": "GetProcAddress",
                    "api_name": "SetThreadDescription",
                    "consumer": "JMP R8",
                },
            },
        ),
        events=(
            InvestigationEvent(
                phase="persist_time_claim_ready",
                action_id=None,
                state=InvestigationThreadState.CLAIM_READY.value,
                evidence_ids=("resolved-1",),
                message="persist HOW",
            ),
        ),
        actions=(),
        gate=GateDecision(
            accepted=False,
            status="CANDIDATE",
            reason="module_input missing",
            evidence_ids=("resolved-1",),
            missing=("module_input",),
        ),
    )
    snapshot = {
        "mechanisms": [
            {
                "id": "seed-api",
                "thread_id": "thread-api",
                "status": "UNKNOWN",
                "type": "static_mechanism",
            }
        ]
    }
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-api",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe",
    )
    row = snapshot["mechanisms"][0]
    assert row["status"] == "CANDIDATE"
    assert row["mechanism_type"] == "DYNAMIC_API_RESOLUTION"
    assert "SetThreadDescription" in " ".join(str(item) for item in row["inputs"])
    assert "JMP R8" in " ".join(str(item) for item in row["transformation_or_control"])
    assert "SetThreadDescription" in " ".join(str(item) for item in row["transformation_or_control"])
    assert "kernel32.dll" not in str(row["inputs"])
    assert "recovered module" not in str(row["inputs"]).casefold()


def test_process_seed_stamp_and_emu_from_flags_and_foxit_string() -> None:
    """HOW8 process thread: flags+Foxit close the seed and still grant CreateProcess emu."""
    flags = {
        "id": "flags-1",
        "kind": "process_creation_flags",
        "nature": "STATIC_DERIVED",
        "value": {
            "function": "FUN_140004605",
            "flags": [{"value": "0x00080000", "set_flags": ["EXTENDED_STARTUPINFO_PRESENT"]}],
        },
    }
    image = {
        "id": "str-foxit",
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {"encoding": "utf-16le", "text": "FoxitPDFReader.exe"},
    }
    playbook = MechanismPlaybookRegistry().by_id("process-execution")
    result = AnalysisService.persist_time_seed_result(
        playbook=playbook,
        evidence=[flags, image],
        thread_id="thread-process",
        artifact_id="artifact-resume",
    )
    assert result is not None
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-process",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe.VIR",
    )
    row = snapshot["mechanisms"][0]
    blob = " ".join(str(item) for item in (row.get("transformation_or_control") or []))
    assert row["status"] == "CANDIDATE"
    assert "FoxitPDFReader.exe" in blob
    assert "0x00080000" in blob
    actions = AnalysisService.persist_ready_emulation_actions(
        evidence=[flags, image],
        thread_id="thread-process",
        hypothesis_id="hyp-process",
        artifact_id="artifact-resume",
    )
    assert len(actions) == 1
    assert actions[0].target_selector["function_entry"] == "0x140004605"


def test_stamp_persist_boundary_writes_http_unknown_not_empty_seed() -> None:
    playbook = MechanismPlaybookRegistry().by_id("http-download")
    result = InvestigationResult(
        thread_id="thread-http",
        artifact_id="artifact-resume",
        thread_state=InvestigationThreadState.UNKNOWN,
        hypothesis_status="UNKNOWN",
        evidence=(),
        events=(
            InvestigationEvent(
                phase="persist_time_static_boundary",
                action_id=None,
                state=InvestigationThreadState.UNKNOWN.value,
                evidence_ids=(),
                message="no transport API",
            ),
        ),
        actions=(),
        gate=GateDecision(
            accepted=False,
            status="UNKNOWN",
            reason="transport API not imported",
            evidence_ids=(),
            missing=("WinHttpSendRequest",),
        ),
    )
    snapshot: dict[str, object] = {"mechanisms": []}
    AnalysisService.stamp_persist_how_snapshot(
        snapshot,
        thread_id="thread-http",
        playbook=playbook,
        result=result,
        artifact_path="Resume.pdf.exe",
    )
    row = snapshot["mechanisms"][0]
    assert row["status"] == "UNKNOWN"
    assert "WinHttpSendRequest" in str(row["missing_fields"])
    assert row["unknowns"]


def test_cross_function_chain_claims_dedupe_category_paths() -> None:
    """HOW8 minted ~100 duplicate anti_analysis->execution->injection claims."""
    chains = [
        {
            "categories": ["anti_analysis", "execution", "file_io", "injection"],
            "functions": [f"FUN_{index}"],
        }
        for index in range(40)
    ]
    chains.append({"categories": ["execution", "loader"], "functions": ["FUN_loader"]})
    selected = AnalysisService._select_cross_function_chain_claims(chains)
    assert len(selected) == 2
    paths = {" -> ".join(item["categories"]) for item in selected}
    assert "anti_analysis -> execution -> file_io -> injection" in paths
    assert "execution -> loader" in paths


def test_generic_ghidra_behavior_claims_yield_to_persist_how() -> None:
    """HOW8: per-function may_execute/may_decode drowned persist Foxit/decode HOW."""
    pending = [
        (
            SimpleNamespace(action="may_execute", object="process or command"),
            ("e1",),
            True,
            {"claim_kind": "ghidra_function_behavior"},
        ),
        (
            SimpleNamespace(action="may_execute", object="process or command"),
            ("e2",),
            True,
            {"claim_kind": "ghidra_function_behavior"},
        ),
        (
            SimpleNamespace(action="may_decode_or_decrypt", object="embedded or transient data"),
            ("e3",),
            True,
            {"claim_kind": "ghidra_function_behavior"},
        ),
        (
            SimpleNamespace(action="may_load_or_prepare_memory", object="code or a secondary component"),
            ("e4",),
            True,
            {"claim_kind": "ghidra_function_behavior"},
        ),
        (
            SimpleNamespace(action="may_load_or_prepare_memory", object="code or a secondary component"),
            ("e5",),
            True,
            {"claim_kind": "ghidra_function_behavior"},
        ),
        (
            SimpleNamespace(action="may_execute", object="a process or command"),
            ("e8",),
            True,
            {"claim_kind": "ghidra_mechanism_chain"},
        ),
        (
            SimpleNamespace(action="may_execute", object="a process or command"),
            ("e9",),
            True,
            {"claim_kind": "ghidra_mechanism_chain"},
        ),
        (
            SimpleNamespace(
                action="may_decode_or_decrypt",
                object="embedded resource or transient buffer",
            ),
            ("e10",),
            True,
            {"claim_kind": "ghidra_mechanism_chain"},
        ),
        (
            SimpleNamespace(action="may_create_process", object="FoxitPDFReader.exe"),
            ("e6",),
            False,
            {"claim_kind": "persist_time_investigated_mechanism"},
        ),
        (
            SimpleNamespace(action="may_decode_configuration", object="decoded configuration buffer"),
            ("e7",),
            False,
            {"claim_kind": "persist_time_investigated_mechanism"},
        ),
    ]
    AnalysisService._collapse_generic_ghidra_behavior_claims(pending)
    actions = [str(item[0].action) for item in pending]
    assert actions.count("may_create_process") == 1
    assert actions.count("may_decode_configuration") == 1
    assert "may_execute" not in actions
    assert "may_decode_or_decrypt" not in actions
    assert actions.count("may_load_or_prepare_memory") == 1
