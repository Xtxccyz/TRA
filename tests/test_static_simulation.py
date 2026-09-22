from threat_report_agent.static_simulation import StaticAbstractExecutor, merged_source_anchor


def _function(*apis: str) -> dict[str, object]:
    return {
        "name": "FUN_loader",
        "entry": "0x401000",
        "instructions": [
            {"text": "MOV RCX, 0x1000"},
            {"text": "CMP RCX, 0"},
            {"text": "JNZ 0x401020"},
        ],
        "references_from": [
            {"from": f"0x4010{index:02x}", "target_name": api, "type": "CALL"}
            for index, api in enumerate(apis)
        ],
    }


def test_static_abstract_execution_predicts_memory_loader_without_runtime() -> None:
    result = StaticAbstractExecutor().analyze(
        _function("VirtualAlloc", "WriteProcessMemory", "VirtualProtect", "CreateThread"),
        source_evidence_ids=("e-function", "e-window"),
    )
    value = result.as_dict()

    assert value["simulation_kind"] == "static_abstract_execution"
    assert value["runtime_observed"] is False
    assert value["predicted"] is True
    assert {item["kind"] for item in value["mechanism_candidates"]} >= {
        "memory_loader",
        "memory_execution",
    }
    assert value["register_state"]["RCX"]["value"] == 4096
    assert value["path_conditions"]
    # A step's anchor is read through `merged_source_anchor`, because fields identical in
    # every step (the function's source_evidence_ids among them) are hoisted to
    # `source_anchor_base` instead of being copied into all of them - on the real 551KB
    # sample that duplication was 65,536 copies of the same 24 UUIDs, 99.97% of an 83.8 MB
    # payload. The assertion below is the same fact as before and now also checks that the
    # hoisted base is combined back in.
    assert all(
        "e-function" in merged_source_anchor(value, step)["source_evidence_ids"]
        for step in value["steps"]
    )
    assert value["source_anchor_base"]["source_evidence_ids"]


def test_static_abstract_execution_recovers_ppid_sequence_as_prediction() -> None:
    result = StaticAbstractExecutor().analyze(
        _function(
            "CreateToolhelp32Snapshot",
            "Process32FirstW",
            "OpenProcess",
            "UpdateProcThreadAttribute",
            "CreateProcessW",
        )
    )
    ppid = [item for item in result.mechanism_candidates if item["kind"] == "ppid_spoofing"]
    assert ppid
    assert ppid[0]["attack_technique"] == "T1134.004"
    assert ppid[0]["api_sequence"][-1] == "CreateProcessW"
    assert result.runtime_observed is False


def test_static_abstract_execution_marks_unknown_api_and_budget() -> None:
    result = StaticAbstractExecutor(max_steps=2).analyze(
        _function("UnknownIndirectCall", "VirtualAlloc", "CreateThread")
    )
    assert result.unknowns
    assert any("budget" in item for item in result.unknowns)
    assert result.confidence == "LOW"


def test_static_abstract_execution_accepts_call_targets_without_type() -> None:
    """Legacy function_context projections still represent callable edges."""
    function = {
        "name": "FUN_loader",
        "entry": "0x401000",
        "call_targets": [
            {"from": "0x401010", "target_name": "VirtualAlloc"},
            {"from": "0x401020", "target_name": "WriteProcessMemory"},
            {"from": "0x401030", "target_name": "VirtualProtect"},
            {"from": "0x401040", "target_name": "CreateThread"},
        ],
    }

    result = StaticAbstractExecutor().analyze(function)

    assert [step.api for step in result.steps] == [
        "VirtualAlloc",
        "WriteProcessMemory",
        "VirtualProtect",
        "CreateThread",
    ]
    assert [step.operation for step in result.steps] == [
        "allocate_memory",
        "write_memory",
        "change_memory_protection",
        "start_thread_or_inject",
    ]
    assert any(item["kind"] == "memory_loader" for item in result.mechanism_candidates)


def _gate_function(*instructions: str) -> dict[str, object]:
    """The real anti-sandbox prologue of task 2fcc0fdc FUN_140004605."""
    return {
        "name": "FUN_140004605",
        "entry": "0x140004605",
        "instructions": [{"text": text} for text in instructions],
    }


def test_compare_records_the_threshold_on_the_side_intel_subtracts() -> None:
    """``CMP RAX,0x493e1`` derives the flags from ``RAX - 0x493e1``.

    The published report could not state the recovered anti-sandbox gate because a
    bare ``RAX cmp 0X493E1`` left the direction to the reader.  The constant was in
    the trace; the comparison's meaning was not.
    """
    result = StaticAbstractExecutor().analyze(
        _gate_function("CMP RAX,0x493e1", "JBE 0x1400046d0")
    )
    expressions = [item.expression for item in result.path_conditions]
    trace_conditions = [step.path_condition for step in result.steps if step.path_condition]
    compared = next(item for item in expressions if "cmp" in item)

    # The destination operand stays first (traceable to the disassembly) and the
    # derivation is explicit, so the expression cannot be read backwards.
    assert compared.startswith("RAX cmp 0X493E1")
    assert "RAX - 0X493E1" in compared
    assert "0X493E1" in compared
    assert compared in trace_conditions
    # Threshold is recoverable as the constant the comparison subtracts.
    assert "0x493e1" in compared.casefold()


def test_compare_keeps_a_memory_destination_verbatim_with_its_constant() -> None:
    """``CMP qword ptr [RSI + 0x8],0x60000000`` is the 1.5 GiB memory gate."""
    result = StaticAbstractExecutor().analyze(
        _gate_function("CMP qword ptr [RSI + 0x8],0x60000000", "JBE 0x140004760")
    )
    compared = next(item.expression for item in result.path_conditions if "cmp" in item.expression)

    assert compared.startswith("QWORD PTR [RSI + 0X8] cmp 0X60000000")
    assert "QWORD PTR [RSI + 0X8] - 0X60000000" in compared
    assert "0x60000000" in compared.casefold()


def test_test_records_a_zero_test_without_claiming_an_order() -> None:
    """``TEST dst, src`` is a bitwise AND: there is no ordering to recover."""
    result = StaticAbstractExecutor().analyze(_gate_function("TEST RAX,RAX"))

    compared = next(item.expression for item in result.path_conditions if "test" in item.expression)
    assert compared.startswith("RAX test RAX")
    assert "RAX & RAX" in compared
    # A TEST must not be rendered as a subtraction with a direction.
    assert " - " not in compared


def test_compare_without_a_second_operand_stays_non_committal() -> None:
    """A truncated ``CMP dst`` must not invent a self-subtraction."""
    result = StaticAbstractExecutor().analyze(_gate_function("CMP RCX"))

    compared = next(item.expression for item in result.path_conditions if "cmp" in item.expression)
    assert compared == "RCX cmp nonzero"
    assert " - " not in compared
