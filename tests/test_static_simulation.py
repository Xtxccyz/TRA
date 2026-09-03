from threat_report_agent.static_simulation import StaticAbstractExecutor


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
    assert all("e-function" in step["source_anchor"]["source_evidence_ids"] for step in value["steps"])


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
