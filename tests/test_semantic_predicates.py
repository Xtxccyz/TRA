from threat_report_agent.investigation.semantic_predicates import (
    ApiSemantic,
    classify_api_symbol,
    normalize_api_symbol,
    semantic_category,
)


def test_ghidra_import_pointer_labels_recover_api_semantics() -> None:
    assert normalize_api_symbol("PTR_CreateProcessW_1401024d8") == "createprocessw"
    assert classify_api_symbol("PTR_CreateProcessW_1401024d8") is ApiSemantic.PROCESS_CREATION
    assert semantic_category("PTR_CreatePipe_1401024d0") == "file_io"
    assert semantic_category("PTR_LoadLibraryW_1401025e8") == "dynamic_resolution"
    assert semantic_category("PTR_GetModuleHandleA_140102570") == "dynamic_resolution"
    assert semantic_category("PTR_SetHandleInformation_140102650") == "file_io"
