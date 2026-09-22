import pytest

from threat_report_agent.investigation.behavior_catalog import BehaviorCatalog
from threat_report_agent.dataflow import (
    addresses_alias,
    catalog_fields_from_api_arguments,
    catalog_buffers_are_same_object,
    catalog_decode_output_to_process_command_relation,
    catalog_output_consumer_relation,
    is_process_command_argument,
    is_process_execution_api,
    catalog_relation_from_api_fields,
    catalog_relation_from_parent_attribute,
    catalog_relation_from_resolved_api,
    catalog_parent_handle_identity,
    catalog_resolved_pointer_identity,
    catalog_return_branch_after_call,
    consumer_from_decoded_pointer,
    consumer_from_decoded_reference,
    decoded_output_consumer,
    decoded_output_from_argument_trace,
    is_ghidra_data_or_string_label,
    is_named_decode_consumer_api,
    is_object_level_decode_consumer,
    output_buffer_identity,
    parse_operand_address,
    trace_return_consumers,
    with_artifact_identity,
)


def test_return_trace_follows_value_to_consumer_not_producer_callees():
    function = {
        "name": "caller",
        "architecture": "x86_64",
        "instructions": [
            {"address": "0x1000", "text": "CALL decode_config"},
            {"address": "0x1005", "text": "MOV RBX, RAX"},
            {"address": "0x1008", "text": "CALL unrelated"},
            {"address": "0x100d", "text": "MOV RCX, RBX"},
            {"address": "0x1010", "text": "CALL LoadLibraryW"},
        ],
    }
    links = trace_return_consumers(function, ("decode_config",))
    assert len(links) == 1
    assert links[0]["api"] == "LoadLibraryW"
    assert links[0]["argument_index"] == 0
    assert links[0]["producer_callsite"] == "0x1000"
    assert links[0]["callsite"] == "0x1010"
    assert links[0]["copy_sites"] == ["0x1005", "0x100d"]


def test_decode_consumer_uses_object_alias_not_exact_length():
    """ADR-0035 / G1 §5.2: Join is an object-alias relation, not byte equality.

    A decoded configuration block is consumed through a pointer into its
    interior, so requiring address *and* length equality left Resume-style
    slices permanently ``UNKNOWN(join)``. Co-occurrence is still rejected.
    """
    output = {"address_space": "artifact-1:memory", "address": "0x2000", "length": 24}
    candidate = {"output_buffer": output}
    trace = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "LoadLibraryW",
        "callsite": "0x1010",
        "argument_index": 0,
        "source_buffer": output,
    }
    assert decoded_output_consumer("decode-1", candidate, "api_argument_trace", trace, {})
    # Same address with a shorter length is a slice of the decoded output.
    assert decoded_output_consumer(
        "decode-1",
        candidate,
        "api_argument_trace",
        {**trace, "source_buffer": {**output, "length": 12}},
        {},
    )
    for change in (
        {"resolved": "UNKNOWN"},
        {"producer_evidence_id": "decode-2"},
        {"source_buffer": {**output, "address": "0x3000"}},
        {"source_buffer": {**output, "address_space": "artifact-2:memory"}},
        {"source_role": "ciphertext"},
        {"api": "UNKNOWN"},
        {"api": "n/a"},
    ):
        assert not decoded_output_consumer(
            "decode-1", candidate, "api_argument_trace", {**trace, **change}, {}
        )


def test_catalog_buffers_require_same_artifact_and_address():
    """T1: Join identity is artifact_id+address[+length], not matching strings."""
    left = {
        "artifact_id": "artifact-1",
        "address_space": "image",
        "address": 0x14004C900,
        "length": 40,
    }
    assert catalog_buffers_are_same_object(left, dict(left))
    assert not catalog_buffers_are_same_object(
        left,
        {**left, "address": 0x140010000},
    )
    assert not catalog_buffers_are_same_object(
        left,
        {**left, "artifact_id": "artifact-2"},
    )
    assert not catalog_buffers_are_same_object(
        left,
        {**left, "length": 12},
    )
    assert not catalog_buffers_are_same_object(
        {"address": 0x14004C900, "length": 40},
        {"address": 0x14004C900, "length": 40},
    )
    # Missing length on one side still matches address+artifact.
    assert catalog_buffers_are_same_object(
        left,
        {"artifact_id": "artifact-1", "address": 0x14004C900},
    )


def test_xor_url_string_match_is_not_a_winhttp_join():
    """T1: matching URL text without the same buffer is not output_to_consumer Join."""
    output = {
        "artifact_id": "artifact-1",
        "address": 0x14004C900,
        "length": 40,
    }
    other = {
        "artifact_id": "artifact-1",
        "address": 0x140010000,
        "length": 40,
    }
    assert not catalog_buffers_are_same_object(output, other)
    # Relation helper still requires an identified output buffer; it does not
    # compare URL strings. Different buffers must not be treated as joined.
    linked = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="http-1",
        output_buffer=output,
        consumer_api="WinHttpOpen",
    )
    assert linked is not None
    assert linked["relation"] == "output_to_consumer"
    assert not catalog_buffers_are_same_object(output, other)


def test_catalog_output_consumer_relation_requires_buffer_identity():
    assert catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="api-1",
        output_buffer={"address": 0x5000, "length": 24},
        consumer_api="LoadLibraryW",
    ) is None
    linked = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="api-1",
        output_buffer={
            "artifact_id": "artifact-1",
            "address_space": "artifact-1",
            "address": 0x5000,
            "length": 24,
        },
        consumer_api="LoadLibraryW",
    )
    assert linked is not None
    assert linked["relation"] == "output_to_consumer"
    assert linked["output_buffer"]["artifact_id"] == "artifact-1"


def test_data_xref_is_not_an_object_level_decode_consumer():
    assert not is_object_level_decode_consumer(
        {"link_kind": "decoded_va_reference", "api": "FUN_140004605"}
    )
    assert not is_object_level_decode_consumer(
        {"link_kind": "decoded_va_reference", "api": "LoadLibraryW"}
    )
    assert not is_named_decode_consumer_api("FUN_140004605")
    assert not is_named_decode_consumer_api("lstrlenA")
    assert is_object_level_decode_consumer(
        {"link_kind": "decoded_pointer_to_call", "api": "LoadLibraryW"}
    )
    assert is_object_level_decode_consumer(
        {"relation": "output_to_consumer", "api": "WinHttpOpen"}
    )
    assert is_object_level_decode_consumer(
        {"kind": "api_argument_trace", "api": "LoadLibraryW"}
    )


def test_decode_plaintext_string_match_is_not_a_process_join():
    buffer = {
        "artifact_id": "artifact-1",
        "address_space": "artifact-1",
        "address": 0x14004C8E1,
        "length": 24,
    }
    assert catalog_decode_output_to_process_command_relation(
        decode_id="decode-1",
        process_id="proc-1",
        output_buffer=buffer,
        command_buffer={"artifact_id": "artifact-1", "address": 0x140010000, "length": 24},
        plaintext="FoxitPDFReader.exe",
        command="FoxitPDFReader.exe",
    ) is None
    joined = catalog_decode_output_to_process_command_relation(
        decode_id="decode-1",
        process_id="proc-1",
        output_buffer=buffer,
        command_buffer=dict(buffer),
        plaintext="FoxitPDFReader.exe",
        command="FoxitPDFReader.exe",
    )
    assert joined is not None
    assert joined["relation"] == "decode_output_to_process_command"


def test_process_command_argument_is_image_or_command_slot_only():
    assert is_process_execution_api("KERNEL32!CreateProcessW")
    assert is_process_command_argument("CreateProcessW", 0)
    assert is_process_command_argument("CreateProcessW", 1)
    assert not is_process_command_argument("CreateProcessW", 5)
    assert not is_process_command_argument("CreateProcessW", None)
    assert not is_process_command_argument("LoadLibraryW", 0)
    assert is_process_command_argument("WinExec", 0)
    assert is_process_command_argument("ShellExecuteW", 2)


def test_nested_argument_window_links_only_when_operand_is_the_output_buffer():
    output = {"address_space": "image", "address": 0x140005000, "length": 24}
    candidate = {"output_buffer": output}
    nested = {
        "api": "LoadLibraryW",
        "callsite": "0x401020",
        "arguments": [
            {"index": 0, "register": "RCX", "value": "0x140005000", "resolved": True},
            {"index": 1, "register": "RDX", "value": "UNKNOWN", "resolved": False},
        ],
    }
    linked = decoded_output_from_argument_trace(
        "decode-1", candidate, "api_argument_trace", nested, {}
    )
    assert linked is not None
    assert linked["producer_evidence_id"] == "decode-1"
    assert linked["source_role"] == "decoded_output"
    assert linked["source_buffer"] == output
    nearby = {
        **nested,
        "arguments": [
            {"index": 0, "register": "RCX", "value": '"kernel32.dll"', "resolved": True},
        ],
    }
    assert decoded_output_from_argument_trace(
        "decode-1", candidate, "api_argument_trace", nearby, {}
    ) is None
    assert addresses_alias(0x5000, 0x140005000, 0x140000000)
    assert parse_operand_address("qword ptr [0x140005000]") == 0x140005000
    assert parse_operand_address('"kernel32.dll"') is None
    assert output_buffer_identity(address_space="image", address=0x5000, length=0) is None


def test_catalog_fields_ignore_registers_and_project_resolved_createprocess_args():
    """Nested TRACE_API_ARGUMENT windows keep UNKNOWN slots; catalog facts must not."""
    fields = catalog_fields_from_api_arguments(
        "KERNEL32!CreateProcessW",
        (
            {"index": 0, "register": "RCX", "value": "R14", "resolved": True},
            {
                "index": 1,
                "name": "lpCommandLine",
                "value": '"schtasks.exe /create"',
                "resolved": True,
            },
            {"index": 2, "register": "R8", "value": "UNKNOWN", "resolved": False},
            {
                "index": 5,
                "name": "dwCreationFlags",
                "value": "0x09080008",
                "resolved": True,
            },
        ),
    )
    assert fields["command"] == "schtasks.exe /create"
    assert fields["command_line"] == "schtasks.exe /create"
    assert fields["creation_flags"] == "0x09080008"
    assert "image" not in fields

    stacked = catalog_fields_from_api_arguments(
        "ShellExecuteW",
        (
            {
                "index": 2,
                "name": "lpFile",
                "value": "[RSP + 0x78]",
                "resolved": True,
            },
        ),
    )
    assert stacked == {}

    relation = catalog_relation_from_api_fields(
        "CreateProcessW",
        fields,
        artifact_id="artifact-1",
        callsite="0x401020",
        source_evidence_id="ins-1",
        target_evidence_id="call-1",
    )
    assert relation is not None
    assert relation["relation"] == "command_to_process_sink"
    assert relation["command_buffer"]["artifact_id"] == "artifact-1"
    assert relation["process_sink"]["handle_id"]

    catalog = BehaviorCatalog()
    rows = [
        {
            "id": "ins-1",
            "kind": "function_instruction_window",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "MOV RDX, command"},
        },
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
        },
        {
            "id": "trace",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {"api": "CreateProcessW", **fields},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": relation,
        },
    ]
    result = catalog.evaluate("process-creation", rows)
    assert "fact:image_or_command" not in result.missing
    assert "image_or_command" not in result.missing
    assert "creation_flags" not in result.missing
    assert "command_to_process_sink" not in result.missing
    assert "process_sink" not in result.missing
    # return_branch is a separate TRACE_RETURN_VALUE fact; do not invent it.
    assert any(item.endswith("return_branch") for item in result.missing)
    assert result.accepted is False


def test_recovered_createprocess_fields_close_process_creation_catalog():
    fields = catalog_fields_from_api_arguments(
        "KERNEL32!CreateProcessW",
        (
            {
                "index": 1,
                "name": "lpCommandLine",
                "value": "cmd.exe /c FoxitPDFReader.exe",
                "resolved": True,
            },
            {
                "index": 5,
                "name": "dwCreationFlags",
                "value": "0x000f4240",
                "resolved": True,
            },
        ),
    )
    fields["return_branch"] = "JZ 0x140004780"
    relation = catalog_relation_from_api_fields(
        "CreateProcessW",
        fields,
        artifact_id="artifact-1",
        callsite="0x140004710",
        source_evidence_id="ins-1",
        target_evidence_id="call-1",
    )
    rows = [
        {
            "id": "ins-1",
            "kind": "function_instruction_window",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "LEA RDX, cmd.exe"},
        },
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW"},
        },
        {
            "id": "trace",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {"api": "CreateProcessW", **fields},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": relation,
        },
    ]
    result = BehaviorCatalog().evaluate("process-creation", rows)
    assert result.accepted is True
    assert result.status == "SUPPORTED_STATIC"


def test_resolved_api_relation_closes_loader_catalog():
    """Resume GetProcAddress → JMP R8 is a persist-time catalog relation, not a later TRACE."""
    resolution = {
        "resolver": "GetProcAddress",
        "resolver_callsite": "140038dfd",
        "api_name": "SetThreadDescription",
        "module_input": "kernel32.dll",
        "consumer": "JMP R8",
        "consumer_callsite": "140038e2d",
        "consumer_kind": "JUMP",
    }
    pointer = catalog_resolved_pointer_identity(
        artifact_id="artifact-1",
        callsite="140038dfd",
    )
    assert pointer is not None
    stamped = {
        **resolution,
        "api_identity": "SetThreadDescription",
        "resolved_pointer": pointer,
        "output_buffer": pointer,
        "consumer_pointer": pointer,
        "input_buffer": pointer,
    }
    relation = catalog_relation_from_resolved_api(
        stamped,
        artifact_id="artifact-1",
        source_evidence_id="resolved-1",
        target_evidence_id="resolved-1",
    )
    assert relation is not None
    assert relation["relation"] == "resolved_pointer_to_call"
    assert catalog_relation_from_resolved_api(
        {**resolution, "consumer": None, "consumer_callsite": None},
        artifact_id="artifact-1",
        source_evidence_id="resolved-1",
    ) is None
    rows = [
        {
            "id": "resolved-1",
            "kind": "resolved_api",
            "nature": "STATIC_DERIVED",
            "value": stamped,
            "anchor": {"function_entry": "0x140038dd0"},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": relation,
            "anchor": {"function_entry": "0x140038dd0"},
        },
    ]
    result = BehaviorCatalog().evaluate("loader-and-api-resolution", rows)
    assert "module_input" not in result.missing
    assert "api_identity" not in result.missing
    assert "resolver" not in result.missing
    assert "consumer" not in result.missing
    assert "resolved_pointer_to_call" not in result.missing
    assert result.accepted is True
    assert result.status == "SUPPORTED_STATIC"


def test_createthread_start_address_projects_without_unresolved_slots():
    fields = catalog_fields_from_api_arguments(
        "CreateThread",
        (
            {"index": 0, "value": "UNKNOWN", "resolved": False},
            {"index": 1, "value": "0x0", "resolved": True},
            {
                "index": 2,
                "name": "lpStartAddress",
                "value": "0x140038ae0",
                "resolved": True,
            },
            {"index": 3, "register": "R9", "value": "UNKNOWN", "resolved": False},
        ),
    )
    assert fields["entry_routine"] == "0x140038ae0"
    assert "parameter" not in fields


def test_artifact_identity_is_required_before_catalog_object_relations():
    bare = {"address_space": "image", "address": 0x140005000, "length": 24}
    identified = with_artifact_identity(bare, "artifact-1")
    assert identified["artifact_id"] == "artifact-1"
    assert with_artifact_identity(bare, "") is None


@pytest.mark.parametrize("intervening", [
    "CALL unrelated", "XOR EAX, EAX", "MOV EAX, 7", "MOV AL, 7", "MOV AH, 7",
    "MOV AX, 7", "CDQE", "JNZ 0x2000", "CPUID",
])
def test_return_trace_does_not_keep_clobbered_or_cross_branch_values(intervening):
    function = {"instructions": [
        {"address": "0x1000", "text": "CALL decode_config"},
        {"address": "0x1005", "text": intervening},
        {"address": "0x1008", "text": "MOV RCX, RAX"},
        {"address": "0x1010", "text": "CALL LoadLibraryW"},
    ]}
    assert trace_return_consumers(function, ("decode_config",)) == ()


def test_catalog_return_branch_requires_test_then_conditional_jump():
    assert catalog_return_branch_after_call(
        (
            {"address": "0x401024", "text": "TEST EAX, EAX"},
            {"address": "0x401026", "text": "JZ 0x401080"},
        )
    ) == "JZ 0x401080"
    assert catalog_return_branch_after_call(
        (
            {"address": "0x401024", "text": "MOV ECX, EAX"},
            {"address": "0x401026", "text": "JZ 0x401080"},
        )
    ) is None


def test_decoded_pointer_consumer_links_register_load_to_the_next_call():
    output = 0x140005000
    hit = consumer_from_decoded_pointer(
        (
            {"address": "0x401000", "text": "LEA RCX, [0x140005000]"},
            {"address": "0x401007", "text": "CALL WinHttpConnect"},
        ),
        output,
    )
    assert hit is not None
    assert hit["api"] == "WinHttpConnect"
    assert hit["argument_index"] == 0
    missed = consumer_from_decoded_pointer(
        (
            {"address": "0x401000", "text": "LEA RCX, [0x140006000]"},
            {"address": "0x401007", "text": "CALL WinHttpConnect"},
        ),
        output,
    )
    assert missed is None


def test_ghidra_string_labels_are_not_api_names():
    assert is_ghidra_data_or_string_label("s_winhttp_export_not_found_14004c66f")
    assert is_ghidra_data_or_string_label("DAT_14004c8e1")
    assert not is_ghidra_data_or_string_label("WinHttpConnect")
    assert not is_ghidra_data_or_string_label("PTR_CreateProcessW_1401024d8")


def test_decoded_reference_consumer_links_rdata_xref_to_the_same_va():
    output = 0x14004C8E1
    hit = consumer_from_decoded_reference(
        "data_reference",
        {"from": "0x140003010", "to": "0x14004c8e1", "target_name": "DAT_14004c8e1"},
        {"function_entry": "0x140003000"},
        output,
    )
    assert hit is not None
    assert hit["callsite"] == "0x140003010"
    assert hit["link_kind"] == "decoded_va_reference"
    assert hit["api"] is None
    nested = consumer_from_decoded_reference(
        "function_context",
        {
            "name": "FUN_140003000",
            "entry": "0x140003000",
            "data_references": [{"from": "0x140003010", "to": 5369022689}],
        },
        {"function_entry": "0x140003000"},
        output,
        image_base=0x140000000,
    )
    assert nested is not None
    assert nested["callsite"] == "0x140003010"
    missed = consumer_from_decoded_reference(
        "data_reference",
        {"from": "0x140003010", "to": "0x14004c66f"},
        {"function_entry": "0x140003000"},
        output,
    )
    assert missed is None


def test_parent_attribute_relation_closes_ppid_catalog() -> None:
    """Persist-time parent handle identities close parent-process-spoofing without flag stuffing."""
    parent_handle = catalog_parent_handle_identity(
        artifact_id="artifact-resume",
        handle_id="openprocess:0x140008b10",
    )
    attribute_handle = catalog_parent_handle_identity(
        artifact_id="artifact-resume",
        handle_id="updateprocthreadattribute:0x140008b28",
    )
    fields = {
        "api": "UpdateProcThreadAttribute",
        "callsite": "0x140008b28",
        "parent_selection": "explorer.exe",
        "access_mask": "PROCESS_CREATE_PROCESS",
        "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        "startup_info": "STARTUPINFOEX",
        "creation_flags": "0x000f4240",
        "open_process": "OpenProcess",
        "parent_handle": parent_handle,
        "attribute_handle": attribute_handle,
    }
    relation = catalog_relation_from_parent_attribute(
        fields,
        artifact_id="artifact-resume",
        source_evidence_id="trace-ppid",
        target_evidence_id="trace-ppid",
        callsite="0x140008b28",
    )
    assert relation is not None
    assert relation["relation"] == "parent_handle_to_attribute"
    assert relation["parent_handle"]["handle_id"] == "openprocess:0x140008b10"
    assert relation["attribute_handle"]["handle_id"] == "updateprocthreadattribute:0x140008b28"
    assert "0x09080008" not in str(relation)

    rows = [
        {
            "id": "trace-ppid",
            "kind": "api_argument_trace",
            "nature": "STATIC_DERIVED",
            "value": {
                "api": "CreateProcessW",
                **fields,
            },
        },
        {
            "id": "link-ppid",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": relation,
        },
    ]
    catalog = BehaviorCatalog()
    result = catalog.evaluate("parent-process-spoofing", rows)
    assert result.accepted
    assert "parent_selection" not in result.missing
    assert "parent_handle_to_attribute" not in result.missing
    assert "fact:parent_selection" not in result.missing


# --- G1 §5.3: 解码消费者 Join (ADR-0035) ---------------------------------


def _decoded_slice_candidate() -> dict[str, object]:
    return {
        "output_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x14004A000,
            "length": 0x200,
        }
    }


def test_decoded_output_slice_is_a_winhttp_join() -> None:
    """G1 §5.3-1 正例切片：WinHttpOpenRequest 参数指向已解码缓冲内部。"""
    trace = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "WinHttpOpenRequest",
        "callsite": "0x140012340",
        "argument_index": 1,
        "source_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x14004A040,
            "length": 0x80,
        },
    }
    assert decoded_output_consumer(
        "decode-1", _decoded_slice_candidate(), "api_argument_trace", trace, {}
    )


def test_decoded_output_image_base_alias_is_a_join() -> None:
    """G1 §5.3-2 正例别名：RVA 与 image_base+RVA 指向同一区域。"""
    candidate = {
        "output_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x4A000,
            "length": 0x200,
        },
        "image_base": 0x140000000,
    }
    trace = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "CreateProcessW",
        "callsite": "0x140012340",
        "argument_index": 0,
        "source_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x14004A000,
            "length": 0x200,
        },
    }
    assert decoded_output_consumer(
        "decode-1", candidate, "api_argument_trace", trace, {}, image_base=0x140000000
    )


def test_decode_cooccurrence_without_range_is_not_a_join() -> None:
    """G1 §5.3-3 反例共现：同函数有 CreateProcess 与解码，参数却是别的 VA 或未解析。"""
    base = {
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "CreateProcessW",
        "callsite": "0x140012340",
        "argument_index": 0,
    }
    other_range = {
        **base,
        "resolved": True,
        "source_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x140060000,
            "length": 0x40,
        },
    }
    assert not decoded_output_consumer(
        "decode-1", _decoded_slice_candidate(), "api_argument_trace", other_range, {}
    )
    assert not decoded_output_consumer(
        "decode-1",
        _decoded_slice_candidate(),
        "api_argument_trace",
        {**other_range, "resolved": False},
        {},
    )


def test_hardcoded_command_string_is_not_a_decoded_join() -> None:
    """G1 §5.3-4 反例硬编码：参数字符串与明文相同，但没有地址关系。"""
    trace = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "CreateProcessW",
        "callsite": "0x140012340",
        "argument_index": 1,
        "source_buffer": {
            "address_space": "artifact-1:image",
            "address": "FoxitPDFReader.exe",
            "length": 19,
        },
    }
    assert not decoded_output_consumer(
        "decode-1", _decoded_slice_candidate(), "api_argument_trace", trace, {}
    )


def test_ghidra_fun_label_is_not_a_named_decode_consumer() -> None:
    """G1 §5.3-5 反例 FUN_：未命名目标不算命名消费者。"""
    trace = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "api": "FUN_140012345",
        "callsite": "0x140012340",
        "argument_index": 0,
        "source_buffer": {
            "address_space": "artifact-1:image",
            "address": 0x14004A000,
            "length": 0x200,
        },
    }
    assert not decoded_output_consumer(
        "decode-1", _decoded_slice_candidate(), "api_argument_trace", trace, {}
    )


def test_missing_consumer_length_joins_only_for_string_arguments() -> None:
    """G1 §5.2：长度缺失时，只有字符串类参数可以靠别名 Join。"""
    candidate = _decoded_slice_candidate()
    base = {
        "resolved": True,
        "producer_evidence_id": "decode-1",
        "source_role": "decoded_output",
        "callsite": "0x140012340",
        "source_buffer": {"address_space": "artifact-1:image", "address": 0x14004A000},
    }
    assert decoded_output_consumer(
        "decode-1",
        candidate,
        "api_argument_trace",
        {**base, "api": "WinHttpOpenRequest", "argument_index": 1},
        {},
    )
    # CreateProcessW argument 5 is dwCreationFlags: a scalar, not a pointer.
    assert not decoded_output_consumer(
        "decode-1",
        candidate,
        "api_argument_trace",
        {**base, "api": "CreateProcessW", "argument_index": 5},
        {},
    )


def test_catalog_output_consumer_relation_stamps_producer_artifact() -> None:
    """G1 §5.2：不能仅因 output_buffer 缺 artifact_id 就返回 None。"""
    buffer = {"address_space": "artifact-1:image", "address": 0x5000, "length": 24}
    linked = catalog_output_consumer_relation(
        producer_id="decode-1",
        consumer_id="api-1",
        output_buffer=buffer,
        consumer_api="WinHttpOpenRequest",
        artifact_id="artifact-1",
    )
    assert linked is not None
    assert linked["output_buffer"]["artifact_id"] == "artifact-1"
    # Nothing can supply the identity -> still unresolved, not invented.
    assert (
        catalog_output_consumer_relation(
            producer_id="decode-1",
            consumer_id="api-1",
            output_buffer=buffer,
            consumer_api="WinHttpOpenRequest",
        )
        is None
    )
