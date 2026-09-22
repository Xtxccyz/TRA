from __future__ import annotations

from threat_report_agent.behavior_catalog import (
    BehaviorCatalog,
    EvidenceContract,
    EvidencePredicate,
    RelationPredicate,
    SupportLevel,
    object_identity,
)


def test_catalog_is_versioned_broad_and_resolves_legacy_mechanism_aliases() -> None:
    catalog = BehaviorCatalog()

    assert len(catalog.entries) >= 24
    assert catalog.catalog_id == "behavior-catalog-v1.0.0"
    assert len(catalog.digest) == 64
    assert catalog.by_id("PPID_SPOOFING").id == "parent-process-spoofing"
    assert catalog.by_id("v3-network-transport").id == "network-transport"
    assert catalog.by_id("does-not-exist") is None
    assert catalog.resolve_or_unknown("does-not-exist").id == "unique-or-unknown"
    assert any(item.support["real_validation"] == SupportLevel.NOT_VALIDATED.value for item in catalog.entries)


def test_api_predicate_uses_exact_typed_symbol_and_rejects_rendered_text() -> None:
    predicate = EvidencePredicate.api("process-sink", ("CreateProcessW",), kinds=("function_call",))
    good = {"id": "good", "kind": "function_call", "value": {"api": "KERNEL32!CreateProcessW"}}
    substring = {"id": "substring", "kind": "function_call", "value": {"api": "CreateProcessWWrapper"}}
    rendered = {"id": "rendered", "kind": "function_call", "value": {"text": "CreateProcessW"}}
    unknown = {"id": "unknown", "kind": "function_call", "value": {"api": "UNKNOWN"}}

    assert predicate.evaluate([good, substring, rendered, unknown]).matched_evidence_ids == ("good",)


def test_api_predicate_normalizes_callsite_decoration_without_substring_matching() -> None:
    predicate = EvidencePredicate.api("process-sink", ("CreateProcessW",), kinds=("function_call",))
    rows = [
        {"id": "qualified", "kind": "function_call", "value": {"api": "KERNEL32!CreateProcessW STARTUPINFOEX"}},
        {"id": "args", "kind": "function_call", "value": {"api": "CreateProcessW(lpApplicationName, lpCommandLine)"}},
        {"id": "decorated", "kind": "function_call", "value": {"api": "__imp_CreateProcessW@28"}},
        {"id": "wrapper", "kind": "function_call", "value": {"api": "CreateProcessWWrapper"}},
    ]
    assert predicate.evaluate(rows).matched_evidence_ids == ("qualified", "args", "decorated")


def test_contract_rejects_placeholder_negative_and_unproven_relation() -> None:
    contract = EvidenceContract(
        fact_predicates=(
            EvidencePredicate.field("output", "value.output_buffer"),
            EvidencePredicate.field("consumer", "value.consumer"),
        ),
        relation_predicates=(
            RelationPredicate(
                "output-to-consumer",
                ("output_to_consumer",),
                source_paths=(("value", "output_buffer"),),
                target_paths=(("value", "input_buffer"),),
                require_same_object=True,
            ),
        ),
    )
    buffer_a = {"artifact_id": "a1", "address_space": "static", "address": "0x2000", "length": 16}
    buffer_b = {"artifact_id": "a1", "address_space": "static", "address": "0x3000", "length": 16}
    rows = [
        {"id": "out", "kind": "decode_result", "nature": "STATIC_OBSERVED", "value": {"output_buffer": buffer_a}},
        {"id": "consumer", "kind": "api_argument_trace", "nature": "STATIC_OBSERVED", "value": {"consumer": "LoadLibraryW", "input_buffer": buffer_a}},
        {"id": "link", "kind": "value_flow", "nature": "STATIC_DERIVED", "value": {"relation": "output_to_consumer", "source_evidence_ids": ["out"], "target_evidence_ids": ["consumer"], "output_buffer": buffer_a, "input_buffer": buffer_a}},
    ]
    assert contract.evaluate(rows).accepted is True

    bad_rows = [
        {"id": "out", "kind": "decode_result", "value": {"output_buffer": buffer_a}},
        {"id": "consumer", "kind": "api_argument_trace", "value": {"consumer": "NOT_IDENTIFIED", "input_buffer": buffer_b}},
        {"id": "link", "kind": "value_flow", "value": {"relation": "output_to_consumer", "source_evidence_ids": ["out"], "target_evidence_ids": ["consumer"], "output_buffer": buffer_a, "input_buffer": buffer_b}},
    ]
    result = contract.evaluate(bad_rows)
    assert result.accepted is False
    assert result.status == "UNKNOWN"
    assert "consumer" in result.missing
    assert "output-to-consumer" in result.missing


def test_object_identity_requires_artifact_address_space_and_extent() -> None:
    assert object_identity({"artifact_id": "a", "address_space": "static", "address": "0x1", "length": 4})
    assert object_identity({"artifact_id": "a", "address": "0x1", "length": 4}) is None
    assert object_identity({"artifact_id": "a", "address_space": "static", "address": "0x1"}) is None
    assert object_identity({"artifact_id": "a", "address_space": "static", "object_id": "buf-1"})


def test_relation_requires_both_provenance_sides_and_rejects_background_rows() -> None:
    """A link cannot self-assert a producer or use background prose as proof."""
    predicate = RelationPredicate(
        "output-to-consumer",
        ("output_to_consumer",),
        source_paths=(("value", "output_buffer"),),
        target_paths=(("value", "input_buffer"),),
        require_same_object=True,
    )
    buffer_a = {
        "artifact_id": "a1",
        "address_space": "static",
        "address": "0x2000",
        "length": 16,
    }
    producer = {
        "id": "producer",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {"output_buffer": buffer_a},
    }
    consumer = {
        "id": "consumer",
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {"input_buffer": buffer_a, "consumer": "LoadLibraryW"},
    }

    missing_target = {
        "id": "partial-link",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "output_to_consumer",
            "source_evidence_ids": ["producer"],
            "output_buffer": buffer_a,
            "input_buffer": buffer_a,
        },
    }
    assert not predicate.evaluate([producer, consumer, missing_target]).matched

    background_link = {
        "id": "background-link",
        "kind": "value_flow",
        "nature": "BACKGROUND_REPORTED",
        "value": {
            "relation": "output_to_consumer",
            "source_evidence_ids": ["producer"],
            "target_evidence_ids": ["consumer"],
        },
    }
    assert not predicate.evaluate([producer, consumer, background_link]).matched


def test_relation_provenance_must_resolve_and_match_endpoint_objects() -> None:
    """A derived row cannot self-assert a link with fabricated citations."""
    predicate = RelationPredicate(
        "output-to-consumer",
        ("output_to_consumer",),
        source_paths=("value.output_buffer",),
        target_paths=("value.input_buffer",),
        require_same_object=True,
    )
    source_buffer = {
        "artifact_id": "a1", "address_space": "static", "address": "0x10", "length": 8,
    }
    other_buffer = {
        "artifact_id": "a1", "address_space": "static", "address": "0x20", "length": 8,
    }
    producer = {
        "id": "producer", "kind": "decode_result", "nature": "STATIC_OBSERVED",
        "value": {"output_buffer": source_buffer},
    }
    consumer = {
        "id": "consumer", "kind": "api_argument_trace", "nature": "STATIC_OBSERVED",
        "value": {"input_buffer": source_buffer},
    }
    fabricated = {
        "id": "fabricated", "kind": "value_flow", "nature": "STATIC_DERIVED",
        "value": {
            "relation": "output_to_consumer",
            "source_evidence_ids": ["does-not-exist"],
            "target_evidence_ids": ["also-missing"],
            "output_buffer": source_buffer,
            "input_buffer": source_buffer,
        },
    }
    assert not predicate.evaluate([fabricated]).matched

    mismatched_citation = {
        **fabricated,
        "id": "mismatched-citation",
        "value": {
            **fabricated["value"],
            "source_evidence_ids": ["producer"],
            "target_evidence_ids": ["consumer"],
            "output_buffer": other_buffer,
            "input_buffer": other_buffer,
        },
    }
    assert not predicate.evaluate([producer, consumer, mismatched_citation]).matched


def test_nested_unknown_status_cannot_satisfy_typed_fact() -> None:
    predicate = EvidencePredicate.field("decoded-output", "value.output")
    rows = [
        {
            "id": "unknown-output",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {"status": "UNKNOWN", "output": "a concrete-looking string"},
        },
    ]
    assert not predicate.evaluate(rows).matched


def test_object_id_is_canonical_when_optional_location_metadata_differs() -> None:
    left = {
        "artifact_id": "a1", "address_space": "static", "object_id": "buf-1",
        "address": "0x10", "length": 8,
    }
    right = {
        "artifact_id": "a1", "address_space": "static", "object_id": "buf-1",
        "address": "0x18", "length": 16,
    }
    assert object_identity(left) == object_identity(right)


def test_catalog_exposes_applicability_and_truthful_executor_alias() -> None:
    catalog = BehaviorCatalog()
    entry = catalog.by_id("parent-process-spoofing")
    assert entry is not None
    assert entry.attack_candidates == ("T1134.004",)
    assert entry.applicability
    assert entry.executor_support == entry.executor
    assert entry.support["applicability"] == list(entry.applicability)
    serialized = catalog.as_dict()
    serialized_entry = next(item for item in serialized["entries"] if item["id"] == entry.id)
    assert serialized_entry["contract"]["fact_predicates"]
    assert serialized_entry["contract"]["relation_predicates"]
    assert serialized_entry["support"]["validation"] == serialized_entry["support"]["real_validation"]


def test_verifier_does_not_promote_specialist_from_string_cooccurrence() -> None:
    """A registered specialist still needs its typed contract first."""
    from threat_report_agent.investigation import Verifier

    rows = [
        {
            "id": "explorer",
            "kind": "string",
            "nature": "STATIC_OBSERVED",
            "value": {"text": "explorer.exe Process32First"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "open",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "OpenProcess(PROCESS_CREATE_PROCESS)"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "attribute",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "UpdateProcThreadAttribute PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "create",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW STARTUPINFOEX"},
            "anchor": {"function_entry": "0x1000"},
        },
        {
            "id": "flags",
            "kind": "constant",
            "nature": "STATIC_OBSERVED",
            "value": {"flags": "0x09080008 CREATE_NO_WINDOW DETACHED_PROCESS"},
            "anchor": {"function_entry": "0x1000"},
        },
    ]
    decision = Verifier().evaluate(
        rows,
        "Does the sample spoof its parent process?",
        "The sample may implement PPID spoofing.",
    )
    assert decision.accepted is False
    assert decision.status == "UNKNOWN"
    assert "typed" in decision.reason.lower() or any(
        item.startswith("fact:") for item in decision.missing
    )


def test_verifier_requires_typed_ppid_facts_and_handle_relation_before_support() -> None:
    from threat_report_agent.investigation import Verifier

    parent_handle = {
        "artifact_id": "a1",
        "handle_id": "h-parent",
    }
    attribute_handle = {
        "artifact_id": "a1",
        "handle_id": "h-attribute",
    }
    anchor = {"function_entry": "0x1000"}
    rows = [
        {
            "id": "selection",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "Process32First", "parent_selection": "explorer.exe"},
            "anchor": anchor,
        },
        {
            "id": "open",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "OpenProcess",
                "access_mask": "PROCESS_CREATE_PROCESS",
                "parent_handle": parent_handle,
            },
            "anchor": anchor,
        },
        {
            "id": "attribute",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                "attribute_handle": attribute_handle,
            },
            "anchor": anchor,
        },
        {
            "id": "startup",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateProcessW",
                "startup_info": "STARTUPINFOEX",
                "creation_flags": "0x09080008",
            },
            "anchor": anchor,
        },
        {
            "id": "relation",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "parent_handle_to_attribute",
                "source_evidence_ids": ["open"],
                "target_evidence_ids": ["attribute"],
                "parent_handle": parent_handle,
                "attribute_handle": attribute_handle,
            },
            "anchor": anchor,
        },
    ]
    decision = Verifier().evaluate(
        rows,
        "Does the sample spoof its parent process?",
        "The sample may implement PPID spoofing.",
    )
    assert decision.accepted is True
    assert decision.status == "SUPPORTED"

    # Removing the consumer citation must reopen the contract even though
    # every API and token remains present.
    bad = [
        row
        if row["id"] != "relation"
        else {
            **row,
            "value": {
                **row["value"],
                "target_evidence_ids": [],
            },
        }
        for row in rows
    ]
    rejected = Verifier().evaluate(
        bad,
        "Does the sample spoof its parent process?",
        "The sample may implement PPID spoofing.",
    )
    assert rejected.accepted is False
    assert rejected.status == "UNKNOWN"


def test_process_and_thread_entries_register_specialized_verifiers() -> None:
    catalog = BehaviorCatalog()
    process = catalog.by_id("PROCESS_EXECUTION")
    thread = catalog.by_id("THREAD_CALLBACK")
    guard = catalog.by_id("ENVIRONMENT_GUARD")
    assert process is not None
    assert process.verifier_id == "PROCESS_EXECUTION"
    assert process.verifier == SupportLevel.SUPPORTED
    assert thread is not None
    assert thread.verifier_id == "THREAD_CALLBACK"
    assert thread.verifier == SupportLevel.SUPPORTED
    assert guard is not None
    assert guard.id == "environment-guard"
    assert guard.verifier_id == "ENVIRONMENT_GUARD"
    assert guard.verifier == SupportLevel.SUPPORTED
    assert "environment API alone proves anti-analysis" in guard.contract.forbidden_inferences


def _c3_join_buffer(address: object = "0x14004C8E1") -> dict[str, object]:
    return {
        "artifact_id": "artifact-1",
        "address_space": "image",
        "address": address,
        "length": 24,
    }


def test_decode_output_to_process_command_is_optional_catalog_join() -> None:
    """Missing Join must not catalog-fail process-creation or config-and-crypto."""
    catalog = BehaviorCatalog()
    for entry_id in ("process-creation", "config-and-crypto"):
        entry = catalog.by_id(entry_id)
        assert entry is not None
        relation_ids = [item.id for item in entry.contract.relation_predicates]
        assert "decode_output_to_process_command" in relation_ids
        assert "decode_output_to_process_command" not in entry.contract.required_relations
        optional = [
            item
            for item in entry.contract.relation_predicates
            if item.id == "decode_output_to_process_command"
        ]
        assert optional
        assert optional[0].required is False

    process_rows = [
        {
            "id": "call-1",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW", "command": "FoxitPDFReader.exe"},
        },
    ]
    process_eval = catalog.evaluate("process-creation", process_rows)
    assert "decode_output_to_process_command" not in process_eval.missing
    xor_rows = [
        {
            "id": "decode-1",
            "kind": "decode_result",
            "nature": "STATIC_OBSERVED",
            "value": {
                "plaintext": "FoxitPDFReader.exe",
                "output_buffer": _c3_join_buffer(),
            },
        },
    ]
    xor_eval = catalog.evaluate("config-and-crypto", xor_rows)
    assert "decode_output_to_process_command" not in xor_eval.missing


def test_catalog_decode_join_rejects_plaintext_command_string_match() -> None:
    catalog = BehaviorCatalog()
    entry = catalog.by_id("process-creation")
    assert entry is not None
    predicate = next(
        item
        for item in entry.contract.relation_predicates
        if item.id == "decode_output_to_process_command"
    )
    producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {"plaintext": "FoxitPDFReader.exe"},
    }
    process_row = {
        "id": "call-1",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "CreateProcessW", "command": "FoxitPDFReader.exe"},
    }
    string_link = {
        "id": "join-string",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "decode_output_to_process_command",
            "plaintext": "FoxitPDFReader.exe",
            "command": "FoxitPDFReader.exe",
            "source_evidence_ids": ["decode-1"],
            "target_evidence_ids": ["call-1"],
        },
    }
    assert not predicate.evaluate([producer, process_row, string_link]).matched

    buffer = _c3_join_buffer()
    other = _c3_join_buffer("0x140010000")
    object_producer = {
        "id": "decode-1",
        "kind": "decode_result",
        "nature": "STATIC_OBSERVED",
        "value": {"output_buffer": buffer, "plaintext": "FoxitPDFReader.exe"},
    }
    object_process = {
        "id": "call-1",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "CreateProcessW", "command_buffer": buffer, "command": "FoxitPDFReader.exe"},
    }
    mismatched = {
        "id": "join-mismatch",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "decode_output_to_process_command",
            "output_buffer": buffer,
            "command_buffer": other,
            "input_buffer": other,
            "plaintext": "FoxitPDFReader.exe",
            "command": "FoxitPDFReader.exe",
            "source_evidence_ids": ["decode-1"],
            "target_evidence_ids": ["call-1"],
        },
    }
    assert not predicate.evaluate([object_producer, object_process, mismatched]).matched

    joined = {
        "id": "join-obj",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "decode_output_to_process_command",
            "output_buffer": buffer,
            "command_buffer": buffer,
            "input_buffer": buffer,
            "plaintext": "FoxitPDFReader.exe",
            "command": "FoxitPDFReader.exe",
            "source_evidence_ids": ["decode-1"],
            "target_evidence_ids": ["call-1"],
        },
    }
    assert predicate.evaluate([object_producer, object_process, joined]).matched


def test_communication_loop_back_edge_is_optional() -> None:
    catalog = BehaviorCatalog()
    entry = catalog.by_id("communication-loop")
    assert entry is not None
    assert "back_edge" not in entry.contract.required_facts
    back_edge = next(item for item in entry.contract.fact_predicates if item.id == "back_edge")
    assert back_edge.required is False
    result = catalog.evaluate("communication-loop", [])
    assert "back_edge" not in result.missing
    assert result.status == "UNKNOWN"


def test_file_operations_size_is_optional() -> None:
    catalog = BehaviorCatalog()
    entry = catalog.by_id("file-operations")
    assert entry is not None
    assert "size" not in entry.contract.required_facts
    size = next(item for item in entry.contract.fact_predicates if item.id == "size")
    assert size.required is False
    result = catalog.evaluate(
        "file-operations",
        [
            {
                "id": "path-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {"path": "C:\\Windows\\Temp\\a.tmp", "access": "GENERIC_WRITE"},
            }
        ],
    )
    assert "size" not in result.missing


def test_defender_dword_value_is_optional() -> None:
    catalog = BehaviorCatalog()
    for entry_id in ("defender-modification", "defense-evasion"):
        entry = catalog.by_id(entry_id)
        assert entry is not None
        assert "dword" not in entry.contract.required_facts
        dword = [item for item in entry.contract.fact_predicates if item.id == "dword"]
        assert dword
        assert dword[0].required is False
        result = catalog.evaluate(
            entry_id,
            [
                {
                    "id": "reg-1",
                    "kind": "function_call",
                    "nature": "STATIC_OBSERVED",
                    "value": {
                        "api": "RegSetValueExW",
                        "key": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                        "value_name": "DisableAntiSpyware",
                    },
                }
            ],
        )
        assert "dword" not in result.missing
        if entry_id == "defense-evasion":
            assert result.status == "UNKNOWN"

