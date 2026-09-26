from __future__ import annotations

import pytest

from threat_report_agent.investigation.behavior_catalog import (
    BehaviorCatalog,
    CounterExample,
    EvidenceContract,
    EvidencePredicate,
    LEGACY_BEHAVIOR_IDS,
    RelationPredicate,
    SupportLevel,
    UNMAPPED_PLAYBOOK_PROFILES,
    counter_example,
    object_identity,
    unmapped_playbook_profiles,
    unreachable_verifier_entries,
    verifier_reachability,
)


def test_catalog_is_versioned_broad_and_resolves_legacy_mechanism_aliases() -> None:
    catalog = BehaviorCatalog()

    assert len(catalog.entries) >= 24
    assert catalog.catalog_id == "behavior-catalog-v1.1.0"
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
    assert process.verifier_reachable_from_entry_path is True
    assert thread is not None
    assert thread.verifier_id == "THREAD_CALLBACK"
    # B03: the specialist is registered and called from emulation
    # re-verification, but no declared playbook resolves to this entry, so the
    # behaviour-entry gate can never evaluate this contract.  The catalogue
    # records the real call paths instead of claiming the entry path works.
    assert thread.verifier == SupportLevel.SUPPORTED
    assert thread.verifier_reachable_from_entry_path is False
    assert thread.verifier_call_paths
    assert guard is not None
    assert guard.id == "environment-guard"
    assert guard.verifier_id == "ENVIRONMENT_GUARD"
    assert guard.verifier == SupportLevel.SUPPORTED
    assert guard.verifier_reachable_from_entry_path is True
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


# ---------------------------------------------------------------------------
# B02/M01: the declared support level must match the real main path.
# ---------------------------------------------------------------------------


def _declared_playbook_links() -> tuple[tuple[str, str], ...]:
    """(playbook id, mechanism type) for every profile best_match can select."""
    from threat_report_agent.investigation import MechanismPlaybookRegistry

    return tuple(
        (item.id, item.mechanism_type)
        for item in MechanismPlaybookRegistry.default_playbooks()
        if item.trigger_terms
    )


def test_declared_verifier_reachability_matches_the_declared_playbooks() -> None:
    """B03: which registered verifiers the behaviour-entry gate really calls."""
    catalog = BehaviorCatalog()
    links = _declared_playbook_links()
    reached = catalog.verifier_reachability(links)

    # Verifier.evaluate -> _evaluate_playbook -> verify_mechanism(verifier_id).
    assert set(reached) == {
        "DECODE_CONFIG",
        "DYNAMIC_API_RESOLUTION",
        "ENVIRONMENT_GUARD",
        "ETW_PATCH",
        "HTTP_DOWNLOAD",
        "PPID_SPOOFING",
        "PROCESS_EXECUTION",
    }
    # SHELL_OUTPUT / THREAD_CALLBACK are registered and called on other main
    # paths, but no declared profile resolves to child-process-output /
    # thread-and-callback, so their contracts never gate a claim here.
    assert {item.id for item in catalog.unreachable_verifier_entries(links)} == {
        "child-process-output",
        "thread-and-callback",
    }
    for entry in catalog.entries:
        computed = entry.verifier_id is None or entry.verifier_id in reached
        assert entry.verifier_reachable_from_entry_path is computed, entry.id


def test_registered_verifier_ids_are_all_accounted_for() -> None:
    """Every name in the dispatch table is either gate-reachable or recorded."""
    from threat_report_agent.investigation.investigation import MECHANISM_VERIFIERS

    catalog = BehaviorCatalog()
    reached = catalog.verifier_reachability(_declared_playbook_links())
    registered = set(MECHANISM_VERIFIERS)

    assert registered == {
        "DECODE_CONFIG",
        "DYNAMIC_API_RESOLUTION",
        "ENVIRONMENT_GUARD",
        "ETW_PATCH",
        "HTTP_DOWNLOAD",
        "PPID_SPOOFING",
        "PROCESS_CREATION",
        "PROCESS_EXECUTION",
        "SHELL_OUTPUT",
        "THREAD_CALLBACK",
    }
    not_reached_by_entry_path = registered - set(reached)
    assert not_reached_by_entry_path == {
        "PROCESS_CREATION",
        "SHELL_OUTPUT",
        "THREAD_CALLBACK",
    }
    # PROCESS_CREATION is a compatibility key for the PROCESS_EXECUTION
    # verifier and no catalogue entry declares it.
    assert catalog.by_id("PROCESS_CREATION").verifier_id == "PROCESS_EXECUTION"
    declared_ids = {
        entry.verifier_id for entry in catalog.entries if entry.verifier_id
    }
    assert "PROCESS_CREATION" not in declared_ids
    # Anything the gate cannot reach must name the path that does call it,
    # or it may not be declared supported.
    for entry in catalog.entries:
        if not entry.verifier_id or entry.verifier_reachable_from_entry_path:
            continue
        assert entry.verifier_call_paths, entry.id
        assert entry.verifier is SupportLevel.SUPPORTED, entry.id


def test_the_recorded_non_entry_call_paths_really_reach_their_verifiers() -> None:
    """The two `verifier_call_paths` claims are executable, not prose."""
    from threat_report_agent.investigation import (
        apply_emulation_reverification,
        derive_static_mechanism_links,
    )

    # SHELL_OUTPUT: the service derives a shell-output link from a real
    # CreateProcess + pipe/read sequence, and the derivation pass verifies it.
    link_rows = [
        {"id": "proc", "kind": "code_api_call", "nature": "STATIC_OBSERVED",
         "value": {"api": "KERNEL32.dll!CreateProcessW", "rva": 0x1240},
         "anchor": {"type": "rva_call_site", "rva": 0x1240}},
        {"id": "pipe", "kind": "code_api_call", "nature": "STATIC_OBSERVED",
         "value": {"api": "KERNEL32.dll!CreatePipe", "rva": 0x12A0},
         "anchor": {"type": "rva_call_site", "rva": 0x12A0}},
        {"id": "read", "kind": "code_api_call", "nature": "STATIC_OBSERVED",
         "value": {"api": "KERNEL32.dll!ReadFile", "rva": 0x1310},
         "anchor": {"type": "rva_call_site", "rva": 0x1310}},
    ]
    links = derive_static_mechanism_links(link_rows)
    shell_links = [
        item for item in links if str(item.get("kind")) == "mechanism_shell_output_link"
    ]
    assert shell_links
    assert shell_links[0]["value"]["mechanism_type"] == "SHELL_OUTPUT"

    # THREAD_CALLBACK: emulation re-verification dispatches by mechanism type.
    emulation_row = {
        "id": "emu-1",
        "kind": "simulation_result",
        "nature": "EMULATION_OBSERVED",
        "value": {"status": "SUCCEEDED", "apis": ["CreateThread"]},
    }
    thread_rows = [
        {"id": "thread-call", "kind": "function_call", "nature": "STATIC_OBSERVED",
         "value": {"api": "CreateThread", "start_routine": "0x401000"}},
        emulation_row,
    ]
    updated = apply_emulation_reverification(
        [{"id": "m-1", "mechanism_type": "THREAD_CALLBACK", "status": "CANDIDATE"}],
        thread_rows,
    )
    assert updated[0]["status"] == "VERIFIED"
    assert updated[0]["verifier"]["mechanism_type"] == "THREAD_CALLBACK"


def test_unrecorded_unreachable_verifier_cannot_be_declared_supported() -> None:
    """A SUPPORTED claim needs a recorded call path, not just a name."""
    catalog = BehaviorCatalog()
    entry = catalog.by_id("thread-and-callback")
    assert entry is not None
    with pytest.raises(ValueError):
        type(entry)(
            id=entry.id,
            version=entry.version,
            category=entry.category,
            discovery_seeds=entry.discovery_seeds,
            contract=entry.contract,
            verifier_id=entry.verifier_id,
            verifier=SupportLevel.SUPPORTED,
            verifier_reachable_from_entry_path=False,
            verifier_call_paths=(),
        )


def test_every_declared_playbook_profile_resolves_or_is_declared_unmapped() -> None:
    catalog = BehaviorCatalog()
    unmapped = unmapped_playbook_profiles(_declared_playbook_links())
    assert unmapped == ("entrypoint-timeline",)
    # The unmapped set is declared with a reason instead of being silent.
    assert set(UNMAPPED_PLAYBOOK_PROFILES) == {
        "generic-mechanism-investigation",
        "entrypoint-timeline",
    }
    assert all(reason.strip() for reason in UNMAPPED_PLAYBOOK_PROFILES.values())
    assert catalog.by_id("entrypoint-timeline") is None


def test_legacy_mechanism_ids_stay_compatible_across_the_version_bump() -> None:
    catalog = BehaviorCatalog()
    compatibility = catalog.compatibility()

    assert compatibility["version"] == "1.1.0"
    assert compatibility["previous_versions"] == ["1.0.0"]
    assert compatibility["unmapped_playbook_profiles"] == dict(UNMAPPED_PLAYBOOK_PROFILES)
    for legacy_id, (current_id, since_version) in LEGACY_BEHAVIOR_IDS.items():
        assert catalog.by_id(legacy_id) is not None, legacy_id
        assert catalog.by_id(legacy_id).id == current_id
        assert compatibility["legacy_ids"][legacy_id] == {
            "resolves_to": current_id,
            "since_version": since_version,
        }
    # Catalogue 1.0.0 could not resolve these profile mechanism types at all.
    for mechanism_type, entry_id in (
        ("DOWNLOAD_DROP", "download-and-drop"),
        ("CLEANUP_SELF_DELETE", "self-delete"),
        ("COMMAND_EXECUTION", "process-creation"),
        ("MEMORY_PERMISSION_CHANGE", "memory-and-mapping"),
        ("MANUAL_PE_LOAD", "loader-and-api-resolution"),
        ("REGISTRY_CONFIGURATION", "registry-operations"),
    ):
        assert catalog.by_id(mechanism_type).id == entry_id


# ---------------------------------------------------------------------------
# M01: the section 7 minimal counter-examples are registered catalog data and
# at least one group really blocks an over-claim on the main path.
# ---------------------------------------------------------------------------


def _persistence_objects() -> tuple[dict[str, object], dict[str, object]]:
    return (
        {"artifact_id": "a1", "address_space": "static", "address": "0x1000", "length": 32},
        {"artifact_id": "a1", "address_space": "static", "address": "0x2000", "length": 32},
    )


def _one_shot_task_rows() -> list[dict[str, object]]:
    """Evidence that satisfied the persistence contract before M01 existed."""
    source_object, target_object = _persistence_objects()
    anchor = {"function_entry": "0x140001000"}
    return [
        {
            "id": "task",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateProcessW",
                "trigger": "schtasks /create /sc once /tn Upd /tr C:\\Temp\\a.exe",
                "payload": "C:\\Temp\\a.exe",
                "permission": "SYSTEM",
                "lifetime": "once",
                "cleanup": "schtasks /delete /tn Upd /f",
                "source_object": source_object,
            },
            "anchor": anchor,
        },
        {
            "id": "run",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "CreateProcessW", "command": "C:\\Temp\\a.exe", "target_object": target_object},
            "anchor": anchor,
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "trigger_to_payload",
                "source_evidence_ids": ["task"],
                "target_evidence_ids": ["run"],
                "source_object": source_object,
                "target_object": target_object,
            },
            "anchor": anchor,
        },
    ]


def test_one_shot_task_cannot_be_promoted_to_durable_persistence() -> None:
    """Section 7 row 11: once+run+delete is not durable persistence.

    Before M01 the catalog published this limit as prose only, so this exact
    evidence reached `Verifier.evaluate` -> CANDIDATE(accepted=True).
    """
    from threat_report_agent.investigation import Verifier

    catalog = BehaviorCatalog()
    rows = _one_shot_task_rows()
    result = catalog.evaluate("persistence", rows)

    assert result.accepted is False
    assert result.status == "COUNTER_EXAMPLE"
    assert result.counter_examples == ("ce:persistence:one-shot-trigger",)
    assert "fact:trigger" in result.missing
    checks = {item["id"]: item for item in result.checks}
    assert checks["ce:persistence:one-shot-trigger"]["blocked"] is True
    assert checks["ce:persistence:one-shot-trigger"]["evidence_ids"] == ["task"]
    assert checks["ce:persistence:one-shot-trigger"]["source"].startswith("plan section 7 row 11")

    decision = Verifier().evaluate(
        rows,
        "Does the sample establish durable persistence?",
        "The sample may install durable persistence.",
    )
    assert decision.accepted is False
    assert decision.status == "COUNTER_EXAMPLE"
    assert "durable persistence" in decision.reason


def test_counter_example_masks_only_its_own_row_and_not_an_independent_trigger() -> None:
    """A durable Run key beside a one-shot task still closes the contract.

    The counter-example withholds the one-shot row's facts.  A different row
    that carries a durable trigger is untouched, which is what keeps the block
    from turning into a string filter over the whole evidence window.
    """
    catalog = BehaviorCatalog()
    one_shot = _one_shot_task_rows()[0]
    durable_object = _persistence_objects()[1]
    durable = {
        "id": "run-key",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {
            "trigger": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
            "payload": "C:\\Temp\\a.exe",
            "permission": "user",
            "lifetime": "persistent",
            "cleanup": "value remains installed",
            "source_object": durable_object,
        },
    }
    consumer = {
        "id": "run",
        "kind": "function_call",
        "nature": "STATIC_OBSERVED",
        "value": {"api": "CreateProcessW", "command": "C:\\Temp\\a.exe", "target_object": durable_object},
    }
    link = {
        "id": "durable-link",
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "trigger_to_payload",
            "source_evidence_ids": ["run-key"],
            "target_evidence_ids": ["run"],
            "source_object": durable_object,
            "target_object": durable_object,
        },
    }
    result = catalog.evaluate("persistence", [one_shot, durable, consumer, link])

    assert result.accepted is True
    assert result.status == "SUPPORTED_STATIC"
    # The pattern was still seen and is still reported for audit.
    assert result.counter_examples == ("ce:persistence:one-shot-trigger",)
    checks = {item["id"]: item for item in result.checks}
    assert checks["fact:trigger"]["evidence_ids"] == ["run-key"]


def test_counter_example_values_are_typed_exact_values_not_tokens() -> None:
    """`lifetime` values that merely contain "once" are not counter-examples."""
    catalog = BehaviorCatalog()
    entry = catalog.by_id("persistence")
    assert entry is not None
    predicate = next(
        item
        for item in entry.contract.counter_examples[0].row_predicates
        if item.id == "ce:persistence:lifetime"
    )
    assert not predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"lifetime": "once_daily_recurring"}}
    )
    assert not predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"lifetime": "not once, persistent"}}
    )
    assert not predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"lifetime": "UNKNOWN"}}
    )
    assert predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"lifetime": "once"}}
    )


def test_same_process_apc_cannot_be_promoted_to_process_injection() -> None:
    """Section 7 row 5: a same-process APC is not remote injection."""
    catalog = BehaviorCatalog()
    source_region = {"artifact_id": "a1", "address_space": "static", "address": "0x1000", "length": 32}
    target_region = {"artifact_id": "a1", "address_space": "static", "address": "0x2000", "length": 32}
    rows = [
        {
            "id": "apc",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "QueueUserAPC",
                "entry_routine": "0x401000",
                "target_process": "self",
                "process_scope": "same_process",
                "source_region": source_region,
                "target_region": target_region,
            },
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "cross_process_code_flow",
                "source_evidence_ids": ["apc"],
                "target_evidence_ids": ["apc"],
                "source_region": source_region,
                "target_region": target_region,
            },
        },
    ]
    result = catalog.evaluate("process-injection", rows)

    assert result.accepted is False
    assert result.status == "COUNTER_EXAMPLE"
    assert result.counter_examples == ("ce:process-injection:same-process-target",)


def test_non_gating_environment_probe_is_not_an_anti_analysis_gate() -> None:
    """Section 7 row 12: a system query whose branch continues is not a gate."""
    catalog = BehaviorCatalog()
    rows = [
        {
            "id": "probe",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "GetTickCount64",
                "probe_input": "GetTickCount64",
                "comparison": "uptime_seconds > 600",
                "threshold": "600",
                "gated_behavior": "continue",
            },
        }
    ]
    result = catalog.evaluate("environment-guard", rows)

    assert result.accepted is False
    assert result.status == "COUNTER_EXAMPLE"
    assert result.counter_examples == ("ce:environment-guard:non-gating-probe",)


def test_counter_example_must_be_published_as_a_forbidden_inference() -> None:
    """The executable gate and the published contract cannot drift apart."""
    orphan = counter_example(
        "ce:test:orphan",
        "test",
        "an unpublished over-claim",
        all_of=(EvidencePredicate.field("x", "value.x"),),
    )
    with pytest.raises(ValueError):
        EvidenceContract(forbidden_inferences=("something else",), counter_examples=(orphan,))
    documented = EvidenceContract(
        forbidden_inferences=("an unpublished over-claim",), counter_examples=(orphan,)
    )
    assert documented.counter_examples == (orphan,)


def test_counter_examples_are_serialized_with_stable_versioned_ids() -> None:
    catalog = BehaviorCatalog()
    registered = catalog.counter_examples()

    ids = {item["id"] for item in registered}
    assert ids == {
        "ce:process-injection:same-process-target",
        "ce:process-injection:ppid-attribute-only",
        "ce:thread-and-callback:runtime-worker-entry",
        "ce:resource-extraction:api-import-only",
        "ce:download-and-drop:url-string-only",
        "ce:self-delete:delete-import-only",
        "ce:persistence:one-shot-trigger",
        "ce:persistence:configuration-trigger",
        "ce:communication-loop:health-check-handler",
        "ce:environment-guard:non-gating-probe",
    }
    for item in registered:
        assert item["version"] == "1.0.0"
        assert item["source"].startswith("plan section 7 row")
        assert item["over_claim"]
        assert item["row_predicates"] or item["row_any_predicates"]
        # Every published limit is the one the executable layer enforces.
        owner = catalog.by_id(item["entry_id"])
        assert owner is not None
        assert item["over_claim"] in owner.contract.forbidden_inferences
    serialized = catalog.as_dict()
    entry = next(item for item in serialized["entries"] if item["id"] == "persistence")
    assert entry["counter_examples"] == [
        item for item in entry["contract"]["counter_examples"]
    ]
    assert entry["support"]["verifier_reachable_from_entry_path"] is True
    process = next(item for item in serialized["entries"] if item["id"] == "process-creation")
    assert process["support"]["verifier_call_paths"] == ["verifier.evaluate->_evaluate_playbook"]
    thread = next(item for item in serialized["entries"] if item["id"] == "thread-and-callback")
    assert thread["support"]["verifier_reachable_from_entry_path"] is False
    assert thread["support"]["verifier_call_paths"]


# ---------------------------------------------------------------------------
# M06 over-claim shapes: network-as-C2, task/registry-as-persistence,
# PPID/APC-as-injection, thread-API-as-callback.  Each has a differential
# control proving the counter-example, not a missing fact, does the blocking.
# ---------------------------------------------------------------------------


def _buffer_objects(*addresses: str) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "artifact_id": "a1",
            "address_space": "static",
            "address": address,
            "length": 32,
        }
        for address in addresses
    )


def _assert_counter_example_differential(
    entry_id: str,
    rows: list[dict[str, object]],
    counter_example_id: str,
    blocked_row_id: str,
) -> None:
    control = _contract_without_counter_examples(entry_id).evaluate(rows)
    assert control.accepted is True, control.missing
    assert control.status == "SUPPORTED_STATIC"

    registered = BehaviorCatalog().evaluate(entry_id, rows)
    assert registered.accepted is False
    assert registered.status == "COUNTER_EXAMPLE"
    assert counter_example_id in registered.counter_examples
    checks = {item["id"]: item for item in registered.checks}
    assert checks[counter_example_id]["blocked"] is True
    assert checks[counter_example_id]["evidence_ids"] == [blocked_row_id]


def test_ppid_attribute_is_not_process_injection() -> None:
    """M06 "PPID/APC 即注入": a parent-process attribute is not a code transfer."""
    source_region, target_region = _buffer_objects("0x1000", "0x2000")
    rows = [
        {
            "id": "ppid",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "UpdateProcThreadAttribute",
                "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                "target_process": "explorer.exe",
                "source_region": source_region,
                "target_region": target_region,
                "entry_routine": "0x401000",
            },
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "cross_process_code_flow",
                "source_evidence_ids": ["ppid"],
                "target_evidence_ids": ["ppid"],
                "source_region": source_region,
                "target_region": target_region,
            },
        },
    ]
    _assert_counter_example_differential(
        "process-injection",
        rows,
        "ce:process-injection:ppid-attribute-only",
        "ppid",
    )
    entry = BehaviorCatalog().by_id("process-injection")
    assert entry is not None
    assert "parent-process spoofing is not process injection" in entry.contract.forbidden_inferences


def test_health_check_loop_is_not_command_and_control() -> None:
    """M06 "网络即 C2": a polling loop with a non-effect handler is not C2."""
    (buffer,) = _buffer_objects("0x3000")
    rows = [
        {
            "id": "loop",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "time_state": "30s interval",
                "message_format": "JSON status",
                "handler": "CheckHealth",
                "network_path": "WinHttpSendRequest -> WinHttpReceiveResponse",
                "handler_side_effect": "health check",
                "buffer": buffer,
            },
        },
        {
            "id": "consumer",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"buffer": buffer},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "network_path_to_loop",
                "source_evidence_ids": ["loop"],
                "target_evidence_ids": ["consumer"],
                "buffer": buffer,
            },
        },
    ]
    _assert_counter_example_differential(
        "communication-loop",
        rows,
        "ce:communication-loop:health-check-handler",
        "loop",
    )


def test_configuration_write_is_not_durable_persistence() -> None:
    """M06 "任务/注册表即持久化": a configuration value write is not a trigger."""
    source_object, target_object = _buffer_objects("0x1000", "0x2000")
    rows = [
        {
            "id": "cfg",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "trigger": r"HKCU\Software\Vendor\App Theme",
                "trigger_kind": "configuration",
                "payload": "C:\\Temp\\a.exe",
                "permission": "user",
                "lifetime": "persistent",
                "cleanup": "value remains installed",
                "source_object": source_object,
            },
        },
        {
            "id": "run",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"target_object": target_object},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "trigger_to_payload",
                "source_evidence_ids": ["cfg"],
                "target_evidence_ids": ["run"],
                "source_object": source_object,
                "target_object": target_object,
            },
        },
    ]
    _assert_counter_example_differential(
        "persistence",
        rows,
        "ce:persistence:configuration-trigger",
        "cfg",
    )

    # The same row with an explicit autostart=False is blocked as well.
    no_autostart = {
        **rows[0],
        "id": "cfg-no-autostart",
        "value": {**rows[0]["value"], "trigger_kind": "settings", "autostart": False},
    }
    registered = BehaviorCatalog().evaluate(
        "persistence",
        [no_autostart, rows[1], {**rows[2], "value": {**rows[2]["value"], "source_evidence_ids": ["cfg-no-autostart"]}}],
    )
    assert registered.accepted is False
    assert "ce:persistence:configuration-trigger" in registered.counter_examples


def test_runtime_worker_entry_is_not_a_callback() -> None:
    """Section 7 row 4: CreateThread with a runtime bootstrap entry is not a callback."""
    (buffer,) = _buffer_objects("0x3000")
    rows = [
        {
            "id": "thread",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "CreateThread",
                "entry_routine": "RtlUserThreadStart",
                "entry_kind": "runtime_worker",
                "parameter": "lpParameter -> 0x140005000",
                "trigger": "CreateThread at 0x140001000",
                "lifetime": "process",
                "buffer": buffer,
            },
        },
        {
            "id": "consumer",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {"buffer": buffer},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "routine_to_thread",
                "source_evidence_ids": ["thread"],
                "target_evidence_ids": ["consumer"],
                "buffer": buffer,
            },
        },
    ]
    _assert_counter_example_differential(
        "thread-and-callback",
        rows,
        "ce:thread-and-callback:runtime-worker-entry",
        "thread",
    )


def test_counter_example_markers_are_exact_values_not_tokens() -> None:
    """A marker that merely mentions a blocked word is not a counter-example."""
    catalog = BehaviorCatalog()
    entry = catalog.by_id("persistence")
    assert entry is not None
    predicate = next(
        item
        for counter in entry.contract.counter_examples
        if counter.id == "ce:persistence:configuration-trigger"
        for item in counter.row_any_predicates
        if item.id == "ce:persistence:cfg-trigger-kind"
    )
    assert not predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"trigger_kind": "configuration_backup"}}
    )
    assert not predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"trigger_kind": "not a configuration"}}
    )
    assert predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"trigger_kind": "configuration"}}
    )
    assert predicate.match_row(
        {"id": "r", "kind": "function_call", "value": {"persistence_scope": "session"}}
    )


def _contract_without_counter_examples(entry_id: str) -> EvidenceContract:
    """The same entry's contract as catalogue 1.0.0 evaluated it.

    Used as the differential control: identical typed facts, relations and
    published forbidden inferences, with the executable counter-example layer
    removed.  Whatever accepts here and is rejected by the registered contract
    is blocked *because of* the counter-example, not because of a missing fact.
    """
    entry = BehaviorCatalog().by_id(entry_id)
    assert entry is not None
    return EvidenceContract(
        required_facts=entry.contract.required_facts,
        required_relations=entry.contract.required_relations,
        forbidden_inferences=entry.contract.forbidden_inferences,
        fact_predicates=entry.contract.fact_predicates,
        relation_predicates=entry.contract.relation_predicates,
    )


def test_one_shot_task_differential_without_the_counter_example_layer() -> None:
    """Differential proof for M01: the counter-example is the blocking change."""
    rows = _one_shot_task_rows()
    control = _contract_without_counter_examples("persistence").evaluate(rows)

    assert control.accepted is True
    assert control.status == "SUPPORTED_STATIC"
    assert control.counter_examples == ()
    registered = BehaviorCatalog().evaluate("persistence", rows)
    assert registered.accepted is False
    assert registered.counter_examples == ("ce:persistence:one-shot-trigger",)


def test_same_process_apc_differential_without_the_counter_example_layer() -> None:
    source_region = {"artifact_id": "a1", "address_space": "static", "address": "0x1000", "length": 32}
    target_region = {"artifact_id": "a1", "address_space": "static", "address": "0x2000", "length": 32}
    rows = [
        {
            "id": "apc",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "QueueUserAPC",
                "entry_routine": "0x401000",
                "target_process": "self",
                "process_scope": "same_process",
                "source_region": source_region,
                "target_region": target_region,
            },
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "cross_process_code_flow",
                "source_evidence_ids": ["apc"],
                "target_evidence_ids": ["apc"],
                "source_region": source_region,
                "target_region": target_region,
            },
        },
    ]
    control = _contract_without_counter_examples("process-injection").evaluate(rows)

    assert control.accepted is True
    assert control.status == "SUPPORTED_STATIC"
    registered = BehaviorCatalog().evaluate("process-injection", rows)
    assert registered.accepted is False
    assert registered.counter_examples == ("ce:process-injection:same-process-target",)


def test_non_gating_probe_differential_without_the_counter_example_layer() -> None:
    rows = [
        {
            "id": "probe",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "GetTickCount64",
                "probe_input": "GetTickCount64",
                "comparison": "uptime_seconds > 600",
                "threshold": "600",
                "gated_behavior": "continue",
            },
        }
    ]
    control = _contract_without_counter_examples("environment-guard").evaluate(rows)

    assert control.accepted is True
    assert control.status == "SUPPORTED_STATIC"
    registered = BehaviorCatalog().evaluate("environment-guard", rows)
    assert registered.accepted is False
    assert registered.counter_examples == ("ce:environment-guard:non-gating-probe",)


# ---------------------------------------------------------------------------
# Section 7 contract completion: rows that had no executable contract.
# ---------------------------------------------------------------------------

def test_resource_extraction_requires_bytes_and_a_consumer_not_an_import() -> None:
    """Section 7 row 1: a resource API import is not resource extraction."""
    catalog = BehaviorCatalog()
    import_only = [
        {
            "id": "import-1",
            "kind": "import_symbol",
            "nature": "STATIC_OBSERVED",
            "value": {"api": "FindResourceW"},
        }
    ]
    rejected = catalog.evaluate("resource-extraction", import_only)
    assert rejected.accepted is False
    assert rejected.status == "COUNTER_EXAMPLE"
    assert rejected.counter_examples == ("ce:resource-extraction:api-import-only",)

    buffer = {"artifact_id": "a1", "address_space": "static", "address": "0x5000", "length": 512}
    consumer_buffer = {"artifact_id": "a1", "address_space": "static", "address": "0x6000", "length": 512}
    rows = [
        {
            "id": "extract",
            "kind": "function_call",
            "nature": "STATIC_OBSERVED",
            "value": {
                "api": "FindResourceW",
                "resource_id": "101",
                "resource_type": "RT_RCDATA",
                "module": "sample.exe",
                "byte_range": "0x14000-0x14200",
                "length": 512,
                "output_buffer": buffer,
            },
        },
        {
            "id": "consumer",
            "kind": "api_argument_trace",
            "nature": "STATIC_OBSERVED",
            "value": {"input_buffer": consumer_buffer, "output_buffer": buffer},
        },
        {
            "id": "link",
            "kind": "value_flow",
            "nature": "STATIC_DERIVED",
            "value": {
                "relation": "resource_bytes_to_consumer",
                "source_evidence_ids": ["extract"],
                "target_evidence_ids": ["consumer"],
                "output_buffer": buffer,
                "input_buffer": consumer_buffer,
            },
        },
    ]
    accepted = catalog.evaluate("resource-extraction", rows)
    assert accepted.accepted is True
    assert accepted.status == "SUPPORTED_STATIC"


def test_communication_loop_requires_network_path_and_handler_side_effect() -> None:
    """Section 7 row 10: a timer plus a message shape is not a C2 loop."""
    catalog = BehaviorCatalog()
    entry = catalog.by_id("communication-loop")
    assert entry is not None
    assert {"network_path", "handler_side_effect"} <= set(entry.contract.required_facts)
    assert "back_edge" not in entry.contract.required_facts

    partial = catalog.evaluate(
        "communication-loop",
        [
            {
                "id": "loop-1",
                "kind": "function_call",
                "nature": "STATIC_OBSERVED",
                "value": {
                    "time_state": "retry delay 30s",
                    "message_format": "JSON envelope",
                    "handler": "HandleMessage",
                },
            }
        ],
    )
    assert partial.accepted is False
    assert "network_path" in partial.missing
    assert "handler_side_effect" in partial.missing


def test_new_section_7_entries_are_queryable_with_support_levels() -> None:
    catalog = BehaviorCatalog()
    for entry_id in ("resource-extraction", "download-and-drop", "network-listener", "self-delete"):
        entry = catalog.by_id(entry_id)
        assert entry is not None, entry_id
        support = entry.support
        assert support["discovery"]
        assert support["executable_contract"]
        assert support["executor"]
        assert support["verifier"]
        assert support["real_validation"] == support["validation"]
        assert entry.qualified_id == f"{entry.id}@{entry.version}"


def test_unknown_category_still_enters_investigation() -> None:
    """B02: a mechanism outside the catalogue is routable, never auto-promoted."""
    catalog = BehaviorCatalog()
    unknown = catalog.resolve_or_unknown("watcher-state-machine-v9")

    assert unknown.id == "unique-or-unknown"
    assert unknown.verifier is SupportLevel.UNSUPPORTED
    assert unknown.executable_contract is SupportLevel.UNSUPPORTED
    assert unknown.preferred_actions
    evaluation = catalog.evaluate("watcher-state-machine-v9", [])
    assert evaluation.accepted is False
    assert evaluation.status == "UNKNOWN"
    assert evaluation.missing == ("catalog:watcher-state-machine-v9",)


def test_counter_example_requires_typed_row_predicates() -> None:
    with pytest.raises(ValueError):
        CounterExample(id="ce:x", source="plan section 7", over_claim="x", row_predicates=())

