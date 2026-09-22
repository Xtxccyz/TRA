from threat_report_agent.static_analysis import (
    analyze_bytes,
    recover_static_xor_configs,
    verify_xor_decode_candidate,
)


def _encode_table(plain: bytes, table: bytes, counter0: int, step: int) -> bytes:
    return bytes(
        byte ^ table[index % len(table)] ^ ((counter0 + index * step) & 0xFF)
        for index, byte in enumerate(plain)
    )


def _pe_with_rdata(payload: bytes) -> bytes:
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    data[0x84:0x86] = (0x8664).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    data[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    data[optional + 16 : optional + 20] = (0x1000).to_bytes(4, "little")
    data[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    data[optional + 108 : optional + 112] = (16).to_bytes(4, "little")
    section = optional + 0xF0
    data[section : section + 8] = b".rdata\x00\x00"
    data[section + 8 : section + 12] = (0x400).to_bytes(4, "little")
    data[section + 12 : section + 16] = (0x4000).to_bytes(4, "little")
    data[section + 16 : section + 20] = (0x400).to_bytes(4, "little")
    data[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    data[0x200 : 0x200 + len(payload)] = payload
    return bytes(data)


def test_rdata_key_table_scan_recovers_http_config_without_ghidra_metadata() -> None:
    table = bytes(range(0x10, 0x20))
    plain = b"http://203.0.113.9/payload.exe"
    payload = table + _encode_table(plain, table, 3, 7)
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(payload, pe)
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert any(item.get("status") == "VERIFIED_STATIC_DATA" for item in hits)
    assert "http://203.0.113.9/payload.exe" in texts
    assert any(item.get("formula") == "key_table_modulo_xor_counter" for item in hits)
    assert any(
        isinstance(item.get("output_buffer"), dict)
        and item["output_buffer"].get("address_space") == "image"
        and int(item["output_buffer"].get("length") or 0) > 0
        for item in hits
    )


def test_rdata_key_table_scan_recovers_config_past_first_4kb() -> None:
    table = bytes(range(0x30, 0x40))
    plain = b"http://198.51.100.7/gate.bin"
    payload = (b"\x00" * 5000) + table + _encode_table(plain, table, 3, 7)
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(payload, pe)
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert any(item.get("status") == "VERIFIED_STATIC_DATA" for item in hits)
    assert "http://198.51.100.7/gate.bin" in texts


def test_rdata_unaligned_key_table_recovers_http_config() -> None:
    table = bytes(range(0x40, 0x50))
    plain = b"http://198.51.100.9/stage.pdf"
    payload = b"\x00" + table + _encode_table(plain, table, 3, 7)
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(payload, pe)
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert "http://198.51.100.9/stage.pdf" in texts


def test_key_table_recovers_cipher_immediately_before_the_table() -> None:
    table = bytes(range(0x50, 0x60))
    first = b"http://198.51.100.11/first.bin"
    second = b"http://198.51.100.11/second.bin"
    payload = _encode_table(first, table, 3, 7) + table + _encode_table(second, table, 3, 7)
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(payload, pe)
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert "http://198.51.100.11/first.bin" in texts
    assert "http://198.51.100.11/second.bin" in texts
    # `http` is a substring of the winhttp marker; URL hits must still rank first.
    mixed = bytearray(payload)
    encoded_open = bytes(
        byte ^ ((3 + index * 7) & 0xFF) ^ 0x3F for index, byte in enumerate(b"WinHttpOpen")
    )
    mixed[0 : len(encoded_open)] = encoded_open
    ranked = recover_static_xor_configs(
        bytes(mixed),
        {
            "image_base": 0x140000000,
            "sections": [
                {
                    "name": ".rdata",
                    "virtual_address": 0x4C000,
                    "virtual_size": len(mixed),
                    "raw_size": len(mixed),
                    "raw_offset": 0,
                }
            ],
        },
    )
    assert str(ranked[0].get("decoded_text") or "").startswith("http://")


def test_rolling_xor_with_extra_constant_recovers_winhttp_api_name() -> None:
    plain = b"winhttp.dll\x00WinHttpOpen"
    ciphertext = bytes(byte ^ ((3 + index * 7) & 0xFF) ^ 0x3F for index, byte in enumerate(plain))
    result = verify_xor_decode_candidate(
        {"memory_addresses": [0], "key_candidates": [3], "key_steps": [7]},
        ciphertext,
        max_bytes=len(plain),
    )
    assert result["status"] == "VERIFIED_STATIC_DATA"
    assert "winhttp.dll" in result["decoded_text"]
    assert result["formula"] in {"single_key_plus_step", "single_key_plus_step_xor_const"}


def test_analyze_bytes_emits_verified_decode_result_from_pe_rdata() -> None:
    table = bytes(range(0x20, 0x30))
    plain = b"http://192.0.2.8/stage.bin"
    payload = table + _encode_table(plain, table, 3, 7)
    result = analyze_bytes(_pe_with_rdata(payload), "loader.exe")
    decode_facts = [item for item in result.facts if item.kind == "decode_result"]
    assert decode_facts
    blob = decode_facts[0].value
    verification = blob.get("verification") if isinstance(blob, dict) else {}
    text = str((verification or {}).get("decoded_text") or blob.get("decoded_text") or "")
    assert "http://192.0.2.8/stage.bin" in text


def _encode_rolling(plain: bytes, key0: int, step: int, extra: int) -> bytes:
    return bytes(byte ^ ((key0 + index * step) & 0xFF) ^ extra for index, byte in enumerate(plain))


def test_rdata_rolling_xor_recovers_https_with_a_different_key_family() -> None:
    """Configs must decode without Resume's 3/7/0x3F constants."""
    plain = b"https://example.invalid/stage.bin"
    payload = bytearray(0x40)
    encoded = _encode_rolling(plain, 1, 1, 0)
    payload[0 : len(encoded)] = encoded
    payload[len(encoded)] = 0x00
    pe = {
        "image_base": 0x400000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x2000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(bytes(payload), pe)
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert "https://example.invalid/stage.bin" in texts


def test_rdata_rolling_xor_recovers_wininet_dll_name() -> None:
    plain = b"wininet.dll"
    payload = bytearray(0x20)
    encoded = _encode_rolling(plain, 3, 7, 0x3F)
    payload[0 : len(encoded)] = encoded
    trailer = 0x04 ^ ((3 + len(plain) * 7) & 0xFF) ^ 0x3F
    payload[len(encoded)] = trailer
    pe = {
        "image_base": 0x400000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x2000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(bytes(payload), pe)
    texts = {str(item.get("decoded_text") or "") for item in hits}
    assert "wininet.dll" in texts


def test_rdata_rolling_xor_recovers_winhttp_names_without_nul_terminator() -> None:
    names = (b"winhttp.dll", b"WinHttpOpen", b"WinHttpConnect")
    payload = bytearray(0x80)
    for offset, name in zip((0, 0x14, 0x28), names, strict=True):
        encoded = _encode_rolling(name, 3, 7, 0x3F)
        payload[offset : offset + len(encoded)] = encoded
        # Resume's names are not NUL-terminated; the next decoded byte is non-printable.
        trailer = 0x04 ^ ((3 + len(name) * 7) & 0xFF) ^ 0x3F
        payload[offset + len(encoded)] = trailer
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".rdata",
                "virtual_address": 0x4C000,
                "virtual_size": len(payload),
                "raw_size": len(payload),
                "raw_offset": 0,
            }
        ],
    }
    hits = recover_static_xor_configs(bytes(payload), pe)
    texts = {str(item.get("decoded_text") or "") for item in hits}
    assert "winhttp.dll" in texts
    assert "WinHttpOpen" in texts
    assert "WinHttpConnect" in texts
    assert all("WinHttpConnect1" not in text for text in texts)
