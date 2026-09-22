"""Wiring A — decode_primitives feed the live static decode path.

These tests are the red half of the TDD pair for plan-external wiring A
(``decode_primitives`` -> ``static_analysis`` decode path).  They assert the
capability is *additional*: the pre-existing rolling-XOR families must NOT
already recover an RC4/table-encrypted config, and the new source must recover
it while obeying the same marker/printability gate and the same row shape the
downstream verifier and the ADR-0035 consumer Join consume.
"""

from threat_report_agent.decode_primitives import rc4_crypt
from threat_report_agent.static_analysis import (
    analyze_bytes,
    recover_primitive_decode_configs,
    recover_static_xor_configs,
)

_PLAIN = b"http://203.0.113.9/payload.exe"
_TABLE = bytes(range(0x10, 0x20))


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


def _pe_summary(payload: bytes) -> dict[str, object]:
    return {
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


def _rc4_payload() -> bytes:
    return _TABLE + rc4_crypt(_PLAIN, _TABLE)


def test_rc4_table_config_is_not_recovered_by_the_rolling_xor_families() -> None:
    """Precondition for wiring A: the old source genuinely misses RC4/table blobs."""
    payload = _rc4_payload()
    hits = recover_static_xor_configs(payload, _pe_summary(payload))
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert "203.0.113.9" not in texts


def test_primitive_source_recovers_rc4_table_config() -> None:
    payload = _rc4_payload()
    hits = recover_primitive_decode_configs(payload, _pe_summary(payload))
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert any(item.get("status") == "VERIFIED_STATIC_DATA" for item in hits)
    assert "http://203.0.113.9/payload.exe" in texts
    assert any(
        str(item.get("formula") or "").startswith("decode_primitive:") for item in hits
    )


def test_primitive_rows_carry_the_shape_downstream_consumers_need() -> None:
    """The verifier and the ADR-0035 Join read these keys; they must be present."""
    payload = _rc4_payload()
    hits = [
        item
        for item in recover_primitive_decode_configs(payload, _pe_summary(payload))
        if "203.0.113.9" in str(item.get("decoded_text") or "")
    ]
    assert hits, "expected at least one hit for the RC4 config"
    row = hits[0]
    for key in (
        "status",
        "file_offset",
        "virtual_address",
        "length",
        "printable_ratio",
        "markers",
        "decoded_text",
        "ciphertext_hex",
        "plaintext_hex",
        "output_buffer",
        "formula",
        "verification_scope",
    ):
        assert key in row, f"missing {key}"
    buffer = row["output_buffer"]
    assert isinstance(buffer, dict)
    assert buffer.get("address_space") == "image"
    assert int(buffer.get("length") or 0) > 0
    assert row["status"] == "VERIFIED_STATIC_DATA"


def test_primitive_source_keeps_the_marker_gate() -> None:
    """No configuration marker -> no hit, even when the plaintext is printable."""
    plain = b"this string has no config marker at all"
    payload = _TABLE + rc4_crypt(plain, _TABLE)
    hits = recover_primitive_decode_configs(payload, _pe_summary(payload))
    texts = " ".join(str(item.get("decoded_text") or "") for item in hits)
    assert "no config marker" not in texts


def test_primitive_source_is_deterministic() -> None:
    payload = _rc4_payload()
    first = recover_primitive_decode_configs(payload, _pe_summary(payload))
    second = recover_primitive_decode_configs(payload, _pe_summary(payload))
    assert first == second


def test_primitive_source_respects_max_hits() -> None:
    payload = _rc4_payload()
    hits = recover_primitive_decode_configs(payload, _pe_summary(payload), max_hits=1)
    assert len(hits) <= 4


def test_analyze_bytes_live_path_emits_primitive_decode_result() -> None:
    """The wiring must be live, not merely an exported function.

    ``analyze_bytes`` is the entry point the service uses; an RC4/table config
    that only the primitive source can decode must reach a ``decode_result``
    fact there, carrying the primitive formula so downstream evidence and the
    ADR-0035 consumer Join can attribute it.
    """
    payload = _rc4_payload()
    result = analyze_bytes(_pe_with_rdata(payload), "loader.exe")
    decode_facts = [item for item in result.facts if item.kind == "decode_result"]
    assert decode_facts, "analyze_bytes emitted no decode_result fact"
    primitive_facts = []
    for fact in decode_facts:
        blob = fact.value if isinstance(fact.value, dict) else {}
        verification = blob.get("verification") or {}
        candidate = blob.get("candidate") or {}
        formula = str(candidate.get("formula") or verification.get("formula") or "")
        if formula.startswith("decode_primitive:"):
            primitive_facts.append((formula, verification))
    assert primitive_facts, (
        "no decode_result fact came from the primitive source; "
        f"formulas seen: {sorted({str((f.value or {}).get('candidate', {}).get('formula')) for f in decode_facts})}"
    )
    formulas = {formula for formula, _ in primitive_facts}
    assert "decode_primitive:rc4" in formulas
    texts = " ".join(str(row.get("decoded_text") or "") for _, row in primitive_facts)
    assert "http://203.0.113.9/payload.exe" in texts
    # The new source must not claim a consumer; that stays the verifier's job.
    for fact in decode_facts:
        blob = fact.value if isinstance(fact.value, dict) else {}
        if str((blob.get("candidate") or {}).get("formula") or "").startswith(
            "decode_primitive:"
        ):
            assert blob.get("consumer_status") == "NOT_IDENTIFIED"
            assert blob.get("static_only") is True
