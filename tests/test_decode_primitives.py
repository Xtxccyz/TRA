"""Contract tests for ``threat_report_agent.decode_primitives``.

Known-answer vectors come from two independent places:

* the ``__main__`` self-test of ``.agents/skills/peinfo/scripts/crypto.py``,
  asserted byte-exactly, and
* the published glibc ``rand()`` sequence after ``srand(1)``
  (16838, 5758, 10113, 17515, 31051), which the CR-011 LCG reproduces.

The primitives only transform bytes that were already extracted from a sample.
No test here runs, emulates, or detonates a sample, and none reaches the network.
"""

from __future__ import annotations

import ast
import pathlib
import struct
import zlib

import pytest

from threat_report_agent import decode_primitives as dp


CR007_KNOWN_CIPHER = "yF^T]2@D]izIWc2]"
CR007_KNOWN_PLAIN = "ZwQuerySemaphore"

# CR-013 single-byte vectors from crypto.py __main__ (10_102.sys SSDT hook names).
CR013_ZWCREATETHREAD_CIPHER = bytes.fromhex("c6 c8 98 d3 89 91 bc b6 9b b2 a0 eb 91 f1")
CR013_ZWCREATETHREAD_SEED = 0x705180
CR013_NTCLOSE_CIPHER = bytes.fromhex("88 e5 e8 fe ca c6 81")
CR013_NTCLOSE_SEED = 0x8F5800

# glibc rand() after srand(1); CR-011 takes bits 16..23 of each LCG state, i.e.
# the low byte of the classic 15-bit value.
GLIBC_SRAND1_SEQUENCE = (16838, 5758, 10113, 17515, 31051)


def _cr001_keystream(seed: int, length: int) -> bytes:
    """Independent CR-001 keystream, written from the source recurrence comment."""
    state = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(length):
        state = (0xDD483B8F - 0x6033A96D * state) & 0xFFFFFFFF
        out.append((state >> 8) & 0xFF)
    return bytes(out)


def _cr013_wide_crypt(data: bytes, seed: int) -> bytes:
    """Independent CR-013 wide-char (UTF-16LE word) transform; XOR is symmetric."""
    state = seed & 0xFFFFFFFF
    out = bytearray(data)
    for index in range(0, len(data), 2):
        state = (0x19660D * state + 0x3C6EF35F) & 0xFFFFFFFF
        word = out[index] | (out[index + 1] << 8)
        word ^= ((state >> 16) & 0xFFFF) | 0x8000
        out[index] = word & 0xFF
        out[index + 1] = (word >> 8) & 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# 1. Known-answer vectors shipped with the source toolkit
# ---------------------------------------------------------------------------


def test_cr007_source_known_vector_decrypts_to_zwquerysemaphore() -> None:
    assert dp.cr007_decrypt(CR007_KNOWN_CIPHER) == CR007_KNOWN_PLAIN


def test_cr007_source_known_vector_encrypts_back() -> None:
    assert dp.cr007_encrypt(CR007_KNOWN_PLAIN) == CR007_KNOWN_CIPHER


def test_cr007_accepts_bytes_ciphertext() -> None:
    assert dp.cr007_decrypt(CR007_KNOWN_CIPHER.encode("latin1")) == CR007_KNOWN_PLAIN


def test_rc4_source_known_vector_survives_encrypt_decrypt() -> None:
    assert dp.rc4_decrypt(dp.rc4_encrypt(b"hello world", b"key"), b"key") == b"hello world"


def test_rc4_aliases_are_the_same_primitive() -> None:
    assert dp.rc4_decrypt is dp.rc4_crypt
    assert dp.rc4_encrypt is dp.rc4_crypt


def test_cr013_source_known_vector_zwcreatethread() -> None:
    plain = dp.cr013_nr_decrypt(CR013_ZWCREATETHREAD_CIPHER, CR013_ZWCREATETHREAD_SEED)
    assert plain == b"ZwCreateThread"


def test_cr013_source_known_vector_ntclose() -> None:
    assert dp.cr013_nr_decrypt(CR013_NTCLOSE_CIPHER, CR013_NTCLOSE_SEED) == b"NtClose"


# ---------------------------------------------------------------------------
# 2. Round trips
# ---------------------------------------------------------------------------


def test_single_byte_xor_round_trip() -> None:
    plain = b"http://203.0.113.9/gate.php"
    assert dp.xor_decrypt(dp.xor_decrypt(plain, 0x5A), 0x5A) == plain


def test_multi_byte_xor_round_trip() -> None:
    plain = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    key = b"d1Ba"
    cipher = dp.xor_decrypt(plain, key)
    assert cipher != plain
    assert dp.xor_decrypt(cipher, key) == plain


def test_xor_with_zero_key_is_identity() -> None:
    assert dp.xor_decrypt(b"\x00\xff\x10", b"\x00") == b"\x00\xff\x10"


def test_rc4_round_trip_on_binary_blob() -> None:
    plain = bytes(range(256)) + b"\x00\x00" + b"\xff" * 17
    assert dp.rc4_crypt(dp.rc4_crypt(plain, b"session-key"), b"session-key") == plain


def test_rc4_matches_rfc_style_known_answer() -> None:
    # Classic RC4 test vector: key "Key", plaintext "Plaintext" -> BBF316E8D940AF0AD3.
    assert dp.rc4_encrypt(b"Plaintext", b"Key").hex().upper() == "BBF316E8D940AF0AD3"


def test_cr001_round_trip() -> None:
    plain = b"payload-config-block"
    cipher = dp.cr001_lcg_decrypt(plain, 0x1234ABCD)
    assert cipher != plain
    assert dp.cr001_lcg_decrypt(cipher, 0x1234ABCD) == plain


def test_cr011_round_trip() -> None:
    plain = b"ExAllocatePoolWithTag"
    cipher = dp.cr011_glibc_decrypt(plain, 0x2A)
    assert cipher != plain
    assert dp.cr011_glibc_decrypt(cipher, 0x2A) == plain


def test_cr013_single_byte_round_trip() -> None:
    plain = b"ZwWriteVirtualMemory"
    cipher = dp.cr013_nr_decrypt(plain, 0x705180)
    assert cipher != plain
    assert dp.cr013_nr_decrypt(cipher, 0x705180) == plain


def test_cr013_wide_round_trip_on_utf16le_device_name() -> None:
    plain = "\\Driver\\msvss".encode("utf-16-le")
    cipher = _cr013_wide_crypt(plain, 0x17B4)
    assert cipher != plain
    assert dp.cr013_nr_decrypt(cipher, 0x17B4, wide=True) == plain


def test_cr013_wide_matches_documented_hidsvc_device_name_vector() -> None:
    # Cipher bytes derived by applying the CR-013 wide recurrence documented in
    # constants.py to the documented hidsvc device name (seed 0x17B4); this is a
    # recurrence anchor, not a byte range extracted from a sample.
    cipher = bytes.fromhex("299600ab69a117c821805cbb2ce06cdb4be490ad7581f6ad40b5")
    assert dp.cr013_nr_decrypt(cipher, 0x17B4, wide=True) == "\\Driver\\msvss".encode("utf-16-le")


def test_cr001_keystream_matches_independent_recurrence() -> None:
    assert dp.cr001_lcg_decrypt(bytes(16), 0x1234ABCD) == _cr001_keystream(0x1234ABCD, 16)


def test_lcg_stream_reproduces_cr001_keystream() -> None:
    expected = dp.cr001_lcg_decrypt(bytes(12), 0x1234)
    # (0xDD483B8F - 0x6033A96D*s) == ((-0x6033A96D mod 2**32) * s + 0xDD483B8F) mod 2**32
    stream = dp.lcg_stream(
        0x1234, (-dp.CR001_LGC_MULT) & 0xFFFFFFFF, dp.CR001_LGC_ADD, 12, xor_shift=8
    )
    assert stream == expected


def test_lcg_stream_reproduces_cr011_keystream() -> None:
    stream = dp.lcg_stream(0x1234, dp.CR011_GLIBC_MULT, dp.CR011_GLIBC_ADD, 12, xor_shift=16)
    assert dp.cr011_glibc_decrypt(bytes(12), 0x1234) == stream


def test_lcg_stream_reproduces_cr013_single_byte_keystream() -> None:
    stream = dp.lcg_stream(0x1234, dp.CR013_NR_MULT, dp.CR013_NR_ADD, 12, xor_shift=16)
    assert dp.cr013_nr_decrypt(bytes(12), 0x1234) == bytes(byte | 0x80 for byte in stream)


def test_cr011_matches_published_glibc_srand1_sequence() -> None:
    keystream = dp.cr011_glibc_decrypt(bytes(len(GLIBC_SRAND1_SEQUENCE)), 1)
    assert tuple(byte for byte in keystream) == tuple(
        value & 0xFF for value in GLIBC_SRAND1_SEQUENCE
    )


def test_lcg_stream_zero_length_is_empty() -> None:
    assert dp.lcg_stream(1, 3, 5, 0) == b""


# ---------------------------------------------------------------------------
# 3. Counter-examples: a wrong key or seed must not reproduce the true plaintext
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("wrong", [0x5B, 0x00, b"d1Bb", b"d1B", b"x"])
def test_wrong_xor_key_does_not_reproduce_plaintext(wrong) -> None:
    plain = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    cipher = dp.xor_decrypt(plain, b"d1Ba")
    assert dp.xor_decrypt(cipher, wrong) != plain


@pytest.mark.parametrize("wrong", [b"keys", b"keyy", b"k", b"\x00\x00\x00"])
def test_wrong_rc4_key_does_not_reproduce_plaintext(wrong) -> None:
    plain = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    cipher = dp.rc4_crypt(plain, b"key")
    assert dp.rc4_crypt(cipher, wrong) != plain


@pytest.mark.parametrize("wrong", [0x705181, 0x8F5800, 0x000000, 0xFFFFFF])
def test_wrong_cr013_seed_does_not_reproduce_zwcreatethread(wrong) -> None:
    assert dp.cr013_nr_decrypt(CR013_ZWCREATETHREAD_CIPHER, wrong) != b"ZwCreateThread"


@pytest.mark.parametrize("wrong", [0x8F5801, 0x705180, 0x000000, 0xFFFFFF])
def test_wrong_cr013_seed_does_not_reproduce_ntclose(wrong) -> None:
    assert dp.cr013_nr_decrypt(CR013_NTCLOSE_CIPHER, wrong) != b"NtClose"


def test_wrong_cr013_variant_does_not_reproduce_zwcreatethread() -> None:
    wide = dp.cr013_nr_decrypt(CR013_ZWCREATETHREAD_CIPHER, CR013_ZWCREATETHREAD_SEED, wide=True)
    assert wide != b"ZwCreateThread"


@pytest.mark.parametrize("wrong", [0x1234ABCE, 0x00000001, 0xFFFFFFFF])
def test_wrong_cr001_seed_does_not_reproduce_plaintext(wrong) -> None:
    plain = b"MZ\x90\x00peak-payload"
    cipher = dp.cr001_lcg_decrypt(plain, 0x1234ABCD)
    assert dp.cr001_lcg_decrypt(cipher, wrong) != plain


@pytest.mark.parametrize("wrong", [0x2B, 0x0001, 0xFFFFFF])
def test_wrong_cr011_seed_does_not_reproduce_plaintext(wrong) -> None:
    plain = b"ZwAllocateVirtualMemory"
    cipher = dp.cr011_glibc_decrypt(plain, 0x2A)
    assert dp.cr011_glibc_decrypt(cipher, wrong) != plain


def test_wrong_cr007_table_direction_does_not_reproduce_plaintext() -> None:
    # Guard against the reversed early fact (table.index(c) + 0x20 in the decode
    # direction): that direction yields a different but equally printable string.
    reversed_direction = "".join(
        chr(dp.CR007_SUBSTITUTION_TABLE.index(char) + 0x20) for char in CR007_KNOWN_CIPHER
    )
    assert reversed_direction != CR007_KNOWN_PLAIN
    assert dp.cr007_decrypt(CR007_KNOWN_CIPHER) == CR007_KNOWN_PLAIN


# ---------------------------------------------------------------------------
# 4. CR-007 substitution table edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [b"\x00\x01\x1f", b"\x7f\x80\xff", b"\r\n\t\x0b", "中文".encode("utf-8")],
)
def test_cr007_preserves_non_printable_and_non_ascii_bytes(raw: bytes) -> None:
    decoded = dp.cr007_decrypt(raw)
    assert decoded.encode("latin1") == raw


def test_cr007_substitutes_printable_chars_and_keeps_every_other_byte() -> None:
    decoded = dp.cr007_decrypt(b"\x00abc\xff")
    assert decoded == "\x00" + dp.cr007_decrypt("abc") + "\xff"
    assert decoded[1:4] != "abc"


def test_cr007_round_trips_full_printable_range() -> None:
    plain = "".join(chr(code) for code in range(0x20, 0x7F))
    assert dp.cr007_decrypt(dp.cr007_encrypt(plain)) == plain


def test_cr007_table_is_a_95_char_bijection_over_printable_ascii() -> None:
    table = dp.CR007_SUBSTITUTION_TABLE
    assert len(table) == 95
    assert len(set(table)) == 95
    assert all(0x20 <= ord(char) < 0x7F for char in table)


def test_cr007_encrypt_rejects_unmappable_characters() -> None:
    with pytest.raises(ValueError):
        dp.cr007_encrypt("ZwQuerySemaphore\x00")


# ---------------------------------------------------------------------------
# 5. base64
# ---------------------------------------------------------------------------


def test_b64_decode_without_padding() -> None:
    assert dp.b64_decode("aGVsbG8") == b"hello"


def test_b64_decode_with_padding_and_bytes_input() -> None:
    assert dp.b64_decode(b"aGVsbG8=") == b"hello"


def test_b64_decode_padding_free_multibyte_utf8() -> None:
    assert dp.b64_decode("5L2g5aW9") == "你好".encode()


def test_b64_decode_tolerates_line_wrapped_input() -> None:
    wrapped = "aGVs\nbG8g\nd29y\nbGQ="
    assert dp.b64_decode(wrapped) == b"hello world"


# ---------------------------------------------------------------------------
# 6. DiBa resource envelope (CR-001 LCG + zlib)
# ---------------------------------------------------------------------------


def _diba_resource(payload: bytes, seed: int) -> bytes:
    framed = struct.pack("<I", len(payload)) + zlib.compress(payload)
    return struct.pack("<I", seed) + dp.cr001_lcg_decrypt(framed, seed)


def test_decrypt_diba_resource_round_trip() -> None:
    payload = b"MZ" + b"\x90" * 64 + b"diba payload"
    assert dp.decrypt_diba_resource(_diba_resource(payload, 0x11223344)) == payload


def test_decrypt_diba_resource_skips_the_four_byte_length_field() -> None:
    payload = b"x" * 5000
    resource = _diba_resource(payload, 0x00000001)
    # The declared length is part of the LCG stream and is skipped, not enforced.
    assert dp.decrypt_diba_resource(resource) == payload
    assert struct.unpack_from("<I", resource, 0)[0] == 0x00000001


def test_decrypt_diba_resource_rejects_wrong_seed() -> None:
    payload = b"payload"
    resource = _diba_resource(payload, 0x11223344)
    tampered = struct.pack("<I", 0x11223345) + resource[4:]
    with pytest.raises(ValueError):
        dp.decrypt_diba_resource(tampered)


# ---------------------------------------------------------------------------
# 7. decrypt_candidates: declarative, deterministic, verdict-free
# ---------------------------------------------------------------------------


def test_decrypt_candidates_returns_declared_shape_only() -> None:
    cipher = dp.rc4_encrypt(b"cmd.exe /c whoami", b"secret")
    candidates = dp.decrypt_candidates(cipher, seeds=[0x705180], keys=[b"secret"])
    assert isinstance(candidates, tuple)
    assert candidates
    for item in candidates:
        assert set(item) == {"algorithm", "key_or_seed", "plaintext"}
        assert item["algorithm"] in {"rc4", "xor", "cr001", "cr011", "cr013", "cr007"}
        assert isinstance(item["key_or_seed"], str)
        assert isinstance(item["plaintext"], bytes)


def test_decrypt_candidates_is_stable_across_calls() -> None:
    cipher = dp.xor_decrypt(b"whoami /all", b"d1Ba")
    first = dp.decrypt_candidates(cipher, seeds=[0x705180, 0x8F5800], keys=[b"d1Ba", b"key"])
    second = dp.decrypt_candidates(cipher, seeds=[0x705180, 0x8F5800], keys=[b"d1Ba", b"key"])
    assert first == second


def test_decrypt_candidates_emission_order_is_deterministic() -> None:
    cipher = dp.rc4_encrypt(b"odd-length-cipher", b"secret")
    candidates = dp.decrypt_candidates(cipher, seeds=[0x705180, 0x8F5800], keys=[b"secret"])
    assert [item["algorithm"] for item in candidates] == [
        "xor",
        "rc4",
        "cr001",
        "cr001",
        "cr011",
        "cr011",
        "cr013",
        "cr013",
        "cr007",
    ]
    assert [item["key_or_seed"] for item in candidates] == [
        "key:736563726574",
        "key:736563726574",
        "0x00705180",
        "0x008F5800",
        "0x00705180",
        "0x008F5800",
        "0x00705180",
        "0x008F5800",
        "substitution-table",
    ]


def test_decrypt_candidates_adds_wide_cr013_for_even_length_input() -> None:
    candidates = dp.decrypt_candidates(bytes(8), seeds=[0x17B4])
    assert [item["algorithm"] for item in candidates] == [
        "cr001",
        "cr011",
        "cr013",
        "cr013",
        "cr007",
    ]
    assert [item["key_or_seed"] for item in candidates] == [
        "0x000017B4",
        "0x000017B4",
        "0x000017B4",
        "0x000017B4 (wide)",
        "substitution-table",
    ]


def test_decrypt_candidates_recovers_each_algorithm_plaintext() -> None:
    plain = b"ZwCreateThread"
    cases = [
        ("xor", plain, dp.xor_decrypt(plain, 0x5A), [b"\x5a"]),
        ("rc4", plain, dp.rc4_crypt(plain, b"key"), [b"key"]),
        ("cr001", plain, dp.cr001_lcg_decrypt(plain, 0x705180), []),
        ("cr011", plain, dp.cr011_glibc_decrypt(plain, 0x705180), []),
        ("cr013", plain, dp.cr013_nr_decrypt(plain, 0x705180), []),
    ]
    for algorithm, expected, cipher, keys in cases:
        candidates = dp.decrypt_candidates(cipher, seeds=[0x705180], keys=keys)
        assert any(
            item["algorithm"] == algorithm and item["plaintext"] == expected for item in candidates
        ), algorithm


def test_decrypt_candidates_keeps_cr007_candidate_for_table_ciphertext() -> None:
    candidates = dp.decrypt_candidates(CR007_KNOWN_CIPHER.encode("latin1"))
    assert candidates[-1] == {
        "algorithm": "cr007",
        "key_or_seed": "substitution-table",
        "plaintext": CR007_KNOWN_PLAIN.encode("latin1"),
    }


def test_decrypt_candidates_does_not_filter_or_rank_candidates() -> None:
    # A zero XOR key reproduces the cipher bytes; the generator must still emit it
    # instead of judging the candidate.
    candidates = dp.decrypt_candidates(b"\x00\x00", keys=[b"\x00"])
    assert {"algorithm": "xor", "key_or_seed": "key:00", "plaintext": b"\x00\x00"} in candidates


def test_decrypt_candidates_preserves_caller_order_and_deduplicates() -> None:
    candidates = dp.decrypt_candidates(b"\x01\x02", seeds=[7, 7, 9], keys=[b"b", b"b", b"a"])
    # Duplicates (key b"b", seed 7) collapse; the caller's first-seen order holds.
    assert [item["key_or_seed"] for item in candidates] == [
        "key:62",
        "key:61",
        "key:62",
        "key:61",
        "0x00000007",
        "0x00000009",
        "0x00000007",
        "0x00000009",
        "0x00000007",
        "0x00000007 (wide)",
        "0x00000009",
        "0x00000009 (wide)",
        "substitution-table",
    ]
    assert [item["algorithm"] for item in candidates] == [
        "xor",
        "xor",
        "rc4",
        "rc4",
        "cr001",
        "cr001",
        "cr011",
        "cr011",
        "cr013",
        "cr013",
        "cr013",
        "cr013",
        "cr007",
    ]


def test_decrypt_candidates_masks_seeds_into_32_bits() -> None:
    negative = dp.decrypt_candidates(b"\x01\x02", seeds=[-1])
    positive = dp.decrypt_candidates(b"\x01\x02", seeds=[0xFFFFFFFF])
    assert negative == positive
    assert negative[0]["key_or_seed"] == "0xFFFFFFFF"


# ---------------------------------------------------------------------------
# 8. Input validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "exception"),
    [
        (lambda: dp.xor_decrypt("abc", 1), TypeError),
        (lambda: dp.xor_decrypt(b"abc", "k"), TypeError),
        (lambda: dp.xor_decrypt(b"abc", 256), ValueError),
        (lambda: dp.xor_decrypt(b"abc", -1), ValueError),
        (lambda: dp.xor_decrypt(b"abc", b""), ValueError),
        (lambda: dp.xor_decrypt(b"abc", bytearray()), ValueError),
        (lambda: dp.rc4_crypt(b"abc", ""), TypeError),
        (lambda: dp.rc4_crypt(b"abc", b""), ValueError),
        (lambda: dp.rc4_crypt(bytearray(b"abc"), "k"), TypeError),
        (lambda: dp.cr001_lcg_decrypt("abc", 1), TypeError),
        (lambda: dp.cr001_lcg_decrypt(b"abc", "1"), TypeError),
        (lambda: dp.cr011_glibc_decrypt(b"abc", None), TypeError),
        (lambda: dp.cr013_nr_decrypt(b"abc", 1, wide=True), ValueError),
        (lambda: dp.cr013_nr_decrypt(b"abc", 1, wide="yes"), TypeError),
        (lambda: dp.cr013_nr_decrypt("abc", 1), TypeError),
        (lambda: dp.cr007_decrypt(123), TypeError),
        (lambda: dp.cr007_decrypt(None), TypeError),
        (lambda: dp.lcg_stream(1, 2, 3, -1), ValueError),
        (lambda: dp.lcg_stream(1, 2, 3, 4, xor_shift=32), ValueError),
        (lambda: dp.lcg_stream(1, 2, 3, 4, xor_shift=-1), ValueError),
        (lambda: dp.lcg_stream(1, 2, 3, "4"), TypeError),
        (lambda: dp.lcg_stream("1", 2, 3, 4), TypeError),
        (lambda: dp.b64_decode(b""), ValueError),
        (lambda: dp.b64_decode("   "), ValueError),
        (lambda: dp.b64_decode("!!!!"), ValueError),
        (lambda: dp.b64_decode(123), TypeError),
        (lambda: dp.b64_decode(None), TypeError),
        (lambda: dp.decrypt_diba_resource(b"\x00" * 7), ValueError),
        (lambda: dp.decrypt_diba_resource("resource"), TypeError),
        (lambda: dp.decrypt_diba_resource(b"\x00" * 16), ValueError),
        (lambda: dp.decrypt_candidates("cipher"), TypeError),
        (lambda: dp.decrypt_candidates(b""), ValueError),
        (lambda: dp.decrypt_candidates(b"\x01", keys=b"key"), TypeError),
        (lambda: dp.decrypt_candidates(b"\x01", keys=[b"ok", b""]), ValueError),
        (lambda: dp.decrypt_candidates(b"\x01", keys=["str-key"]), TypeError),
        (lambda: dp.decrypt_candidates(b"\x01", seeds=[1, "2"]), TypeError),
        (lambda: dp.decrypt_candidates(b"\x01", seeds=["2"]), TypeError),
        (lambda: dp.decrypt_candidates(b"\x01", seeds=None), TypeError),
        (lambda: dp.decrypt_candidates(b"\x01", keys=None), TypeError),
    ],
)
def test_invalid_inputs_raise(call, exception: type[Exception]) -> None:
    with pytest.raises(exception):
        call()


def test_bool_is_rejected_where_an_int_seed_is_expected() -> None:
    with pytest.raises(TypeError):
        dp.cr001_lcg_decrypt(b"abc", True)
    with pytest.raises(TypeError):
        dp.cr013_nr_decrypt(b"abc", False)
    with pytest.raises(TypeError):
        dp.decrypt_candidates(b"abc", seeds=[True])


def test_seeds_are_masked_into_32_bits_like_the_source() -> None:
    assert dp.cr013_nr_decrypt(b"abc", -1) == dp.cr013_nr_decrypt(b"abc", 0xFFFFFFFF)
    assert dp.cr001_lcg_decrypt(b"abc", 1 << 32 | 5) == dp.cr001_lcg_decrypt(b"abc", 5)


def test_bytearray_and_memoryview_inputs_are_accepted() -> None:
    assert dp.xor_decrypt(bytearray(b"abc"), 0x00) == b"abc"
    assert dp.rc4_crypt(memoryview(b"abc"), b"k") == dp.rc4_crypt(b"abc", b"k")
    assert dp.cr001_lcg_decrypt(bytearray(b"abc"), 7) == dp.cr001_lcg_decrypt(b"abc", 7)


def test_empty_data_is_a_valid_no_op() -> None:
    assert dp.xor_decrypt(b"", 0x5A) == b""
    assert dp.rc4_crypt(b"", b"key") == b""
    assert dp.cr001_lcg_decrypt(b"", 1) == b""
    assert dp.cr011_glibc_decrypt(b"", 1) == b""
    assert dp.cr013_nr_decrypt(b"", 1) == b""
    assert dp.cr013_nr_decrypt(b"", 1, wide=True) == b""


def test_returned_buffers_are_immutable_bytes() -> None:
    assert type(dp.cr001_lcg_decrypt(bytearray(b"abc"), 3)) is bytes
    assert type(dp.xor_decrypt(b"abc", b"k")) is bytes
    assert type(dp.rc4_crypt(b"abc", b"k")) is bytes


# ---------------------------------------------------------------------------
# 9. Purity: no file, process, or network access
# ---------------------------------------------------------------------------


def test_module_only_imports_pure_standard_library_helpers() -> None:
    source = pathlib.Path(dp.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {"__future__", "base64", "struct", "zlib", "collections.abc", "typing"}


@pytest.mark.parametrize(
    "forbidden",
    ["subprocess", "socket", "urllib", "http.client", "requests", "httpx", "os.system", "open("],
)
def test_module_source_contains_no_io_or_network_tokens(forbidden: str) -> None:
    source = pathlib.Path(dp.__file__).read_text(encoding="utf-8")
    assert forbidden not in source
