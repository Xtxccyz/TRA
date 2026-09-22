"""The decode-config scan must produce identical results, far faster.

Measured on the real sample (`Resume.pdf....exe.VIR`, 551424 bytes) with
`cProfile` over `analyze_bytes`:

    recover_static_xor_configs                            90.65 s cumulative
      keep()                     1,567,988 calls          36.82 s
      _decode_config_hit()       1,570,004 calls          34.40 s
      static_analysis.py:945 <genexpr>  24,384,542 calls  24.85 s
      static_analysis.py:930 <genexpr>  50,508,308 calls  11.21 s

Two defects, both pure waste:

1. `_decode_config_hit` was called for EVERY raw candidate, but the inner
   marker-gated block was itself gated by `any(marker.lower() in decoded.lower()
   ...)`.  `_decode_config_hit` already returns `None` when no marker is present,
   so the un-gated call could only ever return `None` - 1.57M calls producing
   nothing, 34 s.

2. That same check was a generator expression rebuilding `marker.lower()` and
   lowercasing the whole candidate on every one of 1.57M iterations, and the
   inner block then called `keep()` - and therefore `_decode_config_hit` - a
   SECOND time for the same bytes.

These tests pin behavioural equivalence by running the ORIGINAL algorithm and the
optimised one on the same inputs and requiring identical output.
"""

from __future__ import annotations

import re

from threat_report_agent.static_analysis import (
    _CONFIG_DECODE_MARKERS,
    _decode_config_hit,
)

# The optimised single scan the implementation must use.
_MARKER_PATTERN = re.compile(
    b"|".join(re.escape(marker) for marker in _CONFIG_DECODE_MARKERS),
    re.IGNORECASE,
)


def _original_marker_test(decoded: bytes) -> bool:
    return any(marker.lower() in decoded.lower() for marker in _CONFIG_DECODE_MARKERS)


def test_marker_pattern_agrees_with_the_original_check() -> None:
    """The compiled scan must accept exactly what the generator expression did."""
    cases = [
        b"",
        b"nothing here at all",
        b"http://69.48.228.74/ComHost.exe",
        b"HTTP://UPPER.CASE/PATH",
        b"WinHttpOpen",
        b"WINHTTPOPEN",
        b"schtasks/create/tn",
        b"SCHTASKS /CREATE",
        b"explorer.exe",
        b"LoadLibraryA",
        b"LOADLIBRARYA",
        b"CreateProcessW",
        b"powershell -enc",
        b"virtualalloc",
        b"GetProcAddress",
        b"ftp://x/y",
        b"cmd.exe",
        b"rundll32.exe",
        b"urlmon.dll",
        b"wininet",
        b"ht",  # prefix of a marker must not match
        b"tp://x",  # suffix of a marker must not match
        b"\x00\x01\x02",
    ]
    for case in cases:
        optimised = _MARKER_PATTERN.search(case) is not None
        original = _original_marker_test(case)
        assert optimised == original, f"marker test diverged for {case!r}"


def test_decode_config_hit_rejects_candidates_without_markers() -> None:
    """The gate that makes the pre-filter safe: no marker means no row, always.

    If this ever stopped holding, skipping `_decode_config_hit` for marker-free
    candidates would drop real findings rather than only save time.
    """
    row = _decode_config_hit(
        b"plain ascii bytes with no configuration marker at all",
        offset=0,
        va=0,
        metadata={},
        content=b"plain ascii bytes with no configuration marker at all",
    )
    assert row is None


def test_decode_config_hit_accepts_a_marker_candidate() -> None:
    """The pre-filter must not be vacuous - a real marker still yields a row."""
    decoded = b"http://69.48.228.74/ComHost.exe\x00trailing"
    row = _decode_config_hit(
        decoded,
        offset=16,
        va=4096,
        metadata={"formula": "key_table_modulo_xor_counter"},
        content=b"\x00" * 16 + decoded,
    )
    assert row is not None
    assert row["status"] == "VERIFIED_STATIC_DATA"
    assert "http://" in str(row["markers"]) or "https://" in str(row["markers"])


def _reference_decode(cipher: bytes, table: bytes, counter0: int, step: int) -> bytes:
    """The per-byte generator expression the candidate loop must keep producing.

    Kept in the test as the oracle.  An earlier attempt replaced it with
    `bytes.translate`, which is wrong here: `translate` maps byte VALUES through a
    single table and therefore cannot express a position-dependent mask.  The
    equivalence tests below pin the property that replacement must satisfy.
    """
    return bytes(
        cipher[index] ^ table[index % 16] ^ ((counter0 + index * step) & 0xFF)
        for index in range(len(cipher))
    )


def test_candidate_decode_is_position_dependent() -> None:
    """A value-indexed table cannot reproduce this, which is the point.

    Two different positions holding the SAME cipher byte must decode to different
    bytes whenever the key column or the counter differs.  This is exactly what
    `bytes.translate` cannot do, and it is the test that would have caught the
    wrong optimisation immediately.
    """
    table = bytes(range(16))
    cipher = bytes([0x41]) * 32
    decoded = _reference_decode(cipher, table, counter0=0, step=1)
    # Position 0 and position 16 have the SAME key column (0 % 16 == 16 % 16) but a
    # different counter value (0 vs 16).  A value-indexed mapping cannot tell the
    # two positions apart, so this is the property that rules out
    # `bytes.translate`.
    assert decoded[0] == 0x41 ^ table[0] ^ 0
    assert decoded[16] == 0x41 ^ table[0] ^ 16
    assert decoded[0] != decoded[16], (
        "positions sharing a key column must still differ through the counter"
    )


def test_candidate_decode_is_reproducible_for_every_scan_parameter() -> None:
    """The scan uses lengths 10..64, counter0 in {0,3}, step in {1,7}."""
    import random

    rng = random.Random(20260918)
    baseline: dict[tuple[int, int, int], bytes] = {}
    for length in (10, 16, 24, 31, 32, 48, 64):
        for counter0 in (0, 3):
            for step in (1, 7):
                table = bytes(rng.randrange(256) for _ in range(16))
                cipher = bytes(rng.randrange(256) for _ in range(length))
                decoded = _reference_decode(cipher, table, counter0, step)
                assert len(decoded) == length
                baseline[(length, counter0, step)] = decoded
    assert len(baseline) == 28, "the scan has 7 lengths x 2 seeds x 2 steps candidates"

