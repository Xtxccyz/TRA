"""Static decode primitives for byte ranges already extracted from a sample.

Faithful port of the toolkit script ``.agents/skills/peinfo/scripts/crypto.py``
together with the crypto constants of its sibling ``constants.py`` (both under
``.agents/skills/peinfo/scripts/``).  The constants are copied into this module on
purpose: the skill directory is not a product package path and must not be
imported as one.

Scope discipline
----------------
These helpers only transform bytes that were already recovered during static
analysis (strings, resource blobs, embedded config, decoded buffers).  Nothing
here executes, loads, emulates, or detonates a sample, and nothing touches the
file system, the network, or child processes.  Every function is a pure
transform: same input, same output, no side effects.

Terminology: a decoded byte string is a *static decode candidate*, never proof of
runtime behavior and never a verdict.  ``decrypt_candidates`` in particular only
generates candidates; it does not score, rank, or filter them.

Known limits (deliberate, documented deviations from the source script)
-----------------------------------------------------------------------
* Empty keys raise ``ValueError`` instead of silently returning the input
  unchanged (the source returned a copy of the ciphertext for an empty key,
  which reads as a bogus "plaintext == ciphertext" decode).
* ``cr013_nr_decrypt(..., wide=True)`` rejects odd-length input instead of
  zero-filling the trailing byte, because a UTF-16LE buffer cannot be odd.
* ``decrypt_diba_resource`` converts ``zlib.error`` into ``ValueError`` so the
  module keeps a single invalid-input contract.
"""

from __future__ import annotations

import base64
import struct
import zlib
from collections.abc import Iterable


__all__ = [
    "CR001_LGC_ADD",
    "CR001_LGC_MULT",
    "CR007_SUBSTITUTION_TABLE",
    "CR011_GLIBC_ADD",
    "CR011_GLIBC_MULT",
    "CR013_NR_ADD",
    "CR013_NR_MULT",
    "b64_decode",
    "cr001_lcg_decrypt",
    "cr007_decrypt",
    "cr007_encrypt",
    "cr011_glibc_decrypt",
    "cr013_nr_decrypt",
    "decrypt_candidates",
    "decrypt_diba_resource",
    "lcg_stream",
    "rc4_crypt",
    "rc4_decrypt",
    "rc4_encrypt",
    "xor_decrypt",
]


# ===========================================================================
# Constants copied verbatim from .agents/skills/peinfo/scripts/constants.py
# (section "crypto algorithm constants, NSA Equation Group / DiBa family").
# ===========================================================================

# CR-001 LCG stream cipher (DiBa resource envelope / data decryption).
# Recurrence: seed = (0xDD483B8F - 0x6033A96D * seed) mod 2**32; xor byte = (seed >> 8) & 0xFF.
CR001_LGC_MULT = 0x6033A96D
CR001_LGC_ADD = 0xDD483B8F

# CR-007 single-byte substitution table (95-char bijection over 0x20-0x7E).
# Decode direction: plain = table[ord(cipher_char) - 0x20]
# One 95-char literal split over three raw-string chunks for line length only.
CR007_SUBSTITUTION_TABLE = (
    r"""7;]KED<\{OtA}~5F#+rq@xLU9V0_P,)-"""
    r"""yY:WSiwc&p*v`=31"GINuX4hk g2'eQ("""
    r"""[.|o$J>dsmz?jTbBlH/%CR!f8Za^6Mn"""
)

# CR-011 glibc rand LCG (embedded driver string decryption).
# Recurrence: seed = (0x41C64E6D * seed + 0x3039) mod 2**32; xor byte = (seed >> 16) & 0xFF.
CR011_GLIBC_MULT = 0x41C64E6D  # 1103515245
CR011_GLIBC_ADD = 0x3039  # 12345

# CR-013 Numerical Recipes LCG stream cipher (DiBa embedded drivers).
# Recurrence: seed = (0x19660D * seed + 0x3C6EF35F) mod 2**32
# Single byte: byte ^= ((seed >> 16) & 0xFF) | 0x80
# Wide char (UTF-16LE): word ^= ((seed >> 16) & 0xFFFF) | 0x8000
CR013_NR_MULT = 0x19660D  # 1664525
CR013_NR_ADD = 0x3C6EF35F  # 1013904223

# DiBa embedded RT_RCDATA envelope:
# [4B seed LE] + LCG_encrypt([4B decompressed_size] + zlib_stream)
RESOURCE_FORMAT_DIBA = "[4B seed LE] + LCG_encrypt([4B decompressed_size] + zlib_stream)"

_UINT32_MASK = 0xFFFFFFFF
_B64_ALPHABET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _as_bytes(name: str, value: object) -> bytes:
    """Return ``value`` as immutable ``bytes``; ``str`` is never accepted."""
    if isinstance(value, str):
        raise TypeError(f"{name} must be bytes-like, not str")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes, bytearray, or memoryview")


def _as_uint32(name: str, value: object) -> int:
    """Validate an integer LCG parameter/seed and mask it to 32 bits.

    Negative and wider-than-32-bit values are accepted and reduced modulo 2**32,
    matching the source script (disassembly immediates are frequently reported as
    signed values, e.g. ``0x933D10AC`` as ``-1824714580``).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    return value & _UINT32_MASK


def _as_key(name: str, value: object) -> bytes:
    """Validate a non-empty key/cipher key stream."""
    key = _as_bytes(name, value)
    if not key:
        raise ValueError(f"{name} must not be empty")
    return key


def _xor_stream(data: bytes, stream: bytes) -> bytes:
    return bytes(byte ^ stream[index] for index, byte in enumerate(data))


# ===========================================================================
# Generic primitives
# ===========================================================================


def xor_decrypt(data: bytes, key) -> bytes:
    """Single-byte or repeating-key XOR (XOR is its own inverse).

    Ported from ``crypto.py::xor_decrypt``.

    ``key`` as ``int`` is applied to every byte (must be 0..255); ``key`` as
    ``bytes`` is repeated over ``data``.  An empty ``bytes`` key raises
    ``ValueError`` (see the module docstring for why the source behaviour of
    returning the input unchanged was dropped).
    """
    buffer = _as_bytes("data", data)
    if isinstance(key, bool):
        raise TypeError("key must be an int in 0..255 or a non-empty bytes-like key")
    if isinstance(key, int):
        if not 0 <= key <= 0xFF:
            raise ValueError("int key must be in 0..255")
        return bytes(byte ^ key for byte in buffer)
    stream = _as_key("key", key)
    length = len(stream)
    return bytes(buffer[index] ^ stream[index % length] for index in range(len(buffer)))


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 stream cipher (encryption and decryption are the same operation).

    Ported from ``crypto.py::rc4_crypt``.  KSA builds the 256-byte S-box from
    ``key``; PRGA generates the key stream that is XORed with ``data``.  Typical
    C2 framing: the first 16 bytes of a blob are the session key and the rest is
    ciphertext.
    """
    buffer = _as_bytes("data", data)
    stream_key = _as_key("key", key)
    box = list(range(256))
    j = 0
    key_length = len(stream_key)
    for i in range(256):  # KSA
        j = (j + box[i] + stream_key[i % key_length]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray(len(buffer))
    i = j = 0
    for index in range(len(buffer)):  # PRGA
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out[index] = buffer[index] ^ box[(box[i] + box[j]) & 0xFF]
    return bytes(out)


# Semantic aliases (the source exposes the same three names).
rc4_decrypt = rc4_crypt
rc4_encrypt = rc4_crypt


def lcg_stream(seed: int, mult: int, add: int, length: int, xor_shift: int = 8) -> bytes:
    """Generate an LCG key stream: ``seed = (mult * seed + add) mod 2**32``.

    Ported from ``crypto.py::lcg_stream``.  ``seed`` is the pre-step state, so the
    first emitted byte already reflects one recurrence step.  Each byte is
    ``(seed >> xor_shift) & 0xFF``: shift 8 selects BYTE1 (CR-001), 16 selects
    BYTE2 (CR-011/CR-013).  ``length`` may be 0; ``xor_shift`` must be 0..24.
    """
    state = _as_uint32("seed", seed)
    multiplier = _as_uint32("mult", mult)
    increment = _as_uint32("add", add)
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an int")
    if length < 0:
        raise ValueError("length must not be negative")
    if isinstance(xor_shift, bool) or not isinstance(xor_shift, int):
        raise TypeError("xor_shift must be an int")
    if not 0 <= xor_shift <= 24:
        raise ValueError("xor_shift must be in 0..24")
    out = bytearray(length)
    for index in range(length):
        state = (multiplier * state + increment) & _UINT32_MASK
        out[index] = (state >> xor_shift) & 0xFF
    return bytes(out)


def b64_decode(data) -> bytes:
    """base64 decode with automatic padding.

    Ported from ``crypto.py::b64_decode``.  Accepts ``str`` (ASCII) or
    bytes-like input.  Padding is appended as needed and non-alphabet characters
    (for example line breaks in a wrapped blob) are ignored, matching the source.
    Input with no base64 character at all raises ``ValueError`` rather than
    silently decoding to an empty buffer.
    """
    if isinstance(data, str):
        try:
            raw = data.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("base64 text must be ASCII") from error
    elif isinstance(data, (bytes, bytearray, memoryview)):
        raw = bytes(data)
    else:
        raise TypeError("data must be str or bytes-like")
    if not raw:
        raise ValueError("base64 input must not be empty")
    if not any(byte in _B64_ALPHABET for byte in raw):
        raise ValueError("base64 input contains no base64 character")
    padded = raw + b"=" * (-len(raw) % 4)
    return base64.b64decode(padded)  # raises binascii.Error (a ValueError) if malformed


# ===========================================================================
# NSA Equation Group / DiBa family primitives
# ===========================================================================


def cr001_lcg_decrypt(data: bytes, seed: int) -> bytes:
    """CR-001 LCG stream decryption (DiBa resource envelope / data blobs).

    Ported from ``crypto.py::cr001_lcg_decrypt``.

    Recurrence: ``seed = (0xDD483B8F - 0x6033A96D * seed) mod 2**32``; each output
    byte is ``data[i] ^ ((seed >> 8) & 0xFF)``.

    Envelope: ``[4B seed LE] + LCG_encrypt([4B decompressed_size] + zlib_stream)``
    -- see ``decrypt_diba_resource``.  XOR is symmetric, so this same function
    also produces the ciphertext.
    """
    buffer = _as_bytes("data", data)
    state = _as_uint32("seed", seed)
    out = bytearray(len(buffer))
    for index in range(len(buffer)):
        state = (CR001_LGC_ADD - CR001_LGC_MULT * state) & _UINT32_MASK
        out[index] = buffer[index] ^ ((state >> 8) & 0xFF)
    return bytes(out)


def cr007_decrypt(cipher: str | bytes) -> str:
    """CR-007 substitution-table decryption (DiBa body string obfuscation).

    Ported from ``crypto.py::cr007_decrypt``.

    Decode direction (the measured one -- the reversed early fact
    ``table.index(c) + 0x20`` is wrong)::

        plain = CR007_SUBSTITUTION_TABLE[ord(cipher_char) - 0x20]

    Applied only to characters in ``0x20..0x7E``; every other character is copied
    through unchanged, so bytes >= 0x7F survive a latin1 round trip.  ``bytes``
    input is mapped byte-for-byte through latin1 first, as in the source.
    """
    if isinstance(cipher, (bytes, bytearray, memoryview)):
        text = bytes(cipher).decode("latin1")
    elif isinstance(cipher, str):
        text = cipher
    else:
        raise TypeError("cipher must be str or bytes-like")
    table = CR007_SUBSTITUTION_TABLE
    out = []
    for char in text:
        code = ord(char)
        if 0x20 <= code < 0x7F:
            out.append(table[code - 0x20])
        else:
            out.append(char)
    return "".join(out)


def cr007_encrypt(plain: str | bytes) -> str:
    """CR-007 substitution-table encryption: the inverse of :func:`cr007_decrypt`.

    Ported from ``crypto.py::cr007_encrypt``.  Characters outside the 95-char
    table raise ``ValueError``.
    """
    if isinstance(plain, (bytes, bytearray, memoryview)):
        text = bytes(plain).decode("latin1")
    elif isinstance(plain, str):
        text = plain
    else:
        raise TypeError("plain must be str or bytes-like")
    table = CR007_SUBSTITUTION_TABLE
    out = []
    for char in text:
        index = table.find(char)
        if index < 0:
            raise ValueError(f"character {char!r} is not representable in the CR-007 table")
        out.append(chr(index + 0x20))
    return "".join(out)


def cr011_glibc_decrypt(data: bytes, seed: int) -> bytes:
    """CR-011 glibc ``rand`` LCG decryption (embedded driver API strings).

    Ported from ``crypto.py::cr011_glibc_decrypt``.

    Recurrence: ``seed = (0x41C64E6D * seed + 0x3039) mod 2**32``; each output byte
    is ``data[i] ^ ((seed >> 16) & 0xFF)``.  Measured use: ``10_104.sys`` recovers
    ``ExAllocatePoolWithTag`` / ``ZwAllocateVirtualMemory`` / ``ZwFreeVirtualMemory``.
    """
    buffer = _as_bytes("data", data)
    stream = lcg_stream(seed, CR011_GLIBC_MULT, CR011_GLIBC_ADD, len(buffer), xor_shift=16)
    return _xor_stream(buffer, stream)


def cr013_nr_decrypt(data: bytes, seed: int, wide: bool = False) -> bytes:
    """CR-013 Numerical Recipes LCG decryption (DiBa embedded driver strings).

    Ported from ``crypto.py::cr013_nr_decrypt``.

    Recurrence: ``seed = (0x19660D * seed + 0x3C6EF35F) mod 2**32`` with two
    variants::

        wide=False:  byte ^= ((seed >> 16) & 0xFF) | 0x80
        wide=True:   word ^= ((seed >> 16) & 0xFFFF) | 0x8000   # UTF-16LE word

    Each obfuscated string carries its own seed from a call-site array.  Measured
    use: SSDT hook service names (``ZwCreateThread``, ``NtClose``, ...) and the
    ``ntdll.dll`` module name.  ``wide=True`` requires an even buffer length; an
    odd length raises ``ValueError`` (see the module docstring).
    """
    buffer = _as_bytes("data", data)
    if not isinstance(wide, bool):
        raise TypeError("wide must be a bool")
    state = _as_uint32("seed", seed)
    out = bytearray(len(buffer))
    if wide:
        if len(buffer) % 2:
            raise ValueError("wide CR-013 input must have an even length (UTF-16LE)")
        for index in range(0, len(buffer), 2):
            state = (CR013_NR_MULT * state + CR013_NR_ADD) & _UINT32_MASK
            word = buffer[index] | (buffer[index + 1] << 8)
            word ^= ((state >> 16) & 0xFFFF) | 0x8000
            out[index] = word & 0xFF
            out[index + 1] = (word >> 8) & 0xFF
    else:
        for index in range(len(buffer)):
            state = (CR013_NR_MULT * state + CR013_NR_ADD) & _UINT32_MASK
            out[index] = buffer[index] ^ (((state >> 16) & 0xFF) | 0x80)
    return bytes(out)


def decrypt_diba_resource(encrypted_resource: bytes) -> bytes:
    """Decrypt a DiBa embedded RT_RCDATA resource (CR-001 LCG + zlib).

    Ported from ``crypto.py::decrypt_diba_resource``.

    Layout (``RESOURCE_FORMAT_DIBA``): ``[4B seed LE]`` followed by the CR-001
    encrypted ``[4B decompressed_size][zlib stream]``.  The size field is skipped,
    not enforced (the source does the same).  At least 8 bytes are required.
    Decompression failure raises ``ValueError`` instead of leaking ``zlib.error``.
    """
    resource = _as_bytes("encrypted_resource", encrypted_resource)
    if len(resource) < 8:
        raise ValueError("encrypted resource must be at least 8 bytes")
    seed = struct.unpack_from("<I", resource, 0)[0]
    decrypted = cr001_lcg_decrypt(resource[4:], seed)
    try:
        return zlib.decompress(decrypted[4:])
    except zlib.error as error:
        raise ValueError(f"DiBa resource payload is not a valid zlib stream: {error}") from error


# ===========================================================================
# Candidate generation (declarative, no verdict)
# ===========================================================================


def _as_seed_iterable(name: str, values: Iterable[int]) -> list[int]:
    """Validate an iterable of seed values (a bare key/str is a caller bug)."""
    if values is None or isinstance(values, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be an iterable of int seeds")
    try:
        items = list(values)
    except TypeError as error:
        raise TypeError(f"{name} must be an iterable of int seeds") from error
    return [_as_uint32(f"{name}[{index}]", item) for index, item in enumerate(items)]


def _as_key_iterable(name: str, values: Iterable[bytes]) -> list[bytes]:
    """Validate an iterable of non-empty key streams (a bare key is a caller bug)."""
    if values is None or isinstance(values, (str, bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be an iterable of bytes-like keys, not a single key")
    try:
        items = list(values)
    except TypeError as error:
        raise TypeError(f"{name} must be an iterable of bytes-like keys") from error
    return [_as_key(f"{name}[{index}]", item) for index, item in enumerate(items)]


def _seed_label(seed: int, wide: bool = False) -> str:
    return f"0x{seed & _UINT32_MASK:08X}" + (" (wide)" if wide else "")


def decrypt_candidates(
    cipher: bytes,
    *,
    seeds: Iterable[int] = (),
    keys: Iterable[bytes] = (),
) -> tuple[dict[str, object], ...]:
    """Generate static decode candidates for ``cipher``; never judges them.

    Each candidate is a declarative dict with exactly three keys::

        {"algorithm": "rc4"|"xor"|"cr001"|"cr011"|"cr013"|"cr007",
         "key_or_seed": "<stable label>",
         "plaintext": b"..."}

    ``key_or_seed`` labels: ``key:<hex>`` for XOR/RC4 key streams,
    ``0x<8 upper hex digits>`` for LCG seeds (``" (wide)"`` suffix for the
    CR-013 UTF-16LE variant), and ``substitution-table`` for CR-007.

    Emission order is fixed and duplicates are dropped while keeping the caller's
    first-seen order: XOR per key, RC4 per key, CR-001 per seed, CR-011 per seed,
    then per seed the CR-013 single-byte variant followed immediately by its wide
    variant (wide only for even-length input of at least 2 bytes), and finally the
    single CR-007 candidate.  No candidate is scored, filtered, or dropped for
    looking implausible -- a zero XOR key that reproduces the cipher bytes is still
    reported.
    """
    buffer = _as_bytes("cipher", cipher)
    if not buffer:
        raise ValueError("cipher must not be empty")
    key_list = _as_key_iterable("keys", keys)
    seed_list = _as_seed_iterable("seeds", seeds)
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def emit(algorithm: str, key_or_seed: str, plaintext: bytes) -> None:
        marker = (algorithm, key_or_seed)
        if marker in seen:
            return
        seen.add(marker)
        candidates.append(
            {"algorithm": algorithm, "key_or_seed": key_or_seed, "plaintext": plaintext}
        )

    for key in key_list:
        emit("xor", f"key:{key.hex()}", xor_decrypt(buffer, key))
    for key in key_list:
        emit("rc4", f"key:{key.hex()}", rc4_crypt(buffer, key))
    for seed in seed_list:
        emit("cr001", _seed_label(seed), cr001_lcg_decrypt(buffer, seed))
    for seed in seed_list:
        emit("cr011", _seed_label(seed), cr011_glibc_decrypt(buffer, seed))
    for seed in seed_list:
        emit("cr013", _seed_label(seed), cr013_nr_decrypt(buffer, seed))
        if len(buffer) >= 2 and len(buffer) % 2 == 0:
            emit("cr013", _seed_label(seed, wide=True), cr013_nr_decrypt(buffer, seed, wide=True))
    emit("cr007", "substitution-table", cr007_decrypt(buffer).encode("latin1"))
    return tuple(candidates)
