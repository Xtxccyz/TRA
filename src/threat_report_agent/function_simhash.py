from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence


ALGORITHM = "charikar-simhash-64"
FEATURE = "mnemonic-4gram"
FEATURE_HASH = "md5-prefix-64-le"


def generate_ngrams(mnemonics: Sequence[str], n: int = 4) -> list[str]:
    """Generate the mnemonic n-grams used by the finished SimHash implementation."""
    if len(mnemonics) < n:
        return [" ".join(mnemonics)]
    return [" ".join(mnemonics[index : index + n]) for index in range(len(mnemonics) - n + 1)]


def hash64(feature: str) -> int:
    """Hash a feature as the little-endian first 64 bits of MD5."""
    digest = hashlib.md5(feature.encode("utf-8"), usedforsecurity=False).digest()
    return struct.unpack("<Q", digest[:8])[0]


def simhash(features: Sequence[str], weights: Sequence[int] | None = None) -> int:
    vector = [0] * 64
    feature_weights = weights if weights is not None else [1] * len(features)
    for feature, weight in zip(features, feature_weights, strict=False):
        bits = hash64(feature)
        for index in range(64):
            vector[index] += weight if (bits >> index) & 1 else -weight

    fingerprint = 0
    for index, weight in enumerate(vector):
        if weight > 0:
            fingerprint |= 1 << index
    return fingerprint


def fingerprint_mnemonics(mnemonics: Sequence[str]) -> str:
    normalized = [item.strip().lower() for item in mnemonics if item.strip()]
    return f"{simhash(generate_ngrams(normalized, n=4)):016x}"


def hamming_distance(first: str | int, second: str | int) -> int:
    first_value = int(first, 16) if isinstance(first, str) else first
    second_value = int(second, 16) if isinstance(second, str) else second
    return (first_value ^ second_value).bit_count()
