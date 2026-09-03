from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

from threat_report_agent.function_simhash import ALGORITHM, FEATURE, FEATURE_HASH, hamming_distance


SimilarityScope = Literal["KNOWN_LIBRARY", "CURRENT_TASK", "CASE"]


@dataclass(frozen=True)
class FingerprintRecord:
    evidence_id: str
    artifact_id: str
    reference_id: str
    fingerprint: str
    algorithm: str = ALGORITHM
    feature: str = FEATURE
    hash_name: str = FEATURE_HASH


@dataclass(frozen=True)
class SimilarityQuery:
    source_evidence_id: str
    fingerprint: str
    scopes: frozenset[SimilarityScope]
    threshold: int = 10
    limit: int = 50

    def __post_init__(self) -> None:
        if not 0 <= self.threshold <= 64:
            raise ValueError("similarity threshold must be between 0 and 64")
        if not 1 <= self.limit <= 500:
            raise ValueError("similarity limit must be between 1 and 500")
        if not self.scopes:
            raise ValueError("similarity query requires at least one scope")
        int(self.fingerprint, 16)


@dataclass(frozen=True)
class SimilarityMatch:
    source_evidence_id: str
    reference_kind: str
    reference_id: str
    distance: int
    threshold: int
    algorithm: str
    feature: str
    reference_metadata: dict[str, object]
    catalog_sha256: str | None = None


class FunctionSimilarityIndex:
    """Deterministic, bounded search over evaluator references and Evidence records."""

    def __init__(self, entries: tuple[dict[str, object], ...], catalog_sha256: str) -> None:
        self._entries = entries
        self.catalog_sha256 = catalog_sha256

    @classmethod
    def load_builtin(cls) -> "FunctionSimilarityIndex":
        """Return an empty production index.

        The historical known-function catalog contains sample hashes and
        RVAs, so it is evaluator-only.  Production still supports same-task
        and same-case similarity over freshly observed Evidence.
        """
        return cls.load_from_bytes(b"version: 1\nentries: []\n", "production-empty")

    @classmethod
    def load_from_path(cls, path: str | Path) -> "FunctionSimilarityIndex":
        candidate = Path(path)
        if not candidate.is_file():
            raise FileNotFoundError(candidate)
        return cls.load_from_bytes(candidate.read_bytes(), str(candidate))

    @classmethod
    def load_from_bytes(cls, raw: bytes, source: str = "explicit") -> "FunctionSimilarityIndex":
        """Load an evaluator catalog from explicit, caller-owned bytes."""
        payload = yaml.safe_load(raw.decode("utf-8")) or {}
        if not isinstance(payload, dict):
            raise ValueError("known function catalog must be a mapping")
        algorithm = str(payload.get("algorithm", ALGORITHM))
        feature = str(payload.get("feature", FEATURE))
        hash_name = str(payload.get("hash", FEATURE_HASH))
        if (algorithm, feature, hash_name) != (ALGORITHM, FEATURE, FEATURE_HASH):
            raise ValueError("known function catalog uses an unsupported fingerprint contract")
        entries = tuple(item for item in payload.get("entries", []) if isinstance(item, dict))
        return cls(entries, hashlib.sha256(raw).hexdigest())

    def search(
        self,
        query: SimilarityQuery,
        *,
        records: tuple[FingerprintRecord, ...] = (),
    ) -> tuple[SimilarityMatch, ...]:
        candidates: list[SimilarityMatch] = []
        if "KNOWN_LIBRARY" in query.scopes:
            for item in self._entries:
                value = item.get("simhash")
                if not isinstance(value, str):
                    continue
                distance = hamming_distance(query.fingerprint, value)
                if distance <= query.threshold:
                    reference_id = str(item.get("name", item.get("func", "unknown")))
                    candidates.append(
                        SimilarityMatch(
                            query.source_evidence_id,
                            "KNOWN_LIBRARY",
                            reference_id,
                            distance,
                            query.threshold,
                            ALGORITHM,
                            FEATURE,
                            dict(item),
                            self.catalog_sha256,
                        )
                    )
        if "CURRENT_TASK" in query.scopes or "CASE" in query.scopes:
            for record in records:
                if record.evidence_id == query.source_evidence_id:
                    continue
                if (record.algorithm, record.feature, record.hash_name) != (
                    ALGORITHM,
                    FEATURE,
                    FEATURE_HASH,
                ):
                    continue
                distance = hamming_distance(query.fingerprint, record.fingerprint)
                if distance <= query.threshold:
                    candidates.append(
                        SimilarityMatch(
                            query.source_evidence_id,
                            "CURRENT_TASK" if "CURRENT_TASK" in query.scopes else "CASE",
                            record.evidence_id,
                            distance,
                            query.threshold,
                            ALGORITHM,
                            FEATURE,
                            {
                                "artifact_id": record.artifact_id,
                                "reference_id": record.reference_id,
                            },
                            None,
                        )
                    )
        candidates.sort(key=lambda item: (item.distance, item.reference_kind, item.reference_id))
        return tuple(candidates[: query.limit])
