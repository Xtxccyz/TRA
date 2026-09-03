from __future__ import annotations

from pathlib import Path

from threat_report_agent.function_similarity import (
    FingerprintRecord,
    FunctionSimilarityIndex,
    SimilarityQuery,
)


def test_known_function_catalog_exact_match_is_returned_as_a_lead() -> None:
    index = FunctionSimilarityIndex.load_from_path(
        Path(__file__).resolve().parents[1] / "benchmarks" / "reference" / "known-functions.yaml"
    )

    matches = index.search(
        SimilarityQuery(
            source_evidence_id="evidence-1",
            fingerprint="44e0cbb281dca986",
            scopes=frozenset({"KNOWN_LIBRARY"}),
            threshold=0,
            limit=5,
        )
    )

    assert len(matches) == 1
    assert matches[0].reference_kind == "KNOWN_LIBRARY"
    assert matches[0].reference_id == "NSA-DS-AES-DECRYPT"
    assert matches[0].distance == 0
    assert matches[0].catalog_sha256 == index.catalog_sha256


def test_cross_artifact_search_is_bounded_and_excludes_the_source() -> None:
    index = FunctionSimilarityIndex.load_builtin()
    records = (
        FingerprintRecord("evidence-1", "artifact-1", "same", "0011223344556677"),
        FingerprintRecord("evidence-2", "artifact-2", "peer", "0011223344556677"),
        FingerprintRecord("evidence-3", "artifact-3", "far", "ffffffffffffffff"),
    )

    matches = index.search(
        SimilarityQuery(
            source_evidence_id="evidence-1",
            fingerprint="0011223344556677",
            scopes=frozenset({"CURRENT_TASK"}),
            threshold=0,
            limit=1,
        ),
        records=records,
    )

    assert [(item.reference_id, item.distance) for item in matches] == [("evidence-2", 0)]


def test_known_function_catalog_is_evaluator_only() -> None:
    catalog = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "reference"
        / "known-functions.yaml"
    ).read_bytes()

    assert b"NSA-DS-AES-DECRYPT" in catalog
    assert not FunctionSimilarityIndex.load_builtin().search(
        SimilarityQuery(
            source_evidence_id="evaluator-only",
            fingerprint="44e0cbb281dca986",
            scopes=frozenset({"KNOWN_LIBRARY"}),
            threshold=0,
            limit=5,
        )
    )
