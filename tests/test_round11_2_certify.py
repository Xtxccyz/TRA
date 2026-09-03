from __future__ import annotations

from pathlib import Path

from scripts.round11_2_certify import build_gate, build_partition


def test_round11_2_gate_fails_closed_for_missing_external_proof() -> None:
    gate = build_gate(Path("release-artifacts/round11.2"), {}, [])
    assert gate["status"] == "BLOCKED"
    assert gate["production_ready"] is False
    assert gate["blocker_count"] == len(gate["blockers"])
    assert "model_path_health is BLOCKED" in gate["blockers"]
    assert "development_generalization is BLOCKED" in gate["blockers"]


def test_partition_requires_explicit_labels_and_freezes_counts(tmp_path: Path) -> None:
    malware = tmp_path / "malware"
    benign = tmp_path / "benign"
    malware.mkdir()
    benign.mkdir()
    for index in range(20):
        (malware / f"m{index}.bin").write_bytes(f"malware-{index}".encode())
    for index in range(10):
        (benign / f"b{index}.bin").write_bytes(f"benign-{index}".encode())
    rows, errors = build_partition([malware], [benign])
    assert errors == []
    assert len(rows) == 30
    assert sum(row["split"] == "development" and row["category"] == "malware" for row in rows) == 15
    assert sum(row["split"] == "certification" and row["category"] == "malware" for row in rows) == 5
    assert sum(row["split"] == "development" and row["category"] == "benign" for row in rows) == 5
    assert sum(row["split"] == "certification" and row["category"] == "benign" for row in rows) == 5
    assert all(len(row["sha256"]) == 64 for row in rows)


def test_partition_accepts_explicit_file_inputs_without_copying_samples(tmp_path: Path) -> None:
    malware = tmp_path / "sample-malware.bin"
    benign = tmp_path / "trusted-tool.bin"
    malware.write_bytes(b"malware")
    benign.write_bytes(b"benign")
    rows, errors = build_partition([malware], [benign])
    assert len(rows) == 2
    assert errors
    assert "malware" in {row["category"] for row in rows}
    assert "benign" in {row["category"] for row in rows}
