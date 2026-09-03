from __future__ import annotations

from scripts.ruff_format_debt_gate import evaluate_format_debt, parse_ruff_format_output


def test_parse_ruff_output_normalizes_and_deduplicates_paths() -> None:
    output = """
Would reformat: scripts\\example.py
Would reformat: ./tests/test_example.py
Would reformat: scripts\\example.py
2 files would be reformatted, 1 file already formatted
"""

    assert parse_ruff_format_output(output) == ["scripts/example.py", "tests/test_example.py"]


def test_format_debt_passes_when_only_existing_debt_remains() -> None:
    result = evaluate_format_debt(
        ["scripts/example.py", "tests/test_example.py"],
        ["scripts/example.py", "tests/test_example.py", "src/old.py"],
    )

    assert result["status"] == "PASS"
    assert result["removed_paths"] == ["src/old.py"]
    assert result["new_paths"] == []


def test_format_debt_fails_for_new_path_even_if_count_is_unchanged() -> None:
    result = evaluate_format_debt(
        ["scripts/example.py", "benchmarks/new.py"],
        ["scripts/example.py", "tests/old.py"],
    )

    assert result["status"] == "FAIL"
    assert result["new_paths"] == ["benchmarks/new.py"]
    assert result["count_increased"] is False


def test_format_debt_fails_when_count_increases() -> None:
    result = evaluate_format_debt(
        ["scripts/example.py", "tests/test_example.py"],
        ["scripts/example.py"],
    )

    assert result["status"] == "FAIL"
    assert result["count_increased"] is True
