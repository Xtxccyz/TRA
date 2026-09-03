from pathlib import Path


def test_runtime_source_contains_no_resume_sample_specific_plaintext_token() -> None:
    """Production verification must not depend on the Resume fixture name."""
    root = Path(__file__).resolve().parents[1]
    runtime_files = tuple((root / "src").rglob("*.py"))
    hits = [
        str(path)
        for path in runtime_files
        if "resume.pdf" in path.read_text(encoding="utf-8", errors="replace").casefold()
    ]
    assert hits == []


def test_sample_specific_reference_catalogs_are_outside_runtime_package() -> None:
    """Gold/reference hashes and RVAs must remain evaluator-only inputs."""
    root = Path(__file__).resolve().parents[1]
    runtime = root / "src" / "threat_report_agent"
    forbidden = ("loading-chain-facts.yaml", "known-functions.yaml", "NSA-DS-")
    hits = []
    for path in runtime.rglob("*"):
        if not path.is_file() or path.suffix in {".pyc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in forbidden:
            if token.casefold() in text.casefold():
                hits.append(f"{path}:{token}")
    assert hits == []

    reference_root = root / "benchmarks" / "reference"
    assert (reference_root / "loading-chain-facts.yaml").is_file()
    assert (reference_root / "known-functions.yaml").is_file()
