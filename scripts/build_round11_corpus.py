"""Build a Round 11 corpus manifest without exposing sample contents to runtime.

The command accepts explicitly labeled malware and benign roots.  It hashes
files only; it never opens a sample as code, invokes a parser, or writes Gold
answers.  Missing corpus entries are reported as errors instead of fabricated
fixtures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from threat_report_agent.product_certification import (  # noqa: E402
    sha256_file,
    validate_corpus_split,
)


def _files(root: Path) -> list[Path]:
    return sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink())


def _rows(paths: list[Path], *, category: str, split: str, offset: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, path in enumerate(paths):
        rows.append(
            {
                "sample_id": f"{category}-{offset + index:03d}",
                "path": str(path.resolve()),
                "sha256": sha256_file(path),
                "category": category,
                "split": split,
                "expected_analysis_class": "FULL",
                "critical_mechanisms": [],
                "critical_iocs": [],
                "negative_gold": [],
                "important_unknowns": [],
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malware-root", action="append", type=Path, required=True)
    parser.add_argument("--benign-root", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("release-artifacts"))
    args = parser.parse_args()
    malware = [path for root in args.malware_root for path in _files(root.resolve())]
    benign = [path for root in args.benign_root for path in _files(root.resolve())]
    # Certification is the tail of a deterministic, hash-sorted list.  The
    # caller must provide independently labeled roots; this tool never infers
    # benignness from an extension or filename.
    malware = sorted({path for path in malware}, key=lambda item: (sha256_file(item), str(item)))
    benign = sorted({path for path in benign}, key=lambda item: (sha256_file(item), str(item)))
    rows = (
        _rows(malware[:15], category="malware", split="development", offset=1)
        + _rows(malware[15:20], category="malware", split="certification", offset=16)
        + _rows(benign[:5], category="benign", split="development", offset=1)
        + _rows(benign[5:10], category="benign", split="certification", offset=6)
    )
    errors = validate_corpus_split(rows)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "generalization-corpus-manifest.json").write_text(
        json.dumps([row for row in rows if row["split"] == "development"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "certification-corpus-manifest.json").write_text(
        json.dumps([row for row in rows if row["split"] == "certification"], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if errors:
        raise SystemExit("Round 11 corpus is incomplete:\n" + "\n".join(f"- {item}" for item in errors))
    print(json.dumps({"status": "PASS", "entry_count": len(rows)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
