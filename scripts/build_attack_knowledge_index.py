"""Rebuild the packaged ATT&CK enterprise technique index.

The Desktop knowledge base is the source. Groups and software indexes are
intentionally omitted: they are not sample evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        default=Path.home() / "Desktop" / "ATT&CK知识库",
        help="Directory that contains 02_techniques.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "src"
        / "threat_report_agent"
        / "knowledge"
        / "attack-enterprise-index.json",
    )
    args = parser.parse_args()
    source = args.source
    techniques_path = source / "02_techniques.json"
    readme_path = source / "README_索引说明.json"
    if not techniques_path.is_file():
        raise SystemExit(f"missing {techniques_path}")
    readme = json.loads(readme_path.read_text(encoding="utf-8")) if readme_path.is_file() else {}
    techniques = json.loads(techniques_path.read_text(encoding="utf-8"))
    records: dict[str, object] = {}
    for item in techniques:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("attack_id") or "").strip()
        if not technique_id:
            continue
        detections = []
        for det in item.get("detection_strategies") or []:
            if not isinstance(det, dict):
                continue
            det_id = str(det.get("id") or "").strip()
            name = str(det.get("name") or "").strip()
            if det_id:
                detections.append({"id": det_id, "name": name})
            if len(detections) >= 3:
                break
        records[technique_id] = {
            "name": str(item.get("name") or ""),
            "status": str(item.get("status") or "active"),
            "revoked": bool(item.get("revoked")),
            "deprecated": bool(item.get("deprecated")),
            "revoked_by": str(item.get("revoked_by") or ""),
            "revoked_by_name": str(item.get("revoked_by_name") or ""),
            "is_subtechnique": bool(item.get("is_subtechnique")),
            "parent_id": str(item.get("parent_id") or ""),
            "tactics": [str(value) for value in (item.get("tactics") or []) if str(value).strip()],
            "tactics_ids": [str(value) for value in (item.get("tactics_ids") or []) if str(value).strip()],
            "url": str(item.get("url") or ""),
            "detection_strategies": detections,
        }
    payload = {
        "source": readme.get("source") or str(techniques_path),
        "stix_spec_version": readme.get("stix_spec_version"),
        "statistics": readme.get("statistics"),
        "technique_count": len(records),
        "techniques": records,
    }
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    print(f"wrote {args.output} techniques={len(records)} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
