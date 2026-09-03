from __future__ import annotations

import hashlib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    description: str
    modules: tuple[str, ...]
    actions: tuple[str, ...]
    evidence_kinds: tuple[str, ...]


@dataclass(frozen=True)
class AttackSnapshot:
    version: str
    sha256: str
    entries: tuple[AttackTechnique, ...]


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    subtechnique_id: str | None
    reason: str
    purpose: str
    status: str
    confidence: str
    evidence_ids: tuple[str, ...]
    snapshot_version: str
    snapshot_sha256: str


def _snapshot_bytes() -> bytes:
    try:
        return (
            resources.files("threat_report_agent")
            .joinpath("knowledge/attack-snapshot.yaml")
            .read_bytes()
        )
    except FileNotFoundError:
        candidate = Path(__file__).resolve().parent / "knowledge" / "attack-snapshot.yaml"
        return candidate.read_bytes()


def load_attack_snapshot() -> AttackSnapshot:
    raw = _snapshot_bytes()
    payload = yaml.safe_load(raw.decode("utf-8")) or {}
    if not isinstance(payload, dict) or not isinstance(payload.get("version"), str):
        raise ValueError("ATT&CK snapshot must contain a version")
    entries: list[AttackTechnique] = []
    for item in payload.get("entries", []):
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id", ""))
        name = str(item.get("name", ""))
        if not technique_id or not name:
            continue
        entries.append(
            AttackTechnique(
                technique_id=technique_id,
                name=name,
                description=str(item.get("description", "")),
                modules=tuple(str(value) for value in item.get("modules", [])),
                actions=tuple(str(value) for value in item.get("actions", [])),
                evidence_kinds=tuple(str(value) for value in item.get("evidence_kinds", [])),
            )
        )
    return AttackSnapshot(
        version=payload["version"],
        sha256=hashlib.sha256(raw).hexdigest(),
        entries=tuple(entries),
    )


def map_behavior_claim(
    claim: Any,
    evidence_ids: tuple[str, ...],
    evidence_by_id: dict[str, Any],
    *,
    task_id: str,
    snapshot: AttackSnapshot | None = None,
) -> tuple[AttackMapping, ...]:
    """Map one structured behavior claim to candidate ATT&CK techniques.

    Only evidence belonging to the current task participates. Generic API/string
    references are intentionally excluded because they do not establish behavior.
    """
    snapshot = snapshot or load_attack_snapshot()
    if not evidence_ids or not getattr(claim, "module", ""):
        return ()
    valid_ids = tuple(
        evidence_id
        for evidence_id in dict.fromkeys(evidence_ids)
        if evidence_id in evidence_by_id
        and getattr(evidence_by_id[evidence_id], "task_id", None) == task_id
    )
    if not valid_ids:
        return ()
    kinds = {str(getattr(evidence_by_id[evidence_id], "kind", "")) for evidence_id in valid_ids}
    module = str(getattr(claim, "module", ""))
    action = str(getattr(claim, "action", ""))
    # Claims produced by static triage are not behavior claims unless they use a
    # structured action from the snapshot catalog.
    if action in {"references", "prioritizes", "contains"}:
        return ()
    results: list[AttackMapping] = []
    for entry in snapshot.entries:
        if module not in entry.modules or action not in entry.actions:
            continue
        matched_kinds = sorted(kinds.intersection(entry.evidence_kinds))
        if not matched_kinds:
            continue
        confidence = str(getattr(claim, "confidence", "LOW"))
        results.append(
            AttackMapping(
                technique_id=entry.technique_id,
                technique_name=entry.name,
                subtechnique_id=None,
                reason=(
                    f"Structured behavior claim '{action}' in module '{module}' is "
                    f"supported by evidence kinds: {', '.join(matched_kinds)}."
                ),
                purpose="candidate_behavior_mapping",
                status="candidate",
                confidence=confidence,
                evidence_ids=valid_ids,
                snapshot_version=snapshot.version,
                snapshot_sha256=snapshot.sha256,
            )
        )
    return tuple(results)
