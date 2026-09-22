from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from os import getenv
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
class AttackKnowledgeRecord:
    technique_id: str
    name: str
    status: str
    revoked_by: str
    revoked_by_name: str
    is_subtechnique: bool
    parent_id: str
    tactics: tuple[str, ...]
    tactics_ids: tuple[str, ...]
    url: str
    detection_strategies: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class AttackKnowledge:
    source: str
    sha256: str
    technique_count: int
    records: dict[str, AttackKnowledgeRecord]


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
    knowledge_status: str = "active"
    knowledge_sha256: str = ""
    url: str = ""
    tactics: tuple[str, ...] = ()
    detection_strategies: tuple[dict[str, str], ...] = field(default_factory=tuple)


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


def _packaged_knowledge_bytes() -> bytes:
    try:
        return (
            resources.files("threat_report_agent")
            .joinpath("knowledge/attack-enterprise-index.json")
            .read_bytes()
        )
    except FileNotFoundError:
        candidate = Path(__file__).resolve().parent / "knowledge" / "attack-enterprise-index.json"
        return candidate.read_bytes()


def _knowledge_root() -> Path | None:
    env = getenv("ATTACK_KNOWLEDGE_ROOT") or getenv("THREAT_ATTACK_KNOWLEDGE_ROOT")
    if env:
        root = Path(env)
        if (root / "02_techniques.json").is_file():
            return root
        return None
    profile = getenv("USERPROFILE") or getenv("HOME") or ""
    if profile:
        desktop = Path(profile) / "Desktop" / "ATT&CK知识库"
        if (desktop / "02_techniques.json").is_file():
            return desktop
    return None


def _record_from_mapping(technique_id: str, item: dict[str, Any]) -> AttackKnowledgeRecord | None:
    name = str(item.get("name") or "").strip()
    if not technique_id or not name:
        return None
    raw_status = str(item.get("status") or "").strip().casefold()
    if item.get("revoked") is True:
        status = "revoked"
    elif item.get("deprecated") is True:
        status = "deprecated"
    elif raw_status in {"active", "revoked", "deprecated"}:
        status = raw_status
    else:
        status = "active"
    detections: list[dict[str, str]] = []
    for det in item.get("detection_strategies") or ():
        if not isinstance(det, dict):
            continue
        det_id = str(det.get("id") or det.get("detection_strategy_id") or "").strip()
        det_name = str(det.get("name") or det.get("detection_strategy_name") or "").strip()
        if not det_id:
            continue
        detections.append({"id": det_id, "name": det_name})
        if len(detections) >= 3:
            break
    return AttackKnowledgeRecord(
        technique_id=technique_id,
        name=name,
        status=status,
        revoked_by=str(item.get("revoked_by") or "").strip(),
        revoked_by_name=str(item.get("revoked_by_name") or "").strip(),
        is_subtechnique=bool(item.get("is_subtechnique")),
        parent_id=str(item.get("parent_id") or "").strip(),
        tactics=tuple(str(value) for value in (item.get("tactics") or ()) if str(value).strip()),
        tactics_ids=tuple(str(value) for value in (item.get("tactics_ids") or ()) if str(value).strip()),
        url=str(item.get("url") or item.get("technique_url") or "").strip(),
        detection_strategies=tuple(detections),
    )


def _knowledge_from_payload(raw: bytes, *, source: str) -> AttackKnowledge:
    payload = json.loads(raw.decode("utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("techniques"), dict):
        rows = payload["techniques"]
        declared_source = str(payload.get("source") or source)
    elif isinstance(payload, list):
        rows = {
            str(item.get("attack_id") or item.get("technique_id") or ""): item
            for item in payload
            if isinstance(item, dict)
        }
        declared_source = source
    else:
        raise ValueError("ATT&CK knowledge index must contain techniques")
    records: dict[str, AttackKnowledgeRecord] = {}
    for technique_id, item in rows.items():
        if not isinstance(item, dict):
            continue
        record = _record_from_mapping(str(technique_id).strip(), item)
        if record is None:
            continue
        records[record.technique_id] = record
    if not records:
        raise ValueError("ATT&CK knowledge index has no techniques")
    return AttackKnowledge(
        source=declared_source,
        sha256=hashlib.sha256(raw).hexdigest(),
        technique_count=len(records),
        records=records,
    )


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


@lru_cache(maxsize=1)
def load_attack_knowledge() -> AttackKnowledge:
    """Load the versioned enterprise technique registry.

    Mapping policy stays in ``attack-snapshot.yaml``. This registry supplies
    official names, revoked replacements, tactics, and detection strategy
    identifiers. Groups and software indexes are intentionally not loaded:
    they are not sample evidence and must not enter attribution.
    """
    root = _knowledge_root()
    if root is not None:
        raw = (root / "02_techniques.json").read_bytes()
        return _knowledge_from_payload(raw, source=str(root / "02_techniques.json"))
    return _knowledge_from_payload(
        _packaged_knowledge_bytes(),
        source="packaged:knowledge/attack-enterprise-index.json",
    )


def resolve_attack_technique(
    technique_id: str,
    knowledge: AttackKnowledge | None = None,
) -> AttackKnowledgeRecord | None:
    """Return the active technique, following ``revoked_by`` when needed."""
    knowledge = knowledge or load_attack_knowledge()
    current = str(technique_id or "").strip()
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        record = knowledge.records.get(current)
        if record is None:
            return None
        if record.status == "active":
            return record
        current = record.revoked_by
    return None


def map_behavior_claim(
    claim: Any,
    evidence_ids: tuple[str, ...],
    evidence_by_id: dict[str, Any],
    *,
    task_id: str,
    snapshot: AttackSnapshot | None = None,
    knowledge: AttackKnowledge | None = None,
) -> tuple[AttackMapping, ...]:
    """Map one structured behavior claim to candidate ATT&CK techniques.

    Only evidence belonging to the current task participates. Generic API/string
    references are intentionally excluded because they do not establish behavior.
    """
    snapshot = snapshot or load_attack_snapshot()
    knowledge = knowledge or load_attack_knowledge()
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
    seen_ids: set[str] = set()
    for entry in snapshot.entries:
        if module not in entry.modules or action not in entry.actions:
            continue
        matched_kinds = sorted(kinds.intersection(entry.evidence_kinds))
        if not matched_kinds:
            continue
        resolved = resolve_attack_technique(entry.technique_id, knowledge)
        if resolved is None:
            continue
        if resolved.technique_id in seen_ids:
            continue
        seen_ids.add(resolved.technique_id)
        subtechnique_id = resolved.technique_id if resolved.is_subtechnique else None
        reason = (
            f"Structured behavior claim '{action}' in module '{module}' is "
            f"supported by evidence kinds: {', '.join(matched_kinds)}."
        )
        original = knowledge.records.get(entry.technique_id)
        if resolved.technique_id != entry.technique_id:
            original_status = original.status if original is not None else "inactive"
            reason = (
                f"{reason} Catalog id {entry.technique_id} is {original_status} "
                f"and was replaced by {resolved.technique_id}."
            )
        confidence = str(getattr(claim, "confidence", "LOW"))
        results.append(
            AttackMapping(
                technique_id=resolved.technique_id,
                technique_name=resolved.name,
                subtechnique_id=subtechnique_id,
                reason=reason,
                purpose="candidate_behavior_mapping",
                status="candidate",
                confidence=confidence,
                evidence_ids=valid_ids,
                snapshot_version=snapshot.version,
                snapshot_sha256=snapshot.sha256,
                knowledge_status=resolved.status,
                knowledge_sha256=knowledge.sha256,
                url=resolved.url,
                tactics=resolved.tactics,
                detection_strategies=resolved.detection_strategies,
            )
        )
    return tuple(results)
