from __future__ import annotations

from types import SimpleNamespace

from threat_report_agent.attack_mapping import (
    load_attack_knowledge,
    load_attack_snapshot,
    map_behavior_claim,
    resolve_attack_technique,
)
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.service import AnalysisService


def test_packaged_attack_snapshot_is_versioned_and_hashed() -> None:
    snapshot = load_attack_snapshot()

    assert snapshot.version
    assert len(snapshot.sha256) == 64
    assert snapshot.entries
    assert {entry.technique_id for entry in snapshot.entries} >= {
        "T1027",
        "T1055",
        "T1071",
        "T1497",
    }


def test_structured_behavior_claim_maps_to_candidate_with_current_evidence() -> None:
    claim = SimpleNamespace(
        id="claim-1",
        module="decryption",
        subject="sample.exe",
        action="may_decode_or_decrypt",
        object="embedded data",
        mechanism="static crypto, encoding, or high-entropy indicators",
        condition="inferred from file content without execution",
        confidence="MEDIUM",
        status="CANDIDATE",
    )
    evidence = {
        "ev-1": SimpleNamespace(
            id="ev-1",
            task_id="task-1",
            kind="crypto_indicator",
            value={"algorithm": "AES"},
        )
    }

    result = map_behavior_claim(claim, ("ev-1",), evidence, task_id="task-1")

    assert len(result) == 1
    mapped = result[0]
    assert mapped.technique_id == "T1027"
    assert mapped.status == "candidate"
    assert mapped.evidence_ids == ("ev-1",)
    assert mapped.snapshot_version
    assert len(mapped.snapshot_sha256) == 64
    assert "crypto_indicator" in mapped.reason


def test_api_string_without_structured_behavior_claim_is_not_mapped() -> None:
    claim = SimpleNamespace(
        id="claim-2",
        module="static_triage",
        subject="sample.exe",
        action="references",
        object="VirtualAlloc",
        mechanism="string match",
        condition="static evidence only",
        confidence="HIGH",
        status="CANDIDATE",
    )
    evidence = {
        "ev-2": SimpleNamespace(
            id="ev-2",
            task_id="task-1",
            kind="import_symbol",
            value={"name": "VirtualAlloc"},
        )
    }

    assert map_behavior_claim(claim, ("ev-2",), evidence, task_id="task-1") == ()


def test_mapping_rejects_evidence_from_another_task() -> None:
    claim = SimpleNamespace(
        id="claim-3",
        module="loader",
        subject="sample.exe",
        action="may_load_or_inject",
        object="code or a secondary component",
        mechanism="loader and memory-management APIs",
        condition="inferred from static imports or strings",
        confidence="MEDIUM",
        status="CANDIDATE",
    )
    evidence = {
        "ev-3": SimpleNamespace(
            id="ev-3",
            task_id="other-task",
            kind="loader_indicator",
            value={},
        )
    }

    assert map_behavior_claim(claim, ("ev-3",), evidence, task_id="task-1") == ()


def test_analysis_persists_versioned_attack_mapping_tool_run(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("W5 ATT&CK mapping")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nurl = 'https://example.test/c2'\n",
    )

    task = service.task_view(result.task_id)
    mapping_runs = [run for run in task["tool_runs"] if run["tool"] == "attack-mapping-index"]
    assert len(mapping_runs) == 1
    assert mapping_runs[0]["version"] == "0.2.0"
    mapped_claims = [claim for claim in task["claims"] if claim["attack_mapping"].get("mappings")]
    assert mapped_claims
    assert all(
        item["attack_mapping"]["mappings"][0]["status"] == "candidate" for item in mapped_claims
    )
    assert all(item["attack_mapping"].get("knowledge_sha256") for item in mapped_claims)
    assert all(item["attack_mapping"]["mappings"][0].get("url") for item in mapped_claims)
    revision = service.get_report_revision(result.report_revision_id)
    behavior = next(
        item for item in revision["document"]["modules"] if item["id"] == "behavior_attack"
    )
    mapped_rows = [row for row in behavior["rows"] if row.get("attack_mapping", {}).get("mappings")]
    assert mapped_rows
    assert mapped_rows[0]["attack_mapping"]["snapshot_version"]


def test_enterprise_knowledge_resolves_active_and_revoked_ids() -> None:
    knowledge = load_attack_knowledge()

    assert knowledge.technique_count >= 697
    parent = resolve_attack_technique("T1134.004", knowledge)
    assert parent is not None
    assert parent.status == "active"
    assert parent.name == "Parent PID Spoofing"
    assert parent.url.endswith("/T1134.004/")
    assert "DET0489" in {item["id"] for item in parent.detection_strategies}

    replaced = resolve_attack_technique("T1066", knowledge)
    assert replaced is not None
    assert replaced.technique_id == "T1027.005"
    assert replaced.status == "active"
    assert resolve_attack_technique("T9999.999", knowledge) is None


def test_structured_mapping_uses_official_technique_name() -> None:
    claim = SimpleNamespace(
        id="claim-1",
        module="decryption",
        subject="sample.exe",
        action="may_decode_or_decrypt",
        object="embedded data",
        mechanism="static crypto, encoding, or high-entropy indicators",
        condition="inferred from file content without execution",
        confidence="MEDIUM",
        status="CANDIDATE",
    )
    evidence = {
        "ev-1": SimpleNamespace(
            id="ev-1",
            task_id="task-1",
            kind="crypto_indicator",
            value={"algorithm": "AES"},
        )
    }

    mapped = map_behavior_claim(claim, ("ev-1",), evidence, task_id="task-1")[0]
    knowledge = resolve_attack_technique(mapped.technique_id)
    assert knowledge is not None
    assert mapped.technique_name == knowledge.name
    assert mapped.knowledge_status == "active"
    assert mapped.url
    assert mapped.tactics
    assert mapped.detection_strategies

