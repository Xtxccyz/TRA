from __future__ import annotations

import base64

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, ToolRun
from threat_report_agent.service import AnalysisService


def _apc_injection_ghidra_output() -> dict[str, object]:
    """Same-artifact call-graph: resolver then QueueUserAPC.

    That is an injection-category chain, not cross-address-space injection.
    """
    return {
        "functions": [
            {
                "name": "FUN_resolve",
                "entry": "140001000",
                "entry_rva": 4096,
                "signature": "void FUN_resolve(void)",
                "mnemonics": ["CALL", "CALL", "RET"],
                "instructions": [],
                "references_from": [
                    {
                        "from": "140001001",
                        "to": "KERNEL32!GetProcAddress",
                        "type": "CALL",
                        "target_name": "GetProcAddress",
                    },
                    {
                        "from": "140001010",
                        "to": "140002000",
                        "type": "CALL",
                        "target_function": "FUN_apc",
                    },
                ],
                "xrefs_to_entry": [],
                "cfg_blocks": [],
            },
            {
                "name": "FUN_apc",
                "entry": "140002000",
                "entry_rva": 8192,
                "signature": "void FUN_apc(void)",
                "mnemonics": ["CALL", "RET"],
                "instructions": [],
                "references_from": [
                    {
                        "from": "140002001",
                        "to": "KERNEL32!QueueUserAPC",
                        "type": "CALL",
                        "target_name": "QueueUserAPC",
                    },
                ],
                "xrefs_to_entry": [],
                "cfg_blocks": [],
            },
        ],
        "symbols": [],
    }


def _record_ghidra_on_single_artifact(
    test_settings, output: dict[str, object]
) -> tuple[AnalysisService, str]:
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("injects self-loop")
    stored = store.put(b"MZ static fixture")
    with database.session_factory.begin() as session:
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="resume.dll",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        tool_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
            parameters={},
            environment={"sample_execution": False},
            output=output,
        )
        session.add(tool_run)
        session.flush()
        service.record_ghidra_evidence(session, task, artifact, tool_run, output)
        task_id = task.id
    return service, task_id


def test_same_artifact_injection_chain_does_not_mint_self_injects(
    test_settings,
) -> None:
    service, task_id = _record_ghidra_on_single_artifact(
        test_settings, _apc_injection_ghidra_output()
    )
    task = service.task_view(task_id)

    candidate_chains = [
        item
        for item in task["claims"]
        if item["claim_type"] == "CROSS_FUNCTION_MECHANISM"
        and item["action"] == "exhibits_cross_function_chain"
        and item["status"] == "CANDIDATE"
        and "injection" in str(item["object"]).casefold()
    ]
    assert candidate_chains, "injection-category chain may remain a CANDIDATE Claim"

    self_injects = [
        item
        for item in task["relations"]
        if item["relation_type"] == "INJECTS"
        and item["source_artifact_id"] == item["target_artifact_id"]
    ]
    assert self_injects == []
    assert not any(item["relation_type"] == "INJECTS" for item in task["relations"])


def test_add_component_relation_rejects_behavioral_self_loop(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("behavioral self-loop API")
    result = service.analyze_submission(
        case_id=case.id, filename="sample.py", content=b"print(1)"
    )
    task = service.task_view(result.task_id)
    artifact_id = task["artifacts"][0]["id"]
    claim_id = task["claims"][0]["id"]
    for relation_type in ("INJECTS", "LOADS", "EXECUTES", "DECRYPTS"):
        with pytest.raises(ValueError, match="same Artifact"):
            service.add_component_relation(
                task_id=result.task_id,
                source_artifact_id=artifact_id,
                target_artifact_id=artifact_id,
                relation_type=relation_type,
                claim_id=claim_id,
            )


def test_add_component_relation_allows_injects_to_distinct_artifact(test_settings) -> None:
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("distinct injects target")
    encoded = base64.b64encode(b"VirtualAlloc LoadLibraryA " * 8).decode()
    result = service.analyze_submission(
        case_id=case.id,
        filename="loader.py",
        content=f"import base64\npayload='{encoded}'\nVirtualAlloc\n".encode(),
    )
    task = service.task_view(result.task_id)
    artifact_ids = [item["id"] for item in task["artifacts"]]
    assert len(artifact_ids) >= 2
    source_id, target_id = artifact_ids[0], artifact_ids[1]
    claim_id = task["claims"][0]["id"]
    created = service.add_component_relation(
        task_id=result.task_id,
        source_artifact_id=source_id,
        target_artifact_id=target_id,
        relation_type="INJECTS",
        claim_id=claim_id,
    )
    assert created["relation_type"] == "INJECTS"
    assert created["status"] == "INFERRED"


def test_same_artifact_cross_function_chain_keeps_claim_without_behavioral_self_edges(
    test_settings,
) -> None:
    service, task_id = _record_ghidra_on_single_artifact(
        test_settings, _apc_injection_ghidra_output()
    )
    task = service.task_view(task_id)
    assert any(
        item["claim_type"] == "CROSS_FUNCTION_MECHANISM" and item["status"] == "CANDIDATE"
        for item in task["claims"]
    )
    behavioral = {"LOADS", "DECRYPTS", "EXECUTES", "INJECTS"}
    assert [
        item
        for item in task["relations"]
        if item["relation_type"] in behavioral
        and item["source_artifact_id"] == item["target_artifact_id"]
    ] == []
