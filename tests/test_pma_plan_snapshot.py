from __future__ import annotations

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
from threat_report_agent.report.reporting import STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY
from threat_report_agent.service import AnalysisService


def test_persist_pma_plan_on_packed_pe_snapshot(test_settings) -> None:
    """Live investigation snapshot carries packer latch and unpack UNKNOWN."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("pma packed plan snapshot")
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="a" * 64,
            size=4,
            media_type="application/octet-stream",
            storage_key="sha256/pma-packed-plan",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(
            case_id=case.id,
            lifecycle="RUNNING",
            strategy_snapshot={"investigation": {"threads": []}},
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="packed.exe",
            detected_type="pe",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="pe-parser",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="parser",
                kind="file_identity",
                nature="STATIC_OBSERVED",
                value={
                    "md5": "0123456789abcdef0123456789abcdef",
                    "sha1": "0123456789abcdef0123456789abcdef01234567",
                    "sha256": "ab" * 32,
                },
                anchor={"type": "file"},
            )
        )
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="parser",
                kind="pe_structure",
                nature="STATIC_OBSERVED",
                value={
                    "entry_rva": 0x1000,
                    "imports": [
                        {
                            "module": "KERNEL32.dll",
                            "functions": [
                                "LoadLibraryA",
                                "GetProcAddress",
                                "VirtualAlloc",
                                "VirtualProtect",
                            ],
                        }
                    ],
                    "sections": [
                        {
                            "name": "UPX0",
                            "virtual_size": 0x20000,
                            "raw_size": 0,
                        }
                    ],
                },
                anchor={"type": "file_offset", "offset": 0x80},
            )
        )
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=run.id,
                module="parser",
                kind="import_symbol",
                nature="STATIC_OBSERVED",
                value={"name": "LoadLibraryA", "library": "KERNEL32.dll"},
                anchor={"type": "pe_import"},
            )
        )
        session.flush()
        plan = service._persist_pma_static_analysis_plan(session, task)
        session.flush()
        persisted = session.get(AnalysisTask, task.id)
        investigation = (persisted.strategy_snapshot or {}).get("investigation") or {}
        snapshot = investigation.get(STATIC_ANALYSIS_PLAN_SNAPSHOT_KEY) or {}

    assert plan["packer_latch"] is True
    assert snapshot["packer_latch"] is True
    items = snapshot["items"]
    unpack = next(item for item in items if item["kind"] == "unpack")
    assert unpack["status"] == "UNKNOWN"
    assert unpack["next_method"] in {"GET_DECOMPILE", "CONTROLLED_EMULATE"}
    assert any("OEP" in str(token) for token in unpack["unknowns"])
    assert not any(item.get("kind") in {"windows_object", "covert_launch", "iat"} for item in items)
    assert investigation.get("threads") == []
