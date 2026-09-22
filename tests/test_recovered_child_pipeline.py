from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, Relation, ToolRun
from threat_report_agent.service import AnalysisService


def test_recovered_child_gets_drops_and_static_facts(test_settings) -> None:
    """B10: recovered bytes become a child with DROPS and parser facts, not a blob-only sidecar."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("recovered child pipeline")
    payload = b"MZ" + (b"\x00" * 64) + b"decoded-child-body"
    with database.session_factory.begin() as session:
        stored = store.put(b"parent-bytes")
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        parent = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="parent.bin",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(parent)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=parent.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        child_id = service._materialize_recovered_bytes_child(
            session,
            task,
            parent,
            run,
            payload,
            source="verified_static_data",
            anchor={"function_entry": "0x401000"},
        )
        task_id = task.id
        parent_id = parent.id

    assert child_id
    with database.session_factory() as session:
        relations = {
            str(item)
            for item in session.scalars(
                select(Relation.relation_type).where(
                    Relation.task_id == task_id,
                    Relation.source_artifact_id == parent_id,
                    Relation.target_artifact_id == child_id,
                )
            )
        }
        assert "EXTRACTED_FROM" in relations
        assert "DROPS" in relations
        child_facts = list(
            session.scalars(
                select(Evidence).where(Evidence.task_id == task_id, Evidence.artifact_id == child_id)
            )
        )
        assert child_facts, "recovered child must receive static parser facts"
        parent_impact = [
            row
            for row in session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == parent_id,
                    Evidence.kind == "mechanism_chain",
                )
            )
            if isinstance(row.value, dict) and row.value.get("child_artifact_id") == child_id
        ]
        assert parent_impact, "parent must record recovered-child static impact"
        assert parent_impact[0].value.get("child_fact_kinds")
        assert parent_impact[0].value.get("child_sha256")
        unpacked = [
            row
            for row in session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == parent_id,
                    Evidence.kind == "unpacked_payload",
                )
            )
        ]
        assert unpacked, "parent must record reconstructed IAT so stub suppression can lift"


def test_emulation_recovered_child_is_emulation_observed_not_runtime(test_settings) -> None:
    """C6: emu child bytes stay EMULATION_OBSERVED; execution=False; not DYNAMIC/已运行."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("emu recovered child")
    payload = b"MZ" + (b"\x00" * 64) + b"emu-xor-output"
    with database.session_factory.begin() as session:
        stored = store.put(b"parent-emu")
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        parent = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="parent.bin",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(parent)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=parent.id,
            tool_name="controlled-emulation",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        child_id = service._materialize_recovered_bytes_child(
            session,
            task,
            parent,
            run,
            payload,
            source="controlled_emulation",
            anchor={"simulator": "unicorn"},
        )
        task_id = task.id
        parent_id = parent.id

    assert child_id
    with database.session_factory() as session:
        child = session.get(Artifact, child_id)
        assert child is not None
        assert child.role == "DECODED_PAYLOAD"
        assert child.metadata_json.get("execution") is False
        decoded = [
            row
            for row in session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.artifact_id == parent_id,
                    Evidence.kind == "decoded_artifact",
                )
            )
            if isinstance(row.value, dict) and row.value.get("child_artifact_id") == child_id
        ]
        assert decoded
        assert decoded[0].nature == "EMULATION_OBSERVED"
        blob = " ".join(
            str(item.value) for item in decoded
        ).casefold()
        assert "dynamic" not in blob
        assert "already ran" not in blob


def test_short_xor_output_does_not_materialize_child(test_settings) -> None:
    """C6: 9-byte Unicorn XOR transform is buffer_output, not a decoded child PE."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("short xor child")
    with database.session_factory.begin() as session:
        stored = store.put(b"parent-short")
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        parent = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="parent.bin",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(parent)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=parent.id,
            tool_name="controlled-emulation",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        child_id = service._materialize_recovered_bytes_child(
            session,
            task,
            parent,
            run,
            bytes.fromhex("80350100000055c347"),
            source="controlled_emulation",
            anchor={"simulator": "unicorn"},
        )

    assert child_id is None
