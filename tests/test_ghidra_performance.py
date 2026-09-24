import time
from types import SimpleNamespace
from unittest.mock import Mock

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
from threat_report_agent.service import AnalysisService
from threat_report_agent.static_analysis import StaticFact, analyze_bytes


def test_behavior_claim_validation_is_bounded(test_settings) -> None:
    service = AnalysisService(
        test_settings, Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    session = Mock()
    service._infer_component_relations = Mock()
    service._audit = Mock()
    service._record_ghidra_behavior_claims(
        session,
        SimpleNamespace(id='task', case_id='case'),
        SimpleNamespace(logical_path='sample.exe'),
        {'name': 'entry', 'entry': '0x1000',
         'references_from': [{'target_name': 'CreateProcessW'}]},
        ('evidence-1',),
    )
    session.scalars.assert_not_called()


def test_ghidra_similarity_filter_uses_processed_function_budget(test_settings) -> None:
    """Unselected exporter functions must not enter the similarity index."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("bounded ghidra similarity")
    stored = store.put(b"static fixture")
    with database.session_factory.begin() as session:
        session.add(ContentBlob(
            sha256=stored.sha256,
            size=stored.size,
            media_type="application/octet-stream",
            storage_key=stored.storage_key,
        ))
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="fixture.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        source_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="ghidra-headless",
            tool_version="test",
            status="SUCCEEDED",
            parameters={},
            environment={"sample_execution": False},
        )
        session.add(source_run)
        session.flush()
        source_evidence_ids = {}
        for entry, value in (("0x401000", "44e0cbb281dca986"), ("0x402000", "44e0cbb281dca986")):
            evidence = Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=source_run.id,
                module="static_triage",
                kind="function_simhash",
                nature="STATIC_OBSERVED",
                value={
                    "value": value,
                        "algorithm": "charikar-simhash-64",
                        "feature": "mnemonic-4gram",
                        "hash": "md5-prefix-64-le",
                },
                anchor={"entry": entry},
            )
            session.add(evidence)
            session.flush()
            source_evidence_ids[entry] = evidence.id
        session.flush()
        service.record_function_similarity(
            session,
            task,
            artifact,
            source_run,
            processed_function_entries={"0x401000"},
        )
        similarity_rows = list(session.query(Evidence).filter(
            Evidence.task_id == task.id,
            Evidence.kind == "function_similarity",
        ))
    assert similarity_rows
    assert {
        row.value["source_evidence_id"] for row in similarity_rows
    } == {source_evidence_ids["0x401000"]}


def test_planner_history_bounds_large_evidence_id_lists() -> None:
    actions = [{
        "action_key": "artifact:pe-parser",
        "new_evidence_count": 5000,
        "new_evidence_ids": [f"evidence-{index}" for index in range(5000)],
    }]
    bounded = AnalysisService._bound_completed_actions(actions)
    assert len(bounded) == 1
    assert len(bounded[0]["new_evidence_ids"]) == AnalysisService._MAX_COMPLETED_ACTION_EVIDENCE_IDS
    assert bounded[0]["new_evidence_count"] == 5000
    assert bounded[0]["new_evidence_ids_truncated"] == 5000 - AnalysisService._MAX_COMPLETED_ACTION_EVIDENCE_IDS


def test_ghidra_function_budget_is_bounded_for_large_outputs() -> None:
    """The ceiling is a degenerate-input guard, not an analysis quota.

    It must clear every realistic recovered corpus (the largest seen live is
    3455 functions) so the unranked tail is still analysed, while staying a
    finite, greppable, tunable bound.
    """
    assert AnalysisService._MAX_GHIDRA_FUNCTIONS >= 4096
    assert AnalysisService._MAX_GHIDRA_FUNCTIONS <= 1_000_000
    assert AnalysisService._MAX_GHIDRA_FUNCTIONS % 2 == 0
    assert AnalysisService._MAX_GHIDRA_CALL_EVIDENCE_PER_FUNCTION <= 32
    assert AnalysisService._MAX_GHIDRA_XREF_EVIDENCE_PER_FUNCTION <= 16
    assert AnalysisService._MAX_GHIDRA_CFG_EVIDENCE_PER_FUNCTION <= 16


def test_static_indicator_scan_stays_fast_on_string_heavy_input() -> None:
    """The bounded string triage path should not rebuild term regexes per row."""
    content = (b"GetProcAddress VirtualAlloc IsDebuggerPresent "
               b"https://example.invalid/stage\x00") * 10_000

    started = time.perf_counter()
    result = analyze_bytes(content, "synthetic.bin")
    elapsed = time.perf_counter() - started

    # The parser intentionally caps emitted strings at its 5,000-row budget.
    assert result.summary["string_count"] == 5_000
    # Keep the guard generous enough for a slower CI worker while still
    # catching accidental reintroduction of per-term regex compilation.
    assert elapsed < 2.0


def test_static_result_anchor_recovery_scales_with_derived_facts(test_settings) -> None:
    """Large derived batches should use the anchor index instead of O(n^2) scans."""
    database = Database(test_settings.database_url)
    service = AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    database.create_schema()
    case = service.create_case("anchor recovery performance")
    service._audit = Mock()
    with database.session_factory.begin() as session:
        blob = ContentBlob(
            sha256="a" * 64,
            size=1,
            media_type="application/octet-stream",
            storage_key="sha256/anchor-recovery",
        )
        session.add(blob)
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING", strategy_snapshot={})
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=blob.sha256,
            logical_path="anchor-heavy.bin",
            detected_type="binary",
        )
        session.add(artifact)
        session.flush()
        run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="builtin-static-analyzer",
            tool_version="test",
            status="SUCCEEDED",
        )
        session.add(run)
        session.flush()
        facts = []
        for index in range(1_000):
            anchor = {"type": "file_offset", "offset": index}
            facts.append(StaticFact("static_triage", "raw_observation", {"n": index}, anchor))
            facts.append(StaticFact("static_triage", "string_semantics", {"n": index}, anchor))
        started = time.perf_counter()
        service._record_static_result(
            session,
            task,
            artifact,
            run,
            SimpleNamespace(facts=tuple(facts), limitations=()),
        )
        elapsed = time.perf_counter() - started

    assert elapsed < 2.0


def test_report_projection_bounds_large_evidence_and_keeps_references() -> None:
    rows = [
        {"id": f"string-{index}", "kind": "string", "value": {"text": "noise"}}
        for index in range(10000)
    ]
    rows.append({"id": "critical-link", "kind": "resolved_api", "value": {"api_name": "WinHttpOpen"}})
    selected = AnalysisService._select_report_evidence_rows(
        rows,
        referenced_ids={"critical-link"},
        limit=128,
    )
    assert len(selected) == 128
    assert any(item["id"] == "critical-link" for item in selected)
    assert len({item["id"] for item in selected}) == 128


def test_report_projection_keeps_simulation_result_when_claim_links_fill_limit() -> None:
    rows = [
        {"id": f"linked-{index}", "kind": "string", "value": {"text": "cited"}}
        for index in range(400)
    ]
    rows.append(
        {
            "id": "emu-1",
            "kind": "simulation_result",
            "value": {"status": "SUCCEEDED", "simulator": "speakeasy"},
        }
    )
    rows.append(
        {
            "id": "crypto-how",
            "kind": "function_semantic_summary",
            "value": {"function": "FUN_180038af8", "call_sequence": [{"api": "CryptAcquireContextW"}]},
        }
    )
    selected = AnalysisService._select_report_evidence_rows(
        rows,
        referenced_ids={f"linked-{index}" for index in range(400)},
        limit=128,
    )
    kinds = {item["id"]: item["kind"] for item in selected}
    assert "emu-1" in kinds
    assert "crypto-how" in kinds
    assert len(selected) == 128


def test_report_projection_prefers_crypto_semantic_summaries_inside_cap() -> None:
    rows = [
        {
            "id": f"sleep-{index}",
            "kind": "function_semantic_summary",
            "value": {"function": f"FUN_{index:08x}", "call_sequence": [{"api": "Sleep"}]},
        }
        for index in range(400)
    ]
    rows.append(
        {
            "id": "zzz-crypto-tail",
            "kind": "function_semantic_summary",
            "value": {
                "function": "FUN_180038af8",
                "call_sequence": [{"api": "CryptGenKey", "arguments": [{"name": "Algid", "value": "0x6801"}]}],
            },
        }
    )
    selected = AnalysisService._select_report_evidence_rows(
        rows, referenced_ids=set(), limit=128
    )
    assert any(item["id"] == "zzz-crypto-tail" for item in selected)


def test_report_projection_prioritizes_unlinked_decode_results() -> None:
    rows = [
        {"id": f"string-{index}", "kind": "string", "value": {"text": "noise"}}
        for index in range(10000)
    ]
    rows.append({
        "id": "decode-result", "kind": "decode_result",
        "value": {"verification_status": "VERIFIED_STATIC_DATA"},
    })
    selected = AnalysisService._select_report_evidence_rows(
        rows, referenced_ids=set(), limit=128
    )
    assert any(item["id"] == "decode-result" for item in selected)
