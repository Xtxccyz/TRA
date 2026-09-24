"""The Ghidra function ceiling must not cull a realistic recovered corpus.

The former 96-function page analysed a signal-ranked subset and silently
dropped mechanisms living in the unranked tail.  These tests pin the new
contract: with a ceiling that clears the corpus, every recovered row is kept,
the pinned rows still order ahead of the ranked pool, and the coverage ratio
is observable even when nothing was culled.
"""

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
from threat_report_agent.service import AnalysisService

_CEILING = AnalysisService._MAX_GHIDRA_FUNCTIONS


def _crt_entry_row() -> dict[str, object]:
    """PE AddressOfEntryPoint body: has no API signal, so ranking buries it."""
    return {
        "name": "CRTStartup",
        "entry": "0x140001420",
        "entry_rva": 0x1420,
        "references_from": [{"type": "call", "target_name": "__security_init_cookie"}],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["call"],
    }


def _noise_row(index: int) -> dict[str, object]:
    """A row that outranks everything: many signal APIs, xrefs, calls and blocks."""
    return {
        "name": f"helper_{index}",
        "entry": hex(0x2000 + index),
        "entry_rva": 0x2000 + index,
        "references_from": [
            {"type": "call", "target_name": "CreateProcessW"},
            {"type": "call", "target_name": "VirtualAlloc"},
            {"type": "call", "target_name": "InternetConnectW"},
            {"type": "call", "target_name": "CryptDecrypt"},
        ],
        "xrefs_to_entry": [1, 2, 3, 4],
        "cfg_blocks": [{"id": 1}, {"id": 2}, {"id": 3}],
        "mnemonics": ["mov", "lea", "call", "ret"],
    }


def test_selection_keeps_every_row_when_budget_clears_the_corpus() -> None:
    """`remaining = max(0, budget - len(selected))` must not drop the tail."""
    rows = [_crt_entry_row(), *[_noise_row(index) for index in range(607)]]
    assert len(rows) == 608  # the 551KB Rust PE recovered 703; scale stands in

    selected = AnalysisService.select_ghidra_function_rows(
        rows,
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=_CEILING,
    )

    assert len(selected) == len(rows)
    assert {id(item) for item in selected} == {id(item) for item in rows}


def test_selection_keeps_every_row_at_the_exact_budget_boundary() -> None:
    """budget == len(all_rows) is the tightest no-cull case."""
    rows = [_crt_entry_row(), *[_noise_row(index) for index in range(99)]]

    selected = AnalysisService.select_ghidra_function_rows(
        rows,
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=len(rows),
    )

    assert len(selected) == len(rows)
    assert {id(item) for item in selected} == {id(item) for item in rows}


def test_pinned_rows_still_sort_ahead_of_the_ranked_pool() -> None:
    """PE entry, thread-start and data-xref pins keep their leading order."""
    crt = _crt_entry_row()
    creator = {
        "name": "FUN_1400440b9",
        "entry": "0x1400440b9",
        "entry_rva": 0x440B9,
        "references_from": [{"type": "call", "target_name": "CreateThread"}],
        "xrefs_to_entry": [1],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["lea", "call"],
        "instructions": [
            {"address": "0x1400440b0", "text": "LEA R8,[0x140038ae0]"},
            {"address": "0x1400440b9", "text": "CALL CreateThread"},
        ],
    }
    start = {
        "name": "FUN_140038ae0",
        "entry": "0x140038ae0",
        "entry_rva": 0x38AE0,
        "references_from": [
            {"type": "call", "target_name": "WaitForSingleObject"},
            {"type": "call", "target_name": "ExitThread"},
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [{"id": 1}],
        "mnemonics": ["call"],
        "instructions": [
            {"text": "CALL WaitForSingleObject"},
            {"text": "CALL ExitThread"},
        ],
    }
    consumer = {
        "name": "use_decoded_url",
        "entry": "0x140003000",
        "entry_rva": 0x3000,
        "references_from": [
            {"type": "DATA", "from": "0x140003010", "to": "0x14004c8e1", "target_name": "DAT_14004c8e1"}
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["lea", "call"],
    }
    noise = [_noise_row(index) for index in range(50)]
    rows = [crt, creator, start, consumer, *noise]

    selected = AnalysisService.select_ghidra_function_rows(
        rows,
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=_CEILING,
        pin_data_addresses=(0x14004C8E1,),
    )

    # Nothing culled, but the pins are still front-loaded in a stable order.
    assert len(selected) == len(rows)
    order = [item.get("name") for item in selected]
    assert order.index("CRTStartup") < order.index("FUN_140038ae0")
    assert order.index("FUN_140038ae0") < order.index("use_decoded_url")
    # helper_0 carries the strongest signal and leads the ranked pool, yet the
    # three pins all precede it.
    assert order.index("use_decoded_url") < order.index("helper_0")


def test_pinned_rows_survive_even_a_collapsing_budget() -> None:
    """Ordering is a preference, so the pins must win a starved budget too."""
    crt = _crt_entry_row()
    consumer = {
        "name": "use_decoded_url",
        "entry": "0x140003000",
        "entry_rva": 0x3000,
        "references_from": [
            {"type": "DATA", "from": "0x140003010", "to": "0x14004c8e1", "target_name": "DAT_14004c8e1"}
        ],
        "xrefs_to_entry": [],
        "cfg_blocks": [],
        "mnemonics": ["lea", "call"],
    }
    rows = [crt, consumer, *[_noise_row(index) for index in range(50)]]

    selected = AnalysisService.select_ghidra_function_rows(
        rows,
        {"entry_rva": 0x1420, "image_base": 0x140000000},
        limit=2,
        pin_data_addresses=(0x14004C8E1,),
    )

    assert [item.get("name") for item in selected] == ["CRTStartup", "use_decoded_url"]


def _budget_evidence_after_recording(
    test_settings, output: dict[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("ghidra function ceiling")
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
            logical_path="fixture.exe",
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
        session.flush()
        rows = list(
            session.query(Evidence).filter(
                Evidence.task_id == task.id,
                Evidence.kind == "ghidra_function_budget",
            )
        )
    assert len(rows) == 1, "the coverage ratio must be observable, never absent"
    return rows[0].value, rows[0].anchor


def test_budget_evidence_reports_full_coverage_when_nothing_is_culled(
    test_settings,
) -> None:
    """processed_functions == total_functions tells a reader no cull happened."""
    functions = [_crt_entry_row(), _noise_row(0), _noise_row(1)]
    value, anchor = _budget_evidence_after_recording(
        test_settings, {"functions": functions, "symbols": []}
    )

    assert value["total_functions"] == len(functions)
    assert value["processed_functions"] == len(functions)
    assert value["processed_functions"] == value["total_functions"]
    assert value["selection"] == "pe_entry_pinned_signal_xref_call_cfg_rank"
    # Existing keys must not be dropped just because nothing was culled.
    assert "pinned_entry_rva" in value
    assert "pinned_config_xrefs" in value
    assert anchor["type"] == "ghidra_postprocess_budget"


def test_budget_evidence_is_emitted_for_a_single_function_corpus(
    test_settings,
) -> None:
    """A degenerate one-function corpus still records 1/1 coverage."""
    value, _ = _budget_evidence_after_recording(
        test_settings, {"functions": [_crt_entry_row()], "symbols": []}
    )

    assert value["total_functions"] == 1
    assert value["processed_functions"] == 1
