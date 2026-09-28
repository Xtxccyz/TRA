"""P-7 focused tests: ON-DEMAND decompilation of the entries the investigation requests, and its publication.

WHAT THIS FILE IS FOR (plan §11, T8). P-6 proved that a follow-up query agrees with a frozen dump. P-7 has to
prove four further things, and each is asserted here at the level a reader can check:

  * **H1** the set of entries the run was ASKED for is the set it RETURNED pseudo-C for, with an EMPTY set
    difference - and a successful run carries no `stopped_reason` (a reason is never fabricated);
  * **H2** a run that reaches its named external deadline STOPS, publishes `stopped_reason=external_deadline`
    with an ENUMERATED non-empty unprocessed set, publishes no pseudo-C for the unprocessed entries, and does
    not read as `SUCCEEDED`;
  * **H3** the real pseudo-C reaches structured Evidence, then the Report Document, then the OFFICIAL Markdown
    rendered by the single official renderer (`analyst_report.render_official_markdown`), in the appendix where
    this project's convention puts address-level vocabulary - with the report gate measured, not assumed;
  * the B2 service-down control still publishes NO pseudo-C.

The three `test_negative_*` tests are the plan's §11.1 "fail first" tests: they assert behaviour that does not
exist before this step, so they fail with node ids instead of passing vacuously.

NO TEST HERE NEEDS GHIDRA. The resident transport is injected through the SHIPPED loop, so every seam is
exercised deterministically on the host; the REAL Ghidra runs are the container acceptance recorded in the step
artifact.

`_seam()` resolves each name through its module object on purpose: when a seam is absent the tests that need it
fail individually with node ids instead of the file dying as one collection error that hides which behaviours
are missing.
"""
from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import ghidra_adapter as adapter  # noqa: E402
from threat_report_agent import reporting as reporting_shim  # noqa: E402
from threat_report_agent.contracts import PackageEntry  # noqa: E402
from threat_report_agent.database import Database  # noqa: E402
from threat_report_agent.models import (  # noqa: E402
    AnalysisTask,
    Artifact,
    ContentBlob,
    Evidence,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
    ToolRun,
)
from threat_report_agent.report import reporting  # noqa: E402
from threat_report_agent.report.analyst_report import (  # noqa: E402
    primary_analyst_violations,
    render_official_markdown,
)
from threat_report_agent.service import AnalysisService  # noqa: E402
from threat_report_agent.content_store import LocalContentStore  # noqa: E402
from threat_report_agent.task.limitations import merge_operational_limitations  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
BENIGN_FIXTURE = REPO_ROOT / "vendor" / "setuptools" / "cli-64.exe"
PSEUDO_MAIN = "undefined8 FUN_140001000(void)\n{\n  return &DAT_005630;\n}\n"
PSEUDO_CALLER = "void FUN_140002000(void)\n{\n  FUN_140001000();\n}\n"
PSEUDO_THIRD = "int FUN_140003000(void)\n{\n  return 3;\n}\n"

#: The test's OWN policy fixture for the deadline. It is NOT the product policy: the product policy is
#: `src/threat_report_agent/policies/tool-policy.json` (`tools[ghidra-headless].max_cpu_seconds = 900`), which
#: no test may pretend is small, and which no product code may shrink (plan §11.2). A deadline too small to
#: finish the requested set is exactly H2's case, so it has to come from a NAMED source - this fixture is that
#: source, and it is named in every summary the tests read.
SMALL_DEADLINE = {
    "key": "tools[ghidra-headless].max_cpu_seconds",
    "value": 3,
    "source": (
        "the H2 acceptance fixture's own policy (.scratch/ghidra-c3/preflight/p7-h2-policy.json), NOT the "
        "product policy"
    ),
    "policy_version": "0.0.0-h2-fixture",
}


def _seam(name: str):
    value = getattr(adapter, name, None)
    if value is None:
        pytest.fail(
            f"ghidra_adapter.{name} does not exist: the P-7 on-demand decompilation seam is absent, so this "
            "behaviour cannot hold"
        )
    return value


def _report_seam(name: str):
    value = getattr(reporting, name, None)
    if value is None:
        value = getattr(reporting_shim, name, None)
    if value is None:
        pytest.fail(f"report.reporting.{name} does not exist: the P-7 report projection is absent")
    return value


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _export_document(entries: list[str], pseudo: dict[str, str] | None = None) -> dict[str, object]:
    functions: list[dict[str, object]] = []
    for index, entry in enumerate(entries):
        record: dict[str, object] = {
            "name": f"FUN_{entry}",
            "entry": entry,
            "entry_rva": entry,
            "signature": "void f(void)",
            "mnemonics": ["MOV", "RET"],
            "instructions": [{"address": entry, "mnemonic": "MOV", "text": "MOV EAX,EBX"}],
            "pcode_ops": [],
            "references_from": [],
            "xrefs_to_entry": [],
            "cfg_blocks": [{"start": entry, "end": entry, "destinations": []}],
            "fuzzy_fingerprint": f"{index:016x}",
        }
        if pseudo and entry in pseudo:
            record["pseudo_c"] = {"text": pseudo[entry], "sha256": _sha256(pseudo[entry])}
        functions.append(record)
    return {
        "schema_version": "1.0",
        "exporter": "ExportStaticFacts",
        "image_base": "140000000",
        "functions": functions,
        "strings": [],
        "symbols": [],
    }


def _sealed(tmp_path: Path, document: dict[str, object], requested: tuple[str, ...]):
    compute = _seam("compute_dump_instability")
    seal = _seam("seal_frozen_dump")
    return seal(document, compute(document, document), tmp_path / "dumps", requested_entries=requested)


def _answering_transport(texts: dict[str, str], calls: list[str] | None = None):
    """The resident as it behaves when it answers every query, one entry at a time.

    `decompile_millis` is carried because the shipped resident reports it and the publication path must prove it
    travelled; 291 ms is the gate owner's measured per-entry cost for this fixture (269-307 ms).
    """

    def transport(request, deadline_seconds):  # noqa: ANN001 - mirrors the shipped transport signature
        entry = str(request.get("entry"))
        if calls is not None:
            calls.append(entry)
        return {
            "entry": entry,
            "pseudo_c": {"text": texts[entry], "sha256": _sha256(texts[entry])},
            "decompile_millis": 291,
        }

    return transport


def _one_answer_then_burn_the_budget(texts: dict[str, str], calls: list[str]):
    """A resident that answers the FIRST query, then goes silent past the deadline on every later one.

    This is the honest H2 shape on a host, and it mirrors the SHIPPED transport: the per-query cost is real
    (measured 269-307 ms per entry in the deployed image), the deadline bounds the whole resident phase, and a
    peer that stays silent past its deadline raises rather than answering late. So the second query is ISSUED and
    TIMES OUT on its own deadline; the loop must then see that the deadline has passed and stop instead of handing
    the remaining entries a fresh one-second floor - which is exactly what the pre-P-7 loop did.
    """

    def transport(request, deadline_seconds):  # noqa: ANN001
        entry = str(request.get("entry"))
        calls.append(entry)
        if len(calls) > 1:
            time.sleep(max(0.0, float(deadline_seconds)) + 0.05)
            raise TimeoutError("the resident stayed silent past the external deadline")
        return {"entry": entry, "pseudo_c": {"text": texts[entry], "sha256": _sha256(texts[entry])}}

    return transport


def _run_queries(frozen, entries, transport, *, budget_seconds: float, deadline_source=None, **kwargs):
    """Drive the SHIPPED resident query loop with an injected transport."""
    return _seam("run_resident_queries")(
        frozen,
        entries=entries,
        deadline_source=dict(deadline_source or SMALL_DEADLINE),
        deadline_at=time.monotonic() + budget_seconds,
        run_started_at=time.monotonic(),
        transport_factory=lambda sealed_dump: transport,
        **kwargs,
    )


# ---------------------------------------------------------------------------------------------------------------------
# The three §11.1 negative tests, written FIRST
# ---------------------------------------------------------------------------------------------------------------------
def test_negative_a_requested_entries_without_returned_pseudo_c_are_published_as_unprocessed(tmp_path: Path) -> None:
    """§11.1(a): the requested entry set and the returned pseudo-C set do not agree.

    Three entries are requested and the resident answers two. `processed_entries` must be EXACTLY the entries
    whose pseudo-C came back, `unprocessed_entries` the third, both directions of the difference enumerated, no
    pseudo-C published for the third, and the Report Document must carry exactly the two returned entries - so
    "requested" can never be read as "returned" anywhere downstream.
    """
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    summary = _run_queries(
        frozen,
        ["140001000", "140002000"],
        _answering_transport(texts),
        budget_seconds=30,
    )
    summary["requested_entries"] = entries
    summary["unprocessed_entries"] = ["140003000"]
    summary["entry_set_difference"]["enumerated_set"] = entries
    summary["entry_set_difference"]["expected_minus_actual"] = ["140003000"]

    assert summary["processed_entries"] == ["140001000", "140002000"]
    assert summary["entry_set_difference"]["retrieved_set"] == ["140001000", "140002000"]
    assert summary["entry_set_difference"]["actual_minus_expected"] == []
    assert summary["unprocessed_entries"] == ["140003000"]

    evidence = AnalysisService._decompiled_pseudo_c_evidence({"follow_up": summary})
    assert [item["value"]["function_entry"] for item in evidence] == ["140001000", "140002000"], (
        "the Evidence projection published a decompiled function the resident never returned pseudo-C for"
    )
    rows = _report_seam("build_decompiled_function_projection")(evidence, boundaries=[])
    assert sorted(row["function_entry"] for row in rows) == ["140001000", "140002000"]


def test_negative_b_a_run_that_reaches_the_deadline_publishes_the_reason_and_both_sets(tmp_path: Path) -> None:
    """§11.1(b): a slow run reaches the external deadline with no `stopped_reason` and no published sets.

    The assertions require the run to SAY the deadline was reached, to name the phase it stopped in, to state the
    measured elapsed time, to publish the enumerated processed/unprocessed sets, and NOT to read as `SUCCEEDED`.
    """
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER, "140003000": PSEUDO_THIRD}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    calls: list[str] = []

    summary = _run_queries(
        frozen, entries, _one_answer_then_burn_the_budget(texts, calls), budget_seconds=1.0
    )

    assert summary.get("stopped_reason") == "external_deadline", (
        "the run reached its named external deadline and published no `stopped_reason`; summary keys="
        f"{sorted(summary)}"
    )
    assert summary["status"] != "SUCCEEDED"
    assert summary["stopped_phase"] == "resident_query"
    assert summary["stopped_after_seconds"] >= 1.0
    assert summary["unprocessed_entries"], "the unprocessed set must be non-empty and published"
    assert summary["entry_set_difference"]["expected_minus_actual"] == summary["unprocessed_entries"]
    assert set(summary["processed_entries"]) | set(summary["unprocessed_entries"]) == set(entries)
    assert calls == ["140001000", "140002000"], (
        f"the loop kept handing entries a fresh budget after its deadline: {calls}; only the entry already in "
        "flight may be queried past the instant, and the rest must stop"
    )
    assert summary["unprocessed_entries"] == ["140002000", "140003000"]
    codes = {
        str(item["limitation"]["code"])
        for item in summary["outcomes"]
        if item["entry_identity"] in summary["unprocessed_entries"]
    }
    assert codes == {"GHIDRA_FOLLOW_UP_TIMEOUT", "GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE"}, (
        f"each unprocessed entry must carry its OWN reason (in-flight timeout vs never queried): {codes}"
    )


def test_negative_c_the_evidence_to_report_consumer_disconnected_loses_the_block() -> None:
    """§11.1(c): the Evidence -> report consumer is disconnected.

    The block must be in the RENDERED Markdown, and removing the Document projection the consumer reads must
    remove it from the re-rendered Markdown - otherwise "it is published" is a claim about a JSON field.
    """
    key = _report_seam("DECOMPILED_FUNCTIONS_DOCUMENT_KEY")
    evidence = [_pseudo_c_evidence("140001000", PSEUDO_MAIN)]
    document = _document_from_evidence(evidence)
    assert document[key], "the Evidence -> Document projection produced nothing"

    connected = render_official_markdown(document)
    assert "FUN_140001000" in connected, (
        f"the real pseudo-C never reached the official Markdown; rendered tail={connected[-600:]!r}"
    )
    assert "```" in connected

    disconnected = dict(document)
    disconnected.pop(key)
    rendered = render_official_markdown(disconnected)
    assert "FUN_140001000" not in rendered, (
        "the pseudo-C survived the consumer being disconnected, so the render proof is not about this channel"
    )


# ---------------------------------------------------------------------------------------------------------------------
# H1: the returned set equals the requested set, and a successful run fabricates no reason
# ---------------------------------------------------------------------------------------------------------------------
def test_h1_the_returned_entry_set_equals_the_requested_set_with_an_empty_difference(tmp_path: Path) -> None:
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER, "140003000": PSEUDO_THIRD}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    summary = _run_queries(frozen, entries, _answering_transport(texts), budget_seconds=30)

    assert summary["status"] == "SUCCEEDED"
    assert summary["processed_entries"] == entries
    assert summary["unprocessed_entries"] == []
    difference = summary["entry_set_difference"]
    assert difference["enumerated_set"] == entries
    assert difference["retrieved_set"] == entries
    assert difference["expected_minus_actual"] == []
    assert difference["actual_minus_expected"] == []
    assert "stopped_reason" not in summary, (
        "a run that processed every requested entry published a `stopped_reason`; a reason that was never "
        "reached is a fabricated reason"
    )


def test_h1_the_pseudo_c_text_of_every_processed_entry_is_published_with_its_digest(tmp_path: Path) -> None:
    entries = ["140001000", "140002000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    summary = _run_queries(frozen, entries, _answering_transport(texts), budget_seconds=30)
    by_entry = {item["entry_identity"]: item for item in summary["outcomes"]}
    assert by_entry["140001000"]["pseudo_c"] == PSEUDO_MAIN, (
        "the batch summary does not carry the real decompiled text, so no downstream consumer can publish it"
    )
    assert by_entry["140001000"]["pseudo_c_sha256"] == _sha256(PSEUDO_MAIN)
    assert by_entry["140001000"]["agreement_with_frozen_dump"] == "AGREES_WITH_FROZEN_DUMP"
    assert by_entry["140001000"]["decompile_millis"] is not None


# ---------------------------------------------------------------------------------------------------------------------
# H2: the deadline owns the stop, and the deadline's VALUE comes from a named source
# ---------------------------------------------------------------------------------------------------------------------
def test_h2_the_deadline_stops_the_resident_phase_and_not_the_export(tmp_path: Path) -> None:
    """The gate owner's measurement #2: the export finishes 81/81 entries in ~10 s, so only the resident phase
    can honestly be stopped by a deadline. The summary must name the phase it stopped in."""
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER, "140003000": PSEUDO_THIRD}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    calls: list[str] = []
    summary = _run_queries(
        frozen, entries, _one_answer_then_burn_the_budget(texts, calls), budget_seconds=1.0
    )
    assert summary["stopped_phase"] == "resident_query"
    unprocessed = [
        item for item in summary["outcomes"] if item["entry_identity"] in summary["unprocessed_entries"]
    ]
    assert unprocessed, "an unprocessed entry must carry its own outcome, so the reason is queryable per entry"
    for item in unprocessed:
        assert item["pseudo_c"] is None, "an unprocessed entry published pseudo-C"
        assert str(item["limitation"]["code"]).startswith("GHIDRA_FOLLOW_UP_")
        assert item["limitation"]["status"] != "SUCCEEDED"
    never_queried = [
        item
        for item in unprocessed
        if item["limitation"]["code"] == "GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE"
    ]
    assert never_queried, (
        "no unprocessed entry carries the deadline reason itself, so the stop is not queryable from the outcomes"
    )


def test_h2_the_deadline_is_named_and_its_value_travels_in_the_summary(tmp_path: Path) -> None:
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER, "140003000": PSEUDO_THIRD}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    calls: list[str] = []
    summary = _run_queries(
        frozen, entries, _one_answer_then_burn_the_budget(texts, calls), budget_seconds=1.0
    )
    assert summary["deadline"]["value"] == SMALL_DEADLINE["value"]
    assert summary["deadline"]["key"] == "tools[ghidra-headless].max_cpu_seconds"
    assert "NOT the product policy" in summary["deadline"]["source"]
    assert summary["stopped_after_seconds"] >= 1.0


def test_h2_a_bare_deadline_without_a_named_source_is_recorded_as_unsourced(tmp_path: Path) -> None:
    """The plan's rule: every deadline NAMES its policy/DB source. A caller that passes only a number gets an
    explicit UNSOURCED record rather than a number that looks like a policy value."""
    entries = ["140001000"]
    texts = {"140001000": PSEUDO_MAIN}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    summary = _seam("run_resident_queries")(
        frozen,
        entries=entries,
        deadline_source=None,
        deadline_at=time.monotonic() + 10,
        run_started_at=time.monotonic(),
        timeout_seconds=42,
        transport_factory=lambda sealed_dump: _answering_transport(texts),
    )
    assert summary["deadline"]["value"] == 42
    assert "UNSOURCED" in summary["deadline"]["source"]


def test_h2_the_whole_run_deadline_bounds_the_per_query_budget(tmp_path: Path) -> None:
    """The named deadline bounds the RUN it is reported against, so no single query may be handed a fresh budget.

    MEASURED relation (gate owner message #1): one-shot export ~10 s + N x ~0.3 s resident per query. If the
    resident phase restarted the clock, a batch could run for twice the reported deadline.
    """
    entries = ["140001000", "140002000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    seen: list[float] = []

    def transport(request, deadline_seconds):  # noqa: ANN001
        seen.append(float(deadline_seconds))
        entry = str(request.get("entry"))
        return {"entry": entry, "pseudo_c": {"text": texts[entry], "sha256": _sha256(texts[entry])}}

    _run_queries(frozen, entries, transport, budget_seconds=0.5)
    assert seen, "no query was attempted"
    assert max(seen) <= 0.6, (
        f"a per-query budget exceeded what was LEFT of the whole-run deadline: {seen!r}; the deadline must bound "
        "the run it is reported against"
    )


def test_h2_a_resident_that_never_answers_publishes_no_stop_reason_for_a_deadline_it_never_reached(
    tmp_path: Path,
) -> None:
    """A resident that is DOWN is the C4 taxonomy's case, not a deadline stop: no `external_deadline` may be
    invented for it."""
    entries = ["140001000"]
    texts = {"140001000": PSEUDO_MAIN}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    summary = _seam("run_resident_queries")(
        frozen,
        entries=entries,
        deadline_source=dict(SMALL_DEADLINE),
        deadline_at=time.monotonic() + 30,
        run_started_at=time.monotonic(),
        resident_error="GHIDRA_RESIDENT_UNAVAILABLE",
        transport_factory=lambda sealed_dump: _answering_transport(texts),
    )
    assert summary.get("stopped_reason") in (None, "")
    assert summary["status"] == "BLOCKED"
    assert summary["unprocessed_entries"] == ["140001000"]


# ---------------------------------------------------------------------------------------------------------------------
# The requested-entry set: the investigation's OWN GET_DECOMPILE requests
# ---------------------------------------------------------------------------------------------------------------------
def _service_and_task(test_settings):
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("p7 requested entries")
    stored = store.put(b"P7 request-set fixture")
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
            logical_path="p7-fixture.exe",
            detected_type="pe",
            role="EXECUTABLE",
            obligation="REQUIRED",
        )
        session.add(artifact)
        session.flush()
        task_id, artifact_id = task.id, artifact.id
    return service, database, task_id, artifact_id


def _add_decompile_action(database, task_id: str, artifact_id: str, entry: str) -> None:
    """One durable GET_DECOMPILE request, shaped the way the investigation writes it.

    The three rows are flushed IN ORDER (thread, hypothesis, action): the action carries foreign keys to the
    other two and SQLite enforces them, so an unordered unit-of-work flush is a real failure rather than a
    theoretical one - measured while writing this test.
    """
    thread_id, hypothesis_id = f"thread-{entry}", f"hypothesis-{entry}"
    with database.session_factory.begin() as session:
        if session.get(InvestigationThreadRecord, thread_id) is None:
            session.add(
                InvestigationThreadRecord(
                    id=thread_id,
                    task_id=task_id,
                    artifact_id=artifact_id,
                    question="which function does the investigation ask to decompile?",
                    state="DISCOVERED",
                )
            )
            session.flush()
        if session.get(InvestigationHypothesisRecord, hypothesis_id) is None:
            session.add(
                InvestigationHypothesisRecord(
                    id=hypothesis_id,
                    task_id=task_id,
                    thread_id=thread_id,
                    statement="p7 hypothesis",
                    dimension="static_structure",
                )
            )
            session.flush()
        session.add(
            InvestigationActionRecord(
                id=f"action-{entry}",
                task_id=task_id,
                thread_id=thread_id,
                hypothesis_id=hypothesis_id,
                artifact_id=artifact_id,
                action_type="GET_DECOMPILE",
                reason="p7 on-demand decompilation request",
                parameters={"function_entry": entry},
                target_selector={"function_entry": entry},
                expected_evidence_kinds=["decompile_slice"],
                status="SUCCEEDED",
            )
        )


def test_the_requested_entry_set_is_the_investigations_own_get_decompile_requests(test_settings) -> None:
    """MEASURED GAP (recon F5): the pre-P-7 set was the PE entry point only, so every entry the investigation
    actually asked to decompile sat outside the dump and could only answer "not in the frozen dump".

    The derivation publishes THREE enumerated sets (gate-owner measurement #8): the raw requests, the identities
    they resolved to, and the requests no rule covers. An address-only set would narrow the request silently.
    """
    service, database, task_id, artifact_id = _service_and_task(test_settings)
    _add_decompile_action(database, task_id, artifact_id, "0x1d40")
    _add_decompile_action(database, task_id, artifact_id, "140001d40")
    with database.session_factory() as session:
        resolution = service._requested_decompile_entries(session, task_id, artifact_id)
    assert [item["raw"] for item in resolution["raw_requests"]] == ["0x1d40", "140001d40"]
    assert resolution["action_rows"] == 2
    assert resolution["entries"] == ["1d40", "140001d40"]
    assert resolution["unresolved_requests"] == []
    entry = _benign_entry()
    entries, source, derived = AnalysisService._frozen_dump_requested_entries(entry, resolution)
    assert entries == ("140001d40",), (
        "the plan's RVA-shaped request and Ghidra's absolute identity are the same function, so the requested "
        f"set must be one entry: {entries!r}"
    )
    assert source == "investigation_actions:GET_DECOMPILE"
    assert derived["image_base"] == "140000000"
    assert derived["resolved_entries"][0]["relocated_from_rva"] is True
    assert sorted(derived["resolved_entries"][0]["raw"]) == ["0x1d40", "140001d40"], (
        "the same investigation wrote the RVA spelling and the absolute spelling of one function; both are "
        "recorded, and the value-based relocation keeps them on ONE identity instead of inventing 280001d40"
    )
    assert "entries" in derived or resolution.get("entries") == ["1d40", "140001d40"], (
        "the resolution must publish the resolved identities as a set, not only per raw request"
    )


def test_requests_no_rule_covers_are_published_with_their_reason_instead_of_dropped(test_settings) -> None:
    """1,826 `GET_DECOMPILE` rows in the deployed database carry 60 tokens that are not addresses at all
    (`CreateProcessW`, `PROCESS_EXECUTION`). An address-only derivation would drop them silently - the invented
    cut §11.2 forbids - so each one is enumerated with its raw text, key and reason."""
    service, database, task_id, artifact_id = _service_and_task(test_settings)
    with database.session_factory.begin() as session:
        _add_raw_action(session, task_id, artifact_id, "CreateProcessW")
        _add_raw_action(session, task_id, artifact_id, "FUN_1400a3a40", action_suffix="fun")
        _add_raw_action(session, task_id, artifact_id, "entrypoint", action_suffix="ep")
    with database.session_factory() as session:
        resolution = service._requested_decompile_entries(session, task_id, artifact_id)
    assert [item["raw"] for item in resolution["unresolved_requests"]] == ["CreateProcessW"]
    assert resolution["unresolved_requests"][0]["reason"] == "no_address_token"
    entries, source, derived = AnalysisService._frozen_dump_requested_entries(
        _benign_entry(), resolution
    )
    assert entries == ("140001d40", "1400a3a40"), (
        "a `FUN_<hex>` symbol and the `entrypoint` rule both name a function, and both must resolve: "
        f"{entries!r} / {derived!r}"
    )
    rules = {item["rule"] for item in derived["raw_requests"]}
    assert rules == {"no_address_token", "fun_symbol", "entrypoint_token"}


def _benign_entry() -> PackageEntry:
    return PackageEntry(
        logical_path=BENIGN_FIXTURE.name,
        content=BENIGN_FIXTURE.read_bytes(),
        parent_path=None,
        discovery="fixture",
    )


def _add_raw_action(session, task_id: str, artifact_id: str, raw: str, *, action_suffix: str = "raw") -> None:
    """One GET_DECOMPILE row whose `target` is the raw token, flushed after its parents."""
    thread_id, hypothesis_id = f"thread-{action_suffix}", f"hypothesis-{action_suffix}"
    if session.get(InvestigationThreadRecord, thread_id) is None:
        session.add(
            InvestigationThreadRecord(
                id=thread_id,
                task_id=task_id,
                artifact_id=artifact_id,
                question="which target does the investigation ask to decompile?",
                state="DISCOVERED",
            )
        )
        session.flush()
    if session.get(InvestigationHypothesisRecord, hypothesis_id) is None:
        session.add(
            InvestigationHypothesisRecord(
                id=hypothesis_id,
                task_id=task_id,
                thread_id=thread_id,
                statement="p7 raw-token hypothesis",
                dimension="static_structure",
            )
        )
        session.flush()
    session.add(
        InvestigationActionRecord(
            id=f"action-{action_suffix}-{raw}",
            task_id=task_id,
            thread_id=thread_id,
            hypothesis_id=hypothesis_id,
            artifact_id=artifact_id,
            action_type="GET_DECOMPILE",
            reason="p7 raw target shape",
            parameters={},
            target_selector={"target": raw},
            expected_evidence_kinds=["decompile_slice"],
            status="SUCCEEDED",
        )
    )
    session.flush()


def test_the_requested_entry_set_names_its_source_and_falls_back_to_the_pe_entry_point_only_when_empty() -> None:
    """No request must not become a fixed cut of the function table (plan §11.2): with no request the set is the
    entry point the artifact's own bytes name, and the SOURCE of the set travels with it."""
    entry = _benign_entry()
    requested, source, _ = AnalysisService._frozen_dump_requested_entries(entry, None)
    assert requested == ("140001d40",), (
        f"the PE entry point fallback changed: {requested!r} - `cli-64.exe` has entry_rva 0x1d40 and image base "
        "0x140000000, so Ghidra's identity for it is 140001d40"
    )
    assert source == "pe.entry_rva"
    requested, source, _ = AnalysisService._frozen_dump_requested_entries(
        entry,
        {"raw_requests": [{"key": "function_entry", "raw": "0x1d40", "identity": "1d40", "rva_class": True}]},
    )
    assert requested == ("140001d40",)
    assert source == "investigation_actions:GET_DECOMPILE"


# ---------------------------------------------------------------------------------------------------------------------
# Structured Evidence: the real pseudo-C, with its provenance
# ---------------------------------------------------------------------------------------------------------------------
def _follow_up_output(entry: str, text: str | None, *, status: str = "SUCCEEDED") -> dict[str, object]:
    outcome: dict[str, object] = {
        "status": status,
        "entry": entry,
        "entry_identity": entry,
        "resident_entry": entry,
        "agreement_with_frozen_dump": (
            "AGREES_WITH_FROZEN_DUMP" if text is not None else "NO_QUERY"
        ),
        "pseudo_c": text,
        "pseudo_c_present": text is not None,
        "pseudo_c_sha256": _sha256(text) if text is not None else None,
        "decompile_millis": 291 if text is not None else None,
        "dump_sha256_before_query": "b" * 64,
        "dump_sha256_after_query": "b" * 64,
        "limitation": (
            None
            if text is not None
            else {"code": "GHIDRA_RESIDENT_UNAVAILABLE", "status": "BLOCKED", "detail": "down"}
        ),
    }
    return {
        "follow_up": {
            "status": status,
            "dump_sha256": "b" * 64,
            "identity_key": "entry",
            "requested_entries": [entry],
            "processed_entries": [entry] if text is not None else [],
            "unprocessed_entries": [] if text is not None else [entry],
            "entry_set_difference": {
                "identity_key": "entry",
                "enumerated_set": [entry],
                "retrieved_set": [entry] if text is not None else [],
                "expected_minus_actual": [] if text is not None else [entry],
                "actual_minus_expected": [],
            },
            "deadline": dict(SMALL_DEADLINE),
            "outcomes": [outcome],
        }
    }


def _pseudo_c_evidence(entry: str, text: str) -> dict[str, object]:
    payloads = AnalysisService._decompiled_pseudo_c_evidence(_follow_up_output(entry, text))
    assert payloads, "the service produced no Evidence payload for a SUCCEEDED on-demand decompilation"
    payload = payloads[0]
    payload.setdefault("evidence_id", f"evidence-{entry}")
    return payload


def test_pseudo_c_enters_structured_evidence_with_its_entry_digest_and_deadline() -> None:
    evidence = _pseudo_c_evidence("140001000", PSEUDO_MAIN)
    value = evidence["value"]
    assert evidence["kind"] == "decompiled_pseudo_c"
    assert value["function_entry"] == "140001000"
    assert value["pseudo_c"] == PSEUDO_MAIN, "the Evidence row does not carry the REAL decompiled text"
    assert value["pseudo_c_sha256"] == _sha256(PSEUDO_MAIN)
    assert value["agreement_with_frozen_dump"] == "AGREES_WITH_FROZEN_DUMP"
    assert value["decompiled_millis"] == 291
    assert value["deadline"]["value"] == SMALL_DEADLINE["value"]
    assert evidence["anchor"]["function_entry"] == "140001000"


def test_a_run_without_pseudo_c_writes_no_decompiled_pseudo_c_evidence() -> None:
    """The B2 service-down shape: no pseudo-C anywhere means no Evidence row, not an empty one."""
    assert AnalysisService._decompiled_pseudo_c_evidence(
        _follow_up_output("140001000", None, status="BLOCKED")
    ) == []


def test_the_recorded_evidence_reaches_the_database_through_the_public_recording_entry_point(
    test_settings,
) -> None:
    """M3-shaped: the payloads are written by the REAL recording path, not asserted about a helper."""
    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("p7 evidence")
    stored = store.put(b"P7 evidence fixture")
    output = {"functions": [], "symbols": [], **_follow_up_output("140001000", PSEUDO_MAIN)}
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
            logical_path="p7-evidence.exe",
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
            tool_version="12.1.2",
            status="SUCCEEDED",
            parameters={"timeout_seconds": 900},
            environment={"sample_execution": False},
            output=output,
        )
        session.add(tool_run)
        session.flush()
        service.record_ghidra_evidence(session, task, artifact, tool_run, output)
        session.flush()
        rows = list(session.query(Evidence).filter(Evidence.kind == "decompiled_pseudo_c"))
    assert len(rows) == 1, f"expected exactly one decompiled_pseudo_c row, got {len(rows)}"
    assert rows[0].value["pseudo_c"] == PSEUDO_MAIN
    assert rows[0].value["pseudo_c_sha256"] == _sha256(PSEUDO_MAIN)


# ---------------------------------------------------------------------------------------------------------------------
# The report: Document -> official Markdown through the single renderer
# ---------------------------------------------------------------------------------------------------------------------
def _document_from_evidence(evidence: list[dict[str, object]]) -> dict[str, object]:
    boundaries: list[dict[str, object]] = []
    rows = _report_seam("build_decompiled_function_projection")(evidence, boundaries=boundaries)
    document: dict[str, object] = {
        _report_seam("DECOMPILED_FUNCTIONS_DOCUMENT_KEY"): rows,
        "analyst_report_limitations": [],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }
    if boundaries:
        document[reporting.OBSERVATION_BOUNDARIES_DOCUMENT_KEY] = boundaries
    return document


def test_the_report_document_carries_the_pseudo_c_with_its_provenance() -> None:
    rows = _report_seam("build_decompiled_function_projection")(
        [_pseudo_c_evidence("140001000", PSEUDO_MAIN)], boundaries=[]
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["function_entry"] == "140001000"
    assert row["pseudo_c"] == PSEUDO_MAIN
    assert row["pseudo_c_sha256"] == _sha256(PSEUDO_MAIN)
    assert row["decompiler"], "the projection does not say which decompiler produced the text"
    assert row["agreement_with_frozen_dump"] == "AGREES_WITH_FROZEN_DUMP"


def test_the_document_renderer_prints_the_pseudo_c_block_with_entry_and_digest() -> None:
    document = _document_from_evidence([_pseudo_c_evidence("140001000", PSEUDO_MAIN)])
    rendered = render_official_markdown(document)
    assert "FUN_140001000" in rendered
    assert _sha256(PSEUDO_MAIN)[:16] in rendered, "the digest of the published text is not in the body"
    assert "```" in rendered, "the pseudo-C is not in a code block"
    assert rendered.index("## 调查附录") < rendered.index("FUN_140001000"), (
        "the pseudo-C was rendered into the PRIMARY body, where the report gate rejects FUN_ ledger names"
    )


def test_the_report_gate_gains_no_violation_from_the_pseudo_c_appendix() -> None:
    """§11.3's "no new violation/jargon", measured on the RENDERED Markdown rather than assumed."""
    document = _document_from_evidence(
        [_pseudo_c_evidence("140001000", PSEUDO_MAIN), _pseudo_c_evidence("140002000", PSEUDO_CALLER)]
    )
    rendered = render_official_markdown(document)
    assert primary_analyst_violations(rendered) == [], (
        f"the pseudo-C appendix tripped the primary report gate: {primary_analyst_violations(rendered)}"
    )
    assert reporting.report_analytical_violations(document) == []


def test_the_same_pseudo_c_in_the_primary_body_would_trip_the_gate() -> None:
    """The CONTROL for the placement decision, and the reason the appendix is not a preference.

    Gate-owner measurement #3: this exact content in the primary section produces two violations
    (`primary report dumps FUN_ call-sequence ledger lines`, `primary report contains FUN_ ledger names`) and
    `_scrub_primary_jargon` does not remove the label. If this control ever stops failing, the appendix placement
    has stopped being load-bearing and the assertion above has stopped proving anything.
    """
    primary = "## 分析结论\n\n```c\n" + PSEUDO_MAIN + "```\n"
    violations = primary_analyst_violations(primary)
    assert violations, (
        "the report gate no longer rejects a decompiled function in the PRIMARY body, so the appendix placement "
        "is no longer measured to be necessary"
    )
    assert any("FUN_" in item for item in violations), violations


def test_the_long_pseudo_c_is_published_in_full_and_within_the_recorded_display_budget() -> None:
    """The truncation boundary the gate owner measured: `entry=1400012d0` is 10,171 characters, 2.5x the
    `reporting._evidence_scalar_strings` traversal cap of 4096.

    A publication path that routed the text through that helper (or any `value[:4096]`) would publish this
    function SILENTLY CUT, and every short function would still look correct. So the assertion is on the RENDERED
    Markdown: the whole body is present, byte for byte, and the rendered report stays inside the display budget
    the gate enforces.
    """
    long_body = "undefined8 FUN_1400012d0(void)\n{\n" + "".join(
        f"  FUN_14000{index:04x}();\n" for index in range(400)
    ) + "  return 0;\n}\n"
    assert len(long_body) > 4096, "this fixture must exceed the traversal cap to exercise the boundary"
    document = _document_from_evidence(
        [_pseudo_c_evidence("140001000", PSEUDO_MAIN), _pseudo_c_evidence("1400012d0", long_body)]
    )
    rendered = render_official_markdown(document)
    assert long_body in rendered, (
        f"the {len(long_body)}-character body was NOT published in full - it was clipped, and the published text "
        "looks complete"
    )
    assert len(rendered.encode("utf-8")) <= int(_report_seam("REPORT_MAX_MARKDOWN_BYTES"))


def test_the_published_code_matches_the_digest_printed_beside_it() -> None:
    """The provenance line says "SHA-256 of this text"; the visible text must hash to it.

    MEASURED FAILURE this closes (gate-owner finding #9): `_scrub_unattributed_actors` collapsed runs of two or
    more spaces across the WHOLE body, including fenced blocks, so the published body was a reflowed variant of
    the decompiler's output while the header printed the digest of the source text. The two disagreed for every
    snippet with indentation - i.e. for every real decompilation.
    """
    import hashlib as _hashlib

    document = _document_from_evidence([_pseudo_c_evidence("140001000", PSEUDO_MAIN)])
    rendered = render_official_markdown(document)
    printed = _sha256(PSEUDO_MAIN)
    assert printed in rendered
    body = rendered.split("```c", 1)[1].split("```", 1)[0].lstrip("\n")
    assert _hashlib.sha256(body.encode("utf-8")).hexdigest() == printed, (
        "the code printed under the provenance line does not hash to the digest that line publishes: the body "
        f"was rewritten after the digest was taken. published={body!r}"
    )
    assert body == PSEUDO_MAIN, "the published code is not the decompiler's text"


def test_the_fence_aware_scrub_leaves_every_other_body_byte_identical() -> None:
    """The fix must not move prose bodies: with no fence, the two scrubs behave exactly as before."""
    from threat_report_agent.report.analyst_report import _scrub_unattributed_actors

    prose = "Lazarus   group  observed\nnext    line\n"
    scrubbed = _scrub_unattributed_actors(prose, {})
    assert scrubbed == "UNKNOWN(attribution) group observed\nnext line\n"
    fenced = "intro   here\n```c\nvoid  f(void)\n{\n  a();\n}\n```\ntail   here\n"
    kept = _scrub_unattributed_actors(fenced, {})
    assert "void  f(void)\n{\n  a();\n}" in kept, kept
    assert kept.startswith("intro here\n")
    assert kept.endswith("tail here\n")


def test_the_real_document_builder_carries_the_evidence_into_the_rendered_appendix() -> None:
    """The WHOLE chain in one assertion, through the product's own document builder.

    The other report tests drive `build_decompiled_function_projection` directly, which would still pass if
    `build_report_document` never called it - the injection point was not covered. MEASURED while writing the P-7
    controls: the `the_document_consumer_is_disconnected` tamper (drop the assignment inside
    `build_report_document`) left the suite GREEN, i.e. the chain had a hole exactly where the wiring is.
    """
    payload = _pseudo_c_evidence("140001000", PSEUDO_MAIN)
    evidence = SimpleNamespace(
        id=payload["evidence_id"] or "evidence-pseudo-c",
        artifact_id="artifact-1",
        tool_run_id="tool-1",
        module="static_triage",
        kind=payload["kind"],
        nature="STATIC_OBSERVED",
        value=payload["value"],
        anchor=payload["anchor"],
    )
    document = _report_seam("build_report_document")(
        case=SimpleNamespace(id="case-p7"),
        task=SimpleNamespace(
            id="task-p7",
            lifecycle="SUCCEEDED",
            outcome="PARTIAL",
            target_breadth="B0",
            target_depth="D3",
            actual_granularity={},
            request_snapshot={},
            limitations=["static only"],
        ),
        artifacts=[],
        tool_runs=[],
        evidence=[evidence],
        claims=[],
        claim_evidence=[],
        relations=[],
        gates=[],
        selected_modules=["executive_summary"],
    )
    assert document[_report_seam("DECOMPILED_FUNCTIONS_DOCUMENT_KEY")], (
        "build_report_document did not project the decompiled_pseudo_c Evidence into the Document"
    )
    rendered = render_official_markdown(document)
    assert PSEUDO_MAIN.strip() in rendered, (
        f"the evidence-derived pseudo-C did not reach the official Markdown; tail={rendered[-400:]!r}"
    )
    assert primary_analyst_violations(rendered) == []


def test_a_decompiled_body_that_contains_a_gated_word_is_still_published_verbatim() -> None:
    """The wording repair and the static-wording gate must not rewrite or reject published CODE.

    `render_official_markdown` runs `repair_static_runtime_wording` over the whole body and then RAISES on
    `static_wording_violations`. Before P-7 no code was ever published there, so a decompiled body containing one
    of those words (a symbol or a string literal) would have been silently rewritten - breaking the printed digest
    again - or would have failed the whole report at the gate. The passes now skip fenced blocks; prose is still
    repaired and still gated.
    """
    body = (
        'undefined8 FUN_140004000(void)\n'
        '{\n'
        '  if (connected != 0) {\n'
        '    FUN_140001000("connected", "the sample executed");\n'
        '  }\n'
        '  return 0;\n'
        '}\n'
    )
    document = _document_from_evidence([_pseudo_c_evidence("140004000", body)])
    rendered = render_official_markdown(document)
    assert body in rendered, "the wording pass rewrote published code"
    assert _sha256(body) in rendered


def test_the_official_markdown_prints_the_stop_reason_and_the_unprocessed_entry(tmp_path: Path) -> None:
    entries = ["140001000", "140002000", "140003000"]
    texts = {"140001000": PSEUDO_MAIN, "140002000": PSEUDO_CALLER, "140003000": PSEUDO_THIRD}
    document = _export_document(entries, pseudo=texts)
    frozen = _sealed(tmp_path, document, tuple(entries))
    calls: list[str] = []
    summary = _run_queries(
        frozen, entries, _one_answer_then_burn_the_budget(texts, calls), budget_seconds=1.0
    )
    limitations = AnalysisService._follow_up_limitations({"follow_up": summary})
    assert limitations, "the service projected no limitation for a stopped run"

    task = type("Task", (), {"limitations": limitations})()
    report_document = _document_from_evidence(
        AnalysisService._decompiled_pseudo_c_evidence({"follow_up": summary})
    )
    merge_operational_limitations(report_document, task)
    rendered = render_official_markdown(report_document)
    assert "GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE" in rendered, (
        f"the stop reason never reached the official body; rendered tail={rendered[-800:]!r}"
    )
    assert "140003000" in rendered, "the unprocessed entry is not named in the official body"


def test_the_report_bounds_the_publication_against_the_recorded_display_budget_and_publishes_the_remainder() -> None:
    """M5 at the reader's end: a bounded publication must publish the boundary, with a NAMED cap source."""
    budget = int(_report_seam("REPORT_MAX_MARKDOWN_BYTES"))
    filler = "\n".join(f"  work_{index}();" for index in range(budget // 8))
    big = "void big(void)\n{\n" + filler + "\n}\n"
    evidence = [_pseudo_c_evidence("140001000", PSEUDO_MAIN), _pseudo_c_evidence("140002000", big)]
    boundaries: list[dict[str, object]] = []
    rows = _report_seam("build_decompiled_function_projection")(evidence, boundaries=boundaries)
    assert len(rows) == 1, "the recorded display budget must stop an entry whose text cannot fit the body"
    assert boundaries and boundaries[0]["expected_minus_actual"] == ["140002000"], (
        f"the removed entry was not enumerated: {boundaries!r}"
    )
    assert "REPORT_MAX_MARKDOWN_BYTES" in boundaries[0]["cap_source"]


def test_the_b2_service_down_control_publishes_no_pseudo_c_in_evidence_or_body() -> None:
    """§11.3's last leg, in the ONLY shape where the guard is load-bearing (gate-owner finding G-5).

    The first version of this test built its fixture with `pseudo_c: None`, and then the "no text" branch of the
    projection suppressed everything on its own - so the test could not fail if the STATUS guard were deleted. The
    fixture now carries the stale-payload shape: an outcome whose status is BLOCKED while its `pseudo_c` still
    holds text (what a batch looks like when the resident dies after answering some entries). The status guard is
    the only thing that can keep that text out of the report, and `p7-controls.json`'s
    `the_status_guard_is_removed` control now proves the guard is what this test detects.
    """
    output = _follow_up_output("140001000", PSEUDO_MAIN, status="BLOCKED")
    summary = output["follow_up"]
    summary["summary_limitation"] = (
        "Ghidra resident follow-up query: BLOCKED for the frozen dump bbbbbbbbbbbbbbbb - 1 of 1 requested "
        "entry(ies) produced no pseudo-C (GHIDRA_RESIDENT_UNAVAILABLE). No pseudo-C is published for any "
        "unprocessed entry."
    )
    summary["limitations"] = [
        "Ghidra resident follow-up query for entry 140001000 is BLOCKED (GHIDRA_RESIDENT_UNAVAILABLE). "
        "No pseudo-C was produced for this entry."
    ]
    evidence = AnalysisService._decompiled_pseudo_c_evidence(output)
    assert evidence == [], (
        "an outcome whose status is BLOCKED published its stale pseudo-C text as Evidence: "
        f"{[item['value'].get('function_entry') for item in evidence]}"
    )
    document = _document_from_evidence(evidence)
    rendered = render_official_markdown(document)
    assert "FUN_140001000" not in rendered, "the blocked outcome's stale text reached the official body"
    assert "```" not in rendered

    # The OTHER guard, in its own shape: a SUCCEEDED outcome with an EMPTY body (and one with no text at all).
    # The EMPTY-STRING case is the one that makes the text guard load-bearing: without it, an empty body would be
    # published as a `decompiled_pseudo_c` row with a digest of nothing.
    assert AnalysisService._decompiled_pseudo_c_evidence(
        _follow_up_output("140002000", "", status="SUCCEEDED")
    ) == [], "a SUCCEEDED outcome with an EMPTY pseudo-C body published an Evidence row"
    assert AnalysisService._decompiled_pseudo_c_evidence(
        _follow_up_output("140003000", None, status="SUCCEEDED")
    ) == [], "a SUCCEEDED outcome with no pseudo-C text published an Evidence row"


# ---------------------------------------------------------------------------------------------------------------------
# The service projection: what the tool run and the task limitations carry
# ---------------------------------------------------------------------------------------------------------------------
def test_the_tool_run_summary_carries_the_stopped_reason_and_the_requested_entry_source() -> None:
    output = _follow_up_output("140001000", PSEUDO_MAIN)
    output["follow_up"]["status"] = "PARTIAL"
    output["follow_up"]["stopped_reason"] = "external_deadline"
    output["follow_up"]["stopped_phase"] = "resident_query"
    output["follow_up"]["stopped_after_seconds"] = 12.5
    projected = AnalysisService._follow_up_summary_projection(
        output, requested_entry_source="investigation_actions:GET_DECOMPILE"
    )
    assert projected["stopped_reason"] == "external_deadline"
    assert projected["stopped_phase"] == "resident_query"
    assert projected["stopped_after_seconds"] == 12.5
    assert projected["requested_entry_source"] == "investigation_actions:GET_DECOMPILE"
    assert projected["deadline"]["value"] == SMALL_DEADLINE["value"]


def test_a_successful_tool_run_projection_carries_no_stopped_reason_field_at_all() -> None:
    projected = AnalysisService._follow_up_summary_projection(
        _follow_up_output("140001000", PSEUDO_MAIN),
        requested_entry_source="investigation_actions:GET_DECOMPILE",
    )
    assert "stopped_reason" not in projected


def test_the_service_limitation_projection_carries_the_producers_own_sentences() -> None:
    summary = {
        "status": "PARTIAL",
        "summary_limitation": "producer summary sentence (external_deadline)",
        "limitations": ["producer per-entry sentence for 140003000"],
    }
    assert AnalysisService._follow_up_limitations({"follow_up": summary}) == [
        "producer summary sentence (external_deadline)",
        "producer per-entry sentence for 140003000",
    ]
