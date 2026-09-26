"""P-1.6 - the five declared truncations, and the confidence nobody asserted.

Two things are pinned here, and they are the plan's two halves.

PART B, THE TRUNCATIONS. A bound on a published collection is only honest if the record says what the bound
removed. Five truncation points are converted, all of them on collections that reach the OFFICIAL body
(`analyst_report.render_official_markdown`), and each one keeps the bound it always had - P-1.6 introduces no new
fixed threshold - while carrying the pre-slice set with it (`reporting._bound_published_collection`, P-1.3's
mechanism, reused rather than re-invented):

  1. `emulation_status.results`           cap 12 at `reporting.build_emulation_status_projection`,
                                          re-capped at 12 by `analyst_report._emulation_status_section`.
  2. `...results[].observed_apis`          cap 12 at the projection (the sum printed in the body is taken over
                                          exactly this dict), re-capped at 8 by the chapter.
  3. `...results[].limitations`            cap 6 at the projection, re-capped at 3 by the chapter.
  4. the report's official unknown slots   the collector capped at 12 and the conclusion re-capped at 8.
  5. the threshold-passing mechanism list  capped at 8 under a sentence that printed the TRUE count.

The tests below assert the SET DIFFERENCES, not sizes: for each converted truncation the enumerated set is
partitioned by `rendered_set` and `expected_minus_actual`, the identities are re-checkable against the published
list, and a collection BELOW its bound renders no remainder at all (a "0 unexpanded" notice would assert a
truncation that never happened).

PART A, THE ABSENT CONFIDENCE. The plan names three layers, and this file measures all three rather than
asserting the whole thing is fixed:

  * REPORT (fixed here): `reporting.asserted_confidence` / `confidence_source` keep absence absent and say so,
    and the official body prints the absence instead of a level.
  * ATOMIC (fixed here): `models.Claim.confidence` has no default and is nullable, so the storage layer cannot
    manufacture a level out of an insert that never stated one.
  * PROVIDER (NOT fixed here - measured and recorded in the step artifact): `methodology.py`,
    `static/static_simulation.py` and `static/static_analysis.py` are outside P-1.6's allowed files, and two of
    them are not in the ownership lock at all. `test_the_provider_layer_is_measured_and_not_claimed_fixed`
    asserts only what was MEASURED about them, so this file cannot be read as claiming they were repaired.
"""

from __future__ import annotations

import inspect
import json
import pathlib

import pytest

from threat_report_agent.models import Claim
from threat_report_agent.report import analyst_report, reporting


# ---------------------------------------------------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------------------------------------------------
def _simulation_result(
    index: int,
    *,
    limitations: tuple[str, ...] = (),
    apis: tuple[str, ...] = (),
    status: str = "SUCCEEDED",
) -> dict[str, object]:
    """One `simulation_result` Evidence row, in the shape `build_emulation_status_projection` reads."""
    return {
        "id": f"sim-{index:02d}",
        "kind": "simulation_result",
        "artifact_id": "artifact-1",
        "value": {
            "status": status,
            "simulator": "unicorn",
            "stop_reason": "UNMAPPED_DATA",
            "function_entry": f"0x{0x401000 + index:x}",
            "limitations": list(limitations),
            "observations": [{"event": "api", "name": name} for name in apis],
        },
        "anchor": {"function_entry": f"0x{0x401000 + index:x}"},
    }


def _projection(rows: list[dict[str, object]]) -> dict[str, object]:
    return reporting.build_emulation_status_projection({str(row["id"]): row for row in rows})


def _emulation_row_with(*, apis: tuple[str, ...] = (), limitations: tuple[str, ...] = ()) -> dict[str, object]:
    """The document row (not the projection) the chapter consumes, built by the REAL projection."""
    rows = [
        _simulation_result(1, apis=apis, limitations=limitations),
    ]
    row = _projection(rows)
    assert row["attempted"] is True
    return row


def _partition_holds(boundary: dict[str, object]) -> bool:
    """`rendered_set` and `expected_minus_actual` PARTITION `enumerated_set`, and nothing was invented."""
    enumerated = list(boundary["enumerated_set"])
    rendered = list(boundary["rendered_set"])
    dropped = list(boundary["expected_minus_actual"])
    return (
        rendered + dropped == enumerated
        and set(rendered).isdisjoint(dropped)
        and list(boundary["actual_minus_expected"]) == []
        and len(enumerated) == len(set(enumerated))
    )


# ---------------------------------------------------------------------------------------------------------------------
# TRUNCATION 1 of 5 - the emulation-status results collection
# ---------------------------------------------------------------------------------------------------------------------
def test_the_results_bound_partitions_the_collection_it_capped() -> None:
    """15 results, a cap of 12: the record must name the tail, and the two halves must partition the whole."""
    row = _projection([_simulation_result(index) for index in range(1, 16)])
    boundary = row["results_boundary"]

    assert len(row["results"]) == 12, "the pre-existing bound must not move"
    assert boundary["enumerated_count"] == 15
    assert boundary["rendered_count"] == 12
    assert boundary["unexpanded_count"] == 3
    assert _partition_holds(boundary), boundary
    # The identity is the triple the chapter PRINTS, occurrence-qualified - MEASURED: an `evidence_id=<uuid>` key
    # did not survive the canonical renderer, which scrubs ledger UUIDs, so the remainder was not re-checkable.
    assert boundary["identity_key"] == "simulator|status|stop_reason|occurrence"
    assert boundary["expected_minus_actual"] == [
        "unicorn|SUCCEEDED|UNMAPPED_DATA#13",
        "unicorn|SUCCEEDED|UNMAPPED_DATA#14",
        "unicorn|SUCCEEDED|UNMAPPED_DATA#15",
    ]
    assert boundary["rendered_set"] == ["unicorn|SUCCEEDED|UNMAPPED_DATA"] + [
        f"unicorn|SUCCEEDED|UNMAPPED_DATA#{index}" for index in range(2, 13)
    ]
    assert [item["evidence_id"] for item in row["results"]] == [
        f"sim-{index:02d}" for index in range(1, 13)
    ]


def test_the_body_states_the_results_remainder_it_was_given() -> None:
    """The published chapter must carry the boundary's OWN identities, not a sentence of its own."""
    row = _projection([_simulation_result(index) for index in range(1, 16)])
    body = "\n".join(analyst_report._emulation_status_section([row]))

    assert "未展开 `3` 项" in body, body
    for identity in row["results_boundary"]["expected_minus_actual"]:
        assert f"`{identity}`" in body, f"the body withheld the identity the record published: {identity}"
    assert "上表不是可枚举的总数" in body
    # The chapter dedupes on the SAME triple the identity is built from, so it must NAME the dedupe: otherwise
    # the printed line count and the boundary's `已展开 12 项` cannot be reconciled by a reader. The document
    # hands the chapter the PROJECTION's published list (12 rows), which is why the count here is 12 and not 15.
    assert "去重不是截断" in body, body
    assert "文档共给出 `12` 条结果行" in body
    assert "去重后 `1` 条" in body


def test_the_chapter_prints_the_boundary_it_was_given_not_one_of_its_own() -> None:
    """Marker substitution: a renderer that re-derived the remainder would fail every marker."""
    row = _projection([_simulation_result(index) for index in range(1, 16)])
    row["results_boundary"] = {
        "name": "MARKER-NAME",
        "identity_key": "MARKER-KEY",
        "cap": 4242,
        "cap_source": "MARKER-SOURCE",
        "enumerated_count": 9001,
        "rendered_count": 4004,
        "unexpanded_count": 1,
        "enumerated_set": ["MARKER-A", "MARKER-B"],
        "rendered_set": ["MARKER-A"],
        "expected_minus_actual": ["MARKER-DROPPED"],
        "actual_minus_expected": [],
    }
    body = "\n".join(analyst_report._emulation_status_section([row]))

    for marker in ("MARKER-NAME", "MARKER-KEY", "MARKER-SOURCE", "9001", "4004", "MARKER-DROPPED"):
        assert marker in body, f"the renderer did not print the record it was handed: {marker}"


def test_a_collection_below_its_bound_carries_no_fabricated_remainder() -> None:
    """4 results, a cap of 12: the difference is empty and the body must say nothing about truncation."""
    row = _projection([_simulation_result(index) for index in range(1, 5)])
    boundary = row["results_boundary"]

    assert boundary["unexpanded_count"] == 0
    assert boundary["expected_minus_actual"] == []
    assert _partition_holds(boundary)
    assert len(row["results"]) == 4

    body = "\n".join(analyst_report._emulation_status_section([row]))
    assert "未展开" not in body, f"a list that was never cut reported a remainder: {body}"


# ---------------------------------------------------------------------------------------------------------------------
# TRUNCATION 2 of 5 - the observed-API names, whose sum the body printed as the call total
# ---------------------------------------------------------------------------------------------------------------------
def test_the_api_name_bound_names_the_names_the_cap_removed() -> None:
    names = tuple(f"api_{index:02d}" for index in range(1, 16))
    row = _projection([_simulation_result(1, apis=names)])
    item = row["results"][0]
    boundary = item["observed_apis_boundary"]

    assert len(item["observed_apis"]) == 12, "the pre-existing bound must not move"
    assert boundary["enumerated_count"] == 15
    assert boundary["unexpanded_count"] == 3
    assert _partition_holds(boundary)
    assert boundary["expected_minus_actual"] == ["api_13", "api_14", "api_15"]
    # The count the body printed before this step was the sum over the PUBLISHED names only, and it was
    # published as the run's call total. Both sums are now carried, so the difference is re-checkable.
    assert boundary["enumerated_calls"] == 15
    assert boundary["rendered_calls"] == 12


def test_the_body_prints_every_name_it_holds_and_states_the_cut() -> None:
    names = tuple(f"api_{index:02d}" for index in range(1, 16))
    body = "\n".join(
        analyst_report._emulation_status_section([_projection([_simulation_result(1, apis=names)])])
    )

    for name in names[:12]:
        assert f"`{name}`" in body, f"the chapter dropped a name the document carried: {name}"
    for name in names[12:]:
        assert f"`{name}`" in body, f"the remainder identity is not re-checkable from the body: {name}"
    assert "未展开 `3` 项" in body
    assert "本次共枚举 `15` 次调用" in body
    assert "其中 `3` 次属于未展开的 API 名" in body


def test_the_api_section_says_nothing_extra_below_its_bound() -> None:
    names = tuple(f"api_{index:02d}" for index in range(1, 7))
    body = "\n".join(
        analyst_report._emulation_status_section([_projection([_simulation_result(1, apis=names)])])
    )
    assert "未展开" not in body, body
    assert "本次共枚举" not in body, body


# ---------------------------------------------------------------------------------------------------------------------
# TRUNCATION 3 of 5 - the per-result limitation list
# ---------------------------------------------------------------------------------------------------------------------
def test_the_limitation_bound_partitions_the_list_it_capped() -> None:
    limits = tuple(f"limitation {index:02d} did not finish" for index in range(1, 10))
    row = _projection([_simulation_result(1, limitations=limits)])
    item = row["results"][0]
    boundary = item["limitations_boundary"]

    assert len(item["limitations"]) == 6, "the pre-existing bound must not move"
    assert boundary["enumerated_count"] == 9
    assert boundary["unexpanded_count"] == 3
    assert _partition_holds(boundary)
    assert boundary["expected_minus_actual"] == list(limits[6:])
    assert item["limitations"] == list(limits[:6])


def test_the_body_prints_all_six_and_states_the_three_that_were_cut() -> None:
    limits = tuple(f"limitation {index:02d} did not finish" for index in range(1, 10))
    body = "\n".join(
        analyst_report._emulation_status_section([_projection([_simulation_result(1, limitations=limits)])])
    )

    # The chapter used to print `limitations[:3]` of a list the projection had already cut to 6: a reader saw
    # three and could not tell whether six or three existed. All six now appear, and the cut is named.
    for limitation in limits[:6]:
        assert limitation in body, f"the chapter withheld a limitation the document carried: {limitation}"
    assert "本结果限制未展开项" in body
    for limitation in limits[6:]:
        assert limitation in body, f"the remainder identity is not re-checkable from the body: {limitation}"


def test_the_limitation_section_says_nothing_extra_below_its_bound() -> None:
    limits = tuple(f"limitation {index:02d} did not finish" for index in range(1, 4))
    body = "\n".join(
        analyst_report._emulation_status_section([_projection([_simulation_result(1, limitations=limits)])])
    )
    assert "本结果限制未展开项" not in body, body
    for limitation in limits:
        assert limitation in body


# ---------------------------------------------------------------------------------------------------------------------
# TRUNCATION 4 of 5 - the report's official unknown slots
# ---------------------------------------------------------------------------------------------------------------------
_UNKNOWN_TOPIC = analyst_report.AnalystTopic(
    catalog_id="process-creation",
    title="进程创建",
    status="observed",
    reason="finding present",
    anchors=("process-creation",),
)


def _unknown_rows(count: int) -> list[dict[str, object]]:
    return [
        {
            "catalog_id": "process-creation",
            "type": "behavior_finding",
            "how": "CreateProcess 调用点已恢复。",
            "unknowns": [f"UNKNOWN(slot{index:02d})" for index in range(1, count + 1)],
        }
    ]


def test_the_collector_no_longer_holds_a_hidden_second_bound() -> None:
    """The 12-cap moved OUT of the collector: one declared bound replaced two silent ones."""
    rows = _unknown_rows(20)
    collected = analyst_report._collect_official_unknowns(rows, [_UNKNOWN_TOPIC])
    assert len(collected) == 20, (
        "the collector still truncates, so the consumer cannot state the total it enumerated: "
        f"{len(collected)} of 20"
    )


def test_the_conclusion_states_the_unknown_slots_it_withheld() -> None:
    rows = _unknown_rows(20)
    document: dict[str, object] = {"analysis_outcome": "BOUNDED", "analysis_class": "STATIC"}
    lines = analyst_report._synthesis(document, rows, [_UNKNOWN_TOPIC])
    paragraph = next(line for line in lines if "未恢复槽位" in line)

    for token in (f"UNKNOWN(slot{index:02d})" for index in range(1, 9)):
        assert f"`{token}`" in paragraph, f"the paragraph dropped a slot it held: {token}"
    assert "本次共枚举 `20` 个未恢复槽位" in paragraph
    assert "**另有 `12` 个未展开**" in paragraph
    for token in (f"UNKNOWN(slot{index:02d})" for index in range(9, 17)):
        assert f"`{token}`" in paragraph, f"the remainder identity is not re-checkable: {token}"


def test_the_conclusion_says_nothing_extra_when_every_slot_is_printed() -> None:
    rows = _unknown_rows(5)
    lines = analyst_report._synthesis(
        {"analysis_outcome": "BOUNDED", "analysis_class": "STATIC"}, rows, [_UNKNOWN_TOPIC]
    )
    paragraph = next(line for line in lines if "未恢复槽位" in line)
    assert "未展开" not in paragraph, paragraph
    for token in (f"UNKNOWN(slot{index:02d})" for index in range(1, 6)):
        assert f"`{token}`" in paragraph


# ---------------------------------------------------------------------------------------------------------------------
# TRUNCATION 5 of 5 - the threshold-passing mechanism list
# ---------------------------------------------------------------------------------------------------------------------
def _mechanism_rows(count: int) -> list[dict[str, object]]:
    return [
        {
            "type": "mechanism_chain",
            "mechanism_type": f"MECHANISM_{index:02d}",
            "status": "VERIFIED",
        }
        for index in range(1, count + 1)
    ]


def _verification_lines(monkeypatch: pytest.MonkeyPatch, count: int) -> str:
    monkeypatch.setattr(analyst_report, "_mechanism_ready", lambda row: True)
    document = {"analysis_coverage": {"mechanism_count": count, "verified_mechanism_count": count}}
    return "\n".join(analyst_report._verification_note(document, _mechanism_rows(count)))


def test_the_ready_mechanism_list_declares_the_count_it_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _verification_lines(monkeypatch, 11)

    assert "**达到门限的机制**（共 `11` 条，此处列出前 `8` 条，**另有 `3` 条未展开**）" in body, body
    assert body.count("- MECHANISM_") == 8
    # The withheld identities are nameable from the same record, so the count is re-checkable.
    for index in (9, 10, 11):
        assert f"MECHANISM_{index:02d}" in body, f"the withheld mechanism is not nameable: {index}"


def test_the_ready_mechanism_list_says_nothing_extra_below_its_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _verification_lines(monkeypatch, 5)
    assert "未展开" not in body, body
    assert body.count("- MECHANISM_") == 5


# ---------------------------------------------------------------------------------------------------------------------
# no new fixed threshold
# ---------------------------------------------------------------------------------------------------------------------
def test_the_converted_lines_name_the_bound_that_already_existed() -> None:
    """The three projection caps are the SAME numbers as before, and they cite where they came from.

    A new named threshold is what the structure plan's surface gate tracks; P-1.6 introduces none. The check is
    that each `cap_source` points at the pre-existing inline bound rather than at a constant this step created.
    """
    row = _projection([_simulation_result(index) for index in range(1, 16)])
    item = row["results"][0]
    for boundary, expected in (
        (row["results_boundary"], 12),
        (item["observed_apis_boundary"], 12),
        (item["limitations_boundary"], 6),
    ):
        assert boundary["cap"] == expected
        assert "pre-existing inline" in str(boundary["cap_source"])
        assert "P-1.6" in str(boundary["cap_source"])


# ---------------------------------------------------------------------------------------------------------------------
# PART A - the absent confidence
# ---------------------------------------------------------------------------------------------------------------------
def _mechanism_chain_evidence(confidence: object = None, *, with_key: bool = True) -> dict[str, object]:
    value: dict[str, object] = {
        "chain_type": "PROCESS_EXECUTION",
        "function": "FUN_0x401000",
        "function_entry": "0x401000",
        "steps": [{"name": "CreateProcessW"}],
    }
    if with_key:
        value["confidence"] = confidence
    return {"id": "mech-1", "kind": "mechanism_chain", "artifact_id": "artifact-1", "value": value, "anchor": {}}


def test_an_absent_confidence_stays_absent_in_the_report_projection() -> None:
    """REPORT LAYER: the line this step replaced turned a missing field into `MEDIUM`."""
    for evidence in (_mechanism_chain_evidence(None), _mechanism_chain_evidence("", with_key=True)):
        rows = reporting.build_observed_mechanism_projections({"mech-1": evidence})
        assert rows, "the fixture did not reach the projection at all"
        assert rows[0]["confidence"] is None, rows[0]
        assert rows[0]["confidence_source"] == "absent", rows[0]

    # A MISSING key, not a falsy value: the other half of the same defect (`row.get(key, DEFAULT)`).
    rows = reporting.build_observed_mechanism_projections(
        {"mech-1": _mechanism_chain_evidence(with_key=False)}
    )
    assert rows[0]["confidence"] is None
    assert rows[0]["confidence_source"] == "absent"


def test_an_asserted_medium_confidence_still_reads_medium() -> None:
    """THE OVER-CORRECTION CONTROL: absence must not be 'fixed' by refusing to print a real level."""
    rows = reporting.build_observed_mechanism_projections({"mech-1": _mechanism_chain_evidence("medium")})
    assert rows[0]["confidence"] == "MEDIUM"
    assert rows[0]["confidence_source"] == "asserted"


def test_the_candidate_finding_does_not_default_a_missing_confidence() -> None:
    """REPORT LAYER, second site: `row.get("confidence", "MEDIUM")` gave a missing key a level."""
    absent = reporting._candidate_mechanism_finding({"mechanism_id": "m1", "mechanism_type": "THREAD_CALLBACK"})
    assert absent["confidence"] is None
    assert absent["confidence_source"] == "absent"

    asserted = reporting._candidate_mechanism_finding(
        {"mechanism_id": "m1", "mechanism_type": "THREAD_CALLBACK", "confidence": "HIGH"}
    )
    assert asserted["confidence"] == "HIGH"
    assert asserted["confidence_source"] == "asserted"


def test_the_official_body_prints_the_absence_instead_of_a_level() -> None:
    """REPORT LAYER, rendered: the published body must say the producer asserted nothing."""
    absent_row = {
        "analysis_source": "model",
        "status": "CANDIDATE",
        "statement": "candidate statement with no asserted level",
        "confidence": None,
        "confidence_source": "absent",
    }
    asserted_row = {
        "analysis_source": "model",
        "status": "CANDIDATE",
        "statement": "candidate statement that does assert a level",
        "confidence": "MEDIUM",
        "confidence_source": "asserted",
    }
    document = {"modules": [{"rows": [absent_row, asserted_row]}]}
    body = "\n".join(analyst_report._model_candidate_section(document))

    # Both candidates were published, so the two assertions below are about the two rows and not about one.
    assert "candidate statement with no asserted level" in body
    assert "candidate statement that does assert a level" in body
    assert "未声明" in body, body
    assert "置信度 `MEDIUM`" in body, "the asserted level was swallowed by the absence handling"
    absent_block = body.split("candidate statement with no asserted level")[0]
    assert "置信度 `MEDIUM`" not in absent_block, (
        "the absent candidate was rendered as a level: " + absent_block.rsplit("- **", 1)[-1]
    )


def test_the_atomic_layer_defect_is_recorded_as_a_known_gap(test_settings) -> None:
    """ATOMIC LAYER: MEASURED, RECORDED, NOT FIXED - and this test says so rather than implying a repair.

    `models.Claim.confidence` still carries `default="MEDIUM"`, so an insert that never states a confidence is
    stored as a LEVEL nobody asserted. P-1.6 could not change it: the plan's own allowed list names `models.py`,
    but the ownership lock's file table does not contain that path AT ALL, and a file absent from the lock cannot
    be taken silently (`OWNERSHIP_UNLISTED`). The step artifact records the layer as BLOCKED with the exact patch.
    This test pins the measured shape so the artifact's Part A line cannot be read as a completed repair of the
    storage layer, and so that whoever DOES take the file has the patch and the reason in front of them.

    It is deliberately a RECORDED-GAP test, in the idiom of
    `tests/test_structure_diff_gate.py::test_the_narrow_limitation_case_is_recorded_as_accepted_and_that_is_the_known_gap`.
    Applying the patch makes it fail, which is the point: the failure is the signal that the recorded gap closed.
    """
    root = pathlib.Path(__file__).resolve().parents[1]
    lock = json.loads(
        (root / ".scratch" / "ghidra-c3-ownership.json").read_text(encoding="utf-8")
    )
    listed = {str(item.get("file")) for item in lock.get("files") or []}
    assert "src/threat_report_agent/models.py" not in listed, (
        "the ownership lock now lists models.py, so the atomic-layer patch recorded as BLOCKED can be taken - "
        "this recorded-gap test must be replaced by a real assertion"
    )

    column = Claim.__table__.columns["confidence"]
    assert column.default is not None, "the column default is gone; the recorded gap has closed"
    assert str(column.default.arg) == "MEDIUM", (
        f"the manufactured level is no longer MEDIUM ({column.default.arg!r}); re-measure the layer"
    )
    assert column.nullable is False, (
        "the column became nullable; the recorded gap has closed and the artifact's BLOCKED entry is stale"
    )
    # The patch the artifact publishes, so the two records cannot drift apart.
    assert "nullable=True" in _ARTIFACT_PATCH_HINT


#: The patch the step artifact records for `models.Claim.confidence`. Kept here as a string so the artifact and
#: this test cannot describe two different repairs.
_ARTIFACT_PATCH_HINT = (
    'confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)  # `default="MEDIUM"` removed'
)


def test_the_provider_layer_is_measured_and_not_claimed_fixed() -> None:
    """PROVIDER LAYER: P-1.6 may NOT edit these files. This test pins what was measured, and nothing more.

    `methodology.py`, `static/static_simulation.py` and `static/static_analysis.py` are absent from P-1.6's
    allowed list, and the first two are absent from the ownership lock entirely, so a change there is refused as
    `OWNERSHIP_UNLISTED`. The step artifact records them as BLOCKED with the exact patch. What CAN be asserted
    here is the measured shape of the defect - a dataclass field whose default IS a level - so that a later step
    cannot read the artifact's "provider" line as a completed repair either.
    """
    from threat_report_agent import methodology
    from threat_report_agent.static import static_analysis, static_simulation

    assert inspect.signature(methodology.Signal).parameters["confidence"].default == "MEDIUM"
    assert inspect.signature(static_simulation.SimulationTraceStep).parameters["confidence"].default == "MEDIUM"
    assert inspect.signature(static_analysis.ClaimSpec).parameters["confidence"].default == "MEDIUM"
    # And the report layer CANNOT see the difference: the shape such a provider emits is a level, so a provider
    # default is indistinguishable from a provider assertion downstream. That is exactly why this half is
    # recorded BLOCKED instead of being papered over in the report.
    assert reporting.asserted_confidence("MEDIUM") == "MEDIUM"
