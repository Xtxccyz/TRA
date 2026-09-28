"""P-8 acceptance: T6 (splice artefact) and T7 (`consumer` namespace).

Both defects are measured, not described, before this file existed:

* `.scratch/ghidra-c3/preflight/p8-probe-before.py` -> `p8-probe-before.json` measured the REAL 20-character-record
  splice being published under `- 执行相关 API 名称：` while `primary_analyst_violations(rendered) == []`;
* `.scratch/ghidra-c3/preflight/p8-probe-token-locations.py` -> `p8-probe-token-locations.json` measured
  `UNKNOWN(consumer)` appearing 3x in the PRIMARY body and 3x in the APPENDIX of the same document.

The T6 half is a NAME SET DIFFERENCE (`enumerated - retrieved` and its reverse), not a counter: the audit's
finding was that `primary_analyst_violations == 0` is compatible with the body publishing a spliced token as if it
were a structured name list. The T7 half requires the machine token to keep ONE meaning (the ten-question slot in
the appendix) and the dataflow placeholder to be prose in the primary body, and it must fail on BOTH a wrong
sample and an empty body.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from threat_report_agent.analyst_report import (
    ANALYST_APPENDIX_HEADING,
    ANALYST_CONCLUSION_HEADING,
    primary_analyst_violations,
    render_official_markdown,
    split_analyst_markdown,
)

# The two checkers this step ADDS are imported through a helper instead of at module scope on purpose: a
# module-level ImportError aborts collection, and a collection abort produces no per-node outcome at all - the
# capture would then be cited as a "red run" while showing no failing node (the P-7 finding G-1 shape).
# Imported lazily, every test still COLLECTS and fails individually, which is what
# `focused_failure_nodes_before` has to be recomputable from.
def _checkers():
    from threat_report_agent.analyst_report import (
        _SPLICE_BOUNDARY_SENTENCE,
        _spliced_name_values,
        consumer_namespace_violations,
        name_listing_violations,
    )

    return (
        consumer_namespace_violations,
        name_listing_violations,
        _spliced_name_values,
        _SPLICE_BOUNDARY_SENTENCE,
    )


def consumer_namespace_violations(markdown: str) -> list[str]:
    return _checkers()[0](markdown)


def name_listing_violations(markdown: str, retrieved_names) -> list[str]:  # type: ignore[no-untyped-def]
    return _checkers()[1](markdown, retrieved_names)


def _spliced_name_values(facts, attested):  # type: ignore[no-untyped-def]
    return _checkers()[2](facts, attested)
from threat_report_agent.report.reporting import (
    REPORT_V3_REQUIRED_SECTIONS,
    build_string_fact_projection,
    string_fact_class,
)

from threat_report_agent.analyst_report import _STRING_FACT_LABELS

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / ".scratch"
    / "ghidra-c3"
    / "preflight"
    / "p8-t6-fixture.json"
)

#: The splice, VERBATIM out of the deployed database (artifact `8cbe71d9-…`, task `1b69333a-…`).
SPLICE = (
    "explorer.exeInitializeProcThreadAttributeList failedUpdateProcThreadAttribute "
    "failedCreateProcessW failedOpenProcess failedexplorer not foundsnapshot failed"
)

#: The names the splice is built out of, every one of which the SAME artifact carries as its own standalone
#: SYMBOL-TABLE row (`kind='import_symbol'`; `CreateProcessW` is additionally a `kind='string'` row of that
#: artifact - MEASURED: 136 identifier-shaped `import_symbol` names and 4 identifier-shaped `execution_api` string
#: rows, so the string names are a subset). Every one of them also appears VERBATIM inside the recovered blob
#: (`… failedUpdateProcThreadAttribute failed …`); `UpdateProcThreadAttribute` is a real API name of its own, NOT
#: a record truncation of `UpdateProcThreadAttributeList` (an earlier version of this comment said it was; the
#: P-8 analysis-verification audit measured the `import_symbol` row and it is corrected here).
SPLICE_NAMES = (
    "InitializeProcThreadAttributeList",
    "UpdateProcThreadAttribute",
    "CreateProcessW",
    "OpenProcess",
)

#: The audit's counter-example: raw VERSIONINFO content where nothing was spliced by the product. A rule that
#: rejected any value containing `.exe` would delete this legitimate fact.
VERSION_INFO = (
    "Adobe Acrobat Reader DC 23.006.20380Copyright 1984-2023 Adobe Inc. All rights reserved."
    "AcroRd32.exeAcroCEF.exeAdobe PDF Library 23.006.20380AdobeARMserviceAdobe Update Manager"
    "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"
    "%LOCALAPPDATA%\\Adobe\\Acrobat\\DC\\CachePDFNetC64.dllPDF-1.7%PDF-1.4endstream"
)

#: The prose the dataflow placeholder is allowed to be in the primary body. It contains no machine token.
CONSUMER_PROSE = "命名消费者未从静态证据中恢复，因此该数据流消费链仍未闭合"

#: The boundary sentence the renderer must publish beside a decomposed splice, imported lazily from the product
#: (through `_checkers()`) so a module-level ImportError cannot abort collection.
def splice_boundary_sentence() -> str:
    return _checkers()[3]

#: The WRONG sample for the T7 checker: the dataflow placeholder written into the primary body.
WRONG_SAMPLE = "## 分析结论\n\n静态恢复到 XOR 解码。`UNKNOWN(consumer)`：消费链未闭合。\n"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _objects(fixture: dict[str, object]) -> list[SimpleNamespace]:
    return [
        SimpleNamespace(
            id=str(row["id"]),
            kind=str(row["kind"]),
            module=str(row["module"]),
            value=row["value"],
        )
        for row in fixture["rows"]  # type: ignore[index]
    ]


def _attest_objects(fixture: dict[str, object]) -> list[SimpleNamespace]:
    """The symbol-table Evidence rows of the same artifact - the attestation the producer reads."""
    return [
        SimpleNamespace(
            id=str(row["id"]),
            kind=str(row["kind"]),
            module="static",
            value=row["value"],
        )
        for row in fixture.get("attests") or []  # type: ignore[union-attr]
    ]


def _standalone_names(fixture: dict[str, object]) -> set[str]:
    """Names the SAME artifact carries as their own row - the "evidence" side of the set difference.

    A name is "standalone" when it appears as its OWN row of the artifact: a `kind='string'` row whose whole
    text is that name, or a symbol-table row (`import_symbol`) whose name is that name. Enumerated from the
    evidence rows, NOT from the projection under test, so the difference is not circular - `string_fact_class` is
    used only to decide which STRING rows even count as name-bearing.
    """
    names: set[str] = set()
    for row in fixture["rows"]:  # type: ignore[index]
        text = str((row["value"] or {}).get("text") or "")  # type: ignore[index]
        if not text or text == SPLICE:
            continue
        if string_fact_class(text) != "execution_api":
            continue
        if text.isidentifier():
            names.add(text)
    for row in fixture.get("attests") or []:  # type: ignore[union-attr]
        candidate = str((row["value"] or {}).get("name") or (row["value"] or {}).get("text") or "")  # type: ignore[index]
        if candidate.isidentifier():
            names.add(candidate)
    return names


def _attested_for_projection(fixture: dict[str, object]) -> list[str]:
    """The attestation set the PRODUCER hands the renderer (symbol-table names + standalone string names)."""
    return sorted(_standalone_names(fixture))


def _name_listing_lines(markdown: str) -> list[str]:
    """Lines whose label claims a structured list of API names."""
    label = _STRING_FACT_LABELS["execution_api"]
    return [line for line in markdown.splitlines() if line.startswith(f"- {label}")]


def _primary(markdown: str) -> str:
    return split_analyst_markdown(markdown)[0]


def _document(
    *,
    string_facts: list[dict[str, object]] | None = None,
    rows: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-p8",
        "task_id": "task-p8",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {},
        "modules": [{"id": "static_triage", "title": "Static Triage", "summary": "", "rows": list(rows or [])}],
        "trace": {},
    }
    if string_facts is not None:
        document["string_facts"] = string_facts
    return document


def _projection_from_values(pairs: list[tuple[str, str]]) -> list[dict[str, object]]:
    return [{"fact_class": fact_class, "value": value} for fact_class, value in pairs]


def _real_projection(fixture: dict[str, object]) -> list[dict[str, object]]:
    """The projection the PRODUCER builds from this artifact, verbatim.

    P-8 round 2: this used to hand-build the pairs from the fixture and inject `attested_names` itself, which made
    the "published names are attested" leg circular - the test supplied the very attestation the renderer consumed
    (the audit's finding P8-AV15). It now returns the SHIPPED `reporting.build_string_fact_projection` output over
    the artifact's own Evidence rows (string rows + symbol rows), so the renderer is driven by exactly what
    production emits and the attestation is the producer's, not the test's. `_standalone_names` stays the
    independent side of the difference.
    """
    return build_string_fact_projection(_objects(fixture) + _attest_objects(fixture))


# --------------------------------------------------------------------------- T6
def test_the_real_evidence_fixture_carries_the_splice_verbatim() -> None:
    """The fixture must be the real recovered bytes, or every difference below is about a made-up value."""
    fixture = _fixture()
    values = [str((row["value"] or {}).get("text") or "") for row in fixture["rows"]]  # type: ignore[index]
    assert SPLICE in values
    assert fixture["artifact_id"] == "8cbe71d9-6ba5-4585-862e-ec2b969d45a9"
    assert string_fact_class(SPLICE) == "execution_api"
    # The cross-check row that makes "standalone" mean something on THIS artifact.
    assert _standalone_names(fixture) >= set(SPLICE_NAMES)
    # The version-info row is present too, so the negative control below is the real thing.
    assert any(str((row["value"] or {}).get("text") or "") == VERSION_INFO for row in fixture["rows"])  # type: ignore[index]


def test_a_spliced_name_run_is_not_published_as_a_structured_name_list() -> None:
    """T6: the published API-name line must not be the concatenated 20-character-record run."""
    fixture = _fixture()
    projection = _real_projection(fixture)
    official = render_official_markdown(_document(string_facts=projection))
    listing = _name_listing_lines(official)
    assert listing, "the fixture's execution_api facts did not reach the body at all"

    published_tokens: set[str] = set()
    offender = ""
    for line in listing:
        for token in re.findall(r"`([^`]+)`", line):
            published_tokens.add(token)
            if SPLICE in token:
                offender = token
    assert offender == "", f"the body published the spliced run as a name: {offender!r}"

    # THE SET DIFFERENCE, both directions, on the values the body actually published.
    #
    # `retrieved` is the artifact's whole standalone-name set (MEASURED: 136 identifier-shaped `import_symbol`
    # names, of which the 4 identifier-shaped `execution_api` string rows are a subset). The body publishes a
    # BOUNDED selection of them, so `retrieved - published` is legitimately
    # non-empty (the projection's own `selection_limit`); what must be empty is the other direction - every name
    # the narrative PUBLISHED must be one the evidence attests, which is exactly the claim T6 falsifies.
    retrieved = _standalone_names(fixture)
    assert published_tokens - retrieved == set(), sorted(published_tokens - retrieved)
    # The names out of the spliced value are published too, and they are members of the same set.
    published_components = {
        name for name in retrieved if any(f"`{name}`" == token for token in published_tokens)
    }
    assert published_components - retrieved == set()
    assert {
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "CreateProcessW",
        "OpenProcess",
    } <= published_tokens
    assert name_listing_violations(official, retrieved) == []


def test_the_spliced_run_still_reaches_the_body_and_says_it_is_a_splice() -> None:
    """EC-1/EC-4 guard: the fix must not delete the recovered evidence, only stop calling it a name list.

    STRENGTHENED in round 2 after the audit's finding P8-AV1/P8-AV2: the round-1 version asserted only that three
    NAME tokens were present, which is a string-presence claim, not the property the docstring names - the raw byte
    string (and its un-decomposable remainder) could be, and measurably was, absent from the body while the test
    stayed green. The value is now asserted VERBATIM (the section header promises verbatim publication of every
    value on the page) and it is asserted to be published on a line that does NOT claim it is a name.
    """
    fixture = _fixture()
    official = render_official_markdown(_document(string_facts=_real_projection(fixture)))
    primary = _primary(official)
    # Every name in the run is published as its own entry, so the fact is still there.
    for name in ("InitializeProcThreadAttributeList", "CreateProcessW", "OpenProcess"):
        assert f"`{name}`" in primary, name
    # THE RECOVERED BYTES THEMSELVES SURVIVE, VERBATIM - including the part that is NOT decomposable into a name.
    assert f"`{SPLICE}`" in primary, "the recovered byte string was deleted from the body"
    assert "not foundsnapshot failed" in primary
    # The line is NAMED as a concatenation instead of being presented as a structure, AND the boundary sentence
    # that says so is published (this is the part the control `the_splice_boundary_sentence_is_dropped` removes).
    labels = _name_listing_lines(primary)
    marker_lines = [line for line in labels if "拼接" in line]
    assert marker_lines, labels
    assert splice_boundary_sentence() in primary, "the concatenation was not stated, only listed"
    # The un-decomposable remainder is not published as a NAME: no line that claims a name list carries it.
    for line in labels:
        for token in re.findall(r"`([^`]+)`", line):
            assert "not foundsnapshot" not in token, line
            assert "explorer.exeInitializeProcThreadAttributeList" not in token, line


def test_the_t7_prose_does_not_hide_the_recovered_phase_facts() -> None:
    """P-8/T7 regression pin (audit finding P8-D1): the prose rewrite must not cost the line its facts.

    MEASURED on the REAL revision before this test existed: the runtime-sequence renderer ran
    `dataflow_placeholder_prose` BEFORE `_strip_payload_but_keep_structure`, and the injected CJK made the value
    match `_is_raw_decoded_fragment` ("CJK fused with Latin"), so the WHOLE phase line was replaced by
    `UNKNOWN(该阶段的输入/变换/输出未成文；…)` and the recovered named consumer `consumer=DAT_14004c8e1`, the
    endpoint and the formula disappeared from 正文 - a fix for a token collision deleting recovered evidence
    (EC-1/EC-4). This test drives the renderer with the real phase text and asserts BOTH halves: the token is gone
    from 正文 AND the recovered facts are still published.
    """
    phase_how = (
        "Resume.pdf .exe.VIR statically recovers a decode path using `key_table_modulo_xor_counter` consumed by "
        "`UNKNOWN(consumer)`; runtime use of the plaintext is unverified.; threshold=static evidence threshold "
        "satisfied; runtime execution not proven; consumer=DAT_14004c8e1; http://69.48.228.74/miaom-c.pdf; "
        "formula=key_table_modulo_xor_counter"
    )
    document = _document(
        rows=[
            {
                "type": "assessment",
                "runtime_sequence": [
                    {
                        "type": "runtime_phase",
                        "id": "phase-decode-real",
                        "title": "Phase 3 — decode / config",
                        "status": "CANDIDATE",
                        "how": phase_how,
                        "catalog_ids": ["config-and-crypto"],
                        "runtime_observed": False,
                    }
                ],
            }
        ]
    )
    official = render_official_markdown(document)
    primary, _appendix = split_analyst_markdown(official)
    assert "运行时序" in primary
    assert "UNKNOWN(consumer)" not in primary, "the slot token reached 正文"
    assert CONSUMER_PROSE in primary, "the dataflow fact was not stated in prose"
    # the recovered facts survive on the same line
    assert "DAT_14004c8e1" in primary, "the recovered named consumer was deleted from the body"
    assert "http://69.48.228.74/miaom-c.pdf" in primary, "the recovered endpoint was deleted from the body"
    assert "key_table_modulo_xor_counter" in primary, "the recovered formula was deleted from the body"
    assert "未成文" not in primary, "the phase line was replaced by the 'not written up' stub"
    assert primary_analyst_violations(official) == []


def test_the_version_info_splice_lookalike_is_still_published() -> None:
    """The negative control for T6: `\\.exe[A-Za-z]` alone over-matches, so a real fact must survive.

    The VERSIONINFO row is the measured over-match from `.scratch/t6-confirmed-in-published-body.md`: the product
    spliced nothing there, so the value must be published VERBATIM and must NOT be split into names. The check is
    on the body (`AcroRd32.exe` is published) AND on the splitter (the value is not in the spliced map), because
    a predicate that split every name-bearing run would pass the first half and fail the second.
    """
    fixture = _fixture()
    projection = _real_projection(fixture)
    official = render_official_markdown(_document(string_facts=projection))
    assert "Adobe Acrobat Reader DC 23.006.20380" in official
    assert "AcroRd32.exe" in official
    # The splitter, driven with the SAME facts the body was rendered from. The value must not be split: the
    # VERSIONINFO gaps are copyright prose, not record boundaries, and the splitter must not invent a name out of
    # them. `CreateProcessW` is included so the attested set is non-empty and the walker actually runs.
    facts = [
        (str(row["fact_class"]), str((row["value"] or {}).get("text") or ""))
        for row in fixture["rows"]  # type: ignore[index]
    ]
    assert any(text == VERSION_INFO for _fact_class, text in facts), "the fixture lost the VERSIONINFO row"
    facts = facts + [("execution_api", "CreateProcessW")]
    attested = _attested_for_projection(fixture) or ["CreateProcessW"]
    spliced = _spliced_name_values(facts, attested)
    assert VERSION_INFO not in spliced, f"the VERSIONINFO lookalike was split as if spliced: {spliced.get(VERSION_INFO)}"
    assert SPLICE in spliced, "the real splice was not split at all"

    # THE GAP AGREEMENT IS THE GUARD, AND THIS IS WHERE IT IS MEASURED. The VERSIONINFO row above happens to share
    # no substring with any attested name of this artifact, so it is already excluded by the FIRST condition
    # (there is nothing to fuse) and says nothing about the SECOND one - measured:
    # `.scratch/ghidra-c3/preflight/p8-probe-guards.json` shows that deleting the gap check alone leaves THIS test
    # green (candidate `gap_guard_removed`), and `p8-diagnose-versioninfo.json` shows why (0 fused runs). So the
    # negative control is also driven with the shape the audit actually measured: two attested names FUSED at a
    # record boundary exactly like the real splice, separated by the raw copyright PROSE the real VERSIONINFO row
    # carries. A splice's gaps are the resolver's own connector words (`failed`/`not`/`found`, measured on the real
    # 20-character-record table); these gaps are prose, so the value is NOT a splice and must stay verbatim. A
    # predicate that keyed on "runs longer than a name" alone, or on `.exe[A-Za-z]`, accepts it - which is the
    # over-match the audit recorded.
    prose_gap = "failedCreateProcessW Copyright 1984-2023 Adobe Inc. All rights reserved. failedOpenProcess"
    prose_spliced = _spliced_name_values(
        [("execution_api", prose_gap), ("execution_api", "CreateProcessW")],
        sorted(_standalone_names(fixture)),
    )
    assert prose_gap not in prose_spliced, (
        f"a fused run whose GAPS are copyright prose was accepted as a splice: {prose_spliced.get(prose_gap)}"
    )
    prose_body = render_official_markdown(
        _document(string_facts=_projection_from_values([("execution_api", prose_gap)]))
    )
    assert prose_gap in prose_body, "the prose-gap counter-fixture was not published verbatim"
    assert not [line for line in _name_listing_lines(prose_body) if "拼接" in line], _name_listing_lines(
        prose_body
    )
    # It is not a name list, so name_listing_violations must not be applied to it; if it ever gets classified as
    # one, the checker has to accept it, because no evidence row is concatenated there.
    retrieved = _standalone_names(fixture)
    assert name_listing_violations(official, retrieved | {"AcroRd32.exe", "AcroCEF.exe"}) == []


def test_the_wrong_splice_fixture_is_rejected() -> None:
    """A spliced run whose pieces are NOT standalone evidence must fail, not be published as names."""
    wrong = "explorer.exeTotallyInventedApiName failedAlsoNotReal failed"
    official = render_official_markdown(
        _document(string_facts=_projection_from_values([("execution_api", wrong)]))
    )
    retrieved = _standalone_names(_fixture())
    violations = name_listing_violations(official, retrieved)
    assert violations, "the checker accepted a spliced run built from names no evidence row backs"
    assert any("TotallyInventedApiName" in item or "AlsoNotReal" in item for item in violations)


def test_name_listing_violations_rejects_a_concatenated_token_outside_the_body_too() -> None:
    """The checker is a pure function over text, so it can be driven with any body the plan names."""
    retrieved = set(SPLICE_NAMES)
    good = "- 执行相关 API 名称：`CreateProcessW`\n"
    assert name_listing_violations(good, retrieved) == []
    bad = f"- 执行相关 API 名称：`{SPLICE}`\n"
    assert name_listing_violations(bad, retrieved)
    assert name_listing_violations("- 执行相关 API 名称：`NotInEvidence`\n", retrieved)


def test_the_primary_gate_empty_body_rule_is_distinct_from_the_namespace_one() -> None:
    """Each checker must reject an empty body ON ITS OWN: one covering for the other is not coverage."""
    primary_rules = primary_analyst_violations("")
    namespace_rules = consumer_namespace_violations("")
    assert primary_rules, "primary_analyst_violations accepted an EMPTY body"
    assert namespace_rules, "consumer_namespace_violations accepted an EMPTY body"
    assert any("empty" in item.casefold() and "PRIMARY" in item for item in primary_rules), primary_rules
    assert any("empty" in item.casefold() and "NAMESPACE" in item for item in namespace_rules), namespace_rules


# --------------------------------------------------------------------------- T7
def test_the_dataflow_placeholder_is_prose_and_the_slot_token_stays_in_the_appendix() -> None:
    """T7: `consumer` keeps ONE meaning - the ten-question slot, in the appendix."""
    document = _document(
        rows=[
            {
                "type": "behavior_finding",
                "catalog_id": "config-and-crypto",
                "finding_status": "CANDIDATE",
                "how": "key_table_modulo_xor_counter plaintext=`http://example.invalid/gate` consumer=UNKNOWN(consumer)",
            }
        ]
    )
    official = render_official_markdown(document)
    primary, appendix = split_analyst_markdown(official)
    assert ANALYST_CONCLUSION_HEADING in official
    assert ANALYST_APPENDIX_HEADING in official
    assert "UNKNOWN(consumer)" not in primary
    assert "UNKNOWN(consumer)" in appendix
    assert CONSUMER_PROSE in primary
    assert consumer_namespace_violations(official) == []
    assert primary_analyst_violations(official) == []


def test_the_runtime_sequence_how_is_published_as_prose_not_as_the_token() -> None:
    """The RECOVERED-row path: the phase `how` is published in 正文, so the placeholder must arrive as prose.

    This is the path the real stored document takes (`.data/logs/official-document.json`, measured: the
    runtime-sequence line published ``consumed by `UNKNOWN(consumer)` `` before P-8), and it is the path where
    the PRODUCER-side rewrite (`reporting.dataflow_placeholder_prose` on the row's own text) is what does the
    work - the config-and-crypto chapter's prose comes from `analyst_report` instead.
    """
    document = _document(
        rows=[
            {
                "type": "assessment",
                "runtime_sequence": [
                    {
                        "type": "runtime_phase",
                        "id": "phase-decode",
                        "title": "Phase 3 — decode / config",
                        "status": "CANDIDATE",
                        "how": "decode path consumed by `UNKNOWN(consumer)`",
                        "catalog_ids": ["config-and-crypto"],
                        "runtime_observed": False,
                    }
                ],
            }
        ]
    )
    official = render_official_markdown(document)
    primary, appendix = split_analyst_markdown(official)
    assert "运行时序" in primary
    assert "UNKNOWN(consumer)" not in primary
    assert CONSUMER_PROSE in primary
    assert consumer_namespace_violations(official) == []


def test_the_namespace_checker_fails_on_a_wrong_sample_and_on_an_empty_body() -> None:
    """T7 G2: BOTH the wrong sample and the empty body must make the checker fail (today neither does)."""
    assert consumer_namespace_violations(WRONG_SAMPLE), "the checker accepted the dataflow placeholder in 正文"
    assert consumer_namespace_violations(""), "the checker accepted an EMPTY body"
    assert consumer_namespace_violations("   \n\t\n"), "the checker accepted a whitespace-only body"
    assert primary_analyst_violations(""), "primary_analyst_violations accepted an EMPTY body"
    assert primary_analyst_violations(WRONG_SAMPLE)


def test_the_empty_body_violation_is_reported_by_name() -> None:
    """T7 G2 names the empty body explicitly, so BOTH checkers must reject it, not just one."""
    empty_violations = primary_analyst_violations("")
    assert empty_violations, "primary_analyst_violations accepted an EMPTY body"
    assert any("empty" in item.casefold() for item in empty_violations), empty_violations
    assert primary_analyst_violations("   \n\t\n"), "primary_analyst_violations accepted a whitespace-only body"
    assert consumer_namespace_violations("") and any(
        "empty" in item.casefold() for item in consumer_namespace_violations("")
    )


def test_the_appendix_alone_still_satisfies_the_namespace_checker() -> None:
    """The appendix is where the token is allowed, so a body made only of the appendix must pass."""
    appendix_only = (
        f"{ANALYST_APPENDIX_HEADING}\n\n### 十问槽位\n\n- Consumer: UNKNOWN(consumer)\n"
    )
    assert consumer_namespace_violations(appendix_only) == []


# --------------------------------------------------------------------------- instruments this step cites
def test_the_real_projection_publishes_only_names_it_enumerates() -> None:
    """M5-style recomputation over the production projection, independent of the renderer."""
    fixture = _fixture()
    retrieved = _standalone_names(fixture)
    projection = build_string_fact_projection(_objects(fixture) + _attest_objects(fixture))
    enumerated = {
        str(item.get("value"))
        for item in projection
        if str(item.get("fact_class")) == "execution_api"
    }
    # The PRODUCER keeps the recovered bytes verbatim - the splice is real evidence and is not dropped.
    assert SPLICE in enumerated

    # What the RENDERER publishes as names is the set that must equal the standalone evidence set. The
    # difference is computed on the published tokens, because "the producer kept the blob" and "the narrative
    # called it a name" are different claims (that was the whole T6 defect).
    official = render_official_markdown(_document(string_facts=_real_projection(fixture)))
    published: list[str] = []
    for line in _name_listing_lines(official):
        for token in re.findall(r"`([^`]+)`", line):
            if token not in published:
                published.append(token)
    assert set(published) - retrieved == set(), sorted(set(published) - retrieved)
    # The body publishes a BOUNDED selection of the artifact's names, so the reverse difference is the selection
    # the projection's own `selection_limit` made - it must be a real subset, not an accident.
    assert set(published) <= retrieved

    # The producer hands the renderer the attestation that makes the split possible, and names its source.
    assert projection[0].get("attested_names"), "the producer published no attestation set"
    assert str(projection[0].get("attested_name_source") or "").strip()
    assert set(SPLICE_NAMES) <= {str(item) for item in projection[0]["attested_names"]}


@pytest.mark.parametrize("value", [SPLICE, "CreateProcessW", "WinHTTP export not found"])
def test_string_fact_class_still_classifies_the_real_rows(value: str) -> None:
    """A guard on the classifier itself: it must keep producing a class for the spliced row."""
    assert string_fact_class(value)
