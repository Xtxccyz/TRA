"""隔离模拟章节必须说明「观测到了什么」，而不只是「为什么停了」。

MEASURED gap this pins: the `emulation_status` projection carried only
`status`/`stop_reason`/`limitations`, so a run that observed **256 API calls** and made
**1,031 modelled VB6 runtime calls** rendered as a bare failure. `FAILED` and "observed 256 calls"
are not mutually exclusive, and a reader needs both: the stop reason says where the emulator halted,
the observation counts say how much evidence it produced before that point.

The projection now aggregates observations (`observed_apis`, `shim`) instead of copying all 259 raw
entries, because what a reader needs is which APIs were touched and how often.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import _emulation_status_section


def _row(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "simulator": "speakeasy",
        "status": "FAILED",
        "stop_reason": "EXECUTION_ERROR",
        "limitations": ["Speakeasy observed 256 API call(s) ..."],
        "observed_apis": {"MSVBVM60.__vbaStrCopy": 1028, "MSVBVM60.__vbaChkstk": 1},
        "shim": {"registered": 132, "modelled_calls": 1031, "strings_observed": 1028},
    }
    result.update(overrides)
    return {"type": "emulation_status", "overall": "FAILED", "attempted": True, "results": [result]}


def test_observed_api_counts_are_published() -> None:
    text = "\n".join(_emulation_status_section([_row()]))

    assert "已观测 API 调用" in text
    assert "1029" in text, "the total call count (1028 + 1) must appear"
    assert "MSVBVM60.__vbaStrCopy" in text


def test_shim_summary_is_published_with_its_boundary() -> None:
    text = "\n".join(_emulation_status_section([_row()]))

    assert "VB6 运行时 stub" in text
    assert "132" in text and "1031" in text and "1028" in text
    assert "建模语义" in text, "modelled semantics must not read as real runtime return values"


def test_single_occurrence_apis_omit_the_count_suffix() -> None:
    text = "\n".join(_emulation_status_section([_row(observed_apis={"a": 1})]))

    assert "`a`" in text
    assert "`a`×1" not in text, "a count of one is noise"


def test_missing_observation_fields_render_nothing_extra() -> None:
    """An older or non-observing result must not produce an empty claim."""
    text = "\n".join(
        _emulation_status_section([_row(observed_apis={}, shim={})])
    )

    assert "已观测 API 调用" not in text
    assert "VB6 运行时 stub" not in text
    assert "speakeasy" in text, "the simulator and its stop reason must still be reported"


def test_malformed_observation_fields_do_not_raise() -> None:
    for bad in (None, "not-a-mapping", [], 42):
        text = "\n".join(_emulation_status_section([_row(observed_apis=bad, shim=bad)]))
        assert "speakeasy" in text


def test_ledger_placeholders_never_reach_the_body() -> None:
    """A Ghidra placeholder is a ledger identifier, not an API name.

    MEASURED failure this pins: forwarding observed API names published `FUN_xxxx` into the primary
    body, and the run FAILED with "analyst report still contains ledger residue: primary report
    contains FUN_ ledger names". The projection drops them; this asserts the chapter cannot print one
    even if a projection is built elsewhere.
    """
    text = "\n".join(
        _emulation_status_section(
            [_row(observed_apis={"FUN_0040d2c0": 7, "MSVBVM60.__vbaStrCopy": 3})]
        )
    )

    assert "FUN_" not in text, "a ledger placeholder must never be published"
    assert "MSVBVM60.__vbaStrCopy" in text, "the real API must still be reported"
    assert "3" in text, "the total must count only the visible APIs"


def test_all_placeholder_observations_render_no_claim() -> None:
    """If every observed name is a placeholder there is nothing publishable; say nothing."""
    text = "\n".join(
        _emulation_status_section([_row(observed_apis={"FUN_0040d2c0": 2})])
    )

    assert "FUN_" not in text
    assert "已观测 API 调用" not in text


def test_the_blocking_dependency_is_filtered_by_the_pages_own_gate() -> None:
    """The chapter must not be the place a ledger-shaped name reaches the primary body (T2 audit MED).

    The sibling `observed_apis` path re-filters `FUN_` identifiers in the chapter and is pinned by
    `test_ledger_placeholders_never_reach_the_body`; this path had no such filter, so the projection was the
    only guard. The name is SIMULATOR-SUPPLIED - an emulated image's import/module name - so it is
    sample-influenced input, and a crafted name containing a UUID or a ledger phrase would have made the
    render RAISE (`primary_analyst_violations` runs on the finished body) instead of dropping one value.
    """
    text = "\n".join(
        _emulation_status_section(
            [
                _row(
                    observed_apis={},
                    shim={},
                    unsupported_apis=[
                        "MSVBVM60.ordinal_648",              # a real symbol: must be published
                        "FUN_0040d2c0",                      # a ledger placeholder
                        "pipeline completion",               # a ledger phrase the gate rejects
                        "11111111-2222-3333-4444-555555555555",  # a UUID the gate rejects
                        "   ",                               # whitespace
                        "",
                    ],
                )
            ]
        )
    )

    assert "MSVBVM60.ordinal_648" in text, "the real dependency must still be named"
    assert "FUN_" not in text
    assert "pipeline completion" not in text
    assert "11111111-2222" not in text, "a UUID reached the primary body"


def test_a_lowercase_placeholder_is_also_filtered() -> None:
    """The producer's rule is case-INSENSITIVE (`"FUN_" not in stalled.upper()`); the page gate's is not.

    MEASURED gap this pins (T2 fifth audit, LOW): `fun_0040d2c0` passed `_SYMBOL_RE` and did NOT trip
    `primary_analyst_violations`, because the gate's `_FUN_NAME_RE` is case-sensitive - so the chapter's own
    filter was one case-fold weaker than the projection it mirrors. And the non-regression in the same test:
    the fix must be ANCHORED, not the substring test that used to drop a legitimate image name.
    """
    text = "\n".join(
        _emulation_status_section(
            [
                _row(
                    observed_apis={},
                    shim={},
                    unsupported_apis=["fun_0040d2c0", "Fun_Dispatch.dll", "MSVBVM60.ordinal_648"],
                )
            ]
        )
    )

    assert "fun_0040d2c0" not in text, "a lowercase ledger placeholder reached the primary body"
    assert "Fun_Dispatch.dll" in text, "an anchored rule must not drop a legitimate image name"
    assert "MSVBVM60.ordinal_648" in text


def test_a_truncated_blocker_list_says_it_is_truncated() -> None:
    """A capped list must state the true total - the rule this chapter already applies to API counts.

    The fixture mixes PUBLISHABLE names with REJECTED ones on purpose (T2 audit, LOW): an earlier version used
    seven all-publishable names, which cannot tell "the count is computed after filtering" from "the count is
    the raw input length". Both the named total and the unexpanded remainder must reflect only what survived.
    """
    publishable = [f"KERNEL32.ordinal_{index}" for index in range(6)]
    rejected = ["FUN_0040d2c0", "pipeline completion"]
    text = "\n".join(
        _emulation_status_section(
            [_row(observed_apis={}, shim={}, unsupported_apis=publishable + rejected)]
        )
    )

    assert "按名称去重后 `6` 个" in text, (
        f"the total counts values the filter rejected, or names the wrong unit: {text[-320:]}"
    )
    assert "另有 `2` 个未展开" in text, "six publishable names print four, so two must be reported unexpanded"
    assert "记录中共 `8` 个" in text, (
        "the count is post-filter, so the recorded total must be stated too - otherwise a reader cannot tell "
        f"'the record holds six names' from 'names were dropped' (T2 fifth audit): {text[-300:]}"
    )
    assert "FUN_" not in text
    assert "pipeline completion" not in text


def test_an_exactly_full_blocker_list_does_not_claim_a_remainder() -> None:
    """`M == 0` must stay silent: 「另有 `0` 个未展开」 would be a false claim (T2 third audit, LOW)."""
    text = "\n".join(
        _emulation_status_section(
            [_row(observed_apis={}, shim={}, unsupported_apis=[f"KERNEL32.ordinal_{i}" for i in range(4)])]
        )
    )

    assert "另有" not in text, f"an exactly-four list claimed a remainder: {text[-260:]}"
    assert "按名称去重后 `4` 个" in text, "the unit must name what the list actually holds: deduped NAMES"


def test_a_stalled_run_whose_names_are_all_unpublishable_still_says_it_stalled() -> None:
    """The all-filtered case is the hazard T2 exists to remove, relocated into the filter.

    Every value being unpublishable previously produced NO line at all, which is indistinguishable in the body
    from a run that never stalled - exactly the absence-as-clean-result reading this whole item is about. The
    statement needs no number to be honest, and deliberately states none: the record cannot say how many calls
    the run made.
    """
    text = "\n".join(
        _emulation_status_section(
            [
                _row(
                    observed_apis={},
                    shim={},
                    # Reachable all-filtered inputs: a gate-rejected name and a `_SYMBOL_RE`-rejected one. NOT a
                    # `FUN_` placeholder - the projection drops those before the chapter (fourth audit, LOW).
                    unsupported_apis=["11111111-2222-3333-4444-555555555555", "name with spaces"],
                )
            ]
        )
    )

    assert "未被建模的运行时调用" in text, "a stalled run with unpublishable names rendered as if it never stalled"
    assert "无法在正文中发布" in text, "the body does not say WHY no dependency name is shown"
    assert "FUN_" not in text
    assert "pipeline completion" not in text
    assert "另有" not in text, "a count of nothing must not be stated"


def test_the_blocking_dependency_reaches_the_chapter_through_the_projection() -> None:
    """The CHAIN, not one end of it (T2 audit finding 5).

    Both halves of T2 were previously tested with hand-built fixtures, which cannot catch a broken hop. This
    drives the REAL projection, so the whitelist inside `build_emulation_status_projection` is exercised: it
    is a whitelist, and a field it does not carry never reaches the body - which is exactly where the first
    version of this work stopped, leaving the dependency structured in the evidence and absent from the
    report.
    """
    from threat_report_agent.analyst_report import _emulation_status_section as chapter
    from threat_report_agent.reporting import build_emulation_status_projection

    evidence = {
        "ev-1": {
            "id": "ev-1",
            "kind": "simulation_result",
            "value": {
                "status": "FAILED",
                "simulator": "speakeasy",
                "stop_reason": "EXECUTION_ERROR",
                "observations": [
                    {"event": "unsupported_api", "name": "MSVBVM60.ordinal_648", "kind": "unsupported"},
                    {"event": "summary", "elapsed_ms": 12, "api_count": 0},
                ],
            },
            "anchor": {},
        }
    }
    projection = build_emulation_status_projection(evidence)
    assert projection["results"], "the projection dropped the simulation result entirely"
    assert projection["results"][0]["unsupported_apis"] == ["MSVBVM60.ordinal_648"], (
        "the projection whitelist dropped the blocking dependency, so the chapter can never name it and a "
        "reader is left parsing the prose limitation"
    )

    text = "\n".join(chapter([projection]))
    assert "MSVBVM60.ordinal_648" in text, "the chapter does not name the dependency that bounded the run"
    assert "已观测 API 调用" not in text, (
        "a blocker must not be published as an observed API call; the run never reached one"
    )


def test_the_blocking_dependency_is_not_published_when_there_is_none() -> None:
    """Non-regression: a run that stalled on nothing must not invent a blocker."""
    from threat_report_agent.analyst_report import _emulation_status_section as chapter
    from threat_report_agent.reporting import build_emulation_status_projection

    evidence = {
        "ev-1": {
            "id": "ev-1",
            "kind": "simulation_result",
            "value": {
                "status": "SUCCEEDED",
                "simulator": "unicorn",
                "stop_reason": "END_ADDRESS",
                "observations": [
                    {"event": "api", "name": "KERNEL32.InitializeCriticalSection"},
                    {"event": "summary", "elapsed_ms": 7, "api_count": 1},
                ],
            },
            "anchor": {},
        }
    }
    text = "\n".join(chapter([build_emulation_status_projection(evidence)]))
    assert "未被建模的运行时调用" not in text


def test_a_run_that_observed_no_api_says_so() -> None:
    """MEASURED gap (plan T2 / D1): "observed nothing" was expressed ONLY by empty lists.

    Measured on the real Resume run: every Unicorn result carried `attempted_apis=[]`,
    `unsupported_apis=[]` and `status="SUCCEEDED"`, and the published chapter therefore said

        - **unicorn** 状态 `SUCCEEDED`　停止原因 `UNMAPPED_DATA`

    with nothing to tell a reader that the run produced NO observation at all. A `SUCCEEDED` line plus a
    generic `UNMAPPED_DATA` token reads as "emulation ran and was fine", which is the EC-1 hazard this
    product exists to avoid: absence presented as a clean result.

    The discriminator is `observation_count`, which the projection already carries: it is the number of RAW
    observations the result held. With observations present but no API among them, the run genuinely ran and
    genuinely observed no API - that is a fact the body must state. With `observation_count == 0` the result
    carried no observations at all, which is a DIFFERENT statement ("nothing was recorded") and must not be
    rendered as if the run had been observed.

    This test deliberately uses a wording that does NOT contain 「已观测 API 调用」, so it stays compatible
    with `test_missing_observation_fields_render_nothing_extra`: that test forbids a false POSITIVE claim of
    observation, while this one requires an honest NEGATIVE.
    """
    text = "\n".join(
        _emulation_status_section(
            [_row(status="SUCCEEDED", stop_reason="UNMAPPED_DATA", observed_apis={}, shim={},
                  observation_count=17)]
        )
    )

    assert "未观测到任何 API" in text, (
        "a run that executed but observed no API is published as a bare SUCCEEDED line; a reader cannot tell "
        "it apart from a run that observed a great deal"
    )
    assert "已观测 API 调用" not in text, "the statement must be the honest negative, not a claim of observation"


def test_a_result_with_no_observations_at_all_is_not_reported_as_an_observed_run() -> None:
    """D3: "the simulator never ran" and "it ran and saw no API" are different honest conclusions.

    `observation_count == 0` means the result carried no observations whatsoever - an older or non-observing
    projection. Rendering that as 「未观测到任何 API」 would assert something the record does not support,
    which is the same error in the opposite direction.
    """
    text = "\n".join(
        _emulation_status_section(
            [_row(status="SUCCEEDED", stop_reason="UNMAPPED_DATA", observed_apis={}, shim={},
                  observation_count=0)]
        )
    )

    assert "未观测到任何 API" not in text, (
        "a result that carried no observations was reported as a run that observed no API"
    )
    assert "speakeasy" in text, "the simulator must still be named"
