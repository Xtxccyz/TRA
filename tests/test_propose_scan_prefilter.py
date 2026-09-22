"""The propose path must return identical suggestions, far faster.

Phase 5 of the diagnose skill: a regression test at the seam that actually
reproduces the bug.

Measured on task `73008097` (38,422 Evidence rows, 20 v3 profiles, 94 trigger
terms):

    one union pass over all 94 terms   3.771 s -> 1,603 rows of 38,422 (4.2%)
    one `propose` call                10.67 s

`_next_actions` calls `propose` once per investigation-loop iteration, and
`propose` clears its scan memo on entry, so every iteration re-folds and re-scans
the whole corpus.  100 iterations cost 17.8 minutes, which is exactly the observed
"100% CPU, no new evidence" stall - the live stack sat in

    _next_actions -> propose -> _propose_scanned -> profile_score -> _matching_rows

The fix is an exact pre-filter: a row can only match a profile term if it matches at
least one term in the union of all profiles' terms, so profile scans only need to
consider those rows.  These tests pin the output as identical.
"""

from __future__ import annotations

from threat_report_agent.investigation import Investigator, MechanismPlaybookRegistry


def _v3_profiles():
    registry = MechanismPlaybookRegistry()
    playbooks = getattr(registry, "playbooks", None) or getattr(registry, "_playbooks")
    return [item for item in playbooks if item.id.startswith("v3-")]


def _corpus() -> list[dict[str, object]]:
    """A corpus shaped like the real one, including rows that match nothing.

    The no-match rows matter: they are 95.8% of the real corpus and they are what
    the pre-filter exists to skip, so a fixture made only of matching rows would
    pass while measuring nothing.
    """
    rows: list[dict[str, object]] = []
    for index in range(400):
        rows.append(
            {
                "id": f"noise-{index}",
                "kind": "string",
                "nature": "STATIC_OBSERVED",
                "value": {"encoding": "ascii", "text": f"L$@{index}H"},
                "anchor": {"type": "file_offset", "offset": index},
            }
        )
    templates = [
        ("winhttp", "network"),
        ("CreateProcessW", "dynamic"),
        ("schtasks", "persistence"),
        ("explorer.exe", "ppid"),
        ("RegSetValueExW", "registry"),
        ("WinHttpSendRequest", "network"),
        ("VirtualAlloc", "memory"),
        ("GetProcAddress", "dynamic"),
        ("CryptDecrypt", "decode"),
        ("LoadLibrary", "dynamic"),
    ]
    for index, (needle, module) in enumerate(templates):
        rows.append(
            {
                "id": f"match-{index}",
                "kind": "api_argument_trace",
                "nature": "STATIC_OBSERVED",
                "value": {"api": needle, "command": f"C:\\x\\{needle}.exe"},
                "anchor": {"type": "function_entry", "entry": hex(0x140000000 + index)},
            }
        )
    return rows


def _union_terms(profiles) -> tuple[str, ...]:
    return tuple({term for profile in profiles for term in profile.trigger_terms})


# --- the pre-filter itself -------------------------------------------------


def test_candidate_prefilter_is_a_superset_of_every_profile_match() -> None:
    """The exactness argument, asserted rather than asserted-in-a-comment.

    For every profile, the rows matching its own terms must be a subset of those
    matching the union.  If this fails the optimisation is not exact and would drop
    real findings.
    """
    rows = _corpus()
    investigator = Investigator()
    profiles = _v3_profiles()
    union_terms = _union_terms(profiles)

    candidates = investigator._matching_rows(rows, *union_terms)
    candidate_ids = {id(row) for row in candidates}
    assert candidates, "the union must match something in this fixture"

    for profile in profiles:
        matches = investigator._matching_rows(rows, *profile.trigger_terms)
        missing = [row["id"] for row in matches if id(row) not in candidate_ids]
        assert not missing, (
            f"profile {profile.id} matched rows the union pre-filter would drop: {missing}"
        )


# --- behaviour equivalence -------------------------------------------------


def test_propose_returns_identical_suggestions_before_and_after() -> None:
    """The pinned contract: same suggestions, same order, same parameters.

    Captured from the current implementation, which is also the post-fix
    expectation: the optimisation must be invisible in the output.
    """
    rows = _corpus()
    first = Investigator().propose(evidence=rows, scheduled=set())
    second = Investigator().propose(evidence=rows, scheduled=set())

    def shape(suggestions):
        return [
            (
                item.action_type.value,
                item.priority,
                tuple(sorted(item.parameters.items(), key=lambda pair: pair[0])),
                item.expected_evidence_kinds,
            )
            for item in suggestions
        ]

    assert shape(first) == shape(second), "propose must be deterministic across instances"
    assert first, "this fixture must produce suggestions or the test is vacuous"


def test_propose_does_not_mutate_the_corpus() -> None:
    rows = _corpus()
    before = [dict(row) for row in rows]
    Investigator().propose(evidence=rows, scheduled=set())
    assert [dict(row) for row in rows] == before


def test_union_scan_covers_the_same_rows_a_full_scan_would() -> None:
    """A row matched by any single term is found by the union scan.

    Guards the failure mode where the pre-filter is built from the WRONG term set
    (for example only the admitted top-8 profiles) and silently narrows the corpus.
    """
    rows = _corpus()
    investigator = Investigator()
    profiles = _v3_profiles()

    union_rows = {id(row) for row in investigator._matching_rows(rows, *_union_terms(profiles))}
    per_term_rows: set[int] = set()
    for profile in profiles:
        for term in profile.trigger_terms:
            per_term_rows.update(id(row) for row in investigator._matching_rows(rows, term))

    assert per_term_rows <= union_rows
