"""An EMPTY container must not count as recovered semantics.

MEASURED DEFECT in the mechanism completeness score, found while checking whether a trace-payload change
was lossless.

`has_semantic_value(key, value)` is what decides whether a mechanism field counts toward
`mechanism_completeness_score` - the number the report prints as 「机制闭合率」 and the number the verifier
gate uses. Measured over the eight semantic fields:

    field                      empty dict   absent   empty list
    conditions                     True      False      False
    consumers                      True      False      False
    evidence_ids                   True      False      False
    inputs                         True      False      False
    outputs                        True      False      False
    side_effects                   True      False      False
    target                         True      False      False
    transformation_or_control      True      False      False

So `{}` scores as KNOWN while `[]` scores as unknown - an asymmetry with no justification in the contract,
since neither carries information.

Effect on a real score, measured:

    a mechanism whose semantic fields are ALL empty containers   85
    the same mechanism with those keys absent                     0

An 85-point mechanism that contains nothing at all. And the shape is not hypothetical: walking the published
document of task `50673002` found **16,228** empty dicts among 23,394 mechanism-semantic values (empty lists:
127). This is the objective's 「有证据但分析不完全」 measured inside the scoring function itself - coverage
reported for content that does not exist.

The objective also forbids the reverse error, so the fix must be narrow: an empty container is not semantics,
and a non-empty one still is, however it is spelled.
"""
from __future__ import annotations

from threat_report_agent.investigation.mechanism_completeness import (
    FIELD_WEIGHTS,
    has_semantic_value,
    mechanism_completeness_score,
)

SEMANTIC_FIELDS = sorted(
    {key for key, _weight in FIELD_WEIGHTS}
    | {"inputs", "outputs", "consumers", "transformation_or_control"}
)


def test_an_empty_container_is_not_semantics_whatever_shape_it_takes() -> None:
    """`{}` and `[]` and `''` all carry nothing, so all three must answer the same way."""
    for field in SEMANTIC_FIELDS:
        empty_dict = has_semantic_value(field, {})
        empty_list = has_semantic_value(field, [])
        empty_string = has_semantic_value(field, "")
        absent = has_semantic_value(field, None)
        assert empty_dict == empty_list == empty_string == absent, (
            f"{field}: empty containers disagree (dict={empty_dict}, list={empty_list}, "
            f"str={empty_string}, absent={absent}); an empty container carries no more semantics "
            "than an absent key"
        )
        assert empty_dict is False, f"{field}: an empty container scored as known semantics"


def test_a_mechanism_made_only_of_empty_containers_scores_zero() -> None:
    """The headline effect: 85 points for a mechanism with no content."""
    skeleton = {
        "mechanism_id": "m1",
        "inputs": {},
        "outputs": {},
        "consumers": {},
        "transformation_or_control": {},
        "conditions": {},
        "evidence_ids": [],
        "side_effects": {},
    }
    stripped = {key: value for key, value in skeleton.items() if value not in ({}, [])}
    empty_score = mechanism_completeness_score(skeleton)
    absent_score = mechanism_completeness_score(stripped)
    assert empty_score == absent_score == 0, (
        f"a mechanism of empty containers scored {empty_score} where the same mechanism with the keys "
        f"absent scored {absent_score}; a container with nothing in it is not recovered semantics"
    )


def test_a_non_empty_container_still_counts() -> None:
    """The fix must not become "containers never count" - real recovered semantics are dicts."""
    for field in SEMANTIC_FIELDS:
        assert has_semantic_value(field, {"RAX": {"kind": "constant", "value": "1"}}) is True, (
            f"{field}: a populated container stopped counting as semantics"
        )


def test_a_real_mechanism_keeps_its_score() -> None:
    """A mechanism with actual content must keep a positive score, so coverage is not deflated.

    The fixture is built from values the contract demonstrably accepts rather than from invented strings:
    the first version of this test used `"branch at instruction 92 unresolved"` for `conditions`, which
    `has_semantic_value` rejects on purpose (`_NAVIGATION_MARKERS`), and it failed on a correct
    implementation - the fixture over-constraint habit this work has hit repeatedly.
    """
    real = {
        "mechanism_id": "m2",
        "inputs": {"RAX": {"kind": "constant", "value": "0x60000000"}},
        "outputs": {"comparison": "RAX cmp 0x60000000"},
        "consumers": "VirtualQuery",
        "transformation_or_control": "environment gate on memory size",
        "evidence_ids": ["e1", "e2"],
        "side_effects": "no observed side effect",
    }
    score = mechanism_completeness_score(real)
    assert score > 0, "a populated mechanism scored zero after the empty-container fix"
    for field in ("inputs", "outputs", "consumers", "transformation_or_control", "evidence_ids"):
        assert has_semantic_value(field, real.get(field)) is True, (
            f"{field}: a populated field stopped counting"
        )
