"""The recovered-parent guard must accept a chained join and still reject a bare string.

``reporting._evidence_has_recovered_parent_identity`` decides whether the report may
say the parent identity was recovered or must keep printing ``UNKNOWN(parent
identity)``.  It has to separate two cases that look identical by string content:

* the sample merely *carries* ``explorer.exe`` as data -- not proof, keep UNKNOWN;
* the PPID join resolved OpenProcess -> UpdateProcThreadAttribute(PARENT_PROCESS)
  -> CreateProcessW inside one function and emitted a typed ``parent_selection``
  on the CreateProcess argument trace -- that is proof, and rejecting it made the
  report contradict the mechanism claim sitting right next to it.

The regression this pins: task 1359f2a6 had ``parent_selection: explorer.exe`` in
its evidence while the published report still read ``UNKNOWN(parent identity)`` and
"no Process32 enumeration chain".
"""

from threat_report_agent.report.reporting import (
    _evidence_has_recovered_parent_identity,
    _has_parent_handle_relation,
)


def _typed_join_row() -> dict[str, object]:
    """The real shape emitted by recover_parent_process_attribute + the relation."""
    return {
        "kind": "api_argument_trace",
        "nature": "STATIC_OBSERVED",
        "value": {
            "api": "CreateProcessW",
            "callsite": "140008dce",
            "function": "FUN_140004605",
            "parent_selection": "explorer.exe",
            "attribute": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
            "access_mask": "PROCESS_CREATE_PROCESS",
            "creation_flags": "0x09080008",
        },
    }


def _relation_row() -> dict[str, object]:
    return {
        "kind": "value_flow",
        "nature": "STATIC_DERIVED",
        "value": {
            "relation": "parent_handle_to_attribute",
            "api": "CreateProcessW",
            "parent_handle": {"handle_id": "openprocess:140008dce"},
            "attribute_handle": {"handle_id": "updateprocthreadattribute:140008dce"},
        },
    }


def _bare_string_row() -> dict[str, object]:
    return {
        "kind": "string",
        "nature": "STATIC_OBSERVED",
        "value": {
            "text": (
                "explorer.exeInitializeProcThreadAttributeList failed"
                "UpdateProcThreadAttribute failedCreateProcessW failed"
            )
        },
    }


def test_chained_typed_join_recovers_the_parent_identity() -> None:
    rows = [_typed_join_row(), _relation_row()]
    assert _has_parent_handle_relation(rows) is True
    assert _evidence_has_recovered_parent_identity(rows) is True


def test_bare_explorer_string_is_still_not_parent_identity() -> None:
    """Without the relation the same text stays unproven, as before this change."""
    assert _evidence_has_recovered_parent_identity([_typed_join_row()]) is False
    assert _evidence_has_recovered_parent_identity([_bare_string_row()]) is False
    assert _evidence_has_recovered_parent_identity([_bare_string_row(), _typed_join_row()]) is False


def test_typed_join_without_the_attribute_is_not_proof() -> None:
    row = _typed_join_row()
    del row["value"]["attribute"]  # type: ignore[index]
    assert _evidence_has_recovered_parent_identity([row, _relation_row()]) is False


def test_unknown_parent_selection_is_not_proof() -> None:
    row = _typed_join_row()
    row["value"]["parent_selection"] = "UNKNOWN(parent identity)"  # type: ignore[index]
    assert _evidence_has_recovered_parent_identity([row, _relation_row()]) is False


def test_a_genuinely_typed_parent_image_is_still_accepted_alone() -> None:
    """The pre-existing acceptance path must not regress."""
    row = {
        "kind": "api_argument_trace",
        "value": {"parent_image": "services.exe"},
    }
    assert _evidence_has_recovered_parent_identity([row]) is True
