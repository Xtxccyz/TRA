"""Hoisting the command-line string index out of the per-function loop.

MEASURED STALL. A fresh 1 MB PE run sat at exactly 7,332 evidence rows with the API at 100% CPU for
325 s and the HTTP event loop dead. `faulthandler` (armed via `SIGUSR1`) named the frame:

    static_analysis.py:4296 in _address_variants
    static_analysis.py:4303 in recover_process_creation_arguments
    service.py:19573 in _record_ghidra_evidence

`recover_process_creation_arguments` calls `_address_variants` for EVERY entry of
`strings_by_address` to build a `canonical_strings` lookup, and the caller invokes it once per
analysed function - so the whole mapping is re-indexed per function. Measured on this machine:

    mapping size     one call      x 703 functions
    10,000 strings   0.039 s        27 s
    100,000 strings  0.332 s       233 s   (3.9 min)
    500,000 strings  2.032 s      1428 s  (23.8 min)

That is the O(functions x strings) cost the objective calls pathological, and it is paid inside a
single GIL-holding call, which is why nothing else in the process could run.

These tests pin the fix: the index is built once and passed in, and callers that do not pass one still
get correct results (the parameter is an optimisation, not a new requirement).
"""
from __future__ import annotations

from pathlib import Path

from threat_report_agent.static_analysis import (
    build_command_string_index,
    process_import_thunks,
    recover_process_creation_arguments,
)

# `CreateProcessW` at this thunk, called from the entry function - the shape the real exporter emits.
CREATE_PROCESS_THUNK = {0x140046948: "CreateProcessW"}


def _function(call_address: int = 0x140038AE0) -> dict:
    return {
        "entry": "0x140038ae0",
        "instructions": [
            {"address": "0x140038ae0", "text": "SUB RSP, 0x48"},
            {"address": "0x140038ae4", "text": "LEA RDX, [0x140050000]"},
            {"address": "0x140038aec", "text": "CALL qword ptr [PTR_CreateProcessW_140046948]"},
            {"address": "0x140038af2", "text": "MOV ECX, 0x08000000"},
            {"address": "0x140038af8", "text": "RET"},
        ],
    }


MAPPING = {
    "0x140050000": "C:\\Windows\\System32\\cmd.exe /c whoami",
    "0x140050040": "unrelated",
}


def test_a_prebuilt_index_yields_the_same_result_as_the_internal_one() -> None:
    """The optimisation must not change the answer, including which string wins."""
    internal = recover_process_creation_arguments(
        _function(), MAPPING, thunks=process_import_thunks([{"imports": []}]) or CREATE_PROCESS_THUNK
    )
    index = build_command_string_index(MAPPING)
    hoisted = recover_process_creation_arguments(
        _function(), MAPPING,
        thunks=process_import_thunks([{"imports": []}]) or CREATE_PROCESS_THUNK,
        string_index=index,
    )
    assert hoisted == internal, "passing a prebuilt index changed the recovered arguments"


def test_the_index_resolves_every_address_spelling_the_lookup_uses() -> None:
    """`_address_variants` exists because Ghidra renders one address several ways.

    The index must answer for all of them, or hoisting it would silently drop matches that the
    per-call build used to find - a correctness regression disguised as a speedup.
    """
    index = build_command_string_index(MAPPING)
    # The exact key, the bare hex, and the decimal form must all resolve to the same string.
    for spelling in ("0x140050000", "140050000", str(0x140050000)):
        found = index.get(spelling.casefold()) or index.get(spelling)
        assert found == "C:\\Windows\\System32\\cmd.exe /c whoami", (
            f"address spelling {spelling!r} no longer resolves through the hoisted index"
        )


def test_an_empty_or_absent_index_still_works() -> None:
    """A caller with no strings must not crash and must not invent one."""
    assert build_command_string_index({}) == {}
    assert build_command_string_index(None) == {}
    result = recover_process_creation_arguments(_function(), {}, string_index={})
    assert result == ()


def test_the_service_call_site_binds_every_name_it_uses() -> None:
    """A hoist is only a fix if the module that calls it can resolve the new name.

    The first version of this change added `build_command_string_index` to the per-artifact loop in
    `service.py` without importing it. Every test above still passed, because they exercise
    `static_analysis` directly; the deployed product then failed a live 1 MB run with
    `NameError: name 'build_command_string_index' is not defined` after burning 100 s of CPU. This
    asserts the binding through the module that actually runs it.
    """
    import threat_report_agent.service as service_module

    assert hasattr(service_module, "build_command_string_index"), (
        "service.py calls build_command_string_index but does not import it"
    )
    # And the per-artifact index must be built OUTSIDE the per-function loop: the whole point of the
    # hoist is that the mapping is indexed once, so the call must not sit inside the `for function`
    # block. A source-level check is the only way to lock that in, since the loop is inline.
    source = Path(service_module.__file__).read_text(encoding="utf-8")
    index_call = source.find("command_string_index = build_command_string_index(")
    loop_start = source.find("for function in function_rows:")
    assert index_call != -1, "the per-artifact index is no longer built"
    assert loop_start != -1, "the per-function loop moved; re-anchor this test"
    assert index_call < loop_start, (
        "build_command_string_index is now called INSIDE the per-function loop, which restores the "
        "O(functions x strings) cost this change removed"
    )
    # EVERY per-function recovery that needs the index must receive it. Two functions had their own
    # copy of the build loop; threading only the first left the second rebuilding it 703 times, which
    # is exactly what the second captured stack showed.
    for call in ("recover_process_creation_arguments", "recover_dynamic_api_resolutions"):
        assert f"{call}(" in source
    assert source.count("string_index=command_string_index") >= 2, (
        "a per-function recovery call is still building its own index instead of taking the "
        "per-artifact one"
    )


def test_the_masked_xor_matches_the_per_byte_definition() -> None:
    """The C-level decode must produce the same bytes as the per-byte formula it replaced.

    `recover_static_xor_configs` builds ~1.52M decode candidates for a 551 KB sample, and the module's
    NOTE claimed this could not be done without a per-byte generator because the mask is positional.
    The mask is positional but PERIODIC, so it can be materialised and applied with
    `bytes(map(operator.xor, ...))`: measured 1.31x on the decode itself, projecting `analyze_bytes`
    from 16.0 s to ~13.2 s.

    A speedup that changes the decoded bytes would silently change which configs are recovered, so the
    equivalence is asserted directly against the original formula.
    """
    import os

    from threat_report_agent.static_analysis import _masked_xor

    table = bytes(range(0x40, 0x50))
    for length in (10, 16, 24, 31, 32, 48, 64, 0, 1, 255):
        cipher = os.urandom(length)
        for counter0 in (0, 3):
            for step in (1, 7):
                expected = bytes(
                    cipher[i] ^ table[i % 16] ^ ((counter0 + i * step) & 0xFF)
                    for i in range(length)
                )
                assert _masked_xor(cipher, table, counter0, step) == expected, (
                    f"masked XOR diverged at length={length} counter0={counter0} step={step}"
                )


def test_the_mask_cache_is_keyed_on_the_key_table() -> None:
    """Two different key tables must not share a mask, or one sample's decode corrupts another's."""
    import os

    from threat_report_agent.static_analysis import _masked_xor

    cipher = os.urandom(32)
    first = _masked_xor(cipher, bytes(range(0x40, 0x50)), 0, 1)
    second = _masked_xor(cipher, bytes(range(0x10, 0x20)), 0, 1)
    assert first != second, "the mask cache ignored the key table, so a later call reused a stale mask"
    assert first == _masked_xor(cipher, bytes(range(0x40, 0x50)), 0, 1), "cache broke repeatability"
