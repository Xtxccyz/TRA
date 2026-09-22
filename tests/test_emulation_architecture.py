"""A 32-bit sample must not be emulated as 64-bit code.

MEASURED DEFECT (task `0291d4b1`, PE machine 0x014c = i386). The Unicorn result recorded:

    architecture  : x86_64
    entry_address : 0x408d70
    observations  : {"address": "0x408d70", "event": "instruction", "size": 4059165169}
                    {"errno": 10, "event": "error", "type": "UcError"}
                    {"elapsed_ms": 6, "event": "summary", "instructions": 1}
    status        : FAILED      stop_reason: EMULATOR_ERROR

An "instruction" 4,059,165,169 bytes long, errno 10 (`UC_ERR_EXCEPTION`), one instruction
executed: the decoder was reading 32-bit code as 64-bit and faulted immediately. Two independent
causes, both structural:

1. `emulation_plan.add_unicorn` builds its window dict WITHOUT an `architecture` key, so
   `unicorn_granted_windows_for_worker` defaults it to `"x86_64"`
   (`str(window.get("architecture") or "x86_64")`).
2. `_unicorn_adapter` hardcodes `Uc(UC_ARCH_X86, UC_MODE_64)` and imports only the 64-bit
   register constants, then REJECTS anything that is not `x86_64`/`amd64` with
   `ARCHITECTURE_UNSUPPORTED` - so it never sees the truth either way.

The PE summary already knows: `static_analysis` sets `code_signals.architecture` to `"x86-64"`
or `"x86"`. The fact existed and no consumer read it - the same shape as R1/R2.

Consequence: emulation was silently useless for every 32-bit sample, which is a large share of
real malware, and the failure was reported as an emulator error rather than an architecture bug.
"""

from __future__ import annotations

from threat_report_agent.emulation_plan import (
    controlled_emulation_windows,
    unicorn_granted_windows_for_worker,
)

PE32 = {
    "image_base": 0x400000,
    "entry_rva": 0x1000,
    "machine": 0x014C,
    "code_signals": {"architecture": "x86"},
    "sections": [
        {
            "virtual_address": 0x1000,
            "virtual_size": 0x200,
            "raw_size": 0x200,
            "raw_offset": 0x40,
        }
    ],
}
PE64 = {
    "image_base": 0x140000000,
    "entry_rva": 0x1000,
    "machine": 0x8664,
    "code_signals": {"architecture": "x86-64"},
    "sections": [
        {
            "virtual_address": 0x1000,
            "virtual_size": 0x200,
            "raw_size": 0x200,
            "raw_offset": 0x40,
        }
    ],
}
CONTENT = b"MZ" + b"\x00" * 62 + b"\x90" * 0x200


def test_a_32bit_pe_window_carries_x86_not_x86_64() -> None:
    """The window must state the sample's architecture; defaulting to x86_64 is the defect."""
    windows = controlled_emulation_windows(CONTENT, PE32, (), allow_speakeasy=False)
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn, "no Unicorn window was produced for a valid PE32"
    for window in unicorn:
        assert str(window.get("architecture") or "").casefold() in {"x86", "i386", "x86_32"}, (
            "a 32-bit sample's window did not carry its architecture; "
            f"got {window.get('architecture')!r}, which the worker then treats as x86_64"
        )


def test_a_64bit_pe_window_still_carries_x86_64() -> None:
    """The fix must not make every sample 32-bit."""
    windows = controlled_emulation_windows(CONTENT, PE64, (), allow_speakeasy=False)
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    for window in unicorn:
        assert str(window.get("architecture") or "").casefold() in {"x86_64", "amd64"}, (
            f"a 64-bit sample's window lost its architecture: {window.get('architecture')!r}"
        )


def test_the_worker_serialisation_preserves_the_architecture() -> None:
    """`unicorn_granted_windows_for_worker` must forward it, not substitute a default."""
    granted = unicorn_granted_windows_for_worker(
        (
            {
                "simulator": "unicorn",
                "input_bytes": b"\x90" * 16,
                "entry_address": 0x401000,
                "architecture": "x86",
                "anchor": {"function_entry": "0x401000", "role": "pe_entry"},
            },
        )
    )
    assert granted, "the window was dropped"
    assert granted[0]["architecture"] == "x86", (
        "the serialised grant replaced the architecture with a default, so the worker cannot "
        f"know the mode: {granted[0]['architecture']!r}"
    )
