"""Emulation must not spend worker turns on windows that cannot succeed.

Two measured wastes, both eliminated here.

**D4 — a Linux adapter is handed a Windows PE.** `controlled_emulation_windows` appended a Qiling window
for anything that was not an ELF: 64 bytes of a Windows PE at entry `0x1000000`. The Qiling adapter rejects
it on `payload[:4] != b"\\x7fELF"` and returns `UNSUPPORTED / NOT_LINUX_ELF`, so the outcome was decided
when the window was built. Measured across the database: **418** evidence rows with anchor role
`os_mismatch`, **none** carrying an observation — roughly a sixth of all simulation rows.

**D1 — the PE entry of a bootstrap trampoline.** The 白象 entry (`0x402484`) is

    push 0x4025f0 ; call <IAT thunk> ; <zero padding>

so emulating it executes 3 instructions, faults on the unbound import, and observes nothing; binding the
import still dies 2 instructions later in the padding (`.scratch/probe-iat-stub.py`). Measured across the
database: **71** FAILED `pe_entry` windows against 39 SUCCEEDED.

Both are now recorded as explicit decisions with a reason, so the reader learns why the adapter does not
apply - rather than reading a failure as "the sample resisted analysis".
"""
from __future__ import annotations

import struct

from threat_report_agent.emulation_plan import (
    _entry_is_bootstrap_trampoline,
    controlled_emulation_windows,
)

SAMPLE = (
    r"D:\test\白象_revers_AGENT"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
)


def _pe_summary(content: bytes) -> dict:
    pe = struct.unpack_from("<I", content, 0x3C)[0]
    opt = pe + 24
    image_base = struct.unpack_from("<I", content, opt + 28)[0]
    entry_rva = struct.unpack_from("<I", content, opt + 16)[0]
    count = struct.unpack_from("<H", content, pe + 6)[0]
    opt_size = struct.unpack_from("<H", content, pe + 20)[0]
    table = opt + opt_size
    sections = []
    for index in range(count):
        off = table + index * 40
        name = content[off : off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", content, off + 8)
        sections.append(
            {
                "name": name,
                "virtual_address": vaddr,
                "virtual_size": vsize,
                "raw_size": raw_size,
                "raw_offset": raw_ptr,
            }
        )
    return {
        "image_base": image_base,
        "entry_rva": entry_rva,
        "machine": struct.unpack_from("<H", content, pe + 4)[0],
        "sections": sections,
    }


def _sample() -> bytes | None:
    try:
        with open(SAMPLE, "rb") as handle:
            return handle.read()
    except OSError:
        return None


# --------------------------------------------------------------------------- D4
def test_a_windows_pe_is_not_dispatched_to_the_linux_adapter() -> None:
    content = _sample()
    if content is None:
        return
    windows = controlled_emulation_windows(
        content, _pe_summary(content), functions=(), traces=(),
        allow_speakeasy=False, allow_qiling=True, max_windows=8,
    )
    qiling = [w for w in windows if w.get("simulator") == "qiling"]
    assert qiling, "the qiling applicability decision disappeared entirely"
    for window in qiling:
        assert window.get("skip_reason") == "qiling_requires_linux_elf", (
            "a Windows PE is still dispatched to the Linux-only Qiling adapter, which can only return "
            "NOT_LINUX_ELF"
        )
        assert not window.get("input_bytes"), "a skipped window must not carry bytes to emulate"
    roles = [(w.get("anchor") or {}).get("role") for w in windows]
    assert "os_mismatch" not in roles, "the always-failing os_mismatch window is still being produced"


def test_the_skip_states_why_rather_than_reporting_a_failure() -> None:
    content = _sample()
    if content is None:
        return
    windows = controlled_emulation_windows(
        content, _pe_summary(content), functions=(), traces=(),
        allow_speakeasy=False, allow_qiling=True, max_windows=8,
    )
    anchor = next(
        (w.get("anchor") or {}) for w in windows if w.get("simulator") == "qiling"
    )
    reason = str(anchor.get("reason") or "")
    assert reason, "the skip carries no reason, so the reader cannot tell why"
    assert "Linux" in reason or "ELF" in reason


def test_an_elf_is_still_dispatched_to_qiling() -> None:
    """The guard must not disable the adapter for the artifacts it does support."""
    # A minimal ELF header is enough: the branch keys on the magic.
    elf = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 120
    windows = controlled_emulation_windows(
        elf, {}, functions=(), traces=(), allow_speakeasy=False, allow_qiling=True, max_windows=8,
    )
    qiling = [w for w in windows if w.get("simulator") == "qiling"]
    assert qiling, "no qiling window was produced for an ELF"
    assert not qiling[0].get("skip_reason"), "a real ELF must not be skipped"
    assert qiling[0].get("input_bytes"), "an ELF window must carry the image bytes"


# --------------------------------------------------------------------------- D1
def test_the_bootstrap_trampoline_entry_is_recognised() -> None:
    content = _sample()
    if content is None:
        return
    summary = _pe_summary(content)
    assert _entry_is_bootstrap_trampoline(content, summary, summary["entry_rva"]), (
        "the VB6 bootstrap trampoline was not recognised, so a useless pe_entry window is still produced"
    )


def test_a_native_entry_is_not_mistaken_for_a_trampoline() -> None:
    """A wrong skip hides real behaviour, so the test must pass on an ordinary prologue."""
    content = _sample()
    if content is None:
        return
    summary = _pe_summary(content)
    patched = bytearray(content)
    text = next(s for s in summary["sections"] if s["name"] == ".text")
    offset = text["raw_offset"]
    # push ebp ; mov ebp, esp ; sub esp, 0x10 ; mov eax, [0] ; test eax, eax
    patched[offset : offset + 12] = bytes.fromhex("558bec83ec10a10000000085c0")
    assert not _entry_is_bootstrap_trampoline(bytes(patched), summary, summary["entry_rva"])


def test_the_entry_trampoline_is_recorded_as_a_decision() -> None:
    content = _sample()
    if content is None:
        return
    summary = _pe_summary(content)
    windows = controlled_emulation_windows(
        content, summary, functions=(), traces=(),
        allow_speakeasy=False, allow_qiling=False, max_windows=8,
    )
    unicorn = [w for w in windows if w.get("simulator") == "unicorn"]
    assert unicorn, "the entry decision vanished, so nothing records why no entry window ran"
    assert all(w.get("skip_reason") == "pe_entry_is_bootstrap_trampoline" for w in unicorn)
    assert all(not w.get("input_bytes") for w in unicorn)
