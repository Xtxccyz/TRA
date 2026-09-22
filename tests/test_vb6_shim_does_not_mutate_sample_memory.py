"""The shim must not write to the sample's own memory, and dest must be reported as unobservable.

Why this file is separate: `FakeEmu` in `test_vb6_runtime_shim.py` has NO `mem_write` method at all, so the
handler's write-back raised `AttributeError`, was swallowed by the handler's own `except Exception`, and
**no test could observe that the shim was overwriting the sample's hex record table**. The corruption was
invisible twice over. This file uses an emulator that RECORDS writes instead of lacking the method, so the
question "did the shim mutate the sample?" is answerable.

MEASURED, the defect this pins: `_register_arguments` returns `[EDX]`, the record pointer the installer is
walking, so `args[0]` is the SOURCE - yet the handler used it as `destination` and `mem_write` there. Each
record was read before being overwritten (EDX advances 0x30 per call), which is the only reason the observed
strings were still correct.
"""
from __future__ import annotations

import struct

from threat_report_agent.vb6_runtime_shim import (
    DESTINATION_OBSERVABLE,
    Vb6ShimState,
    build_vb6_handlers,
)


class RecordingEmu:
    """Minimal memory model that RECORDS writes, unlike the existing `FakeEmu`."""

    def __init__(self, memory: dict[int, bytes] | None = None) -> None:
        self.memory = dict(memory or {})
        self.writes: list[tuple[int, bytes]] = []

    def mem_read(self, address: int, size: int) -> bytes:
        for base, payload in self.memory.items():
            if base <= address and address + size <= base + len(payload):
                return payload[address - base : address - base + size]
        raise ValueError(f"unmapped 0x{address:x}")

    def mem_write(self, address: int, data: bytes) -> None:
        self.writes.append((address, bytes(data)))
        self.memory[address] = bytes(data)

    def read_mem_string(self, address: int, width: int = 1, max_chars: int = 0) -> str:
        for base, payload in self.memory.items():
            if base <= address < base + len(payload):
                raw = payload[address - base :]
                end = raw.find(b"\x00\x00" if width == 2 else b"\x00")
                text = raw[: end if end >= 0 else len(raw)].decode(
                    "utf-16-le" if width == 2 else "latin-1", errors="replace"
                )
                return text[:max_chars] if max_chars else text
        raise ValueError(f"unmapped 0x{address:x}")


def _record(hex_text: str) -> bytes:
    """One table slot: 20 ASCII-hex chars as UTF-16LE, then terminator and size field."""
    payload = hex_text.encode("utf-16-le").ljust(40, b"\x00")
    return payload + b"\x00\x00\x00\x00" + b"\x28\x00\x00\x00"


# `61 63 65 28` = "ace(" ; the sample's first record in its own layout.
FIRST_RECORD_VA = 0x402C08
RECORD = _record("61636528227620626120")


def _emu() -> RecordingEmu:
    return RecordingEmu({FIRST_RECORD_VA: RECORD})


def test_dest_is_declared_unobservable() -> None:
    """A caller must not describe an observed string as having been copied anywhere."""
    assert DESTINATION_OBSERVABLE is False


def test_the_single_argument_shape_writes_nothing_to_the_source_address() -> None:
    """The real dispatch shape: `_register_arguments` returns one value, the source pointer."""
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    emu = _emu()
    before = bytes(emu.memory[FIRST_RECORD_VA])

    result = handlers["__vbastrcopy"](emu, "MSVBVM60.__vbaStrCopy", None, [FIRST_RECORD_VA])

    assert emu.writes == [], (
        f"the shim wrote {len(emu.writes)} time(s) while observing the sample's literal table; "
        f"the first write targeted 0x{emu.writes[0][0]:x} with {emu.writes[0][1][:32]!r}"
    )
    assert emu.memory[FIRST_RECORD_VA] == before, "the sample's own record table was mutated"
    assert result == FIRST_RECORD_VA, (
        "the return value changed; MEASURED constraint: returning a fresh arena pointer aborted the run "
        "after 9 calls, so the observed pointer must be returned"
    )


def test_the_two_argument_shape_also_writes_nothing() -> None:
    """A dispatch path that does supply argv must not write either - dest is unobservable there too."""
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    dest, src = 0x2000, 0x3000
    text = "hi".encode("utf-16-le")
    emu = RecordingEmu(
        {
            dest: b"\x00" * 16,
            src - 4: struct.pack("<I", len(text)) + text + b"\x00\x00",
        }
    )

    handlers["__vbastrcopy"](emu, "MSVBVM60.__vbaStrCopy", None, [dest, src])

    assert emu.writes == [], f"the shim wrote to {[hex(a) for a, _ in emu.writes]}"
    assert state.arguments_seen == ["hi"], "the source is still observed"


def test_the_source_is_still_observed_after_the_write_is_removed() -> None:
    """Removing the write must not remove the observation - that would trade one defect for another."""
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    emu = _emu()

    handlers["__vbastrcopy"](emu, "MSVBVM60.__vbaStrCopy", None, [FIRST_RECORD_VA])

    assert state.arguments_seen, "the shim stopped recording what the sample handed to the runtime"
    assert state.calls.get("__vbastrcopy") == 1
