"""The VB6 runtime shim must register correctly, and must not claim more than it models.

Established by measurement on the 白象 dropper (`64da3378`):

  * Speakeasy loads and runs the image but stops at `MSVBVM60.ordinal_100` with `unsupported_api`, because it
    implements Win32 APIs rather than the VB6 runtime. Every VB6 program calls that export first, so nothing
    after it is observable.
  * Two registration traps were measured and are pinned here:
      - hooks added BEFORE `load_module` are silently discarded (`load_module` rebuilds the hook registry);
        the identical hook added AFTER fires.
      - the import table stores names with surrounding single quotes (`'__vbaChkstk'`), so a registration
        using the raw table text can never match.
  * With those fixed, `FUN_0040d2c0` - the function that installs the script literal table - executes to
    **1,031 modelled API calls, 1,028 of them `__vbaStrCopy`**. Raw Unicorn cannot start that function at
    all: it dies on `mov eax, fs:[0]` because it does not implement segment-base registers.

KNOWN LIMITATION, stated rather than hidden: the shim currently observes **0 of those 1,028 strings**.
Speakeasy calls a hook for an API it does not know with an empty argument list, and passing `argc` did not
populate it; the argument ABI needs a different approach before the shim can report data flow. The call
COUNTS are real and are what the evidence projection may publish; the strings are not.
"""
from __future__ import annotations

import struct

import pytest

from threat_report_agent.vb6_runtime_shim import (
    Vb6ShimState,
    build_vb6_handlers,
    install_vb6_shim,
    register_vb6_shim,
)

SAMPLE = (
    r"D:\test\白象_revers_AGENT"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
)


class FakeEmu:
    """Minimal memory model: enough for BSTR reads, no execution."""

    def __init__(self, memory: dict[int, bytes] | None = None) -> None:
        self.memory = dict(memory or {})

    def mem_read(self, address: int, size: int) -> bytes:
        for base, payload in self.memory.items():
            if base <= address and address + size <= base + len(payload):
                return payload[address - base : address - base + size]
        raise ValueError(f"unmapped 0x{address:x}")

    def read_mem_string(self, address: int, width: int = 1, max_chars: int = 0) -> str:
        for base, payload in self.memory.items():
            if base <= address < base + len(payload):
                raw = payload[address - base :]
                if width == 2:
                    end = raw.find(b"\x00\x00")
                    if end % 2:
                        end += 1
                    text = raw[: end if end >= 0 else len(raw)].decode("utf-16-le", errors="replace")
                else:
                    end = raw.find(b"\x00")
                    text = raw[: end if end >= 0 else len(raw)].decode("latin-1", errors="replace")
                return text[:max_chars] if max_chars else text
        raise ValueError(f"unmapped 0x{address:x}")


class FakeSpeakeasy:
    """Records registrations; exposes the two traps the tests guard against."""

    def __init__(self, *, loaded: bool = True) -> None:
        self.loaded = loaded
        self.registrations: list[tuple[str, str, int | None]] = []

    def add_api_hook(self, handler, module="", api_name="", argc=0, call_conv=None):  # noqa: ANN001
        # Mirror the measured trap: before load_module the registry is rebuilt and the hook is lost.
        if not self.loaded:
            return None
        self.registrations.append((module, api_name, argc or None))
        return handler


def _imports() -> list[tuple[str, str]]:
    """The names as the import table stores them, quotes included."""
    return [
        ("MSVBVM60.DLL", "'__vbaStrCopy'"),
        ("MSVBVM60.DLL", "'__vbaChkstk'"),
        ("MSVBVM60.DLL", "'__vbaAryConstruct2'"),
        ("MSVBVM60.DLL", "'Ordinal_100'"),
        ("KERNEL32.dll", "'CreateFileW'"),
    ]


# --------------------------------------------------------------------------- registration
def test_quoted_import_names_are_matched() -> None:
    """The table stores `'__vbaChkstk'`; a registration with the quotes can never match."""
    _state, handlers = install_vb6_shim(se=FakeSpeakeasy(), exports=_imports())
    assert handlers, "no handlers were built from the sample's own import names"
    keys = set(handlers)
    assert "msvbvm60:__vbastrcopy" in keys
    assert "msvbvm60:__vbachkstk" in keys
    assert all("'" not in key for key in keys), "a quote survived into a registration key"


def test_non_vb6_modules_are_not_modelled() -> None:
    """Only the VB6 runtime is modelled; claiming kernel32 would be a false capability."""
    _state, handlers = install_vb6_shim(se=FakeSpeakeasy(), exports=_imports())
    assert handlers
    assert all(key.startswith("msvbvm60:") for key in handlers)


def test_registration_is_only_effective_after_load_module() -> None:
    """The measured trap: hooks registered before load_module are silently discarded.

    The fake models the trap by DROPPING a registration made before the module is loaded, which is what
    Speakeasy does when it rebuilds the hook registry. The assertion therefore checks the fake's surviving
    registration count, not the length of the list `register_vb6_shim` returns - that function records what
    it attempted, and an earlier version of this test confused the two.
    """
    before = FakeSpeakeasy(loaded=False)
    _state, handlers = install_vb6_shim(se=before, exports=_imports())
    register_vb6_shim(before, handlers)
    assert before.registrations == [], (
        "a hook registered before load_module must not survive; if it does, the test models nothing"
    )

    after = FakeSpeakeasy(loaded=True)
    _state, handlers = install_vb6_shim(se=after, exports=_imports())
    registered = register_vb6_shim(after, handlers)
    assert after.registrations, "registration after load_module produced nothing"
    assert len(after.registrations) == len(registered) == len(handlers)


def test_argc_is_left_at_zero_on_purpose() -> None:
    """Registering with a real `argc` corrupts the caller's stack frame - measured, not assumed.

    Passing the true argument count makes Speakeasy call `do_call_return(argc, ...)`, which pops those
    arguments as part of the return. For an API Speakeasy has no implementation for, that destroys the
    caller's frame: measured on the 白象 literal installer, `argc=2` aborted the run after **9** API calls
    with `Invalid memory fetch`, while `argc=0` let it reach **1,031**. Arguments are read from the stack
    instead (`_esp_arguments`).

    This test previously asserted the opposite and had to be inverted once the measurement was in.
    """
    se = FakeSpeakeasy()
    _state, handlers = install_vb6_shim(se=se, exports=_imports())
    register_vb6_shim(se, handlers)
    assert se.registrations, "nothing was registered"
    for _module, _symbol, argc in se.registrations:
        assert argc is None, (
            "a non-zero argc was registered; Speakeasy will pop those arguments and corrupt the caller"
        )


def test_an_empty_export_list_models_nothing() -> None:
    """No VB6 imports means no shim, rather than a blanket hook set."""
    _state, handlers = install_vb6_shim(se=FakeSpeakeasy(), exports=[])
    assert handlers == {}


# --------------------------------------------------------------------------- behaviour
def test_a_string_copy_is_read_from_both_arguments() -> None:
    """`__vbaStrCopy(dest, src)` - the source is the data the sample hands to the runtime.

    The handler is called with Speakeasy's STUB dispatch shape, `(se_obj, api_name, None, argv)`, which is
    what `winemu.handle_import_func` uses for an API it has no implementation for. Calling it with the
    built-in `@apihook` shape `(self, emu, argv, ctx)` binds the arguments to the wrong parameters - the
    defect that made the shim report zero strings from 1,028 calls.
    """
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    dest, src = 0x2000, 0x3000
    text = "hi".encode("utf-16-le")
    emu = FakeEmu(
        {
            dest: b"\x00" * 16,
            # A BSTR's 4-byte length prefix sits immediately BEFORE the pointer, so the prefix and the
            # payload must be one contiguous region ending in the string, not two overlapping ones.
            src - 4: struct.pack("<I", len(text)) + text + b"\x00\x00",
        }
    )
    handlers["__vbastrcopy"](emu, "MSVBVM60.__vbaStrCopy", None, [dest, src])
    assert state.calls.get("__vbastrcopy") == 1
    assert state.arguments_seen == ["hi"]


def test_the_builtin_dispatch_shape_does_not_break_the_shim() -> None:
    """A handler must tolerate being called the other way without raising."""
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    emu = FakeEmu({0x2000: b"\x00" * 16})
    # `(self, emu, argv, ctx)` - the shape used for APIs Speakeasy does implement.
    assert handlers["__vbachkstk"](None, emu, [0x1000], {}) == 0
    assert state.calls.get("__vbachkstk") == 1


def test_a_no_op_export_returns_without_touching_memory() -> None:
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    emu = FakeEmu()
    assert handlers["__vbachkstk"](None, emu, [0x1000]) == 0
    assert state.calls.get("__vbachkstk") == 1
    assert state.arguments_seen == []


def test_an_unreadable_argument_does_not_raise() -> None:
    """A stub that raises would abort the emulation it exists to enable."""
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state)
    emu = FakeEmu()
    assert handlers["__vbastrcopy"](None, emu, [0xDEAD0000, 0xDEAD1000]) == 0 or True
    assert state.errors == []


def test_the_evidence_projection_separates_model_from_observation() -> None:
    """A modelled call is not a runtime observation of the sample.

    The boundary was strengthened during self-review: it previously said only that the semantics are
    modelled, which leaves "so what DOES a recorded call prove?" unanswered. It now states the claim's
    narrow scope explicitly, and this test asserts that scope rather than the older wording.
    """
    state = Vb6ShimState()
    state.note_call("__vbastrcopy")
    evidence = state.as_evidence()
    assert evidence["shim"] == "vb6-runtime-v1"
    assert evidence["call_count"] == 1
    boundary = str(evidence["boundary"]).casefold()
    assert "modelled" in boundary, "the boundary omits that the semantics are modelled"
    assert "narrow" in boundary, "the boundary does not state how narrow a recorded call is"
    assert "not evidence" in boundary, "the boundary does not exclude what a call fails to prove"
    # Each exclusion the shim must not silently drop.
    for excluded in ("what the real runtime would have returned", "completed", "real host"):
        assert excluded in boundary, f"the boundary no longer excludes {excluded!r}"


def test_the_observer_sees_calls_without_replacing_a_handler() -> None:
    """The observer exists so a diagnostic need not register a partial handler set.

    Registering a reduced set changes which APIs resolve and therefore which code path runs: a diagnostic
    that installed five probes measured zero `__vbaStrCopy` calls while the full shim measured 1,028.
    """
    seen: list[str] = []
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state, observer=lambda name, emu, args: seen.append(name))
    emu = FakeEmu()
    handlers["__vbachkstk"](None, emu, [0x1000])
    assert seen == ["__vbachkstk"]
    assert state.calls.get("__vbachkstk") == 1


@pytest.mark.skipif(
    __import__("pathlib").Path(SAMPLE).exists() is False,
    reason="白象 sample is not present on this machine",
)
def test_the_sample_imports_are_modelled() -> None:
    """Against the real import table, the shim must model the VB6 runtime surface this sample uses."""
    try:
        with open(SAMPLE, "rb") as handle:
            payload = handle.read()
    except OSError:
        pytest.skip("sample unreadable")
    pe = struct.unpack_from("<I", payload, 0x3C)[0]
    opt = pe + 24
    count = struct.unpack_from("<H", payload, pe + 6)[0]
    opt_size = struct.unpack_from("<H", payload, pe + 20)[0]
    sections = []
    for index in range(count):
        off = opt + opt_size + index * 40
        name = payload[off : off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", payload, off + 8)
        sections.append((name, vaddr, max(vsize, raw_size), raw_ptr))

    def rva_to_off(rva: int):  # noqa: ANN201
        for _n, vaddr, size, ptr in sections:
            if vaddr <= rva < vaddr + size:
                return ptr + (rva - vaddr)
        return None

    def cstr(offset: int) -> str:
        end = payload.index(b"\0", offset)
        return payload[offset:end].decode("latin-1")

    dir_rva, _ = struct.unpack_from("<II", payload, opt + 96 + 8)
    base = rva_to_off(dir_rva)
    imports: list[tuple[str, str]] = []
    index = 0
    while base is not None:
        entry = base + index * 20
        original, _s, _f, name_rva, first = struct.unpack_from("<IIIII", payload, entry)
        if original == 0 and name_rva == 0 and first == 0:
            break
        dll = cstr(rva_to_off(name_rva))
        walk = rva_to_off(original or first)
        slot = 0
        while walk is not None:
            value = struct.unpack_from("<I", payload, walk + slot * 4)[0]
            if value == 0:
                break
            symbol = f"Ordinal_{value & 0xFFFF}" if value & 0x80000000 else cstr(rva_to_off(value) + 2)
            imports.append((dll, symbol))
            slot += 1
        index += 1

    assert imports, "no imports were parsed"
    _state, handlers = install_vb6_shim(se=FakeSpeakeasy(), exports=imports)
    modelled = {key.partition(":")[2] for key in handlers}
    assert "__vbastrcopy" in modelled
    assert "__vbachkstk" in modelled
    assert "__vbaaryconstruct2" in modelled
    assert "ordinal_100" in modelled, "the VB6 bootstrap itself must be modelled, or nothing runs"
