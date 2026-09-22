"""VB6 runtime semantics for the isolated Speakeasy adapter.

WHY THIS EXISTS
---------------
Measured on the 白象 VB6 dropper (`64da3378`): Speakeasy loads and runs the image but stops immediately at

    error: {'type': 'unsupported_api', 'api_name': 'MSVBVM60.ordinal_100', 'instr': 'disasm_failed'}

because it implements **Win32** APIs, not the **VB6 runtime**. Every VB6 program's first act is to call
`MSVBVM60!Ordinal_100`, so nothing after it is observable - and the same boundary blocks Unicorn, for a
different reason (it does not implement the x86 segment-base registers `fs:[0]`, which every VB6 function's
SEH prologue reads; measured: `UC_X86_REG_FS_BASE` round-trips to 0 in both 1.0.2 and 2.1.4).

Speakeasy exposes `add_api_hook(handler, module, api_name)` for supplying an implementation it lacks, so the
VB6 runtime surface this sample actually imports can be modelled here. The hook registration is done by
lower-case name because Speakeasy lower-cases API names internally - its own report says
`MSVBVM60.ordinal_100`, and registering the import table's exact case silently never matched.

BOUNDARY - WHAT THESE STUBS DO AND DO NOT CLAIM
-----------------------------------------------
A stub is a MODEL, not the real runtime. Where the true semantics are simple and observable (copy a string,
concatenate, report a length) the model is faithful for the purpose of letting execution proceed and letting
the caller observe the data flow. Where they are not (VB6's `Variant` layout, array descriptors, error
objects) the stub returns a benign value and the result is reported as `hooked_or_stubbed_apis` rather than
as emulated behaviour. Nothing here may be published as a runtime observation of the sample.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

#: VB6 runtime ordinals and named exports whose semantics are modelled. The value is the scratch-buffer
#: size used for a returned string, so a caller never receives a dangling descriptor.
_STRING_RETURNING = frozenset(
    {
        "__vbastrcopy",
        "__vbastrcat",
        "__vbavarcat",
        "__vbastrvarmove",
        "__vbavarmove",
        "__vbavarcopy",
        "__vbavarcopyvar",
        "__vbavarvarmove",
        "__vbaisempty",
        "__vbavarbstrval",
        "__vbafreestr",
        "__vbafreevar",
        "__vbafreevarlist",
        "__vbafreestrlist",
        "__vbastrvarmove",
        "__vbavarsetvar",
        "__vbavarsetobjaddref",
        "__vbalenbstr",
        "__vbastrvallen",
        "__vbastrlen",
    }
)

#: Exports that only need to return without doing anything, because their effect is bookkeeping the caller
#: does not observe (stack probing, error-state setup, flushes, destructors).
_NOOP = frozenset(
    {
        "ordinal_100",  # the VB6 bootstrap itself; the caller only needs it to return
        "__vbachkstk",
        "__vbaonerror",
        "__vbaerroroverflow",
        "__vbagenerateboundserror",
        "__vbaexcepthandler",
        "__vbaend",
        "__vbafileclose",
        "__vbahresultcheckobj",
        "__vbanew2",
        "__vbaaryconstruct2",
        "__vbaarydestruct",
        "__vbachkstk",
        "rtcmsgbox",
        "rtcrandomize",
    }
)

#: Argument counts for the modelled exports.
#:
#: MEASURED: `add_api_hook` without `argc` calls the handler with an EMPTY `argv`, so every argument read
#: returned nothing and the shim recorded 0 strings from 1,028 `__vbaStrCopy` calls. Speakeasy decodes
#: arguments from the stack using this count, so each hook must declare it. `CALL_CONV_STDCALL` is the VB6
#: runtime's convention.
_ARG_COUNTS: Mapping[str, int] = {
    "__vbastrcopy": 2,
    "__vbastrcat": 3,
    "__vbavarcat": 3,
    "__vbastrvarmove": 2,
    "__vbavarmove": 2,
    "__vbavarcopy": 2,
    "__vbavarcopyvar": 2,
    "__vbavarvarmove": 2,
    "__vbalenbstr": 1,
    "__vbastrvallen": 1,
    "__vbastrlen": 1,
    "__vbavarbstrval": 1,
    "__vbaisempty": 3,
    "__vbafreestr": 1,
    "__vbafreevar": 1,
    "__vbafreevarlist": 2,
    "__vbafreestrlist": 2,
    "__vbavarsetvar": 2,
    "__vbavarsetobjaddref": 2,
    "__vbachkstk": 1,
    "__vbaonerror": 1,
    "__vbaaryconstruct2": 3,
    "ordinal_100": 1,
}

_DEFAULT_ARGC = 2


def _argc_for(symbol: str) -> int:
    return _ARG_COUNTS.get(symbol, _DEFAULT_ARGC)


#: Allocation arena for strings this shim returns. Kept well clear of the image and of Speakeasy's own
#: heaps, and never handed back to the host.
SHIM_HEAP = 0x61000000
SHIM_HEAP_SIZE = 0x00100000


@dataclass
class Vb6ShimState:
    """What the shim observed, for the evidence projection."""

    calls: dict[str, int] = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    #: Strings the sample passed into a modelled API - i.e. data the sample actually handed to the runtime.
    arguments_seen: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    heap_cursor: int = 0

    #: (source record address, decoded text) for every string the shim read.
    #:
    #: The address is the EDX record pointer the installer walks; it is read then discarded otherwise, leaving
    #: no way to say WHICH slot a string came from or to correlate two runs by position. Kept as pairs so the
    #: address and the text cannot drift apart.
    #:
    #: SCOPE - the pairing is exact only on the EDX path. `register_vb6_shim` always registers `argc=0` (see
    #: `DESTINATION_OBSERVABLE` above: a real argc corrupts the caller's frame), so arguments come from
    #: `_register_arguments` (EDX, one value) or the `_esp_arguments` fallback (up to 3 dwords that the module
    #: itself documents as NOT being arguments - they are the words after the return address). On that fallback
    #: `args[0]` is recorded as the address while the decoded text can come from `args[1]`, so the pair is
    #: positional rather than causal. MEASURED on the real 白象 run the main path is the one that fires
    #: (addresses `0x402c08`, `0x402c38`, ... at stride 0x30, all EDX source records), so published pairs were
    #: correct there - but a consumer must not read `argument_pairs` as "the address this text was read from"
    #: without checking which path produced it.
    argument_pairs: list[tuple[int, str]] = field(default_factory=list)

    def note_call(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    def as_evidence(self) -> dict[str, object]:
        return {
            "shim": "vb6-runtime-v1",
            "modelled_api_calls": dict(sorted(self.calls.items())),
            "call_count": sum(self.calls.values()),
            "sample_strings_observed": self.arguments_seen[:SAMPLE_STRINGS_CAP],
            "returned_strings": self.strings[:32],
            "errors": self.errors[:8],
            # PUBLISHED, not merely declared. `DESTINATION_OBSERVABLE` sat as a module constant that nothing in
            # `src/` read, so no evidence row and no report could carry it - a reader had no way to learn that
            # this shim never sees where a string API writes. MEASURED reason it matters: without this, a
            # consumer can describe an observed string as having been "copied to" something, and nothing in the
            # record contradicts it.
            "destination_observable": DESTINATION_OBSERVABLE,
            # The sample strings are CAPPED at 32 (`[:32]` above), so a consumer that compares two runs by
            # `sample_strings_observed` length is comparing two capped lists. Stating the cap and the true count
            # is what makes that comparison honest: MEASURED, this slice is why a probe printed "32" for both a
            # 1,028-read run and a 32-read run.
            "sample_strings_cap": SAMPLE_STRINGS_CAP,
            "reads_recorded": len(self.arguments_seen),
            # The first 16 pairs: address + text. Truncated like its sibling fields, and the TRUE count is
            # carried next to it so a comparison cannot mistake a capped list for the whole set.
            "argument_pairs": [
                {"address": hex(address), "text": value}
                for address, value in self.argument_pairs[:ARGUMENT_PAIRS_CAP]
            ],
            "argument_pairs_cap": ARGUMENT_PAIRS_CAP,
            "argument_pairs_recorded": len(self.argument_pairs),
            "boundary": (
                "These are MODELLED runtime semantics, not the real MSVBVM60. What a recorded call proves "
                "is narrow: the emulated instruction stream reached this export at this count. It is NOT "
                "evidence of what the real runtime would have returned, NOT evidence that the sample's "
                "logic completed, and NOT evidence of any behaviour on a real host. An argument list that "
                "could not be decoded is reported as no strings rather than as an empty result. "
                "`destination_observable` is false: this harness observes what the sample READS, never where "
                "it writes, so an observed string must not be described as copied anywhere."
            ),
        }


def _read_bstr(emu: Any, address: int, *, max_chars: int = 512) -> str:
    """Read a VB6 BSTR.

    A BSTR is a length-prefixed UTF-16LE string: a 4-byte byte-count sits immediately BEFORE the pointer,
    and the pointer itself must be 4-byte aligned. Passing the pointer straight to a flat string reader
    works only when the descriptor byte count is below 64 KiB (it is a byte count, not a character count),
    so the length prefix is read first and used to bound the read.
    """
    if not address:
        return ""
    try:
        prefix = emu.mem_read(address - 4, 4)
        byte_count = struct.unpack("<I", prefix)[0]
    except Exception:  # noqa: BLE001
        byte_count = 0
    if 0 < byte_count <= 0x10000 and byte_count % 2 == 0:
        try:
            raw = emu.mem_read(address, byte_count)
            return raw.decode("utf-16-le", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    try:
        return emu.read_mem_string(address, 2, max_chars)
    except Exception:  # noqa: BLE001
        try:
            return emu.read_mem_string(address, 2)
        except Exception:  # noqa: BLE001
            return ""


def _write_bstr(emu: Any, state: Vb6ShimState, text: str) -> int:
    """Place `text` in the shim arena as a BSTR and return its pointer."""
    encoded = text.encode("utf-16-le", errors="replace")
    # BSTRs are often odd-length in bytes; keep the length prefix and payload aligned.
    if len(encoded) % 4:
        encoded += b"\x00" * (4 - len(encoded) % 4)
    needed = len(encoded) + 8
    if state.heap_cursor + needed > SHIM_HEAP_SIZE:
        return 0
    base = SHIM_HEAP + state.heap_cursor
    state.heap_cursor += needed + 8
    try:
        emu.mem_write(base, struct.pack("<I", len(encoded)) + encoded + b"\x00\x00")
    except Exception:  # noqa: BLE001
        return 0
    state.strings.append(text[:200])
    return base + 4


def build_vb6_handlers(
    state: Vb6ShimState,
    *,
    observer: Callable[[str, Any, list], None] | None = None,
) -> dict[str, Callable[..., int]]:
    """The hook bodies, keyed by lower-case export name.

    `observer` is called as `observer(symbol, emu, raw_argv)` before the modelled behaviour runs. It exists
    so a diagnostic can inspect real arguments WITHOUT replacing a handler: registering a partial handler
    set changes which APIs resolve, and therefore changes the execution path being measured. A first attempt
    at reading the `__vbaStrCopy` ABI registered only five symbols and the run diverged to a different API
    with zero `__vbaStrCopy` calls - a measurement artefact, not a finding.
    """

    def make(name: str) -> Callable[..., int]:
        def handler(
            se_obj: Any,
            emu: Any,
            _unused: Any = None,
            argv: Any = None,
            *extra: Any,
        ) -> int:
            """Speakeasy's STUB dispatch is `hook.cb(self, imp_api, None, argv)`.

            MEASURED (`winemu.handle_import_func`, the `else` branch for an API Speakeasy does not
            implement): the third argument is always `None` and the fourth is the argument list. The
            signature used by the built-in `@apihook` methods - `(self, emu, argv, ctx)` - is a DIFFERENT
            dispatch used only when Speakeasy has its own implementation. Reading the stub call with the
            built-in signature binds `emu` to the API NAME STRING and `argv` to `None`, which is exactly why
            the shim fired 1,028 times and observed zero arguments. The emulator object for memory access is
            `se_obj` here, not the second parameter.
            """
            state.note_call(name)
            session = se_obj if hasattr(se_obj, "mem_read") else emu
            # Accept either dispatch: if the 2nd positional is a string this is the stub call and the list
            # is the 4th; otherwise it is the built-in call and the list is the 3rd.
            if isinstance(emu, str):
                args = list(argv or [])
            elif isinstance(_unused, str):
                args = list(argv or [])
            elif isinstance(emu, (list, tuple)):
                args = list(emu)
            else:
                args = list(argv or [])
            # With `argc=0` Speakeasy hands over no argument list, so read the arguments the x86 stdcall
            # convention leaves on the stack. This observes them WITHOUT changing stack handling.
            # Arguments are read from the REGISTERS first, then the stack.
            #
            # MEASURED: with `argc=0` the stack holds no arguments, so a stack-only reader observed
            # nothing from 1,028 calls. The real source is `EDX` (see `_register_arguments`); the stack
            # read stays as a fallback for any dispatch path that does supply argv.
            if not args and name != "ordinal_100":
                args = _register_arguments(session, 3) or _esp_arguments(session, 3)
            if observer is not None:
                try:
                    observer(name, session, args)
                except Exception:  # noqa: BLE001
                    pass
            # VB6 string APIs take (destination, source), but THIS harness can only see the source.
            #
            # MEASURED: `_register_arguments` returns `[EDX]`, the hex-record pointer the installer is
            # walking, so `args[0]` is the SOURCE - not the destination descriptor an earlier comment here
            # claimed. With `argc=0` Speakeasy decodes no arguments and the stack holds none, so there is
            # no register or stack slot carrying dest. `DESTINATION_OBSERVABLE` records that.
            source = ""
            if len(args) >= 2:
                source = _read_bstr(session, int(args[1]))
            elif args:
                source = _read_bstr(session, int(args[0]))
            if source:
                state.arguments_seen.append(source[:200])
                # The paired record: address first, text second, appended together so they cannot diverge.
                try:
                    state.argument_pairs.append((int(args[0]), source[:200]))
                except (IndexError, TypeError, ValueError):
                    # No readable address on this dispatch path; the TEXT observation still stands, and
                    # inventing an address would be worse than recording none.
                    pass
            if name == "__vbalenbstr" or name == "__vbastrlen":
                return len(source)
            if name in {"__vbaisempty", "__vbaonerror"}:
                return 0
            if name in _NOOP:
                return 0
            if name == "__vbavarcat" or name == "__vbastrcat":
                if len(args) >= 2:
                    left = _read_bstr(session, int(args[len(args) - 2]))
                    right = _read_bstr(session, int(args[len(args) - 1]))
                    return _write_bstr(session, state, left + right)
                return 0
            if name in _STRING_RETURNING:
                # `__vbaStrCopy(dest, src)` is SUPPOSED to mutate `dest` and return it.
                #
                # This shim cannot do that, because dest is unobservable (see `DESTINATION_OBSERVABLE`).
                # What it did instead - `destination = int(args[0])` then `mem_write` there - wrote the
                # DECODED TEXT BACK OVER THE SAMPLE'S OWN HEX RECORD TABLE, because `args[0]` is the source
                # pointer. That is self-inflicted corruption of the evidence being read: invisible only
                # because EDX advances 0x30 per call, so each record is read before it is overwritten.
                #
                # The write is now removed. MEASURED constraint that shapes the return value: returning a
                # fresh pointer from the shim arena aborted the run after 9 API calls with
                # `Invalid memory fetch`, because the caller stores the result into the VB6 array it is
                # building and dereferences it as a descriptor. Returning the observed pointer keeps the
                # array's own storage valid, so the call sequence survives; what is lost is only the copy,
                # which this harness could never perform at the right address anyway.
                if not args:
                    return 0
                return int(args[0])
            return 0

        return handler

    return {name: make(name) for name in sorted(set(_STRING_RETURNING) | set(_NOOP))}


#: Whether this harness can see the DESTINATION of a VB6 string API. It cannot, and the reason is
#: structural rather than a gap to be filled later:
#:
#:   * `argc` must be 0. Passing the real count makes Speakeasy pop the arguments and corrupt the caller's
#:     frame - MEASURED: the call count collapses from 1,031 to 9.
#:   * With `argc=0` Speakeasy decodes no arguments, and the stack therefore holds none either, so the
#:     `_esp_arguments` fallback reads the words after the return address, not arguments.
#:   * The only readable value is `EDX`, which is the SOURCE record pointer the installer walks.
#:
#: Consequence for any claim built on this shim: it observes what the sample READS, never where it writes.
#: A caller must not describe an observed string as having been "copied to" anything.
DESTINATION_OBSERVABLE = False

#: Caps on the two evidence lists, defined ONCE each.
#:
#: MEASURED dishonesty this prevents: the slice and the reported cap used to be two independent literals
#: (`self.arguments_seen[:32]` next to `"sample_strings_cap": 32`, `[:16]` next to `"argument_pairs_cap": 16`).
#: Changing one slice to `[:64]` would have kept publishing `cap: 32` - the published number describing a list
#: it no longer bounds, which is precisely the failure these cap fields exist to prevent. Deriving both from
#: one constant makes that impossible. `simulation_adapters.py` reads the caps from `as_evidence()` instead of
#: repeating them, so the value has exactly one definition end to end.
SAMPLE_STRINGS_CAP = 32
ARGUMENT_PAIRS_CAP = 16


def _register_arguments(session: Any, count: int = 3) -> list[int]:
    """Read the call arguments from the REGISTERS, which is where VB6 actually passes them.

    MEASURED root cause of "the two dwords read from the stack are not string pointers":
    `_esp_arguments` reads the stack, but `argc` is deliberately 0 (passing the real count makes
    Speakeasy pop those arguments and corrupt the caller's frame - the call count collapses from
    1,031 to 9). With `argc=0` the stack holds NO arguments, so the reader saw the words after the
    return address.

    The real source is `EDX`. Measured over consecutive `__vbaStrCopy` calls on the 白象 sample:

        call 0  EDX=0x402c08  prefix=40  '61636528227620626120'  -> "ace(\\"v ba "
        call 1  EDX=0x402c38  prefix=40  '696D2066736F2C20666F'  -> "im fso, fo"
        call 2  EDX=0x402c68  prefix=40  '2C205265706C61636528'  -> ", Replace("
        call 4  EDX=0x402cc8  -> " UsrPrf & "       call 6  EDX=0x402d28  -> 'new_down/"'

    `EDX` advances by 0x30 (48) per call, walking the hex-record table - i.e. it IS the source
    record pointer, and the concatenation reproduces the script the report previously carried only
    as a fragment.

    `get_register_state` values arrive as hex STRINGS (`'0x00402c08'`), not ints; filtering on
    `isinstance(value, int)` silently drops every register.
    """
    reader = getattr(session, "get_register_state", None)
    if reader is None:
        return []
    try:
        state = reader() or {}
    except Exception:  # noqa: BLE001
        return []
    values: dict[str, int] = {}
    for key, value in state.items():
        name = str(key).lower()
        if isinstance(value, int):
            values[name] = value
        elif isinstance(value, str):
            try:
                values[name] = int(value, 16) if value.lower().startswith("0x") else int(value)
            except ValueError:
                continue
    # `__vbaStrCopy`'s only argument we can act on is the source record in EDX.
    return [values["edx"]] if "edx" in values else []


def _esp_arguments(emu: Any, count: int = 3) -> list[int]:
    """Read `count` dwords off the stack above the return address.

    `argc=0` is registered deliberately (see `register_vb6_shim`), so Speakeasy does not decode arguments -
    but x86 stdcall still leaves them on the stack, directly above the return address. Reading the stack
    pointer is therefore how arguments are observed without changing the emulator's stack handling.

    The accessor is `get_stack_ptr()`, NOT `get_esp()`. `get_stack_ptr` is defined on Speakeasy's emulator
    object and dispatches on the architecture; `get_esp` was not found on that object, so calling it raised
    AttributeError, and the shim's `except` swallowed it and fell back to reporting no arguments. That is
    why a run with 1,028 `__vbaStrCopy` calls reported zero strings. (Stated as "not found", not as "does
    not exist": the check was `getattr` against the emulator instance actually passed to the handler, which
    is a weaker fact than an absence.)

    Returns [] when the stack pointer is unavailable or unmapped, so a caller degrades to call counts
    instead of crashing.
    """
    sp = None
    for accessor in ("get_stack_ptr", "get_esp", "get_sp"):
        method = getattr(emu, accessor, None)
        if callable(method):
            try:
                sp = int(method())
                break
            except Exception:  # noqa: BLE001
                continue
    if not sp:
        return []
    out: list[int] = []
    for index in range(count):
        try:
            out.append(struct.unpack("<I", emu.mem_read(sp + 4 + index * 4, 4))[0])
        except Exception:  # noqa: BLE001
            break
    return out


def _default_observer(name: str, emu: Any, args: list) -> None:
    """Unused placeholder kept so the shim has no hidden default behaviour."""
    return None


#: Module names the VB6 runtime is imported under. The shim registers against all of them when the
#: caller does not supply an import table, because a missed module name means the stub never fires and
#: the emulation dies on the same unmapped sentinel it was written to fix.
_VB6_MODULES = ("msvbvm60", "msvbvm50", "vba6", "vba7")

#: Symbols the shim models that are NOT string APIs but must still resolve, because Speakeasy cannot
#: resolve them either. `ordinal_100` is the one the 白象 sample actually imports (measured: the entry
#: thunk `jmp [0x4010e4]` targets it, and without a handler execution jumps to Speakeasy's unmapped
#: sentinel 0xfeedf0f0). It is in `_NOOP` because the caller only needs it to return.
_NON_STRING_STUBS = frozenset({"ordinal_100"})


def install_vb6_shim(
    se: Any,
    *,
    exports: Any = None,
    observer: Callable[[str, Any, list], None] | None = None,
) -> tuple[Vb6ShimState, dict[str, Callable[..., int]]]:
    """Build the shim state and handlers for a Speakeasy instance.

    Returns `(state, handlers_by_symbol)`. **The caller must register the hooks AFTER `load_module`.**

    MEASURED: registering before `load_module` silently has no effect. Six registration variants were tried
    against `MSVBVM60.__vbaChkstk` - lower/exact case, bare and `.DLL` module names, and a `*` wildcard - and
    every one left the symbol unresolved with the handler never firing. Registering the identical hook AFTER
    `load_module` fires it and execution advances past the symbol. `load_module` rebuilds the emulator's hook
    registry, discarding API hooks added earlier.

    With no ``exports`` the shim registers every symbol it models against every VB6 runtime module name.
    MEASURED reason: the caller has no import table to hand (`SimulationRequest` carries bytes, not
    imports), and an earlier `exports=()` call returned an EMPTY mapping - the filter below intersected
    the modelled symbols with an empty set - so nothing registered and the adapter would have appeared
    wired while the sample still died on `MSVBVM60.ordinal_100`. Registering a stub for a symbol the
    sample never imports is inert: a hook only fires if that import is actually called. With ``exports``
    supplied the original narrowing applies, so a shim only models what the sample imports.
    """
    state = Vb6ShimState()
    handlers = build_vb6_handlers(state, observer=observer)
    if exports is None:
        return state, {
            f"{module}:{symbol}": handlers[symbol]
            for module in _VB6_MODULES
            for symbol in handlers
        }
    modules: set[str] = set()
    symbols: set[str] = set()
    for item in exports or ():
        try:
            dll, symbol = item
        except (TypeError, ValueError):
            continue
        dll_text = str(dll or "")
        if "MSVBVM" not in dll_text.upper() and "VBA" not in dll_text.upper():
            continue
        modules.add(dll_text.split(".")[0].lower())
        # The import table stores the names with surrounding single quotes (`'__vbaChkstk'`), so strip
        # them or no registration can ever match.
        symbols.add(str(symbol or "").strip().strip("'").lower())
    if not symbols:
        return state, {}
    return state, {
        f"{module}:{symbol}": handlers[symbol]
        for module in modules
        for symbol in symbols
        if symbol in handlers
    }


def register_vb6_shim(se: Any, handlers: Mapping[str, Callable[..., int]]) -> list[str]:
    """Register pre-built handlers on a loaded Speakeasy instance. Call AFTER `load_module`.

    **`argc` is deliberately left at 0.** MEASURED, and it reverses an earlier assumption: passing the real
    argument count makes Speakeasy call `do_call_return(argc, ...)`, which pops those arguments as part of
    the return - and for these stubs that corrupts the caller's stack frame. The measured effect was
    dramatic: with `argc=0` the literal installer executes **1,031 API calls** (1,028 of them
    `__vbaStrCopy`); with `argc=2` it aborts after **9** with `Invalid memory fetch`. Arguments are read from
    ESP instead (see `_esp_arguments`), which observes them without altering stack handling.

    Returns the keys that registered, so a caller can report coverage rather than assume it.
    """
    registered: list[str] = []
    for key, handler in handlers.items():
        module, _sep, symbol = key.partition(":")
        try:
            se.add_api_hook(handler, module, symbol)
        except Exception:  # noqa: BLE001
            continue
        registered.append(key)
    return registered
