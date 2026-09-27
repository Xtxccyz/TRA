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

WHICH MODELS EXIST IS NOT DECIDED BY THE CALLER (plan §9.1). The symbol set, the module names, the
enable/disable flag, the version and the provenance of this model are DECLARED in the runtime-model library at
the bottom of this file, and `install_vb6_shim` selects through it. The handler BODIES stay at the top - they
need the emulator object - and the declaration sits below them. MEASURED reason the split matters: with the
symbol set implicit, "this emulator has no model for that runtime" could only be expressed as a handler set that
happened to be empty, which is indistinguishable from a model that ran and matched nothing. The library reports
the two as different gaps.

WHERE THE LIBRARY LIVES, AND WHY IT IS NOT A SECOND MODULE. §9.1 permits a new registry module; this file keeps
it here instead, for a measured structural reason that is recorded in full above the library itself and in the
P-5 artifact: a separate module must be registered in `docs/import-policy.json`, and the two-module shape is a
real import CYCLE while the repository's recorded module graph has none.
"""
from __future__ import annotations

import hashlib
import pathlib
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

    #: Which DECLARED model, if any, selected the handlers this state belongs to (`""` when none did).
    #:
    #: §9.2 requires every round to record the model-registry version and the model identity. Publishing them
    #: here is what makes that recordable at all: without it a run can report 1,031 modelled calls and not say
    #: which declaration produced them. The value is the registry's model id, which is the string this shim
    #: already publishes as `shim` (`vb6-runtime-v1`), so a reader can attribute the numbers to a model.
    runtime_model_id: str = ""
    runtime_model_version: str = ""
    #: Reasons no model (or not all of one) applied. EVERY reason the registry can give is concrete: the
    #: runtime identity, the model id, how many exports the model declares, and a sentence. §9.3 forbids a
    #: model being skipped silently, so an empty handler set is never allowed to mean "nothing to say".
    gaps: list[dict[str, Any]] = field(default_factory=list)
    #: How many export keys this install SELECTED for registration. The number of hooks that actually
    #: survived to the emulator is the length of `register_vb6_shim`'s return value, which the adapter
    #: publishes as `registered`; this field is the selection side of the same count and is filled by
    #: `install_vb6_shim`.
    registered: int = 0

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
            # WHICH declared model produced the numbers above (plan §9.2: every round records the model-registry
            # version and the identity it selected). `runtime_model_id` is empty when no declared model applied,
            # and `runtime_model_gaps` then says why - the two are published together so an empty handler set
            # can never be mistaken for a model that ran and matched nothing.
            "runtime_model_id": self.runtime_model_id,
            "runtime_model_version": self.runtime_model_version,
            "runtime_model_registry": runtime_model_registry_version(),
            "runtime_model_identity_key_form": IDENTITY_KEY_FORM,
            "runtime_model_gaps": [dict(gap) for gap in self.gaps],
            "registered_hooks": self.registered,
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


# =============================================================================================================
# THE DECLARATIVE RUNTIME-MODEL LIBRARY (plan §9, C3b)
# =============================================================================================================
#
# WHY IT LIVES IN THIS FILE. Plan §9.1 permits three surfaces - `vb6_runtime_shim.py`, a NEW registry module, and
# T3 tests - and names one success standard: VB6's existing path is chosen BY the registry, the entries are
# hand-written declarative models, and no model may be generated automatically. A separate module was built
# first and then REMOVED, for a measured structural reason rather than for convenience:
#
#   * a new module must be registered in `docs/import-policy.json` (`known_modules` plus every new runtime
#     edge) in the same commit that adds it, or `scripts/check-import-graph.py --strict` exits 1. MEASURED:
#     exit 1 with the module (1 unregistered module, 3 unregistered edges), exit 0 without it (118 modules,
#     263 edges, 0 unregistered, 0 cycles);
#   * the two-module shape is a REAL 2-cycle - the registry reads this module's handler surface to build its
#     declaration, and this module consults the registry to select the default model - while the repository's
#     recorded module graph is ZERO cycles. Registering that cycle in the policy would have written a
#     structural regression into the gate's own data to silence the gate.
#
# Both halves are declaration and selection for ONE runtime, so keeping them in one module removes the cycle
# instead of laundering it, and §9.1 does not require a second file - it ALLOWS one.
#
# WHAT A MODEL IS, AND IS NOT. An entry is a DECLARATION: "for runtime identity `vb6`, imported under these
# module names, these export names are modelled, by this adapter, at this version, declared by these people
# from this record". The handler BODIES stay above, because they need the emulator object. That split is what
# makes a runtime the library does not model a REPORTED gap (`RUNTIME_MODEL_MISSING`) instead of a silent
# no-op, and a disabled model a reported gap too (`RUNTIME_MODEL_DISABLED`) with the size of the hole named.
#
# NO NEW FIXED CONSTANTS. §9.2 forbids adding fixed "at most N rounds / N models / N% coverage" constants.
# Nothing here bounds an increment, a model count or a coverage ratio. The two literals that exist are an
# IDENTITY (`vb6-runtime-v1`, already the published value of `as_evidence()["shim"]`) and a human-written DATE;
# neither takes part in any comparison.
#
# NO MODEL MAY BE GENERATED AUTOMATICALLY (§1.2: "不让模型自动生成 runtime stub；C3b 模型由人写、声明式注册、
# 按真实 stop reason 选择"). This file imports no network client and no provider SDK, and builds its entries in
# exactly ONE place - `_runtime_model` - from literals and from this module's own declared handler surface.

#: How a runtime export is identified. A STABLE IDENTITY KEY, never an index and never a count: §2.5 requires
#: every published collection's elements to have one, and §9.2 defines `no-gain` as the set difference over
#: THIS key being empty.
IDENTITY_KEY_FORM = "module:export"

#: Runtime identities this library speaks about. A runtime identity is the name of a RUNTIME - never a sample,
#: an address or a count.
RUNTIME_ID_VB6 = "vb6"

#: Reasons a model did NOT apply. A gap is always one of these four; the library never invents a fifth.
GAP_RUNTIME_MODEL_MISSING = "RUNTIME_MODEL_MISSING"
GAP_RUNTIME_MODEL_DISABLED = "RUNTIME_MODEL_DISABLED"
GAP_HANDLER_NOT_IMPLEMENTED = "HANDLER_NOT_IMPLEMENTED"
GAP_NO_MODELLED_EXPORT_PRESENT = "NO_MODELLED_EXPORT_PRESENT"


def runtime_model_registry_version() -> str:
    """The model-surface revision this library declares.

    A REVISION, not a bound: it takes part in no comparison and caps nothing (§9.2). It is published with every
    installed shim state so a run can name the surface it ran against (§9.2: every round records the registry
    version).
    """
    return "1"


def model_id_vb6() -> str:
    """The VB6 model's identity.

    This exact string is already the published value of `Vb6ShimState.as_evidence()["shim"]`, so the model a
    run used is attributable from the official body WITHOUT introducing a second published symbol.
    """
    return "vb6-runtime-v1"


def identity_key(module: str, export: str) -> str:
    """`module:export`, lower-cased the way `install_vb6_shim` lower-cases an import table entry."""
    return f"{str(module or '').strip().split('.')[0].lower()}:{str(export or '').strip().strip(chr(39)).lower()}"


def identity_keys(exports: "Any") -> "frozenset[str]":
    """Every import-table entry as a stable identity key, deduplicated into a set.

    MEASURED shape this has to survive: the import table stores names with surrounding single quotes
    (`'__vbaChkstk'`) and module names with an extension (`MSVBVM60.DLL`), so a key taken verbatim from the table
    can never match a declaration.
    """
    keys: set[str] = set()
    for item in exports or ():
        try:
            module, export = item
        except (TypeError, ValueError):
            continue
        key = identity_key(str(module or ""), str(export or ""))
        if key not in {":", ""} and not key.endswith(":"):
            keys.add(key)
    return frozenset(keys)


@dataclass(frozen=True)
class RuntimeModelProvenance:
    """Where a declaration came from. Every field is required and none is defaulted.

    NO DEFAULT FOR `author`/`reviewer` ON PURPOSE: the plan forbids a model generated automatically by an LLM,
    and the only durable evidence of human authorship a repository can hold is that a named author wrote it and
    a DIFFERENT named reviewer accepted it. A default here would let an entry be added with the field omitted
    and still look reviewed.
    """

    author: str
    reviewer: str
    source_record: str
    source_sha256: str
    decision: str
    recorded_at: str


@dataclass(frozen=True)
class RuntimeModel:
    """One hand-written, declarative runtime model.

    Frozen: a declaration that can be rewritten in place after review is not a declaration. Hashable for the
    same reason - two entries under one identity must not be able to differ silently.
    """

    model_id: str
    runtime_ids: tuple[str, ...]
    module_names: tuple[str, ...]
    exports: "frozenset[str]"
    handler_symbols: "frozenset[str]"
    semantic_adapter: str
    enabled: bool
    version: str
    provenance: RuntimeModelProvenance

    @property
    def identity_key_form(self) -> str:
        return IDENTITY_KEY_FORM

    def matches(self, runtime_id: str) -> bool:
        return str(runtime_id or "").strip().lower() in self.runtime_ids


@dataclass(frozen=True)
class RuntimeModelLibrary:
    """A set of declarations plus the selection rule over them.

    Selection is by runtime identity ONLY, and an identity with no declaration resolves to `None` rather than to
    a default. MEASURED reason: a library that answers for a runtime it does not model converts "this emulator
    cannot run that" into an unmodelled run that looks successful.
    """

    models: tuple[RuntimeModel, ...]

    def resolve(self, *, runtime_id: str) -> "RuntimeModel | None":
        wanted = str(runtime_id or "").strip().lower()
        if not wanted:
            return None
        for model in self.models:
            if model.matches(wanted):
                return model
        return None

    def unmodelled_identity_keys(self, runtime_id: str, observed: "Any") -> "frozenset[str]":
        """The observed identity keys the model for `runtime_id` does not declare.

        This is the set §9.2's `no-gain` difference is computed over. Absence of a model at all means NOTHING is
        modelled, which is reported as the whole observed set - never as an empty difference, which would read
        as "nothing left to do".
        """
        keys = frozenset(str(item) for item in observed or ())
        model = self.resolve(runtime_id=runtime_id)
        if model is None:
            return keys
        return keys - model.exports


def runtime_model_gap(*, reason: str, runtime_id: str, model_id: str = "", detail: str, **extra: Any) -> dict[str, Any]:
    """One reported reason the library did not model something. Always concrete, never a bare boolean."""
    gap: dict[str, Any] = {
        "reason": reason,
        "runtime_id": str(runtime_id or ""),
        "model_id": str(model_id or ""),
        "identity_key_form": IDENTITY_KEY_FORM,
        "detail": detail,
    }
    gap.update(extra)
    return gap


def _runtime_model(*, provenance: RuntimeModelProvenance, **fields: Any) -> RuntimeModel:
    """THE single place a `RuntimeModel` is constructed.

    Every entry in this module goes through here, so the T3 test's AST check has one function to point at and an
    entry cannot be assembled anywhere else - from measured data or from a generator.
    """
    return RuntimeModel(provenance=provenance, **fields)


def _source_record_sha256(relative: str) -> str:
    path = pathlib.Path(__file__).resolve().parents[3] / relative
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:  # pragma: no cover - the record is in this repository
        return ""


def _vb6_handler_symbols() -> "frozenset[str]":
    """The VB6 runtime exports this module can actually implement, as bare symbols.

    READ FROM `build_vb6_handlers` rather than repeated as a list, so the declaration cannot drift from what is
    implemented - a copy would drift the moment either side changed, and the library would then declare exports
    nothing implements.
    """
    return frozenset(build_vb6_handlers(Vb6ShimState()))


def _vb6_export_keys() -> "frozenset[str]":
    """The declared export set: every handler this module implements, under every module name VB6 uses."""
    return frozenset(
        f"{module}:{symbol}" for module in _VB6_MODULES for symbol in _vb6_handler_symbols()
    )


def default_runtime_model_library() -> RuntimeModelLibrary:
    """The library this repository ships.

    ONE entry, hand-written, declared from the measured record named in its provenance. There is no code path
    here that derives an entry from a sample, a scan, a coverage number or a model call.
    """
    return RuntimeModelLibrary(
        models=(
            _runtime_model(
                model_id=model_id_vb6(),
                runtime_ids=(RUNTIME_ID_VB6,),
                module_names=tuple(_VB6_MODULES),
                exports=_vb6_export_keys(),
                handler_symbols=_vb6_handler_symbols(),
                semantic_adapter=(
                    "threat_report_agent.emulation.vb6_runtime_shim:build_vb6_handlers"
                ),
                enabled=True,
                version=runtime_model_registry_version(),
                provenance=RuntimeModelProvenance(
                    author="T3 (plan .scratch/plan-ghidra-b3-c3-execution-plan-reviewed-20260922.md §9.1)",
                    reviewer="P-5 step record (.scratch/ghidra-c3/preflight/P-5-artifact.json)",
                    source_record="src/threat_report_agent/emulation/vb6_runtime_shim.py",
                    source_sha256=_source_record_sha256(
                        "src/threat_report_agent/emulation/vb6_runtime_shim.py"
                    ),
                    decision="DECLARED_FROM_MEASURED_RECORD",
                    recorded_at="2026-09-22",
                ),
            ),
        )
    )


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


def _declared_exports(
    state: Vb6ShimState,
    model: Any,
    handlers: Mapping[str, Callable[..., int]],
    observed_keys: frozenset[str] | None,
) -> dict[str, Callable[..., int]]:
    """The handlers this install will build, decided by the SELECTED MODEL's declaration.

    Two rules, both from §9.2's honesty requirement rather than from convenience:

      * a declared export the shim has no handler for is REPORTED (`HANDLER_NOT_IMPLEMENTED`), never silently
        dropped - a model that declares more than it implements is a capability claim, and an unreported one
        would be read as covered;
      * a declared module name the shim has no handler key for is reported for the same reason.

    With `observed_keys` supplied (the sample's own import table) the declaration is narrowed to what the
    sample imports; without it every declared export is offered, which is the measured behaviour the wired
    adapter depends on (`SimulationRequest` carries bytes, not imports). Registering a hook for a symbol the
    sample never imports is inert: a hook only fires if that import is called.
    """
    selected: dict[str, Callable[..., int]] = {}
    for key in sorted(model.exports):
        module, _sep, symbol = key.partition(":")
        if observed_keys is not None and key not in observed_keys:
            continue
        handler = handlers.get(symbol)
        if handler is None:
            state.gaps.append(
                runtime_model_gap(
                    reason=GAP_HANDLER_NOT_IMPLEMENTED,
                    runtime_id=model.runtime_ids[0] if model.runtime_ids else "",
                    model_id=model.model_id,
                    detail=(
                        f"the model declares export `{key}` but the shim has no handler for symbol "
                        f"`{symbol}`; the export is NOT modelled"
                    ),
                    identity_key=key,
                )
            )
            continue
        if module not in model.module_names:
            state.gaps.append(
                runtime_model_gap(
                    reason=GAP_HANDLER_NOT_IMPLEMENTED,
                    runtime_id=model.runtime_ids[0] if model.runtime_ids else "",
                    model_id=model.model_id,
                    detail=(
                        f"the model declares export `{key}` under module `{module}`, which is not one of its "
                        f"declared module names {list(model.module_names)}; the export is NOT modelled"
                    ),
                    identity_key=key,
                )
            )
            continue
        selected[key] = handler
    return selected


def install_vb6_shim(
    se: Any,
    *,
    exports: Any = None,
    observer: Callable[[str, Any, list], None] | None = None,
    library: Any = None,
    runtime_id: str = "vb6",
) -> tuple[Vb6ShimState, dict[str, Callable[..., int]]]:
    """Select a DECLARED runtime model and build the shim state and handlers for it.

    Returns `(state, handlers_by_symbol)`. **The caller must register the hooks AFTER `load_module`.**

    MEASURED: registering before `load_module` silently has no effect. Six registration variants were tried
    against `MSVBVM60.__vbaChkstk` - lower/exact case, bare and `.DLL` module names, and a `*` wildcard - and
    every one left the symbol unresolved with the handler never firing. Registering the identical hook AFTER
    `load_module` fires it and execution advances past the symbol. `load_module` rebuilds the emulator's hook
    registry, discarding API hooks added earlier.

    ## The selection is the REGISTRY's (plan §9.1)

    `library` defaults to `default_runtime_model_library()` and the model is resolved by
    `runtime_id` alone. This function no longer decides which exports exist: it asks the selected model. The
    production caller is unchanged - `simulation_adapters._speakeasy_adapter` still calls
    `install_vb6_shim(se)` - so VB6's existing path is chosen BY the registry without the adapter being edited.

    Every way the selection can fail to model something is REPORTED on `state.gaps`, because §9.3 forbids a
    silent skip:

      * `RUNTIME_MODEL_MISSING` - the library has no model for `runtime_id` at all;
      * `RUNTIME_MODEL_DISABLED` - a model matched but a reviewer disabled it;
      * `HANDLER_NOT_IMPLEMENTED` - the model declares an export this shim cannot implement;
      * `NO_MODELLED_EXPORT_PRESENT` - a model was selected but the sample imports none of its exports.

    The last one is MEASURED-reachable and is why "empty handler set" is not allowed to be a silent result: a
    sample that imports only VB6 data APIs this shim does not model produced an empty set, and before this the
    install was indistinguishable from a model that matched nothing.

    With no ``exports`` (the adapter's call) every export the selected model declares is offered. With
    ``exports`` supplied the declaration is narrowed to what the sample imports, which is the original
    behaviour and is what keeps a shim from claiming a surface the sample never touches.
    """
    if library is None:
        library = default_runtime_model_library()
    state = Vb6ShimState()
    state.runtime_model_version = runtime_model_registry_version()
    handlers = build_vb6_handlers(state, observer=observer)

    model = library.resolve(runtime_id=runtime_id)
    if model is None:
        state.gaps.append(
            runtime_model_gap(
                reason=GAP_RUNTIME_MODEL_MISSING,
                runtime_id=runtime_id,
                detail=(
                    f"the runtime-model library holds no model for runtime `{runtime_id}`; the caller required "
                    "one, so NOTHING is modelled on this path"
                ),
                library_size=len(library.models),
                library_model_ids=sorted(item.model_id for item in library.models),
            )
        )
        return state, {}
    if not model.enabled:
        state.gaps.append(
            runtime_model_gap(
                reason=GAP_RUNTIME_MODEL_DISABLED,
                runtime_id=runtime_id,
                model_id=model.model_id,
                detail=(
                    f"model `{model.model_id}` for runtime `{runtime_id}` is DECLARED BUT DISABLED; it "
                    f"declares {len(model.exports)} export(s) and none of them is modelled on this run"
                ),
                declared_export_count=len(model.exports),
                declared_module_names=list(model.module_names),
            )
        )
        return state, {}

    observed_keys = None if exports is None else identity_keys(exports)
    selected = _declared_exports(state, model, handlers, observed_keys)
    if exports is not None and not selected:
        state.gaps.append(
            runtime_model_gap(
                reason=GAP_NO_MODELLED_EXPORT_PRESENT,
                runtime_id=runtime_id,
                model_id=model.model_id,
                detail=(
                    f"model `{model.model_id}` was selected for runtime `{runtime_id}`, but the sample imports "
                    f"none of its {len(model.exports)} declared export(s); the model applied to nothing"
                ),
                declared_export_count=len(model.exports),
                observed_identity_keys=sorted(observed_keys or ()),
            )
        )
    state.runtime_model_id = model.model_id
    state.registered = len(selected)
    return state, selected


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
