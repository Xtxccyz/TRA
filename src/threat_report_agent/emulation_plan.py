"""Select bounded emulator windows after static recovery, never from sample_path."""

from __future__ import annotations

import re
from typing import Iterable, Mapping

from threat_report_agent.dataflow import addresses_alias, parse_operand_address
from threat_report_agent.investigation import recovered_thread_start_address
from threat_report_agent.static.static_analysis import (
    pe_slice_at_rva,
    recover_static_xor_configs,
    unique_thread_function_starts,
)


_HOW_CALLSITE_PRIORITY = (
    ("createprocess", "shellexecute", "winexec"),
    ("getprocaddress", "loadlibrary", "ldrgetprocedureaddress"),
    ("updateprocthreadattribute",),
    ("winhttp", "httpsendrequest", "internetopen"),
    ("openprocess",),
)
_HOW_CALLSITE_TERMS = tuple(term for group in _HOW_CALLSITE_PRIORITY for term in group)
_FUN_LABEL_PREFIX = re.compile(r"^(?:FUN_|sub_|thunk_)", re.I)


def _as_int_address(value: object) -> int | None:
    """Parse a Unicorn entry from Ghidra VA, bare hex, or FUN_/sub_/thunk_ labels.

    Memory operands such as ``[R8]`` are not code entries and must not grant
    a window. Short decimal PE fields such as section RVAs keep base-10.
    Unprefixed 8+ digit Ghidra VAs such as ``140004605`` are hex, not decimal.
    """
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value or "").strip()
    if not text or "[" in text:
        return None
    stripped = _FUN_LABEL_PREFIX.sub("", text)
    if stripped != text:
        return _as_int_address(stripped)
    lowered = text.lower()
    if lowered.startswith("0x"):
        try:
            parsed = int(text, 16)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    if re.fullmatch(r"[0-9a-fA-F]+", text) and (
        re.search(r"[A-Fa-f]", text) or len(text) >= 8
    ):
        try:
            parsed = int(text, 16)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    try:
        parsed = int(text, 0)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def readable_pe_memory_maps(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    *,
    max_total: int = 524288,
) -> tuple[dict[str, object], ...]:
    """Grant readable PE sections to Unicorn so RIP-relative .rdata is mapped."""
    pe = dict(pe_summary or {})
    image_base = _as_int_address(pe.get("image_base")) or 0
    maps: list[dict[str, object]] = []
    used = 0
    for section in pe.get("sections") or ():
        if not isinstance(section, Mapping):
            continue
        name = str(section.get("name") or "").casefold()
        if name.startswith(".rsrc") or name.startswith(".reloc"):
            continue
        raw_offset = int(section.get("raw_offset") or 0)
        raw_size = int(section.get("raw_size") or 0)
        virtual = _as_int_address(section.get("virtual_address"))
        if virtual is None or raw_size < 8 or raw_offset < 0 or raw_offset >= len(content):
            continue
        take = min(raw_size, max(0, max_total - used), len(content) - raw_offset)
        if take < 8:
            continue
        payload = content[raw_offset : raw_offset + take]
        va = virtual + image_base if image_base and virtual < image_base else virtual
        maps.append({"address": va, "bytes": payload})
        used += take
        if used >= max_total:
            break
    return tuple(maps)


def _function_names_recovered_vas(
    function: Mapping[str, object],
    addresses: Iterable[int],
    *,
    image_base: int = 0,
) -> bool:
    wanted = tuple(item for item in addresses if isinstance(item, int) and item >= 0)
    if not wanted:
        return False
    blobs: list[Mapping[str, object]] = []
    for key in ("references_from", "data_references", "references"):
        raw = function.get(key)
        if isinstance(raw, list):
            blobs.extend(item for item in raw if isinstance(item, Mapping))
    for ins in function.get("instructions") or ():
        if isinstance(ins, Mapping):
            blobs.append(ins)
    for blob in blobs:
        for locator in (
            blob.get("to"),
            blob.get("address"),
            blob.get("target"),
            blob.get("target_name"),
            blob.get("text"),
        ):
            parsed = parse_operand_address(locator)
            if parsed is None:
                parsed = _as_int_address(locator)
            if parsed is None:
                continue
            if any(addresses_alias(parsed, va, image_base) for va in wanted):
                return True
    return False


def _how_callsite_priority(text: object) -> int | None:
    blob = str(text or "").casefold()
    for index, terms in enumerate(_HOW_CALLSITE_PRIORITY):
        if any(term in blob for term in terms):
            return index
    return None


def _is_import_thunk_name(name: object) -> bool:
    blob = str(name or "").casefold()
    if not blob or blob.startswith("fun_"):
        return False
    return any(term in blob for term in _HOW_CALLSITE_TERMS)


def unicorn_granted_windows_for_worker(
    windows: Iterable[Mapping[str, object]] | None,
    *,
    max_windows: int = 4,
) -> tuple[dict[str, object], ...]:
    """Serialize Unicorn snippets for the isolated worker. Skip Speakeasy full-PE.

    CALLER CONTRACT - the skip is NOT reported. Every window whose simulator is not `unicorn` is dropped by
    the filter below, and the caller receives a shorter tuple with no way to tell "there were only Unicorn
    windows" from "non-Unicorn windows were dropped". That is deliberate here (this function's job is the
    Unicorn grant payload) but it means a caller wanting the full-PE window MUST plan it separately - which is
    what `tool_execution.py` does, prepending it as an incremental window outside the grant budget. Calling
    this function and assuming it returns every window silently loses the others. Recorded as a known latent
    trap in `.scratch/finding-suppression-point-1-latent.md`; reporting the skip needs a signature change.

    PROVENANCE of `max_windows` (G2): the value 4 is NOT derived from a measurement. It mirrors the per-run
    execution budget in `tool_execution.py` (`execution_budget = 4`), which is itself the pre-existing literal
    on that path, and it is a legacy default that no production caller relies on - `service.py` calls this
    function without passing `max_windows`, so the effective bound today is whatever the caller passes, not
    this default. Stated here rather than left looking authoritative; deriving it from a measurement is open
    work, and G4 forbids quietly changing it in the meantime.
    """
    output: list[dict[str, object]] = []
    for window in windows or ():
        if not isinstance(window, Mapping):
            continue
        if str(window.get("simulator") or "").casefold() != "unicorn":
            continue
        payload = window.get("input_bytes")
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 8:
            continue
        anchor = window.get("anchor") if isinstance(window.get("anchor"), Mapping) else {}
        output.append(
            {
                "simulator": "unicorn",
                "input_hex": bytes(payload).hex(),
                "entry_address": window.get("entry_address"),
                "architecture": str(window.get("architecture") or "x86_64"),
                "function_entry": str(anchor.get("function_entry") or ""),
                "role": str(anchor.get("role") or "granted_window"),
            }
        )
        if len(output) >= max(1, max_windows):
            break
    return tuple(output)


def _pe_architecture(pe_summary: Mapping[str, object]) -> str:
    """The sample's CPU architecture in the spelling the worker's adapters accept.

    Sources, strongest first: the PE code-signal projection (`"x86-64"` / `"x86"`), then the
    COFF machine word.  Returns `"x86"` or `"x86_64"` - the spellings `_unicorn_adapter`
    documents - and falls back to `"x86_64"` only when nothing identifies the machine, which is
    the previous behaviour rather than a new guess.

    Machine values: 0x014c i386, 0x8664 amd64.  `"x86_64"` is NOT a valid answer for a 32-bit
    image, and that substitution is the defect this function exists to remove.
    """
    signals = pe_summary.get("code_signals")
    if isinstance(signals, Mapping):
        token = str(signals.get("architecture") or "").strip().casefold()
        if token in {"x86", "i386", "x86_32", "x86-32"}:
            return "x86"
        if token in {"x86_64", "x86-64", "amd64", "x64"}:
            return "x86_64"
    machine = pe_summary.get("machine")
    try:
        word = int(machine) if machine not in (None, "") else None
    except (TypeError, ValueError):
        word = None
    if word == 0x014C:
        return "x86"
    if word in {0x8664, 0x0200}:
        return "x86_64"
    for key in ("architecture", "calling_convention"):
        token = str(pe_summary.get(key) or "").strip().casefold()
        if token in {"x86", "i386", "x86_32", "x86-32"}:
            return "x86"
        if token in {"x86_64", "x86-64", "amd64", "x64"}:
            return "x86_64"
    return "x86_64"


def _entry_is_bootstrap_trampoline(
    content: bytes,
    pe_summary: Mapping[str, object],
    entry_rva: int,
) -> bool:
    """True when the entry point only forwards into a runtime bootstrap and has no logic of its own.

    MEASURED SHAPE (白象 sample `64da3378`, VB6):

        0x402484  push 0x4025f0          ; the runtime's entry descriptor
        0x402489  call 0x40247c          ; `ff 25 e4 10 40 00` -> jmp [0x4010e4] -> MSVBVM60.ordinal_100
        0x40248e  ...                    ; MORE CODE, not padding - see CORRECTION below

    Emulating that dies on the first fetch of `0xfeedf0f0`, the sentinel Speakeasy installs for an
    ordinal it cannot resolve at load time, and observes nothing (probes `.scratch/probe-unicorn-setup.py`,
    `.scratch/probe-speakeasy-entry-error.py`).

    CORRECTION (`.scratch/probe-vb6-control-flow.py`): an earlier revision of this docstring asserted
    "binding the import does not help - execution then falls into the padding and faults two instructions
    later". That is true ONLY of a stub that returns 0, because the next instruction dereferences the
    return value; it is not evidence of padding. Patching the IAT slot to a stub returning a NON-NULL
    pointer lets execution continue and run a 13-instruction sequence. So the entry DOES hold behaviour.

    The detector is therefore a *cost* decision, not a claim that the entry is empty: it skips a window
    that cannot observe anything while the runtime ordinal is unresolved.

    The test is deliberately narrow so a native entry point is never skipped:

      * the first instruction is a `push imm32` or `push imm8` (a descriptor / argument),
      * the second is a relative `call` (E8) whose target is inside the image,
      * the call target is an import thunk - `jmp [imm32]` (FF 25) or `jmp rel32` (E9) - OR the bytes right
        after the call are zero padding,
      * nothing before the call writes memory or registers in a way that would be an observation.

    Returns False when anything cannot be established, because a wrong skip hides real behaviour and this
    function's only job is to avoid wasting a worker turn.
    """
    offset = _rva_to_file_offset(content, pe_summary, entry_rva)
    if offset is None or offset + 16 > len(content):
        return False
    code = content[offset : offset + 16]

    # 1. push imm32 (68) or push imm8 (6A) as the first instruction.
    if code[0] == 0x68:
        first_len = 5
    elif code[0] == 0x6A:
        first_len = 2
    else:
        return False

    # 2. a relative call immediately after it.
    if code[first_len] != 0xE8:
        return False
    call_len = 5
    rel = int.from_bytes(code[first_len + 1 : first_len + 5], "little", signed=True)
    call_site_rva = entry_rva + first_len
    target_rva = call_site_rva + call_len + rel
    if target_rva <= 0 or target_rva >= 0x4000_0000:
        return False

    # 3. the call target must be a thunk inside the image.
    target_off = _rva_to_file_offset(content, pe_summary, target_rva)
    if target_off is None or target_off + 6 > len(content):
        return False
    target = content[target_off : target_off + 6]
    is_thunk = (target[0] == 0xFF and target[1] == 0x25) or target[0] == 0xE9
    if not is_thunk:
        return False

    # 4. what follows the call must look like padding, not code: a run of zeros.
    after = content[offset + first_len + call_len : offset + first_len + call_len + 8]
    if len(after) < 4 or any(byte != 0x00 for byte in after[:4]):
        return False
    return True


def _rva_to_file_offset(
    content: bytes,
    pe_summary: Mapping[str, object],
    rva: int,
) -> int | None:
    """Map an RVA to a file offset using the parsed section table."""
    for section in pe_summary.get("sections") or ():
        if not isinstance(section, Mapping):
            continue
        virtual = _as_int_address(section.get("virtual_address"))
        if virtual is None:
            continue
        raw_size = int(section.get("raw_size") or 0)
        virtual_size = int(section.get("virtual_size") or 0)
        span = max(raw_size, virtual_size)
        if virtual <= rva < virtual + span:
            raw_offset = int(section.get("raw_offset") or 0)
            delta = rva - virtual
            if delta >= raw_size:
                return None
            candidate = raw_offset + delta
            if 0 <= candidate < len(content):
                return candidate
            return None
    return None


#: Span used when the section table yields no usable image extent; keeps the start-address rule bounded
#: rather than letting any recovered function entry through.
_SPEAKEASY_RECOVERY_SPAN_FALLBACK = 0x00400000


#: Symbols that mark a function as driving VB6 runtime semantics. A function that CALLS these is doing
#: real runtime work, which is what makes an emulation window worth spending.
#:
#: Matched with `in`, not `startswith`: MEASURED, the runtime target appears as
#: `PTR___vbaChkstk_00401058` (an indirection slot) and `__vbaChkstk` (the external call), so a
#: startswith test misses the pointer spelling entirely.
_VB6_RUNTIME_PREFIXES = ("__vba", "ordinal_", "rtcmsgbox", "rtcrandomize")


def _mentions_vb6_runtime(text: str) -> bool:
    folded = text.strip().casefold()
    if not folded:
        return False
    return any(prefix in folded for prefix in _VB6_RUNTIME_PREFIXES)


def _is_vb6_runtime_symbol(name: object) -> bool:
    """True when the NAME is itself a VB6 runtime export rather than sample code.

    MEASURED failure this prevents: `_calls_vb6_runtime` ranked `__vbaChkstk` first because a runtime
    import trivially "mentions the runtime" - so the window started INSIDE the runtime stub and the run
    ended after one call (`entry_address=0x4022c0`, `modelled_calls=1`). A runtime export is the callee
    of real work, never the place to start.
    """
    text = str(name or "").strip().strip("'").casefold()
    if not text:
        return False
    return any(prefix in text for prefix in _VB6_RUNTIME_PREFIXES)


def _calls_vb6_runtime(function: Mapping[str, object]) -> bool:
    """True when a recovered function's record shows it invoking the VB6 runtime.

    Scans the record RECURSIVELY. MEASURED why that is required: the runtime target lives in a NESTED
    collection, not at the top level of the function row -

        {"name": "__vbaChkstk", "entry": "004022c0", "caller_count": 6, "callee_count": 0,
         "call_targets": [],
         "data_references": [{"from": "004022c0", "to": "00401058", "type": "INDIRECTION",
                              "target_name": "PTR___vbaChkstk_00401058"}]}

    A top-level-only check therefore reports "no runtime calls" for a function that plainly makes one,
    which is exactly how the first wired run picked a routine that produced `modelled_calls=1`. Recursing
    also removes the need for the caller to pre-compute the address set.
    """
    seen: set[int] = set()

    def walk(node: object, depth: int) -> bool:
        if depth > 6 or node is None:
            return False
        if isinstance(node, Mapping):
            if id(node) in seen:
                return False
            seen.add(id(node))
            for key, value in node.items():
                if isinstance(value, str):
                    if _mentions_vb6_runtime(value):
                        return True
                elif isinstance(value, (Mapping, list, tuple)):
                    if walk(value, depth + 1):
                        return True
            return False
        if isinstance(node, (list, tuple)):
            return any(walk(item, depth + 1) for item in node)
        if isinstance(node, str):
            return _mentions_vb6_runtime(node)
        return False

    return walk(function, 0)


def _speakeasy_entry_from_functions(
    functions: Iterable[Mapping[str, object]] | None,
    *,
    image_base: int,
    image_span: int,
    entry_rva: int | None,
    runtime_caller_addresses: Iterable[int] | None = None,
) -> tuple[int | None, str]:
    """Pick a recovered function entry to run Speakeasy FROM, and name the BASIS for that choice.

    Returns `(address, basis)` where basis is one of:

      * `recovered_function_entry`    - an in-image function CALLED by something was chosen;
      * `recovered_runtime_driver`    - an in-image function that drives the VB6 runtime was chosen, but no
                                        candidate carried caller evidence;
      * `image_entry`                 - nothing with evidence was found (address is None), so the run keeps
                                        the default, which is `run_module` from the image entry.

    The basis is returned rather than inferred by the caller because `address is not None` says only that an
    address was picked - not WHAT justified it.

    WHAT THE BASIS NAMES, stated exactly (T1a/T1b audit finding F5): it records whether the chosen candidate
    carried CALLER evidence. Runtime-driving behaviour is used to QUALIFY and to RANK candidates, but when a
    candidate carries both signals the label reads `recovered_function_entry` and does not separately say that
    it also drives the runtime. So the label is a partial description, not a false one - do not read
    `recovered_function_entry` as "this start had no runtime evidence".

    SCOPE, stated precisely because an earlier version of this docstring overstated it (T1b audit finding):
    the basis is carried into the window's `anchor`, which reaches the tool result payload. **No renderer
    reads it today** (`reporting.py` has no `start_basis` reference), so the distinction is currently visible
    only in the evidence layer, not in a report. Making it reach the report is T2's job.

    MEASURED motivation: the 白象 PE entry is a bootstrap trampoline that dies on the unimplemented
    `MSVBVM60.ordinal_100`, so an entry-driven Speakeasy run observes NOTHING (`1 modelled call`).
    Running instead from the recovered VB6 literal-table constructor produced, in the isolated worker:

        modelled_calls=1031   api observations=256   strings observed=1028

    Without a rule here the window would carry the historical hardcoded `0x1000000`, which the adapter's
    guard rejects (it is outside the image), so the whole capability stays unreachable.

    The rule is deliberately generic - no sample address is named, because `literal_table.py` already
    records why that is unacceptable ("a projection keyed to one sample's address is not a capability"):

      * the entry must lie INSIDE the loaded image, so it is a real code address and not a sentinel;
      * it must not BE the image entry, since running from the entry is what `run_module` already does;
      * a function that CALLS THE VB6 RUNTIME ranks first. MEASURED why caller/callee counts are not
        enough: the first end-to-end run after wiring picked an entry that produced `modelled_calls=1`
        and only one observed API (`__vbaChkstk`), because a routine that merely probes the stack looks
        as "called" as one that drives 1,028 `__vbaStrCopy` calls. `runtime_caller_addresses` carries
        the call-graph evidence for that distinction; `_calls_vb6_runtime` covers a record that states
        its own targets.
      * then callers, then callees, then the lowest address for a stable choice.
    """
    runtime_callers = {
        int(item) for item in (runtime_caller_addresses or ()) if isinstance(item, int)
    }
    candidates: list[tuple[int, int, int, int]] = []
    for function in functions or ():
        if not isinstance(function, Mapping):
            continue
        # A VB6 runtime export is never a start point: it is the callee of real work. MEASURED: without
        # this, `__vbaChkstk` itself was selected (it trivially "mentions the runtime") and the run ended
        # after one call.
        if _is_vb6_runtime_symbol(function.get("name")):
            continue
        # `entry`/`target` are VAs; `entry_rva` is an RVA. Treating any small VA as an RVA would let a
        # genuine low address (a data offset, or the historical sentinel) pass as an in-image code
        # address, so the two forms are handled separately instead of "add base if below base".
        address: int | None = None
        for key in ("entry", "target"):
            if key in function:
                address = _as_int_address(function.get(key))
                if address is not None:
                    break
        if address is None:
            rva = _as_int_address(function.get("entry_rva"))
            if rva is not None:
                address = image_base + rva
        if address is None:
            continue
        if not (image_base < address < image_base + image_span):
            continue
        if entry_rva is not None and address == image_base + entry_rva:
            continue

        def _count(key: str) -> int:
            value = function.get(key)
            return int(value) if isinstance(value, int) else 0

        callers = _count("caller_count")
        drives_runtime = 1 if _calls_vb6_runtime(function) else 0
        if not drives_runtime and address in runtime_callers:
            drives_runtime = 1
        # A candidate must carry SOME evidence that it is real work. MEASURED history of both extremes:
        #
        #   * requiring `callers > 0` ALONE silently destroyed the capability on Resume: with the 64 functions
        #     production passes, every candidate was discarded (`no_callers 63 -> candidates 0`), the window
        #     kept the sentinel 0x1000000, and the run collapsed to `run_module`.
        #   * removing the requirement ENTIRELY was worse, and measurably so. With no evidence at all the
        #     selector picked the lowest-address/most-callee function and Speakeasy started there:
        #         entry-driven (old fallback) : 1 api, 647 ms, stops at msvcrt.__iob_func
        #         0x140001d0d (no evidence)   : 0 api, 147 ms, UC_ERR_READ_UNMAPPED at 0x140001d16
        #     i.e. nine bytes into the function, observing strictly LESS than the fallback it replaced.
        #
        # So the requirement stays and the EVIDENCE is widened: a caller count OR runtime-driving behaviour
        # qualifies a candidate. A function that drives the runtime is the case the whole mechanism exists for
        # (measured: the runtime driver produced 1,031 modelled calls and 256 api observations), and it is a
        # stronger signal than a caller count. With neither signal there is nothing to justify leaving the
        # entry, and the bounded `run_module` fallback is the honest choice.
        if callers <= 0 and not drives_runtime:
            continue
        candidates.append((drives_runtime, callers, _count("callee_count"), address))
    if not candidates:
        return None, "image_entry"
    # Runtime-driving first, then most callers, then most callees, then lowest address. A caller-backed
    # candidate therefore always outranks a runtime-only one at equal runtime evidence, and 白象's
    # `0x40d2c0` is unaffected by the widening.
    candidates.sort(key=lambda item: (-item[0], -item[1], -item[2], item[3]))
    best = candidates[0]
    if best[1] > 0:
        basis = "recovered_function_entry"
    else:
        # Qualified by runtime-driving behaviour rather than by callers. Recorded distinctly because the two
        # are different evidence and a reader must be able to tell which one justified the start.
        basis = "recovered_runtime_driver"
    return best[3], basis


def controlled_emulation_windows(
    content: bytes,
    pe_summary: Mapping[str, object] | None,
    functions: Iterable[Mapping[str, object]] | None,
    traces: Iterable[Mapping[str, object]] | None = None,
    *,
    allow_speakeasy: bool = False,
    allow_qiling: bool = False,
    max_windows: int = 4,
    snippet_length: int = 512,
    max_pe_bytes: int = 4_194_304,
    preferred_entries: Iterable[object] | None = None,
) -> tuple[dict[str, object], ...]:
    """Static-first windows: persist HOW, then callers, then thread starts.

    CreateThread lpStartAddress flood must not consume the four-window
    budget before CreateProcess / GetProcAddress / persist leftover
    tickets. Speakeasy is not skipped merely because a CreateThread
    callsite exists. Full-PE windows are only included when
    ``allow_speakeasy`` is true (Docker isolation). Callers never pass a
    filesystem sample path.
    """
    pe = dict(pe_summary or {})
    windows: list[dict[str, object]] = []
    seen: set[str] = set()
    speakeasy_reserved = 1 if allow_speakeasy and content[:2] == b"MZ" and 64 <= len(content) <= max_pe_bytes else 0
    qiling_reserved = 1 if allow_qiling else 0
    unicorn_budget = max(1, max_windows) - speakeasy_reserved - qiling_reserved
    image_base = _as_int_address(pe.get("image_base")) or 0
    # The architecture MUST travel with the window.  Without it the worker defaulted to x86_64
    # and ran 64-bit Unicorn over 32-bit code, which faults on the first instruction; measured on
    # task `0291d4b1` (PE machine 0x014c) as `size: 4059165169, errno: 10 (UC_ERR_EXCEPTION)`,
    # one instruction executed, reported as `EMULATOR_ERROR`.  The fact was already available -
    # `static_analysis` records `code_signals.architecture` as "x86-64" or "x86" - and no consumer
    # read it, which is the R1/R2 shape: a fact in evidence that never reaches its consumer.
    pe_architecture = _pe_architecture(pe)
    xor_vas = tuple(
        int(item["virtual_address"])
        for item in recover_static_xor_configs(content, pe)
        if isinstance(item, dict) and isinstance(item.get("virtual_address"), int)
    )
    memory_maps = readable_pe_memory_maps(content, pe)

    def add_unicorn(entry: object, *, role: str) -> None:
        if len([item for item in windows if item.get("simulator") == "unicorn"]) >= unicorn_budget:
            return
        address = _as_int_address(entry)
        if address is None:
            return
        snippet = pe_slice_at_rva(content, pe, address, length=snippet_length)
        if len(snippet) < 8:
            return
        mapped_entry = address
        if image_base and address < image_base:
            mapped_entry = address + image_base
        key = f"unicorn:{mapped_entry}"
        if key in seen:
            return
        seen.add(key)
        window = {
            "simulator": "unicorn",
            "input_bytes": snippet,
            "entry_address": mapped_entry,
            # Read by the worker to choose the Unicorn mode and register set.  Defaulting this
            # made every 32-bit sample fail on its first instruction.
            "architecture": pe_architecture,
            "anchor": {
                "type": "unique_thread_emulation",
                "simulator": "unicorn",
                "function_entry": hex(mapped_entry),
                "role": role,
            },
        }
        if memory_maps:
            window["memory_maps"] = [
                {"address": item["address"], "bytes": item["bytes"]} for item in memory_maps
            ]
        windows.append(window)

    for entry in preferred_entries or ():
        add_unicorn(entry, role="persist_how")

    for function in functions or ():
        if not isinstance(function, Mapping):
            continue
        if xor_vas and _function_names_recovered_vas(function, xor_vas, image_base=image_base):
            add_unicorn(
                function.get("entry") or function.get("entry_rva") or function.get("target"),
                role="decoded_config_xref",
            )

    how_candidates: list[tuple[int, object]] = []
    for row in traces or ():
        value = row.get("value") if isinstance(row, Mapping) else None
        payload = value if isinstance(value, Mapping) else row if isinstance(row, Mapping) else {}
        blob = " ".join(
            str(payload.get(key) or "")
            for key in ("api", "api_name", "resolver", "name", "command")
        )
        rank = _how_callsite_priority(blob)
        if rank is None:
            continue
        how_candidates.append(
            (
                rank,
                payload.get("function_entry")
                or payload.get("function")
                or payload.get("callsite")
                or payload.get("resolver_callsite"),
            )
        )
    for function in functions or ():
        if not isinstance(function, Mapping) or _is_import_thunk_name(function.get("name")):
            continue
        blob = " ".join(
            str(item.get("target_name") or item.get("api") or item.get("name") or "")
            for item in (
                *(function.get("references_from") or ()),
                *(function.get("call_targets") or ()),
            )
            if isinstance(item, Mapping)
        )
        blob = f"{blob} {function.get('api') or ''} {function.get('name') or ''}"
        rank = _how_callsite_priority(blob)
        if rank is None:
            continue
        how_candidates.append(
            (
                rank,
                function.get("entry") or function.get("entry_rva") or function.get("target"),
            )
        )
    for _, address in sorted(how_candidates, key=lambda item: item[0]):
        add_unicorn(address, role="how_callsite")

    for function in functions or ():
        if not isinstance(function, Mapping) or not function.get("planned_emulation"):
            continue
        add_unicorn(
            function.get("entry") or function.get("entry_rva") or function.get("target"),
            role="investigation_entry",
        )

    for row in traces or ():
        value = row.get("value") if isinstance(row, Mapping) else None
        payload = value if isinstance(value, Mapping) else row if isinstance(row, Mapping) else {}
        start = recovered_thread_start_address(payload)
        if start:
            add_unicorn(start, role="os_thread_start_routine")

    for function in unique_thread_function_starts(functions):
        entry = function.get("entry") or function.get("entry_rva") or function.get("address")
        add_unicorn(entry, role="thread_creator")

    if not any(item.get("simulator") == "unicorn" for item in windows):
        # The PE entry is only worth a window when it can actually execute.
        #
        # MEASURED on the 白象 sample `64da3378`: the entry body is exactly
        #     push 0x4025f0 ; call <IAT thunk> ; <code>
        # where the thunk (`0x40247c`: `ff 25 e4 10 40 00` -> `jmp [0x4010e4]`) resolves to the VB6
        # runtime import `MSVBVM60.ordinal_100`. Speakeasy cannot resolve that ordinal at LOAD time, so
        # the slot holds its unmapped sentinel `0xfeedf0f0` and the window dies on the first fetch,
        # observing nothing. Across the database that produced 71 FAILED `pe_entry` windows against 39
        # SUCCEEDED. The entry remains a legitimate FALLBACK for a native binary whose entry holds real
        # code, so it is kept - but a sample whose entry is a trampoline gets an explicit decision
        # recorded instead of a wasted worker turn.
        #
        # CORRECTION (measured later, `.scratch/probe-vb6-control-flow.py`): the bytes after the call are
        # NOT padding. An earlier revision of this comment claimed "with the import stubbed it still dies
        # 2 instructions later in the padding", which was only ever true of a stub returning 0. Patching
        # the IAT slot to a stub that returns a NON-NULL pointer lets execution continue past
        # `0x40248e` and run a real instruction sequence (`0x402484, 489, 47c, 48e, 490, 492, ...`),
        # which is a VB6 context walk. So the entry holds code, not alignment filler; what blocks it is
        # the unresolved runtime ordinal, not the absence of behaviour.
        entry_rva = _as_int_address(pe.get("entry_rva") or pe.get("address_of_entry_point"))
        if entry_rva is not None and _entry_is_bootstrap_trampoline(content, pe, entry_rva):
            windows.append(
                {
                    "simulator": "unicorn",
                    "input_bytes": b"",
                    "entry_address": entry_rva,
                    "architecture": pe_architecture,
                    "skip_reason": "pe_entry_is_bootstrap_trampoline",
                    "anchor": {
                        "type": "pe_entry_not_emulatable",
                        "simulator": "unicorn",
                        "role": "pe_entry_trampoline",
                        "reason": (
                            "the entry point only forwards into a runtime bootstrap thunk and has no "
                            "recoverable logic of its own, so emulating it yields no observation"
                        ),
                    },
                }
            )
        else:
            add_unicorn(entry_rva, role="pe_entry")

    if allow_speakeasy and content[:2] == b"MZ" and 64 <= len(content) <= max_pe_bytes:
        # Run FROM a recovered function when one is suitable; fall back to the historical sentinel.
        # MEASURED: with `0x1000000` the adapter's image guard rejects the address and the run falls back
        # to `run_module`, which on a VB6 bootstrap-trampoline entry observes nothing. Running from a
        # recovered function entry instead produced 1,031 modelled calls, 256 API observations and 1,028
        # observed strings in the isolated worker.
        recovery_span = 0
        for section in pe.get("sections") or ():
            if isinstance(section, Mapping):
                virtual = _as_int_address(section.get("virtual_address"))
                size = section.get("virtual_size") or section.get("raw_size")
                if virtual is not None and isinstance(size, int):
                    recovery_span = max(recovery_span, virtual + size - image_base)
        if recovery_span <= 0:
            recovery_span = _SPEAKEASY_RECOVERY_SPAN_FALLBACK
        # The basis comes FROM the selector rather than being inferred here from `is not None`. The two are
        # not the same statement: an address chosen without call-graph evidence is a DEGRADED choice, and
        # collapsing it into the same `recovered_function_entry` label would make a fallback start
        # indistinguishable from an evidence-backed one in the published evidence.
        start_address, start_basis = _speakeasy_entry_from_functions(
            functions,
            image_base=image_base,
            image_span=recovery_span,
            entry_rva=_as_int_address(
                pe.get("entry_rva") or pe.get("address_of_entry_point")
            ),
        )
        speakeasy_window: dict[str, object] = {
            "simulator": "speakeasy",
            "input_bytes": content[:max_pe_bytes],
            "entry_address": start_address if start_address is not None else 0x1000000,
            "anchor": {
                "type": "controlled_emulation",
                "simulator": "speakeasy",
                "start_basis": start_basis,
            },
        }
        windows.append(speakeasy_window)
    if allow_qiling:
        if content.startswith(b"\x7fELF") and 16 <= len(content) <= max_pe_bytes:
            windows.append(
                {
                    "simulator": "qiling",
                    "input_bytes": content[:max_pe_bytes],
                    "entry_address": 0x400000,
                    "architecture": "x86_64",
                    "anchor": {
                        "type": "qiling_linux_usermode",
                        "simulator": "qiling",
                        "role": "linux_elf",
                    },
                }
            )
        # A non-ELF is NOT dispatched to Qiling any more.
        #
        # The old branch below built a qiling window for anything that was not an ELF - 64 bytes of a
        # Windows PE, entry 0x1000000 - and the adapter then rejected it on `payload[:4] != b"\x7fELF"`
        # with `UNSUPPORTED / NOT_LINUX_ELF`. The outcome was therefore decided at window-construction
        # time, so every such window was guaranteed waste. Measured across the database: 418 evidence rows
        # with anchor role `os_mismatch` and zero of them carrying an observation - a sixth of all
        # simulation rows, produced by a branch that could never succeed. The plan now records the
        # decision instead of spending a worker turn on it.
        else:
            windows.append(
                {
                    "simulator": "qiling",
                    "input_bytes": b"",
                    "entry_address": 0x1000000,
                    "architecture": "x86_64",
                    "skip_reason": "qiling_requires_linux_elf",
                    "anchor": {
                        "type": "qiling_not_applicable",
                        "simulator": "qiling",
                        "role": "qiling_not_applicable",
                        "reason": (
                            "granted bytes are not a Linux ELF, and the pinned Qiling adapter is a Linux "
                            "user-mode runner; no Linux execution is claimed for this artifact"
                        ),
                    },
                }
            )
    return tuple(windows[: max(1, max_windows)])
