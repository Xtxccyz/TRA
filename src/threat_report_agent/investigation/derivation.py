"""P3.3e: the implementation module for `AnalysisService._derive_investigation_observations` and its cluster.

WHY THIS MODULE EXISTS. `_derive_investigation_observations` is 2,795 lines and calls 15 in-class helpers, four
module-level names and 16 nested closures. Its helpers split three ways, measured rather than guessed
(`docs/p33e-derivation-slice-design-20260922.md` section 2b, `.scratch/p33e-cluster-fixed-point.py`):

* **PURE** - read by un-moved code as well, no host state: they live in
  `investigation/derivation_support.py`, which is a hostless leaf this module imports.
* **TRAVELS** - no reader outside the giant: they belong HERE, beside the giant that calls them.
* **HOST** - read by un-moved code as well and needing a receiver (or an implementation module): they stay on
  `AnalysisService` and the giant will reach them through an explicit host port, the port being extended by the
  giant's own move rather than by this one.

WHAT IS HERE NOW, after both halves of P3.3e:

  * **THE GIANT ITSELF** - `_derive_investigation_observations` (2,787 lines) as a module-level function whose first
    parameter is `host: DerivationHost` - plus `_DECODE_PRODUCER_KINDS`, the module constant it closes over (its only
    reader was the giant, so it travelled with it);
  * the travelling cluster: `_bind_recovered_xor_verification`, `_decode_output_buffer` and
    `plausible_traced_creation_flags` as module-level functions, the two instruction regexes whose single reader
    travelled, and the four in-class helpers that follow from those two facts;
  * the two execution-seam members (see below) live on the HOST, not here, and the giant reaches them as
    `host._run_simulation_window` / `host._qiling_unavailable_observation`;
  * the host pin (`INVESTIGATION_HOST_MEMBERS`, 7 measured members) and the `DerivationHost` Protocol.

`service.py` keeps one-statement delegations for the methods, so every caller and every test that reaches
`service.<name>` is unchanged. The three module-level functions are re-exported from `service.py` as `X as X` until
P4.3 removes that surface - a review found the mechanical import cleanup had deleted them, which broke
`from threat_report_agent.service import plausible_traced_creation_flags`.

WHY IT IS NOT PART OF `derivation_support.py`: that leaf is deliberately hostless and reachable from un-moved code in
both directions, and it documents which members may NOT sink into it and why. This module is the opposite shape: it
holds the giant and therefore a host port.

THE IMPORT CANONICALISATION IS THE LARGEST OF ITS KIND IN THE PHASE, not a two-name detail. `service.py` reaches
seventeen of the moved body's names through `threat_report_agent.dataflow`, the LEGACY shim path that the plan's import
policy records as debt to be repaid; this module imports all seventeen from `threat_report_agent.facts.dataflow`
instead, which plan section 7.1 step 4 requires of a new implementation. That is the only import rewrite the move
performed, and it is recorded in the step's records.

THE EXECUTION SEAM (P3.3e-move-2a) was carved out one step earlier because it is the migration's only
behaviour-adjacent part: the giant's `CONTROLLED_EMULATE` branch built a simulation runner and called
`qiling_unavailable_observation` inline, and BOTH live in `simulation_adapters`, an IMPLEMENTATION module that plan
section 3.2 does not admit into `investigation/`. The host grew two members whose bodies are the giant's own lines
relocated, and the giant calls them through `host`. This module declares the outcome TYPE of the first of those
(`SimulationWindowOutcome`, below) because it is what consumes it.
"""
from __future__ import annotations

import hashlib
import json
import re

from typing import Iterable, Mapping, Protocol

from threat_report_agent.emulation.emulation_plan import controlled_emulation_windows
from threat_report_agent.emulation.policy import (
    SimulationExecutionPolicy,
    evidence_nature_for_simulation_status,
    simulation_policy_from_settings,
    worker_defers_simulation,
)
# THE WHOLE LEGACY-PATH SET IS CANONICALISED HERE, and it is the largest single act of that kind in the phase: the
# giant closed over SEVENTEEN names that `service.py` reaches through `threat_report_agent.dataflow`, the shim path
# `docs/import-policy.json` records as `legacy_path_imports` debt. Plan section 7.1 step 4 says a new implementation
# must not import the old path, so they are imported from `facts.dataflow`, where every one of them is defined (checked
# name by name by `.scratch/p33e-giant-prep.py`). The two the earlier cluster slice already needed are in this same
# block, so there is one canonical import of this module and not two.
from threat_report_agent.facts.dataflow import (
    addresses_alias,
    catalog_decode_output_to_process_command_relation,
    catalog_fields_from_api_arguments,
    catalog_fields_from_decode_verification,
    catalog_output_consumer_relation,
    catalog_relation_from_api_fields,
    catalog_return_branch_after_call,
    consumer_from_decoded_pointer,
    consumer_from_decoded_reference,
    decoded_output_from_argument_trace,
    is_ghidra_data_or_string_label,
    is_object_level_decode_consumer,
    is_process_command_argument,
    is_projected_catalog_value,
    output_buffer_identity,
    trace_return_consumers,
    with_artifact_identity,
)
from threat_report_agent.investigation import derivation_support as _derivation_support
# From the DEFINING submodule, not the package: the extractor's own lesson is that a package re-export can be a partial
# initialisation, and `investigation/__init__.py` is imported before this module is.
from threat_report_agent.investigation.investigation import (
    ActionSpec,
    ActionType,
    derive_static_mechanism_links,
)
from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol
from threat_report_agent.models import Evidence
from threat_report_agent.static.static_analysis import (
    build_function_semantic_summary,
    build_pcode_slice,
    classify_pe_semantics,
    credible_windows_process_creation_flags,
    creation_flag_from_abi_slot,
    decode_windows_process_creation_flags,
    evidence_function_body,
    is_specialist_ppid_creation_flag,
    recover_static_xor_configs,
    trace_static_api_arguments,
    track_indirect_function_pointers,
    unique_plausible_creation_flag,
    verify_xor_decode_candidate,
)
from threat_report_agent.static.static_simulation import StaticAbstractExecutor


class SimulationWindowOutcome(Protocol):
    """What running ONE granted window through the host's isolated runner reports back.

    DECLARED HERE, WHERE IT IS CONSUMED - a deliberate deviation from the P3.3e design document, which places it "in
    the coordinator". The reason it cannot go there is measurable: `coordinator.py`'s contract test asserts that its
    `INVESTIGATION_HOST_MEMBERS` pin equals EXACTLY the receiver references its own moved bodies make, so widening that
    pin for a member the coordinator never calls would fail a gate that exists to keep pins honest. This type is the
    return of the host member `_run_simulation_window`, and it is what the GIANT's body will consume next step: that
    body reads `status`, `stop_reason` and `output_bytes` and calls `as_dict()` - which is why all four are declared,
    even though the seam member itself only forwards the object.

    The four members are exactly what that body touches (MEASURED in the giant's `CONTROLLED_EMULATE` branch), and
    their types are those of the object the host really returns (`simulation_adapters.SimulationResult`): `status: str`,
    `stop_reason: str | None`, `output_bytes: bytes`. A narrower or wider shape here would be a lie only a type checker
    could catch - and `tests/test_investigation_derivation_seam.py` pins the shape against a real outcome.

    THE HOST PIN WAS DECLARED WITH THE GIANT'S BODY, not with this type. When this Protocol was written (the execution
    seam) the giant was still on the host, and a pin must name exactly what this module's own bodies read - declaring
    seven host members for a module that read none of them would have been the aspirational-pin defect this phase has
    already recorded once. The step that moved the giant declared the pin in the same change, and
    `tests/test_investigation_derivation_contract.py` asserts the equality the coordinator's contract test asserts.
    """

    status: str
    stop_reason: str | None
    output_bytes: bytes

    def as_dict(self) -> dict[str, object]: ...


#: What `_derive_investigation_observations` may still reach through its `host` parameter, MEASURED name by name against
#: `service.py` (`.scratch/p33e-giant-prep.py` prints every receiver reference the giant makes together with the
#: signature the host member really has).
#:
#: WHY EACH ONE IS ON THE PORT RATHER THAN MOVED HERE:
#:
#:   * `settings` is an instance attribute, so it is host state by construction;
#:   * `_run_simulation_window` / `_qiling_unavailable_observation` wrap `simulation_adapters`, an implementation module
#:     plan section 3.2 does not admit into `investigation/` (added by the execution seam, one step before this one);
#:   * `_emulation_entry_key` needs the same emulation implementation module;
#:   * `_follow_local_tail_jmp` reads `_MAX_GHIDRA_INSTRUCTIONS_PER_FUNCTION`, which two UN-MOVED methods also read, so
#:     the class attribute must stay on the class and its reader stays with it (design section 2b);
#:   * `_investigation_value_text` calls itself through the CLASS NAME, so moving it here would make this module import
#:     `service` and create a cycle;
#:   * `_matching_simulation_results` needs the same emulation implementation module as the two seam members.
#:
#: The four pure helpers the giant also calls (`_locator_key`, `_function_entry_integers`,
#: `_overlay_pe_parser_thread_start`, `_pe_entry_integers`) are NOT here: they live in `derivation_support` and the moved
#: body reaches them as `_derivation_support.<name>`. The four members this module already owns
#: (`_row_own_function_matches`, `_instruction_access_kind`, `_reference_access_kind`, `_global_accesses_from_rows`) are
#: not here either - the moved body calls them BARE, because they are in this module.
INVESTIGATION_HOST_MEMBERS: tuple[str, ...] = (
    "settings",
    # --- added by P3.3e's execution seam, one step before the giant moved ---
    "_run_simulation_window",
    "_qiling_unavailable_observation",
    # --- the four helpers that stay on the host for the measured reasons above ---
    "_emulation_entry_key",
    "_follow_local_tail_jmp",
    "_investigation_value_text",
    "_matching_simulation_results",
)


class DerivationHost(Protocol):
    """What the moved derivation may use on the object that owns it.

    SEVEN members, each measured. `settings` is annotated loosely ON PURPOSE, the same choice the coordinator's port
    documents for `database`: naming its concrete class here would create an import edge from `investigation/` to a
    module plan section 3.2 does not list, purely to describe an attribute this code only reads fields from at runtime.

    The rest are declared with the shapes the host really has them in: two plain methods (`_run_simulation_window`,
    `_qiling_unavailable_observation`), THREE classmethods that the moved code calls on the instance
    (`_emulation_entry_key`, `_follow_local_tail_jmp`, `_matching_simulation_results`) and one staticmethod
    (`_investigation_value_text`). A first version of this sentence miscounted them; a Standards-axis review of the
    move measured the real shapes.
    """

    settings: object

    def _run_simulation_window(
        self, policy: SimulationExecutionPolicy, window: Mapping[str, object]
    ) -> SimulationWindowOutcome: ...

    def _qiling_unavailable_observation(
        self, policy: SimulationExecutionPolicy
    ) -> dict[str, object] | None: ...

    def _emulation_entry_key(self, value: Mapping[str, object] | str | None) -> str: ...

    def _follow_local_tail_jmp(
        self, function: dict[str, object], artifact_rows: list[object]
    ) -> dict[str, object]: ...

    @staticmethod
    def _investigation_value_text(value: object, *, limit: int = 12000) -> str: ...

    def _matching_simulation_results(
        self,
        rows: Iterable[object],
        selector: Mapping[str, object],
        *,
        require_success: bool = True,
    ) -> tuple[object, ...]: ...


# NO `missing_investigation_host_members` HELPER HERE, and the reason is a gate that fired: the structure-diff check
# reported `duplicate canonical implementation: missing_investigation_host_members` between this module and
# `coordinator.py`, because copying the coordinator's helper produces a byte-identical body in a second place. That
# helper is bound to ITS pin, so a shared one would have to take the pin as an argument; the honest shape is that this
# module exports the PIN (data) and the Protocol (shape), and that a contract test evaluates the pin directly - which is
# what `tests/test_investigation_derivation_contract.py` now does. A second copy of a ten-line function is a worse trade
# than a comprehension in a test, and the gate was right to refuse it.


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py. The receiver each body used to reach
# through `self`/`cls` is either DROPPED (the cluster helpers below, which need none) or an explicit
# `host: DerivationHost` parameter (the giant, which reads seven host members). This banner is deliberately
# SLICE-AGNOSTIC, and it was written by the first slice that landed here - the extractor deduplicates the banner, so
# keeping it TRUE for the module as it grows is the reader's job, and a review of the giant's move found this
# parenthetical still claiming the module declares no host port.
# ---------------------------------------------------------------------------


def _row_own_function_matches(row: object, target: str) -> bool:
    target_text = str(target or "").strip()
    if not target_text:
        return False
    payload = _derivation_support._row_own_function_payload(row)
    name = str(payload.get("name") or payload.get("function") or "").strip()
    if name and name.casefold() == target_text.casefold():
        return True
    target_ints = _derivation_support._code_locator_integers(target_text)
    if not target_ints:
        return False
    own = _derivation_support._function_entry_integers(payload) | _derivation_support._code_locator_integers(name)
    return bool(target_ints & own)


def _instruction_access_kind(text: object) -> str | None:
    folded = str(text or "").strip()
    if not folded:
        return None
    if _DATA_STORE_INSTRUCTION.search(folded):
        return "write"
    if _DATA_LOAD_INSTRUCTION.search(folded):
        return "read"
    return None


def _reference_access_kind(
    ref_type: object, instruction_text: object = ""
) -> str | None:
    folded = str(ref_type or "").upper()
    if "CALL" in folded:
        return None
    if "READ_WRITE" in folded or "WRITE" in folded or "STORE" in folded:
        return "write"
    if "READ" in folded or "LOAD" in folded:
        return "read"
    return _instruction_access_kind(instruction_text)


def _global_accesses_from_rows(
    rows: Iterable[object],
) -> tuple[dict[str, object], ...]:
    """Collect WRITE/READ data references without executing the image."""
    instruction_text: dict[str, str] = {}
    for row in rows:
        kind = str(getattr(row, "kind", "") or "")
        value = getattr(row, "value", None)
        value = value if isinstance(value, dict) else {}
        if kind not in {"function_instruction_window", "function_context"}:
            continue
        raw_instructions = value.get("instructions") or ()
        if not isinstance(raw_instructions, list):
            continue
        for item in raw_instructions:
            if not isinstance(item, dict):
                continue
            address = _derivation_support._locator_key(item.get("address") or item.get("from"))
            if address:
                instruction_text[address] = str(
                    item.get("text") or item.get("mnemonic") or ""
                )
    found: list[dict[str, object]] = []
    for row in rows:
        kind = str(getattr(row, "kind", "") or "")
        value = getattr(row, "value", None)
        value = value if isinstance(value, dict) else {}
        anchor = getattr(row, "anchor", None)
        anchor = anchor if isinstance(anchor, dict) else {}
        entry = _derivation_support._locator_key(
            value.get("entry") or anchor.get("function_entry") or anchor.get("entry")
        )
        function_name = str(value.get("name") or "")
        refs: list[object] = []
        if kind == "data_reference":
            refs.append(value)
        else:
            raw = value.get("data_references") or value.get("references") or ()
            if isinstance(raw, list):
                refs.extend(raw)
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            ref_type = str(
                ref.get("type") or ref.get("reference_type") or ref.get("access") or ""
            )
            site = _derivation_support._locator_key(ref.get("from"))
            access = _reference_access_kind(
                ref_type, instruction_text.get(site, "")
            )
            if access is None:
                continue
            name = str(ref.get("target_name") or ref.get("name") or "").strip()
            address = _derivation_support._locator_key(
                ref.get("to") or ref.get("address") or ref.get("target")
            )
            if not name and not address:
                continue
            found.append(
                {
                    "function_entry": entry or _derivation_support._locator_key(ref.get("from")),
                    "function_name": function_name,
                    "access": access,
                    "name": name or address,
                    "address": address,
                    "row": row,
                }
            )
    return tuple(found)


def _bind_recovered_xor_verification(
    candidate: Mapping[str, object],
    recovered: Iterable[Mapping[str, object]],
    claimed: set[str],
    *,
    image_base: int = 0,
) -> dict[str, object] | None:
    """Assign at most one recovered XOR config to one DECODE_CANDIDATE row.

    ``recover_static_xor_configs`` can return several buffers. Binding every
    address-less row to ``recovered[0]`` made a second blob inherit the first
    buffer's consumer. Match the declared output/VA when present; otherwise
    consume the next unused hit once.
    """
    wanted = candidate.get("output_buffer") if isinstance(candidate.get("output_buffer"), Mapping) else {}
    wanted_address = wanted.get("address") if isinstance(wanted, Mapping) else None
    raw_addresses = candidate.get("memory_addresses")
    if wanted_address in (None, "") and isinstance(raw_addresses, (list, tuple)) and raw_addresses:
        wanted_address = raw_addresses[0]
    fallback: Mapping[str, object] | None = None
    for item in recovered:
        if not isinstance(item, Mapping):
            continue
        token = str(item.get("file_offset") if item.get("file_offset") is not None else item.get("virtual_address") or "")
        if not token or token in claimed:
            continue
        output = item.get("output_buffer") if isinstance(item.get("output_buffer"), Mapping) else {}
        hit_address = output.get("address") if isinstance(output, Mapping) else item.get("virtual_address")
        if wanted_address not in (None, ""):
            if not addresses_alias(wanted_address, hit_address, image_base):
                continue
            claimed.add(token)
            return dict(item)
        if fallback is None:
            fallback = item
            fallback_token = token
    if fallback is not None:
        claimed.add(fallback_token)
        return dict(fallback)
    return None


def _decode_output_buffer(row: Evidence) -> dict[str, object] | None:
    """Return a producer-declared decoder output identity, never a ciphertext fallback."""
    value = row.value if isinstance(getattr(row, "value", None), dict) else {}
    buffers = [value.get("output_buffer")]
    verification = value.get("verification_result") or value.get("verification")
    if isinstance(verification, Mapping):
        buffers.append(verification.get("output_buffer"))
    for buf in buffers:
        if not isinstance(buf, Mapping):
            continue
        identity = output_buffer_identity(
            address_space=buf.get("address_space"),
            address=buf.get("address"),
            length=buf.get("length"),
        )
        if identity is not None:
            return identity
    return None


def plausible_traced_creation_flags(parsed_flags: int | None) -> int | None:
    """Return the immediate only when it can be a real ``dwCreationFlags`` argument.

    G1 §4.5/§5.4: the TRACE_API_ARGUMENT path used to exclude only
    ``0xFFFFFFFF``/``0xFFFFFFFE``, so a neighbouring timeout constant such as
    ``0x000f4240`` (1,000,000 ms) was written as ``process_creation_flags``
    Evidence and reached the process-creation HOW. Bit 19 of that value happens to
    coincide with ``EXTENDED_STARTUPINFO_PRESENT``, so the coarse plausibility
    table alone is not enough: ``credible_windows_process_creation_flags`` also
    rejects an immediate carrying several undocumented bits.
    """
    if parsed_flags is None:
        return None
    if not credible_windows_process_creation_flags(parsed_flags):
        return None
    return parsed_flags


_DATA_LOAD_INSTRUCTION = re.compile(
    r"(?i)\b(?:MOV|MOVZX|MOVSX|LEA|LODS|AND|OR|XOR|ADD|SUB|CMP|TEST)\s+"
    r"[^,]+,\s*(?:(?:BYTE|WORD|DWORD|QWORD)\s+PTR\s+)?\["
)


_DATA_STORE_INSTRUCTION = re.compile(
    r"(?i)\b(?:MOV|MOVZX|MOVSX|XCHG|STOS|AND|OR|XOR|ADD|SUB)\s+"
    r"(?:(?:BYTE|WORD|DWORD|QWORD)\s+PTR\s+)?\["
)


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py. The receiver it used to reach
# through `self`/`cls` is now an explicit `host: DerivationHost` parameter, and ONLY where the body still
# needs one. This banner is deliberately SLICE-AGNOSTIC: it used to name the first slice, so the second slice's
# code was appended under a label that lied about which step moved it.
# ---------------------------------------------------------------------------


def _derive_investigation_observations(
    host: DerivationHost,
    source_rows: list[Evidence],
    action: ActionSpec,
    *,
    artifact_content: bytes | None = None,
    pe_summary: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Execute a catalog action against existing static evidence only.

        These actions are intentionally read-only.  They provide a real
        executor seam today and can later be backed by Ghidra/Qiling workers
        without changing the queue, persistence, or Claim Gate contracts.
        """
    # Keep the complete artifact-local set before applying citation scope.
    # A cited function/xref is an authorization anchor; the static query
    # may then inspect the same function's already-persisted context (call
    # edges, instruction window, CFG) without crossing the artifact
    # boundary.  This is what makes GET_DECOMPILE/GET_PCODE_SLICE useful
    # when a model cites a single xref row.
    artifact_rows = list(source_rows)
    # A model action is causally authorized only by the Evidence IDs it
    # cited.  Deterministic playbook actions have no citations and retain
    # the complete artifact-local source set.  Always enforce the artifact
    # boundary here as a second line of defense for callers that bypass the
    # planner validation path.
    # Some offline callers provide lightweight evidence-shaped objects
    # without an artifact_id (the artifact boundary is already implicit in
    # that fixture).  Enforce the boundary whenever the source carries
    # the field, while retaining compatibility with those value objects.
    if any(getattr(row, "artifact_id", None) is not None for row in artifact_rows):
        artifact_rows = [
            row
            for row in artifact_rows
            if getattr(row, "artifact_id", None) == action.artifact_id
        ]
    if action.source_evidence_ids:
        cited_ids = set(action.source_evidence_ids)
        source_rows = [row for row in artifact_rows if row.id in cited_ids]
    else:
        source_rows = artifact_rows
    known_apis = (
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
        "OpenProcess",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
        "UpdateProcThreadAttribute",
        "InitializeProcThreadAttributeList",
        "CreateProcess",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpConnect",
        "WinHttpReceiveResponse",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
    )
    token_rows: list[tuple[Evidence, str]] = [
        (
            row,
            host._investigation_value_text({"value": row.value, "anchor": row.anchor}),
        )
        for row in source_rows
    ]
    selector = dict(action.target_selector) or dict(action.parameters)
    target = ""
    for key in ("target", "api", "function", "function_entry", "entry", "rva", "address"):
        value = selector.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            target = str(value).strip()
            break
    target_casefold = target.casefold()

    def selectors(value: object) -> set[str]:
        if not isinstance(value, dict):
            return set()
        result: set[str] = set()
        for key in (
            "name",
            "entry",
            "function_entry",
            "rva",
            "address",
            "from",
            "to",
            "target",
            "target_name",
            "target_function",
            "caller",
            "callee",
        ):
            item = value.get(key)
            if isinstance(item, (str, int)) and str(item).strip():
                result.add(str(item).casefold())
        return result

    all_token_rows: list[tuple[Evidence, str]] = [
        (
            row,
            host._investigation_value_text({"value": row.value, "anchor": row.anchor}),
        )
        for row in artifact_rows
    ]
    wildcard_targets = {
        "global",
        "file",
        "strings",
        "string",
        "str",
        "file_header",
        "pe_header",
        "pe_headers_and_imports",
        "strings_and_signals",
        "functions_and_xrefs",
        "script",
        "document",
        "carrier",
        "decode",
        "network",
        # Resource-backed payload actions intentionally use an artifact
        # scoped selector.  The resource inventory rows carry the exact
        # offsets/entry metadata; the wildcard keeps the action useful
        # when the parser has no stable resource name, while the cited
        # Evidence IDs still constrain model-originated requests.
        "resource",
        "payload",
        "embedded",
        "archive",
        "staging",
    }
    target_rows = (
        all_token_rows
        if not target_casefold or target_casefold in wildcard_targets
        else [(row, text) for row, text in all_token_rows if target_casefold in text.casefold()]
    )
    # Normalize the planner's logical entry-point selector to the PE
    # AddressOfEntryPoint.  Ghidra rows may store that as an RVA or as
    # image_base+RVA; both must resolve.  Matching the literal word
    # ``entry`` as a wildcard previously selected a random small function.
    if target_casefold in {"entry", "entrypoint", "entry_point", "address_of_entry_point"}:
        locators = _derivation_support._pe_entry_integers(
            pe_summary if isinstance(pe_summary, dict) else {}
        )
        target_rows = [
            (row, text)
            for row, text in all_token_rows
            if locators & _derivation_support._function_entry_integers(
                {
                    **(row.value if isinstance(row.value, dict) else {}),
                    **(row.anchor if isinstance(row.anchor, dict) else {}),
                }
            )
        ]
        for row, _ in target_rows:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            for item in (
                anchor.get("function_entry"),
                value.get("entry"),
                value.get("entry_rva"),
                anchor.get("rva"),
            ):
                if item is not None and str(item).strip():
                    target_casefold = str(item).strip().casefold()
                    break
            else:
                continue
            break
    abstract_function_actions = {
        ActionType.GET_DECOMPILE,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_CFG_SLICE,
    }
    if action.action_type in abstract_function_actions and target_casefold not in wildcard_targets:
        own_rows = [
            (row, text)
            for row, text in all_token_rows
            if _row_own_function_matches(row, target)
            or _row_own_function_matches(row, target_casefold)
        ]
        if own_rows:
            target_rows = own_rows
    # Function/RVA actions use a cited row as the seed and expand to every
    # row sharing its function identity.  This handles Ghidra's split
    # Evidence model where context, instruction windows, CFG and calls are
    # separate rows with the same function_entry anchor.
    if target_casefold not in wildcard_targets:
        seed_keys: set[str] = set()
        # A selector that names a function is itself a bounded target. If
        # the context row matches but the instruction window does not
        # contain the textual function name, expand to sibling Evidence
        # rows sharing the same function entry. Citation-scoped model
        # actions still remain bounded by ``source_evidence_ids`` because
        # ``all_token_rows`` is the artifact-local corpus and the seed
        # keys are derived only from cited rows when citations exist.
        seed_basis = (
            source_rows
            if action.source_evidence_ids
            else [
                row
                for row, _ in target_rows
                if row.kind
                in {
                    "function",
                    "function_context",
                    "function_instruction_window",
                    "function_call",
                    "cfg_block",
                }
            ]
        )
        for row in seed_basis:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            if action.action_type in abstract_function_actions:
                seed_keys.update(
                    selectors(
                        {
                            "name": value.get("name"),
                            "entry": value.get("entry", anchor.get("entry")),
                            "function_entry": anchor.get("function_entry"),
                            "rva": value.get("entry_rva", anchor.get("rva")),
                        }
                    )
                )
                continue
            seed_keys.update(
                selectors(
                    {
                        "name": value.get("name"),
                        "entry": value.get("entry", anchor.get("entry")),
                        "function_entry": anchor.get("function_entry"),
                        "rva": value.get("entry_rva", anchor.get("rva")),
                        "from": value.get("from", anchor.get("from")),
                        "to": value.get("to"),
                        "target_name": value.get("target_name"),
                        "target_function": value.get("target_function"),
                    }
                )
            )
        expanded_rows: list[tuple[Evidence, str]] = []
        for row, text in all_token_rows:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            if action.action_type in abstract_function_actions:
                row_keys = selectors(
                    {
                        "name": value.get("name"),
                        "entry": value.get("entry", anchor.get("entry")),
                        "function_entry": anchor.get("function_entry"),
                        "rva": value.get("entry_rva", anchor.get("rva")),
                    }
                )
            else:
                row_keys = selectors(
                    {
                        "name": value.get("name"),
                        "entry": value.get("entry", anchor.get("entry")),
                        "function_entry": anchor.get("function_entry"),
                        "rva": value.get("entry_rva", anchor.get("rva")),
                        "from": value.get("from", anchor.get("from")),
                        "to": value.get("to"),
                        "target_name": value.get("target_name"),
                        "target_function": value.get("target_function"),
                    }
                )
            if seed_keys & row_keys:
                expanded_rows.append((row, text))
        if expanded_rows:
            target_rows = expanded_rows
    observations: list[dict[str, object]] = []

    def symbols_match(observed: object, expected: object) -> bool:
        """Match exact API/RVA identities across exporter decoration."""
        observed_text = str(observed or "").strip()
        expected_text = str(expected or "").strip()
        if not observed_text or not expected_text:
            return False
        if observed_text.casefold() == expected_text.casefold():
            return True
        # Numeric function/RVA locators remain exact.  Normalization is
        # intended for symbols such as ``KERNEL32!CreateProcessW`` only.
        numeric_pattern = r"(?:0x)?[0-9a-f]+"
        if re.fullmatch(numeric_pattern, observed_text, re.IGNORECASE) or re.fullmatch(
            numeric_pattern, expected_text, re.IGNORECASE
        ):
            return False
        observed_symbol = normalize_api_symbol(observed_text)
        expected_symbol = normalize_api_symbol(expected_text)
        return bool(observed_symbol and expected_symbol and observed_symbol == expected_symbol)

    def add(
        kind: str,
        value: dict[str, object],
        rows: list[Evidence],
        *,
        nature: str = "STATIC_DERIVED",
    ) -> None:
        if not rows:
            return
        source_evidence_ids = [item.id for item in rows[:24]]
        source_anchors = [
            item.anchor for item in rows[:24] if isinstance(item.anchor, dict) and item.anchor
        ]
        input_digest = hashlib.sha256(
            json.dumps(
                {
                    "action_type": action.action_type.value,
                    "target": target,
                    "source_evidence_ids": source_evidence_ids,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        output_digest = hashlib.sha256(
            json.dumps(value, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        # The Ghidra persistence path uses ``entry`` on the immutable
        # function-context anchor, while older/exported rows may use
        # ``function_entry``.  Derived action evidence must expose one
        # canonical locator at the top level so a later action/report can
        # merge function_context, instruction windows and calls without
        # re-parsing provenance lists.
        function_entry = next(
            (
                str(anchor.get(field))
                for anchor in source_anchors
                for field in ("function_entry", "entry", "function")
                if anchor.get(field) is not None and str(anchor.get(field)).strip()
            ),
            None,
        )
        rva = next(
            (
                str(anchor.get("rva"))
                for anchor in source_anchors
                if anchor.get("rva") is not None and str(anchor.get("rva")).strip()
            ),
            None,
        )
        derived_anchor = {
            "type": "investigation_action",
            "action_type": action.action_type.value,
            "target_selector": target or None,
            "source_evidence_ids": source_evidence_ids,
            "source_anchors": source_anchors,
            **({"function_entry": function_entry} if function_entry else {}),
            **({"rva": rva} if rva else {}),
        }
        observations.append(
            {
                "kind": kind,
                "value": {
                    **value,
                    "source_evidence_ids": source_evidence_ids,
                    "derivation": {
                        "evaluator": "static-evidence-query-v2",
                        "input_evidence_ids": source_evidence_ids,
                        "input_digest": input_digest,
                        "output_digest": output_digest,
                        "exact": nature == "STATIC_DERIVED",
                    },
                },
                "anchor": derived_anchor,
                "nature": nature,
            }
        )

    def function_identity(row: Evidence) -> set[str]:
        value = row.value if isinstance(row.value, dict) else {}
        anchor = row.anchor if isinstance(row.anchor, dict) else {}
        return selectors(
            {
                "name": value.get("name"),
                "entry": value.get("entry", anchor.get("entry")),
                "function_entry": anchor.get("function_entry"),
                "rva": value.get("entry_rva", anchor.get("rva")),
            }
        )

    def function_label(row: Evidence) -> str:
        value = row.value if isinstance(row.value, dict) else {}
        anchor = row.anchor if isinstance(row.anchor, dict) else {}
        for item in (
            value.get("name"),
            value.get("entry"),
            anchor.get("function_entry"),
            value.get("entry_rva"),
        ):
            if isinstance(item, (str, int)) and str(item).strip():
                return str(item)
        return ""

    def function_edges(row: Evidence, field: str) -> list[dict[str, object]]:
        value = row.value if isinstance(row.value, dict) else {}
        raw = value.get(field, ())
        if not isinstance(raw, list):
            return []
        return [
            dict(item) if isinstance(item, dict) else {"target_name": str(item)}
            for item in raw
            if isinstance(item, (dict, str, int)) and str(item).strip()
        ]

    def edge_target(edge: dict[str, object]) -> str:
        for key in (
            "target_name",
            "target_function",
            "to",
            "target",
            "api",
            "indicator",
            "name",
            "entry",
        ):
            item = edge.get(key)
            if isinstance(item, (str, int)) and str(item).strip():
                return str(item)
        return ""

    def edge_matches_target(edge: dict[str, object], expected: str) -> bool:
        """Match Ghidra symbol/RVA aliases without broad co-occurrence.

            Exporters commonly spell one destination as ``FUN_14000a2c0``,
            ``0x14000a2c0`` or ``14000a2c0``.  Caller actions are keyed by the
            canonical target selector, so exact string comparison silently
            dropped valid caller edges whenever the exporter added a symbol
            prefix.  Compare explicit edge locator fields and a token-bounded
            rendered fallback; never accept a decimal substring inside an
            unrelated identifier.
            """
        needle = str(expected or "").strip().casefold()
        if not needle:
            return False
        values: set[str] = set()
        for key in (
            "target_name", "target_function", "to", "target", "api",
            "indicator", "name", "entry", "target_entry", "target_rva",
            "callee", "callee_entry", "callee_rva",
        ):
            item = edge.get(key)
            if isinstance(item, (str, int)) and str(item).strip():
                values.add(str(item).strip().casefold())
        if needle in values:
            return True
        # Numeric RVA/address aliases may be wrapped by FUN_/function_ or
        # carry a 0x prefix.  Keep the match token-bounded.
        numeric = needle[2:] if needle.startswith("0x") else needle
        if numeric and re.fullmatch(r"[0-9a-f]+", numeric):
            aliases = {
                numeric,
                f"0x{numeric}",
                f"fun_{numeric}",
                f"function_{numeric}",
            }
            if values & aliases:
                return True
            rendered = " ".join(values)
            return re.search(
                rf"(?<![A-Za-z0-9_])(?:0x)?{re.escape(numeric)}(?![A-Za-z0-9_])",
                rendered,
                flags=re.IGNORECASE,
            ) is not None
        # Named symbols can be qualified by a namespace or DLL.  Only
        # accept a token-bounded suffix, preserving exactness for names
        # such as ``CreateProcess`` vs ``CreateProcessW``.
        rendered = " ".join(values)
        return re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])",
            rendered,
            flags=re.IGNORECASE,
        ) is not None

    # These investigation actions use the same safe abstract executor as
    # the Ghidra persistence path.  They refine a hypothesis from existing
    # static evidence and never load or execute the sample.
    abstract_actions = {
        ActionType.READ_BYTES,
        ActionType.GET_DECOMPILE,
        ActionType.GET_PCODE_SLICE,
        ActionType.GET_CFG_SLICE,
        ActionType.TRACE_API_ARGUMENT,
        ActionType.TRACE_RETURN_VALUE,
        ActionType.TRACE_GLOBAL_USAGE,
    }
    if action.action_type in abstract_actions:
        # The analysed body is rebuilt by one pure helper so the
        # completeness contract (full recovered instruction list, no hidden
        # prefix cut) is testable without a task or a sample.  This dict is
        # the input to the abstract executor, the CFG slice and the
        # decompile projection, so it must carry the complete recovered
        # instruction list.
        function = evidence_function_body(
            action=action,
            target_rows=target_rows,
            fallback_name="investigation-target",
        )
        # The helper returns the analysed body under its public keys; the
        # same lists were local names before the extraction.
        data_reference_rows = function["data_references"]
        context = function.get("context", {})
        if action.action_type == ActionType.GET_DECOMPILE:
            function = host._follow_local_tail_jmp(function, artifact_rows)
        source_ids = [
            row.id
            for row, _ in target_rows
            if row.kind
            in {
                "function_context",
                "function_instruction_window",
                "function_call",
                "function_mechanism",
            }
        ]
        simulated = StaticAbstractExecutor(
            max_steps=host.settings.static_abstract_execution_max_steps
        ).analyze(
            function, source_evidence_ids=source_ids
        )
        relevant_rows = [
            row
            for row, _ in target_rows
            if row.kind
            in {
                "function_context",
                "function_instruction_window",
                "function_call",
                "function_mechanism",
            }
        ]
        add(
            "abstract_execution_trace",
            simulated.as_dict(),
            relevant_rows[:24],
            nature="STATIC_INFERRED",
        )
        # Keep each abstract probe distinguishable in the evidence ledger.
        # A shared ``abstract_execution_trace`` is useful context, but it
        # must not satisfy CFG/byte/value-flow facets belonging to a
        # different action.
        if action.action_type == ActionType.GET_DECOMPILE:
            add(
                "decompile_slice",
                {
                    "function": function,
                    "summary": simulated.as_dict(),
                    "static_only": True,
                },
                relevant_rows[:24],
                nature="STATIC_INFERRED",
            )
            # A decompile action must answer the analyst's question, not
            # merely return another instruction-shaped payload.  The
            # ordered semantic projection joins the same function's
            # calls, bounded argument producers, predicates and
            # downstream consumers, while retaining explicit static-only
            # and runtime-unknown boundaries.  This makes a recursive
            # deep-mining action produce a mechanism-oriented observation
            # that the report and the next planner turn can consume.
            semantic_summary = build_function_semantic_summary(function)
            add(
                "function_semantic_summary",
                semantic_summary,
                relevant_rows[:24],
                nature="STATIC_INFERRED",
            )
        elif action.action_type == ActionType.GET_CFG_SLICE:
            cfg_rows = [row for row, _ in target_rows if row.kind == "cfg_block"]
            cfg_blocks = []
            for row in cfg_rows[:128]:
                value = row.value if isinstance(row.value, dict) else {}
                cfg_blocks.append(dict(value))
            context_cfg = context.get("cfg_blocks", context.get("cfg", []))
            if isinstance(context_cfg, list):
                cfg_blocks.extend(
                    dict(item) for item in context_cfg[:128] if isinstance(item, dict)
                )
            if cfg_blocks:
                add(
                    "cfg_block",
                    {
                        "function_entry": function.get("entry"),
                        "blocks": cfg_blocks[:128],
                        "block_count": len(cfg_blocks),
                        "static_only": True,
                    },
                    cfg_rows or relevant_rows[:24],
                    nature="STATIC_DERIVED",
                )
        elif action.action_type == ActionType.READ_BYTES:
            if artifact_content:
                # Resource inventories expose file offsets and sizes for
                # RT_RCDATA/embedded entries.  Reading the file prefix
                # for every READ_BYTES action used to make a resource
                # investigation technically productive but semantically
                # useless.  Prefer the first bounded resource entry and
                # retain a prefix fallback only when no offset is known.
                resource_kinds = {
                    "resource_inventory",
                    "pe_resource",
                    "mechanism_resource_payload",
                    "mechanism_resource_extraction",
                    "mechanism_decompression",
                    "mechanism_decompression_format",
                    "mechanism_decode",
                    "mechanism_integrity_check",
                    "pe_resource_directory",
                    "embedded_object",
                    "embedded_artifact",
                    "document_embedded_object",
                    "document_embedded_file",
                    "archive_member",
                    "decoded_artifact",
                }

                def _as_nonnegative_int(value: object) -> int | None:
                    try:
                        parsed = int(str(value), 0)
                    except (TypeError, ValueError):
                        try:
                            parsed = int(str(value), 16)
                        except (TypeError, ValueError):
                            return None
                    return parsed if parsed >= 0 else None

                resource_entries: list[tuple[Evidence, dict[str, object]]] = []
                for row, _ in target_rows:
                    if row.kind not in resource_kinds:
                        continue
                    value = row.value if isinstance(row.value, dict) else {}
                    entries = value.get("entries")
                    candidates = entries if isinstance(entries, list) else [value]
                    for candidate in candidates:
                        if not isinstance(candidate, dict):
                            continue
                        offset = next(
                            (
                                _as_nonnegative_int(candidate.get(key))
                                for key in ("file_offset", "payload_offset", "data_offset", "offset")
                                if candidate.get(key) is not None
                            ),
                            None,
                        )
                        if offset is None:
                            continue
                        resource_entries.append((row, {**candidate, "file_offset": offset}))
                        if len(resource_entries) >= 8:
                            break
                    if len(resource_entries) >= 8:
                        break

                if not resource_entries:
                    resource_entries = [
                        (row, {})
                        for row, _ in (target_rows[:1] or all_token_rows[:1])
                    ]
                for row, entry in resource_entries:
                    offset = _as_nonnegative_int(
                        selector.get("offset")
                        or selector.get("file_offset")
                        or entry.get("file_offset")
                    ) or 0
                    requested_size = _as_nonnegative_int(
                        selector.get("length")
                        or selector.get("size")
                        or entry.get("size")
                        or entry.get("payload_size")
                    )
                    end = min(
                        len(artifact_content),
                        offset + min(requested_size or 4096, 4096),
                    )
                    window = artifact_content[offset:end]
                    if not window:
                        continue
                    add(
                        "bytes_read",
                        {
                            "selector": dict(selector),
                            "offset": offset,
                            "byte_count": len(window),
                            "declared_size": requested_size,
                            "resource_entry": {
                                key: value
                                for key, value in entry.items()
                                if key not in {"content", "bytes"}
                            },
                            "sha256": hashlib.sha256(window).hexdigest(),
                            "preview_hex": window[:64].hex(),
                            "static_only": True,
                        },
                        [row],
                        nature="STATIC_OBSERVED",
                    )
        elif action.action_type == ActionType.TRACE_RETURN_VALUE:
            groups: dict[str, list[Evidence]] = {}
            for evidence in artifact_rows:
                if evidence.kind not in {"function_context", "function_instruction_window"}:
                    continue
                value = evidence.value if isinstance(evidence.value, dict) else {}
                anchor = evidence.anchor if isinstance(evidence.anchor, dict) else {}
                entry = str(anchor.get("function_entry") or anchor.get("entry")
                            or value.get("entry") or "").casefold()
                if not entry:
                    continue
                if re.fullmatch(r"(?:0x)?[0-9a-f]+", entry):
                    entry = f"0x{int(entry, 16):x}"
                groups.setdefault(entry, []).append(evidence)
            producer_aliases = tuple(str(value) for value in (
                target, function.get("name"), function.get("entry")
            ) if value)
            found = False
            for entry, group in groups.items():
                contexts = [item for item in group if item.kind == "function_context"]
                if not contexts:
                    continue
                caller = dict(contexts[0].value)
                caller["entry"] = entry
                instructions: dict[str, dict[str, object]] = {}
                conflicting = False
                for item in group:
                    value = item.value if isinstance(item.value, dict) else {}
                    for instruction in value.get("instructions", []):
                        if not isinstance(instruction, dict):
                            continue
                        address = str(instruction.get("address") or "")
                        previous = instructions.get(address)
                        if previous and previous.get("text") != instruction.get("text"):
                            conflicting = True
                        instructions[address] = instruction
                if conflicting:
                    continue
                caller["instructions"] = list(instructions.values())
                ordered_instructions = sorted(
                    (
                        item
                        for item in caller["instructions"]
                        if isinstance(item, Mapping)
                    ),
                    key=lambda item: str(item.get("address") or item.get("offset") or ""),
                )
                return_branch = None
                for index, instruction in enumerate(ordered_instructions):
                    text = str(instruction.get("text") or instruction.get("mnemonic") or "")
                    if not re.search(r"(?i)\bCALL\b", text):
                        continue
                    if not any(
                        str(alias).strip()
                        and str(alias).casefold() in text.casefold()
                        for alias in producer_aliases
                    ):
                        continue
                    return_branch = catalog_return_branch_after_call(
                        ordered_instructions[index + 1 : index + 13]
                    )
                    if return_branch:
                        break
                if return_branch:
                    add(
                        "return_value_trace",
                        {
                            "return_branch": return_branch,
                            "function": caller.get("name"),
                            "function_entry": entry,
                            "producer": next(
                                (str(item) for item in producer_aliases if item),
                                None,
                            ),
                            "static_only": True,
                        },
                        [*group, *relevant_rows][:24],
                    )
                links = trace_return_consumers(caller, producer_aliases)
                if not links:
                    continue
                found = True
                add(
                    "value_flow",
                    {
                        "direction": "return_to_consumers",
                        "function": function.get("name"),
                        "function_entry": function.get("entry"),
                        "caller_function": caller.get("name"),
                        "caller_entry": entry,
                        "consumers": list(dict.fromkeys(str(link["api"]) for link in links)),
                        "links": list(links),
                        "resolved": True,
                        "static_only": True,
                    },
                    [*group, *relevant_rows][:24],
                )
            if not found:
                add(
                    "value_flow",
                    {
                        "direction": "return_to_consumers",
                        "function": function.get("name"),
                        "function_entry": function.get("entry"),
                        "consumers": [],
                        "links": [],
                        "resolved": False,
                        "missing_evidence": [
                            "caller instructions linking the returned value to an argument"
                        ],
                        "static_only": True,
                    },
                    relevant_rows[:24],
                )
        elif action.action_type == ActionType.TRACE_GLOBAL_USAGE:
            target_entry = _derivation_support._locator_key(function.get("entry") or target)
            accesses = _global_accesses_from_rows(artifact_rows)
            writes = [
                item
                for item in accesses
                if item["access"] == "write"
                and (not target_entry or item["function_entry"] == target_entry)
            ]
            recovered = False
            for write in writes:
                identity = str(write["address"] or write["name"]).casefold()
                name_key = str(write["name"] or "").casefold()
                readers = [
                    item
                    for item in accesses
                    if item["access"] == "read"
                    and item["function_entry"] != write["function_entry"]
                    and (
                        str(item["address"] or "").casefold() == identity
                        or (
                            name_key
                            and str(item["name"] or "").casefold() == name_key
                        )
                    )
                ]
                supporting = [write["row"], *[item["row"] for item in readers]]
                add(
                    "global_usage",
                    {
                        "name": write["name"],
                        "address": write["address"] or write["name"],
                        "writer": write["function_name"] or write["function_entry"],
                        "writer_entry": write["function_entry"],
                        "readers": [
                            item["function_name"] or item["function_entry"]
                            for item in readers
                        ],
                        "role": "producer",
                        "writes": True,
                        "relation": "producer_to_global",
                        "source_role": "producer",
                        "output_buffer": write["name"],
                        "static_only": True,
                    },
                    supporting[:24],
                )
                add(
                    "value_flow",
                    {
                        "name": write["name"],
                        "relation": "producer_to_global",
                        "source_role": "producer",
                        "source_function": write["function_name"],
                        "function": write["function_name"],
                        "function_entry": write["function_entry"],
                        "output_buffer": write["name"],
                        "global": write["name"],
                        "address": write["address"] or write["name"],
                        "writes": True,
                        "consumer": (
                            readers[0]["function_name"] or readers[0]["function_entry"]
                            if readers
                            else None
                        ),
                        "resolved": True,
                        "static_only": True,
                    },
                    supporting[:24],
                )
                recovered = True
            if not recovered:
                add(
                    "value_flow",
                    {
                        "direction": "global_reads_writes",
                        "function": function.get("name"),
                        "function_entry": function.get("entry"),
                        "references": data_reference_rows[:128],
                        "resolved": False,
                        "references_observed": bool(data_reference_rows),
                        "missing_evidence": ["matched global write/read value provenance"],
                        "static_only": True,
                    },
                    relevant_rows[:24],
                    nature="STATIC_DERIVED",
                )
        if action.action_type == ActionType.GET_PCODE_SLICE:
            add(
                "pcode_slice",
                build_pcode_slice(
                    function,
                    source_evidence_ids=source_ids,
                    max_operations=64,
                ),
                relevant_rows[:24],
                nature="STATIC_INFERRED",
            )
            for link in track_indirect_function_pointers(function):
                add(
                    "indirect_function_pointer_link",
                    dict(link),
                    relevant_rows[:24],
                    nature="STATIC_DERIVED",
                )
            # A compact role classification gives the agent a
            # discriminating answer for PE parsing hypotheses.  Header
            # access alone remains a validator candidate; mapper claims
            # require the separate allocation/relocation/write path.
            for role in classify_pe_semantics(function, pe_summary):
                add(
                    "pe_semantic_classification",
                    role,
                    relevant_rows[:24],
                    nature="STATIC_INFERRED",
                )

    if action.action_type == ActionType.GET_FUNCTION:
        for row, _ in target_rows:
            if row.kind == "function":
                add("function", dict(row.value), [row])
    elif action.action_type == ActionType.GET_STRINGS_REFERENCED:
        # Strings are first-class observations.  The old implementation
        # only emitted a function_call when a string happened to contain a
        # hard-coded API name, silently discarding ordinary paths, URLs,
        # registry keys and configuration text.
        for row, text in target_rows:
            if row.kind == "string":
                value = dict(row.value) if isinstance(row.value, dict) else {"text": text}
                add("string_reference", value, [row])
            elif row.kind == "function_data_correlation":
                add(
                    "string_reference",
                    dict(row.value) if isinstance(row.value, dict) else {"text": text},
                    [row],
                )
            elif row.kind in {"import_symbol", "function_context", "function_call"}:
                for api in known_apis:
                    if api.casefold() in text.casefold():
                        add("function_call", {"api": api, "source_kind": row.kind}, [row])
            elif row.kind in {
                "script_line",
                "script_indicator",
                "document_url",
                "document_active_content",
                "document_embedded_object",
                "document_embedded_file",
            }:
                # Non-native-code artifacts have no function identity, but
                # their line/offset/embedded-object anchors are still
                # first-class investigation evidence.
                add(
                    "string_reference",
                    {
                        "source_kind": row.kind,
                        "text": (
                            row.value.get("text")
                            or row.value.get("indicator")
                            or row.value.get("name")
                            or text
                        )
                        if isinstance(row.value, dict)
                        else text,
                        "anchor": dict(row.anchor or {})
                        if isinstance(row.anchor, dict)
                        else {},
                        "static_only": True,
                    },
                    [row],
                )
            elif row.kind in {
                "resource_inventory",
                "pe_resource",
                "pe_resource_directory",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "mechanism_decompression_format",
                "mechanism_decode",
                "mechanism_integrity_check",
                "embedded_artifact",
                "embedded_object",
                "archive_member",
                "decoded_artifact",
            }:
                # Resource/child metadata is a navigation surface rather
                # than a claim. Preserve its structured value and anchor
                # so follow-up actions can cite the exact payload/path.
                metadata = dict(row.value) if isinstance(row.value, dict) else {"text": text}
                display = next(
                    (
                        str(metadata[key])
                        for key in (
                            "text",
                            "indicator",
                            "name",
                            "logical_path",
                            "internal_path",
                            "resource_type",
                            "api",
                        )
                        if metadata.get(key) not in (None, "")
                    ),
                    text,
                )
                add(
                    "string_reference",
                    {
                        "source_kind": row.kind,
                        "text": display,
                        "metadata": metadata,
                        "anchor": dict(row.anchor or {})
                        if isinstance(row.anchor, dict)
                        else {},
                        "static_only": True,
                    },
                    [row],
                )
    elif action.action_type == ActionType.GET_DATA_REFERENCES:
        for row, text in target_rows:
            value = row.value if isinstance(row.value, dict) else {}
            if row.kind == "data_reference":
                add("data_reference", dict(value), [row])
                continue
            references = value.get("data_references", value.get("references", ()))
            if isinstance(references, list):
                for reference in references:
                    if isinstance(reference, dict):
                        add("data_reference", dict(reference), [row])
            elif row.kind in {"string", "function_data_correlation"}:
                add("data_reference", {"source_kind": row.kind, "text": text}, [row])
            elif row.kind in {
                "script_line",
                "script_indicator",
                "document_embedded_object",
                "document_embedded_file",
                "resource_inventory",
                "pe_resource",
                "pe_resource_directory",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "mechanism_decompression_format",
                "mechanism_decode",
                "mechanism_integrity_check",
                "embedded_object",
                "embedded_artifact",
                "archive_member",
                "decoded_artifact",
            }:
                value_payload = (
                    dict(value)
                    if isinstance(value, dict)
                    else {"text": text}
                )
                # Keep the resource inventory structured and bounded. A
                # single derived row is preferable to flattening every
                # entry into a task-wide string list; the report can then
                # cite the exact source row and entry offsets.
                add(
                    "data_reference",
                    {
                        "source_kind": row.kind,
                        "line_or_path": row.anchor.get("line")
                        or row.anchor.get("internal_path")
                        if isinstance(row.anchor, dict)
                        else None,
                        "value": value_payload,
                        "resource_entry_count": len(value.get("entries", []))
                        if isinstance(value.get("entries"), list)
                        else None,
                        "static_only": True,
                    },
                    [row],
                )
    elif action.action_type == ActionType.GET_CALLERS:
        # A cited target commonly narrows ``target_rows`` to the target's
        # own function context.  Caller edges, however, are stored on the
        # caller's sibling function context.  Search the target rows first
        # to preserve the narrow query, then fall back to the complete
        # artifact-local corpus only when no caller edge was recovered.
        def collect_caller_edges(rows: list[tuple[Evidence, str]]) -> None:
            for row, _ in rows:
                if row.kind != "function_context":
                    continue
                for edge in function_edges(row, "call_targets"):
                    callee = edge_target(edge)
                    if not edge_matches_target(edge, target_casefold):
                        continue
                    caller = function_label(row)
                    add(
                        "function_call",
                        {
                            "direction": "caller",
                            "caller": caller,
                            "callee": callee,
                            "api": callee,
                            "edge": edge,
                        },
                        [row],
                    )

        before_caller_observations = len(observations)
        collect_caller_edges(target_rows)
        if len(observations) == before_caller_observations:
            collect_caller_edges(all_token_rows)
    elif action.action_type == ActionType.GET_CALLEES:
        for row, _ in target_rows:
            if row.kind != "function_context" or target_casefold not in function_identity(row):
                continue
            caller = function_label(row) or target
            for edge in function_edges(row, "call_targets"):
                callee = edge_target(edge)
                if not callee:
                    continue
                add(
                    "function_call",
                    {
                        "direction": "callee",
                        "caller": caller,
                        "callee": callee,
                        "api": callee,
                        "edge": edge,
                    },
                    [row],
                )
        # Script parsers expose calls as line-anchored rows rather than
        # native function contexts. Preserve that ordered call evidence
        # and let the report layer explain the static boundary.
        for row, _ in target_rows:
            if row.kind != "script_call":
                continue
            value = row.value if isinstance(row.value, dict) else {}
            add(
                "script_call_trace",
                {
                    "call": value.get("name") or value.get("call") or value.get("api"),
                    "language": value.get("language"),
                    "line": (row.anchor or {}).get("line")
                    if isinstance(row.anchor, dict)
                    else None,
                    "consumer": "script control/data flow not executed",
                    "static_only": True,
                },
                [row],
            )
        # Resource/decompression facts carry call-site summaries rather
        # than a native function context. Preserve those explicit
        # consumers so the resource target can advance beyond
        # ``resource exists`` without inventing a runtime observation.
        for row, _ in target_rows:
            if row.kind not in {
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "mechanism_decompression_format",
                "mechanism_resource_payload",
                "mechanism_decode",
                "mechanism_integrity_check",
            }:
                continue
            value = row.value if isinstance(row.value, dict) else {}
            call_sites = value.get("call_sites", [])
            if not isinstance(call_sites, list):
                call_sites = []
            if not call_sites:
                call_sites = [{"api": value.get("api")}]
            for call_site in call_sites[:32]:
                if not isinstance(call_site, dict):
                    call_site = {"api": str(call_site)}
                api = (
                    call_site.get("api")
                    or call_site.get("target_name")
                    or value.get("api")
                )
                if not api:
                    continue
                add(
                    "resource_consumer",
                    {
                        "api": str(api),
                        "call_site": dict(call_site),
                        "role": "resource_extraction_or_decompression",
                        "static_only": True,
                    },
                    [row],
                    nature="STATIC_DERIVED",
                )
        # Child artifacts and archive members do not expose a native call
        # graph, but their typed relationship still answers the action's
        # question and records an explicit unresolved-consumer boundary.
        for row, _ in target_rows:
            if row.kind not in {
                "embedded_artifact",
                "embedded_object",
                "document_embedded_object",
                "document_embedded_file",
                "archive_member",
                "decoded_artifact",
                "pe_resource",
            }:
                continue
            value = row.value if isinstance(row.value, dict) else {}
            consumer = (
                value.get("consumer")
                or value.get("consumer_api")
                or value.get("downstream_consumer")
                or value.get("detected_type")
                or value.get("logical_path")
                or value.get("internal_path")
                or value.get("name")
            )
            add(
                "resource_consumer",
                {
                    "source_kind": row.kind,
                    "consumer": str(consumer) if consumer not in (None, "") else None,
                    "resolved": consumer not in (None, ""),
                    "relationship": "embedded_or_decoded_child_to_consumer",
                    "static_boundary": consumer in (None, ""),
                    "static_only": True,
                },
                [row],
                nature="STATIC_DERIVED",
            )
    elif action.action_type == ActionType.GET_XREFS_TO:
        # API xrefs are often cited from a PE import/indicator row. That
        # row has no function identity, so function-local expansion can
        # otherwise discard the actual Ghidra call rows and report
        # NO_NEW_EVIDENCE. The artifact-local corpus is already bounded
        # and authorized by the action's cited Evidence IDs; use it as a
        # fallback for exact API matching while retaining artifact scope.
        xref_rows = target_rows or all_token_rows
        before_xref_observations = len(observations)

        def collect_xrefs(rows_to_scan: list[tuple[Evidence, str]]) -> None:
            for row, _ in rows_to_scan:
                if row.kind not in {
                    "function_context",
                    "xref",
                    "function_call",
                    "import_symbol",
                    "loader_indicator",
                    "execution_indicator",
                    "anti_analysis_indicator",
                    "mechanism_dynamic_resolution",
                    "mechanism_memory_permission",
                    "resource_inventory",
                    "mechanism_resource_payload",
                    "mechanism_resource_extraction",
                    "mechanism_decompression",
                    "mechanism_decompression_format",
                    "mechanism_decode",
                    "mechanism_integrity_check",
                    "pe_resource",
                    "pe_resource_directory",
                    "embedded_object",
                    "embedded_artifact",
                    "document_embedded_object",
                    "document_embedded_file",
                    "archive_member",
                    "decoded_artifact",
                }:
                    continue
                value = row.value if isinstance(row.value, dict) else {}
                direct_targets = function_edges(row, "call_targets")
                if row.kind in {
                    "xref",
                    "function_call",
                    "import_symbol",
                    "loader_indicator",
                    "execution_indicator",
                    "anti_analysis_indicator",
                    "mechanism_dynamic_resolution",
                    "mechanism_memory_permission",
                }:
                    direct_targets.append(value)
                for edge in direct_targets:
                    referenced = edge_target(edge)
                    if not symbols_match(referenced, target):
                        continue
                    caller = function_label(row) or str(value.get("from", ""))
                    add(
                        "function_call",
                        {
                            "direction": "xref_to",
                            "caller": caller,
                            "referenced_target": referenced,
                            "api": referenced,
                            "edge": edge,
                        },
                        [row],
                    )
                if row.kind in {
                    "resource_inventory",
                    "mechanism_resource_payload",
                    "mechanism_resource_extraction",
                    "mechanism_decompression",
                    "mechanism_decompression_format",
                    "mechanism_decode",
                    "mechanism_integrity_check",
                    "pe_resource",
                    "pe_resource_directory",
                    "embedded_object",
                    "embedded_artifact",
                    "document_embedded_object",
                    "document_embedded_file",
                    "archive_member",
                    "decoded_artifact",
                }:
                    entries = value.get("entries", [])
                    if not isinstance(entries, list) or not entries:
                        entries = [value]
                    for entry in entries[:16]:
                        if not isinstance(entry, dict):
                            continue
                        add(
                            "embedded_object",
                            {
                                "relationship": "resource_or_embedded_payload",
                                "resource": {
                                    key: item
                                    for key, item in entry.items()
                                    if key not in {"content", "bytes"}
                                },
                                "consumer_status": "NOT_IDENTIFIED",
                                "static_only": True,
                            },
                            [row],
                            nature="STATIC_DERIVED",
                        )

        collect_xrefs(xref_rows)
        # A PE import row can be the only exact target match, while the
        # useful caller edge lives in a Ghidra function_context row whose
        # text is not selected after citation expansion. Retry the exact
        # target over the already-authorized artifact corpus when the
        # first pass produced no call evidence.
        if len(observations) == before_xref_observations and xref_rows is not all_token_rows:
            collect_xrefs(all_token_rows)
    elif action.action_type == ActionType.GET_XREFS_FROM:
        for row, _ in target_rows:
            if row.kind != "function_context" or target_casefold not in function_identity(row):
                continue
            source = function_label(row) or target
            for edge in function_edges(row, "call_targets"):
                referenced = edge_target(edge)
                if not referenced:
                    continue
                add(
                    "function_call",
                    {
                        "direction": "xref_from",
                        "source": source,
                        "referenced_target": referenced,
                        "api": referenced,
                        "edge": edge,
                    },
                    [row],
                )
    elif action.action_type == ActionType.TRACE_API_ARGUMENT:
        # Recover a bounded Windows argument trace from the static
        # instruction window.  x64 uses RCX/RDX/R8/R9; PE32 CreateThread
        # and similar stdcall sites use PUSH immediates.  Unresolved
        # arguments remain explicit UNKNOWN values.
        call_candidates: list[tuple[str, str, Evidence]] = []
        for row, _ in target_rows:
            value = row.value if isinstance(row.value, dict) else {}
            if row.kind == "function_call":
                api = str(
                    value.get("api")
                    or value.get("target_name")
                    or value.get("target_function")
                    or ""
                ).strip()
                callsite = str(
                    value.get("from")
                    or value.get("address")
                    or (row.anchor or {}).get("callsite")
                    or ""
                ).strip()
                if api:
                    call_candidates.append((api, callsite, row))
            elif row.kind == "function_context":
                for edge in function_edges(row, "call_targets"):
                    api = edge_target(edge)
                    callsite = str(edge.get("from") or edge.get("address") or "").strip()
                    if api:
                        call_candidates.append((api, callsite, row))
        # A function may expose the call only in an instruction window;
        # use it as a callsite candidate when the target API is explicit.
        for row, text in target_rows:
            if row.kind != "function_instruction_window":
                continue
            for match in re.finditer(
                r"\bCALL\s+(?:[A-Za-z0-9_.$@!]+!)?([A-Za-z_][A-Za-z0-9_@$]*)", text, re.I
            ):
                call_candidates.append((match.group(1), "", row))

        def parse_address(raw: object) -> int | None:
            value = str(raw or "").strip()
            if not value:
                return None
            try:
                return int(value, 0)
            except ValueError:
                try:
                    return int(value, 16)
                except ValueError:
                    return None

        def function_name(row: Evidence) -> str:
            value = row.value if isinstance(row.value, dict) else {}
            anchor = row.anchor if isinstance(row.anchor, dict) else {}
            return str(
                value.get("name") or value.get("function") or anchor.get("function_entry") or ""
            )

        # Deduplicate rows/call candidates while retaining the strongest
        # function-context provenance.
        selector_key = next(
            (
                key
                for key in (
                    "function",
                    "function_entry",
                    "entry",
                    "rva",
                    "address",
                    "api",
                    "target_api",
                    "target",
                )
                if selector.get(key) not in (None, "")
            ),
            "target",
        )
        # A numeric target, or an explicitly function-shaped selector,
        # scopes the call trace to the function.  It must never be used
        # as an API-name filter.  ``target`` is also used by model plans
        # for function names, so recognize an exact function identity in
        # the already-authorized rows before treating it as an API.
        function_scope_target = selector_key in {
            "function",
            "function_entry",
            "entry",
            "rva",
            "address",
        } or bool(re.fullmatch(r"(?:0x)?[0-9a-f]+", target_casefold, re.I))
        if not function_scope_target and selector_key == "target":
            for candidate_row, _ in target_rows:
                candidate_value = (
                    candidate_row.value if isinstance(candidate_row.value, dict) else {}
                )
                candidate_anchor = (
                    candidate_row.anchor if isinstance(candidate_row.anchor, dict) else {}
                )
                function_names = {
                    str(candidate_value.get("name") or "").strip().casefold(),
                    str(candidate_value.get("function") or "").strip().casefold(),
                    str(candidate_value.get("entry") or "").strip().casefold(),
                    str(candidate_anchor.get("function_entry") or "").strip().casefold(),
                }
                if target_casefold and target_casefold in function_names:
                    function_scope_target = True
                    break

        def api_symbols_match(observed: object, expected: object) -> bool:
            observed_text = str(observed or "").strip()
            expected_text = str(expected or "").strip()
            if not observed_text or not expected_text:
                return False
            if observed_text.casefold() == expected_text.casefold():
                return True
            if re.fullmatch(r"(?:0x)?[0-9a-f]+", observed_text, re.I) or re.fullmatch(
                r"(?:0x)?[0-9a-f]+", expected_text, re.I
            ):
                return False
            observed_symbol = normalize_api_symbol(observed_text)
            expected_symbol = normalize_api_symbol(expected_text)
            return bool(observed_symbol and expected_symbol and observed_symbol == expected_symbol)

        unique_calls: dict[tuple[str, str, str], tuple[str, str, Evidence]] = {}
        for api, callsite, row in call_candidates:
            if is_ghidra_data_or_string_label(api):
                continue
            if target_casefold and target_casefold not in {"api", "function", "global"}:
                if not function_scope_target and not api_symbols_match(api, target):
                    continue
            key = (api.casefold(), callsite.casefold(), function_name(row).casefold())
            unique_calls.setdefault(key, (api, callsite, row))

        instruction_rows: list[tuple[Evidence, dict[str, object], int | None, int]] = []
        for row, _ in target_rows:
            if row.kind != "function_instruction_window" or not isinstance(row.value, dict):
                continue
            raw_instructions = row.value.get("instructions", [])
            if not isinstance(raw_instructions, list):
                continue
            for ordinal, instruction in enumerate(raw_instructions):
                if not isinstance(instruction, dict):
                    continue
                instruction_rows.append(
                    (
                        row,
                        instruction,
                        parse_address(instruction.get("address") or instruction.get("offset")),
                        ordinal,
                    )
                )
        instruction_rows.sort(
            key=lambda item: (item[2] is None, item[2] if item[2] is not None else item[3])
        )

        arg_registers = ("RCX", "RDX", "R8", "R9")
        assignment_re = re.compile(r"\b(?:MOV|MOVABS|LEA)\s+(RCX|RDX|R8|R9)\s*,\s*(.+)$", re.I)
        stamped_decoded_outputs: set[tuple[str, str, int]] = set()
        for api, callsite, call_row in unique_calls.values():
            call_address = parse_address(callsite)
            # Keep only instructions in the same function window and stop
            # at the target call.  If addresses are absent, exporter order
            # is retained and the call's ordinal is the best boundary.
            scoped = [
                item
                for item in instruction_rows
                if function_name(item[0]).casefold() == function_name(call_row).casefold()
            ]
            if not scoped:
                scoped = instruction_rows
            before: list[tuple[Evidence, dict[str, object], int | None, int]] = []
            for item in scoped:
                if call_address is not None and item[2] is not None and item[2] > call_address:
                    break
                before.append(item)
            latest: dict[str, dict[str, object]] = {}
            for source_row, instruction, address, ordinal in before:
                text_value = str(
                    instruction.get("text") or instruction.get("mnemonic") or ""
                ).strip()
                assignment = assignment_re.search(text_value)
                if not assignment:
                    continue
                register, raw_value = assignment.groups()
                latest[register.upper()] = {
                    "register": register.upper(),
                    "value": raw_value.strip(),
                    "source_instruction": text_value,
                    "address": instruction.get("address") or instruction.get("offset"),
                    "source_evidence_id": source_row.id,
                }
            args: list[dict[str, object]] = []
            arg_names = {
                "createthread": (
                    "lpThreadAttributes",
                    "dwStackSize",
                    "lpStartAddress",
                    "lpParameter",
                    "dwCreationFlags",
                    "lpThreadId",
                ),
                "createthreadex": (
                    "lpThreadAttributes",
                    "dwStackSize",
                    "lpStartAddress",
                    "lpParameter",
                ),
                "createprocessw": (
                    "lpApplicationName",
                    "lpCommandLine",
                    "lpProcessAttributes",
                    "lpThreadAttributes",
                    "bInheritHandles",
                    "dwCreationFlags",
                ),
                "createprocessa": (
                    "lpApplicationName",
                    "lpCommandLine",
                    "lpProcessAttributes",
                    "lpThreadAttributes",
                    "bInheritHandles",
                    "dwCreationFlags",
                ),
                "getprocaddress": ("hModule", "lpProcName"),
                "loadlibraryw": ("lpLibFileName",),
                "loadlibrarya": ("lpLibFileName",),
                "loadlibraryexw": ("lpLibFileName", "hFile", "dwFlags"),
                "loadlibraryexa": ("lpLibFileName", "hFile", "dwFlags"),
                "winhttpopenrequest": (
                    "hConnect",
                    "pwszVerb",
                    "pwszObjectName",
                    "pwszVersion",
                    "pwszReferrer",
                    "ppwszAcceptTypes",
                    "dwFlags",
                ),
                "winhttpconnect": ("hSession", "pswzServerName", "nServerPort", "dwReserved"),
                "cryptdecrypt": ("hKey", "hHash", "Final", "dwFlags", "pbData", "pdwDataLen"),
            }.get(normalize_api_symbol(api), ())
            if not latest:
                call_value = call_row.value if isinstance(call_row.value, dict) else {}
                architecture = str(
                    call_value.get("architecture")
                    or call_value.get("calling_convention")
                    or (pe_summary or {}).get("architecture")
                    or (pe_summary or {}).get("machine")
                    or ""
                )
                function_for_trace = {
                    "architecture": architecture,
                    "instructions": [dict(item[1]) for item in (scoped or instruction_rows)],
                    "references_from": [
                        {
                            "target_name": api,
                            "from": callsite
                            or (
                                str((scoped or instruction_rows)[-1][1].get("address") or "")
                                if (scoped or instruction_rows)
                                else ""
                            ),
                        }
                    ],
                }
                for linked in trace_static_api_arguments(
                    function_for_trace, api, callsite=callsite
                ):
                    index = int(linked.get("argument_index") or 0)
                    raw_value = linked.get("value")
                    text_value = str(raw_value or "").strip()
                    resolved = bool(text_value) and str(linked.get("source_kind") or "") not in {
                        "unknown",
                        "",
                    }
                    named = (
                        {"name": arg_names[index]}
                        if index < len(arg_names) and arg_names[index]
                        else {}
                    )
                    if resolved and re.fullmatch(r"(?:0x[0-9a-f]+|-?\d+)", text_value, re.I):
                        try:
                            text_value = hex(int(text_value, 0))
                        except ValueError:
                            pass
                    args.append(
                        {
                            "index": index,
                            "value": text_value if resolved else "UNKNOWN",
                            "resolved": resolved,
                            "source_kind": linked.get("source_kind"),
                            "source_instruction": linked.get("source_instruction"),
                            "address": linked.get("source_callsite"),
                            **named,
                        }
                    )
                if not args:
                    for index, register in enumerate(arg_registers):
                        args.append(
                            {
                                "index": index,
                                "register": register,
                                "value": "UNKNOWN",
                                "resolved": False,
                            }
                        )
            else:
                for index, register in enumerate(arg_registers):
                    item = latest.get(register)
                    if item is None:
                        args.append(
                            {
                                "index": index,
                                "register": register,
                                "value": "UNKNOWN",
                                "resolved": False,
                            }
                        )
                    else:
                        raw_value = str(item.get("value", ""))
                        raw_value = re.sub(r"^(?:offset|near)\s+", "", raw_value, flags=re.I)
                        source_kind = (
                            "string"
                            if raw_value.startswith(('"', "'"))
                            else "constant"
                            if re.fullmatch(
                                r"(?:0x[0-9a-f]+|[-+]?\d+|FUN_[0-9a-f]+|sub_[0-9a-f]+)",
                                raw_value,
                                re.I,
                            )
                            else "global"
                            if raw_value.startswith("[")
                            else "expression"
                        )
                        named = (
                            {"name": arg_names[index]}
                            if index < len(arg_names) and arg_names[index]
                            else {}
                        )
                        args.append(
                            {
                                "index": index,
                                **item,
                                "value": raw_value,
                                "source_kind": source_kind,
                                "resolved": True,
                                **named,
                            }
                        )
            overlay = _derivation_support._overlay_pe_parser_thread_start(
                {
                    "api": api,
                    "callsite": callsite or None,
                    "arguments": args,
                },
                pe_summary,
            )
            if overlay.get("arguments"):
                args = [dict(item) for item in overlay["arguments"] if isinstance(item, dict)]
            process_symbols = {
                "createprocessw",
                "createprocessa",
                "winexec",
                "shellexecutew",
                "shellexecutea",
            }
            if normalize_api_symbol(api) in process_symbols:
                has_flags = any(
                    str(item.get("name") or "").casefold()
                    in {"dwcreationflags", "creationflags"}
                    and item.get("resolved") is True
                    and is_projected_catalog_value(item.get("value"))
                    for item in args
                ) or any(
                    item.get("index") == 5
                    and item.get("resolved") is True
                    and is_projected_catalog_value(item.get("value"))
                    for item in args
                )
                if not has_flags:
                    flag = creation_flag_from_abi_slot(
                        (
                            str(item[1].get("text") or item[1].get("mnemonic") or "")
                            for item in before
                        )
                    )
                    if flag and not is_specialist_ppid_creation_flag(flag):
                        args.append(
                            {
                                "index": 5,
                                "name": "dwCreationFlags",
                                "value": flag,
                                "resolved": True,
                                "source_kind": "constant",
                                "source_instruction": f"immediate {flag}",
                            }
                        )
            downstream: list[str] = []
            if call_address is not None:
                for candidate_api, candidate_site, _ in unique_calls.values():
                    candidate_address = parse_address(candidate_site)
                    if (
                        candidate_address is not None
                        and candidate_address > call_address
                        and candidate_api.casefold() != api.casefold()
                    ):
                        downstream.append(candidate_api)
            source_rows_for_trace = [call_row]
            source_rows_for_trace.extend(item[0] for item in before[-8:])
            source_rows_for_trace.extend(
                row
                for row, _ in target_rows
                if row.kind == "function_call"
                and isinstance(row.value, dict)
                and str(
                    row.value.get("api")
                    or row.value.get("target_name")
                    or row.value.get("target_function")
                    or ""
                ).casefold()
                == api.casefold()
            )
            # Preserve every explicitly cited row in the derived trace.
            # A planner may cite a context row, an instruction window and
            # a callsite separately; dropping one of those IDs makes the
            # resulting evidence look less reproducible even though the
            # same static data was used for the calculation.
            source_rows_for_trace.extend(source_rows)
            source_rows_for_trace = list(
                {str(row.id): row for row in source_rows_for_trace}.values()
            )
            add(
                "api_argument_trace",
                {
                    "api": api,
                    "callsite": callsite or None,
                    "function": function_name(call_row),
                    "function_entry": (call_row.anchor or {}).get("function_entry")
                    if isinstance(call_row.anchor, dict)
                    else None,
                    "rva": (call_row.anchor or {}).get("rva")
                    if isinstance(call_row.anchor, dict)
                    else None,
                    "arguments": args,
                    "recovered_argument_count": sum(1 for item in args if item.get("resolved")),
                    "consumer": api,
                    "downstream_consumers": list(dict.fromkeys(downstream))[:8],
                    "trace_quality": overlay.get("trace_quality")
                    or (
                        "x86_stdcall_push"
                        if not latest and any(item.get("resolved") for item in args)
                        else "x64_register_window"
                        if any(item.get("resolved") for item in args)
                        else "callsite_only"
                    ),
                    "static_only": True,
                },
                source_rows_for_trace,
            )
            catalog_fields = catalog_fields_from_api_arguments(api, args)
            after_instructions: list[dict[str, object]] = []
            if call_address is not None:
                for item in scoped:
                    if item[2] is not None and item[2] > call_address:
                        after_instructions.append(item[1])
                        if len(after_instructions) >= 12:
                            break
            else:
                call_ordinal = None
                for item in scoped:
                    text_value = str(item[1].get("text") or item[1].get("mnemonic") or "")
                    if re.search(rf"(?i)\bCALL\s+(?:.*!)?{re.escape(str(api).rsplit('!', 1)[-1])}\b", text_value):
                        call_ordinal = item[3]
                if call_ordinal is not None:
                    for item in scoped:
                        if item[3] > call_ordinal:
                            after_instructions.append(item[1])
                            if len(after_instructions) >= 12:
                                break
            return_branch = catalog_return_branch_after_call(after_instructions)
            if return_branch:
                catalog_fields = {**catalog_fields, "return_branch": return_branch}
            if catalog_fields:
                add(
                    "api_argument_trace",
                    {
                        "api": api,
                        "callsite": callsite or None,
                        "function": function_name(call_row),
                        "function_entry": (call_row.anchor or {}).get("function_entry")
                        if isinstance(call_row.anchor, dict)
                        else None,
                        "consumer": api,
                        **catalog_fields,
                        "static_only": True,
                    },
                    source_rows_for_trace,
                )
                flag_raw = catalog_fields.get("creation_flags") or catalog_fields.get("flags")
                parsed_flags: int | None = None
                if flag_raw not in (None, ""):
                    try:
                        parsed_flags = int(str(flag_raw), 0) & 0xFFFFFFFF
                    except (TypeError, ValueError):
                        parsed_flags = None
                if plausible_traced_creation_flags(parsed_flags) is not None:
                    decoded_flags = decode_windows_process_creation_flags(parsed_flags)
                    add(
                        "process_creation_flags",
                        {
                            "creation_flags": decoded_flags.get("value")
                            or f"0x{parsed_flags:08x}",
                            "flags": decoded_flags.get("value") or f"0x{parsed_flags:08x}",
                            "api": api,
                            "callsite": callsite or None,
                            "function": function_name(call_row),
                            "set_flags": list(decoded_flags.get("set_flags") or []),
                            "static_only": True,
                        },
                        source_rows_for_trace,
                    )
                producer_id = next(
                    (
                        str(item.get("source_evidence_id"))
                        for item in args
                        if item.get("resolved") and item.get("source_evidence_id")
                    ),
                    str(call_row.id),
                )
                relation = catalog_relation_from_api_fields(
                    api,
                    catalog_fields,
                    artifact_id=getattr(call_row, "artifact_id", None),
                    callsite=callsite,
                    source_evidence_id=producer_id,
                    target_evidence_id=call_row.id,
                )
                if relation is not None:
                    add("value_flow", relation, source_rows_for_trace)
            image_base = int((pe_summary or {}).get("image_base") or 0)
            nested_trace = {
                "api": api,
                "callsite": callsite or None,
                "arguments": args,
            }
            call_anchor = {
                "callsite": callsite,
                **(dict(call_row.anchor) if isinstance(call_row.anchor, dict) else {}),
            }
            for producer in artifact_rows:
                if producer.kind not in _DECODE_PRODUCER_KINDS:
                    continue
                identity = _decode_output_buffer(producer)
                if identity is None:
                    continue
                linked = decoded_output_from_argument_trace(
                    producer.id,
                    {"output_buffer": identity},
                    "api_argument_trace",
                    nested_trace,
                    call_anchor,
                    image_base=image_base,
                )
                if linked is None:
                    continue
                index = linked.get("argument_index")
                if not isinstance(index, int):
                    continue
                stamp_key = (str(producer.id), api.casefold(), index)
                if stamp_key in stamped_decoded_outputs:
                    continue
                stamped_decoded_outputs.add(stamp_key)
                identified = with_artifact_identity(
                    linked.get("source_buffer")
                    if isinstance(linked.get("source_buffer"), Mapping)
                    else identity,
                    getattr(producer, "artifact_id", None),
                )
                linked_payload = {
                    **linked,
                    "function": function_name(call_row),
                    "function_entry": (call_row.anchor or {}).get("function_entry")
                    if isinstance(call_row.anchor, dict)
                    else None,
                    "consumer": api,
                    "static_only": True,
                }
                if identified is not None:
                    linked_payload["source_buffer"] = identified
                    linked_payload["input_buffer"] = identified
                add(
                    "api_argument_trace",
                    linked_payload,
                    list(
                        {
                            str(item.id): item
                            for item in (*source_rows_for_trace, producer)
                        }.values()
                    ),
                    nature="STATIC_INFERRED",
                )
                consumer_link = catalog_output_consumer_relation(
                    producer_id=producer.id,
                    consumer_id=call_row.id,
                    output_buffer=identified,
                    consumer_api=api,
                )
                if consumer_link is not None:
                    add(
                        "value_flow",
                        consumer_link,
                        list(
                            {
                                str(item.id): item
                                for item in (*source_rows_for_trace, producer)
                            }.values()
                        ),
                        nature="STATIC_INFERRED",
                    )
                if identified is not None and is_process_command_argument(api, index):
                    process_join = catalog_decode_output_to_process_command_relation(
                        decode_id=producer.id,
                        process_id=call_row.id,
                        output_buffer=identified,
                        command_buffer=identified,
                        command=(
                            catalog_fields.get("command")
                            or catalog_fields.get("command_line")
                            or catalog_fields.get("image")
                        ),
                    )
                    if process_join is not None:
                        process_join["api"] = str(api).rsplit("!", 1)[-1]
                        process_join["consumer"] = str(api).rsplit("!", 1)[-1]
                    if process_join is not None:
                        add(
                            "value_flow",
                            process_join,
                            list(
                                {
                                    str(item.id): item
                                    for item in (*source_rows_for_trace, producer)
                                }.values()
                            ),
                            nature="STATIC_INFERRED",
                        )
    elif action.action_type == ActionType.EVALUATE_CONSTANT:
        for row, text in target_rows:
            upper = text.upper()
            if (
                "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS" in upper
                or "0X00020000" in upper
                or "0X20000" in upper
            ):
                add(
                    "constant",
                    {
                        "name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                        "value": "0x00020000",
                        "verification": "static",
                    },
                    [row],
                )
            flag_value = None
            env_probe = None
            env_threshold = None
            env_branch = None
            if row.kind == "process_creation_flags" and isinstance(row.value, dict):
                values = []
                for item in row.value.get("flags") or ():
                    if isinstance(item, Mapping) and item.get("value"):
                        values.append(str(item.get("value")))
                unique = tuple(dict.fromkeys(values))
                if len(unique) == 1:
                    flag_value = unique[0]
            elif row.kind == "function_instruction_window" and isinstance(row.value, dict):
                instructions = [
                    item
                    for item in row.value.get("instructions") or ()
                    if isinstance(item, Mapping)
                ]
                texts = [
                    str(item.get("text") or item.get("mnemonic") or "")
                    for item in instructions
                ]
                probe_re = re.compile(
                    r"(?i)\bCALL\s+(?:[A-Za-z0-9_.$@!]+!)?("
                        r"GetTickCount64|GetTickCount|IsDebuggerPresent|"
                        r"GlobalMemoryStatusEx|CheckRemoteDebuggerPresent"
                        r")\b"
                )
                cmp_re = re.compile(
                    r"(?i)\b(?:CMP|TEST)\s+\S+,\s*(0x[0-9a-fA-F]+|\d+)\b"
                )
                jcc_re = re.compile(
                    r"(?i)\b(J[N]?[ABGL]E|J[ABGL]|JZ|JNZ|JE|JNE|JA|JB|JAE|JBE)\s+(\S+)"
                )
                saw_probe = ""
                for text_value in texts:
                    hit = probe_re.search(text_value)
                    if hit:
                        saw_probe = hit.group(1)
                        continue
                    if not saw_probe:
                        continue
                    compared = cmp_re.search(text_value)
                    if compared and env_threshold is None:
                        env_probe = saw_probe
                        env_threshold = compared.group(1)
                        continue
                    jumped = jcc_re.search(text_value)
                    if jumped and env_threshold is not None and env_branch is None:
                        env_branch = f"{jumped.group(1).upper()} {jumped.group(2)}"
                        break
                if env_threshold is None:
                    flag_value = unique_plausible_creation_flag(
                        texts,
                        window=max(len(texts), 1),
                    )
            if env_threshold:
                add(
                    "constant",
                    {
                        "name": "threshold",
                        "threshold": env_threshold,
                        "comparison": env_threshold,
                        "api": env_probe or "GetTickCount64",
                        "return_branch": env_branch,
                        "verification": "static",
                        "static_only": True,
                    },
                    [row],
                )
            if flag_value:
                add(
                    "constant",
                    {
                        "name": "creation_flags",
                        "creation_flags": flag_value,
                        "flags": flag_value,
                        "verification": "static",
                        "static_only": True,
                    },
                    [row],
                )
    elif action.action_type == ActionType.DECODE_CANDIDATE:
        decode_rows = [
            (row, text)
            for row, text in token_rows
            if row.kind in {
                "mechanism_decode_window",
                "encoded_blob",
                "crypto_indicator",
                "mechanism_decryption",
                "resource_inventory",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "pe_resource_directory",
                "embedded_object",
                "archive_member",
            }
            and (
                target_casefold in text.casefold()
                or target_casefold in {"xor", "decode", "config"}
            )
        ]
        recovered_xor_configs: tuple[dict[str, object], ...] | None = None
        claimed_xor_configs: set[str] = set()
        image_base = int((pe_summary or {}).get("image_base") or 0)
        for row, _ in decode_rows:
            if row.kind in {
                "mechanism_decode_window",
                "encoded_blob",
                "crypto_indicator",
                "mechanism_decryption",
                # Resource-backed payloads are decode candidates too.
                # Keep them in the same action branch so the bounded
                # format probe below runs for resource inventory rows,
                # even when no XOR verification metadata exists.
                "resource_inventory",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "pe_resource_directory",
                "embedded_object",
                "archive_member",
            }:
                candidate = dict(row.value) if isinstance(row.value, dict) else {}
                verification = candidate.get("verification_result")
                if artifact_content is not None and candidate.get("memory_addresses"):
                    verification = verify_xor_decode_candidate(
                        candidate,
                        artifact_content,
                        pe_summary or {},
                    )
                elif artifact_content is not None and not candidate.get("memory_addresses"):
                    if recovered_xor_configs is None:
                        recovered_xor_configs = tuple(
                            recover_static_xor_configs(artifact_content, pe_summary or {})
                        )
                    matched = _bind_recovered_xor_verification(
                        candidate,
                        recovered_xor_configs,
                        claimed_xor_configs,
                        image_base=image_base,
                    )
                    if matched is not None:
                        verification = dict(matched)
                if isinstance(verification, dict):
                    # A successful byte replay is only half of decoder
                    # recovery.  Link the decoded value to a statically
                    # visible consumer in the same function/RVA when one
                    # exists (LoadLibrary, resolver, transport, process,
                    # or file sink).  Keep the absence explicit instead
                    # of promoting a decoded string to a behavior claim.
                    if not isinstance(candidate.get("output_buffer"), Mapping):
                        verified_buf = (
                            verification.get("output_buffer")
                            if isinstance(verification, Mapping)
                            else None
                        )
                        attached = (
                            output_buffer_identity(
                                address_space=verified_buf.get("address_space"),
                                address=verified_buf.get("address"),
                                length=verified_buf.get("length"),
                            )
                            if isinstance(verified_buf, Mapping)
                            else None
                        )
                        if attached is not None:
                            candidate = {**candidate, "output_buffer": attached}
                    consumer_rows: list[Evidence] = []
                    consumer_candidates: list[dict[str, object]] = []
                    for possible in artifact_rows:
                        if possible.id == row.id:
                            continue
                        possible_anchor = (
                            possible.anchor if isinstance(possible.anchor, dict) else {}
                        )
                        value = possible.value if isinstance(possible.value, dict) else {}
                        linked = decoded_output_from_argument_trace(
                            row.id,
                            candidate,
                            possible.kind,
                            value,
                            possible_anchor,
                            image_base=image_base,
                        )
                        if linked is None:
                            continue
                        consumer_rows.append(possible)
                        api = (
                            linked.get("api")
                            or value.get("api")
                            or value.get("target_name")
                            or value.get("target_function")
                        )
                        consumer_candidates.append(
                            {
                                "evidence_id": possible.id,
                                "kind": possible.kind,
                                "api": str(api) if api else None,
                                "function_entry": possible_anchor.get("function_entry"),
                                "callsite": linked.get("callsite") or value.get("callsite"),
                                "argument_index": linked.get("argument_index"),
                                "source_buffer": linked.get("source_buffer"),
                                "link_kind": "decoded_output_consumer",
                            }
                        )
                    if not consumer_rows:
                        output = (
                            candidate.get("output_buffer")
                            if isinstance(candidate.get("output_buffer"), Mapping)
                            else None
                        )
                        output_address = (
                            output.get("address") if isinstance(output, Mapping) else None
                        )
                        for possible in artifact_rows:
                            if possible.id == row.id:
                                continue
                            if possible.kind not in {
                                "function_instruction_window",
                                "function_context",
                            }:
                                continue
                            possible_anchor = (
                                possible.anchor if isinstance(possible.anchor, dict) else {}
                            )
                            value = possible.value if isinstance(possible.value, dict) else {}
                            hit = consumer_from_decoded_pointer(
                                value.get("instructions") or (),
                                output_address,
                                image_base=image_base,
                            )
                            if hit is None:
                                continue
                            consumer_rows.append(possible)
                            consumer_candidates.append(
                                {
                                    "evidence_id": possible.id,
                                    "kind": possible.kind,
                                    "api": hit.get("api"),
                                    "function_entry": possible_anchor.get("function_entry"),
                                    "callsite": hit.get("callsite") or value.get("callsite"),
                                    "argument_index": hit.get("argument_index"),
                                    "source_buffer": output,
                                    "link_kind": "decoded_pointer_to_call",
                                }
                            )
                        if not consumer_rows:
                            for possible in artifact_rows:
                                if possible.id == row.id:
                                    continue
                                possible_anchor = (
                                    possible.anchor if isinstance(possible.anchor, dict) else {}
                                )
                                value = possible.value if isinstance(possible.value, dict) else {}
                                hit = consumer_from_decoded_reference(
                                    possible.kind,
                                    value,
                                    possible_anchor,
                                    output_address,
                                    image_base=image_base,
                                )
                                if hit is None:
                                    continue
                                consumer_rows.append(possible)
                                consumer_candidates.append(
                                    {
                                        "evidence_id": possible.id,
                                        "kind": possible.kind,
                                        "api": hit.get("api"),
                                        "function_entry": possible_anchor.get("function_entry"),
                                        "callsite": hit.get("callsite") or value.get("from"),
                                        "argument_index": hit.get("argument_index"),
                                        "source_buffer": output,
                                        "link_kind": hit.get("link_kind")
                                        or "decoded_va_reference",
                                    }
                                )
                    consumer_candidates = list(
                        {
                            (
                                str(item.get("evidence_id")),
                                str(item.get("api")),
                                str(item.get("function_entry")),
                            ): item
                            for item in consumer_candidates
                        }.values()
                    )[:16]
                    object_consumers = [
                        item
                        for item in consumer_candidates
                        if is_object_level_decode_consumer(item)
                    ]
                    artifact_id = getattr(row, "artifact_id", None) or getattr(
                        action, "artifact_id", None
                    )
                    decode_facts = catalog_fields_from_decode_verification(
                        verification,
                        artifact_id=artifact_id,
                        output_buffer=candidate.get("output_buffer")
                        if isinstance(candidate.get("output_buffer"), Mapping)
                        else None,
                    )
                    identified = (
                        decode_facts.get("output_buffer")
                        if isinstance(decode_facts.get("output_buffer"), Mapping)
                        else None
                    )
                    if identified is None:
                        identified = with_artifact_identity(
                            candidate.get("output_buffer")
                            if isinstance(candidate.get("output_buffer"), Mapping)
                            else None,
                            artifact_id,
                        )
                    linked_consumers: list[dict[str, object]] = []
                    linked_flows: list[dict[str, object]] = []
                    if isinstance(identified, Mapping):
                        for item in object_consumers:
                            link = catalog_output_consumer_relation(
                                producer_id=row.id,
                                consumer_id=item.get("evidence_id"),
                                output_buffer=identified,
                                consumer_api=item.get("api"),
                            )
                            if link is None:
                                continue
                            linked_consumers.append(item)
                            linked_flows.append(link)
                    decode_value = {
                        "source_kind": row.kind,
                        "candidate": {
                            key: value
                            for key, value in candidate.items()
                            if key != "verification_result"
                        },
                        "verification": verification,
                        "verification_status": verification.get("status", "UNKNOWN"),
                        "consumer_status": "LINKED_STATIC"
                        if linked_consumers
                        else "NOT_IDENTIFIED",
                        "consumer_candidates": consumer_candidates,
                        "consumer_evidence_ids": [
                            str(item["evidence_id"]) for item in linked_consumers
                        ],
                        "missing_evidence": [] if linked_consumers else [
                            "decoder output buffer and resolved consumer argument provenance"
                        ],
                        "static_only": True,
                    }
                    add(
                        "decode_result",
                        decode_value,
                        [row, *consumer_rows[:23]],
                    )
                    if decode_facts:
                        add(
                            "decode_result",
                            {**decode_facts, "static_only": True},
                            [row, *consumer_rows[:23]],
                        )
                    for link in linked_flows:
                        add(
                            "value_flow",
                            link,
                            [row, *consumer_rows[:23]],
                            nature="STATIC_INFERRED",
                        )
                    if isinstance(identified, Mapping):
                        for item in object_consumers:
                            if not is_process_command_argument(
                                item.get("api"), item.get("argument_index")
                            ):
                                continue
                            process_join = catalog_decode_output_to_process_command_relation(
                                decode_id=row.id,
                                process_id=item.get("evidence_id"),
                                output_buffer=identified,
                                command_buffer=identified,
                            )
                            if process_join is None:
                                continue
                            api_name = str(item.get("api") or "").rsplit("!", 1)[-1]
                            if api_name:
                                process_join["api"] = api_name
                                process_join["consumer"] = api_name
                            add(
                                "value_flow",
                                process_join,
                                [row, *consumer_rows[:23]],
                                nature="STATIC_INFERRED",
                            )
                else:
                    add(
                        "decode_candidate",
                        {
                            "status": "UNVERIFIED_STATIC_CANDIDATE",
                            "source_kind": row.kind,
                            "static_only": True,
                        },
                        [row],
                    )
                if row.kind in {
                    "resource_inventory",
                    "mechanism_resource_payload",
                    "mechanism_resource_extraction",
                    "mechanism_decompression",
                    "pe_resource_directory",
                    "embedded_object",
                    "archive_member",
                } and artifact_content is not None:
                    # A resource/embedded payload is often the only
                    # statically recoverable child object. Classify its
                    # bounded bytes for the next investigation turn, but
                    # never call a loader or claim that it executed.
                    value = row.value if isinstance(row.value, dict) else {}
                    entries = value.get("entries", [])
                    if not isinstance(entries, list):
                        entries = [value]

                    def _payload_format(window: bytes) -> str:
                        if window.startswith(b"MZ"):
                            return "pe"
                        if window.startswith(b"%PDF-"):
                            return "pdf"
                        if window.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                            return "zip"
                        if window.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
                            return "7z"
                        if window.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                            return "ole"
                        return "unknown_binary"

                    for entry in entries[:16]:
                        if not isinstance(entry, dict):
                            continue
                        try:
                            offset = int(str(
                                entry.get("file_offset")
                                or entry.get("payload_offset")
                                or entry.get("data_offset")
                                or entry.get("offset")
                            ), 0)
                        except (TypeError, ValueError):
                            try:
                                offset = int(str(
                                    entry.get("file_offset")
                                    or entry.get("payload_offset")
                                    or entry.get("data_offset")
                                    or entry.get("offset")
                                ), 16)
                            except (TypeError, ValueError):
                                continue
                        if offset < 0 or offset >= len(artifact_content):
                            continue
                        try:
                            declared = int(str(entry.get("size") or 4096), 0)
                        except (TypeError, ValueError):
                            declared = 4096
                        window = artifact_content[offset : min(
                            len(artifact_content), offset + min(max(declared, 1), 4096)
                        )]
                        if not window:
                            continue
                        add(
                            "decoded_artifact",
                            {
                                "source_kind": row.kind,
                                "format_candidate": _payload_format(window),
                                "offset": offset,
                                "byte_count": len(window),
                                "sha256": hashlib.sha256(window).hexdigest(),
                                "static_only": True,
                                "runtime_execution": "not_performed",
                            },
                            [row],
                            nature="STATIC_DERIVED",
                        )
    elif action.action_type == ActionType.CONTROLLED_EMULATE:
        policy = simulation_policy_from_settings(host.settings)
        cited = [row for row, _ in target_rows[:8]] or list(source_rows[:8])
        traces = [
            {"value": dict(row.value)}
            for row in artifact_rows
            if row.kind == "api_argument_trace" and isinstance(row.value, dict)
        ]
        function_rows: list[dict[str, object]] = []
        for row in artifact_rows:
            if row.kind in {"function", "function_context"} and isinstance(row.value, dict):
                function_rows.append(dict(row.value))
        if not policy.enabled:
            add(
                "simulation_result",
                {
                    "status": "DISABLED_BY_POLICY",
                    "simulator": "unicorn",
                    "stop_reason": "DISABLED_BY_POLICY",
                    "limitations": [
                        "CONTROLLED_EMULATE waits until SIMULATION_PROFILE authorizes granted bytes"
                    ],
                },
                cited,
                nature="STATIC_INFERRED",
            )
        elif worker_defers_simulation(policy):
            existing_real = host._matching_simulation_results(
                [
                    row
                    for row in artifact_rows
                    if str(getattr(row, "kind", "")) == "simulation_result"
                ],
                selector,
                require_success=False,
            )
            if existing_real:
                for row in existing_real[:8]:
                    add(
                        "simulation_result",
                        dict(row.value),
                        [row],
                        nature=str(getattr(row, "nature", "") or "STATIC_INFERRED"),
                    )
            else:
                add(
                    "simulation_result",
                    {
                        "status": "DEFERRED_TO_WORKER",
                        "simulator": "unicorn",
                        "stop_reason": "DEFERRED_TO_WORKER",
                        "deferred": "isolated_emu_worker",
                        "function_entry": host._emulation_entry_key(selector),
                        "limitations": [
                            "CONTROLLED_EMULATE is dispatched to the isolated emu-worker, "
                                "not the API process; this row is replaced by the worker result"
                        ],
                    },
                    cited,
                    nature="STATIC_INFERRED",
                )
                add(
                    "investigation_observation",
                    {
                        "deferred": "isolated_emu_worker",
                        "reason": (
                            "CONTROLLED_EMULATE is dispatched to the isolated emu-worker, "
                                "not the API process"
                        ),
                    },
                    cited,
                    nature="STATIC_INFERRED",
                )
            # Do not emit a leftover Qiling DEFERRED row. The isolated
            # worker writes the real qiling decision during post-static
            # dispatch; a second placeholder survives into the report even
            # after SUCCEEDED/UNSUPPORTED lands.
        elif artifact_content:
            windows = controlled_emulation_windows(
                artifact_content,
                pe_summary or {},
                function_rows,
                traces,
                allow_speakeasy=False,
                max_windows=2,
            )
            if not windows:
                add(
                    "simulation_result",
                    {
                        "status": "WORKER_REQUIRED"
                        if policy.isolation_kind == "docker"
                        else "FAILED",
                        "simulator": "unicorn",
                        "stop_reason": "NO_GRANTED_WINDOW",
                        "limitations": ["no bounded start-routine window was recovered"],
                    },
                    cited,
                    nature="STATIC_INFERRED",
                )
            for window in windows[:2]:
                result = host._run_simulation_window(policy, window)
                payload = result.as_dict()
                if result.status == "SUCCEEDED" and result.output_bytes:
                    payload["output_hex"] = result.output_bytes.hex()
                add(
                    "simulation_result",
                    payload,
                    cited,
                    nature=evidence_nature_for_simulation_status(
                        result.status, stop_reason=result.stop_reason
                    ),
                )
            qiling_row = (
                host._qiling_unavailable_observation(policy)
                if not worker_defers_simulation(policy)
                else None
            )
            if qiling_row is not None:
                add(
                    "simulation_result",
                    qiling_row,
                    cited,
                    nature=evidence_nature_for_simulation_status(
                        qiling_row.get("status"),
                        stop_reason=qiling_row.get("stop_reason"),
                    ),
                )
    elif action.action_type == ActionType.COMPARE_FUNCTION:
        for row, _ in target_rows[:8]:
            if row.kind == "function_simhash":
                add("function_similarity_candidate", {"fingerprint": row.value}, [row])
    else:
        for row, _ in token_rows[:8]:
            if row.kind.startswith("function") or row.kind in {"xref", "cfg_block"}:
                add("investigation_observation", {"source_kind": row.kind}, [row])
    # A model-selected investigation action should leave behind a
    # semantic, evaluator-addressable link when the static corpus already
    # contains all components of a mechanism. The correlator is read-only
    # and every emitted row is wrapped by ``add`` so it receives the same
    # derivation digest and provenance contract as other observations.
    if action.planner_turn_id:
        static_rows = [
            {
                "id": row.id,
                "kind": row.kind,
                "value": row.value,
                "anchor": row.anchor,
            }
            for row in artifact_rows
        ]
        for link in derive_static_mechanism_links(static_rows):
            link_value = link.get("value") if isinstance(link.get("value"), dict) else {}
            source_ids = {
                str(item) for item in link_value.get("source_evidence_ids", ()) if item
            }
            link_text = host._investigation_value_text(link_value).casefold()
            cited_ids = {str(item) for item in action.source_evidence_ids if item}
            # Keep model action output target-focused. A GET_XREFS_TO for
            # GetProcAddress may discover a resolver link, but must not
            # attach an unrelated shell/ETW link found elsewhere in the
            # same artifact. The source citation is a second valid route
            # for a model-selected function-level action.
            if (
                target_casefold
                and target_casefold not in link_text
                and not (source_ids & cited_ids)
            ):
                continue
            link_rows = [row for row in artifact_rows if row.id in source_ids]
            add(
                str(link.get("kind", "investigation_mechanism_link")),
                dict(link_value),
                link_rows,
                nature="STATIC_DERIVED",
            )
    # Deduplicate only semantically identical observations.  The same API
    # can occur at multiple call sites, with different edge arguments, and
    # each edge is an independent piece of evidence.  A key based only on
    # ``(kind, api)`` silently discarded those call-site semantics.  The
    # normalizer below removes only generated provenance envelopes, leaving
    # the complete semantic payload (including edge/from/to fields) in the
    # identity.
    def _without_provenance(value: object) -> object:
        if isinstance(value, Mapping):
            cleaned: dict[str, object] = {}
            for raw_key, raw_value in value.items():
                key = str(raw_key)
                normalized_key = key.casefold()
                if normalized_key in {
                    "derivation",
                    "source_evidence_ids",
                    "evidence_ids",
                    "consumer_evidence_ids",
                    "input_evidence_ids",
                    "output_evidence_ids",
                } or normalized_key.endswith("_evidence_ids"):
                    continue
                cleaned[key] = _without_provenance(raw_value)
            return cleaned
        if isinstance(value, (list, tuple, set, frozenset)):
            return [_without_provenance(item) for item in value]
        return value

    unique: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in observations:
        value = item.get("value") if isinstance(item.get("value"), dict) else {}
        source_ids = tuple(
            str(item_id) for item_id in value.get("source_evidence_ids", ()) if item_id
        )
        anchor = item.get("anchor") if isinstance(item.get("anchor"), dict) else {}
        semantic_anchor = {
            key: raw_value
            for key, raw_value in anchor.items()
            if str(key).casefold()
            not in {"source_evidence_ids", "source_anchors"}
        }
        key = (
            str(item.get("kind")),
            json.dumps(
                _without_provenance(value),
                ensure_ascii=True,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            ),
            json.dumps(
                _without_provenance(semantic_anchor),
                ensure_ascii=True,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            ),
        )
        existing = unique.get(key)
        if existing is None:
            unique[key] = item
            continue
        existing_value = (
            existing.get("value") if isinstance(existing.get("value"), dict) else {}
        )
        merged_ids = list(
            dict.fromkeys(
                [
                    str(item_id)
                    for item_id in existing_value.get("source_evidence_ids", ())
                    if item_id
                ]
                + list(source_ids)
            )
        )
        existing_value["source_evidence_ids"] = merged_ids
        derivation = existing_value.get("derivation")
        if isinstance(derivation, dict):
            derivation["input_evidence_ids"] = merged_ids
            derivation["input_digest"] = hashlib.sha256(
                json.dumps(
                    {
                        "action_type": action.action_type.value,
                        "target": target,
                        "source_evidence_ids": merged_ids,
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        existing["value"] = existing_value
        if isinstance(existing.get("anchor"), dict):
            existing["anchor"]["source_evidence_ids"] = merged_ids
    return list(unique.values())[:64]


_DECODE_PRODUCER_KINDS = {
    "mechanism_decode_window",
    "encoded_blob",
    "crypto_indicator",
    "mechanism_decryption",
    "decode_result",
}
