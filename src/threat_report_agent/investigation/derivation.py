"""P3.3e + P3.3f: the implementation module for the investigation giant, its cluster and the investigation loop.

THIS MODULE NOW HOLDS TWO GIANT MIGRATIONS, and the docstring says which is which because the first version of it
described only `_derive_investigation_observations` (P3.3e) and a 7-member port - both false one step later, which is the
inverse of the "aspirational pin" defect this phase keeps recording:

  * **P3.3e** moved `AnalysisService._derive_investigation_observations` (2,787 lines), its travelling cluster and
    `_DECODE_PRODUCER_KINDS` here;
  * **P3.3f** moved `_run_investigation_loop` (3,523 lines), the eighteen helpers whose only reader it was, and
    `_investigation_scheduled_keys` here, behind the SAME pin - which therefore grew from 7 to the **42 measured
    members** this module's bodies now read.

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
  * the host pin (`INVESTIGATION_HOST_MEMBERS`, now **42 measured members** - it grew with P3.3f) and the `DerivationHost` Protocol.

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

from dataclasses import replace
from typing import Any, Iterable, Mapping, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

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
# FOR THE FIVE CALLS THE LOOP DEFERS TO THE COORDINATOR'S SLICE. MEASURED with `.scratch/p33f-member-homes.py`: five of
# the loop's 45 receiver references are one-statement delegations to `_coordinator`, so the moved body can call that
# module directly instead of costing the port five members. The direction is a sibling import inside `investigation/`,
# the coordinator does NOT import this module (so no cycle), and `--external` makes the mover rewrite those calls.
from threat_report_agent.investigation import coordinator as _coordinator
# From the DEFINING submodule, not the package: the extractor's own lesson is that a package re-export can be a partial
# initialisation, and `investigation/__init__.py` is imported before this module is.
from threat_report_agent.investigation.investigation import (
    ActionCatalog,
    ActionSpec,
    ActionType,
    DeepMiningPlanner,
    GateDecision,
    InvestigationEvent,
    InvestigationLoopDriver,
    InvestigationResult,
    InvestigationThreadState,
    MechanismPlaybookRegistry,
    completed_investigation_methods,
    derive_static_mechanism_links,
    how_timebox_disposition,
    investigation_next_method,
    investigation_scheduled_keys,
    recovery_actions_for_gap,
    verify_mechanism,
)
from threat_report_agent.investigation.evidence_autopsy import no_new_evidence_autopsy
from threat_report_agent.investigation.investigation_ledger import (
    LEDGER_OPEN,
    LEDGER_UNKNOWN,
    attach_results,
    begin_item,
    close_item,
    defer_item,
    register_work_item,
    should_skip_work_item,
    status_from_thread_state,
    terminate_item,
)
from threat_report_agent.investigation.investigation_protocol import (
    fill_protocol,
    tool_authoring_required_ticket,
)
from threat_report_agent.investigation.loop_path import (
    LOOP_PATH_BUDGET_DEFER,
    LOOP_PATH_PERSIST_BOUNDARY,
    LOOP_PATH_PERSIST_READY,
    next_investigation_loop_path,
    resolve_persist_how_skip,
)
from threat_report_agent.investigation.mechanism_completeness import mechanism_is_critical_ready
from threat_report_agent.investigation.mechanism_ready import inspect_mechanism_ready
from threat_report_agent.investigation.persist_how import PersistHow
from threat_report_agent.investigation.seed_support import (
    _HOW_SEED_CATEGORIES,
    _evidence_anchor_keys,
    _evidence_api_symbols,
    _provenance_free_digest,
    _scoped_investigation_action_key,
    _seed_context_rows,
    _seed_playbook,
    admit_investigation_seed_clusters,
    coalesce_investigation_seed_clusters,
    how_seed_slot_rank,
    investigation_budget_charged_action_count,
    investigation_seed_step_budget,
)
from threat_report_agent.investigation.semantic_predicates import normalize_api_symbol
from threat_report_agent.models import (
    AnalysisTask,
    Artifact,
    AuditChainHead,
    AuditEvent,
    Claim,
    ContentBlob,
    Evidence,
    InvestigationActionRecord,
    InvestigationHypothesisRecord,
    InvestigationThreadRecord,
    ToolRun,
    new_id,
    utcnow,
)
from threat_report_agent.static.evidence_recovery import FailureInterpretation
from threat_report_agent.static.static_analysis import (
    build_function_semantic_summary,
    build_pcode_slice,
    classify_pe_semantics,
    credible_windows_process_creation_flags,
    creation_flag_from_abi_slot,
    decode_windows_process_creation_flags,
    evidence_function_body,
    is_specialist_ppid_creation_flag,
    projected_process_image_name,
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


#: What this module's bodies may still reach through their `host` parameter - BOTH migrations' needs, not just the
#: giant's - MEASURED name by name against `service.py` (`.scratch/p33e-giant-prep.py` prints every receiver reference a
#: body makes together with the signature the host member really has; `.scratch/p33f-member-homes.py` adds the axis of
#: WHERE each referenced member lives today).
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
    "_CATALOG_HOW_SEED_SCAN_LIMIT",
    "_CONFIG_CONSUMER_SEED_KIND_LIMITS",
    "_HOW_PLAYBOOK_IDS",
    "_INVESTIGATION_EXECUTION_EVIDENCE_LIMIT",
    "_PERSIST_HOW_CLAIM_MODULES",
    "_audit",
    "_canonical_json",
    "_emulation_entry_key",
    "_follow_local_tail_jmp",
    "_gate_for_seed_playbook",
    "_investigation_row_mapping",
    "_investigation_value_text",
    "_is_config_consumer_seed_row",
    "_is_dynamic_api_seed_row",
    "_is_explorer_parent_string_row",
    "_is_http_transport_seed_row",
    "_is_parent_attribute_seed_row",
    "_is_process_creation_seed_row",
    "_is_process_enumeration_row",
    "_is_task_cancelled",
    "_is_unique_thread_seed_row",
    "_keep_emulation_after_persist_skip",
    "_link_claim_evidence",
    "_load_investigation_execution_rows",
    "_matching_simulation_results",
    "_persist_partial_how_ready",
    "_persist_pma_static_analysis_plan",
    "_persist_ready_emulation_actions",
    "_persist_time_seed_result",
    "_persist_time_static_boundary",
    "_persist_time_unique_thread_result",
    "_persist_unique_thread_claim_specs",
    "_qiling_unavailable_observation",
    "_run_simulation_window",
    "_select_investigation_execution_rows",
    "_static_decode_recovery_from_limitations",
    "_supersede_queued_trace_after_persist_skip",
    "_supporting_seed_static_boundary",
    "_unique_thread_start_keys",
    "content_store",
    "database",
    "settings",
)


class DerivationHost(Protocol):
    """What the moved derivation may use on the object that owns it.

    FORTY-TWO members, each measured (seven from P3.3e; the rest with P3.3f's loop). `settings` is annotated loosely ON PURPOSE, the same choice the coordinator's port
    documents for `database`: naming its concrete class here would create an import edge from `investigation/` to a
    module plan section 3.2 does not list, purely to describe an attribute this code only reads fields from at runtime.

    The rest are declared with the shapes the host really has them in: two plain methods (`_run_simulation_window`,
    `_qiling_unavailable_observation`), THREE classmethods that the moved code calls on the instance
    (`_emulation_entry_key`, `_follow_local_tail_jmp`, `_matching_simulation_results`) and one staticmethod
    (`_investigation_value_text`). A first version of this sentence miscounted them; a Standards-axis review of the
    move measured the real shapes.
    """

    _CATALOG_HOW_SEED_SCAN_LIMIT: int
    _CONFIG_CONSUMER_SEED_KIND_LIMITS: dict
    _HOW_PLAYBOOK_IDS: object
    _INVESTIGATION_EXECUTION_EVIDENCE_LIMIT: int
    _PERSIST_HOW_CLAIM_MODULES: object
    def _audit(self, session: Session, *, case_id: str | None, event_type: str, actor: str, object_type: str, object_id: str, payload: dict[str, object], task_id: str | None = None) -> AuditEvent: ...
    @staticmethod
    def _canonical_json(value: object) -> str: ...
    def _emulation_entry_key(self, value: Mapping[str, object] | str | None) -> str: ...
    def _follow_local_tail_jmp(self, function: dict[str, object], artifact_rows: list[object]) -> dict[str, object]: ...
    def _gate_for_seed_playbook(self): ...
    def _investigation_row_mapping(self): ...
    @staticmethod
    def _investigation_value_text(value: object, *, limit: int = 12000) -> str: ...
    def _is_config_consumer_seed_row(self, row: object) -> bool: ...
    def _is_dynamic_api_seed_row(self, row: object) -> bool: ...
    def _is_explorer_parent_string_row(self): ...
    def _is_http_transport_seed_row(self): ...
    def _is_parent_attribute_seed_row(self): ...
    def _is_process_creation_seed_row(self): ...
    def _is_process_enumeration_row(self): ...
    def _is_task_cancelled(self, task_id: str, *, observing: Session | None = None) -> bool: ...
    def _is_unique_thread_seed_row(self, row: object, start_keys: set[str]) -> bool: ...
    def _keep_emulation_after_persist_skip(self, actions: Iterable[object]) -> tuple[ActionSpec, ...]: ...
    @staticmethod
    def _link_claim_evidence(session: Session, *, claim_id: str, evidence_id: str, stance: str = 'SUPPORTS') -> None: ...
    def _load_investigation_execution_rows(self, session: Session, *, task_id: str, artifact_id: str, action_kinds: set[str] | frozenset[str], limit: int | None = None) -> list[Evidence]: ...
    def _matching_simulation_results(self, rows: Iterable[Any], selector: Mapping[str, object], *, require_success: bool = True) -> tuple[Any, ...]: ...
    def _persist_partial_how_ready(self): ...
    def _persist_pma_static_analysis_plan(self, session: Session, task: AnalysisTask) -> dict[str, object]: ...
    def _persist_ready_emulation_actions(self, *, evidence: Iterable[object], thread_id: str, hypothesis_id: str, artifact_id: str, scheduled_keys: Iterable[str] = ()) -> tuple[ActionSpec, ...]: ...
    def _persist_time_seed_result(self, *, playbook: object, evidence: Iterable[object], thread_id: str, artifact_id: str) -> InvestigationResult | None: ...
    def _persist_time_static_boundary(self, *, playbook: object, evidence: Iterable[object], thread_id: str, artifact_id: str) -> InvestigationResult | None: ...
    def _persist_time_unique_thread_result(self, *, evidence: Iterable[object], thread_id: str, artifact_id: str) -> InvestigationResult | None: ...
    def _persist_unique_thread_claim_specs(self): ...
    def _qiling_unavailable_observation(self, policy: SimulationExecutionPolicy) -> dict[str, object] | None: ...
    def _run_simulation_window(self, policy: SimulationExecutionPolicy, window: Mapping[str, object]) -> SimulationWindowOutcome: ...
    def _select_investigation_execution_rows(self, rows: list[Evidence], *, limit: int | None = None) -> list[Evidence]: ...
    @staticmethod
    def _static_decode_recovery_from_limitations(limitations) -> str: ...
    def _supersede_queued_trace_after_persist_skip(self, queued_rows: Iterable[object], *, thread_id: str) -> None: ...
    def _supporting_seed_static_boundary(self, *, evidence: Iterable[object], thread_id: str, artifact_id: str, category: str) -> InvestigationResult: ...
    def _unique_thread_start_keys(self, rows: Iterable[object]) -> set[str]: ...
    content_store: object  # instance attribute set in __init__
    database: object  # instance attribute set in __init__
    settings: object  # instance attribute set in __init__


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


def _run_investigation_loop(
    host: DerivationHost,
    task_id: str,
    *,
    model_actions_only: bool = False,
    ledger_phase: str = "coverage",
) -> list[str]:
    """Persist and run investigation threads for all non-container artifacts.

        ``model_actions_only`` is the immediate Action Executor path between a
        planner turn and its replan.  It runs only catalog-approved model
        proposals and deliberately does not let deterministic playbooks add
        unrelated experiments in the same turn.
        """
    limitations: list[str] = []
    cancellation_probe_enabled = (
        host.settings.environment.lower() != "test"
        and not host.settings.database_url.lower().startswith("sqlite")
    )
    with host.database.session_factory.begin() as session:
        # Investigation emits a large append-only audit/evidence graph in
        # small dependency-aware batches. Implicit autoflush before a read
        # can flush a later action while its ToolRun/foreign-key parents
        # are still pending, poisoning the outer transaction. Every write
        # boundary below flushes the rows it owns explicitly.
        session.autoflush = False
        task = session.get(AnalysisTask, task_id, with_for_update=True)
        if task is None:
            raise LookupError(task_id)
        artifacts = list(
            session.scalars(
                select(Artifact)
                .where(Artifact.task_id == task_id, Artifact.role != "CONTAINER")
                .order_by(Artifact.created_at)
            )
        )
        # Capture immutable identifiers for the action callbacks.
        artifact_identity = {
            id(item): (str(item.id), str(item.logical_path), str(item.detected_type))
            for item in artifacts
        }
        snapshot = dict(task.strategy_snapshot or {}).get("investigation", {})
        work_ledger: list[dict[str, object]] = [
            dict(item)
            for item in (snapshot.get("work_ledger") or [])
            if isinstance(item, Mapping)
        ]
        # Keep the first durable thread per artifact as the primary seed.
        # Spawned specialist threads are appended later and must not steal
        # this identity on the next bounded invocation.
        snapshot_threads: dict[str, dict[str, object]] = {}
        for item in snapshot.get("threads", []):
            if not isinstance(item, dict):
                continue
            artifact_key = str(item.get("artifact_id") or "")
            if not artifact_key or artifact_key in snapshot_threads:
                continue
            snapshot_threads[artifact_key] = item
        # Investigation may be invoked more than once for a task (for
        # example, a model-action turn followed by deterministic
        # finalization).  Keep the durable runtime projection append-only
        # across invocations; replacing it here made the last no-op pass
        # erase the evidence of earlier actions from task snapshots.
        prior_runtime = snapshot.get("runtime", {})
        prior_runtime = prior_runtime if isinstance(prior_runtime, dict) else {}
        runtime_events: list[dict[str, object]] = [
            item for item in prior_runtime.get("events", []) if isinstance(item, dict)
        ][-512:]
        runtime_actions: list[dict[str, object]] = [
            item for item in prior_runtime.get("actions", []) if isinstance(item, dict)
        ][-128:]
        runtime_gates: list[dict[str, object]] = [
            item for item in prior_runtime.get("gates", []) if isinstance(item, dict)
        ][-128:]
        prior_convergence = snapshot.get("convergence", {})
        if not isinstance(prior_convergence, Mapping):
            prior_convergence = {}
        runtime_convergence: dict[str, dict[str, object]] = {
            str(key): dict(value)
            for key, value in prior_convergence.items()
            if isinstance(value, Mapping)
        }
        playbooks = MechanismPlaybookRegistry()
        # Bound one invocation across all seed threads, not the task's
        # lifetime. The transaction is atomic on crash; committed action
        # keys below deduplicate completed work on follow-up invocations.
        task_action_budget_limit = max(
            1, int(host.settings.investigation_task_max_actions)
        )
        existing_task_actions = list(
            session.scalars(
                select(InvestigationActionRecord).where(
                    InvestigationActionRecord.task_id == task.id,
                    InvestigationActionRecord.status.in_(
                        ("SUCCEEDED", "FAILED", "RUNNING")
                    ),
                )
            )
        )
        task_action_budget_used = 0
        # Rebuild the live frontier as threads are visited. Prior events
        # remain in the append-only audit ledger, not as stale blockers.
        deferred_frontier: list[dict[str, object]] = []
        deferred_frontier_keys = {
            (
                str(item.get("thread_id", "")),
                str(item.get("reason", "")),
                str(item.get("action_id", "")),
            )
            for item in deferred_frontier
        }

        def record_deferred_frontier(item: Mapping[str, object]) -> None:
            key = (
                str(item.get("thread_id", "")),
                str(item.get("reason", "")),
                str(item.get("action_id", "")),
            )
            if key in deferred_frontier_keys:
                return
            deferred_frontier_keys.add(key)
            deferred_frontier.append(dict(item))

        budget_limitation = (
            f"Investigation invocation action budget is {task_action_budget_limit}; "
                "remaining investigation frontiers are deferred when exhausted."
        )
        # Expand every bounded high-value seed cluster into its own
        # durable investigation thread.  The old implementation selected
        # only the first cluster and left the remaining frontier as
        # descriptive snapshot data, making multi-seed scheduling
        # effectively write-only.  Keep the first thread identity stable
        # for replay compatibility and derive deterministic identities for
        # additional clusters.
        work_items: list[tuple[Artifact, dict[str, object]]] = []
        # Action records remain thread-scoped for auditability, but the
        # static executor's work scope is artifact-local. Reserve each
        # normalized action key across sibling seed threads so an action
        # with a new thread/sequence ID cannot replay the same query and
        # consume budget on NO_NEW_EVIDENCE.
        artifact_frontier_keys: dict[str, set[str]] = {}
        seed_maps = snapshot.get("seed_maps", {})
        for artifact in artifacts:
            base_seed = dict(snapshot_threads.get(artifact.id, {}) or {})
            artifact_seed_map = (
                seed_maps.get(artifact.id, {}) if isinstance(seed_maps, dict) else {}
            )
            clusters = (
                artifact_seed_map.get("clusters", [])
                if isinstance(artifact_seed_map, dict)
                else []
            )
            # Keep every raw cluster in the immutable seed map, then
            # collapse equivalent mechanism dimensions for the actual
            # work frontier.  Coalescing before the four-thread budget
            # prevents repeated resolver/decoder seeds from starving
            # unrelated network, execution or evasion questions.
            # Keep every bounded seed dimension emitted by the seed map
            # (currently at most 12). Each thread is seed-local and
            # action-family bounded below, so this does not turn into an
            # artifact-wide unbounded action fan-out. Truncating here
            # would make later high-value dimensions report-only rather
            # than investigated.
            # Keep a larger, still bounded admission window for real
            # binaries.  Twelve clusters were enough for toy samples but
            # caused high-risk functions after the first page to remain
            # report-only forever.  The planner itself remains
            # action-budgeted; this window only determines which
            # evidence-grounded investigation questions receive durable
            # thread identities.
            bounded_clusters = admit_investigation_seed_clusters(clusters)
            coalesced_clusters = coalesce_investigation_seed_clusters(clusters)
            work_clusters = list(bounded_clusters)
            admitted_ids = {
                str(item.get("id") or "").strip()
                for item in bounded_clusters
                if str(item.get("id") or "").strip()
            }
            for cluster in coalesced_clusters:
                cluster_id = str(cluster.get("id") or "").strip()
                if not cluster_id or cluster_id in admitted_ids:
                    continue
                work_clusters.append(cluster)
                admitted_ids.add(cluster_id)
            if not work_clusters:
                work_items.append((artifact, base_seed))
                continue
            for index, cluster in enumerate(work_clusters):
                cluster_seed = dict(base_seed)
                cluster_seed["_seed_cluster"] = cluster
                if index:
                    cluster_id = str(cluster.get("id") or f"cluster-{index}")
                    thread_id = (
                        "thread-"
                        + hashlib.sha256(
                            f"{task.id}:{artifact.id}:{cluster_id}".encode("utf-8")
                        ).hexdigest()[:20]
                    )
                    hypothesis_id = (
                        "hypothesis-"
                        + hashlib.sha256(f"{thread_id}:mechanism".encode("utf-8")).hexdigest()[
                            :20
                        ]
                    )
                    cluster_seed.update(
                        {
                            "id": thread_id,
                            "hypothesis_ids": [hypothesis_id],
                            "mechanism_ids": [
                                "mechanism-"
                                + hashlib.sha256(
                                    f"{thread_id}:static".encode("utf-8")
                                ).hexdigest()[:20]
                            ],
                        }
                    )
                work_items.append((artifact, cluster_seed))

        # High-value HOW slots first (process/PPID/network), then less-explored.
        historical_attempts: dict[str, int] = {}
        for action in existing_task_actions:
            if not (action.parameters or {}).get("deferred"):
                historical_attempts[action.thread_id] = historical_attempts.get(action.thread_id, 0) + 1
        work_items.sort(
            key=lambda item: (
                how_seed_slot_rank(item[1] if isinstance(item[1], Mapping) else {}),
                historical_attempts.get(
                    str(
                        item[1].get("id")
                        or (
                            "thread-"
                            + hashlib.sha256(f"{task.id}:{item[0].id}".encode()).hexdigest()[:20]
                        )
                    ),
                    0,
                ),
            )
        )

        for work_index, (artifact, seed_override) in enumerate(work_items):
            artifact_id_value, artifact_path_value, artifact_type_value = artifact_identity[
                id(artifact)
            ]
            seed = dict(seed_override or snapshot_threads.get(artifact_id_value, {}) or {})
            # The static parser emits a bounded seed map before this
            # loop.  Consume its highest-priority cluster as the active
            # investigation question, while retaining the original
            # artifact seed as a fallback for older snapshots.
            seed_maps = snapshot.get("seed_maps", {})
            artifact_seed_map = (
                seed_maps.get(artifact_id_value, {}) if isinstance(seed_maps, dict) else {}
            )
            clusters = (
                artifact_seed_map.get("clusters", [])
                if isinstance(artifact_seed_map, dict)
                else []
            )
            selected_clusters = [
                item
                for item in clusters
                if isinstance(item, dict) and str(item.get("question", "")).strip()
            ][:4]
            override_cluster = seed.get("_seed_cluster")
            if isinstance(override_cluster, dict):
                selected_clusters = [override_cluster]
            selected_cluster = selected_clusters[0] if selected_clusters else None
            if selected_cluster is not None:
                frontier_questions = list(
                    dict.fromkeys(
                        str(item.get("question", "")).strip()
                        for item in selected_clusters
                        if str(item.get("question", "")).strip()
                    )
                )
                frontier_evidence_ids = list(
                    dict.fromkeys(
                        str(evidence_id)
                        for item in selected_clusters
                        for evidence_id in (
                            item.get("evidence_ids", [])
                            if isinstance(item.get("evidence_ids", []), list)
                            else []
                        )
                        if str(evidence_id).strip()
                    )
                )[:96]
                seed = {
                    **seed,
                    # The first cluster remains the stable primary ID for
                    # replay compatibility; the frontier fields make the
                    # bounded multi-seed decision explicit to the Agent,
                    # report, and audit consumers.
                    "seed_cluster_id": str(selected_cluster.get("id", "")),
                    "seed_cluster_ids": [str(item.get("id", "")) for item in selected_clusters],
                    "seed_cluster_categories": [
                        str(item.get("category", "generic")) for item in selected_clusters
                    ],
                    "seed_cluster_category": str(selected_cluster.get("category", "generic")),
                    "seed_cluster_evidence_ids": frontier_evidence_ids[:32],
                    "seed_frontier_evidence_ids": frontier_evidence_ids,
                    "seed_frontier_questions": frontier_questions,
                }
            thread_id = str(
                seed.get("id")
                or f"thread-{hashlib.sha256(f'{task.id}:{artifact.id}'.encode()).hexdigest()[:20]}"
            )
            hypothesis_id = str(
                (seed.get("hypothesis_ids") or [""])[0]
                or f"hypothesis-{hashlib.sha256(f'{thread_id}:mechanism'.encode()).hexdigest()[:20]}"
            )
            thread = session.get(InvestigationThreadRecord, thread_id)
            if thread is None:
                cluster_question = (
                    str(selected_cluster.get("question", "")).strip()
                    if selected_cluster is not None
                    else ""
                )
                thread = InvestigationThreadRecord(
                    id=thread_id,
                    task_id=task.id,
                    artifact_id=artifact.id,
                    state="DISCOVERED",
                    question=str(
                        cluster_question
                        or seed.get("question")
                        or "Which evidence explains the artifact's highest-risk static mechanism?"
                    ),
                    seed_kind=str(seed.get("seed_kind") or "artifact_triage"),
                    hypothesis_ids=[hypothesis_id],
                )
                session.add(thread)
                session.flush()
            hypothesis = session.get(InvestigationHypothesisRecord, hypothesis_id)
            if hypothesis is None:
                hypothesis = InvestigationHypothesisRecord(
                    id=hypothesis_id,
                    task_id=task.id,
                    thread_id=thread.id,
                    statement=str(
                        seed.get("hypothesis_statement")
                        or "The artifact may contain an ordered process, loading, decode, network, or evasion mechanism."
                    ),
                    dimension=str(seed.get("hypothesis_dimension") or "mechanism_discovery"),
                    status="OPEN",
                    confidence="LOW",
                    required_evidence=list(
                        seed.get("required_evidence") or ["function_context", "function_call"]
                    ),
                )
                session.add(hypothesis)
                session.flush()
            work_ledger = register_work_item(
                work_ledger,
                {
                    "id": thread.id,
                    "thread_id": thread.id,
                    "artifact_id": artifact.id,
                    "question": thread.question,
                    "seed_kind": thread.seed_kind,
                    "status": status_from_thread_state(thread.state)
                    if str(thread.state or "")
                    not in {
                        "DISCOVERED",
                        "PRIORITIZED",
                        "CONTEXT_READY",
                        "HYPOTHESIZING",
                        "INVESTIGATING",
                        "",
                    }
                    else LEDGER_OPEN,
                },
            )
            current_item = next(
                (item for item in work_ledger if str(item.get("id")) == thread.id),
                None,
            )
            if (
                not model_actions_only
                and current_item is not None
                and should_skip_work_item(
                    current_item, phase=ledger_phase, ledger=work_ledger
                )
            ):
                continue
            # A thread whose bounded continuation already recorded
            # STALLED/STATIC_BOUNDARY has, by this loop's own measurement,
            # exercised distinct static methods to zero gain with no next
            # method left.  Re-entering the driver for it re-selects the
            # same method frontier and is the measured grind: on the storm
            # task `e53de9f7` one thread executed 128 of 144 actions and
            # recorded 26 `investigation.stalled` events, then kept running
            # for another 76 actions / 8 minutes because a recorded stall
            # had no scheduling effect.  Recognise the recorded terminal
            # state instead of paying for it again: stamp the honest static
            # UNKNOWN the loop already described and stop scheduling it.
            # Isolated worker emulation is unaffected - the outer
            # orchestration dispatches it from `run_analysis_task_*`, not
            # from this thread's ledger status, and the ledger item must end
            # terminal or `completion_allows_stop` can never say yes.  No
            # budget, quota or action family changes here: the useful
            # frontier of every non-stalled thread is untouched.
            stalled_record = runtime_convergence.get(thread.id, {})
            if (
                not model_actions_only
                and isinstance(stalled_record, Mapping)
                and str(stalled_record.get("status") or "").upper() == "STALLED"
            ):
                stall_visits = int(stalled_record.get("stall_visits") or 0) + 1
                runtime_convergence[thread.id] = {
                    **stalled_record,
                    "stall_visits": stall_visits,
                }
                work_ledger = terminate_item(
                    work_ledger,
                    thread.id,
                    LEDGER_UNKNOWN,
                    reason="STALLED",
                    next_method="STATIC_BOUNDARY",
                )
                if thread.state not in {
                    InvestigationThreadState.CLAIM_READY.value,
                    InvestigationThreadState.CLOSED.value,
                }:
                    thread.state = InvestigationThreadState.UNKNOWN.value
                stall_limitation = (
                    f"Investigation thread {thread.id} is STALLED; "
                        "STATIC_BOUNDARY after distinct static methods produced "
                        "no new evidence. The exhausted frontier was not replayed."
                )
                if stall_limitation not in limitations:
                    limitations.append(stall_limitation)
                runtime_events.append(
                    {
                        "thread_id": thread.id,
                        "phase": "investigation.stalled_skipped",
                        "action_id": None,
                        "state": thread.state,
                        "evidence_ids": list(thread.evidence_ids or []),
                        "message": (
                            "recorded STALLED frontier stamped as an honest "
                                "static UNKNOWN; absence is not refutation"
                        ),
                    }
                )
                host._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="investigation.stalled",
                    actor="scheduler",
                    object_type="InvestigationThread",
                    object_id=thread.id,
                    payload={
                        "status": "STALLED",
                        "intervention": "STATIC_BOUNDARY",
                        "replayed": False,
                        "method_ids": list(stalled_record.get("method_ids") or []),
                        "frontier_fingerprint": stalled_record.get(
                            "frontier_fingerprint"
                        ),
                    },
                )
                thread.updated_at = utcnow()
                continue
            # Persist-time CLAIM_READY / static-boundary skip is
            # zero-cost. Do not defer those seeds just because an earlier
            # OPEN thread already spent the 64-action cap on TRACE.
            budget_exhausted = task_action_budget_used >= task_action_budget_limit
            # Investigation context must remain bounded independently of
            # the parser's raw output volume.  Large binaries commonly
            # produce thousands of low-signal string rows; loading and
            # repeatedly flattening all of them holds the task transaction
            # open and can starve the API.  Keep all high-signal mechanism
            # kinds within a generous cap, then add a small deterministic
            # string/other sample for discovery.
            high_signal_kinds = {
                "pe_structure",
                "import_symbol",
                "export_symbol",
                "function",
                "function_context",
                "function_call",
                "function_mechanism",
                "function_instruction_window",
                "function_interface",
                "function_ioc",
                "function_data_correlation",
                "api_argument_trace",
                "resolved_api",
                "function_simhash",
                "xref",
                "cfg_block",
                "cross_function_chain",
                "mechanism_decode_window",
                "mechanism_decode",
                "decode_result",
                "encoded_blob",
                "mechanism_integrity_check",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "mechanism_decompression_format",
                "mechanism_dynamic_resolution",
                # Derived mechanism links are bounded, provenance-bearing
                # static observations.  They must be visible to the
                # investigation verifier; otherwise the correlator's
                # output is effectively write-only for real samples.
                "mechanism_dynamic_api_link",
                "mechanism_http_transport_link",
                "mechanism_shell_output_link",
                "mechanism_etw_patch_link",
                "mechanism_environment_check",
                "mechanism_memory_permission",
                "mechanism_process_creation",
                "loader_indicator",
                "execution_indicator",
                "anti_analysis_indicator",
                "network_indicator",
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
                "document_embedded_object",
                "document_embedded_file",
                "archive_member",
                "decoded_artifact",
                "simulation_result",
                "script_line",
                "script_call",
                "script_import",
            }
            # Derived static links have a different purpose from the
            # broad discovery corpus: each is a small, provenance-bearing
            # hypothesis for a specialist semantic verifier.  Do not let
            # a large Ghidra function/CFG corpus consume their budget just
            # because it was persisted earlier in the same task.
            static_link_kinds = frozenset(
                {
                    "mechanism_dynamic_api_link",
                    "mechanism_http_transport_link",
                    "mechanism_shell_output_link",
                    "mechanism_etw_patch_link",
                }
            )
            base_evidence_filter = (
                Evidence.task_id == task.id,
                Evidence.artifact_id == artifact.id,
                Evidence.nature != "BACKGROUND_REPORTED",
            )
            high_signal_rows = list(
                session.scalars(
                    select(Evidence)
                    .where(
                        *base_evidence_filter,
                        Evidence.kind.in_(high_signal_kinds - static_link_kinds),
                    )
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(768)
                )
            )
            static_link_rows = list(
                session.scalars(
                    select(Evidence)
                    .where(*base_evidence_filter, Evidence.kind.in_(static_link_kinds))
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(128)
                )
            )
            # Recover precisely the bounded provenance that the selected
            # links cite.  The verifier must never infer a cross-function
            # relationship from task-wide co-occurrence; it receives only
            # same-artifact Evidence explicitly named by each link.
            static_link_source_ids = list(
                dict.fromkeys(
                    str(source_id)
                    for link_row in static_link_rows
                    if isinstance(link_row.value, Mapping)
                    for source_id in (link_row.value.get("source_evidence_ids") or ())[:24]
                    if str(source_id).strip()
                )
            )
            static_link_source_rows = (
                list(
                    session.scalars(
                        select(Evidence).where(
                            *base_evidence_filter,
                            Evidence.id.in_(static_link_source_ids),
                        )
                    )
                )
                if static_link_source_ids
                else []
            )
            config_consumer_candidates: list[Evidence] = []
            for kind, cap in host._CONFIG_CONSUMER_SEED_KIND_LIMITS.items():
                config_consumer_candidates.extend(
                    session.scalars(
                        select(Evidence)
                        .where(*base_evidence_filter, Evidence.kind == kind)
                        .order_by(Evidence.created_at.desc(), Evidence.id)
                        .limit(cap)
                    )
                )
            # Persist-time HOW catalog rows are written during Ghidra, in
            # the middle of the function budget, then investigation floods
            # newer traces. Newest-256 and oldest-128 both miss them.
            for kind in ("api_argument_trace", "value_flow", "resolved_api", "process_creation_flags", "decode_result"):
                config_consumer_candidates.extend(
                    session.scalars(
                        select(Evidence)
                        .where(*base_evidence_filter, Evidence.kind == kind)
                        .order_by(Evidence.created_at.asc(), Evidence.id)
                        .limit(host._CATALOG_HOW_SEED_SCAN_LIMIT)
                    )
                )
            for row in session.scalars(
                select(Evidence)
                .where(*base_evidence_filter, Evidence.kind == "string")
                .order_by(Evidence.created_at.asc(), Evidence.id)
            ):
                value = row.value if isinstance(row.value, Mapping) else {}
                if projected_process_image_name(value.get("text")):
                    config_consumer_candidates.append(row)
            config_consumer_rows = _select_config_consumer_seed_rows(host, 
                config_consumer_candidates,
                limit=128,
            )
            process_creation_rows = _select_process_creation_seed_rows(host, 
                config_consumer_candidates,
                limit=128,
            )
            http_transport_rows = _select_http_transport_seed_rows(host, 
                config_consumer_candidates,
                limit=128,
            )
            parent_attribute_rows = _select_parent_attribute_seed_rows(host, 
                config_consumer_candidates,
                limit=128,
            )
            parent_identity_rows = _select_ppid_parent_identity_rows(host, 
                [*config_consumer_candidates, *high_signal_rows],
                limit=32,
            )
            parent_seen = {
                str(getattr(row, "id", "") or "")
                for row in parent_attribute_rows
                if str(getattr(row, "id", "") or "")
            }
            for row in parent_identity_rows:
                row_id = str(getattr(row, "id", "") or "")
                if row_id and row_id in parent_seen:
                    continue
                if row_id:
                    parent_seen.add(row_id)
                parent_attribute_rows.append(row)
            dynamic_api_rows = _select_dynamic_api_seed_rows(host, 
                config_consumer_candidates,
                limit=128,
            )
            catalog_seed_rows = [
                *config_consumer_rows,
                *process_creation_rows,
                *http_transport_rows,
                *parent_attribute_rows,
                *dynamic_api_rows,
            ]
            config_consumer_ids = list(
                dict.fromkeys(
                    str(item_id)
                    for row in catalog_seed_rows
                    if isinstance(getattr(row, "value", None), Mapping)
                    for key in (
                        "source_evidence_ids",
                        "target_evidence_ids",
                        "consumer_evidence_ids",
                        "source_evidence_id",
                        "target_evidence_id",
                    )
                    for item_id in (
                        row.value.get(key)
                        if isinstance(row.value.get(key), (list, tuple, set))
                        else ((row.value.get(key),) if row.value.get(key) else ())
                    )
                    if str(item_id).strip()
                )
            )
            config_consumer_source_rows = (
                list(
                    session.scalars(
                        select(Evidence).where(
                            *base_evidence_filter,
                            Evidence.id.in_(config_consumer_ids),
                        )
                    )
                )
                if config_consumer_ids
                else []
            )
            sampled_rows = list(
                session.scalars(
                    select(Evidence)
                    .where(*base_evidence_filter, ~Evidence.kind.in_(high_signal_kinds))
                    .order_by(Evidence.created_at, Evidence.id)
                    .limit(256)
                )
            )
            all_source_rows = list(
                {
                    row.id: row
                    for row in (
                        *high_signal_rows,
                        *static_link_rows,
                        *static_link_source_rows,
                        *config_consumer_rows,
                        *process_creation_rows,
                        *http_transport_rows,
                        *parent_attribute_rows,
                        *dynamic_api_rows,
                        *config_consumer_source_rows,
                        *sampled_rows,
                    )
                }.values()
            )
            # SQLite returns persisted timestamps as naive values while
            # freshly-created rows in the same transaction may still be
            # timezone-aware.  Sort by their canonical textual form so a
            # multi-seed pass cannot fail merely because both forms are
            # present in one session.
            all_source_rows.sort(
                key=lambda row: (
                    row.created_at.isoformat() if getattr(row, "created_at", None) else "",
                    row.id,
                )
            )
            # Background reports are provenance-bearing context, never
            # authorization for a sample-derived action or mechanism.
            # Keep them in the immutable ledger/report, but isolate them
            # from playbook matching and investigation execution.
            source_rows = [
                row for row in all_source_rows if row.nature != "BACKGROUND_REPORTED"
            ]
            profile_rows = [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "nature": row.nature,
                    "value": row.value,
                    "anchor": row.anchor,
                }
                for row in source_rows
            ]
            # Reuse one bounded artifact-local corpus for all actions in
            # this thread. A cited row outside the cap is added per action
            # below, preserving targeted lookups without repeated 50k-row
            # ORM queries.
            action_kinds = {
                "function",
                "function_context",
                "function_call",
                "function_interface",
                "function_data_correlation",
                "function_instruction_window",
                "function_mechanism",
                "function_ioc",
                "function_simhash",
                "api_argument_trace",
                "resolved_api",
                "cross_function_chain",
                "abstract_execution_trace",
                "value_flow",
                "constant",
                "string_reference",
                "import_symbol",
                "loader_indicator",
                "execution_indicator",
                "anti_analysis_indicator",
                "mechanism_dynamic_resolution",
                "mechanism_memory_permission",
                "xref",
                "cfg_block",
                "string",
                "data_reference",
                "mechanism_decode_window",
                "mechanism_decode",
                "decode_result",
                "encoded_blob",
                "mechanism_integrity_check",
                "mechanism_resource_payload",
                "mechanism_resource_extraction",
                "mechanism_decompression",
                "mechanism_decompression_format",
                "encoded_blob",
                "decoded_artifact",
                "simulation_result",
                "resource_inventory",
                "pe_resource",
                "pe_resource_directory",
                "embedded_object",
                "embedded_artifact",
                "document_embedded_object",
                "document_embedded_file",
                "archive_member",
            }
            execution_corpus = host._load_investigation_execution_rows(
                session,
                task_id=task.id,
                artifact_id=artifact.id,
                action_kinds=action_kinds,
                limit=host._INVESTIGATION_EXECUTION_EVIDENCE_LIMIT,
            )
            execution_corpus = host._select_investigation_execution_rows(
                execution_corpus,
                limit=host._INVESTIGATION_EXECUTION_EVIDENCE_LIMIT,
            )

            # Promote only verifier-accepted, provenance-bearing static
            # correlations into durable mechanism records.  The parser's
            # ``mechanism_*_link`` rows are not runtime proof, but they do
            # contain a bounded same-function/call-graph derivation and
            # are the correct input to the static semantic verifier.  A
            # link that fails its verifier remains an Evidence-only lead.
            static_link_types = {
                "mechanism_dynamic_api_link": "DYNAMIC_API_RESOLUTION",
                "mechanism_http_transport_link": "HTTP_DOWNLOAD",
                "mechanism_shell_output_link": "SHELL_OUTPUT",
                "mechanism_etw_patch_link": "ETW_PATCH",
            }

            def _link_values(value: Mapping[str, object], *keys: str) -> list[str]:
                result: list[str] = []
                for key in keys:
                    raw = value.get(key)
                    if isinstance(raw, (list, tuple, set)):
                        result.extend(str(item) for item in raw if item not in (None, ""))
                    elif raw not in (None, ""):
                        result.append(str(raw))
                return list(dict.fromkeys(result))

            source_rows_by_id = {str(row.id): row for row in source_rows}
            for link_row in source_rows:
                mechanism_type = static_link_types.get(str(link_row.kind).casefold())
                if mechanism_type is None or not isinstance(link_row.value, Mapping):
                    continue
                source_ids = [
                    str(item)
                    for item in (link_row.value.get("source_evidence_ids") or ())
                    if str(item).strip()
                ]
                source_id_set = set(source_ids)
                source_rows_for_link = [
                    source_rows_by_id[item_id]
                    for item_id in source_id_set
                    if item_id in source_rows_by_id
                ]
                # A derived link is admissible only when every cited
                # source row is present in the same task/artifact scope.
                # This prevents a hand-authored link row from satisfying
                # all verifier groups by repeating its own labels.
                if not source_ids or len(source_rows_for_link) != len(set(source_ids)):
                    continue
                verification = verify_mechanism(
                    mechanism_type,
                    [
                        {
                            "id": row.id,
                            "kind": row.kind,
                            "nature": row.nature,
                            "value": row.value,
                            "anchor": row.anchor,
                        }
                        for row in [*source_rows_for_link, link_row]
                    ],
                )
                if not verification.accepted:
                    continue
                value = link_row.value
                if mechanism_type == "DYNAMIC_API_RESOLUTION":
                    inputs = _link_values(value, "module", "entry_point")
                    transforms = _link_values(value, "relationship")
                    outputs = _link_values(value, "function_pointer")
                    consumers = _link_values(value, "consumer", "consumer_apis")
                    effects = [
                        "prepares a resolved API entry point; runtime loading is unobserved"
                    ]
                elif mechanism_type == "HTTP_DOWNLOAD":
                    inputs = _link_values(value, "endpoint", "transport")
                    transforms = _link_values(value, "relationship")
                    outputs = _link_values(value, "response_side_effect", "side_effect")
                    consumers = _link_values(value, "consumer")
                    effects = ["may receive response bytes; network access was not performed"]
                elif mechanism_type == "SHELL_OUTPUT":
                    inputs = _link_values(value, "input", "shell")
                    transforms = _link_values(value, "relationship")
                    outputs = _link_values(value, "output_capture", "side_effect")
                    consumers = _link_values(value, "consumer")
                    effects = [
                        "captures a child-process output channel; process execution is unobserved"
                    ]
                else:
                    inputs = _link_values(value, "entry")
                    transforms = _link_values(value, "relationship", "condition")
                    outputs = _link_values(value, "patch_bytes")
                    consumers = _link_values(value, "flush")
                    effects = [
                        "may alter an ETW provider target; memory writes were not executed"
                    ]
                mechanism_id = (
                    "mechanism-"
                    + hashlib.sha256(
                        f"{task.id}:{artifact.id}:{mechanism_type}".encode("utf-8")
                    ).hexdigest()[:20]
                )
                mechanism = next(
                    (
                        item
                        for item in snapshot.setdefault("mechanisms", [])
                        if isinstance(item, dict) and str(item.get("id")) == mechanism_id
                    ),
                    None,
                )
                if mechanism is None:
                    mechanism = {
                        "id": mechanism_id,
                        "thread_id": thread.id,
                        "artifact_id": artifact_id_value,
                        "dimension": mechanism_type,
                        "steps": [],
                        "type": mechanism_type,
                    }
                    snapshot["mechanisms"].append(mechanism)
                mechanism.update(
                    {
                        "mechanism_type": mechanism_type,
                        "status": "VERIFIED",
                        "target": artifact.logical_path,
                        "inputs": inputs or ["UNKNOWN(input)"],
                        "transformation_or_control": transforms
                        or ["UNKNOWN(transformation_or_control)"],
                        "conditions": [
                            "static linked evidence only; runtime reachability and intent are unobserved"
                        ],
                        "outputs": outputs or ["UNKNOWN(output)"],
                        "consumers": consumers or ["UNKNOWN(consumer)"],
                        "side_effects": effects,
                        "evidence_ids": list(
                            dict.fromkeys(
                                (list(verification.evidence_ids) + [link_row.id] + source_ids)
                            )
                        )[:32],
                        "verifier": verification.as_dict(),
                        "limitations": [
                            "Static evidence; sample execution and network access are not observed."
                        ],
                        "claim_ids": list(
                            dict.fromkeys(
                                str(item) for item in mechanism.get("claim_ids", []) if item
                            )
                        ),
                    }
                )
                ready = inspect_mechanism_ready(mechanism)
                mechanism["completeness"] = ready.completeness
                static_claim_ready = mechanism_is_critical_ready(mechanism)
                # A specialist verifier can close a narrowly-defined
                # static mechanism even when the broader seed hypothesis
                # still lacks evidence.  Persist that smaller conclusion
                # now rather than making reportability depend on a later,
                # unrelated generic ClaimGate result.
                static_claim_profiles = {
                    "DYNAMIC_API_RESOLUTION": (
                        "resolves_dynamic_api",
                        "a dynamically resolved API entry point",
                        "A static resolver-to-consumer path is recovered; runtime module loading and invocation are not observed.",
                        {
                            "status": "candidate",
                            "mappings": [
                                {
                                    "technique_id": "T1027.007",
                                    "technique_name": "Obfuscated Files or Information: Dynamic API Resolution",
                                    "status": "candidate",
                                }
                            ],
                        },
                    ),
                    "HTTP_DOWNLOAD": (
                        "receives_http_response_data",
                        "HTTP response bytes",
                        "A static HTTP request/response path is recovered; no network request was performed.",
                        {
                            "status": "candidate",
                            "mappings": [
                                {
                                    "technique_id": "T1071.001",
                                    "technique_name": "Application Layer Protocol: Web Protocols",
                                    "status": "candidate",
                                }
                            ],
                        },
                    ),
                    "SHELL_OUTPUT": (
                        "captures_child_process_output",
                        "a child-process output channel",
                        "A static child-process pipe/output capture path is recovered; process execution is not observed.",
                        {
                            "status": "candidate",
                            "mappings": [
                                {
                                    "technique_id": "T1059",
                                    "technique_name": "Command and Scripting Interpreter",
                                    "status": "candidate",
                                }
                            ],
                        },
                    ),
                    "ETW_PATCH": (
                        "may_patch_etw_reporting",
                        "the EtwEventWrite reporting target",
                        "A static ETW patch sequence is recovered; memory writes and telemetry impairment are not observed.",
                        {
                            "status": "candidate",
                            "mappings": [
                                {
                                    "technique_id": "T1562.001",
                                    "technique_name": "Impair Defenses: Disable or Modify Tools",
                                    "status": "candidate",
                                }
                            ],
                        },
                    ),
                }
                claim_action, claim_object, static_boundary, attack_mapping = (
                    static_claim_profiles[mechanism_type]
                )
                existing_static_claim = next(
                    iter(
                        session.scalars(
                            select(Claim)
                            .where(
                                Claim.task_id == task.id,
                                Claim.claim_type == "STATIC_MECHANISM_LINK",
                                Claim.subject == artifact.logical_path,
                                Claim.action == claim_action,
                            )
                            .order_by(Claim.id)
                            .limit(1)
                        )
                    ),
                    None,
                )
                if existing_static_claim is None:
                    existing_static_claim = Claim(
                        task_id=task.id,
                        module="investigation",
                        claim_type="STATIC_MECHANISM_LINK",
                        subject=artifact.logical_path,
                        action=claim_action,
                        object=claim_object,
                        mechanism=" -> ".join(transforms)
                        or mechanism_type.replace("_", " ").lower(),
                        condition="specialist static verifier accepted the provenance-bearing evidence path",
                        statement=(
                            f"Static analysis recovered a verified {mechanism_type.replace('_', ' ').lower()} "
                                f"mechanism in {artifact.logical_path}. {static_boundary}"
                        ),
                        nature="STATIC_INFERRED",
                        status="SUPPORTED" if static_claim_ready else "CANDIDATE",
                        confidence="MEDIUM",
                        attack_mapping=attack_mapping,
                    )
                    session.add(existing_static_claim)
                    session.flush()
                for evidence_id in mechanism["evidence_ids"]:
                    host._link_claim_evidence(
                        session,
                        claim_id=existing_static_claim.id,
                        evidence_id=evidence_id,
                    )
                mechanism["claim_id"] = mechanism.get("claim_id") or existing_static_claim.id
                mechanism["claim_ids"] = list(
                    dict.fromkeys(
                        [
                            *[str(item) for item in mechanism.get("claim_ids", []) if item],
                            existing_static_claim.id,
                        ]
                    )
                )
                host._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="investigation.static_mechanism_claim_supported",
                    actor="specialist-static-verifier",
                    object_type="Claim",
                    object_id=existing_static_claim.id,
                    payload={
                        "mechanism_type": mechanism_type,
                        "link_evidence_id": link_row.id,
                        "evidence_ids": mechanism["evidence_ids"][:32],
                        "static_only": True,
                        "report_ready": static_claim_ready,
                    },
                )
            # ``source_rows`` is intentionally bounded before a thread is
            # created. On a large PE, however, Ghidra's function contexts
            # can be written after thousands of import/Xref observations.
            # Do not let that prompt-oriented cap turn an API seed into an
            # API-only investigation: recover just the selected seed's
            # function-local closure from the immutable artifact ledger.
            # This is a precise, bounded lookup, not an artifact-wide
            # expansion for every thread.
            seed_context_pool = list(source_rows)
            if isinstance(selected_cluster, Mapping):
                cluster_source_ids = [
                    str(item)
                    for item in selected_cluster.get("evidence_ids", ())
                    if isinstance(item, (str, int)) and str(item).strip()
                ][:96]
                cluster_source_rows = (
                    list(
                        session.scalars(
                            select(Evidence).where(
                                Evidence.task_id == task.id,
                                Evidence.artifact_id == artifact.id,
                                Evidence.id.in_(cluster_source_ids),
                                Evidence.nature != "BACKGROUND_REPORTED",
                            )
                        )
                    )
                    if cluster_source_ids
                    else []
                )
                seed_api_symbols = {
                    symbol
                    for row in cluster_source_rows
                    for symbol in _evidence_api_symbols(row)
                }
                if seed_api_symbols:
                    function_context_rows = list(
                        session.scalars(
                            select(Evidence)
                            .where(
                                Evidence.task_id == task.id,
                                Evidence.artifact_id == artifact.id,
                                Evidence.kind == "function_context",
                                Evidence.nature != "BACKGROUND_REPORTED",
                            )
                            .order_by(Evidence.created_at, Evidence.id)
                        )
                    )
                    matched_context_rows = [
                        row
                        for row in function_context_rows
                        if _evidence_api_symbols(row) & seed_api_symbols
                    ][:24]
                    function_anchors = {
                        key
                        for row in matched_context_rows
                        for key in _evidence_anchor_keys(row)
                    }
                    if function_anchors:
                        # All of these kinds are function-scoped and are
                        # bounded by the recovered anchor set below. They
                        # supply the function, instruction, CFG and data
                        # facets that a deep-mining action can consume.
                        function_local_rows = list(
                            session.scalars(
                                select(Evidence)
                                .where(
                                    Evidence.task_id == task.id,
                                    Evidence.artifact_id == artifact.id,
                                    Evidence.kind.in_(
                                        {
                                            "function",
                                            "function_context",
                                            "function_instruction_window",
                                            "function_mechanism",
                                            "function_data_correlation",
                                            "cfg_block",
                                            "data_reference",
                                            "api_argument_trace",
                                        }
                                    ),
                                    Evidence.nature != "BACKGROUND_REPORTED",
                                )
                                .order_by(Evidence.created_at, Evidence.id)
                                .limit(4096)
                            )
                        )
                        seed_context_pool.extend(cluster_source_rows)
                        seed_context_pool.extend(matched_context_rows)
                        seed_context_pool.extend(
                            row
                            for row in function_local_rows
                            if _evidence_anchor_keys(row) & function_anchors
                        )
            seed_context_pool = list(
                {row.id: row for row in seed_context_pool}.values()
            )
            seed_context_pool.sort(
                key=lambda row: (
                    row.created_at.isoformat() if getattr(row, "created_at", None) else "",
                    row.id,
                )
            )
            seed_profile_rows = _seed_context_rows(seed_context_pool, selected_cluster)
            cluster_category = (
                str(selected_cluster.get("category") or "").strip()
                if isinstance(selected_cluster, Mapping)
                else ""
            )
            if cluster_category == "thread":
                body_candidates = list(
                    session.scalars(
                        select(Evidence)
                        .where(
                            *base_evidence_filter,
                            Evidence.kind.in_(
                                {
                                    "function_context",
                                    "function",
                                    "function_semantic_summary",
                                    "decompile_slice",
                                }
                            ),
                        )
                        .order_by(Evidence.created_at.asc(), Evidence.id)
                        .limit(host._CATALOG_HOW_SEED_SCAN_LIMIT)
                    )
                )
                unique_thread_rows = _select_unique_thread_seed_rows(host, 
                    [
                        *config_consumer_candidates,
                        *body_candidates,
                        *seed_profile_rows,
                    ],
                    limit=128,
                )
                if unique_thread_rows:
                    seed_profile_rows = unique_thread_rows
            elif cluster_category in _HOW_SEED_CATEGORIES:
                seed_profile_rows = _pin_config_consumer_seed_rows(
                    seed_profile_rows,
                    [*config_consumer_rows, *process_creation_rows, *http_transport_rows, *parent_attribute_rows, *dynamic_api_rows, *config_consumer_source_rows],
                )
            profile_rows = [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "nature": row.nature,
                    "value": row.value,
                    "anchor": row.anchor,
                }
                for row in seed_profile_rows
            ]
            # A thread's seed declares its semantic obligation. Do not
            # let broad, unrelated artifact evidence overwrite that
            # contract. Keyword supporting seeds must not best-match a
            # HOW playbook and inherit leftover TRACE.
            playbook = _seed_playbook(playbooks, selected_cluster)
            if (
                playbook is None
                and cluster_category in _HOW_SEED_CATEGORIES
                and cluster_category != "thread"
            ):
                playbook = playbooks.best_match(profile_rows)
            # Artifacts without a seed map still need evidence-driven
            # thread identity (PPID/decode). Persist HOW skip stays bound
            # to an explicit seed-map contract so API co-occurrence cannot
            # mint CANDIDATE.
            profile_playbook = playbook
            if profile_playbook is None and selected_cluster is None:
                profile_playbook = playbooks.best_match(profile_rows)
            # Real seed clusters already become threads. Do not fabricate a
            # sibling with empty evidence_ids (resolver-callers / generic
            # corroboration): it spends TRACE and never closes.
            profile_specs = {
                "dynamic-api-resolution": (
                    "Which statically resolved API path explains this artifact's dynamic loading behavior?",
                    "The artifact may resolve API addresses dynamically and route them into a loading or execution path.",
                    "dynamic_api_resolution",
                ),
                "xor-config-recovery": (
                    "Which bounded decode path explains the artifact's encoded configuration or payload?",
                    "The artifact may contain a recoverable XOR or encoded configuration used by a later mechanism.",
                    "decode_recovery",
                ),
                "ppid-process-chain": (
                    "Does the artifact construct a parent-process spoofing chain, and which evidence proves it?",
                    "The artifact may construct a child process with a spoofed parent identity through an attribute-list chain.",
                    "process_creation",
                ),
                "entrypoint-timeline": (
                    "What ordered static call and control-flow path begins at the entrypoint?",
                    "The artifact's entrypoint may lead into an ordered execution timeline that explains its primary behavior.",
                    "entrypoint_timeline",
                ),
                "http-download": (
                    "Which endpoint and transport call path receives response bytes?",
                    "The artifact may download data through a statically recoverable HTTP transport path.",
                    "network_download",
                ),
                "process-execution": (
                    "What command, flags, and input data reach the process creation API?",
                    "The artifact may construct a child process or command from statically traced inputs.",
                    "process_execution",
                ),
                "defender-modification": (
                    "Which Defender registry path, value name, and data reach the write operation?",
                    "The artifact may modify Defender configuration through a statically traced registry write.",
                    "defender_modification",
                ),
                "etw-patch": (
                    "Does a protection change target EtwEventWrite and write the expected patch bytes?",
                    "The artifact may patch ETW reporting through a statically traceable protection and byte-write path.",
                    "etw_patch",
                ),
                "scheduled-task-execution": (
                    "What scheduled-task command sequence is statically reconstructed?",
                    "The artifact may use a scheduled-task execution or fallback command sequence.",
                    "scheduled_task",
                ),
                "plugin-module-load": (
                    "Which module is loaded, initialized, used, and released?",
                    "The artifact may load a secondary module through a statically traceable lifecycle.",
                    "plugin_lifecycle",
                ),
                "entry-timeline-v2": (
                    "What ordered static path leaves the entrypoint and reaches a high-value mechanism?",
                    "The artifact entrypoint may lead into an ordered call path for a high-value mechanism.",
                    "entrypoint_timeline",
                ),
            }
            cluster_question = (
                str(selected_cluster.get("question", "")).strip()
                if selected_cluster is not None
                else ""
            )
            profile_spec = (
                profile_specs.get(profile_playbook.id) if profile_playbook is not None else None
            )
            if profile_spec is not None:
                default_question, default_statement, default_dimension = profile_spec
                # A seed-cluster question is the durable identity of this
                # thread.  Playbook templates only fill empty prompts; they
                # must not replace a later-pass cluster after the thread
                # has already left DISCOVERED.
                if not seed.get("question") and not cluster_question:
                    thread.question = default_question
                if not seed.get("hypothesis_statement"):
                    hypothesis.statement = default_statement
                hypothesis.dimension = default_dimension
                hypothesis.required_evidence = list(profile_playbook.required_evidence_kinds)
                thread.seed_kind = profile_playbook.id
            elif not seed.get("hypothesis_statement"):
                hypothesis.dimension = "mechanism_discovery"
                hypothesis.required_evidence = ["function_context", "function_call"]
            if selected_cluster is not None:
                if cluster_question:
                    thread.question = cluster_question
                category = str(selected_cluster.get("category", "generic"))
                if category != "generic" and profile_spec is None:
                    thread.seed_kind = f"seed-cluster:{category}"
                runtime_events.append(
                    {
                        "thread_id": thread.id,
                        "phase": "seed_cluster_selected",
                        "action_id": None,
                        "state": thread.state,
                        "evidence_ids": list(selected_cluster.get("evidence_ids", []))[:32],
                        "message": (
                            f"Selected {selected_cluster.get('id', 'seed cluster')} "
                                f"({category}) as the bounded investigation frontier."
                        ),
                    }
                )
            artifact_content: bytes | None = None
            content_blob = session.get(ContentBlob, artifact.content_sha256)
            if content_blob is not None and content_blob.disposed_at is None:
                try:
                    artifact_content = host.content_store.read(content_blob.storage_key)
                except (OSError, ValueError):
                    artifact_content = None
            pe_summary = next(
                (
                    row.value
                    for row in source_rows
                    if row.kind == "pe_structure" and isinstance(row.value, dict)
                ),
                {},
            )

            def execute(action: ActionSpec) -> list[dict[str, object]]:
                action_row = session.get(InvestigationActionRecord, action.id)
                action_provenance = dict(action.provenance or {})
                convergence_plan = action.plan.get("convergence", {})
                convergence_plan = (
                    dict(convergence_plan)
                    if isinstance(convergence_plan, Mapping)
                    else {}
                )
                action_origin = str(action_provenance.get("origin") or "").strip().casefold()
                if action_origin not in {"model", "human", "deterministic_fallback"}:
                    action_origin = (
                        "model" if action.planner_turn_id else "deterministic_fallback"
                    )
                if action.planner_turn_id:
                    action_provenance.setdefault("planner_turn_id", action.planner_turn_id)
                action_provenance.setdefault("origin", action_origin)
                if action_row is None:
                    action_row = InvestigationActionRecord(
                        id=action.id,
                        task_id=task.id,
                        thread_id=thread.id,
                        hypothesis_id=hypothesis.id,
                        artifact_id=artifact.id,
                        action_type=action.action_type.value,
                        reason=action.reason,
                        parameters={
                            **dict(action.parameters),
                            "origin": action_origin,
                            **({"_analysis_plan": dict(action.plan)} if action.plan else {}),
                            # Preserve the model's cited evidence on the
                            # durable action so queued/replayed execution
                            # retains the same authorization scope.
                            "_source_evidence_ids": list(action.source_evidence_ids),
                            **(
                                {"_planner_turn_id": action.planner_turn_id}
                                if action.planner_turn_id
                                else {}
                            ),
                            **(
                                {"_model_provenance": dict(action.provenance)}
                                if action.provenance
                                else {}
                            ),
                            **(
                                {"_convergence": convergence_plan}
                                if convergence_plan
                                else {}
                            ),
                        },
                        target_selector=dict(action.target_selector),
                        expected_evidence_kinds=list(action.expected_evidence_kinds),
                        success_condition=action.success_condition,
                        failure_interpretation=action.failure_interpretation.value,
                        cost_units=action.cost_units
                        or ActionCatalog.default().require(action.action_type).cost_units,
                        priority=action.priority,
                        depends_on=list(action.depends_on),
                    )
                    session.add(action_row)
                else:
                    # Workbench actions are inserted before this executor
                    # runs.  Merge the normalized metadata defensively so
                    # a replay cannot lose its planner correlation.
                    existing_parameters = dict(action_row.parameters or {})
                    existing_parameters.setdefault("origin", action_origin)
                    if action.plan:
                        existing_parameters.setdefault("_analysis_plan", dict(action.plan))
                    if action.planner_turn_id:
                        existing_parameters.setdefault(
                            "_planner_turn_id", action.planner_turn_id
                        )
                    if action.source_evidence_ids:
                        existing_parameters.setdefault(
                            "_source_evidence_ids", list(action.source_evidence_ids)
                        )
                    if convergence_plan:
                        existing_parameters.setdefault(
                            "_convergence", convergence_plan
                        )
                    if action_provenance:
                        existing_model_provenance = existing_parameters.get(
                            "_model_provenance", {}
                        )
                        if not isinstance(existing_model_provenance, Mapping):
                            existing_model_provenance = {}
                        existing_parameters["_model_provenance"] = {
                            **dict(action_provenance),
                            **dict(existing_model_provenance),
                        }
                    stored_plan = existing_parameters.get("_analysis_plan")
                    if isinstance(stored_plan, Mapping) and stored_plan:
                        merged_plan = {**dict(stored_plan), **dict(action.plan or {})}
                        if stored_plan.get("next_method_action_type") or stored_plan.get("next_method"):
                            merged_plan["next_method"] = (
                                stored_plan.get("next_method")
                                or stored_plan.get("next_method_action_type")
                            )
                            merged_plan["next_method_action_type"] = (
                                stored_plan.get("next_method_action_type")
                                or stored_plan.get("next_method")
                            )
                        action = replace(action, plan=merged_plan)
                    action_row.parameters = existing_parameters
                action_row.status = "RUNNING"
                action_row.attempts = int(action_row.attempts or 0) + 1
                frontier_before = _coordinator._convergence_frontier_fingerprint(
                    source_rows + execution_corpus
                )
                try:
                    # The investigation context above is deliberately
                    # bounded for planner prompts.  It must not become a
                    # correctness boundary for an approved action: a
                    # cited function may be outside that prompt window.
                    # Reload the cited rows and the bounded high-signal
                    # artifact-local corpus at execution time so targeted
                    # xref/decompile queries can recover their complete
                    # static context without crossing artifacts.
                    execution_rows = list(source_rows)
                    cited_ids = tuple(
                        dict.fromkeys(
                            str(item_id)
                            for item_id in action.source_evidence_ids
                            if str(item_id).strip()
                        )
                    )
                    if cited_ids:
                        cited_rows = list(
                            session.scalars(
                                select(Evidence).where(
                                    Evidence.task_id == task.id,
                                    Evidence.artifact_id == artifact.id,
                                    Evidence.id.in_(cited_ids),
                                    Evidence.nature != "BACKGROUND_REPORTED",
                                )
                            )
                        )
                        execution_rows.extend(cited_rows)
                    # Function-targeted actions need same-function context;
                    # API/xref actions need call-bearing rows. The shared
                    # corpus is already artifact-local and priority bounded.
                    execution_rows.extend(execution_corpus)
                    execution_rows = list({row.id: row for row in execution_rows}.values())
                    produced = _derive_investigation_observations(host, 
                        execution_rows,
                        action,
                        artifact_content=artifact_content,
                        pe_summary=pe_summary if isinstance(pe_summary, dict) else {},
                    )
                except Exception as exc:
                    convergence = _coordinator._convergence_failure_contract(host, 
                        action,
                        outcome="EXECUTOR_FAILURE",
                        frontier_before=frontier_before,
                        frontier_after=frontier_before,
                        existing_method_ids=(
                            convergence_plan.get("attempted_method_ids", [])
                            if isinstance(convergence_plan, Mapping)
                            else []
                        ),
                        error_type=type(exc).__name__,
                    )
                    action_row.status = "FAILED"
                    action_row.error = f"{type(exc).__name__}: {exc}"[:512]
                    action_row.parameters = {
                        **dict(action_row.parameters or {}),
                        "_convergence": convergence,
                        "_autopsy": no_new_evidence_autopsy(
                            {
                                "action_type": action.action_type.value,
                                "target_selector": dict(action.target_selector),
                                "target_artifact_id": artifact.id,
                                "artifact_boundary": artifact.id,
                                "dedupe_key": action.dedupe_key,
                                "source_evidence_ids": list(action.source_evidence_ids),
                                "tool_status": "FAILED",
                                "tool_error": type(exc).__name__,
                            }
                        ),
                    }
                    action_row.finished_at = utcnow()
                    host._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="investigation.action_failed",
                        actor="investigator",
                        object_type="InvestigationAction",
                        object_id=action.id,
                        payload={
                            "action_type": action.action_type.value,
                            "error_type": type(exc).__name__,
                            "origin": action_origin,
                            "planner_turn_id": action.planner_turn_id,
                            "model_call_id": action_provenance.get("model_call_id"),
                            "model_run_id": action_provenance.get("model_run_id"),
                            "provider": action_provenance.get("provider"),
                            "model": action_provenance.get("model"),
                        },
                    )
                    raise
                rows: list[dict[str, object]] = []
                evidence_ids: list[str] = []
                tool_run: ToolRun | None = None

                def _semantic_evidence_key(
                    kind: str,
                    nature: str,
                    value: object,
                    anchor: object,
                ) -> tuple[str, str, str, str]:
                    """Normalize one action output for artifact-local reuse.

                        Action/tool IDs and provenance envelopes describe *who*
                        produced an observation, not the observation itself.
                        They must not defeat reuse when two mechanism threads
                        ask the same bounded static query.  Keep the complete
                        semantic payload (including edge/call-site fields) so
                        distinct observations at one function remain separate.

                        The normalisation walks the whole payload, which is
                        expensive for multi-MB windows - but see the MEASURED NOTE
                        on `_strip_provenance`: removing the copy and serialising
                        the original directly measured 3-6x SLOWER, so the copy
                        stays.  The cost is the payload size, not the copy.
                        """

                    def digest(item: object) -> str:
                        return _provenance_free_digest(item)

                    return str(kind), str(nature), digest(value), digest(anchor)

                # Action scopes intentionally allow independent mechanism
                # questions to share a target.  Index prior investigation
                # outputs by semantic content so those scopes can reuse an
                # immutable Evidence row instead of appending duplicates.
                produced_kinds = {
                    str(item.get("kind", "investigation_observation"))
                    for item in produced
                }
                existing_semantic: dict[
                    tuple[str, str, str, str], Evidence
                ] = {}
                if produced_kinds:
                    for existing in session.scalars(
                        select(Evidence).where(
                            Evidence.task_id == task.id,
                            Evidence.artifact_id == artifact.id,
                            Evidence.module == "investigation",
                            Evidence.kind.in_(produced_kinds),
                        )
                    ):
                        existing_semantic.setdefault(
                            _semantic_evidence_key(
                                existing.kind,
                                existing.nature,
                                existing.value,
                                existing.anchor,
                            ),
                            existing,
                        )
                if produced:
                    tool_run = ToolRun(
                        id=new_id(),
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_name=f"investigation:{action.action_type.value.lower()}",
                        tool_version="1.0.0",
                        status="SUCCEEDED",
                        parameters={
                            "action_type": action.action_type.value,
                            "target_selector": dict(action.target_selector),
                            "source_evidence_ids": list(action.source_evidence_ids),
                            "expected_evidence_kinds": list(action.expected_evidence_kinds),
                            "success_condition": action.success_condition,
                            "failure_interpretation": action.failure_interpretation.value,
                            "dedupe_key": action.dedupe_key,
                            "scheduler": "investigation_loop",
                            "origin": action_origin,
                            "planner_turn_id": action.planner_turn_id,
                            "model_provenance": dict(action_provenance),
                        },
                        environment={
                            "sample_execution": False,
                            "network_access": False,
                            "executor": "static_evidence_query",
                            # This executor reads already-persisted Evidence
                            # rows only; it never opens or executes sample
                            # bytes.  The explicit boundary distinguishes
                            # it from worker-backed untrusted-data tools.
                            "isolation_boundary": "database_only_no_sample_execution",
                        },
                        output={"evidence_count": len(produced)},
                        started_at=utcnow(),
                        finished_at=utcnow(),
                    )
                    session.add(tool_run)
                    # Evidence stores a scalar foreign key to ToolRun,
                    # so SQLAlchemy cannot infer this dependency during
                    # an implicit flush triggered by the audit/index
                    # queries below. Persist the parent row immediately
                    # while selector indexing is deferred; the following
                    # evidence rows can then safely reference it on both
                    # SQLite and PostgreSQL.
                    prior_defer = session.info.get("defer_evidence_search_keys")
                    session.info["defer_evidence_search_keys"] = True
                    try:
                        session.flush(objects=[tool_run])
                    finally:
                        if prior_defer is None:
                            session.info.pop("defer_evidence_search_keys", None)
                        else:
                            session.info["defer_evidence_search_keys"] = prior_defer
                # Keep the new rows local to this action.  A full
                # session flush here re-walks every Evidence and audit
                # object accumulated by the investigation, turning a
                # long sample into an O(n^2) persistence path.
                new_evidence_rows: list[Evidence] = []
                for item in produced:
                    item_kind = str(item.get("kind", "investigation_observation"))
                    item_nature = str(item.get("nature", "STATIC_INFERRED"))
                    item_value = (
                        dict(item.get("value", {}))
                        if isinstance(item.get("value"), dict)
                        else {}
                    )
                    item_anchor = {
                        **(
                            dict(item.get("anchor", {}))
                            if isinstance(item.get("anchor"), dict)
                            else {}
                        ),
                        "artifact_id": artifact.id,
                        "logical_path": artifact.logical_path,
                        "content_sha256": artifact.content_sha256,
                        "investigation_action_id": action.id,
                        "origin": action_origin,
                        **(
                            {"planner_turn_id": action.planner_turn_id}
                            if action.planner_turn_id
                            else {}
                        ),
                        **(
                            {"model_call_id": action_provenance.get("model_call_id")}
                            if action_provenance.get("model_call_id")
                            else {}
                        ),
                    }
                    semantic_key = _semantic_evidence_key(
                        item_kind, item_nature, item_value, item_anchor
                    )
                    existing = existing_semantic.get(semantic_key)
                    if existing is not None:
                        # Reuse is explicit in the action trace.  The
                        # immutable row remains owned by its original
                        # tool-run/action while the current action gets a
                        # stable reference for verifier consumption.
                        evidence_ids.append(existing.id)
                        existing_id = str(existing.id)
                        if existing_id not in {str(row.id) for row in source_rows}:
                            source_rows.append(existing)
                        if existing_id not in {str(row.id) for row in execution_corpus}:
                            execution_corpus.append(existing)
                        rows.append(
                            {
                                "id": existing.id,
                                "kind": existing.kind,
                                "nature": existing.nature,
                                "value": existing.value,
                                "anchor": existing.anchor,
                                "reused": True,
                            }
                        )
                        host._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.evidence_reused",
                            actor="investigator",
                            object_type="Evidence",
                            object_id=existing.id,
                            payload={
                                "action_id": action.id,
                                "action_type": action.action_type.value,
                                "kind": existing.kind,
                                "evidence_ids": [existing.id],
                                "origin": action_origin,
                                "planner_turn_id": action.planner_turn_id,
                                "model_call_id": action_provenance.get("model_call_id"),
                            },
                        )
                        continue
                    evidence = Evidence(
                        id=new_id(),
                        task_id=task.id,
                        artifact_id=artifact.id,
                        tool_run_id=tool_run.id if tool_run is not None else action_row.id[:36],
                        module="investigation",
                        kind=item_kind,
                        nature=item_nature,
                        value=item_value,
                        anchor=item_anchor,
                    )
                    session.add(evidence)
                    new_evidence_rows.append(evidence)
                    existing_semantic[semantic_key] = evidence
                    source_rows.append(evidence)
                    execution_corpus.append(evidence)
                    rows.append(
                        {
                            "id": evidence.id,
                            "kind": evidence.kind,
                            "nature": evidence.nature,
                            "value": evidence.value,
                            "anchor": evidence.anchor,
                        }
                    )
                    evidence_ids.append(evidence.id)
                    host._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="investigation.evidence_observed",
                        actor="investigator",
                        object_type="Evidence",
                        object_id=evidence.id,
                        payload={
                            "action_id": action.id,
                            "action_type": action.action_type.value,
                            "kind": evidence.kind,
                            "evidence_ids": [evidence.id],
                            "origin": action_origin,
                            "planner_turn_id": action.planner_turn_id,
                            "model_call_id": action_provenance.get("model_call_id"),
                            "model_run_id": action_provenance.get("model_run_id"),
                            "provider": action_provenance.get("provider"),
                            "model": action_provenance.get("model"),
                        },
                    )
                if tool_run is not None:
                    tool_run.output = {
                        "evidence_count": len(
                            [item for item in rows if not item.get("reused")]
                        ),
                        "reused_evidence_count": len(
                            [item for item in rows if item.get("reused")]
                        ),
                        "result_evidence_count": len(evidence_ids),
                    }
                action_row.result_evidence_ids = evidence_ids
                action_row.finished_at = utcnow()
                frontier_after = _coordinator._convergence_frontier_fingerprint(
                    source_rows + execution_corpus
                )
                action_row.parameters = {
                    **dict(action_row.parameters or {}),
                    "_convergence": {
                        "attempt_id": action.id,
                        "method_id": _coordinator._convergence_method_id(
                            action.action_type,
                            action.target_selector,
                            action.plan,
                        ),
                        "frontier_fingerprint_before": frontier_before,
                        "frontier_fingerprint_after": frontier_after,
                        "evidence_delta": len(new_evidence_rows),
                        "gain_class": (
                            "EVIDENCE_GAIN"
                            if new_evidence_rows
                            else "REUSED_CONTEXT"
                            if evidence_ids
                            else "NO_NEW_EVIDENCE"
                        ),
                        "outcome": (
                            "EVIDENCE_GAIN"
                            if new_evidence_rows
                            else "REUSED_CONTEXT"
                            if evidence_ids
                            else "NO_NEW_EVIDENCE"
                        ),
                        "requires_alternate": False,
                        "alternate_of": convergence_plan.get("alternate_of"),
                    },
                }
                if evidence_ids:
                    action_row.status = "SUCCEEDED"
                    action_row.error = None
                    host._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="investigation.action_completed",
                        actor="investigator",
                        object_type="InvestigationAction",
                        object_id=action.id,
                        payload={
                            "action_type": action.action_type.value,
                            "evidence_count": len(evidence_ids),
                            "evidence_ids": evidence_ids[:32],
                            "origin": action_origin,
                            "planner_turn_id": action.planner_turn_id,
                            "model_call_id": action_provenance.get("model_call_id"),
                            "model_run_id": action_provenance.get("model_run_id"),
                            "provider": action_provenance.get("provider"),
                            "model": action_provenance.get("model"),
                        },
                    )
                else:
                    # A query that ran correctly but found no eligible
                    # static observation is not a successful experiment.
                    # Persist an explicit, non-refuting outcome so the
                    # scheduler, UI and evaluator cannot mistake it for a
                    # productive investigation step.
                    action_row.status = "FAILED"
                    action_row.error = "NO_NEW_EVIDENCE"
                    selector_values = {
                        str(value).casefold()
                        for value in dict(action.target_selector).values()
                        if isinstance(value, (str, int)) and str(value).strip()
                    }
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
                        "resource",
                        "payload",
                        "embedded",
                        "archive",
                        "staging",
                    }
                    target_found = bool(selector_values & wildcard_targets) or any(
                        any(
                            value
                            in host._investigation_value_text(
                                {"value": row.value, "anchor": row.anchor}
                            ).casefold()
                            for value in selector_values
                        )
                        for row in execution_rows
                    )
                    expected_kinds = {
                        str(kind).casefold()
                        for kind in action.expected_evidence_kinds
                        if str(kind).strip()
                    }
                    existing_ids = [
                        row.id
                        for row in execution_rows
                        if not expected_kinds or row.kind.casefold() in expected_kinds
                    ][:32]
                    autopsy = no_new_evidence_autopsy(
                        {
                            "action_type": action.action_type.value,
                            "target_selector": dict(action.target_selector),
                            "target_artifact_id": artifact.id,
                            "artifact_boundary": artifact.id,
                            "dedupe_key": action.dedupe_key,
                            "source_evidence_ids": list(action.source_evidence_ids),
                            "existing_evidence_ids": existing_ids,
                            "target_found": target_found,
                            "target_resolved": target_found,
                            "tool_status": "SUCCEEDED",
                            "failure_interpretation": action.failure_interpretation.value,
                            "static_only": True,
                        }
                    )
                    convergence = _coordinator._convergence_failure_contract(host, 
                        action,
                        outcome="NO_NEW_EVIDENCE",
                        frontier_before=frontier_before,
                        frontier_after=frontier_before,
                        existing_method_ids=(
                            convergence_plan.get("attempted_method_ids", [])
                            if isinstance(convergence_plan, Mapping)
                            else []
                        ),
                    )
                    action_row.parameters = {
                        **dict(action_row.parameters or {}),
                        "_convergence": convergence,
                        "_autopsy": autopsy,
                    }
                    host._audit(
                        session,
                        case_id=task.case_id,
                        task_id=task.id,
                        event_type="investigation.action_no_new_evidence",
                        actor="investigator",
                        object_type="InvestigationAction",
                        object_id=action.id,
                        payload={
                            "action_type": action.action_type.value,
                            "failure_interpretation": FailureInterpretation.NO_NEW_EVIDENCE.value,
                            "target_selector": dict(action.target_selector),
                            "origin": action_origin,
                            "planner_turn_id": action.planner_turn_id,
                            "model_call_id": action_provenance.get("model_call_id"),
                            "model_run_id": action_provenance.get("model_run_id"),
                            "provider": action_provenance.get("provider"),
                            "model": action_provenance.get("model"),
                            **autopsy,
                        },
                    )
                # Flush only this action's durable rows. Audit events are
                # intentionally left in the outer transaction so the
                # append-only chain is committed atomically at the end.
                # Evidence stores a scalar ToolRun foreign key (rather
                # than an ORM relationship), so SQLAlchemy cannot infer
                # the dependency when all rows are passed to one partial
                # flush. Flush the ToolRun first, with selector indexing
                # deferred while Evidence is still pending, then flush
                # the action and its Evidence. This keeps the transaction
                # valid on SQLite as well as PostgreSQL and avoids the
                # accumulated-ledger O(n^2) full flush.
                if tool_run is not None:
                    prior_defer = session.info.get("defer_evidence_search_keys")
                    session.info["defer_evidence_search_keys"] = True
                    try:
                        session.flush(objects=[tool_run])
                    finally:
                        if prior_defer is None:
                            session.info.pop("defer_evidence_search_keys", None)
                        else:
                            session.info["defer_evidence_search_keys"] = prior_defer
                local_flush_rows: list[object] = [action_row]
                local_flush_rows.extend(new_evidence_rows)
                # ``_audit`` appends immutable events and updates the
                # in-memory chain head. Include only those pending/dirty
                # bookkeeping rows in this boundary; otherwise the next
                # SELECT would trigger an implicit flush of an unrelated
                # action and turn a recoverable executor error into a
                # failed outer transaction.
                local_flush_rows.extend(
                    row
                    for row in session.new
                    if isinstance(row, (AuditEvent, AuditChainHead))
                )
                local_flush_rows.extend(
                    row
                    for row in session.dirty
                    if isinstance(row, (AuditChainHead, InvestigationActionRecord))
                    and row not in local_flush_rows
                )
                session.flush(objects=local_flush_rows)
                return rows

            # Investigation starts from the selected mechanism question,
            # not from the entire artifact. Actions can still query the
            # bounded artifact-local execution corpus, but their initial
            # hypothesis and verifier evidence remain seed-scoped.
            initial = profile_rows
            proposed_actions: list[ActionSpec] = []
            dynamic_plan = (task.strategy_snapshot or {}).get("dynamic_planning", {})
            raw_model_actions: list[object] = []
            if isinstance(dynamic_plan, dict):
                raw_model_actions.extend(dynamic_plan.get("action_history", []))
                raw_model_actions.extend(dynamic_plan.get("actions", []))
            # Action history is durable across planner turns and service
            # invocations.  A no-gain query is terminal for the current
            # selector: replaying it on every invocation creates an
            # unbounded action storm.  K01 allows one different-family
            # alternate, not a retry of the same method because unrelated
            # Evidence arrived later.
            seen_model_action_keys: set[str] = set()
            existing_action_rows = list(
                session.scalars(
                    select(InvestigationActionRecord).where(
                        InvestigationActionRecord.task_id == task.id,
                        InvestigationActionRecord.artifact_id == artifact.id,
                    )
                )
            )
            # Seed the in-memory loop with durable action keys.  This is
            # especially important when one artifact has several seed
            # clusters: each subsequent thread must advance to a new
            # target rather than replaying the first thread's queries.
            initial_scheduled_keys: set[str] = set(
                artifact_frontier_keys.setdefault(artifact.id, set())
            )
            for existing_action in existing_action_rows:
                if not existing_action.action_type or not existing_action.target_selector:
                    continue
                existing_parameters = dict(existing_action.parameters or {})
                existing_plan = existing_parameters.get("_analysis_plan", {})
                keys = _investigation_scheduled_keys(
                    str(existing_action.action_type),
                    dict(existing_action.target_selector or {}),
                    existing_plan if isinstance(existing_plan, Mapping) else None,
                )
                if existing_action.status in {"SUCCEEDED", "RUNNING"}:
                    seen_model_action_keys.update(keys)
                    initial_scheduled_keys.update(keys)
                    continue
                if (
                    existing_action.status == "FAILED"
                    and existing_action.error == "NO_NEW_EVIDENCE"
                ):
                    # Same method + selector is terminal for this frontier.
                    # A later unrelated Evidence timestamp is not a new
                    # input.  K01 materializes at most one different-family
                    # alternate below; do not replay the failed query.
                    seen_model_action_keys.update(keys)
                    initial_scheduled_keys.update(keys)
                elif existing_action.status == "FAILED":
                    # A tool exception is a bounded static boundary for
                    # this evidence frontier.  Retrying it on every task
                    # invocation would starve later high-value targets and
                    # create an unbounded failure storm.  Keep the failed
                    # action visible for audit/coverage, but advance the
                    # frontier; a new planner turn may explicitly propose
                    # a different complementary action.
                    seen_model_action_keys.update(keys)
                    initial_scheduled_keys.update(keys)
            # Carry durable keys forward for subsequent seed threads in
            # this invocation.  ``existing_action_rows`` may include
            # queued work from a prior planner turn; reserving it here is
            # safe because the current thread's queued rows are handled
            # separately below, while sibling threads must not duplicate
            # their selectors.
            artifact_frontier_keys[artifact.id].update(initial_scheduled_keys)
            # Apply the same reservation to model/Workbench proposals.
            # This avoids constructing a queued duplicate only to have
            # the driver discard it at execution time.
            seen_model_action_keys.update(initial_scheduled_keys)
            # DSH/human proposals are persisted before execution. Feed
            # only queued, task-owned catalog actions into this loop; the
            # normal executor and verifier remain authoritative.
            # A failed/no-gain action carries an append-only convergence
            # contract. Materialize at most one different-method probe on
            # the next bounded pass so failure cannot silently become a
            # static conclusion.
            convergence_alternates: list[ActionSpec] = []
            for failed_action in existing_action_rows:
                if failed_action.status not in {"FAILED", "TIMED_OUT", "CANCELLED"}:
                    continue
                if str(failed_action.thread_id) != str(thread.id):
                    continue
                alternate = _coordinator._build_convergence_alternate(host, 
                    original=failed_action,
                    thread_id=str(failed_action.thread_id or thread.id),
                    hypothesis_id=str(failed_action.hypothesis_id or hypothesis.id),
                    artifact_id=str(failed_action.artifact_id or artifact.id),
                )
                if alternate is None or alternate.dedupe_key in seen_model_action_keys:
                    continue
                seen_model_action_keys.add(alternate.dedupe_key)
                convergence_alternates.append(alternate)
            proposed_actions.extend(convergence_alternates)
            queued_rows = list(
                session.scalars(
                    select(InvestigationActionRecord).where(
                        InvestigationActionRecord.task_id == task.id,
                        InvestigationActionRecord.artifact_id == artifact.id,
                        InvestigationActionRecord.status == "QUEUED",
                    )
                )
            )
            model_specs: list[tuple[ActionSpec, tuple[str, ...], int]] = []
            for queued in queued_rows:
                try:
                    queued_type = ActionType(queued.action_type)
                    queued_failure = FailureInterpretation(queued.failure_interpretation)
                except ValueError:
                    queued.status = "FAILED"
                    queued.error = "ACTION_CATALOG_MISMATCH"
                    continue
                queued_parameters = dict(queued.parameters or {})
                queued_plan = queued_parameters.get("_analysis_plan", {})
                queued_key = _scoped_investigation_action_key(
                    queued_type.value,
                    dict(queued.target_selector or {}),
                    queued_plan if isinstance(queued_plan, Mapping) else None,
                )
                if queued_key in seen_model_action_keys:
                    continue
                seen_model_action_keys.add(queued_key)
                queued_provenance = queued_parameters.get("_model_provenance", {})
                if not isinstance(queued_provenance, Mapping):
                    queued_provenance = {}
                queued_source_evidence_ids = queued_parameters.get("_source_evidence_ids", [])
                if not isinstance(queued_source_evidence_ids, (list, tuple, set)):
                    queued_source_evidence_ids = []
                if not isinstance(queued_plan, Mapping):
                    queued_plan = {}
                queued_dependency_value = queued.depends_on
                if not isinstance(queued_dependency_value, (list, tuple, set)):
                    queued_dependency_value = []
                queued_planner_turn_id = queued_parameters.get("_planner_turn_id")
                queued_planner_turn_id = (
                    str(queued_planner_turn_id).strip()[:200]
                    if isinstance(queued_planner_turn_id, (str, int))
                    and str(queued_planner_turn_id).strip()
                    else None
                )
                queued_spec = ActionSpec(
                        id=queued.id,
                        action_type=queued_type,
                        thread_id=thread.id,
                        hypothesis_id=hypothesis.id,
                        artifact_id=artifact.id,
                        priority=queued.priority,
                        reason=queued.reason,
                        # Only catalog selector fields enter the executor;
                        # provenance remains on the immutable action row.
                        parameters=dict(queued.target_selector or {}),
                        target_selector=dict(queued.target_selector or {}),
                        expected_evidence_kinds=tuple(queued.expected_evidence_kinds or ()),
                        success_condition=queued.success_condition,
                        failure_interpretation=queued_failure,
                        cost_units=queued.cost_units,
                        source_evidence_ids=tuple(
                            str(item)
                            for item in queued_source_evidence_ids
                            if isinstance(item, (str, int)) and str(item).strip()
                        )[:32],
                        planner_turn_id=queued_planner_turn_id,
                        provenance=dict(queued_provenance),
                        plan=dict(queued_plan),
                        depends_on=tuple(
                            str(item).strip()
                            for item in queued_dependency_value
                            if isinstance(item, (str, int)) and str(item).strip()
                        )[:32],
                    )
                proposed_actions.append(queued_spec)
                model_specs.append(
                    (
                        queued_spec,
                        tuple(
                            str(item).strip()
                            for item in queued_dependency_value
                            if isinstance(item, (str, int)) and str(item).strip()
                        )[:32],
                        -(len(model_specs) + 1),
                    )
                )
            for raw_index, raw_action in enumerate(raw_model_actions):
                if (
                    not isinstance(raw_action, dict)
                    or raw_action.get("target_artifact_id") != artifact.id
                ):
                    continue
                raw_type = raw_action.get("action_type")
                if not raw_type:
                    continue
                try:
                    action_type = ActionType(str(raw_type))
                except ValueError:
                    continue
                try:
                    failure_interpretation = FailureInterpretation(
                        str(raw_action.get("failure_interpretation", "UNKNOWN"))
                    )
                except ValueError:
                    continue
                raw_parameters = raw_action.get("parameters", {})
                if not isinstance(raw_parameters, dict):
                    raw_parameters = {}
                raw_selector = raw_action.get("target_selector", {})
                if not isinstance(raw_selector, dict):
                    raw_selector = {}
                if not raw_selector:
                    raw_selector = {
                        key: value
                        for key, value in raw_parameters.items()
                        if key
                        in {
                            "target",
                            "api",
                            "function",
                            "function_entry",
                            "entry",
                            "rva",
                            "address",
                        }
                        and isinstance(value, (str, int))
                        and str(value).strip()
                    }
                if not raw_selector or set(raw_selector) - {
                    "target",
                    "api",
                    "function",
                    "function_entry",
                    "entry",
                    "rva",
                    "address",
                }:
                    continue
                raw_expected = raw_action.get("expected_evidence_kinds", [])
                if not isinstance(raw_expected, list) or not raw_expected:
                    raw_expected = raw_action.get("expected_evidence", [])
                if not isinstance(raw_expected, list):
                    raw_expected = []
                if not any(isinstance(item, str) and item.strip() for item in raw_expected):
                    # An incomplete model action must not abort the task;
                    # deterministic playbooks will schedule the next step.
                    continue
                action_key = _scoped_investigation_action_key(
                    str(raw_type),
                    raw_selector,
                    raw_action,
                )
                if action_key in seen_model_action_keys:
                    continue
                seen_model_action_keys.add(action_key)
                action_spec = ActionSpec(
                        # A semantic, stable ID lets later model actions
                        # depend on an earlier action across planner turns
                        # without relying on list position.
                        id=(
                            f"{thread.id}:model:{hashlib.sha256(host._canonical_json({
                                'artifact_id': artifact.id,
                                'action_type': action_type.value,
                                'target_selector': raw_selector,
                                'expected_evidence_kinds': [str(item) for item in raw_expected if isinstance(item, str)],
                            }).encode('utf-8')).hexdigest()[:24]}"
                        ),
                        action_type=action_type,
                        thread_id=thread.id,
                        hypothesis_id=hypothesis.id,
                        artifact_id=artifact.id,
                        priority=int(raw_action.get("priority", 25)),
                        reason=str(
                            raw_action.get("reason", "model-proposed investigation action")
                        ),
                        parameters=raw_selector,
                        target_selector=raw_selector,
                        expected_evidence_kinds=tuple(
                            str(item)
                            for item in raw_expected
                            if isinstance(item, str) and item.strip()
                        )[:32],
                        success_condition=str(
                            raw_action.get("success_condition", "new_targeted_evidence")
                        )[:160],
                        failure_interpretation=failure_interpretation,
                        cost_units=ActionCatalog.default().require(action_type).cost_units,
                        source_evidence_ids=tuple(
                            str(item)
                            for item in raw_action.get("evidence_ids", [])
                            if isinstance(item, (str, int)) and str(item).strip()
                        )[:32],
                        planner_turn_id=(
                            str(raw_action.get("planner_turn_id"))
                            if raw_action.get("planner_turn_id")
                            else None
                        ),
                        provenance={
                            key: raw_action.get(key)
                            for key in (
                                "prompt_sha256",
                                "profile_digest",
                                "policy_digest",
                                "action_validation_digest",
                                "action_validation",
                            )
                            if raw_action.get(key) is not None
                        },
                        plan=_coordinator._model_action_plan(raw_action),
                    )
                proposed_actions.append(action_spec)
                raw_dependency_value = raw_action.get("depends_on", [])
                if not isinstance(raw_dependency_value, (list, tuple, set)):
                    raw_dependency_value = []
                raw_dependencies = tuple(
                    str(item).strip()
                    for item in raw_dependency_value
                    if isinstance(item, (str, int)) and str(item).strip()
                )[:32]
                model_specs.append((action_spec, raw_dependencies, raw_index))

            # Resolve model dependency references only to actions that are
            # actually present in this artifact-local frontier.  The model
            # may name an exact action ID, an accepted-plan index, a
            # semantic dedupe key, or an action type when that type is
            # unambiguous.  Unknown references are retained as audit
            # metadata but never reach the queue, avoiding a deadlock on a
            # dependency that cannot possibly complete.
            if model_specs:
                by_id = {
                    item.id: item.id
                    for item, _deps, _idx in model_specs
                }
                by_id.update(
                    {
                        row.id: row.id
                        for row in queued_rows
                        if row.id
                    }
                )
                by_index = {idx: item.id for item, _deps, idx in model_specs}
                by_key = {
                    item.dedupe_key: item.id
                    for item, _deps, _idx in model_specs
                }
                by_key.update(
                    {
                        _scoped_investigation_action_key(
                            str(row.action_type),
                            dict(row.target_selector or {}),
                            (
                                dict(row.parameters or {}).get("_analysis_plan", {})
                                if isinstance(dict(row.parameters or {}).get("_analysis_plan", {}), Mapping)
                                else None
                            ),
                        ): row.id
                        for row in queued_rows
                        if row.id and row.action_type
                    }
                )
                by_type: dict[str, list[str]] = {}
                for item, _deps, _idx in model_specs:
                    by_type.setdefault(item.action_type.value, []).append(item.id)
                for item, raw_dependencies, _raw_index in model_specs:
                    resolved: list[str] = []
                    unresolved: list[str] = []
                    for dependency in raw_dependencies:
                        candidate = by_id.get(dependency) or by_key.get(dependency)
                        if candidate is None:
                            index_text = dependency.removeprefix("action:").removeprefix("index:")
                            if index_text.isdigit():
                                candidate = by_index.get(int(index_text))
                        if candidate is None and len(by_type.get(dependency.upper(), ())) == 1:
                            candidate = by_type[dependency.upper()][0]
                        if candidate is None or candidate == item.id:
                            unresolved.append(dependency)
                        else:
                            resolved.append(candidate)
                    updated_plan = dict(item.plan)
                    if raw_dependencies:
                        updated_plan["depends_on"] = resolved
                        if unresolved:
                            updated_plan["unresolved_dependencies"] = unresolved
                            host._audit(
                                session,
                                case_id=task.case_id,
                                task_id=task.id,
                                event_type="investigation.dependency_unresolved",
                                actor="analysis-planner-agent",
                                object_type="InvestigationAction",
                                object_id=item.id,
                                payload={
                                    "dependencies": unresolved,
                                    "action_type": item.action_type.value,
                                    "target_selector": dict(item.target_selector),
                                },
                            )
                    replacement = replace(
                        item,
                        depends_on=tuple(dict.fromkeys(resolved)),
                        plan=updated_plan,
                    )
                    position = next(
                        index for index, candidate in enumerate(proposed_actions)
                        if candidate.id == item.id
                    )
                    proposed_actions[position] = replacement
            # Depth is driven by the configured investigation budget alone.
            # ``max_sample_files`` used to clip this as ``max(8, files // 2)``:
            # a sample-*count* setting deciding how many actions one
            # investigation round may run, so a 551KB PE with 703 recovered
            # functions was governed by an unrelated intake limit.  The floor
            # of 1 is the degenerate-input guard for the division below.
            investigation_step_budget = max(
                1, int(host.settings.investigation_max_steps)
            )
            work_ledger = begin_item(work_ledger, thread.id)
            # Kunglao leftover remainder / cost-is-noise: DSH-owned
            # planning queues TRACE before this loop. Persist HOW skip
            # must still fire; queued GET_CALLEES cannot invent
            # module_input or 0x09080008, and it burns the 64-action cap.
            persist_how = resolve_persist_how_skip(
                playbook=playbook,
                evidence=initial,
                thread_id=thread.id,
                artifact_id=artifact_id_value,
                cluster_category=cluster_category,
                model_actions_only=model_actions_only,
                proposed_actions=proposed_actions,
                historical_attempts=historical_attempts.get(str(thread.id), 0),
                seed_result=host._persist_time_seed_result,
                static_boundary=host._persist_time_static_boundary,
                unique_thread=host._persist_time_unique_thread_result,
                supporting_boundary=host._supporting_seed_static_boundary,
            )
            playbook = persist_how.playbook
            loop_path = next_investigation_loop_path(
                persist_how,
                budget_exhausted=budget_exhausted,
            )
            if loop_path == LOOP_PATH_PERSIST_READY:
                result = persist_how.result
                host._supersede_queued_trace_after_persist_skip(
                    queued_rows,
                    thread_id=thread.id,
                )
                emu_actions = list(
                    host._keep_emulation_after_persist_skip(proposed_actions)
                )
                persist_emu = host._persist_ready_emulation_actions(
                    evidence=initial,
                    thread_id=thread.id,
                    hypothesis_id=hypothesis.id,
                    artifact_id=artifact_id_value,
                    scheduled_keys=initial_scheduled_keys,
                )
                seen_emu = {item.dedupe_key for item in emu_actions}
                for item in persist_emu:
                    if item.dedupe_key in seen_emu:
                        continue
                    seen_emu.add(item.dedupe_key)
                    emu_actions.append(item)
                if emu_actions:
                    emu_result = InvestigationLoopDriver(
                        max_steps=max(1, len(emu_actions)),
                    ).run_until_converged(
                        thread_id=thread.id,
                        artifact_id=artifact_id_value,
                        question=thread.question,
                        hypothesis_id=hypothesis.id,
                        hypothesis_statement=hypothesis.statement,
                        initial_evidence=initial,
                        execute=execute,
                        proposed_actions=list(emu_actions),
                        initial_scheduled=initial_scheduled_keys,
                        allow_investigator_actions=False,
                        should_stop=(
                            (lambda: host._is_task_cancelled(task.id))
                            if cancellation_probe_enabled
                            else None
                        ),
                        max_rounds=1,
                        max_total_steps=max(1, len(emu_actions)),
                        initial_completed_action_ids=(
                            row.id
                            for row in existing_action_rows
                            if row.status == "SUCCEEDED"
                        ),
                    )
                    result = replace(
                        result,
                        evidence=tuple((*result.evidence, *emu_result.evidence)),
                        actions=tuple((*result.actions, *emu_result.actions)),
                        events=tuple((*result.events, *emu_result.events)),
                    )
            elif loop_path == LOOP_PATH_PERSIST_BOUNDARY:
                result = persist_how.result
                host._supersede_queued_trace_after_persist_skip(
                    queued_rows,
                    thread_id=thread.id,
                )
                recovery_actions = list(
                    host._keep_emulation_after_persist_skip(proposed_actions)
                )
                if recovery_actions:
                    recovery_result = InvestigationLoopDriver(
                        max_steps=max(1, len(recovery_actions)),
                    ).run_until_converged(
                        thread_id=thread.id,
                        artifact_id=artifact_id_value,
                        question=thread.question,
                        hypothesis_id=hypothesis.id,
                        hypothesis_statement=hypothesis.statement,
                        initial_evidence=initial,
                        execute=execute,
                        proposed_actions=list(recovery_actions),
                        initial_scheduled=initial_scheduled_keys,
                        allow_investigator_actions=False,
                        should_stop=(
                            (lambda: host._is_task_cancelled(task.id))
                            if cancellation_probe_enabled
                            else None
                        ),
                        max_rounds=1,
                        max_total_steps=max(1, len(recovery_actions)),
                        initial_completed_action_ids=(
                            row.id
                            for row in existing_action_rows
                            if row.status == "SUCCEEDED"
                        ),
                    )
                    result = replace(
                        result,
                        evidence=tuple((*result.evidence, *recovery_result.evidence)),
                        actions=tuple((*result.actions, *recovery_result.actions)),
                        events=tuple((*result.events, *recovery_result.events)),
                    )
            elif loop_path == LOOP_PATH_BUDGET_DEFER:
                deferred_item = {
                    "artifact_id": artifact_id_value,
                    "artifact_path": artifact_path_value,
                    "thread_id": thread.id,
                    "question": thread.question,
                    "seed_kind": thread.seed_kind,
                    "reason": "INVESTIGATION_BUDGET_EXHAUSTED",
                    "budget_used": task_action_budget_used,
                    "budget_limit": task_action_budget_limit,
                }
                record_deferred_frontier(deferred_item)
                work_ledger = defer_item(
                    work_ledger,
                    thread.id,
                    reason="INVESTIGATION_BUDGET_EXHAUSTED",
                )
                if budget_limitation not in limitations:
                    limitations.append(budget_limitation)
                if thread.state not in {
                    InvestigationThreadState.CLAIM_READY.value,
                    InvestigationThreadState.CLOSED.value,
                }:
                    playbook_id = str(getattr(playbook, "id", "") or "")
                    thread.state = (
                        InvestigationThreadState.UNKNOWN.value
                        if playbook_id in host._HOW_PLAYBOOK_IDS
                        else InvestigationThreadState.BLOCKED.value
                    )
                runtime_events.append(
                    {
                        "thread_id": thread.id,
                        "phase": "budget_deferred",
                        "action_id": None,
                        "state": thread.state,
                        "evidence_ids": [],
                        "message": (
                            "Task-level investigation action budget exhausted; "
                                "seed frontier deferred for a later bounded pass."
                        ),
                    }
                )
                continue
            else:
                # A single driver round is intentionally bounded, but the
                # service must not mistake that per-round budget for the
                # complete investigation frontier.  Estimate the currently
                # admitted deterministic planner frontier from this thread's
                # bounded context and grant enough continuation rounds to
                # consume it.  Keep the configured round budget as the floor
                # and the validated eight-round ceiling as the safety bound;
                # model-only turns remain deliberately single-pass below.
                investigation_round_budget = host.settings.investigation_max_rounds
                if not model_actions_only:
                    planner_frontier = DeepMiningPlanner.plan_actions(
                        initial,
                        scheduled=set(initial_scheduled_keys),
                        max_actions=32,
                    )
                    frontier_size = max(len(planner_frontier), len(proposed_actions))
                    if frontier_size:
                        required_rounds = (
                            frontier_size + investigation_step_budget - 1
                        ) // investigation_step_budget
                        investigation_round_budget = max(
                            investigation_round_budget,
                            min(8, required_rounds),
                        )
                result = InvestigationLoopDriver(
                    max_steps=investigation_step_budget
                ).run_until_converged(
                    thread_id=thread.id,
                    artifact_id=artifact_id_value,
                    question=thread.question,
                    hypothesis_id=hypothesis.id,
                    hypothesis_statement=hypothesis.statement,
                    initial_evidence=initial,
                    execute=execute,
                    proposed_actions=proposed_actions,
                    initial_scheduled=initial_scheduled_keys,
                    allow_investigator_actions=not model_actions_only,
                    should_stop=(
                        (lambda: host._is_task_cancelled(task.id))
                        if cancellation_probe_enabled
                        else None
                    ),
                    max_rounds=(
                        1 if model_actions_only else investigation_round_budget
                    ),
                    # A seed thread works until its own frontier is
                    # exhausted or the invocation's action budget runs out.
                    # The former per-slot TRACE total (8; see
                    # investigation_seed_step_budget and
                    # _PER_SLOT_TRACE_CAP) clipped every seeded thread to
                    # eight actions no matter how large the configured
                    # investigation budget was, so raising
                    # investigation_max_steps alone could not deepen
                    # anything.  Keeping the slot cap at 0 leaves only the
                    # shared invocation bound; depth is decided by the
                    # frontier.
                    max_total_steps=max(1, investigation_seed_step_budget(
                        remaining=task_action_budget_limit - task_action_budget_used,
                        slot_cap=0,
                    )),
                    initial_completed_action_ids=(
                        row.id for row in existing_action_rows if row.status == "SUCCEEDED"
                    ),
                )
                result = _apply_seed_playbook_gate(host, result, playbook)
            attempted_result_ids = {
                item.action_id
                for item in result.events
                if item.action_id
                and item.phase
                in {
                    "action_completed",
                    "action_failed",
                    "no_new_evidence",
                    "no_new_evidence_autopsy",
                }
            }
            task_action_budget_used += investigation_budget_charged_action_count(
                attempted_ids=attempted_result_ids,
                actions=result.actions,
                evidence=result.evidence,
            )
            pending_result_actions = [
                item
                for item in result.actions
                if item.id not in attempted_result_ids
            ]
            completed_action_ids = {
                row.id for row in existing_action_rows if row.status == "SUCCEEDED"
            } | {
                event.action_id for event in result.events if event.phase == "action_completed"
            }
            for pending_action in pending_result_actions:
                unresolved_dependencies = [
                    dep for dep in pending_action.depends_on if dep not in completed_action_ids
                ]
                pending_reason = (
                    "INVESTIGATION_DEPENDENCY_BLOCKED" if unresolved_dependencies
                    else "INVESTIGATION_BUDGET_EXHAUSTED"
                    if any(event.phase == "budget_exhausted" for event in result.events)
                    else "INVESTIGATION_ROUND_LIMIT"
                )
                record_deferred_frontier(
                    {
                        "artifact_id": artifact_id_value,
                        "artifact_path": artifact_path_value,
                        "thread_id": thread.id,
                        "action_id": pending_action.id,
                        "action_type": pending_action.action_type.value,
                        "question": thread.question,
                        "seed_kind": thread.seed_kind,
                        "target_selector": dict(pending_action.target_selector),
                        "source_evidence_ids": list(pending_action.source_evidence_ids),
                        "expected_evidence_kinds": list(
                            pending_action.expected_evidence_kinds
                        ),
                        "reason": pending_reason,
                        "unresolved_dependencies": unresolved_dependencies,
                        "status": "DEFERRED",
                        "resumption": "replan_or_explicit_resume_required",
                        "budget_used": task_action_budget_used,
                        "budget_limit": task_action_budget_limit,
                    }
                )
            if any(item.phase == "budget_exhausted" for item in result.events):
                if budget_limitation not in limitations:
                    limitations.append(budget_limitation)
                record_deferred_frontier(
                    {
                        "artifact_id": artifact_id_value,
                        "artifact_path": artifact_path_value,
                        "thread_id": thread.id,
                        "question": thread.question,
                        "seed_kind": thread.seed_kind,
                        "reason": "INVESTIGATION_BUDGET_EXHAUSTED",
                        "budget_used": task_action_budget_used,
                        "budget_limit": task_action_budget_limit,
                    }
                )
            # Unexecuted proposals must not suppress useful work in a
            # sibling seed; only attempted selectors reserve capacity.
            artifact_frontier_keys[artifact_id_value].update(
                item.dedupe_key for item in result.actions if item.id in attempted_result_ids
            )
            thread.state = result.thread_state.value
            attempted_names = completed_investigation_methods(
                result.actions, result.evidence
            )
            last_action_type = (
                result.actions[-1].action_type
                if result.actions
                else ActionType.GET_FUNCTION
            )
            next_method = investigation_next_method(last_action_type, attempted_names)
            playbook_type = str(getattr(playbook, "mechanism_type", "") or "")
            recovery: tuple[str, ...] = ()
            if playbook_type:
                recovery = recovery_actions_for_gap(
                    playbook_type,
                    getattr(result.gate, "missing", ()) or (),
                    attempted=attempted_names,
                    evidence=result.evidence,
                )
                if recovery:
                    next_method = recovery[0]
            evidence_ids = [
                str(item.get("id")) for item in result.evidence if item.get("id")
            ]
            action_ids = [item.id for item in result.actions]
            persist_boundary_event = any(
                item.phase == "persist_time_static_boundary" for item in result.events
            )
            persist_claim_event = any(
                item.phase == "persist_time_claim_ready" for item in result.events
            )
            ready_states = {
                InvestigationThreadState.CLAIM_READY.value,
                InvestigationThreadState.CLOSED.value,
            }

            def park_unfinished(*, reason: str, method: str) -> None:
                nonlocal work_ledger
                disposition, parked = how_timebox_disposition(
                    method,
                    attempted=attempted_names,
                    evidence=result.evidence,
                )
                if disposition == "defer":
                    work_ledger = defer_item(
                        work_ledger,
                        thread.id,
                        reason=reason,
                        next_method=parked,
                    )
                    if thread.state not in ready_states:
                        thread.state = InvestigationThreadState.BLOCKED.value
                else:
                    work_ledger = terminate_item(
                        work_ledger,
                        thread.id,
                        LEDGER_UNKNOWN,
                        reason=reason,
                        next_method=parked,
                        evidence_ids=evidence_ids,
                        action_ids=action_ids,
                    )
                    if thread.state not in ready_states:
                        thread.state = InvestigationThreadState.UNKNOWN.value

            if result.thread_state == InvestigationThreadState.CLAIM_READY:
                if persist_claim_event and recovery:
                    park_unfinished(reason="TIMEBOX", method=recovery[0])
                else:
                    work_ledger = close_item(
                        work_ledger,
                        thread.id,
                        evidence_ids=evidence_ids,
                        claim_ids=list(result.gate.evidence_ids),
                        action_ids=action_ids,
                    )
            elif persist_boundary_event:
                if recovery:
                    park_unfinished(reason="TIMEBOX", method=recovery[0])
                else:
                    work_ledger = terminate_item(
                        work_ledger,
                        thread.id,
                        LEDGER_UNKNOWN,
                        reason=str(result.gate.reason or "STATIC_BOUNDARY"),
                        next_method="STATIC_BOUNDARY",
                        evidence_ids=evidence_ids,
                        action_ids=action_ids,
                    )
            elif model_actions_only:
                work_ledger = attach_results(
                    work_ledger,
                    thread.id,
                    evidence_ids=evidence_ids,
                    action_ids=action_ids,
                )
            elif ledger_phase == "tail":
                park_unfinished(
                    reason=str(result.gate.reason or result.thread_state.value),
                    method=next_method,
                )
            elif next_method in {"", "STATIC_BOUNDARY"}:
                park_unfinished(
                    reason=str(result.gate.reason or "STATIC_BOUNDARY"),
                    method=next_method or "STATIC_BOUNDARY",
                )
            else:
                park_unfinished(reason="TIMEBOX", method=next_method)
            thread.evidence_ids = [
                str(item.get("id")) for item in result.evidence if item.get("id")
            ]
            thread.action_ids = [item.id for item in result.actions]
            thread.transition_count += sum(1 for item in result.events if item.phase == "state")
            thread.updated_at = utcnow()
            hypothesis.status = result.hypothesis_status
            hypothesis.confidence = (
                "HIGH"
                if result.gate.accepted and result.coverage.get("claim_eligible")
                else "LOW"
            )
            hypothesis.evidence_ids = list(result.gate.evidence_ids)
            hypothesis.updated_at = utcnow()
            coverage = dict(result.coverage or {})
            protocol = coverage.get("protocol")
            ladder = coverage.get("s_ladder")
            snapshot.setdefault("thread_protocols", {})
            if isinstance(snapshot.get("thread_protocols"), dict):
                snapshot["thread_protocols"][thread.id] = {
                    "protocol": protocol if isinstance(protocol, dict) else {},
                    "s_ladder": ladder if isinstance(ladder, dict) else {},
                }
            for snapshot_thread in snapshot.get("threads", []):
                if isinstance(snapshot_thread, dict) and str(snapshot_thread.get("id")) == thread.id:
                    if isinstance(protocol, dict):
                        snapshot_thread["protocol"] = protocol
                    if isinstance(ladder, dict):
                        snapshot_thread["s_ladder"] = ladder
                    snapshot_thread["state"] = thread.state
                    break
            specialized_verification = None
            prior_verified_mechanism: dict[str, object] | None = None
            seed_mechanism_ids = seed.get("mechanism_ids", [])
            seed_mechanism_id = (
                str(seed_mechanism_ids[0])
                if isinstance(seed_mechanism_ids, list) and seed_mechanism_ids
                else ""
            )
            if playbook is not None and playbook.mechanism_type:
                verifier_type = str(playbook.mechanism_type).upper()
                for candidate_mechanism in snapshot.get("mechanisms", []):
                    if not isinstance(candidate_mechanism, dict):
                        continue
                    candidate_type = str(
                        candidate_mechanism.get("mechanism_type")
                        or candidate_mechanism.get("type")
                        or candidate_mechanism.get("dimension")
                        or ""
                    ).upper().removeprefix("TRACE_")
                    if (
                        candidate_type == verifier_type
                        and str(candidate_mechanism.get("artifact_id") or artifact_id_value)
                        == artifact_id_value
                        and (
                            str(candidate_mechanism.get("id")) == seed_mechanism_id
                            if seed_mechanism_id
                            else str(candidate_mechanism.get("thread_id")) == str(thread.id)
                        )
                        and str(candidate_mechanism.get("status", "")).upper()
                        in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
                    ):
                        prior_verified_mechanism = candidate_mechanism
                        break
                verifier_rows = _specialized_verifier_context(
                    result.evidence,
                    source_rows,
                    mechanism_type=verifier_type,
                    prior_mechanism=prior_verified_mechanism,
                )
                specialized_verification = verify_mechanism(
                    playbook.mechanism_type,
                    verifier_rows,
                )
                # A narrow continuation can fail to repeat a prior static
                # proof even though the proof is still durable in the
                # artifact ledger. Preserve that accepted state and expose
                # the bounded replay limitation in the runtime gate.
                if (
                    prior_verified_mechanism is not None
                    and not specialized_verification.accepted
                ):
                    runtime_events.append(
                        {
                            "thread_id": thread.id,
                            "phase": "verifier_context_recovered",
                            "action_id": None,
                            "state": thread.state,
                            "evidence_ids": list(
                                prior_verified_mechanism.get("evidence_ids", [])
                            ),
                            "message": (
                                "Prior verified static mechanism retained; "
                                    "bounded thread context did not reproduce every source row."
                            ),
                        }
                    )
                if (
                    not specialized_verification.accepted
                    and artifact_type_value == "pe"
                    and not result.gate.accepted
                ):
                    missing = (
                        ", ".join(specialized_verification.missing) or "semantic closure fields"
                    )
                    boundary = (
                        f"Static boundary: no new evidence closed the "
                        f"{specialized_verification.mechanism_type} mechanism "
                            f"for {artifact_path_value}; missing evidence: {missing}."
                    )
                    if boundary not in limitations:
                        limitations.append(boundary)
                    # G6-B ticket form: name the gap as one the current tool
                    # set cannot close, and list the action types this thread
                    # actually ran so the claim is self-evidencing.  This is
                    # NOT an authoring attempt -- there is no execution
                    # surface for authored tools, and inventing one would be
                    # the new architecture the plan forbids.
                    ticket = tool_authoring_required_ticket(
                        mechanism_type=specialized_verification.mechanism_type,
                        artifact_path=artifact_path_value,
                        missing=specialized_verification.missing,
                        action_types=attempted_names,
                        static_recovery=(
                            _static_decode_recovery_from_evidence(verifier_rows)
                            or host._static_decode_recovery_from_limitations(limitations)
                        ),
                    )
                    if ticket not in limitations:
                        limitations.append(ticket)
            runtime_events.extend(
                {
                    "thread_id": thread.id,
                    "phase": item.phase,
                    "action_id": item.action_id,
                    "state": item.state,
                    "evidence_ids": list(item.evidence_ids),
                    "message": item.message,
                }
                for item in result.events
            )

            # Hydrate the action rows once.  The previous projection
            # repeatedly called ``session.get`` for every field of every
            # action; long investigations therefore paid avoidable ORM
            # identity-map lookups (and could issue queries after an
            # expired session).  The result is immutable for this
            # transaction, so one bounded lookup is sufficient.
            persisted_action_rows = {
                row.id: row
                for row in session.scalars(
                    select(InvestigationActionRecord).where(
                        InvestigationActionRecord.id.in_(
                            tuple(item.id for item in result.actions)
                        )
                    )
                ).all()
            } if result.actions else {}

            def persisted_action_metadata(
                item: ActionSpec,
                row: InvestigationActionRecord | None,
            ) -> dict[str, object]:
                parameters = dict(row.parameters or {}) if row is not None else {}
                raw_provenance = parameters.get("_model_provenance", {})
                provenance = dict(raw_provenance) if isinstance(raw_provenance, Mapping) else {}
                origin = parameters.get("origin")
                if not isinstance(origin, str) or origin not in {
                    "model",
                    "human",
                    "deterministic_fallback",
                }:
                    origin = "model" if item.planner_turn_id else "deterministic_fallback"
                result = {
                    "origin": origin,
                    "planner_turn_id": parameters.get("_planner_turn_id")
                    or item.planner_turn_id,
                }
                result.update(
                    {
                        key: provenance[key]
                        for key in ("model_call_id", "provider", "model")
                        if provenance.get(key) is not None
                    }
                )
                return result

            for item in result.actions:
                persisted = persisted_action_rows.get(item.id)
                result_evidence_ids = list(
                    persisted.result_evidence_ids or []
                ) if persisted is not None else []
                autopsy = (
                    dict((persisted.parameters or {}).get("_autopsy", {}))
                    if persisted is not None
                    and isinstance(
                        (persisted.parameters or {}).get("_autopsy", {}),
                        dict,
                    )
                    else {}
                )
                convergence = (
                    dict((persisted.parameters or {}).get("_convergence", {}))
                    if persisted is not None
                    and isinstance(
                        (persisted.parameters or {}).get("_convergence", {}),
                        Mapping,
                    )
                    else {}
                )
                runtime_actions.append({
                    "id": item.id,
                    "action_type": item.action_type.value,
                    "thread_id": item.thread_id,
                    "hypothesis_id": item.hypothesis_id,
                    "artifact_id": item.artifact_id,
                    "priority": item.priority,
                    "reason": item.reason,
                    "target_selector": dict(item.target_selector),
                    "source_evidence_ids": list(item.source_evidence_ids),
                    "analysis_plan": dict(item.plan),
                    "expected_evidence_kinds": list(item.expected_evidence_kinds),
                    "success_condition": item.success_condition,
                    "failure_interpretation": item.failure_interpretation.value,
                    "cost_units": item.cost_units
                    or ActionCatalog.default().require(item.action_type).cost_units,
                    "dedupe_key": item.dedupe_key,
                    **persisted_action_metadata(item, persisted),
                    "result_evidence_ids": result_evidence_ids,
                    "outcome": (
                        "PRODUCTIVE"
                        if result_evidence_ids
                        else (
                            "NO_NEW_EVIDENCE"
                            if persisted is not None
                            and persisted.error
                            == "NO_NEW_EVIDENCE"
                            else "NEUTRAL"
                        )
                    ),
                    "convergence": convergence,
                    **autopsy,
                })
                if convergence:
                    current_convergence = dict(runtime_convergence.get(thread.id, {}))
                    prior_methods = list(current_convergence.get("method_ids", []))
                    no_gain_methods = list(current_convergence.get("no_gain_method_ids", []))
                    method_id = str(convergence.get("method_id") or "")
                    if method_id and method_id not in prior_methods:
                        prior_methods.append(method_id)
                    gain_class = str(convergence.get("gain_class") or convergence.get("outcome") or "UNKNOWN")
                    if gain_class == "EVIDENCE_GAIN":
                        no_gain_streak = 0
                        no_gain_methods = []
                    else:
                        no_gain_streak = int(current_convergence.get("no_gain_streak", 0) or 0) + 1
                        if method_id and method_id not in no_gain_methods:
                            no_gain_methods.append(method_id)
                    distinct_no_gain_methods = len(set(no_gain_methods))
                    next_method = str(convergence.get("next_method") or "")
                    # Two dry static methods are not a boundary while a
                    # concrete next method, including CONTROLLED_EMULATE,
                    # remains unattempted.
                    stalled = (
                        distinct_no_gain_methods >= 2
                        and no_gain_streak >= 2
                        and next_method in {"", "STATIC_BOUNDARY"}
                    )
                    intervention = (
                        "STATIC_BOUNDARY"
                        if stalled
                        else next_method or convergence.get("next_method")
                    )
                    runtime_convergence[thread.id] = {
                        **current_convergence,
                        "thread_id": thread.id,
                        "frontier_fingerprint": convergence.get("frontier_fingerprint_after")
                        or convergence.get("frontier_fingerprint_before"),
                        "method_ids": prior_methods[-16:],
                        "no_gain_method_ids": no_gain_methods[-16:],
                        "last_method_id": method_id,
                        "no_gain_streak": no_gain_streak,
                        "distinct_no_gain_methods": distinct_no_gain_methods,
                        "last_gain_class": gain_class,
                        "status": "STALLED" if stalled else "PROGRESSING",
                        "intervention": intervention,
                        "last_attempt_id": convergence.get("attempt_id"),
                    }
                    if stalled:
                        runtime_events.append({
                            "thread_id": thread.id,
                            "phase": "investigation.stalled",
                            "action_id": item.id,
                            "state": thread.state,
                            "evidence_ids": result_evidence_ids,
                            "message": (
                                "STALLED/STATIC_BOUNDARY after distinct methods produced no gain."
                                if intervention == "STATIC_BOUNDARY"
                                else "STALLED/BACKTRACK_REQUIRED after distinct methods produced no gain."
                            ),
                        })
                        host._audit(
                            session,
                            case_id=task.case_id,
                            task_id=task.id,
                            event_type="investigation.stalled",
                            actor="scheduler",
                            object_type="InvestigationThread",
                            object_id=thread.id,
                            payload={
                                "status": "STALLED",
                                "intervention": intervention,
                                "method_ids": prior_methods[-16:],
                                "frontier_fingerprint": runtime_convergence[thread.id]["frontier_fingerprint"],
                            },
                        )
                        limitation = (
                            f"Investigation thread {thread.id} is STALLED; "
                            f"{intervention} after distinct static methods produced no new evidence."
                        )
                        if limitation not in limitations:
                            limitations.append(limitation)
            runtime_gates.append(
                {
                    "thread_id": thread.id,
                    "hypothesis_id": hypothesis.id,
                    "status": result.gate.status,
                    "accepted": result.gate.accepted,
                    "reason": result.gate.reason,
                    "missing": list(result.gate.missing),
                    "contradictions": list(result.gate.contradictions),
                    # Claim eligibility and depth coverage are distinct:
                    # a Candidate gate must not hide an uninspected
                    # function, data-flow, CFG, or consumer facet.
                    "deep_static_coverage": dict(result.coverage),
                    "mechanism_verifier": specialized_verification.as_dict()
                    if specialized_verification
                    else None,
                    "prior_verified_preserved": prior_verified_mechanism is not None
                    and not specialized_verification.accepted
                    if specialized_verification
                    else False,
                }
            )
            if specialized_verification is not None:
                for mechanism in snapshot.get("mechanisms", []):
                    if not isinstance(mechanism, dict):
                        continue
                    # Older planning snapshots may omit mechanism_ids on
                    # the thread seed. Fall back to the thread identity so
                    # a successful verifier cannot become write-only.
                    mechanism_type = (
                        str(
                            mechanism.get("mechanism_type")
                            or mechanism.get("type")
                            or mechanism.get("dimension")
                            or ""
                        )
                        .upper()
                        .removeprefix("TRACE_")
                    )
                    verifier_type = str(specialized_verification.mechanism_type or "").upper()
                    if not (
                        str(mechanism.get("id")) == seed_mechanism_id
                        or (
                            not seed_mechanism_id
                            and str(mechanism.get("thread_id")) == str(thread.id)
                            and (not mechanism_type or mechanism_type == verifier_type)
                        )
                    ):
                        continue
                    if specialized_verification.accepted:
                        evidence_ids = list(specialized_verification.evidence_ids)
                        catalog_fields = _catalog_candidate_mechanism_fields(
                            playbook,
                            result.evidence,
                            artifact.logical_path,
                        )
                        if catalog_fields.get("inputs") or catalog_fields.get(
                            "transformation_or_control"
                        ):
                            mechanism.update(catalog_fields)
                            mechanism["evidence_ids"] = list(
                                dict.fromkeys(
                                    [
                                        *(catalog_fields.get("evidence_ids") or ()),
                                        *evidence_ids,
                                    ]
                                )
                            )[:12]
                        else:
                            mechanism["target"] = artifact.logical_path
                            mechanism["evidence_ids"] = evidence_ids
                        mechanism["verifier"] = specialized_verification.as_dict()
                        mechanism["status"] = "VERIFIED"
                    else:
                        if prior_verified_mechanism is not None:
                            # Do not erase an already accepted static
                            # mechanism because this thread's bounded
                            # continuation did not carry every source row.
                            preserved = _preserve_verified_mechanism(
                                prior_verified_mechanism,
                                {
                                    "verifier": specialized_verification.as_dict(),
                                    "evidence_ids": list(specialized_verification.evidence_ids),
                                    "status": specialized_verification.status,
                                },
                            )
                            mechanism.update(preserved)
                        elif result.gate.accepted:
                            mechanism.update(
                                _catalog_candidate_mechanism_fields(
                                    playbook,
                                    result.evidence,
                                    artifact.logical_path,
                                )
                            )
                            mechanism["verifier"] = specialized_verification.as_dict()
                            mechanism["status"] = str(result.gate.status or "CANDIDATE")
                        else:
                            mechanism["verifier"] = specialized_verification.as_dict()
                            mechanism["status"] = "UNKNOWN"
                            mechanism["evidence_ids"] = list(specialized_verification.evidence_ids)
            _stamp_persist_how_snapshot(
                snapshot,
                thread_id=thread.id,
                playbook=playbook,
                result=result,
                artifact_path=str(artifact.logical_path or ""),
            )
            host._audit(
                session,
                case_id=task.case_id,
                task_id=task.id,
                event_type="investigation.thread_completed",
                actor="investigator-verifier",
                object_type="InvestigationThread",
                object_id=thread.id,
                payload={
                    "state": thread.state,
                    "hypothesis_status": hypothesis.status,
                    "gate_status": result.gate.status,
                    "action_count": len(result.actions),
                    "evidence_count": len(result.evidence),
                },
            )
            if cancellation_probe_enabled and host._is_task_cancelled(task.id):
                limitations.append("Investigation loop stopped after task cancellation.")
                break
            if (
                result.gate.accepted
                and result.thread_state == InvestigationThreadState.CLAIM_READY
                and bool(result.coverage.get("claim_eligible"))
                and not model_actions_only
            ):
                claim_fields = _investigated_mechanism_claim_fields(
                    playbook,
                    result.evidence,
                    artifact.logical_path,
                )
                claim_action = str(claim_fields["action"])
                claim_object = str(claim_fields["object"])[:500]
                claim_mechanism = str(claim_fields["mechanism"])
                claim_statement = str(claim_fields["statement"])
                attack_mapping = dict(claim_fields.get("attack_mapping") or {})
                claim = session.scalar(
                    select(Claim).where(
                        Claim.task_id == task.id,
                        Claim.claim_type == "INVESTIGATED_MECHANISM",
                        Claim.action == claim_action,
                        Claim.object == claim_object,
                        Claim.subject == artifact.logical_path,
                    ).limit(1)
                )
                if claim is None:
                    playbook_id = str(getattr(playbook, "id", "") or "")
                    claim_module = host._PERSIST_HOW_CLAIM_MODULES.get(
                        playbook_id, "execution"
                    )
                    claim = Claim(
                        task_id=task.id,
                        module=claim_module,
                        claim_type="INVESTIGATED_MECHANISM",
                        subject=artifact.logical_path,
                        action=claim_action,
                        object=claim_object,
                        mechanism=claim_mechanism,
                        condition="static evidence threshold satisfied; runtime execution not proven",
                        statement=claim_statement,
                        nature="STATIC_INFERRED",
                        status="CANDIDATE",
                        confidence="HIGH",
                        attack_mapping=attack_mapping,
                    )
                    session.add(claim)
                    session.flush()
                if specialized_verification is not None and specialized_verification.accepted:
                    for mechanism in snapshot.get("mechanisms", []):
                        if isinstance(mechanism, dict) and str(
                            mechanism.get("thread_id")
                        ) == str(thread.id):
                            mechanism["claim_id"] = mechanism.get("claim_id") or claim.id
                            mechanism["claim_ids"] = list(
                                dict.fromkeys(
                                    [
                                        str(item)
                                        for item in (mechanism.get("claim_ids") or ())
                                        if item
                                    ]
                                    + [claim.id]
                                )
                            )
                            mechanism["status"] = "VERIFIED"
                            # A verifier acceptance only upgrades the
                            # Claim when the resulting mechanism also has
                            # complete semantic fields. This prevents a
                            # broad API match from becoming a supported
                            # security finding without input/output
                            # provenance.
                            if inspect_mechanism_ready(mechanism).completeness >= 80:
                                claim.status = "SUPPORTED"
                # A statically correlated mechanism can be verified before
                # the selected playbook has a specialist verifier (for
                # example, a shell-output link on a process-execution
                # thread).  Keep its Claim provenance instead of leaving a
                # valid mechanism write-only in the snapshot.
                for mechanism in snapshot.get("mechanisms", []):
                    if not isinstance(mechanism, dict):
                        continue
                    if str(mechanism.get("thread_id")) != str(thread.id):
                        continue
                    if str(mechanism.get("status", "")).upper() != "VERIFIED":
                        continue
                    mechanism["claim_id"] = mechanism.get("claim_id") or claim.id
                    mechanism["claim_ids"] = list(
                        dict.fromkeys(
                            [str(item) for item in (mechanism.get("claim_ids") or ()) if item]
                            + [claim.id]
                        )
                    )
                    if inspect_mechanism_ready(mechanism).completeness >= 80:
                        claim.status = "SUPPORTED"
                relevant = [
                    item
                    for item in result.evidence
                    if item.get("kind") in {
                        "function_call",
                        "constant",
                        "api_argument_trace",
                        "value_flow",
                        "resolved_api",
                        "decode_result",
                        "data_reference",
                    }
                ]
                if not relevant:
                    relevant = list(result.evidence[:8])
                for item in relevant:
                    evidence_id = str(item.get("id"))
                    if evidence_id:
                        host._link_claim_evidence(
                            session,
                            claim_id=claim.id,
                            evidence_id=evidence_id,
                        )
                host._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="investigation.claim_gate_passed",
                    actor="verifier",
                    object_type="Claim",
                    object_id=claim.id,
                    payload={
                        "thread_id": thread.id,
                        "hypothesis_id": hypothesis.id,
                        "evidence_ids": [str(item.get("id")) for item in relevant],
                    },
                )
            else:
                host._audit(
                    session,
                    case_id=task.case_id,
                    task_id=task.id,
                    event_type="investigation.claim_gate_unknown",
                    actor="verifier",
                    object_type="InvestigationHypothesis",
                    object_id=hypothesis.id,
                    payload={
                        "thread_id": thread.id,
                        "missing": list(result.gate.missing),
                        "contradictions": list(result.gate.contradictions),
                    },
                )

        updated_investigation = {
            **snapshot,
            "runtime": {
                "events": runtime_events[-512:],
                "actions": runtime_actions[-128:],
                "gates": runtime_gates,
            },
            "convergence": runtime_convergence,
            "action_budget": {
                "scope": "invocation",
                "limit": task_action_budget_limit,
                "used": min(task_action_budget_used, task_action_budget_limit),
                "remaining": max(
                    0, task_action_budget_limit - task_action_budget_used
                ),
                "deferred_count": len(deferred_frontier),
            },
            "deferred_frontier": deferred_frontier,
            "work_ledger": work_ledger,
            "current_state": runtime_events[-1]["state"]
            if runtime_events
            else snapshot.get("current_state", "UNKNOWN"),
            "last_transition": "investigation_loop_completed",
            "private_chain_of_thought": False,
        }
        if limitations:
            task.limitations = sorted(
                set(list(task.limitations or [])) | set(limitations)
            )
        task.strategy_snapshot = {
            **(task.strategy_snapshot or {}),
            "investigation": updated_investigation,
        }
        host._persist_pma_static_analysis_plan(session, task)
    return limitations


def _apply_seed_playbook_gate(host: DerivationHost, result: object, playbook: object):
    seed_gate = host._gate_for_seed_playbook(playbook, getattr(result, "evidence", ()))
    if seed_gate is None:
        return result
    thread_state = getattr(result, "thread_state", None)
    hypothesis_status = getattr(result, "hypothesis_status", "UNKNOWN")
    if seed_gate.accepted:
        # Persist-time command/flags/sink already satisfy the seed
        # playbook. Deep-mining claim_eligible still waits for TRACE /
        # GET_DECOMPILE contracts and would spend the 64-action cap on a
        # seed that can already emit CANDIDATE/SUPPORTED.
        thread_state = InvestigationThreadState.CLAIM_READY
        hypothesis_status = seed_gate.status
    else:
        hypothesis_status = "UNKNOWN"
    return replace(
        result,
        gate=seed_gate,
        thread_state=thread_state,
        hypothesis_status=hypothesis_status,
    )


def _catalog_candidate_mechanism_fields(*args, **kwargs):
    return PersistHow._catalog_candidate_mechanism_fields(*args, **kwargs)


def _investigated_mechanism_claim_fields(*args, **kwargs):
    return PersistHow._investigated_mechanism_claim_fields(*args, **kwargs)


def _persist_time_seed_result(
    host: DerivationHost,
    *,
    playbook: object,
    evidence: Iterable[object],
    thread_id: str,
    artifact_id: str,
) -> InvestigationResult | None:
    """Close a seed from persist-time catalog facts without charging TRACE.

        Kunglao Artifact→Evidence→Claim: recovered HOW rows are already in the
        ledger. Dispatching GET_CALLEES/TRACE_API_ARGUMENT on that seed burns
        leftover budget and leaves sibling threads empty.
        """
    rows = [
        dict(row) if isinstance(row, Mapping) else row
        for row in evidence
        if isinstance(row, Mapping)
    ]
    seed_gate = host._gate_for_seed_playbook(playbook, rows)
    playbook_id = str(getattr(playbook, "id", "") or "").strip()
    if seed_gate is not None and seed_gate.accepted:
        hypothesis_status = seed_gate.status
        gate = seed_gate
        claim_eligible = True
        message = (
            "Persist-time catalog facts already satisfy the seed "
                "playbook; TRACE was not charged."
        )
    elif host._persist_partial_how_ready(playbook_id, rows):
        hypothesis_status = "CANDIDATE"
        gate = seed_gate or GateDecision(
            accepted=False,
            status="CANDIDATE",
            reason=(
                "persist-time recovered HOW is claimable as CANDIDATE; "
                    "catalog/specialist tokens remain incomplete"
            ),
            evidence_ids=tuple(
                str(item.get("id") or "")
                for item in rows
                if isinstance(item, Mapping) and str(item.get("id") or "").strip()
            )[:32],
            missing=getattr(seed_gate, "missing", ()) if seed_gate is not None else ("catalog_contract",),
        )
        claim_eligible = True
        message = (
            "Persist-time recovered HOW is enough for a CANDIDATE claim; "
                "TRACE was not charged because leftover mining cannot invent "
                "missing catalog tokens."
        )
    else:
        return None
    evidence_ids = tuple(
        str(item.get("id") or "")
        for item in rows
        if isinstance(item, Mapping) and str(item.get("id") or "").strip()
    )
    return InvestigationResult(
        thread_id=thread_id,
        artifact_id=artifact_id,
        thread_state=InvestigationThreadState.CLAIM_READY,
        hypothesis_status=hypothesis_status,
        evidence=tuple(rows),
        events=(
            InvestigationEvent(
                phase="persist_time_claim_ready",
                action_id=None,
                state=InvestigationThreadState.CLAIM_READY.value,
                evidence_ids=evidence_ids[:32],
                message=message,
            ),
        ),
        actions=(),
        gate=gate,
        coverage={
            "complete": True,
            "evidence_complete": True,
            "claim_eligible": claim_eligible,
            "target_count": 0,
            "targets": (),
            "protocol": fill_protocol(rows),
        },
    )


def _persist_time_unique_thread_result(
    host: DerivationHost,
    *,
    evidence: Iterable[object],
    thread_id: str,
    artifact_id: str,
) -> InvestigationResult | None:
    """Close a unique-thread seed when persist already recovered lpStartAddress.

        Unique OS-thread seeds have no typed playbook, so leftover TRACE used
        to burn GET_CALLEES and leave the one-round report UNKNOWN even after
        CreateThread arguments were stamped. Do not invent a start address.
        """
    rows = [
        mapped
        for mapped in (host._investigation_row_mapping(item) for item in evidence)
        if mapped is not None
    ]
    specs = host._persist_unique_thread_claim_specs("", rows)
    if not specs:
        return None
    evidence_ids = tuple(
        str(item.get("id") or "")
        for item in rows
        if str(item.get("id") or "").strip()
    )
    starts = [str(fields.get("object") or "") for _playbook, fields, _ids in specs]
    start_text = ", ".join(item for item in starts if item) or "recovered start"
    return InvestigationResult(
        thread_id=thread_id,
        artifact_id=artifact_id,
        thread_state=InvestigationThreadState.CLAIM_READY,
        hypothesis_status="CANDIDATE",
        evidence=tuple(rows),
        events=(
            InvestigationEvent(
                phase="persist_time_claim_ready",
                action_id=None,
                state=InvestigationThreadState.CLAIM_READY.value,
                evidence_ids=evidence_ids[:32],
                message=(
                    "Persist-time recovered OS-thread start "
                    f"{start_text}; TRACE was not charged."
                ),
            ),
        ),
        actions=(),
        gate=GateDecision(
            accepted=False,
            status="CANDIDATE",
            reason=(
                "persist-time recovered lpStartAddress is claimable as "
                    "CANDIDATE; runtime start remains unobserved"
            ),
            evidence_ids=evidence_ids[:32],
            missing=("runtime_thread_start",),
        ),
        coverage={
            "complete": True,
            "evidence_complete": True,
            "claim_eligible": True,
            "target_count": 0,
            "targets": (),
            "protocol": fill_protocol(rows),
        },
    )


def _pin_config_consumer_seed_rows(
    seed_rows: Iterable[object],
    pinned_rows: Iterable[object],
) -> list[object]:
    """Keep recovered XOR links after a seed-cluster filter drops them."""
    merged: dict[str, object] = {}
    for row in seed_rows:
        row_id = str(getattr(row, "id", "") or "")
        if row_id:
            merged[row_id] = row
    for row in pinned_rows:
        row_id = str(getattr(row, "id", "") or "")
        if row_id:
            merged[row_id] = row
    return list(merged.values())


def _preserve_verified_mechanism(
    current: Mapping[str, object], candidate: Mapping[str, object]
) -> dict[str, object]:
    """Prevent a narrow later pass from downgrading verified static state."""
    merged = dict(current)
    merged.update(dict(candidate))
    current_status = str(current.get("status", "")).upper()
    candidate_status = str(candidate.get("status", "")).upper()
    if current_status in {"VERIFIED", "SUPPORTED", "CONFIRMED"} and candidate_status not in {
        "VERIFIED", "SUPPORTED", "CONFIRMED"
    }:
        merged["status"] = current.get("status")
        if current.get("verifier"):
            merged["verifier"] = current.get("verifier")
        if current.get("evidence_ids"):
            merged["evidence_ids"] = list(
                dict.fromkeys(
                    [str(item) for item in (current.get("evidence_ids") or ()) if item]
                    + [str(item) for item in (candidate.get("evidence_ids") or ()) if item]
                )
            )[:32]
    return merged


def _select_config_consumer_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    found: list[object] = []
    for row in rows:
        if not host._is_config_consumer_seed_row(row):
            continue
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_dynamic_api_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    found: list[object] = []
    for row in rows:
        if not host._is_dynamic_api_seed_row(row):
            continue
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_http_transport_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    found: list[object] = []
    seen: set[str] = set()
    for row in rows:
        if not host._is_http_transport_seed_row(row):
            continue
        row_id = str(
            row.get("id") if isinstance(row, Mapping) else getattr(row, "id", "") or ""
        )
        if row_id and row_id in seen:
            continue
        if row_id:
            seen.add(row_id)
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_parent_attribute_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    found: list[object] = []
    for row in rows:
        if not host._is_parent_attribute_seed_row(row):
            continue
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_ppid_parent_identity_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 32,
) -> list[object]:
    """Join Process32 enumeration with explorer.exe strings. Do not stamp parent from a lone string."""
    material = list(rows)
    if not any(host._is_process_enumeration_row(item) for item in material):
        return []
    found: list[object] = []
    seen: set[str] = set()
    for row in material:
        if not (
            host._is_explorer_parent_string_row(row)
            or host._is_process_enumeration_row(row)
        ):
            continue
        row_id = str(
            row.get("id") if isinstance(row, Mapping) else getattr(row, "id", "") or ""
        )
        if row_id and row_id in seen:
            continue
        if row_id:
            seen.add(row_id)
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_process_creation_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    found: list[object] = []
    for row in rows:
        if not host._is_process_creation_seed_row(row):
            continue
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _select_unique_thread_seed_rows(
    host: DerivationHost,
    rows: Iterable[object],
    *,
    limit: int = 128,
) -> list[object]:
    material = list(rows)
    start_keys = host._unique_thread_start_keys(material)
    found: list[object] = []
    seen: set[str] = set()
    for row in material:
        if not host._is_unique_thread_seed_row(row, start_keys):
            continue
        row_id = str(getattr(row, "id", "") or "")
        if row_id and row_id in seen:
            continue
        if row_id:
            seen.add(row_id)
        found.append(row)
        if len(found) >= limit:
            break
    return found


def _specialized_verifier_context(
    current_rows: list[Mapping[str, object]],
    scope_rows: list[Any],
    *,
    mechanism_type: str,
    prior_mechanism: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Build a bounded, artifact-local verifier corpus.

        Investigation threads intentionally receive a narrow seed context.  A
        specialist verifier, however, must be able to replay a previously
        derived static link and every Evidence row named by that link.  This
        seam joins only exact provenance IDs from the same artifact; it never
        broadens a mechanism through task-wide co-occurrence.
        """
    link_types = {
        "DYNAMIC_API_RESOLUTION": ("mechanism_dynamic_api_link",),
        "HTTP_DOWNLOAD": ("mechanism_http_transport_link",),
        "SHELL_OUTPUT": ("mechanism_shell_output_link",),
        "ETW_PATCH": ("mechanism_etw_patch_link",),
        "DECODE_CONFIG": ("decode_result", "value_flow"),
    }
    expected_kinds = {
        str(item).casefold()
        for item in (link_types.get(str(mechanism_type).upper()) or ())
        if str(item).strip()
    }

    def read(row: Any, key: str, default: object = None) -> object:
        if isinstance(row, Mapping):
            return row.get(key, default)
        return getattr(row, key, default)

    def as_mapping(row: Any) -> dict[str, object]:
        return {
            "id": read(row, "id"),
            "artifact_id": read(row, "artifact_id"),
            "kind": read(row, "kind", ""),
            "nature": read(row, "nature", "STATIC_OBSERVED"),
            "value": read(row, "value", {}),
            "anchor": read(row, "anchor", {}),
        }

    static_natures = frozenset(
        {"STATIC_OBSERVED", "STATIC_DERIVED", "STATIC_INFERRED"}
    )
    current = [
        as_mapping(row)
        for row in current_rows
        if read(row, "id")
        and str(read(row, "nature", "STATIC_OBSERVED")).upper() in static_natures
    ]
    current_artifact_ids = {
        str(row.get("artifact_id"))
        for row in current
        if row.get("artifact_id") not in (None, "")
    }
    scoped = [
        as_mapping(row)
        for row in scope_rows
        if read(row, "id")
        # Historical/serialized Evidence rows may omit ``nature``.  The
        # static investigation corpus is the only caller of this helper,
        # so retain the same conservative static default used by
        # ``as_mapping`` rather than dropping provenance rows silently.
        and str(read(row, "nature", "STATIC_OBSERVED")).upper() in static_natures
        and (
            not current_artifact_ids
            or str(read(row, "artifact_id", "")) in current_artifact_ids
        )
    ]
    by_id = {str(row["id"]): row for row in scoped if row.get("id")}
    recover_ids: set[str] = set()
    if isinstance(prior_mechanism, Mapping):
        recover_ids.update(
            str(item)
            for item in (prior_mechanism.get("evidence_ids") or ())
            if str(item).strip()
        )
    # If a previously verified mechanism exists, its provenance is the
    # only admissible recovery root.  For a first pass, a link is allowed
    # only when it explicitly cites one of the current thread rows; this
    # prevents unrelated same-type functions from being joined.
    current_ids = {str(row["id"]) for row in current if row.get("id")}
    seeded_from_prior = bool(recover_ids)
    for row in scoped:
        if str(row.get("kind", "")).casefold() not in expected_kinds:
            continue
        value = row.get("value")
        raw_source_ids = value.get("source_evidence_ids") if isinstance(value, Mapping) else ()
        source_ids = {
            str(item)
            for item in (raw_source_ids or ())
            if str(item).strip()
        }
        if seeded_from_prior:
            if str(row["id"]) in recover_ids:
                recover_ids.update(source_ids)
        elif source_ids & current_ids:
            recover_ids.add(str(row["id"]))
            recover_ids.update(source_ids)

    merged: list[dict[str, object]] = []
    seen: set[str] = set()
    for row in [*current, *(by_id[item] for item in recover_ids if item in by_id)]:
        row_id = str(row.get("id"))
        if not row_id or row_id in seen:
            continue
        seen.add(row_id)
        merged.append(row)
    return merged


def _stamp_persist_how_snapshot(*args, **kwargs):
    return PersistHow._stamp_persist_how_snapshot(*args, **kwargs)


def _static_decode_recovery_from_evidence(rows: Iterable[object]) -> str:
    """Summarise an already-registered static decode recovery, from evidence already in hand.

        MEASURED reason the ticket needs this: the 白象 run published

            TOOL_AUTHORING_REQUIRED: DECODE_CONFIG on 64da3378… needs a tool the product does not
            have; missing evidence: key, algorithm, counter, step, consumer, …

        while the same run's own evidence held `verification_status=DECODED_STATIC`,
        `encoding=utf16le-asciihex-record-table`, a four-step `decode_chain` and 5,881 recovered
        characters. Two claims there are false: the product HAS the tool (`literal_table.py`) and the
        algorithm WAS recovered.

        Deliberately PURE over the rows the caller already holds. Two earlier attempts failed and both
        were caught by probes rather than by reasoning:

          * a DB query filtered on `nature='STATIC_DERIVED'` matched nothing (the row is
            `STATIC_OBSERVED`), so the helper silently returned "" and the false claim survived;
          * opening a session mid-investigation broke the audit chain
            (`StaleDataError: UPDATE ... audit_chain_heads ... 0 were matched`), failing 8 tests;
          * reading `limitations` matched nothing either - the decode recovery is not in that list.

        So the input is the verifier's own evidence rows, which demonstrably carry the fact.
        """
    for row in rows or ():
        if not isinstance(row, Mapping):
            continue
        # These rows are shaped `{id, artifact_id, kind, nature, value, anchor}`
        # (`_specialized_verifier_context.as_mapping`), so the decode fields live INSIDE `value`.
        # An earlier revision read them off the row itself and found nothing, leaving the false
        # ticket wording in place while appearing fixed.
        inner = row.get("value")
        if not isinstance(inner, Mapping):
            continue
        blob = dict(inner)
        status = str(blob.get("verification_status") or "").strip()
        candidate = blob.get("candidate") if isinstance(blob.get("candidate"), Mapping) else {}
        encoding = str(candidate.get("encoding") or blob.get("encoding") or "").strip()
        if "DECODED_STATIC" not in status and not encoding:
            continue
        chain = candidate.get("decode_chain") or blob.get("decode_chain") or []
        steps = [str(item).strip() for item in chain if str(item).strip()]
        recovered = len(str(blob.get("recovered_text") or blob.get("decoded_text") or ""))
        parts: list[str] = []
        if status:
            parts.append(f"status={status}")
        if encoding:
            parts.append(f"encoding={encoding}")
        if steps:
            parts.append("chain=" + " -> ".join(steps))
        if recovered:
            parts.append(f"recovered_chars={recovered}")
        if parts:
            return "; ".join(parts)[:400]
    return ""


def _supporting_seed_static_boundary(
    *,
    evidence: Iterable[object],
    thread_id: str,
    artifact_id: str,
    category: str,
) -> InvestigationResult:
    """Do not spend leftover TRACE on keyword supporting seeds.

        Persistence/evasion/pe_parser clusters without a typed HOW playbook
        used to inherit the leftover 64-action cap after decode/process skip.
        """
    rows = [
        dict(row) if isinstance(row, Mapping) else row
        for row in evidence
        if isinstance(row, Mapping)
    ]
    evidence_ids = tuple(
        str(item.get("id") or "")
        for item in rows
        if isinstance(item, Mapping) and str(item.get("id") or "").strip()
    )
    label = str(category or "supporting").strip() or "supporting"
    return InvestigationResult(
        thread_id=thread_id,
        artifact_id=artifact_id,
        thread_state=InvestigationThreadState.UNKNOWN,
        hypothesis_status="UNKNOWN",
        evidence=tuple(rows),
        events=(
            InvestigationEvent(
                phase="persist_time_static_boundary",
                action_id=None,
                state=InvestigationThreadState.UNKNOWN.value,
                evidence_ids=evidence_ids[:32],
                message=(
                    f"{label} keyword seed has no typed HOW contract; "
                        "TRACE was not charged."
                ),
            ),
        ),
        actions=(),
        gate=GateDecision(
            accepted=False,
            status="UNKNOWN",
            reason="supporting seed without typed HOW contract",
            evidence_ids=evidence_ids[:32],
            missing=("typed_behavior_contract",),
        ),
        coverage={
            "complete": True,
            "evidence_complete": True,
            "claim_eligible": False,
            "target_count": 0,
            "targets": (),
            "protocol": fill_protocol(rows),
        },
    )


def _investigation_scheduled_keys(
    action_type: str,
    selector: Mapping[str, object],
    plan: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return planner and loop keys that must suppress a durable attempt."""
    return investigation_scheduled_keys(action_type, selector, plan)
