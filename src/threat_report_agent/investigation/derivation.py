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

WHAT IS HERE NOW: the travelling cluster, with ONE measured exception. `_bind_recovered_xor_verification`,
`_decode_output_buffer` and `plausible_traced_creation_flags` are module-level functions that `service.py` called by
bare name; the two instruction regexes had exactly one reader each (`_instruction_access_kind`), so they travel as
module constants; and the four in-class helpers that follow from those two facts travel with them. `service.py` keeps
one-statement delegations for the four methods and imports the three functions back, so every caller and every test
that reaches `service.<name>` is unchanged.

THE EXCEPTION, because the design document's travel list includes it and this file does not: `_DECODE_PRODUCER_KINDS`
stays in `service.py`. Its only reader is the giant (one BARE read, measured) - so it travels with the giant, in the
step that moves the giant, and bringing it here now would leave a constant in this module that nothing here reads
while `service.py` still reads it. An earlier version of this docstring called the cluster simply "travelling", which
overstated what had landed; a Spec-axis review of the step caught that, and this paragraph is the correction.

WHAT IS NOT HERE YET, stated so the next reader is not misled: **the giant itself, and therefore no host port** - this
module currently declares no `INVESTIGATION_HOST_MEMBERS` pin, and the extractor refuses to write a body here that
still refers to `self`/`cls`, which is the stronger guarantee while the port does not exist. The giant's move adds the
pin, the `_run_simulation_window` / `_qiling_unavailable_observation` host members and the `host: InvestigationHost`
parameter, in the same step that adds the bodies needing them.

WHY IT IS NOT PART OF `derivation_support.py`: that leaf is deliberately hostless and reachable from un-moved code in
both directions, and it documents which members may NOT sink into it and why. Mixing a future host-taking surface into
it would make that document false.

ONE IMPORT IS CANONICALISED ON PURPOSE. The moved bodies need `addresses_alias` and `output_buffer_identity`.
`service.py` reaches them through `threat_report_agent.dataflow`, the LEGACY shim path that the plan's import policy
records as debt to be repaid; a new module imports `threat_report_agent.facts.dataflow` instead. That is the only
import rewrite this move performs, and it is recorded in the step's records.

THE EXECUTION SEAM, added by the step after this one (P3.3e-move-2a). The giant's body builds a simulation runner and
calls `qiling_unavailable_observation` inline. Both live in `simulation_adapters`, an IMPLEMENTATION module that plan
section 3.2 does not admit into `investigation/`, so neither can be imported here. The host therefore grew two members -
`_run_simulation_window` and `_qiling_unavailable_observation` - whose bodies are the giant's own lines relocated, and
the giant now calls them through `self`. This module declares the outcome TYPE of the first of those
(`SimulationWindowOutcome`, below) because it is what consumes it.
"""
from __future__ import annotations

import re

from typing import Iterable, Mapping, Protocol

from threat_report_agent.facts.dataflow import addresses_alias, output_buffer_identity
from threat_report_agent.investigation import derivation_support as _derivation_support
from threat_report_agent.models import Evidence
from threat_report_agent.static.static_analysis import credible_windows_process_creation_flags


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

    THE HOST PIN ARRIVES WITH THE GIANT'S BODY, not with this type. A pin must name exactly what this module's own
    bodies read (the coordinator's contract test asserts that equality), and after this seam none of those bodies is
    here yet; declaring seven host members for a module that reads none of them would be the aspirational-pin defect
    this phase has already recorded once.
    """

    status: str
    stop_reason: str | None
    output_bytes: bytes

    def as_dict(self) -> dict[str, object]: ...


# ---------------------------------------------------------------------------
# Moved implementation (P3.3 slices): identical to its old home in service.py, with the receiver it used to reach
# through `self`/`cls` dropped - none of these bodies needs one (this module declares no host port, and the
# extractor refuses to write a body that still refers to a receiver). This banner is deliberately SLICE-AGNOSTIC.
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
