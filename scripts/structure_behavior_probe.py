"""Behaviour-freeze probe. Records OBSERVED outputs so a structural move can be compared against them.

Plan section P0.5. This does NOT assert that the behaviour is correct - it records what it IS, because a
structural step is forbidden from changing it either way. A behaviour that looks wrong is recorded as a
`known_behavior_gap` and must be fixed in a separate behaviour plan, never inside a move (section 1.4, 14.5).

Every item below exists because the plan names it, and each is chosen to catch a specific false-green:

  1. compose_official_markdown on a minimal document        - the published layer must keep producing the same
                                                              bytes; a heading-only check is not enough.
  2. A draft that DROPS the operational-limitation bullet   - section 14.1's first false-green: "heading exists
                                                              but the limitation bullets are gone". The gate must
                                                              report a violation, not accept the draft.
  3. An external/unprovenanced IOC in a draft               - the gate's current stance must be RECORDED. If it
                                                              silently passes today, that is a recorded gap, not
                                                              a green.
  4. Decoded object-level alias/join positive case          - ADR-0035's accepting direction, PLUS a per-guard
                                                              sensitivity block (4b): two booleans cannot see a
                                                              deleted guard, and an audit measured 15/15 mutants
                                                              leaving them unchanged.
  5. Same-function API-name co-occurrence (negative)        - ADR-0035's rejecting direction; the plan calls this
                                                              an invariant that must survive every step.
  6. credible_windows_process_creation_flags(0x000f4240)     - the known counter-example must stay rejected.
  7. DEFERRED_TO_WORKER is not a real simulation             - a placeholder must never count as an observed run;
                                                              measured through `is_real_simulation_row` (the
                                                              predicate the pipeline calls), not just the literal
                                                              negation of the constant.

Output: `.scratch/structure-baseline/behavior.json`. Run with no arguments to print and write the baseline.

    python scripts/structure_behavior_probe.py
    python scripts/structure_behavior_probe.py --check <baseline.json>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / ".scratch" / "structure-baseline" / "behavior.json"


def minimal_document() -> dict[str, object]:
    return {
        "analyst_report_limitations": [],
        "analyst_chapters": [],
        "analyst_report_unavailable": {},
        "analysis": {},
    }


def probe() -> dict[str, object]:
    from threat_report_agent.analyst_report import (
        OPERATIONAL_LIMITATIONS_HEADING,
        compose_gate_violations,
        compose_official_markdown,
    )
    from threat_report_agent.controlled_emulation import is_placeholder_status, is_real_simulation_value
    from threat_report_agent.facts.dataflow import decoded_output_consumer
    from threat_report_agent.static_analysis import credible_windows_process_creation_flags

    observed: dict[str, object] = {}

    # 1. published layer, minimal document.
    published = compose_official_markdown(minimal_document())
    observed["1_compose_minimal"] = {
        "length": len(published),
        "first_line": published.splitlines()[0] if published else "",
        "has_appendix_heading": "调查附录" in published,
    }

    # 2. a draft that loses the operational-limitation bullet.
    #
    # MEASURED LIMIT OF THIS ITEM, and why the third reading was added: the first two readings only distinguish
    # "the whole block is gone" from "the whole block is present". The false-green the plan names (section 14.1)
    # is narrower - the HEADING kept, every BULLET dropped - and `compose_gate_violations` tests the heading
    # substring only (`analyst_report.py:6123`), so that draft passes clean. A probe that records only the first
    # two readings reports PASS for a gate that cannot see the case it was written for.
    block = f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- [pipeline] Tool run x ended TIMED_OUT: T.\n"
    fragments = f"# 静态分析报告\n\n## 分析结论\n\n正文。\n\n{block}"
    draft_without = "# 静态分析报告\n\n## 分析结论\n\n模型润色正文。\n"
    draft_with = draft_without + "\n" + block
    draft_heading_only = f"{draft_without}\n{OPERATIONAL_LIMITATIONS_HEADING}\n"
    observed["2_limitation_bullet_dropped"] = {
        "violations_for_draft_without": compose_gate_violations(draft_without, fragments),
        "violations_for_draft_with": compose_gate_violations(draft_with, fragments),
        "violations_for_heading_kept_bullets_dropped": compose_gate_violations(draft_heading_only, fragments),
        "heading": OPERATIONAL_LIMITATIONS_HEADING,
        "known_gap": (
            "PLAN-NAMED FALSE-GREEN, RECORDED NOT FIXED: `violations_for_heading_kept_bullets_dropped` is empty, "
            "so a draft that keeps the heading and drops every bullet clears the compose gate. The check at "
            "analyst_report.py:6123 is a heading substring test. Fixing it changes behaviour and is forbidden "
            "inside a structural step (plan 1.4 / 14.5); the reading is frozen here so a later step that DOES "
            "change it is visible instead of silent."
        ),
    }

    # 3. external/unprovenanced IOC in a draft whose fragments never mention it.
    draft_ioc = draft_without + "\n端点 http://203.0.113.9/payload.bin\n"
    observed["3_unprovenanced_ioc"] = {
        "violations": compose_gate_violations(draft_ioc, fragments),
        "ioc_marker": "203.0.113.9",
    }

    # 4/5. ADR-0035: object-level alias accepted, name co-occurrence rejected.
    anchor = {"artifact": "sample.exe", "function": "FUN_140001000", "callsite": "0x140001010"}
    producer = "evidence:decoded-buffer-1"
    candidate = {
        "decoder": "CryptDecrypt",
        "image_base": "140000000",
        "output_buffer": {"address_space": "ram", "address": "0x14005d080", "length": 64},
    }
    positive_value = {
        "resolved": True,
        "api": "WinHttpSendRequest",
        "argument_index": 2,
        "producer_evidence_id": producer,
        "source_role": "decoded_output",
        "callsite": "0x140001010",
        "source_buffer": {"address_space": "ram", "address": "0x14005d080", "length": 32},
    }
    cooccurrence_value = {"resolved": True, "api": "WinHttpSendRequest", "argument_index": 2}

    def consumer(value: dict[str, object]) -> bool:
        return decoded_output_consumer(producer, candidate, "api_argument_trace", value, anchor)

    observed["4_decoded_join_positive"] = consumer(positive_value)
    observed["5_name_cooccurrence_rejected"] = consumer(cooccurrence_value)

    # 4b. GUARD SENSITIVITY - the reading that makes items 4/5 falsifiable.
    #
    # MEASURED WHY THIS EXISTS (P0.5 audit, r1): 15 of 15 mutants of `decoded_output_consumer` - dropping the
    # `source_role` / `producer_evidence_id` / `argument_index` / `address_space` guards, forcing the API-name
    # check, or replacing the whole length branch with `return True` - left items 4/5 reading exactly
    # (True, False). Two booleans pin the OUTPUT for two inputs, not the guards: the freeze could not see the
    # behaviour it exists to freeze. Each entry below removes ONE input field, or uses an unprobed sibling
    # input, and MUST read False while that guard is doing work. A mutant that deletes the guard turns the
    # entry True and the drift check fires - which is the whole point of a behaviour freeze.
    def without(field: str) -> dict[str, object]:
        return {key: item for key, item in positive_value.items() if key != field}

    source = positive_value["source_buffer"]
    no_length_string_slot = {
        **positive_value,
        "api": "CreateProcessW",
        "argument_index": 1,
        "source_buffer": {"address_space": "ram", "address": source["address"]},
    }
    no_length_scalar_slot = {
        **positive_value,
        "api": "CreateProcessW",
        "argument_index": 5,
        "source_buffer": {"address_space": "ram", "address": source["address"]},
    }
    observed["4b_guard_sensitivity"] = {
        "positive_baseline": consumer(positive_value),
        "resolved_not_true": consumer({**positive_value, "resolved": "UNKNOWN"}),
        "api_missing": consumer(without("api")),
        "api_is_ghidra_label": consumer({**positive_value, "api": "FUN_140001234"}),
        "api_is_placeholder": consumer({**positive_value, "api": "UNKNOWN"}),
        "producer_evidence_id_missing": consumer(without("producer_evidence_id")),
        "producer_evidence_id_mismatch": consumer({**positive_value, "producer_evidence_id": "evidence:other"}),
        "source_role_missing": consumer(without("source_role")),
        "source_role_is_ciphertext": consumer({**positive_value, "source_role": "ciphertext"}),
        "argument_index_missing": consumer(without("argument_index")),
        "argument_index_negative": consumer({**positive_value, "argument_index": -1}),
        "source_buffer_missing": consumer(without("source_buffer")),
        "callsite_absent_in_value_and_anchor": decoded_output_consumer(
            producer, candidate, "api_argument_trace", without("callsite"), {}
        ),
        "address_space_mismatch": consumer(
            {**positive_value, "source_buffer": {**source, "address_space": "disk"}}
        ),
        "address_does_not_alias": consumer(
            {**positive_value, "source_buffer": {**source, "address": "0x140099999"}}
        ),
        "no_length_string_class_slot": consumer(no_length_string_slot),
        "no_length_scalar_slot": consumer(no_length_scalar_slot),
        "kind_not_a_join_kind": decoded_output_consumer(
            producer, candidate, "co_occurrence", positive_value, anchor
        ),
    }

    # 6. creation-flag counter-example.
    observed["6_creation_flags_counterexample"] = {
        "0x000f4240": credible_windows_process_creation_flags(0x000F4240),
        "0x00080000": credible_windows_process_creation_flags(0x00080000),
    }

    # 7. a deferred/placeholder status must not count as a real simulation.
    #
    # The first version of this item recorded `not is_placeholder_status(...)` only, which is VACUOUS: that
    # function is `str(status).upper() in PLACEHOLDER_STATUSES` (`controlled_emulation.py:48-49`), so the reading
    # restates a literal negation of the constant. The predicate the pipeline actually calls is
    # `is_real_simulation_row` (the gate in `analysis_task_orchestration.py`), so that is measured too - and so
    # is the second, DIFFERENT status set in `simulation_adapters`, because the audit flagged that the two may
    # disagree and a divergence would let a never-executed window read as a real simulation.
    from threat_report_agent.controlled_emulation import PLACEHOLDER_STATUSES, is_real_simulation_row
    from threat_report_agent.emulation.policy import _POLICY_OR_PLACEHOLDER_STATUSES

    def row(status: str) -> dict[str, object]:
        return {"kind": "simulation_result", "value": {"status": status}}

    observed["7_deferred_not_real"] = {
        "is_placeholder_DEFERRED_TO_WORKER": is_placeholder_status("DEFERRED_TO_WORKER"),
        "is_real_DEFERRED_TO_WORKER": is_real_simulation_value(
            {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"}
        ),
        "is_real_SUCCEEDED": is_real_simulation_value({"status": "SUCCEEDED", "simulator": "unicorn"}),
        "row_DEFERRED_TO_WORKER": is_real_simulation_row(row("DEFERRED_TO_WORKER")),
        "row_SUCCEEDED": is_real_simulation_row(row("SUCCEEDED")),
        "row_empty_status": is_real_simulation_row(row("")),
        "row_DISABLED_BY_POLICY": is_real_simulation_row(row("DISABLED_BY_POLICY")),
        "row_NO_GRANTED_WINDOW": is_real_simulation_row(row("NO_GRANTED_WINDOW")),
        "row_not_a_simulation_kind": is_real_simulation_row({"kind": "claim", "value": {"status": "SUCCEEDED"}}),
        "only_in_policy_or_placeholder_set": sorted(_POLICY_OR_PLACEHOLDER_STATUSES - PLACEHOLDER_STATUSES),
        "only_in_placeholder_set": sorted(PLACEHOLDER_STATUSES - _POLICY_OR_PLACEHOLDER_STATUSES),
    }

    # 8. IDENTITY of every module that has already MOVED: the old path must be a shim onto the new module, not a
    #    second copy of it.
    #
    # MEASURED why this reading exists (adversarial audit of the report move): the probe imported only the OLD
    # path, so it would have read green even if the old path still held its own copy of the implementation - the
    # "one implementation, moved not copied" claim lived only in a contract test. The readings below are
    # order-independent on purpose: `find_spec()` on a shimmed path changes name and origin depending on which
    # path was imported first (measured), so freezing it would be a reading that drifts for reasons unrelated to
    # structure. What is frozen instead is `same_object`, `same_file`, and the origin the OLD path reports.
    observed["8_moved_module_identity"] = moved_module_identity()
    return observed


#: (old path, new path, a symbol whose object identity must match). One row per completed move in the plan.
MOVED_MODULES: tuple[tuple[str, str, str], ...] = (
    ("threat_report_agent.dataflow", "threat_report_agent.facts.dataflow", "decoded_output_consumer"),
    ("threat_report_agent.decode_primitives", "threat_report_agent.facts.decode_primitives",
     "decode_primitive_sequence"),
    ("threat_report_agent.analyst_report", "threat_report_agent.report.analyst_report",
     "compose_official_markdown"),
    ("threat_report_agent.report_verification", "threat_report_agent.report.report_verification",
     "verify_report_correctness"),
    ("threat_report_agent.gold_output_bar", "threat_report_agent.report.gold_output_bar", "GOLD_OUTPUT_BAR"),
)


def moved_module_identity() -> dict[str, object]:
    """For each completed move: are the two paths one module object with one file behind them?"""
    import importlib

    readings: dict[str, object] = {}
    for old_name, new_name, symbol in MOVED_MODULES:
        old = importlib.import_module(old_name)
        new = importlib.import_module(new_name)
        new_file = str(getattr(new, "__file__", ""))
        old_file = str(getattr(old, "__file__", ""))
        readings[new_name] = {
            "same_object": old is new,
            "same_file": old_file == new_file and bool(new_file),
            "old_path_reports_the_new_file": old_file.endswith(new_file.split("threat_report_agent")[-1]),
            "symbol_is_the_same_object": getattr(old, symbol, None) is getattr(new, symbol, None),
        }
    return readings


def to_jsonable(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return repr(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", default="", help="compare against a previously recorded baseline")
    args = parser.parse_args()

    observed = to_jsonable(probe())
    if args.check:
        baseline = json.loads(Path(args.check).read_text(encoding="utf-8-sig"))
        drift = sorted(
            key for key in set(baseline) | set(observed)
            if json.dumps(baseline.get(key), sort_keys=True, ensure_ascii=False)
            != json.dumps(observed.get(key), sort_keys=True, ensure_ascii=False)
        )
        if drift:
            print("BEHAVIOUR DRIFTED:")
            for key in drift:
                print(f"  - {key}\n      was: {json.dumps(baseline.get(key), ensure_ascii=False)[:200]}"
                      f"\n      now: {json.dumps(observed.get(key), ensure_ascii=False)[:200]}")
            return 1
        print("behaviour UNCHANGED against the recorded baseline")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(observed, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(observed, indent=2, sort_keys=True, ensure_ascii=False))
    print(f"\nrecorded -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
