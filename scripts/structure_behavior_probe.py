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
  4. Decoded object-level alias/join positive case          - ADR-0035's accepting direction.
  5. Same-function API-name co-occurrence (negative)        - ADR-0035's rejecting direction; the plan calls this
                                                              an invariant that must survive every step.
  6. credible_windows_process_creation_flags(0x000f4240)     - the known counter-example must stay rejected.
  7. DEFERRED_TO_WORKER is not a real simulation             - a placeholder must never count as an observed run.

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
    block = f"{OPERATIONAL_LIMITATIONS_HEADING}\n\n- [pipeline] Tool run x ended TIMED_OUT: T.\n"
    fragments = f"# 静态分析报告\n\n## 分析结论\n\n正文。\n\n{block}"
    draft_without = "# 静态分析报告\n\n## 分析结论\n\n模型润色正文。\n"
    draft_with = draft_without + "\n" + block
    observed["2_limitation_bullet_dropped"] = {
        "violations_for_draft_without": compose_gate_violations(draft_without, fragments),
        "violations_for_draft_with": compose_gate_violations(draft_with, fragments),
        "heading": OPERATIONAL_LIMITATIONS_HEADING,
    }

    # 3. external/unprovenanced IOC in a draft whose fragments never mention it.
    draft_ioc = draft_without + "\n端点 http://203.0.113.9/payload.bin\n"
    observed["3_unprovenanced_ioc"] = {
        "violations": compose_gate_violations(draft_ioc, fragments),
        "ioc_marker": "203.0.113.9",
    }

    # 4/5. ADR-0035: object-level alias accepted, name co-occurrence rejected.
    anchor = {"artifact": "sample.exe", "function": "FUN_140001000", "callsite": "0x140001010"}
    producer = "decoded_buffer:0x14005d080"
    candidate = {"decoder": "CryptDecrypt", "output": "0x14005d080", "input": "0x14005d000"}
    positive_value = {
        "resolved": True,
        "api": "WinHttpSendRequest",
        "argument_index": 2,
        "producer": producer,
        "callsite": "0x140001010",
    }
    cooccurrence_value = {"resolved": True, "api": "WinHttpSendRequest"}  # same function, no trace
    observed["4_decoded_join_positive"] = decoded_output_consumer(
        producer, candidate, "api_argument_trace", positive_value, anchor
    )
    observed["5_name_cooccurrence_rejected"] = decoded_output_consumer(
        producer, candidate, "api_argument_trace", cooccurrence_value, anchor
    )

    # 6. creation-flag counter-example.
    observed["6_creation_flags_counterexample"] = {
        "0x000f4240": credible_windows_process_creation_flags(0x000F4240),
        "0x00080000": credible_windows_process_creation_flags(0x00080000),
    }

    # 7. a deferred/placeholder status must not count as a real simulation.
    observed["7_deferred_not_real"] = {
        "is_placeholder_DEFERRED_TO_WORKER": is_placeholder_status("DEFERRED_TO_WORKER"),
        "is_real_DEFERRED_TO_WORKER": is_real_simulation_value(
            {"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"}
        ),
        "is_real_SUCCEEDED": is_real_simulation_value({"status": "SUCCEEDED", "simulator": "unicorn"}),
    }
    return observed


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
