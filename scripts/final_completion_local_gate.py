"""Run the local, static-only portion of the Final Completion gate.

The seeded mechanism fixture is evaluator input and never enters the product
runtime.  It verifies that the differential evaluator, model-action
productivity metric, and static execution boundary remain deterministic.  A
green result is L1 evidence only; it cannot close real-sample, browser,
external-Gold, or production gates.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.comhost_differential import evaluate_task_view  # noqa: E402
from threat_report_agent.deep_analysis_quality import deep_analysis_metrics  # noqa: E402


GOLD_PATH = ROOT / "benchmarks" / "gold" / "comhost-critical-v1.json"


def _seeded_task() -> dict[str, object]:
    """Build a complete evaluator fixture without reading a sample."""
    evidence = [
        {
            "id": "seed-comhost-chain",
            "kind": "static_semantic_fixture",
            "value": (
                "entrypoint hash resolver function pointer GetProcAddress WinHTTP "
                "https WinHttpSendRequest WinHttpReceiveResponse registration check-in tasking "
                "shell pipe output capture HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                "RegSetValue Defender EtwEventWrite VirtualProtect 33 C0 C3 "
                "FlushInstructionCache LoadLibrary plugin FreeLibrary decoder encoded decoded"
            ),
            "anchor": {"function_entry": "0x401000", "rva": "0x1000"},
            "nature": "STATIC_OBSERVED",
        }
    ]
    return {
        "id": f"seeded-{uuid4()}",
        "evidence": evidence,
        "evidence_delivery": {"records": []},
        "claims": [],
        "claim_evidence": [],
        "investigation": {
            "actions": [
                {
                    "id": "seed-action",
                    "origin": "model",
                    "status": "SUCCEEDED",
                    "result_evidence_ids": ["seed-comhost-chain"],
                }
            ]
        },
        "limitations": ["Static fixture only; runtime behavior was not executed."],
    }


def _model_effectiveness() -> dict[str, object]:
    """Evaluate the A2 productivity contract using a deterministic stub trace."""
    actions = [
        {
            "origin": "model",
            "status": "SUCCEEDED",
            "result_evidence_ids": [f"model-evidence-{index}"],
            "new_evidence_ids": [f"model-evidence-{index}"],
        }
        for index in range(4)
    ] + [
        {
            "origin": "model",
            "status": "FAILED",
            "error": "NO_NEW_EVIDENCE",
            "result_evidence_ids": [],
        }
        for _ in range(2)
    ]
    mechanism = {
        "type": "mechanism_candidate",
        "mechanism_id": "seed-model-mechanism",
        "status": "SUPPORTED",
        "target": "resolver@0x401000",
        "inputs": ["hash"],
        "transformation_or_control": ["resolver"],
        "conditions": ["hash matches"],
        "outputs": ["function pointer"],
        "consumers": ["GetProcAddress"],
        "evidence_ids": ["model-evidence-0"],
        "verifier": {"status": "VERIFIED"},
        "alternative_hypotheses": ["static import only"],
    }
    document = {
        "modules": [
            {
                "rows": [
                    mechanism,
                    {
                        "type": "mechanism_chain",
                        "rendered": "hash -> resolver -> function pointer -> consumer",
                    },
                    {"type": "indicator", "value": "resolver"},
                    {"type": "analysis_limitation", "value": "runtime not executed"},
                ]
            }
        ]
    }
    metrics = deep_analysis_metrics(document=document, mechanisms=[mechanism], investigation_actions=actions)
    accepted = int(metrics.get("accepted_model_actions", 0))
    useful = int(metrics.get("useful_model_actions", 0))
    productivity = float(metrics.get("model_action_productivity_rate", 0.0))
    result = {
        "accepted_model_actions": accepted,
        "useful_model_actions": useful,
        "productivity": productivity,
        "thresholds": {
            "accepted_at_least": 6,
            "productivity_at_least": 0.5,
            "mechanism_consumed_model_evidence": True,
        },
        "mechanism_evidence_ids": mechanism["evidence_ids"],
        "model_evidence_ids": [item["new_evidence_ids"][0] for item in actions if item.get("new_evidence_ids")],
        "status": "PASS"
        if accepted >= 6
        and productivity >= 0.5
        and set(mechanism["evidence_ids"]) & {
            item for action in actions for item in action.get("new_evidence_ids", [])
        }
        else "BLOCKED",
    }
    return result


def run(output: Path) -> dict[str, object]:
    gold = json.loads(GOLD_PATH.read_text(encoding="utf-8"))
    runs: list[dict[str, object]] = []
    for index in range(3):
        task = _seeded_task()
        score = evaluate_task_view(task, GOLD_PATH)
        mechanisms = score.get("mechanisms", [])
        critical = {
            item["mechanism_id"]: item["status"]
            for item in mechanisms
            if item.get("mechanism_id") in set(gold.get("critical_mechanisms", []))
        }
        runs.append(
            {
                "run_id": f"seeded-c1-c4-{index + 1}-{task['id'].split('-', 1)[1]}",
                "status": "PASS" if all(value == "SUPPORTED" for value in critical.values()) else "BLOCKED",
                "critical_mechanisms": critical,
                "evaluator_only": score.get("evaluator_only") is True,
                "sample_execution": False,
                "sample_network_access": False,
                "dynamic_emulators_invoked": False,
            }
        )
    model = _model_effectiveness()
    payload = {
        "schema_version": "final-completion-local-gate-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "evidence_level": "L1",
        "status": "PASS" if all(item["status"] == "PASS" for item in runs) and model["status"] == "PASS" else "BLOCKED",
        "seeded_c1_c4": {
            "runs_required": 3,
            "runs_completed": len(runs),
            "runs": runs,
            "three_consecutive_pass": all(item["status"] == "PASS" for item in runs),
        },
        "model_effectiveness": model,
        "execution_boundary": {
            "sample_execution": False,
            "sample_network_access": False,
            "dynamic_emulators_invoked": False,
            "gold_in_runtime": False,
        },
        "limitations": [
            "Seeded fixture is evaluator-only L1 evidence and is not a real-sample certification.",
            "Real provider attribution, blind ComHost, Resume regression, and external Gold remain separate gates.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "release-artifacts" / "final-round" / "final-completion-local-gate-20260902.json")
    args = parser.parse_args()
    payload = run(args.output)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
