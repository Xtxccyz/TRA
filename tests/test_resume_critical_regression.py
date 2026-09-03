from __future__ import annotations

import json
from pathlib import Path

from benchmarks.semantic_differential import build_semantic_differential
from benchmarks.resume_differential import evaluate_task_view


def test_resume_critical_scorecard_is_evaluator_only_and_scores_static_components() -> None:
    gold_path = Path("benchmarks/gold/resume-critical-v1.json")
    gold = json.loads(gold_path.read_text("utf-8"))
    task_view = {
        "id": "synthetic-static-regression",
        "evidence": [
            {"id": "xor", "value": {"mechanism": "xor"}, "anchor": {"function_entry": "0x1000"}},
            {"id": "open", "value": {"api": "OpenProcess"}, "anchor": {"function_entry": "0x2000"}},
            {"id": "attribute", "value": {"api": "UpdateProcThreadAttribute"}, "anchor": {"function_entry": "0x2000"}},
            {"id": "constant", "value": {"name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"}, "anchor": {"function_entry": "0x2000"}},
            {"id": "entry", "value": {"entrypoint": "0x3000"}, "anchor": {"function_entry": "0x3000"}},
            {"id": "resolver", "value": {"api": "GetProcAddress", "consumer": "LoadLibraryA"}, "anchor": {"function_entry": "0x4000"}},
        ],
        "evidence_delivery": {"records": []},
        "investigation": {"actions": [{"id": "a1"}]},
        "claims": [{"id": "c1"}],
        "limitations": [],
    }

    scorecard = build_semantic_differential(task_view, gold)

    assert scorecard["evaluator_only"] is True
    assert scorecard["summary"]["supported"] == 4


def test_runtime_package_does_not_import_evaluator_gold() -> None:
    runtime_source = "\n".join(
        path.read_text("utf-8", errors="ignore")
        for path in Path("src/threat_report_agent").rglob("*.py")
    ).casefold()
    assert "benchmarks.gold" not in runtime_source
    assert "resume-critical-v1.json" not in runtime_source


def test_full_resume_scorecard_scores_all_seven_static_mechanisms() -> None:
    gold_path = Path("benchmarks/gold/resume-mechanisms-v2.json")
    gold = json.loads(gold_path.read_text("utf-8"))
    task_view = {
        "id": "offline-resume-evaluation-fixture",
        "evidence": [
            {
                "id": "entry",
                "kind": "pe_structure",
                "value": {
                    "entrypoint": "0x140001000",
                    "apis": ["WinHttpOpen", "CreateProcessW", "GetTickCount64"],
                },
                "anchor": {"function_entry": "0x140001000"},
            },
            {
                "id": "decode",
                "kind": "decode_result",
                "value": {
                    "encoded": "config",
                    "transformation": "xor",
                    "verification": {"status": "VERIFIED_STATIC_DATA"},
                },
                "anchor": {"function_entry": "0x140003be4"},
            },
            {
                "id": "ppid",
                "kind": "function_call",
                "value": {
                    "apis": [
                        "OpenProcess",
                        "UpdateProcThreadAttribute",
                        "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
                        "CreateProcessW",
                    ]
                },
                "anchor": {"function_entry": "0x140002000"},
            },
            {
                "id": "resolver",
                "kind": "function_call",
                "value": {"apis": ["GetProcAddress", "LoadLibraryA"]},
                "anchor": {"function_entry": "0x140004000"},
            },
            {
                "id": "network",
                "kind": "function_call",
                "value": {"apis": ["WinHttpOpen", "WinHttpSendRequest", "WinHttpReceiveResponse"]},
                "anchor": {"function_entry": "0x140005000"},
            },
            {
                "id": "anti-analysis",
                "kind": "function_instruction_window",
                "value": {"api": "GetTickCount64", "comparison": "0x493e1"},
                "anchor": {"function_entry": "0x140006000"},
            },
            {
                "id": "timeline",
                "kind": "function_call",
                "value": {"function_call": "phase_1_to_phase_2"},
                "anchor": {"function_entry": "0x140001000"},
            },
        ],
        "evidence_delivery": {"records": []},
        "investigation": {"actions": [{"id": "static-action"}]},
        "claims": [{"id": "static-claim"}],
        "limitations": [],
    }

    scorecard = build_semantic_differential(task_view, gold)

    assert len(scorecard["mechanisms"]) == 7
    assert scorecard["summary"]["supported"] == 7
    assert all(item["status"] == "SUPPORTED" for item in scorecard["mechanisms"])


def test_resume_evaluator_entrypoint_requires_evaluator_only_gold() -> None:
    task_view = {
        "id": "offline",
        "evidence": [],
        "evidence_delivery": {"records": []},
        "investigation": {"actions": []},
        "claims": [],
        "limitations": [],
    }
    scorecard = evaluate_task_view(task_view)
    assert scorecard["evaluator_only"] is True
    assert scorecard["gold_version"] == "resume-mechanisms-v2"
