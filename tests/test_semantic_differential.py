from __future__ import annotations

import ast
from pathlib import Path

from benchmarks.semantic_differential import build_semantic_differential


def test_semantic_differential_is_evaluator_only_and_classifies_retrieval_gap() -> None:
    task_view = {
        "id": "task-1",
        "evidence": [
            {
                "id": "e1",
                "value": {"api": "GetProcAddress"},
                "anchor": {"function_entry": "0x1000"},
            }
        ],
        "evidence_delivery": {
            "records": [
                {
                    "evidence_id": "e1",
                    "stage": "CANDIDATE",
                    "exclusion_reason": "budget",
                }
            ]
        },
        "investigation": {"actions": [{"id": "action-1"}]},
        "claims": [],
        "limitations": [],
    }
    gold = {
        "version": "test-v1",
        "mechanisms": [
            {
                "id": "resolver",
                "components": {
                    "entry": ["GetProcAddress"],
                    "anchors": ["0x1000"],
                    "consumer": ["LoadLibrary"],
                },
            }
        ],
    }

    scorecard = build_semantic_differential(task_view, gold)

    result = scorecard["mechanisms"][0]
    assert scorecard["evaluator_only"] is True
    assert result["status"] == "UNKNOWN"
    assert result["discrepancy"] == "retrieval_failure"
    assert result["components"][0]["status"] == "UNKNOWN"


def test_semantic_differential_classifies_each_incomplete_static_path() -> None:
    gold = {
        "version": "test-v1",
        "mechanisms": [
            {
                "id": "resolver",
                "components": {"entry": ["GetProcAddress", "caller"]},
            }
        ],
    }
    partial_evidence = [
        {
            "id": "resolver-seed",
            "value": {"api": "GetProcAddress"},
            "anchor": {"function_entry": "0x1000"},
        }
    ]
    scenarios = {
        "missing_static_evidence": {
            "evidence": [],
            "evidence_delivery": {"records": []},
            "investigation": {"actions": []},
            "claims": [],
            "limitations": [],
        },
        "retrieval_failure": {
            "evidence": partial_evidence,
            "evidence_delivery": {
                "records": [
                    {
                        "evidence_id": "resolver-seed",
                        "stage": "CANDIDATE",
                        "exclusion_reason": "budget",
                    }
                ]
            },
            "investigation": {"actions": []},
            "claims": [],
            "limitations": [],
        },
        "action_planning_failure": {
            "evidence": partial_evidence,
            "evidence_delivery": {"records": []},
            "investigation": {"actions": []},
            "claims": [],
            "limitations": [],
        },
        "analysis_or_verifier_failure": {
            "evidence": partial_evidence,
            "evidence_delivery": {"records": []},
            "investigation": {"actions": [{"id": "resolver-xref"}]},
            "claims": [],
            "limitations": [],
        },
        "requires_authorized_dynamic_phase": {
            "evidence": partial_evidence,
            "evidence_delivery": {"records": []},
            "investigation": {"actions": [{"id": "resolver-xref"}]},
            "claims": [{"id": "candidate"}],
            "limitations": ["requires authorized dynamic phase"],
        },
        "unsupported_child_type_or_static_boundary": {
            "evidence": partial_evidence,
            "evidence_delivery": {"records": []},
            "investigation": {"actions": [{"id": "resolver-xref"}]},
            "claims": [{"id": "candidate"}],
            "limitations": ["unsupported decoded child artifact type"],
        },
    }

    for expected, task_view in scenarios.items():
        scorecard = build_semantic_differential(task_view, gold)
        assert scorecard["mechanisms"][0]["discrepancy"] == expected


def test_runtime_source_has_no_ast_import_path_to_evaluator_or_gold() -> None:
    for path in Path("src/threat_report_agent").rglob("*.py"):
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(not item.name.startswith("benchmarks") for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("benchmarks")
