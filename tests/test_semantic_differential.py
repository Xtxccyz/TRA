from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

from benchmarks.semantic_differential import build_semantic_differential


def _load_streaming_reader():
    path = Path(__file__).parents[1] / "scripts" / "evaluate_semantic_differential.py"
    spec = importlib.util.spec_from_file_location("evaluate_semantic_differential", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load evaluator script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_large_task_view_stream_reader_accepts_null_and_scalar_projections(tmp_path: Path) -> None:
    """Large live views may use null/scalar optional fields beside the ledger."""
    payload = {
        "evidence": [
            {"id": str(index), "value": {"marker": "x" * 128}}
            for index in range(70_000)
        ],
        "evidence_delivery": None,
        "investigation": "not-started",
        "id": "large-task",
        "limitations": [],
        "claims": [],
    }
    path = tmp_path / "large-task-view.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert path.stat().st_size > 8 * 1024 * 1024

    reader = _load_streaming_reader()
    loaded = reader._load_task_view(path)

    assert loaded["id"] == "large-task"
    assert len(loaded["evidence"]) == len(payload["evidence"])
    assert loaded["evidence_delivery"] is None
    assert loaded["investigation"] == "not-started"
