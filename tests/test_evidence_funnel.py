from __future__ import annotations

from benchmarks.evidence_funnel import build_evidence_funnel


def test_evidence_funnel_reports_each_loss_stage_and_traceability() -> None:
    task_view = {
        "id": "fixture-task",
        "evidence": [
            {"id": "e1", "value": {"api": "GetProcAddress"}, "anchor": {"function_entry": "0x1"}},
            {"id": "e2", "value": {"api": "LoadLibraryA"}, "anchor": {"function_entry": "0x2"}},
            {"id": "e3", "value": {"api": "unrelated"}, "anchor": {"function_entry": "0x3"}},
        ],
        "evidence_delivery": {
            "records": [
                {"evidence_id": "e1", "stage": "CANDIDATE"},
                {"evidence_id": "e1", "stage": "SELECTED"},
                {"evidence_id": "e1", "stage": "DELIVERED"},
                {"evidence_id": "e1", "stage": "REFERENCED_BY_MODEL"},
                {"evidence_id": "e1", "stage": "ACCEPTED_AS_SUPPORT"},
                {"evidence_id": "e2", "stage": "CANDIDATE", "exclusion_reason": "budget"},
            ]
        },
        "claims": [{"id": "c1", "confidence": "HIGH"}],
        "claim_evidence": [{"claim_id": "c1", "evidence_id": "e1"}],
        "investigation": {"actions": [{"status": "SUCCEEDED", "attempts": 1, "result_evidence_ids": ["e1"]}]},
        "limitations": [],
    }
    gold = {
        "version": "fixture-v1",
        "evaluator_only": True,
        "mechanisms": [{"id": "resolver", "components": {"input": ["GetProcAddress"], "consumer": ["LoadLibrary"]}}],
    }
    scorecard = build_evidence_funnel(task_view, gold)
    mechanism = scorecard["mechanisms"][0]
    assert mechanism["available"] == 2
    assert mechanism["candidate"] == 2
    assert mechanism["selected"] == 1
    assert mechanism["delivered"] == 1
    assert mechanism["referenced"] == 1
    assert mechanism["accepted"] == 1
    assert scorecard["summary"]["claim_evidence_traceability"] == 1.0
    assert scorecard["summary"]["action_productivity"] == 1.0


def test_evidence_funnel_rejects_non_evaluator_gold() -> None:
    try:
        build_evidence_funnel({}, {"version": "not-gold"})
    except ValueError as exc:
        assert "evaluator-only" in str(exc)
    else:
        raise AssertionError("non-evaluator Gold must be rejected")


def test_evidence_funnel_reports_thread_recall_and_round8_gate() -> None:
    task_view = {
        "id": "blind-task",
        "evidence": [
            {"id": "e1", "value": {"api": "GetProcAddress"}, "anchor": {}},
            {"id": "e2", "value": {"api": "LoadLibraryA"}, "anchor": {}},
        ],
        "evidence_delivery": {
            "records": [
                {"evidence_id": "e1", "stage": "CANDIDATE"},
                {"evidence_id": "e1", "stage": "SELECTED"},
                {"evidence_id": "e1", "stage": "DELIVERED"},
                {"evidence_id": "e1", "stage": "REFERENCED_BY_MODEL"},
                {"evidence_id": "e1", "stage": "ACCEPTED_AS_SUPPORT"},
            ]
        },
        "claims": [],
        "claim_evidence": [],
        "investigation": {
            "threads": [{"id": "thread-resolver", "question": "resolve API"}],
            "actions": [{"status": "SUCCEEDED", "result_evidence_ids": ["e1"]}],
        },
        "limitations": [],
    }
    gold = {
        "version": "blind-v2",
        "evaluator_only": True,
        "mechanisms": [
            {
                "id": "resolver",
                "components": {"input": ["GetProcAddress"], "consumer": ["LoadLibraryA"]},
                "thread_ids": ["thread-resolver", "thread-consumer"],
            }
        ],
    }
    scorecard = build_evidence_funnel(task_view, gold)
    assert scorecard["summary"]["thread_discovery_recall"] == 0.5
    assert scorecard["summary"]["silent_evidence_loss"] == 1
    assert scorecard["summary"]["refuted_from_absence_errors"] == 0
    assert scorecard["gate"]["status"] == "FAIL"
    assert "delivery_recall" in scorecard["gate"]["failures"]
    assert "silent_evidence_loss" in scorecard["gate"]["failures"]


def test_evidence_funnel_flags_refuted_from_absence() -> None:
    task_view = {
        "evidence": [],
        "evidence_delivery": {"records": []},
        "claims": [
            {"id": "c1", "status": "REFUTED", "statement": "not found", "confidence": "HIGH"}
        ],
        "claim_evidence": [],
        "investigation": {"threads": [], "actions": []},
        "limitations": [],
    }
    gold = {"version": "v1", "evaluator_only": True, "mechanisms": []}
    scorecard = build_evidence_funnel(task_view, gold)
    assert scorecard["summary"]["refuted_from_absence_errors"] == 1


def test_evidence_funnel_supports_multi_row_components_and_semantic_threads() -> None:
    task_view = {
        "evidence": [
            {"id": "e-api", "value": {"api": "OpenProcess"}, "anchor": {"artifact_id": "a1"}},
            {"id": "e-flag", "value": {"name": "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS"}, "anchor": {"artifact_id": "a1"}},
        ],
        "evidence_delivery": {"records": [
            {"evidence_id": "e-api", "stage": "CANDIDATE"},
            {"evidence_id": "e-flag", "stage": "CANDIDATE"},
        ]},
        "claims": [], "claim_evidence": [],
        "investigation": {"threads": [{"id": "runtime-hash", "seed_kind": "ppid-process-chain", "question": "parent process"}], "actions": []},
        "limitations": [],
    }
    gold = {
        "version": "semantic-v1", "evaluator_only": True,
        "mechanisms": [{"id": "ppid", "components": {"chain": ["OpenProcess", "PARENT_PROCESS"]}, "thread_matches": [{"seed_kind": "ppid-process-chain"}]}],
    }
    scorecard = build_evidence_funnel(task_view, gold)
    assert scorecard["mechanisms"][0]["available"] == 2
    assert scorecard["summary"]["thread_discovery_recall"] == 1.0
    assert scorecard["gate"]["status"] == "FAIL"
    assert "delivery_recall" in scorecard["gate"]["failures"]
