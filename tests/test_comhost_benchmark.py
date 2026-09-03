import json
from pathlib import Path

from benchmarks.comhost_differential import evaluate_task_view
from benchmarks.semantic_differential import build_semantic_differential


def test_comhost_gold_is_evaluator_only_and_scores_critical_fixture() -> None:
    gold = json.loads(Path("benchmarks/gold/comhost-critical-v1.json").read_text("utf-8"))
    assert gold["evaluator_only"] is True
    task = {
        "id": "comhost-fixture",
        "evidence": [
            {"id": "e1", "value": "GetProcAddress function pointer WinHTTP", "anchor": {}},
            {"id": "e2", "value": "https WinHttpSendRequest WinHttpReceiveResponse", "anchor": {}},
            {"id": "e3", "value": "shell pipe output capture", "anchor": {}},
            {"id": "e4", "value": "EtwEventWrite ntdll.dll VirtualProtect 33 C0 C3 FlushInstructionCache", "anchor": {}},
        ],
        "evidence_delivery": {"records": []},
        "claims": [], "claim_evidence": [], "investigation": {"actions": []}, "limitations": [],
    }
    result = evaluate_task_view(task)
    assert result["evaluator_only"] is True
    assert result["sample"] == "ComHost"
    assert result["gold_version"] == "comhost-critical-v1"


def test_evaluator_scores_unexcluded_evidence_when_retrieval_contains_excluded_lead() -> None:
    """A rejected duplicate must not hide a valid evidence row for the same component."""
    task = {
        "id": "mixed-retrieval",
        "evidence": [
            {"id": "excluded", "value": "WinHttpSendRequest", "anchor": {}},
            {"id": "valid", "value": "WinHttpSendRequest", "anchor": {}},
        ],
        "evidence_delivery": {
            "records": [
                {
                    "evidence_id": "excluded",
                    "stage": "CANDIDATE",
                    "exclusion_reason": "low_relevance",
                }
            ]
        },
        "claims": [],
        "investigation": {"actions": []},
        "limitations": [],
    }
    gold = {
        "version": "test",
        "evaluator_only": True,
        "mechanisms": [
            {"id": "m", "components": {"consumer": ["WinHttpSendRequest"]}}
        ],
    }
    result = build_semantic_differential(task, gold)
    component = result["mechanisms"][0]["components"][6]
    assert component["status"] == "SUPPORTED"
    assert component["evidence_ids"] == ["valid"]


def test_evaluator_keeps_all_excluded_matches_as_retrieval_failure() -> None:
    task = {
        "id": "all-excluded",
        "evidence": [{"id": "excluded", "value": "WinHttpSendRequest", "anchor": {}}],
        "evidence_delivery": {
            "records": [
                {
                    "evidence_id": "excluded",
                    "stage": "CANDIDATE",
                    "exclusion_reason": "budget",
                }
            ]
        },
        "claims": [],
        "investigation": {"actions": []},
        "limitations": [],
    }
    gold = {
        "version": "test",
        "evaluator_only": True,
        "mechanisms": [
            {"id": "m", "components": {"consumer": ["WinHttpSendRequest"]}}
        ],
    }
    result = build_semantic_differential(task, gold)
    component = result["mechanisms"][0]["components"][6]
    assert component["status"] == "UNKNOWN"
    assert component["reason"] == "retrieval_failure"


def test_semantic_differential_does_not_promote_explicitly_unobserved_output() -> None:
    """A limitation such as ``decoded output not observed`` stays UNKNOWN."""
    task_view = {
        "id": "negative-decoder-fixture",
        "evidence": [
            {
                "id": "candidate",
                "kind": "mechanism_decode_window",
                "value": "decoded output not observed; verification unverified",
                "anchor": {"function_entry": "0x1000"},
            }
        ],
        "investigation": {"actions": [{"id": "a1"}]},
        "claims": [{"id": "c1"}],
        "limitations": [],
    }
    gold = {
        "version": "negative",
        "mechanisms": [
            {"id": "decoder", "components": {"output": ["decoded", "output"]}}
        ],
    }

    result = build_semantic_differential(task_view, gold)
    mechanism = result["mechanisms"][0]
    assert mechanism["status"] == "UNKNOWN"
    output = next(item for item in mechanism["components"] if item["component"] == "output")
    assert output["status"] == "UNKNOWN"
