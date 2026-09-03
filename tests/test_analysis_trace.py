from __future__ import annotations

from fastapi.testclient import TestClient

from threat_report_agent.analysis_trace import build_analysis_trace
from threat_report_agent.main import create_app


def test_analysis_trace_is_evidence_linked_and_redacted(test_settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        case = client.post("/api/v1/cases", json={"title": "trace"})
        assert case.status_code == 201
        submitted = client.post(
            f"/api/v1/cases/{case.json()['id']}/tasks",
            files={
                "sample": (
                    "network.py",
                    b"import socket\nsocket.create_connection(('example.invalid', 443))",
                    "text/x-python",
                )
            },
        )
        assert submitted.status_code == 202
        task_id = submitted.json()["task_id"]
        response = client.get(f"/api/v1/tasks/{task_id}/analysis-trace")

    assert response.status_code == 200, response.text
    trace = response.json()
    assert trace["task_id"] == task_id
    assert trace["disclosure"]["private_chain_of_thought"] == "withheld"
    assert trace["steps"]
    assert {step["phase"] for step in trace["steps"]} >= {
        "intake",
        "extraction",
        "evidence",
        "inference",
    }
    assert any(link["relation"] == "SUPPORTED_BY" for link in trace["links"])
    assert any(link["relation"] == "OBSERVED" for link in trace["links"])
    serialized = str(trace)
    assert "messages" not in serialized
    assert "raw_response" not in serialized
    assert "test-key" not in serialized


def test_analysis_trace_keeps_model_status_without_payload() -> None:
    trace = build_analysis_trace(
        task_id="task-1",
        trace_id="trace-1",
        events=[
            {
                "event_type": "agent.run.started",
                "actor": "agent-runtime",
                "object_type": "AgentRun",
                "object_id": "run-1",
                "payload": {"run_id": "run-1"},
                "chain_sequence": 1,
                "created_at": "2026-08-23T00:00:00+00:00",
            },
            {
                "event_type": "agent.run.failed",
                "actor": "agent-runtime",
                "object_type": "AgentRun",
                "object_id": "run-1",
                "payload": {"error": "MODEL_PROVIDERS_UNAVAILABLE"},
                "chain_sequence": 2,
                "created_at": "2026-08-23T00:00:01+00:00",
            },
        ],
    )
    agent_steps = [step for step in trace["steps"] if step["phase"] == "agent"]
    assert agent_steps
    assert any(step["event_type"] == "agent.run.started" for step in agent_steps)
    assert all("messages" not in step["details"] for step in agent_steps)


def test_analysis_trace_exposes_methodology_decisions_without_raw_profile_payload() -> None:
    trace = build_analysis_trace(
        task_id="task-2",
        trace_id="trace-2",
        events=[
            {
                "event_type": "methodology.profile_generated",
                "actor": "signal-extractor",
                "object_type": "Evidence",
                "object_id": "profile-1",
                "payload": {
                    "artifact_id": "artifact-1",
                    "dimensions": {"loading_chain": 1},
                    "knowledge_sha256": "a" * 64,
                    "expected_verdict": "INCONCLUSIVE",
                    "actual_verdict": "EXCLUDE_NSA",
                },
                "chain_sequence": 1,
            },
            {
                "event_type": "methodology.fact_matched",
                "actor": "knowledge-fact-matcher",
                "object_type": "Claim",
                "object_id": "claim-1",
                "payload": {"fact_id": "FACT-1", "status": "MISMATCH", "evidence_ids": ["e1"]},
                "chain_sequence": 2,
            },
        ],
    )
    assert {step["phase"] for step in trace["steps"]} == {"signal_extraction", "attribution"}
    assert trace["steps"][0]["details"]["knowledge_sha256"] == "a" * 64
    assert "raw_profile_payload" not in str(trace)


def test_analysis_trace_exposes_structured_investigation_state_without_cot() -> None:
    trace = build_analysis_trace(
        task_id="task-3",
        trace_id="trace-3",
        events=[],
        strategy_snapshot={
            "investigation": {
                "current_state": "INVESTIGATING",
                "last_question": "Which chain is supported?",
                "last_transition": "HYPOTHESIZING->INVESTIGATING",
                "threads": [{"id": "thread-1", "state": "INVESTIGATING"}],
                "hypotheses": [{"id": "h-1", "status": "OPEN"}],
                "mechanisms": [{"id": "m-1", "status": "UNKNOWN"}],
                "seed_rankings": [{"artifact_id": "a-1", "priority": 1}],
                "action_proposals": [{"tool_name": "pe-parser"}],
                "context_policy": {"max_bytes": 1024},
                "private_chain_of_thought": True,
            }
        },
    )
    assert trace["investigation"]["current_state"] == "INVESTIGATING"
    assert trace["investigation"]["last_question"] == "Which chain is supported?"
    assert trace["investigation"]["private_chain_of_thought"] is False


def test_analysis_trace_exposes_evidence_funnel_without_payloads() -> None:
    trace = build_analysis_trace(
        task_id="task-4",
        trace_id="trace-4",
        events=[],
        evidence_delivery=[
            {
                "turn_id": "turn-1",
                "thread_id": "thread-1",
                "evidence_id": "e-1",
                "stage": "CANDIDATE",
                "details": {"retrieval_request": {"artifact_id": "a-1"}},
            },
            {
                "turn_id": "turn-1",
                "thread_id": "thread-1",
                "evidence_id": "e-1",
                "stage": "DELIVERED",
            },
        ],
    )
    assert trace["evidence_funnel"]["counts"] == {"CANDIDATE": 1, "DELIVERED": 1}
    assert trace["evidence_funnel"]["turns"][0]["counts"]["DELIVERED"] == 1
    assert "messages" not in str(trace)


def test_analysis_trace_exposes_each_turn_context_manifest() -> None:
    trace = build_analysis_trace(
        task_id="task-manifest",
        trace_id="trace-manifest",
        events=[],
        analysis_turns=[
            {
                "id": "turn-record",
                "turn_id": "task:planning:1",
                "context_manifest": [{"evidence_id": "e1", "artifact_id": "a1", "kind": "xref"}],
            }
        ],
    )
    assert trace["analysis_turns"][0]["context_manifest"][0]["evidence_id"] == "e1"


def test_analysis_trace_builds_mechanism_effectiveness_trace_without_model_payload() -> None:
    trace = build_analysis_trace(
        task_id="task-mechanism-trace",
        trace_id="trace-mechanism-trace",
        events=[
            {
                "event_type": "report.generated",
                "object_type": "ReportRevision",
                "object_id": "revision-1",
                "payload": {"revision_id": "revision-1"},
                "chain_sequence": 4,
            }
        ],
        analysis_turns=[
            {
                "thread_id": "thread-1",
                "turn_id": "turn-1",
                "phase": "mechanism-investigation",
                "hypothesis_before": [{"id": "hyp-1", "status": "OPEN"}],
                "action_proposals": [
                    {
                        "id": "action-1",
                        "origin": "model",
                        "action_type": "GET_XREFS_TO",
                        "target_selector": {"target": "GetProcAddress"},
                    }
                ],
                "tool_run_ids": ["tool-1"],
                "new_evidence_ids": ["evidence-1"],
                "verifier_result": {"status": "SUPPORTED", "evidence_ids": ["evidence-1"]},
                "hypothesis_after": [{"id": "hyp-1", "status": "SUPPORTED"}],
                "mechanism_state": "EVIDENCE_UPDATED",
            }
        ],
        analysis_turn_results=[
            {
                "turn_id": "turn-1",
                "thread_id": "thread-1",
                "completed_actions": [
                    {
                        "action_type": "GET_XREFS_TO",
                        "origin": "model",
                        "new_evidence_ids": ["evidence-1"],
                    }
                ],
                "tool_run_ids": ["tool-1"],
                "new_evidence_ids": ["evidence-1"],
                "verifier_result": {"status": "SUPPORTED"},
                "hypothesis_after": [{"id": "hyp-1", "status": "SUPPORTED"}],
                "mechanism_state": "CLAIM_READY",
            }
        ],
        strategy_snapshot={
            "investigation": {
                "seed_rankings": [
                    {
                        "seed_id": "seed-1",
                        "artifact_id": "artifact-1",
                        "mechanism_type": "DYNAMIC_API_RESOLUTION",
                        "question": "Which exports are resolved and consumed?",
                        "evidence_ids": ["evidence-0"],
                    }
                ],
                "hypotheses": [
                    {
                        "id": "hyp-1",
                        "mechanism_id": "mechanism-1",
                        "statement": "The resolver supplies an indirect API table.",
                        "status": "SUPPORTED",
                    },
                    {
                        "id": "hyp-alt",
                        "mechanism_id": "mechanism-1",
                        "statement": "The imports are statically linked only.",
                        "status": "REJECTED",
                    },
                ],
                "mechanisms": [
                    {
                        "id": "mechanism-1",
                        "artifact_id": "artifact-1",
                        "mechanism_type": "DYNAMIC_API_RESOLUTION",
                        "status": "SUPPORTED",
                    }
                ],
                "runtime": {
                    "gates": [
                        {
                            "mechanism_id": "mechanism-1",
                            "status": "SUPPORTED",
                            "evidence_ids": ["evidence-1"],
                        }
                    ]
                },
            }
        },
    )

    rows = trace["mechanism_effectiveness_traces"]
    assert len(rows) == 1
    row = rows[0]
    assert row["mechanism_id"] == "mechanism-1"
    assert row["seed"]["seed_id"] == "seed-1"
    assert row["question"] == "Which exports are resolved and consumed?"
    assert {item["id"] for item in row["competing_hypotheses"]} == {"hyp-1", "hyp-alt"}
    assert row["action_proposals"][0]["origin"] == "model"
    assert row["new_evidence_ids"] == ["evidence-1"]
    assert row["evidence_delta"]["count"] == 1
    assert row["verifier_result"]["status"] == "SUPPORTED"
    assert row["claim_gate"]["status"] == "SUPPORTED"
    assert row["report_projection"]["revision_ids"] == ["revision-1"]
    serialized = str(row)
    assert "raw_response" not in serialized
    assert "private_chain_of_thought" not in serialized
