from threat_report_agent.deep_analysis_quality import (
    critic_pass,
    deep_analysis_metrics,
    no_new_evidence_autopsy,
    report_depth_score,
)


def _closed() -> dict[str, object]:
    return {
        "type": "mechanism_candidate",
        "mechanism_id": "m1",
        "status": "VERIFIED",
        "target": "resolver@0x1000",
        "inputs": ["module and API hash"],
        "transformation_or_control": ["enumerate exports -> DJB2 hash -> compare"],
        "conditions": ["hash matches target"],
        "outputs": ["function pointer"],
        "consumers": ["indirect call site"],
        "side_effects": ["dynamic API resolution"],
        "evidence_ids": ["e1", "e2"],
        "verifier": {"status": "VERIFIED"},
    }


def test_report_depth_scores_how_and_flow_from_closed_mechanism() -> None:
    result = report_depth_score({"modules": [{"rows": [_closed(), {"type": "mechanism_chain", "rendered": "a -> b -> c"}]}]})
    assert result["score"] >= 50
    assert result["closed_mechanisms"] == 1


def test_critic_blocks_unverified_strong_claim() -> None:
    result = critic_pass({"modules": [{"rows": [{"type": "analytical_claim", "statement": "active C2 confirmed", "status": "CANDIDATE"}]}]})
    assert result["status"] == "BLOCKED"
    assert result["unsupported_claims"]


def test_metrics_keep_candidate_noise_and_seed_closure_explicit() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": [_closed(), {"type": "mechanism_candidate", "status": "CANDIDATE"}]}]},
        mechanisms=[_closed()],
        investigation_threads=[{"state": "CLAIM_READY"}, {"state": "INVESTIGATING"}],
        investigation_actions=[{"result_evidence_ids": ["e1"]}, {"result_evidence_ids": []}],
    )
    assert result["high_value_seed_closure_rate"] == 0.5
    assert result["action_productivity_rate"] == 0.5
    assert result["static_only"] is True


def test_metrics_fall_back_to_report_mechanisms_when_projection_omits_them() -> None:
    document = {
        "modules": [{
            "rows": [
                _closed(),
                {"type": "mechanism_candidate", "mechanism_id": "m-open", "status": "CANDIDATE", "unknowns": ["consumer"]},
            ]
        }]
    }

    result = deep_analysis_metrics(document=document)

    assert result["candidate_noise_ratio"] == 0.5
    assert result["critical_mechanism_closure_rate"] == 0.5


def test_readiness_blocks_when_actions_are_unproductive_or_mechanisms_open() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": [_closed()]}]},
        mechanisms=[{**_closed(), "status": "UNKNOWN"}],
        investigation_threads=[{"state": "CLAIM_READY"}],
        investigation_actions=[{"result_evidence_ids": []}],
    )
    assert result["readiness"] == "BOUNDED_WITH_LIMITATIONS"
    assert "action_productivity" in result["readiness_blockers"]
    assert "critical_mechanism_closure" in result["readiness_blockers"]


def test_critic_reports_missing_alternatives_and_unknown_fields() -> None:
    result = critic_pass({"modules": [{"rows": [{
        "type": "mechanism_candidate", "mechanism_id": "m-open", "status": "SUPPORTED",
        "target": "VirtualProtect", "evidence_ids": ["e1"],
        "verifier": {"status": "VERIFIED"},
    }]}]})
    assert "m-open" in result["alternative_hypotheses_not_ruled_out"]
    assert "m-open" in result["static_wording_violations"]


def test_action_productivity_ignores_referenced_ids_when_outcome_has_no_gain() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_actions=[
            {"outcome": "NO_NEW_EVIDENCE", "result_evidence_ids": ["stale"]},
            {"outcome": "PRODUCTIVE", "new_evidence_ids": ["new"]},
        ],
    )
    assert result["action_productivity_rate"] == 0.5


def test_model_action_productivity_excludes_deterministic_fallback_actions() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_actions=[
            {"origin": "model", "status": "SUCCEEDED", "result_evidence_ids": ["e-model"]},
            {"origin": "model", "status": "FAILED", "error": "NO_NEW_EVIDENCE"},
            {
                "origin": "deterministic_fallback",
                "status": "SUCCEEDED",
                "result_evidence_ids": ["e-fallback"],
            },
        ],
    )
    assert result["accepted_model_actions"] == 2
    assert result["useful_model_actions"] == 1
    assert result["model_action_productivity_rate"] == 0.5


def test_explicit_fallback_origin_overrides_planner_metadata() -> None:
    """Fallback actions must not earn model credit from copied planner fields."""
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_actions=[
            {
                "origin": "deterministic_fallback",
                "scheduler": "model_plan",
                "planner_turn_id": "turn-copied-from-model",
                "status": "SUCCEEDED",
                "new_evidence_ids": ["e-fallback"],
            }
        ],
    )
    assert result["accepted_model_actions"] == 0
    assert result["useful_model_actions"] == 0
    assert result["model_action_productivity_rate"] == 0.0


def test_no_new_evidence_autopsy_is_complete_and_uses_a_bounded_cause() -> None:
    duplicate = no_new_evidence_autopsy(
        {
            "action_type": "GET_XREFS_TO",
            "target_selector": {"target": "GetProcAddress"},
            "dedupe_key": "action-key",
            "artifact_boundary": "artifact-1",
            "existing_evidence_ids": ["e-existing"],
        }
    )
    assert duplicate["category"] == "EVIDENCE_ALREADY_PRESENT"
    assert duplicate["target_selector"] == {"target": "GetProcAddress"}
    assert duplicate["target"] == "GetProcAddress"
    assert duplicate["dedupe_key"] == "action-key"
    assert duplicate["artifact_boundary"] == "artifact-1"
    assert duplicate["next_action"] == "REUSE_EXISTING_EVIDENCE"

    assert no_new_evidence_autopsy({"target_selector": {}})["category"] == "SELECTOR_ERROR"
    assert no_new_evidence_autopsy({"target_selector": {"target": "x"}, "target_resolved": False})["category"] == "TARGET_ERROR"
    assert no_new_evidence_autopsy({"target_selector": {"target": "x"}, "dedupe_suppressed": True})["category"] == "DEDUP_SUPPRESSED"
    assert no_new_evidence_autopsy({"target_selector": {"target": "x"}, "failure_interpretation": "STATIC_BOUNDARY"})["category"] == "STATIC_BOUNDARY"
    assert no_new_evidence_autopsy({"target_selector": {"target": "x"}, "tool_status": "FAILED"})["category"] == "TOOL_EXTRACTION_GAP"
    assert no_new_evidence_autopsy({"target_selector": {"target": "x"}, "source_evidence_ids": []})["category"] == "LOW_INFORMATION_ACTION"


def test_model_productivity_credits_verified_hypothesis_and_mechanism_deltas() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_actions=[
            {
                "origin": "model",
                "status": "SUCCEEDED",
                "outcome": "HYPOTHESIS_ELIMINATED",
                "hypothesis_delta": {"eliminated_hypothesis_ids": ["alternative-1"]},
            },
            {
                "origin": "model",
                "status": "SUCCEEDED",
                "outcome": "MECHANISM_FIELDS_COMPLETED",
                "mechanism_delta": {"completed_fields": ["consumer"]},
            },
            {
                "origin": "model",
                "status": "SUCCEEDED",
                "new_evidence_ids": ["e-model"],
            },
            {
                "origin": "model",
                "status": "FAILED",
                "error": "NO_NEW_EVIDENCE",
                "target_selector": {"target": "missing"},
                "tool_status": "FAILED",
            },
            {
                "origin": "deterministic_fallback",
                "status": "SUCCEEDED",
                "new_evidence_ids": ["e-fallback"],
            },
        ],
    )
    assert result["accepted_model_actions"] == 4
    assert result["useful_model_actions"] == 3
    assert result["model_action_productivity_rate"] == 0.75
    assert result["no_new_evidence_autopsy"][0]["category"] == "TOOL_EXTRACTION_GAP"
