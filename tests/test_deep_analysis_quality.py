from threat_report_agent.deep_analysis_quality import (
    apply_adversarial_downgrades,
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


def test_report_depth_scores_only_verified_specialist_link() -> None:
    specialist_link = {**_closed(), "type": "mechanism_link"}
    candidate_link = {**specialist_link, "mechanism_id": "m2", "status": "CANDIDATE"}

    result = report_depth_score(
        {"modules": [{"rows": [specialist_link, candidate_link]}]}
    )

    assert result["closed_mechanisms"] == 1
    assert result["candidate_mechanisms"] == 1
    assert result["dimensions"]["mechanism_how"] == 25


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


def test_metrics_use_visible_projection_metadata_over_legacy_mechanism_rows() -> None:
    """Visible candidate metadata must drive unknown/limitation quality checks."""
    visible = {
        "type": "mechanism_observation",
        "mechanism_id": "m-open",
        "status": "CANDIDATE",
        "target": "resolver@0x2000",
        "inputs": ["encoded API name"],
        "transformation_or_control": ["bounded decode candidate"],
        "conditions": ["static branch observed"],
        "outputs": ["possible function pointer"],
        "consumers": ["consumer not recovered"],
        "evidence_ids": ["e-open"],
        "unknowns": ["runtime reachability", "decoded consumer"],
        "limitations": ["static-only evidence"],
    }

    result = deep_analysis_metrics(
        document={"modules": [{"rows": [visible]}]},
        # This is the legacy ORM projection: it has the status but not the
        # analyst-facing unknowns/limitations fields.
        mechanisms=[{"id": "m-open", "status": "UNKNOWN"}],
        mechanism_projections=[visible],
    )

    assert result["unknown_recorded_rate"] == 1.0
    assert "unknowns" not in result["readiness_blockers"]


def test_suppressed_projection_does_not_lower_quality_metrics() -> None:
    """Presentation-only duplicate suppression must not count as open noise."""
    closed = _closed()
    suppressed = {
        "type": "mechanism_observation",
        "mechanism_id": "duplicate-open",
        "status": "CANDIDATE",
        "target": "resolver@0x1000",
        "inputs": [],
        "transformation_or_control": [],
        "outputs": [],
        "consumers": [],
        "evidence_ids": ["duplicate-evidence"],
        "unknowns": ["consumer not recovered"],
        "suppressed_by_verified": True,
    }

    baseline = deep_analysis_metrics(
        document={"modules": [{"rows": [closed]}]},
        mechanisms=[closed],
    )
    result = deep_analysis_metrics(
        document={"modules": [{"rows": [closed]}]},
        mechanisms=[closed],
        mechanism_projections=[closed, suppressed],
    )

    assert result["mechanism_completeness"] == baseline["mechanism_completeness"]
    assert result["critical_mechanism_closure_rate"] == baseline["critical_mechanism_closure_rate"]
    assert result["candidate_noise_ratio"] == 0.0
    assert result["unknown_recorded_rate"] == 1.0
    assert "candidate_noise" not in result["readiness_blockers"]
    assert "critical_mechanism_closure" not in result["readiness_blockers"]


def test_suppressed_rows_are_ignored_even_if_snapshot_contains_them() -> None:
    """A replayed snapshot cannot inflate candidate noise with hidden rows."""
    closed = _closed()
    hidden = {
        "type": "mechanism_link",
        "mechanism_id": "hidden-link",
        "status": "CANDIDATE",
        "evidence_ids": ["e-hidden"],
        "suppressed_by_verified": True,
        "unknowns": ["runtime reachability"],
    }
    result = deep_analysis_metrics(
        document={"modules": [{"rows": [closed, hidden]}]},
    )

    assert result["candidate_noise_ratio"] == 0.0
    assert result["critical_mechanism_closure_rate"] == 1.0
    assert result["unknown_recorded_rate"] == 1.0


def test_metrics_count_all_visible_unresolved_mechanism_projections_as_candidate_noise() -> None:
    document = {
        "modules": [{
            "rows": [
                _closed(),
                {
                    "type": "mechanism_observation",
                    "mechanism_id": "m-observed",
                    "mechanism_type": "DECODE_TRANSFORM",
                    "status": "CANDIDATE",
                    "evidence_ids": ["e-observed"],
                    "unknowns": ["consumer"],
                },
                {
                    "type": "mechanism_link",
                    "mechanism_id": "m-linked",
                    "mechanism_type": "HTTP_DOWNLOAD",
                    "status": "CANDIDATE",
                    "evidence_ids": ["e-linked"],
                    "unknowns": ["endpoint"],
                },
            ]
        }]
    }

    result = deep_analysis_metrics(document=document)

    assert result["candidate_noise_ratio"] == 0.6667
    assert "candidate_noise" in result["readiness_blockers"]


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


def test_critic_blocks_common_behavior_overclaims_with_structured_rules() -> None:
    result = critic_pass({"modules": [{"rows": [
        {
            "type": "security_finding",
            "mechanism_id": "network-cooccurrence",
            "status": "SUPPORTED",
            "statement": "active C2 beacon confirmed from HTTP request",
            "target": "HTTP endpoint",
            "inputs": ["URL"],
            "transformation_or_control": ["HTTP request"],
            "conditions": ["request succeeds"],
            "outputs": ["response"],
            "consumers": ["buffer"],
            "evidence_ids": ["e-http"],
            "alternative_hypotheses": ["one-shot update check"],
            "verifier": {"status": "VERIFIED"},
        },
        {
            "type": "security_finding",
            "mechanism_id": "registry-cooccurrence",
            "status": "SUPPORTED",
            "statement": "registry persistence is established",
            "mechanism_type": "REGISTRY_CONFIGURATION",
            "target": "registry",
            "inputs": ["key"],
            "transformation_or_control": ["RegSetValue"],
            "conditions": ["call returns"],
            "outputs": ["value"],
            "consumers": ["unknown"],
            "evidence_ids": ["e-reg"],
            "alternative_hypotheses": ["configuration write"],
            "verifier": {"status": "VERIFIED"},
        },
    ]}]})

    assert result["status"] == "BLOCKED"
    rules = {item["rule_id"] for item in result["overclaim_checks"]}
    assert "NETWORK_IS_C2" in rules
    assert "REGISTRY_IS_PERSISTENCE" in rules


def test_metrics_records_s4_orchestration_boundary_for_each_thread() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_threads=[
            {"id": "closed", "state": "CLAIM_READY", "question": "q1", "evidence_ids": ["e1"], "action_ids": ["a1"]},
            {"id": "open", "state": "INVESTIGATING", "question": "q2", "evidence_ids": ["e2"], "action_ids": ["a2"]},
            {"id": "blocked", "state": "BLOCKED", "question": "q3", "evidence_ids": [], "action_ids": ["a3"]},
        ],
        investigation_actions=[
            {"id": "a1", "status": "SUCCEEDED", "result_evidence_ids": ["e1"]},
            {"id": "a2", "status": "SUCCEEDED", "result_evidence_ids": []},
            {"id": "a3", "status": "FAILED", "error": "STATIC_BOUNDARY"},
        ],
    )

    by_id = {item["thread_id"]: item for item in result["s4_orchestration"]}
    assert by_id["closed"]["status"] == "CLOSED"
    assert by_id["open"]["status"] == "BLOCKED"
    assert by_id["blocked"]["status"] == "BLOCKED"
    assert "s4_orchestration" in result["readiness_blockers"]


def test_metrics_reject_vacuous_s4_closed_with_empty_attempts() -> None:
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_threads=[
            {
                "id": "vacuous",
                "state": "INVESTIGATING",
                "question": "high-value decode",
                "evidence_ids": [],
                "action_ids": [],
                "s_ladder": {
                    "s1_context": "NOT_APPLICABLE",
                    "s2_dataflow": "NOT_APPLICABLE",
                    "s3_consumer": "NOT_APPLICABLE",
                    "s4_orchestration": "CLOSED",
                    "attempted_action_types": [],
                    "required_action_types": [],
                },
            },
            {
                "id": "explicit-na",
                "state": "INVESTIGATING",
                "question": "string-only contract",
                "evidence_ids": [],
                "action_ids": [],
                "s_ladder": {
                    "s1_context": "NOT_APPLICABLE",
                    "s2_dataflow": "NOT_APPLICABLE",
                    "s3_consumer": "NOT_APPLICABLE",
                    "s4_orchestration": "CLOSED",
                    "attempted_action_types": [],
                    "required_action_types": ["DECODE_STRING"],
                },
            },
            {
                "id": "attempted",
                "state": "INVESTIGATING",
                "question": "context recovered",
                "evidence_ids": ["e1"],
                "action_ids": ["a1"],
                "s_ladder": {
                    "s1_context": "ATTEMPTED",
                    "s2_dataflow": "NOT_APPLICABLE",
                    "s3_consumer": "NOT_APPLICABLE",
                    "s4_orchestration": "CLOSED",
                    "attempted_action_types": ["GET_FUNCTION"],
                    "required_action_types": [],
                },
            },
        ],
        investigation_actions=[{"id": "a1", "status": "SUCCEEDED", "result_evidence_ids": ["e1"]}],
    )
    by_id = {item["thread_id"]: item for item in result["s4_orchestration"]}
    assert by_id["vacuous"]["status"] in {"BLOCKED", "OPEN"}
    assert by_id["vacuous"]["status"] != "CLOSED"
    assert by_id["explicit-na"]["status"] == "CLOSED"
    assert by_id["attempted"]["status"] == "CLOSED"
    assert "s4_orchestration" in result["readiness_blockers"]


def test_metrics_persist_claim_ready_without_trace_is_s4_closed() -> None:
    """Kunglao leftover remainder: persist HOW skip is report CLOSED, not 再深入."""
    result = deep_analysis_metrics(
        document={"modules": [{"rows": []}]},
        investigation_threads=[
            {
                "id": "persist-process",
                "state": "CLAIM_READY",
                "question": "How does CreateProcess start Foxit?",
                "evidence_ids": ["e-process"],
                "action_ids": [],
            },
            {
                "id": "http-unknown",
                "state": "UNKNOWN",
                "question": "Which WinHTTP call sends the beacon?",
                "evidence_ids": ["e-http-string"],
                "action_ids": [],
            },
        ],
        investigation_actions=[],
    )
    by_id = {item["thread_id"]: item for item in result["s4_orchestration"]}
    assert by_id["persist-process"]["status"] == "CLOSED"
    assert "leftover remainder" in by_id["persist-process"]["reason"]
    assert by_id["http-unknown"]["status"] == "RECORDED"
    assert by_id["http-unknown"]["status"] != "BLOCKED"
    assert "s4_orchestration" not in result["readiness_blockers"]


def test_adversarial_overclaim_downgrades_closed_findings() -> None:
    rows = [
        {
            "type": "behavior_finding",
            "finding_id": "behavior-finding:c2",
            "status": "SUPPORTED",
            "finding_status": "SUPPORTED",
            "verdict": "SUPPORTED",
            "what": "active C2 beacon",
            "how": "HTTP request",
            "target": "endpoint",
            "inputs": ["url"],
            "transformation_or_control": ["HTTP"],
            "conditions": ["request"],
            "outputs": ["bytes"],
            "consumers": ["buffer"],
            "evidence_ids": ["e1"],
        }
    ]
    downgraded, checks = apply_adversarial_downgrades(rows)
    assert any(item["rule_id"] == "NETWORK_IS_C2" for item in checks)
    assert downgraded[0]["status"] == "CANDIDATE"
    assert downgraded[0]["finding_status"] == "CANDIDATE"
    assert downgraded[0]["adversarial_downgrade"] is True
    assert any("adversarial overclaim" in str(item) for item in downgraded[0]["unknowns"])


def test_adversarial_gate_blocks_same_artifact_injects_self_loop() -> None:
    rows = [
        {
            "type": "behavior_relation",
            "relation_id": "rel-self-injects",
            "relation_type": "INJECTS",
            "source_artifact_id": "artifact-1",
            "target_artifact_id": "artifact-1",
            "source_object": "sample.dll",
            "target_object": "sample.dll",
            "status": "INFERRED",
            "validation_status": "INFERRED",
            "severity": "HIGH",
            "claim_id": "c-inject",
            "evidence_ids": ["e1"],
        }
    ]
    downgraded, checks = apply_adversarial_downgrades(rows)
    assert any(item["rule_id"] == "INJECTS_SELF_LOOP" and item["status"] == "BLOCKED" for item in checks)
    assert downgraded[0]["status"] in {"CANDIDATE", "UNKNOWN"}
    assert downgraded[0]["validation_status"] in {"CANDIDATE", "UNKNOWN"}
    assert downgraded[0]["status"] not in {"VERIFIED", "SUPPORTED", "CONFIRMED", "INFERRED"}
    assert str(downgraded[0].get("severity") or "").upper() != "HIGH"
    assert downgraded[0]["adversarial_downgrade"] is True


def test_adversarial_gate_blocks_same_process_apc_without_cross_process() -> None:
    rows = [
        {
            "type": "behavior_finding",
            "finding_id": "behavior-finding:apc",
            "status": "SUPPORTED",
            "finding_status": "SUPPORTED",
            "verdict": "SUPPORTED",
            "severity": "HIGH",
            "what": "QueueUserAPC",
            "how": "same-process APC queued to the current thread",
            "target": "current process thread",
            "inputs": ["APC routine"],
            "transformation_or_control": ["QueueUserAPC"],
            "conditions": ["thread alertable"],
            "outputs": ["queued APC"],
            "consumers": ["current thread"],
            "evidence_ids": ["e-apc"],
        }
    ]
    downgraded, checks = apply_adversarial_downgrades(rows)
    assert any(item["rule_id"] == "PROCESS_API_IS_INJECTION" and item["status"] == "BLOCKED" for item in checks)
    assert downgraded[0]["status"] == "CANDIDATE"
    assert downgraded[0]["finding_status"] == "CANDIDATE"
    assert str(downgraded[0].get("severity") or "").upper() != "HIGH"
    assert downgraded[0]["adversarial_downgrade"] is True

