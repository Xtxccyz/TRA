"""Build a safe, structured view of an analysis run.

The trace is deliberately a system-level explanation.  It describes the
observable workflow and its evidence links; it never exposes model prompts,
raw responses, secrets, or private chain-of-thought.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from threat_report_agent.deep_analysis_quality import action_is_productive


_PHASES: dict[str, str] = {
    "analysis_task.created": "intake",
    "analysis_task.started": "intake",
    "analysis_task.succeeded": "completion",
    "analysis_task.failed": "completion",
    "analysis_task.cancelled": "completion",
    "gate.created": "gate",
    "gate.approved": "gate",
    "gate.rejected": "gate",
    "gate.approval_failed": "gate",
    "artifact.registered": "triage",
    "triage.decided": "triage",
    "tool_run.started": "extraction",
    "tool_run.completed": "extraction",
    "orchestration.action_dequeued": "scheduling",
    "orchestration.plan_created": "scheduling",
    "orchestration.plan_proposed": "scheduling",
    "investigation.thread_seeded": "scheduling",
    "evidence.recorded": "evidence",
    "claim.validation": "validation",
    "claim.created": "inference",
    "agent.run.started": "agent",
    "agent.context.checked": "agent",
    "agent.run.completed": "agent",
    "agent.run.failed": "agent",
    "agent.run.cancelled": "agent",
    "model_call.completed": "agent",
    "model_call.failed": "agent",
    "report.generated": "report",
    "report.recomposed": "report",
    "report.manually_edited": "report",
    "audit.sealed": "audit",
    "methodology.profile_generated": "signal_extraction",
    "methodology.fact_matched": "attribution",
    "evidence.delivery_traced": "evidence",
    "blind_run.prepared": "blind_run",
    "blind_run.frozen": "blind_run",
}

_SUMMARIES: dict[str, str] = {
    "analysis_task.created": "冻结输入快照并创建分析任务",
    "analysis_task.started": "开始执行静态分析计划",
    "analysis_task.succeeded": "分析任务完成",
    "analysis_task.failed": "分析任务失败并记录限制",
    "analysis_task.cancelled": "分析任务被取消",
    "gate.created": "创建人工输入审查点",
    "gate.approved": "人工审查通过，继续分析",
    "gate.rejected": "人工审查拒绝，停止该分支",
    "gate.approval_failed": "人工审查凭据校验失败",
    "artifact.registered": "登记不可变 Artifact 并保留哈希",
    "triage.decided": "分诊 Agent 判定 Artifact 角色和覆盖义务",
    "tool_run.started": "启动受策略约束的静态工具",
    "tool_run.completed": "静态工具完成并产出工具结果",
    "evidence.recorded": "将工具观察转换为 Evidence",
    "claim.validation": "校验证据引用和 Claim 边界",
    "claim.created": "Agent 形成带证据引用的 Claim",
    "agent.run.started": "Agent 运行开始",
    "agent.context.checked": "Agent 上下文预算和证据范围检查完成",
    "agent.run.completed": "Agent 运行完成并返回结构化结果",
    "agent.run.failed": "Agent 运行失败，保留确定性结果并进入降级路径",
    "agent.run.cancelled": "Agent 运行取消，保留已提交的确定性结果",
    "model_call.completed": "模型调用结果已持久化为可审计记录",
    "model_call.failed": "模型调用失败并记录失败原因",
    "report.generated": "基于不可变 Snapshot 生成报告",
    "report.recomposed": "按选择的模块重组报告",
    "report.manually_edited": "保存人工编辑后的报告版本",
    "audit.sealed": "审计链生成封存点",
}

_SUMMARIES.update(
    {
        "methodology.profile_generated": "Generate a six-dimension analysis Profile with a versioned knowledge snapshot",
        "methodology.fact_matched": "Match a concrete signal to a fact or record a context exclusion with Evidence",
        "evidence.delivery_traced": "Persist the per-turn evidence selection funnel",
        "blind_run.prepared": "Prepare a reference-isolated blind protocol",
        "blind_run.frozen": "Freeze the reproducible blind-run manifest before model planning",
    }
)

_PAYLOAD_KEYS = {
    "run_id",
    "tool_name",
    "status",
    "error",
    "error_type",
    "decision",
    "accepted",
    "reason",
    "source_independence",
    "provider",
    "model",
    "attempt_count",
    "context_bytes",
    "context_evidence_count",
    "mapped_count",
    "snapshot_id",
    "snapshot_version",
    "revision_id",
    "gate_id",
    "profile_only",
    "module",
    "confidence",
    "claim_type",
    "prompt_sha256",
    "model_call_id",
    "phase",
    "action_count",
    "rejected_action_count",
    "scheduler",
    "planned_tools",
    "question",
    "seed_kind",
    "state",
    "transition",
    "action_key",
    "priority",
    "depends_on",
    "artifact_id",
    "fact_id",
    "signal_count",
    "match_count",
    "verdict",
    "expected_verdict",
    "actual_verdict",
    "knowledge_sha256",
    "dimensions",
    "evidence_ids",
    "turn_id",
    "thread_id",
    "record_count",
    "snapshot_sha256",
    "scorecard_version",
    "reference_isolated",
    "initial_evidence_count",
}


def _safe_details(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}
    details: dict[str, Any] = {}
    for key in _PAYLOAD_KEYS:
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            details[key] = value
    return details


def _claim_evidence_map(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in rows:
        claim_id = row.get("claim_id")
        evidence_id = row.get("evidence_id")
        if not claim_id or not evidence_id:
            continue
        result.setdefault(str(claim_id), []).append(str(evidence_id))
    return result


def _string_ids(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return list(dict.fromkeys(str(item) for item in values if item is not None and str(item)))


def _compact_hypothesis(row: Mapping[str, Any]) -> dict[str, Any]:
    """Keep hypothesis deltas useful without copying model payloads."""
    result: dict[str, Any] = {}
    for key in ("id", "mechanism_id", "thread_id", "statement", "dimension", "status", "confidence"):
        if row.get(key) is not None:
            result[key] = row[key]
    evidence_ids = _string_ids(row.get("evidence_ids"))
    if evidence_ids:
        result["evidence_ids"] = evidence_ids
    return result


def _compact_action(row: Mapping[str, Any]) -> dict[str, Any]:
    """Expose an auditable action proposal, never its raw model response."""
    result: dict[str, Any] = {}
    for key in (
        "id",
        "origin",
        "action_type",
        "target_artifact_id",
        "target_selector",
        "reason",
        "success_condition",
        "failure_interpretation",
        "planner_turn_id",
        "status",
        "outcome",
        "dedupe_key",
        "artifact_boundary",
        "autopsy_category",
        "category",
        "target",
        "next_action",
        "hypothesis_delta",
        "mechanism_delta",
        "prompt_sha256",
        "profile_digest",
        "policy_digest",
        "action_validation_digest",
        "action_validation",
    ):
        if row.get(key) is not None:
            value = row[key]
            if key == "target_selector" and not isinstance(value, Mapping):
                continue
            result[key] = dict(value) if key == "target_selector" else value
    expected = row.get("expected_evidence_kinds") or row.get("expected_evidence")
    if isinstance(expected, (list, tuple)):
        result["expected_evidence_kinds"] = [str(item) for item in expected if str(item)]
    source_ids = _string_ids(row.get("source_evidence_ids") or row.get("evidence_ids"))
    if source_ids:
        result["source_evidence_ids"] = source_ids
    result_ids = _string_ids(row.get("new_evidence_ids") or row.get("result_evidence_ids"))
    if result_ids:
        result["new_evidence_ids"] = result_ids
    for key in ("autopsy", "hypothesis_delta", "mechanism_delta"):
        value = row.get(key)
        if isinstance(value, Mapping):
            result[key] = dict(value)
    return result


def _compact_model_call(row: Mapping[str, Any]) -> dict[str, Any]:
    """Expose auditable model-attempt diagnostics without payload material.

    Model requests and responses are restricted payloads. The trace only
    needs enough metadata to explain routing, retries and fallback decisions;
    keep this projection explicit so a new gateway parameter cannot leak into
    the user-facing trace by accident.
    """
    result: dict[str, Any] = {}
    for key in (
        "id",
        "turn_id",
        "phase",
        "provider",
        "model",
        "origin",
        "attempt",
        "status",
        "error_type",
        "agent_run_id",
        "fallback_used",
        "fallback_reason",
        "http_status",
        "endpoint_path",
        "error_detail",
        "prompt_sha256",
        "request_sha256",
        "response_sha256",
        "context_evidence_count",
        "context_bytes",
        "latency_ms",
    ):
        value = row.get(key)
        if value is not None:
            result[key] = value

    parameters = row.get("parameters")
    if isinstance(parameters, Mapping):
        for key in (
            "agent_run_id",
            "fallback_used",
            "fallback_reason",
            "http_status",
            "endpoint_path",
            "error_detail",
            "context_evidence_count",
            "context_bytes",
            "origin",
        ):
            if key not in result and parameters.get(key) is not None:
                result[key] = parameters[key]
    return result


def build_mechanism_effectiveness_traces(
    *,
    strategy_snapshot: Mapping[str, Any] | None,
    analysis_turns: Iterable[Mapping[str, Any]],
    analysis_turn_results: Iterable[Mapping[str, Any]],
    events: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Build the redacted mechanism trace rows used by persistence and API views."""
    return _build_mechanism_effectiveness_traces(
        strategy_snapshot=strategy_snapshot,
        analysis_turns=analysis_turns,
        analysis_turn_results=analysis_turn_results,
        events=events,
    )


def _compact_verifier(value: Any) -> dict[str, Any]:
    """Return only the stable, non-secret portion of a verifier decision."""
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key in ("status", "verdict", "reason", "missing", "contradictions", "evidence_ids"):
        item = value.get(key)
        if item is None:
            continue
        if key in {"missing", "contradictions", "evidence_ids"}:
            result[key] = _string_ids(item)
        elif isinstance(item, (str, int, float, bool)):
            result[key] = item
    return result


def _build_mechanism_effectiveness_traces(
    *,
    strategy_snapshot: Mapping[str, Any] | None,
    analysis_turns: Iterable[Mapping[str, Any]],
    analysis_turn_results: Iterable[Mapping[str, Any]],
    events: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Join durable planner/result records into one trace per mechanism.

    This is a projection only.  It deliberately uses the already persisted
    structured records and never attempts to reconstruct private model
    reasoning or raw request/response payloads.
    """
    investigation = (
        strategy_snapshot.get("investigation", {})
        if isinstance(strategy_snapshot, Mapping)
        else {}
    )
    if not isinstance(investigation, Mapping):
        return []
    mechanisms = [item for item in investigation.get("mechanisms", []) if isinstance(item, Mapping)]
    if not mechanisms:
        return []
    seeds = [item for item in investigation.get("seed_rankings", []) if isinstance(item, Mapping)]
    hypotheses = [item for item in investigation.get("hypotheses", []) if isinstance(item, Mapping)]
    turns = [item for item in analysis_turns if isinstance(item, Mapping)]
    results = [item for item in analysis_turn_results if isinstance(item, Mapping)]
    event_rows = [item for item in events if isinstance(item, Mapping)]
    runtime = investigation.get("runtime") if isinstance(investigation.get("runtime"), Mapping) else {}
    gates = [item for item in runtime.get("gates", []) if isinstance(item, Mapping)]
    report_revision_ids = list(
        dict.fromkeys(
            str(item.get("object_id"))
            for item in event_rows
            if str(item.get("event_type", "")) in {"report.generated", "report.recomposed"}
            and item.get("object_id")
        )
    )

    traces: list[dict[str, Any]] = []
    for mechanism in mechanisms:
        mechanism_id = str(mechanism.get("id") or mechanism.get("mechanism_id") or "")
        if not mechanism_id:
            continue
        artifact_id = str(mechanism.get("artifact_id") or "")
        mechanism_type = str(
            mechanism.get("mechanism_type") or mechanism.get("type") or mechanism.get("dimension") or ""
        )
        matching_seeds = [
            seed
            for seed in seeds
            if (not artifact_id or str(seed.get("artifact_id") or "") == artifact_id)
            and (
                str(seed.get("mechanism_id") or "") == mechanism_id
                or not mechanism_type
                or str(seed.get("mechanism_type") or seed.get("type") or "").casefold()
                == mechanism_type.casefold()
            )
        ]
        seed = matching_seeds[0] if matching_seeds else None
        matching_hypotheses = [
            hypothesis
            for hypothesis in hypotheses
            if str(hypothesis.get("mechanism_id") or "") == mechanism_id
            or (not hypothesis.get("mechanism_id") and artifact_id and str(hypothesis.get("artifact_id") or "") == artifact_id)
        ]
        thread_ids = {
            str(item.get("thread_id"))
            for item in matching_hypotheses
            if item.get("thread_id")
        }
        if mechanism.get("thread_id"):
            thread_ids.add(str(mechanism["thread_id"]))
        matching_turns = [
            turn
            for turn in turns
            if (not thread_ids or str(turn.get("thread_id") or "") in thread_ids)
            or mechanism_id in str(turn.get("phase") or "")
        ]
        matching_turn_ids = {str(turn.get("turn_id")) for turn in matching_turns if turn.get("turn_id")}
        matching_results = [
            result
            for result in results
            if (not matching_turn_ids or str(result.get("turn_id") or "") in matching_turn_ids)
            or (thread_ids and str(result.get("thread_id") or "") in thread_ids)
        ]
        action_rows = [
            action
            for turn in matching_turns
            for action in (turn.get("action_proposals") or [])
            if isinstance(action, Mapping)
        ]
        action_rows.extend(
            action
            for result in matching_results
            for action in (result.get("completed_actions") or [])
            if isinstance(action, Mapping)
        )
        compact_actions: list[dict[str, Any]] = []
        action_keys: set[str] = set()
        for action in action_rows:
            compact = _compact_action(action)
            key = repr(sorted(compact.items()))
            if key not in action_keys:
                compact_actions.append(compact)
                action_keys.add(key)

        evidence_ids = _string_ids(mechanism.get("evidence_ids"))
        tool_run_ids = _string_ids(mechanism.get("tool_run_ids"))
        for row in matching_turns + matching_results:
            evidence_ids.extend(_string_ids(row.get("new_evidence_ids")))
            tool_run_ids.extend(_string_ids(row.get("tool_run_ids")))
        evidence_ids = list(dict.fromkeys(evidence_ids))
        tool_run_ids = list(dict.fromkeys(tool_run_ids))

        before = []
        after = []
        if matching_turns:
            before = [_compact_hypothesis(item) for item in matching_turns[0].get("hypothesis_before", []) if isinstance(item, Mapping)]
        if matching_results:
            after = [_compact_hypothesis(item) for item in matching_results[-1].get("hypothesis_after", []) if isinstance(item, Mapping)]
        if not after and matching_turns:
            after = [_compact_hypothesis(item) for item in matching_turns[-1].get("hypothesis_after", []) if isinstance(item, Mapping)]
        verifier_result = {}
        for row in reversed(matching_results + matching_turns):
            verifier_result = _compact_verifier(row.get("verifier_result"))
            if verifier_result:
                break
        claim_gate = {}
        for gate in gates:
            if str(gate.get("mechanism_id") or "") == mechanism_id or not gate.get("mechanism_id"):
                claim_gate = _compact_verifier(gate)
                if claim_gate:
                    break
        model_actions = [item for item in compact_actions if item.get("origin") == "model"]
        useful_model_actions = [item for item in model_actions if action_is_productive(item)]
        traces.append(
            {
                "trace_version": "mechanism-effectiveness-v1",
                "mechanism_id": mechanism_id,
                "mechanism_type": mechanism_type,
                "artifact_id": artifact_id or None,
                "seed": {
                    key: seed.get(key)
                    for key in ("seed_id", "artifact_id", "mechanism_type", "question", "priority", "reason")
                    if seed is not None and seed.get(key) is not None
                },
                "question": (seed or {}).get("question") or investigation.get("last_question"),
                "competing_hypotheses": [_compact_hypothesis(item) for item in matching_hypotheses],
                "action_proposals": compact_actions[:64],
                "tool_runs": tool_run_ids,
                "new_evidence_ids": evidence_ids,
                "evidence_delta": {"count": len(evidence_ids), "ids": evidence_ids},
                "hypothesis_delta": {"before": before, "after": after},
                "mechanism_delta": {
                    "initial_status": mechanism.get("status"),
                    "final_state": next(
                        (row.get("mechanism_state") for row in reversed(matching_results + matching_turns) if row.get("mechanism_state")),
                        mechanism.get("status"),
                    ),
                },
                "verifier_result": verifier_result,
                "claim_gate": claim_gate,
                "report_projection": {"revision_ids": report_revision_ids},
                "model_action_productivity": {
                    "accepted": len(model_actions),
                    "useful": len(useful_model_actions),
                    "ratio": (len(useful_model_actions) / len(model_actions) if model_actions else 0.0),
                },
            }
        )
    return traces


def build_analysis_trace(
    *,
    task_id: str,
    trace_id: str,
    events: Iterable[Mapping[str, Any]],
    claims: Iterable[Mapping[str, Any]] = (),
    claim_evidence: Iterable[Mapping[str, Any]] = (),
    evidence: Iterable[Mapping[str, Any]] = (),
    tool_runs: Iterable[Mapping[str, Any]] = (),
    model_calls: Iterable[Mapping[str, Any]] = (),
    analysis_turns: Iterable[Mapping[str, Any]] = (),
    analysis_turn_results: Iterable[Mapping[str, Any]] = (),
    evidence_delivery: Iterable[Mapping[str, Any]] = (),
    artifacts: Iterable[Mapping[str, Any]] = (),
    persisted_mechanism_effectiveness_traces: Iterable[Mapping[str, Any]] | None = None,
    limitations: Iterable[str] = (),
    lifecycle: str | None = None,
    outcome: str | None = None,
    integrity: Mapping[str, Any] | None = None,
    strategy_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a redacted event timeline plus typed provenance links."""

    events = list(events)
    claims = list(claims)
    evidence = list(evidence)
    tool_runs = list(tool_runs)
    model_calls = list(model_calls)
    analysis_turns = list(analysis_turns)
    analysis_turn_results = list(analysis_turn_results)
    evidence_delivery = list(evidence_delivery)
    artifacts = list(artifacts)
    claim_evidence_by_claim = _claim_evidence_map(claim_evidence)
    evidence_by_tool: dict[str, list[str]] = {}
    for row in evidence:
        tool_run_id = row.get("tool_run_id")
        evidence_id = row.get("id")
        if tool_run_id and evidence_id:
            evidence_by_tool.setdefault(str(tool_run_id), []).append(str(evidence_id))

    claims_by_id = {str(row.get("id")): row for row in claims if row.get("id")}
    tools_by_id = {str(row.get("id")): row for row in tool_runs if row.get("id")}
    model_calls_by_id = {str(row.get("id")): row for row in model_calls if row.get("id")}

    steps: list[dict[str, Any]] = []
    for event in events:
        event_type = str(event.get("event_type", "unknown"))
        object_type = str(event.get("object_type", ""))
        object_id = str(event.get("object_id", ""))
        payload = event.get("payload")
        evidence_ids: list[str] = []
        claim_ids: list[str] = []
        tool_run_ids: list[str] = []
        model_call_ids: list[str] = []

        if object_type == "Evidence" and object_id:
            evidence_ids.append(object_id)
        elif object_type == "Claim" and object_id:
            claim_ids.append(object_id)
            evidence_ids.extend(claim_evidence_by_claim.get(object_id, []))
        elif object_type == "ToolRun" and object_id:
            tool_run_ids.append(object_id)
            evidence_ids.extend(evidence_by_tool.get(object_id, []))
        elif object_type == "ModelCall" and object_id:
            model_call_ids.append(object_id)
        if isinstance(payload, Mapping):
            for key, target in (
                ("evidence_id", evidence_ids),
                ("claim_id", claim_ids),
                ("tool_run_id", tool_run_ids),
                ("model_call_id", model_call_ids),
            ):
                value = payload.get(key)
                if value:
                    target.append(str(value))

        details = _safe_details(payload)
        if object_type == "Claim" and object_id in claims_by_id:
            claim = claims_by_id[object_id]
            details.update(
                {
                    "claim_module": claim.get("module"),
                    "claim_status": claim.get("status"),
                    "claim_confidence": claim.get("confidence"),
                }
            )
        if object_type == "ToolRun" and object_id in tools_by_id:
            tool = tools_by_id[object_id]
            details.update(
                {
                    "tool": tool.get("tool"),
                    "tool_status": tool.get("status"),
                    "scheduler": tool.get("scheduler"),
                    "planned_tools": tool.get("planned_tools", []),
                }
            )
        if object_type == "ModelCall" and object_id in model_calls_by_id:
            call = model_calls_by_id[object_id]
            details.update(
                {
                    "provider": call.get("provider"),
                    "model": call.get("model"),
                    "call_status": call.get("status"),
                    "agent_run_id": call.get("agent_run_id"),
                    "context_evidence_count": call.get("context_evidence_count"),
                    "context_bytes": call.get("context_bytes"),
                }
            )

        steps.append(
            {
                "sequence": event.get("chain_sequence"),
                "timestamp": event.get("created_at"),
                "phase": _PHASES.get(event_type, "other"),
                "event_type": event_type,
                "actor": event.get("actor"),
                "summary": _SUMMARIES.get(event_type, "记录分析过程事件"),
                "object": {"type": object_type, "id": object_id} if object_id else None,
                "references": {
                    "tool_run_ids": sorted(set(tool_run_ids)),
                    "evidence_ids": sorted(set(evidence_ids)),
                    "claim_ids": sorted(set(claim_ids)),
                    "model_call_ids": sorted(set(model_call_ids)),
                },
                "details": details,
            }
        )

    links: list[dict[str, str]] = []
    for claim_id, evidence_ids in claim_evidence_by_claim.items():
        for evidence_id in sorted(set(evidence_ids)):
            links.append(
                {
                    "from_type": "Claim",
                    "from_id": claim_id,
                    "relation": "SUPPORTED_BY",
                    "to_type": "Evidence",
                    "to_id": evidence_id,
                }
            )
    for tool_run_id, evidence_ids in evidence_by_tool.items():
        for evidence_id in sorted(set(evidence_ids)):
            links.append(
                {
                    "from_type": "ToolRun",
                    "from_id": tool_run_id,
                    "relation": "OBSERVED",
                    "to_type": "Evidence",
                    "to_id": evidence_id,
                }
            )
    for artifact in artifacts:
        artifact_id = artifact.get("id")
        if artifact_id:
            links.append(
                {
                    "from_type": "AnalysisTask",
                    "from_id": task_id,
                    "relation": "CONTAINS",
                    "to_type": "Artifact",
                    "to_id": str(artifact_id),
                }
            )
    for tool in tools_by_id.values():
        artifact_id = tool.get("artifact_id")
        if artifact_id:
            links.append(
                {
                    "from_type": "Artifact",
                    "from_id": str(artifact_id),
                    "relation": "ANALYZED_BY",
                    "to_type": "ToolRun",
                    "to_id": str(tool["id"]),
                }
            )
    for call in model_calls_by_id.values():
        call_id = str(call["id"])
        agent_run_id = call.get("agent_run_id")
        if agent_run_id:
            links.append(
                {
                    "from_type": "AgentRun",
                    "from_id": str(agent_run_id),
                    "relation": "INCLUDES",
                    "to_type": "ModelCall",
                    "to_id": call_id,
                }
            )
        for claim in claims:
            if claim.get("model_call_id") == call_id:
                links.append(
                    {
                        "from_type": "ModelCall",
                        "from_id": call_id,
                        "relation": "PRODUCED",
                        "to_type": "Claim",
                        "to_id": str(claim["id"]),
                    }
                )

    planning = {}
    investigation = {}
    if isinstance(strategy_snapshot, Mapping):
        raw_planning = strategy_snapshot.get("dynamic_planning")
        if isinstance(raw_planning, Mapping):
            # Keep only the structured scheduler record.  Prompts, raw model
            # responses, and secrets are deliberately excluded from this view.
            planning = {
                "status": raw_planning.get("status"),
                "phase": raw_planning.get("phase"),
                "objective": raw_planning.get("objective"),
                "actions": list(raw_planning.get("actions", []))[:64],
                "completed_actions": list(raw_planning.get("completed_actions", []))[-64:],
                "rejected_actions": list(raw_planning.get("rejected_actions", []))[:32],
                "rejected_action_count": raw_planning.get("rejected_action_count", 0),
                "history": list(raw_planning.get("history", []))[-8:],
                "failure": raw_planning.get("failure"),
            }
        raw_investigation = strategy_snapshot.get("investigation")
        if isinstance(raw_investigation, Mapping):
            investigation = {
                "current_state": raw_investigation.get("current_state"),
                "last_question": raw_investigation.get("last_question"),
                "last_transition": raw_investigation.get("last_transition"),
                "threads": list(raw_investigation.get("threads", []))[:32],
                "hypotheses": list(raw_investigation.get("hypotheses", []))[:64],
                "mechanisms": list(raw_investigation.get("mechanisms", []))[:64],
                "seed_rankings": list(raw_investigation.get("seed_rankings", []))[:64],
                "action_proposals": list(raw_investigation.get("action_proposals", []))[:64],
                "runtime": {
                    "events": list((raw_investigation.get("runtime") or {}).get("events", []))[-512:]
                    if isinstance(raw_investigation.get("runtime"), Mapping)
                    else [],
                    "actions": list((raw_investigation.get("runtime") or {}).get("actions", []))[-128:]
                    if isinstance(raw_investigation.get("runtime"), Mapping)
                    else [],
                    "gates": list((raw_investigation.get("runtime") or {}).get("gates", []))[:64]
                    if isinstance(raw_investigation.get("runtime"), Mapping)
                    else [],
                },
                "context_policy": raw_investigation.get("context_policy", {}),
                "action_budget": dict(raw_investigation.get("action_budget", {}))
                if isinstance(raw_investigation.get("action_budget"), Mapping)
                else {},
                "deferred_frontier": list(raw_investigation.get("deferred_frontier", []))[:256],
                "private_chain_of_thought": False,
            }

    turn_rows = []
    for turn in analysis_turns:
        if not isinstance(turn, Mapping):
            continue
        # The trace exposes the auditable control-plane manifest.  Raw model
        # payloads remain available only through restricted encrypted storage.
        turn_rows.append(
            {
                key: turn.get(key)
                for key in (
                    "id",
                    "thread_id",
                    "turn_id",
                    "phase",
                    "hypothesis_before",
                    "retrieval_request",
                    "candidate_evidence_ids",
                    "selected_evidence_ids",
                    "delivered_evidence_ids",
                    "context_manifest",
                    "model_call_id",
                    "action_proposals",
                    "policy_decisions",
                    "tool_run_ids",
                    "new_evidence_ids",
                    "verifier_result",
                    "hypothesis_after",
                    "mechanism_state",
                    "stop_reason",
                    "created_at",
                )
                if key in turn
            }
        )

    result_rows = []
    for result in analysis_turn_results:
        if not isinstance(result, Mapping):
            continue
        result_rows.append(
            {
                key: result.get(key)
                for key in (
                    "id",
                    "parent_turn_id",
                    "thread_id",
                    "turn_id",
                    "phase",
                    "completed_actions",
                    "tool_run_ids",
                    "new_evidence_ids",
                    "verifier_result",
                    "hypothesis_after",
                    "mechanism_state",
                    "stop_reason",
                    "created_at",
                )
                if key in result
            }
        )

    delivery_counts: dict[str, int] = {}
    delivery_by_turn: dict[str, dict[str, Any]] = {}
    delivery_rows: list[dict[str, Any]] = []
    for row in evidence_delivery:
        if not isinstance(row, Mapping):
            continue
        stage = str(row.get("stage", ""))
        if stage:
            delivery_counts[stage] = delivery_counts.get(stage, 0) + 1
        turn_id = str(row.get("turn_id", ""))
        if turn_id:
            turn = delivery_by_turn.setdefault(turn_id, {"turn_id": turn_id, "counts": {}})
            counts = turn["counts"]
            counts[stage] = counts.get(stage, 0) + 1
        delivery_rows.append(
            {
                key: row.get(key)
                for key in (
                    "turn_id",
                    "thread_id",
                    "model_call_id",
                    "subject_key",
                    "evidence_id",
                    "stage",
                    "context_role",
                    "selection_score",
                    "exclusion_reason",
                    "details",
                )
                if key in row
            }
        )

    persisted_trace_rows = [
        dict(row)
        for row in (persisted_mechanism_effectiveness_traces or ())
        if isinstance(row, Mapping)
    ]
    mechanism_effectiveness_traces = (
        persisted_trace_rows
        if persisted_mechanism_effectiveness_traces is not None
        else _build_mechanism_effectiveness_traces(
            strategy_snapshot=strategy_snapshot,
            analysis_turns=analysis_turns,
            analysis_turn_results=analysis_turn_results,
            events=events,
        )
    )
    model_call_rows = [_compact_model_call(row) for row in model_calls if isinstance(row, Mapping)]

    return {
        "task_id": task_id,
        "trace_id": trace_id,
        "lifecycle": lifecycle,
        "outcome": outcome,
        "disclosure": {
            "type": "structured_system_trace",
            "private_chain_of_thought": "withheld",
            "message": (
                "This view exposes observable analysis steps, evidence links, "
                "validation decisions, limitations, and model status. "
                "The model's private chain-of-thought is not stored or displayed."
            ),
        },
        "steps": steps,
        "links": links,
        "limitations": list(dict.fromkeys(str(item) for item in limitations if item)),
        "integrity": dict(integrity or {}),
        "model_calls": model_call_rows,
        "analysis_turns": turn_rows,
        "analysis_turn_results": result_rows,
        "evidence_funnel": {
            "counts": delivery_counts,
            "records": delivery_rows,
            "turns": list(delivery_by_turn.values()),
        },
        "mechanism_effectiveness_traces": mechanism_effectiveness_traces,
        "dynamic_planning": planning,
        "investigation": investigation,
    }
