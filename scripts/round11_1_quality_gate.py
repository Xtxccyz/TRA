"""Evaluate the Round 11.1 four-sample semantic closure gate.

The evaluator consumes only task/report projections exposed by the local API;
it never submits samples, executes binaries, or sends sample-derived network
traffic.  It is intentionally conservative: an incomplete or failed task is
reported as a blocker instead of being treated as a successful HTTP request.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import httpx

from threat_report_agent.product_certification import static_wording_violations


NAVIGATION_MARKERS = (
    "xref/cfg/instruction prominence",
    "call-site density",
    "contains rva-level call sites",
    "prioritizes",
    "raw function reference",
    "ghidra call references",
)
STRUCTURAL_MARKERS = (
    "missing custom dll",
    "required artifact",
    "packed",
    "virtualized",
    "runtime-only",
    "unresolved",
    "obfuscat",
    "code recovery",
    "decompil",
    "architecture",
    "static boundary",
    "no new evidence",
    "missing evidence",
)


def _get(client: httpx.Client, path: str) -> dict[str, object]:
    response = client.get(path)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise TypeError(f"expected object from {path}")
    return payload


def _core_section(markdown: str) -> str:
    match = re.search(
        r"## 3\. Key Static Findings(.*?)(?=^## 4\. Verified Mechanisms|\Z)",
        markdown,
        flags=re.IGNORECASE | re.DOTALL | re.MULTILINE,
    )
    return match.group(1) if match else ""


def _mechanism_section(markdown: str) -> str:
    match = re.search(
        r"## 4\. Verified Mechanisms(.*?)(?=^## 5\. Reconstructed Static Behavior Flow|\Z)",
        markdown,
        flags=re.IGNORECASE | re.DOTALL | re.MULTILINE,
    )
    return match.group(1) if match else ""


def _flow_section(markdown: str) -> str:
    match = re.search(
        r"## 5\. Reconstructed Static Behavior Flow(.*?)(?=^## 6\. IOC / Indicators|\Z)",
        markdown,
        flags=re.IGNORECASE | re.DOTALL | re.MULTILINE,
    )
    return match.group(1) if match else ""


def evaluate_sample(client: httpx.Client, sample_name: str, task_id: str) -> dict[str, object]:
    status = _get(client, f"/api/v1/tasks/{task_id}/status")
    detail = _get(client, f"/api/v1/tasks/{task_id}")
    revision_id = detail.get("latest_report_revision_id")
    report = _get(client, f"/api/v1/reports/{revision_id}") if revision_id else {}
    markdown = str(report.get("markdown") or "")
    core = _core_section(markdown)
    mechanism = _mechanism_section(markdown)
    flow = _flow_section(markdown)
    coverage = status.get("analysis_coverage")
    if not isinstance(coverage, dict):
        coverage = detail.get("analysis_coverage") if isinstance(detail.get("analysis_coverage"), dict) else {}
    dimensions = coverage.get("dimensions", {}) if isinstance(coverage, dict) else {}
    if not isinstance(dimensions, dict):
        dimensions = {}
    verified = float(dimensions.get("verified_mechanism_coverage", 0.0) or 0.0)
    relation_flow = float(dimensions.get("relation_flow_coverage", 0.0) or 0.0)
    semantic_flow_nodes = int(coverage.get("semantic_flow_nodes", 0) or 0) if isinstance(coverage, dict) else 0
    semantic_flow_edges = int(coverage.get("semantic_flow_edges", 0) or 0) if isinstance(coverage, dict) else 0
    coverage_flow_present = bool(coverage.get("behavior_flow_present", False)) if isinstance(coverage, dict) else False
    coverage_applicable = bool(coverage.get("coverage_applicable", False)) if isinstance(coverage, dict) else False
    limitations = [str(item) for item in (detail.get("limitations") or [])]
    structural = [item for item in limitations if any(marker in item.casefold() for marker in STRUCTURAL_MARKERS)]
    navigation_findings = [
        line for line in core.splitlines()
        if any(marker in line.casefold() for marker in NAVIGATION_MARKERS)
    ]
    timing_execution = [
        line for line in core.splitlines()
        if re.search(r"getsystemtime|getsystemtimeasfiletime|queryperformancecounter|getcurrentprocessid|getcurrentthreadid|gettickcount", line, re.IGNORECASE)
        and re.search(r"execution|process creation|command", line, re.IGNORECASE)
    ]
    unknown_high = []
    current_score: int | None = None
    for line in mechanism.splitlines():
        score_match = re.search(r"completeness=(\d+)/100", line, re.IGNORECASE)
        if score_match:
            current_score = int(score_match.group(1))
        if current_score is not None and current_score >= 80 and re.search(r"UNKNOWN\((?:input|consumer|output|side_effect)", line, re.IGNORECASE):
            unknown_high.append(line)
        if line.strip() == "" and current_score is not None:
            current_score = None
    placeholder = markdown.count("Requires deterministic verification before escalation.")
    flow_unknown = "未恢复出有序的静态行为链" in flow or "no evidence-backed mechanism chain established" in flow.casefold()
    report_flow_present = bool(flow.strip()) and not flow_unknown
    wording = static_wording_violations(markdown)
    integrity = _get(client, f"/api/v1/tasks/{task_id}/audit/integrity").get("valid") is True
    blockers: list[str] = []
    if status.get("lifecycle") != "SUCCEEDED":
        blockers.append(f"lifecycle={status.get('lifecycle')}")
    if not revision_id:
        blockers.append("report_missing")
    if not integrity:
        blockers.append("audit_integrity")
    if timing_execution:
        blockers.append("timing_api_execution_misclassification")
    if navigation_findings:
        blockers.append("navigation_core_finding")
    if unknown_high:
        blockers.append("unknown_mandatory_field_high_completeness")
    if placeholder:
        blockers.append("security_meaning_placeholder")
    if wording:
        blockers.append("static_wording_gate")
    if coverage_flow_present != report_flow_present:
        blockers.append("relation_flow_metric_inconsistent_with_report")
    if coverage_flow_present and (semantic_flow_nodes < 3 or semantic_flow_edges < 2 or relation_flow <= 0.0):
        blockers.append("semantic_flow_metric_contract")
    if not coverage_applicable and (relation_flow != 0.0 or coverage_flow_present):
        blockers.append("non_applicable_flow_metric_contract")
    result_class = str(status.get("analysis_class") or detail.get("analysis_class") or "")
    if result_class == "FULL_STATIC_ANALYSIS" and verified <= 0 and relation_flow <= 0:
        blockers.append("full_without_semantic_closure")
    if result_class == "BOUNDED_STATIC_ANALYSIS" and verified <= 0 and not structural:
        blockers.append("bounded_without_structural_boundary")
    return {
        "sample_name": sample_name,
        "task_id": task_id,
        "lifecycle": status.get("lifecycle"),
        "outcome": status.get("outcome"),
        "analysis_class": result_class,
        "evidence_count": status.get("evidence_count"),
        "claim_count": status.get("claim_count"),
        "tool_run_count": status.get("tool_run_count"),
        "model_call_count": status.get("model_call_count"),
        "report_revision_id": revision_id,
        "coverage": coverage,
        "verified_mechanism_coverage": verified,
        "relation_flow_coverage": relation_flow,
        "semantic_flow_nodes": semantic_flow_nodes,
        "semantic_flow_edges": semantic_flow_edges,
        "coverage_flow_present": coverage_flow_present,
        "coverage_applicable": coverage_applicable,
        "structural_limitations": structural,
        "navigation_finding_count": len(navigation_findings),
        "semantic_misclassification_count": len(timing_execution),
        "unknown_high_completeness_count": len(unknown_high),
        "security_meaning_placeholder_count": placeholder,
        "behavior_flow_present": report_flow_present,
        "static_wording_violation_count": len(wording),
        "audit_integrity": integrity,
        "sample_execution": False,
        "blockers": blockers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample", action="append", nargs=2, metavar=("NAME", "TASK_ID"), required=True)
    args = parser.parse_args()
    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=120.0) as client:
        samples = [evaluate_sample(client, name, task_id) for name, task_id in args.sample]
    checks = {
        "four_sample_rerun": len(samples) == 4 and all(item["lifecycle"] == "SUCCEEDED" for item in samples),
        "semantic_misclassification": all(item["semantic_misclassification_count"] == 0 for item in samples),
        "core_finding_quality": all(item["navigation_finding_count"] == 0 for item in samples),
        "completeness": all(item["unknown_high_completeness_count"] == 0 for item in samples),
        "security_meaning": all(item["security_meaning_placeholder_count"] == 0 for item in samples),
        "static_boundary": all(item["sample_execution"] is False for item in samples),
        "audit_integrity": all(item["audit_integrity"] for item in samples),
        "analysis_class": all("full_without_semantic_closure" not in item["blockers"] for item in samples),
        "task_success": all(not item["blockers"] for item in samples),
    }
    payload = {
        "version": "round11.1-quality-gate-v1",
        "status": "PASS" if all(checks.values()) else "BLOCKED",
        "blocker_count": sum(len(item["blockers"]) for item in samples),
        "checks": {key: "PASS" if value else "BLOCKED" for key, value in checks.items()},
        "samples": samples,
        "external_certification": "BLOCKED",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
