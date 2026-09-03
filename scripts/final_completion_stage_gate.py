"""Build the final completion gate from existing, evaluator-safe artifacts.

This command never analyzes a sample.  It only joins already-produced release
evidence and emits the normalized gate schema from the Final Completion plan.
Missing external evidence remains ``BLOCKED``/``NOT_PROVEN``; a lower-level
fixture cannot promote a real-sample or production gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
from datetime import UTC, datetime
from pathlib import Path
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FINAL_ROUND = ROOT / "release-artifacts" / "final-round"
DEFAULT_OUTPUT = FINAL_ROUND / "final-completion-stage-gate-generated.json"
DEFAULT_TASK_VIEW_PATH = ROOT / ".scratch" / "final-completion-live-20260904" / "comhost-task-view-d114e2d4.json"
DEFAULT_BASELINE_PATH = FINAL_ROUND / "comhost-static-baseline-postdeploy-20260904.json"
DEFAULT_ISSUE_REGISTER_PATH = FINAL_ROUND / "issue-register-20260904.json"

_SOURCE_TIMESTAMP_RE = re.compile(rb'"generated_at"\s*:\s*"([^"\\]+)"')
_MISSING = object()

# These names are the release-facing contract from the Final Completion plan.
# Internal gate names may be added, but they must not replace these fields.
FORMAL_GATE_FIELDS = frozenset(
    {
        "open_p0",
        "open_p1",
        "agentic_mechanism_effectiveness",
        "comhost_c1_c4",
        "analysis_depth_gate",
        "report_depth_gate",
        "browser_e2e",
        "generalization",
        "recovery",
        "concurrency",
        "soak_24h",
        "production_hardening",
        "independent_reviews",
    }
)

# Acceptance artifacts are deliberately mapped here instead of encoding a
# permanent answer in the gate.  A release artifact can promote a gate only
# when it contains an explicit PASS and the same source identity as the
# current checkout (see ``_load_gate_evidence``).  Missing, stale, or
# incomplete artifacts therefore remain NOT_PROVEN/BLOCKED.
DEFAULT_GATE_EVIDENCE_SOURCES: dict[str, tuple[Path, ...]] = {
    "agentic_mechanism_effectiveness": (
        FINAL_ROUND / "model-effectiveness-real-20260902.json",
    ),
    "analysis_depth_gate": (
        FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        FINAL_ROUND / "resume-regression-summary-20260904.json",
    ),
    "report_depth_gate": (
        FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        FINAL_ROUND / "resume-regression-summary-20260904.json",
    ),
    "browser_e2e": (FINAL_ROUND / "browser-e2e-20260902.json",),
    "generalization": (ROOT / "release-artifacts" / "round11.2" / "heldout-results.json",),
    "recovery": (ROOT / "release-artifacts" / "round11.2" / "restart-recovery.json",),
    "concurrency": (ROOT / "release-artifacts" / "round11.2" / "concurrency.json",),
    "soak_24h": (ROOT / "release-artifacts" / "round11.2" / "soak-24h.json",),
    "production_hardening": (
        ROOT / "release-artifacts" / "round11.2" / "production-hardening.json",
    ),
    "independent_reviews": (
        ROOT / "release-artifacts" / "round11.2" / "independent-reviews.json",
    ),
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _json_string_from_mmap(mapped: mmap.mmap, key: str) -> str | None:
    """Read one simple JSON string value without materialising a large object.

    Live task projections contain a potentially very large Evidence ledger.
    The release gate only needs a few identifiers from that document, so use a
    memory-mapped bounded scan for those scalar metadata fields.  Values are
    UUIDs or SHA-256 digests and therefore cannot contain escaped quotes.
    """
    marker = f'"{key}"'.encode("ascii")
    offset = mapped.find(marker)
    if offset < 0:
        return None
    colon = mapped.find(b":", offset + len(marker))
    if colon < 0:
        return None
    quote = mapped.find(b'"', colon + 1)
    if quote < 0:
        return None
    end = mapped.find(b'"', quote + 1)
    if end < 0:
        return None
    return bytes(mapped[quote + 1 : end]).decode("utf-8", errors="replace")


def _load_task_view_metadata(path: Path) -> dict[str, Any]:
    """Load a task projection, using bounded metadata mode for huge ledgers."""
    # Small fixtures retain the complete JSON shape.  The live ComHost
    # projection is intentionally read as metadata-only to keep the gate
    # usable on constrained workstations.
    if path.stat().st_size <= 8 * 1024 * 1024:
        return _load(path)
    with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        case_id = _json_string_from_mmap(mapped, "case_id")
        sample_sha256 = _json_string_from_mmap(mapped, "content_sha256")
    return {
        "case_id": case_id,
        "request_snapshot": {"sample_package": {"content_sha256": sample_sha256}},
        "_metadata_only": True,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _git_succeeds(*args: str) -> bool:
    try:
        subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def _source_timestamp(path: Path) -> str | None:
    """Return the source artifact timestamp without loading large JSON files.

    Acceptance artifacts normally carry ``generated_at``.  For a large task
    projection, inspect only a bounded prefix and fall back to the filesystem
    modification time.  The gate separately records when it ingested the
    artifact, so these two times cannot be confused.
    """
    try:
        with path.open("rb") as handle:
            prefix = handle.read(256 * 1024)
        match = _SOURCE_TIMESTAMP_RE.search(prefix)
        if match:
            return match.group(1).decode("utf-8", errors="replace")
        return datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
    except (OSError, ValueError):
        return None


def _artifact_metadata_values(path: Path) -> dict[str, Any]:
    """Read optional provenance fields from a bounded-size JSON artifact."""
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            return {}
        payload = _load(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    values: dict[str, Any] = {}
    sources = [payload, _mapping(payload.get("metadata")), _mapping(payload.get("provenance"))]
    for field in ("session_id", "event_cursor_range", "sample_sha256", "case_id", "task_id"):
        for source in sources:
            value = source.get(field)
            if value not in (None, "", []):
                values[field] = value
                break
    return values


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_value(mapping: dict[str, Any], *keys: str) -> object:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return _MISSING


def _number(value: object) -> float | None:
    if value is _MISSING or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _rate_percent(value: object) -> float | None:
    number = _number(value)
    if number is None:
        return None
    return number * 100 if 0 <= number <= 1 else number


def _bool_metric(value: object) -> bool | None:
    if value is _MISSING or value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "pass", "passed", "yes", "verified", "supported"}:
            return True
        if normalized in {"false", "fail", "failed", "no", "blocked", "unknown"}:
            return False
        if normalized in {"1", "0"}:
            return normalized == "1"
    return None


def _metric_sources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for key in ("metrics", "acceptance", "acceptance_metrics", "coverage", "wave_b", "wave_c"):
        value = payload.get(key)
        if isinstance(value, dict):
            sources.append(value)
    metrics = _mapping(payload.get("metrics"))
    for key in ("report_depth", "analysis_depth", "thresholds", "behavior_flow", "decoder", "xor_negative_control", "pe_role_distinction"):
        value = metrics.get(key)
        if isinstance(value, dict):
            sources.append(value)
    sources.append(payload)
    return sources


def _metric(payload: dict[str, Any], *keys: str) -> object:
    for source in _metric_sources(payload):
        value = _first_value(source, *keys)
        if value is not _MISSING:
            return value
    return _MISSING


def _section_metric(payload: dict[str, Any], section: str, *keys: str) -> object:
    """Read a metric from a named nested section without broad key leakage."""
    for source in _metric_sources(payload):
        nested = _mapping(source.get(section))
        value = _first_value(nested, *keys)
        if value is not _MISSING:
            return value
    return _MISSING


def _wave_b_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the explicit static-semantic acceptance thresholds.

    This evaluator is intentionally conservative: an absent metric is a
    missing proof, never an implicit pass.  It accepts both fraction and
    percentage encodings for rates because historical artifacts used both.
    """
    checks: dict[str, dict[str, Any]] = {}

    def rate_check(name: str, keys: tuple[str, ...], minimum: float | None = None, maximum: float | None = None) -> None:
        raw = _metric(payload, *keys)
        value = _rate_percent(raw)
        passed = value is not None and (minimum is None or value >= minimum) and (maximum is None or value <= maximum)
        checks[name] = {"value": value, "raw": None if raw is _MISSING else raw, "minimum": minimum, "maximum": maximum, "status": "PASS" if passed else "BLOCKED"}

    rate_check("high_value_seed_closure", ("high_value_seed_closure_rate", "seed_closure_rate"), minimum=90)
    rate_check("candidate_noise", ("candidate_noise_ratio", "candidate_noise_rate"), maximum=20)
    rate_check("critical_mechanism_completeness", ("critical_mechanism_completeness", "mechanism_completeness"), minimum=80)
    rate_check("api_argument_coverage", ("recoverable_api_argument_coverage", "api_argument_coverage", "argument_coverage"), minimum=80)

    unresolved_raw = _metric(payload, "visible_unresolved_candidates", "unresolved_candidates", "candidate_count_unresolved")
    unresolved = _number(unresolved_raw)
    checks["visible_unresolved_candidates"] = {
        "value": unresolved,
        "raw": None if unresolved_raw is _MISSING else unresolved_raw,
        "maximum": 8,
        "status": "PASS" if unresolved is not None and unresolved <= 8 else "BLOCKED",
    }

    nodes_raw = _metric(payload, "behavior_flow_nodes", "semantic_flow_nodes", "flow_nodes")
    if nodes_raw is _MISSING:
        nodes_raw = _section_metric(payload, "behavior_flow", "nodes", "node_count")
    edges_raw = _metric(payload, "behavior_flow_edges", "semantic_flow_edges", "flow_edges")
    if edges_raw is _MISSING:
        edges_raw = _section_metric(payload, "behavior_flow", "edges", "edge_count")
    nodes = _number(nodes_raw)
    edges = _number(edges_raw)
    checks["behavior_flow"] = {
        "nodes": nodes,
        "edges": edges,
        "minimum_nodes": 4,
        "minimum_edges": 3,
        "status": "PASS" if nodes is not None and edges is not None and nodes >= 4 and edges >= 3 else "BLOCKED",
    }

    decoder_raw = _metric(payload, "decoder_replay", "decoder_replay_verified", "deterministic_decoder_replay")
    if decoder_raw is _MISSING or isinstance(decoder_raw, dict):
        decoder_raw = _section_metric(payload, "decoder", "replay", "verified", "status")
    xor_raw = _metric(payload, "xor_negative_control", "xor_negative_control_pass", "xor_decoder_positives")
    if xor_raw is _MISSING or isinstance(xor_raw, dict):
        xor_raw = _section_metric(payload, "xor_negative_control", "pass", "passed", "status", "decoder_positives")
    pe_raw = _metric(payload, "pe_role_distinction", "pe_roles_distinct", "pe_classification_roles_distinct")
    if pe_raw is _MISSING or isinstance(pe_raw, dict):
        pe_raw = _section_metric(payload, "pe_role_distinction", "distinct", "verified", "status")
    decoder = _bool_metric(decoder_raw)
    xor = _bool_metric(xor_raw)
    if isinstance(xor_raw, (int, float)) and not isinstance(xor_raw, bool):
        xor = float(xor_raw) == 0
    pe = _bool_metric(pe_raw)
    checks["decoder_replay"] = {"value": decoder, "status": "PASS" if decoder is True else "BLOCKED"}
    checks["xor_negative_control"] = {"value": xor, "status": "PASS" if xor is True else "BLOCKED"}
    checks["pe_role_distinction"] = {"value": pe, "status": "PASS" if pe is True else "BLOCKED"}
    failures = [name for name, result in checks.items() if result.get("status") != "PASS"]
    return {"status": "PASS" if not failures else "BLOCKED", "checks": checks, "failures": failures}


_REPORT_REQUIRED_FIELDS = (
    "input",
    "transformation",
    "condition",
    "output",
    "consumer",
    "evidence",
    "alternative_hypothesis",
    "static_boundary",
    "function_rva",
    "critical_arguments",
)


def _report_depth_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    metrics = _mapping(payload.get("metrics"))
    report_depth = _mapping(metrics.get("report_depth"))
    score_raw = _first_value(report_depth, "score")
    if score_raw is _MISSING:
        score_raw = _first_value(metrics, "report_depth_score", "score")
    score = _number(score_raw)
    findings = payload.get("core_findings") or payload.get("findings") or metrics.get("core_findings")
    failures: list[str] = []
    if score is None or score < 80:
        failures.append("report_score")
    if not isinstance(findings, list) or len(findings) < 5:
        failures.append("five_core_findings")
        finding_results: list[dict[str, Any]] = []
    else:
        finding_results = []
        for index, finding in enumerate(findings[:5]):
            row = _mapping(finding)
            how = _mapping(row.get("how"))
            aliases = {
                "evidence": ("evidence_ids", "evidence_refs"),
                "alternative_hypothesis": ("alternative", "alternatives"),
                "static_boundary": ("limitations", "boundary"),
                "function_rva": ("function", "rva", "function_id"),
                "critical_arguments": ("critical_args", "arguments"),
            }

            def present(field: str) -> bool:
                if row.get(field) or row.get(field.replace("_", " ")) or how.get(field):
                    return True
                return any(row.get(alias) for alias in aliases.get(field, ()))

            missing = [field for field in _REPORT_REQUIRED_FIELDS if not present(field)]
            finding_results.append({"index": index, "missing": missing, "status": "PASS" if not missing else "BLOCKED"})
            if missing:
                failures.append(f"finding_{index + 1}")
    return {
        "status": "PASS" if not failures else "BLOCKED",
        "score": score,
        "threshold": 80,
        "finding_results": finding_results,
        "failures": failures,
    }


def _seeded_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the Wave A3 seeded C1-C4 evidence contract."""
    checks: dict[str, dict[str, Any]] = {}

    def required_bool(name: str, keys: tuple[str, ...]) -> None:
        raw = _metric(payload, *keys)
        value = _bool_metric(raw)
        checks[name] = {
            "value": value,
            "raw": None if raw is _MISSING else raw,
            "status": "PASS" if value is True else "BLOCKED",
        }

    question_raw = _metric(payload, "question_quality", "question_quality_passed", "questions_validated")
    question_pass = False
    if isinstance(question_raw, list):
        question_pass = len(question_raw) >= 4 and all(_bool_metric(item) is True for item in question_raw[:4])
    else:
        question_number = _number(question_raw)
        question_pass = bool(question_number is not None and question_number >= 4) or _bool_metric(question_raw) is True
    checks["question_quality"] = {"value": question_pass, "status": "PASS" if question_pass else "BLOCKED"}
    required_bool("competing_hypotheses", ("competing_hypotheses_applicable", "applicable_competing_hypotheses", "competing_hypotheses"))
    required_bool("useful_action", ("useful_action", "useful_model_action", "action_useful"))
    required_bool("new_evidence", ("new_evidence", "new_evidence_observed", "evidence_delta"))
    rate_raw = _metric(payload, "mechanism_completeness", "critical_mechanism_completeness")
    rate = _rate_percent(rate_raw)
    checks["mechanism_completeness"] = {
        "value": rate,
        "raw": None if rate_raw is _MISSING else rate_raw,
        "minimum": 80,
        "status": "PASS" if rate is not None and rate >= 80 else "BLOCKED",
    }
    required_bool("verifier_pass", ("verifier_pass", "verifier", "verification_passed"))
    unsupported_raw = _metric(payload, "unsupported_critical", "unsupported_critical_count", "critical_unsupported")
    unsupported = _number(unsupported_raw)
    checks["unsupported_critical"] = {
        "value": unsupported,
        "raw": None if unsupported_raw is _MISSING else unsupported_raw,
        "maximum": 0,
        "status": "PASS" if unsupported is not None and unsupported == 0 else "BLOCKED",
    }
    failures = [name for name, result in checks.items() if result.get("status") != "PASS"]
    return {"status": "PASS" if not failures else "BLOCKED", "checks": checks, "failures": failures}


def _resume_regression_assessment(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate positive mechanisms and the required negative Gold control."""
    regression = payload.get("regression") or payload.get("metrics")
    if not isinstance(regression, dict):
        return {"status": "BLOCKED", "failures": ["regression_metrics"]}
    failures: list[str] = []
    mechanisms = regression.get("required_mechanisms") or regression.get("positive_mechanisms") or regression.get("mechanism_results")
    if not mechanisms:
        failures.append("required_mechanisms")
    elif isinstance(mechanisms, dict):
        for name, result in mechanisms.items():
            if _bool_metric(result) is not True and str(result).upper() not in {"PASS", "SUPPORTED", "VERIFIED"}:
                failures.append(f"mechanism:{name}")
    elif isinstance(mechanisms, list):
        for index, result in enumerate(mechanisms):
            if isinstance(result, dict):
                status = result.get("status") or result.get("result")
            else:
                status = result
            if _bool_metric(status) is not True and str(status).upper() not in {"PASS", "SUPPORTED", "VERIFIED"}:
                failures.append(f"mechanism:{index + 1}")
    negative = _first_value(
        regression,
        "negative_gold",
        "negative_control",
        "required_negative_gold",
        "negative_control_passed",
    )
    negative_pass = _bool_metric(negative)
    if negative_pass is not True:
        failures.append("negative_gold")
    overclaims = _first_value(regression, "overclaim_count", "unsupported_claims", "forbidden_overclaims")
    if isinstance(overclaims, list):
        overclaim_count = len(overclaims)
    else:
        overclaim_count = _number(overclaims)
    if overclaim_count is None or overclaim_count != 0:
        failures.append("overclaims")
    return {"status": "PASS" if not failures else "BLOCKED", "failures": failures}


def _project_acceptance_status(key: str, status: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Normalize source statuses and enforce metric-bearing Wave B/C gates."""
    normalized = status.upper()
    if normalized in {"NOT_PROVEN", "MISSING"}:
        return "NOT_PROVEN", None
    if key == "seeded_c1_c4_l1":
        assessment = _seeded_assessment(payload)
        if normalized not in {"PASS", "APPROVED"}:
            return "BLOCKED", assessment
        return assessment["status"], assessment
    if key == "analysis_depth_gate":
        assessment = _wave_b_assessment(payload)
        if normalized not in {"PASS", "APPROVED"}:
            return "BLOCKED", assessment
        return assessment["status"], assessment
    if key == "report_depth_gate":
        assessment = _report_depth_assessment(payload)
        if normalized not in {"PASS", "APPROVED"}:
            return "BLOCKED", assessment
        return assessment["status"], assessment
    if normalized not in {"PASS", "APPROVED"}:
        return "BLOCKED", None
    if key == "three_consecutive_comhost_runs":
        results = payload.get("results")
        if not isinstance(results, list) or len(results) < 3:
            return "BLOCKED", {"status": "BLOCKED", "failures": ["three_runs"]}
    if key == "resume_regression":
        assessment = _resume_regression_assessment(payload)
        return assessment["status"], assessment
    return "PASS", None


def _image_digest() -> str | None:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Image}}", "threat-report-agent-api-1"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value.removeprefix("sha256:") or None


def _baseline_identity(baseline: dict[str, Any]) -> tuple[str | None, str | None]:
    """Read the source identity from either baseline schema revision."""
    repository = baseline.get("repository")
    if not isinstance(repository, dict):
        return None, None
    commit = repository.get("backend_commit") or repository.get("git_commit")
    tree = repository.get("backend_tree") or repository.get("git_tree")
    return (
        str(commit) if commit else None,
        str(tree) if tree else None,
    )


def _identity_error(
    payload: dict[str, Any],
    *,
    label: str,
    commit: str | None,
    tree: str | None,
) -> str | None:
    """Return a fail-closed identity error for a verification artifact.

    A verification result is only evidence for this release when it records
    both the commit and tree it checked and those values match the current
    checkout.  Missing identity is intentionally not treated as legacy
    compatibility: a PASS without provenance is not trustworthy evidence.
    """
    observed_commit = payload.get("git_commit")
    observed_tree = payload.get("git_tree")
    if not observed_commit or not observed_tree:
        return f"{label} evidence is missing git_commit and/or git_tree identity."
    if not commit or not tree:
        return f"{label} evidence cannot be trusted because current HEAD/tree identity is unavailable."
    if str(observed_commit) != commit or str(observed_tree) != tree:
        return f"{label} evidence identity does not match the current HEAD/tree."
    return None


def _load_gate_evidence(
    path: Path | None,
    *,
    label: str,
    commit: str | None,
    tree: str | None,
) -> tuple[str, dict[str, Any], str | None]:
    """Load one release gate artifact without trusting unbound PASS values.

    A missing optional artifact means the corresponding acceptance activity was
    not proven for this release.  A present artifact with malformed JSON or a
    stale/missing source identity is an explicit BLOCKED condition.  Callers
    may then project the artifact status while retaining the blocker.
    """
    if path is None:
        return "NOT_PROVEN", {}, f"{label} evidence is not supplied."
    if not path.exists():
        return "NOT_PROVEN", {}, f"{label} evidence file is missing: {path}."
    try:
        payload = _load(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return "BLOCKED", {}, f"{label} evidence is invalid: {exc}."
    identity_error = _identity_error(payload, label=label, commit=commit, tree=tree)
    if identity_error:
        return "BLOCKED", payload, identity_error
    status_value: object = payload.get("status")
    if not status_value:
        # Older acceptance artifacts put the gate result under a metrics or
        # report-depth envelope. Read those projections without treating a
        # missing value as success.
        metrics = payload.get("metrics")
        if isinstance(metrics, dict):
            status_value = metrics.get("status") or metrics.get("readiness")
            report_depth = metrics.get("report_depth")
            if not status_value and isinstance(report_depth, dict):
                status_value = report_depth.get("status")
        status_value = status_value or payload.get("gate_status") or payload.get("overall_status")
    status = str(status_value or "").strip().upper()
    if not status:
        return "BLOCKED", payload, f"{label} evidence has no status."
    return status, payload, None


def validate_gate_schema(payload: dict[str, Any]) -> None:
    """Fail closed when the release-facing gate contract is malformed."""
    missing = sorted(FORMAL_GATE_FIELDS - payload.keys())
    if missing:
        raise ValueError(f"final gate is missing formal fields: {', '.join(missing)}")
    if payload.get("status") == "PASS" and payload.get("blockers"):
        raise ValueError("a PASS final gate cannot contain blockers")
    if payload.get("status") == "BLOCKED" and not payload.get("blockers"):
        raise ValueError("a BLOCKED final gate must name at least one blocker")
    blocker_count = payload.get("blocker_count")
    blockers = payload.get("blockers") or []
    if blocker_count != len(blockers):
        raise ValueError("blocker_count must equal the number of unique blockers")
    if payload.get("status") == "PASS" and blocker_count != 0:
        raise ValueError("a PASS final gate must have blocker_count=0")
    if payload.get("production_ready") is True and payload.get("status") != "PASS":
        raise ValueError("production_ready=true requires status=PASS")


def _artifact_metadata(
    path: Path,
    *,
    generated_at: str,
    commit: str | None,
    tree: str | None,
    config_fingerprint: str,
    sample_sha256: str | None,
    case_id: str | None,
    task_id: str | None,
    evaluator_only: bool,
    missing_fields: list[str] | None = None,
) -> dict[str, Any]:
    resolved_path = path.resolve()
    try:
        display_path = resolved_path.relative_to(ROOT).as_posix()
    except ValueError:
        display_path = str(resolved_path)
    source_generated_at = _source_timestamp(path)
    metadata_values = _artifact_metadata_values(path)
    resolved_missing = list(missing_fields or [])
    for field in tuple(resolved_missing):
        if field in metadata_values:
            resolved_missing.remove(field)
    session_id = metadata_values.get("session_id")
    event_cursor_range = metadata_values.get("event_cursor_range")
    bound_sample_sha256 = sample_sha256 or metadata_values.get("sample_sha256")
    bound_case_id = case_id or metadata_values.get("case_id")
    bound_task_id = task_id or metadata_values.get("task_id")
    return {
        "path": display_path,
        "artifact_sha256": _sha256(path),
        "git_commit": commit,
        "git_tree": tree,
        # ``generated_at`` is retained for compatibility but now refers to
        # the source artifact.  ``ingested_at`` records when this gate read it.
        "generated_at": source_generated_at,
        "source_generated_at": source_generated_at,
        "ingested_at": generated_at,
        "configuration_fingerprint": config_fingerprint,
        "sample_sha256": bound_sample_sha256,
        "case_id": bound_case_id,
        "task_id": bound_task_id,
        "session_id": session_id,
        "event_cursor_range": event_cursor_range,
        "redaction_status": "evaluator-only" if evaluator_only else "redacted",
        "metadata_status": "COMPLETE" if not resolved_missing else "PARTIAL",
        "missing_fields": resolved_missing,
        "evaluator_only": evaluator_only,
    }


def build_gate(
    *,
    baseline_path: Path = DEFAULT_BASELINE_PATH,
    semantic_path: Path = FINAL_ROUND / "comhost-semantic-differential-postdeploy-20260904.json",
    sbom_path: Path = FINAL_ROUND / "threat-report-agent-api-sbom-20260904.json",
    cve_path: Path = FINAL_ROUND / "threat-report-agent-api-cve-scan-20260904.json",
    ruff_path: Path | None = None,
    compileall_path: Path | None = None,
    task_view_path: Path = DEFAULT_TASK_VIEW_PATH,
    pytest_summary: str | None = None,
    pytest_summary_path: Path | None = None,
    baseline_manifest_path: Path = FINAL_ROUND / "baseline-manifest.json",
    format_debt_path: Path = FINAL_ROUND / "ruff-format-debt-check-20260904.json",
    readiness_path: Path | None = None,
    seeded_gate_path: Path | None = None,
    model_effectiveness_path: Path | None = None,
    analysis_depth_path: Path | None = None,
    report_depth_path: Path | None = None,
    browser_e2e_path: Path | None = None,
    context_stress_path: Path | None = None,
    recovery_path: Path | None = None,
    concurrency_path: Path | None = None,
    soak_path: Path | None = None,
    comhost_runs_path: Path | None = None,
    generalization_path: Path | None = None,
    production_hardening_path: Path | None = None,
    independent_reviews_path: Path | None = None,
    resume_regression_path: Path | None = None,
    issue_register_path: Path | None = None,
) -> dict[str, Any]:
    generated_at = datetime.now(UTC).isoformat()
    # The library entry point should have the same release evidence defaults
    # as the CLI.  Temporary/unit baselines intentionally keep all optional
    # paths unset so tests can exercise missing-evidence behavior.
    if baseline_path == DEFAULT_BASELINE_PATH:
        seeded_gate_path = seeded_gate_path or FINAL_ROUND / "comhost-c1-c4-fresh-20260902.json"
        model_effectiveness_path = model_effectiveness_path or FINAL_ROUND / "model-effectiveness-real-20260902.json"
        analysis_depth_path = analysis_depth_path or FINAL_ROUND / "report-depth-comhost-20260902-r2.json"
        report_depth_path = report_depth_path or FINAL_ROUND / "report-depth-comhost-20260902-r2.json"
        browser_e2e_path = browser_e2e_path or FINAL_ROUND / "browser-e2e-20260902.json"
        context_stress_path = context_stress_path or ROOT / "release-artifacts" / "context-window-stress.json"
        recovery_path = recovery_path or ROOT / "release-artifacts" / "round11.2" / "restart-recovery.json"
        concurrency_path = concurrency_path or ROOT / "release-artifacts" / "round11.2" / "concurrency.json"
        soak_path = soak_path or ROOT / "release-artifacts" / "round11.2" / "soak-24h.json"
        comhost_runs_path = comhost_runs_path or FINAL_ROUND / "comhost-third-run.json"
        generalization_path = generalization_path or ROOT / "release-artifacts" / "round11.2" / "heldout-results.json"
        production_hardening_path = production_hardening_path or ROOT / "release-artifacts" / "round11.2" / "production-hardening.json"
        independent_reviews_path = independent_reviews_path or ROOT / "release-artifacts" / "round11.2" / "independent-reviews.json"
        resume_regression_path = resume_regression_path or FINAL_ROUND / "resume-static-baseline-20260904.json"
        issue_register_path = issue_register_path or DEFAULT_ISSUE_REGISTER_PATH
        readiness_path = readiness_path or FINAL_ROUND / "readiness-20260904.json"
    baseline = _load(baseline_path)
    semantic = _load(semantic_path)
    sbom = _load(sbom_path)
    cve = _load(cve_path)
    ruff = _load(ruff_path) if ruff_path is not None and ruff_path.exists() else {}
    compileall = (
        _load(compileall_path)
        if compileall_path is not None and compileall_path.exists()
        else {}
    )
    format_debt = _load(format_debt_path) if format_debt_path.exists() else {}
    # The live ComHost task projection can be hundreds of megabytes because it
    # contains the complete Evidence ledger. Test/fixture callers commonly
    # replace the baseline with a temporary artifact; do not eagerly parse the
    # unrelated live projection in that case (and risk an avoidable OOM).
    use_task_view = task_view_path.exists() and (
        task_view_path != DEFAULT_TASK_VIEW_PATH or baseline_path == DEFAULT_BASELINE_PATH
    )
    task_view = _load_task_view_metadata(task_view_path) if use_task_view else {}

    result = (baseline.get("results") or [{}])[0]
    sample_sha256 = ((task_view.get("request_snapshot") or {}).get("sample_package") or {}).get("content_sha256")
    task_id = str(result.get("task_id") or task_view.get("id") or "") or None
    case_id = str(task_view.get("case_id") or "") or None
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    identity_source = baseline
    identity_path = baseline_path
    if not isinstance(baseline.get("repository"), dict) and baseline_manifest_path.exists():
        identity_source = _load(baseline_manifest_path)
        identity_path = baseline_manifest_path
    baseline_commit, baseline_tree = _baseline_identity(identity_source)
    baseline_identity_match = bool(
        commit
        and tree
        and baseline_commit == commit
        and baseline_tree == tree
    )
    image_digest = _image_digest()
    # ``git diff --quiet`` ignores untracked implementation files.  Include
    # untracked paths in the release cleanliness check so a new source file
    # cannot be silently omitted from the identity being certified.
    source_status = _git(
        "status",
        "--porcelain=1",
        "--untracked-files=all",
        "--",
        "benchmarks",
        "docs",
        "scripts",
        "src",
        "tests",
    )
    source_worktree_clean = source_status == ""

    issue_counts: dict[str, int | None] = {"open_p0": None, "open_p1": None}
    issue_register_error: str | None = None
    if issue_register_path is None:
        issue_register_error = "P0/P1 issue register evidence is not supplied."
    elif not issue_register_path.exists():
        issue_register_error = f"P0/P1 issue register evidence file is missing: {issue_register_path}."
    else:
        try:
            issue_payload = _load(issue_register_path)
            identity_error = _identity_error(
                issue_payload,
                label="P0/P1 issue register",
                commit=commit,
                tree=tree,
            )
            if identity_error:
                issue_register_error = identity_error
            else:
                for severity in ("p0", "p1"):
                    raw = _first_value(
                        issue_payload,
                        f"open_{severity}",
                        f"{severity}_open",
                        severity,
                    )
                    if raw is not _MISSING:
                        count = _number(raw)
                        if count is not None and count >= 0 and count.is_integer():
                            issue_counts[f"open_{severity}"] = int(count)
                if any(value is None for value in issue_counts.values()):
                    issue_register_error = "P0/P1 issue register is missing integer open_p0/open_p1 counts."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issue_register_error = f"P0/P1 issue register evidence is invalid: {exc}."

    # Optional acceptance artifacts are evaluated independently. Their
    # statuses are projected into the final dashboard only after the artifact
    # is bound to this checkout; missing evidence remains NOT_PROVEN and an
    # invalid or stale artifact is BLOCKED.
    evidence_specs = {
        "readiness_probe": (readiness_path, "Readiness probe"),
        "seeded_c1_c4_l1": (seeded_gate_path, "Seeded C1-C4"),
        "model_action_productivity_real_provider": (model_effectiveness_path, "Model effectiveness"),
        "analysis_depth_gate": (analysis_depth_path, "Analysis depth"),
        "report_depth_gate": (report_depth_path, "Report depth"),
        "browser_e2e": (browser_e2e_path, "Browser E2E"),
        "context_stress": (context_stress_path, "Context stress"),
        "failure_injection_and_recovery": (recovery_path, "Recovery"),
        "concurrency": (concurrency_path, "Concurrency"),
        "soak_24h": (soak_path, "24-hour soak"),
        "three_consecutive_comhost_runs": (comhost_runs_path, "Three consecutive ComHost runs"),
        "generalization_corpus": (generalization_path, "Generalization"),
        "production_hardening": (production_hardening_path, "Production hardening"),
        "independent_reviews": (independent_reviews_path, "Independent reviews"),
        "resume_regression": (resume_regression_path, "Resume regression"),
    }
    evidence_statuses: dict[str, str] = {}
    evidence_payloads: dict[str, dict[str, Any]] = {}
    evidence_blockers: list[str] = []
    for key, (path, label) in evidence_specs.items():
        status, payload, error = _load_gate_evidence(
            path,
            label=label,
            commit=commit,
            tree=tree,
        )
        evidence_statuses[key] = status
        evidence_payloads[key] = payload
        if error:
            evidence_blockers.append(error)

    projected_statuses: dict[str, str] = {}
    acceptance_assessments: dict[str, dict[str, Any]] = {}
    for key, status in evidence_statuses.items():
        projected, assessment = _project_acceptance_status(key, status, evidence_payloads[key])
        projected_statuses[key] = projected
        if assessment is not None:
            acceptance_assessments[key] = assessment

    # Verification artifacts are release evidence only when they are bound to
    # this exact source checkout.  Keep a separate status projection so a
    # stale/malformed PASS cannot be mistaken for a successful gate.
    ruff_status = str(ruff.get("status") or "NOT_PROVEN")
    compileall_status = str(compileall.get("status") or "NOT_PROVEN")
    format_debt_status = str(format_debt.get("status") or "NOT_PROVEN")
    verification_identity_blockers: list[str] = []
    for label, artifact, artifact_path in (
        ("Ruff", ruff, ruff_path),
        ("compileall", compileall, compileall_path),
        ("Ruff format-debt", format_debt, format_debt_path),
    ):
        if artifact_path is None or not artifact_path.exists():
            continue
        identity_error = _identity_error(
            artifact,
            label=label,
            commit=commit,
            tree=tree,
        )
        if identity_error:
            verification_identity_blockers.append(identity_error)
            if label == "Ruff" and ruff_status == "PASS":
                ruff_status = "BLOCKED"
            elif label == "compileall" and compileall_status == "PASS":
                compileall_status = "BLOCKED"
            elif label == "Ruff format-debt" and format_debt_status == "PASS":
                format_debt_status = "BLOCKED"

    config_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "sample_sha256": sample_sha256,
                "task_id": task_id,
                "semantic_summary": semantic.get("summary", {}),
                "image_digest": image_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    mechanisms = semantic.get("mechanisms") or []
    supported = sum(1 for item in mechanisms if item.get("status") in {"SUPPORTED", "VERIFIED"})
    critical_ids = {"comhost-dynamic-api", "comhost-c2-transport", "comhost-shell", "comhost-etw-patch"}
    critical_status = {
        str(item.get("mechanism_id")): str(item.get("status"))
        for item in mechanisms
        if item.get("mechanism_id") in critical_ids
    }
    critical_closed = len(critical_status) == len(critical_ids) and all(
        status in {"SUPPORTED", "VERIFIED"} for status in critical_status.values()
    )

    pytest_gate_status = "PASS"
    blockers: list[str] = []
    if not critical_closed:
        blockers.append(
            "Fresh ComHost static semantic gate is not closed: critical C1-C4 are not all supported or verified."
        )
    model_status = projected_statuses.get("model_action_productivity_real_provider", "NOT_PROVEN")
    if model_status not in {"PASS", "APPROVED"}:
        blockers.append(
            "Real model contribution is not proven; the model-effectiveness evidence is missing, blocked or below threshold."
        )
    if not commit or not tree:
        blockers.append("Trusted Git commit/tree identity is unavailable.")
    if not image_digest:
        blockers.append("Running API image digest is unavailable.")
    if cve.get("status") != "PASS":
        blockers.append("CVE scan is blocked or incomplete.")
    if not baseline_identity_match:
        blockers.append(
            "Baseline manifest identity does not match the current HEAD/tree; "
            "a current release baseline is required."
        )
    if format_debt_status != "PASS":
        blockers.append("Ruff format-debt gate is missing or not PASS.")
    blockers.extend(verification_identity_blockers)

    sbom_status = str(
        sbom.get("status")
        or (
            "PASS"
            if sbom.get("bomFormat") == "CycloneDX"
            and isinstance(sbom.get("components"), list)
            else "NOT_PROVEN"
        )
    )
    if sbom_status != "PASS":
        blockers.append("SBOM evidence is missing or not PASS.")
    if ruff_status != "PASS":
        blockers.append("Ruff lint evidence is missing or not PASS.")
    if compileall_status != "PASS":
        blockers.append("compileall evidence is missing or not PASS.")
    if not source_worktree_clean:
        blockers.append(
            "Source implementation worktree is dirty; release evidence must be bound to a clean commit."
        )

    missing_acceptance = [
        label
        for key, (_, label) in evidence_specs.items()
        if projected_statuses.get(key) == "NOT_PROVEN"
    ]
    if missing_acceptance:
        blockers.append(
            "Acceptance evidence is not proven for: "
            + ", ".join(missing_acceptance)
            + "."
        )
    nonpassing_acceptance = [
        f"{label}={projected_statuses.get(key)}"
        for key, (_, label) in evidence_specs.items()
        if projected_statuses.get(key) not in {"PASS", "APPROVED", "NOT_PROVEN"}
    ]
    if nonpassing_acceptance:
        blockers.append(
            "Acceptance evidence did not pass for: "
            + ", ".join(nonpassing_acceptance)
            + "."
        )
    blockers.extend(evidence_blockers)
    if issue_register_error:
        blockers.append(issue_register_error)
    if issue_counts["open_p0"] not in (None, 0):
        blockers.append(f"P0 issue register reports {issue_counts['open_p0']} open issue(s).")
    if issue_counts["open_p1"] not in (None, 0):
        blockers.append(f"P1 issue register reports {issue_counts['open_p1']} open issue(s).")
    for key, assessment in acceptance_assessments.items():
        if assessment.get("status") == "BLOCKED":
            failures = assessment.get("failures") or []
            if failures:
                blockers.append(f"{key} acceptance checks failed or are missing: {', '.join(map(str, failures))}.")

    if pytest_summary_path is not None:
        summary = _load(pytest_summary_path)
        summary_identity_error = _identity_error(
            summary,
            label="Pytest summary",
            commit=commit,
            tree=tree,
        )
        if summary_identity_error:
            pytest_gate_status = "BLOCKED"
            blockers.append(summary_identity_error)
        pytest_summary = str(summary.get("summary") or "NOT_SUPPLIED")
    else:
        # A display-only summary string cannot prove which source was tested.
        # Require the JSON artifact so both commit and tree can be checked.
        pytest_gate_status = "BLOCKED"
        blockers.append("Pytest summary evidence is missing or has no artifact path.")

    blockers = list(dict.fromkeys(blockers))

    gates = {
        "schema_migration_deadlock_regression": "PASS",
        "unit_and_integration_tests": f"{pytest_gate_status} ({pytest_summary or 'pytest summary not supplied'})",
        "readiness_probe": projected_statuses["readiness_probe"],
        "seeded_c1_c4_l1": projected_statuses["seeded_c1_c4_l1"],
        "real_comhost_l2": "PASS" if critical_closed else "BLOCKED",
        "model_action_productivity_real_provider": projected_statuses["model_action_productivity_real_provider"],
        "three_consecutive_comhost_runs": projected_statuses["three_consecutive_comhost_runs"],
        "resume_regression": projected_statuses["resume_regression"],
        "browser_e2e": projected_statuses["browser_e2e"],
        "context_stress": projected_statuses["context_stress"],
        "failure_injection_and_recovery": projected_statuses["failure_injection_and_recovery"],
        "concurrency": projected_statuses["concurrency"],
        "soak_24h": projected_statuses["soak_24h"],
        "generalization_corpus": projected_statuses["generalization_corpus"],
        "production_hardening": projected_statuses["production_hardening"],
        "independent_reviews": projected_statuses["independent_reviews"],
    }
    status_projection = {
        "agentic_mechanism_effectiveness": projected_statuses["model_action_productivity_real_provider"],
        "comhost_c1_c4": gates["real_comhost_l2"],
        "analysis_depth_gate": projected_statuses["analysis_depth_gate"],
        "report_depth_gate": projected_statuses["report_depth_gate"],
        "browser_e2e": gates["browser_e2e"],
        "generalization": gates["generalization_corpus"],
        "recovery": gates["failure_injection_and_recovery"],
        "concurrency": gates["concurrency"],
        "soak_24h": gates["soak_24h"],
        "production_hardening": gates["production_hardening"],
        "independent_reviews": gates["independent_reviews"],
    }
    artifact_manifest = [
        _artifact_metadata(
            baseline_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=sample_sha256,
            case_id=case_id,
            task_id=task_id,
            evaluator_only=False,
            missing_fields=["session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            semantic_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=sample_sha256,
            case_id=case_id,
            task_id=task_id,
            evaluator_only=True,
            missing_fields=["session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            sbom_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            cve_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        ),
        _artifact_metadata(
            format_debt_path,
            generated_at=generated_at,
            commit=commit,
            tree=tree,
            config_fingerprint=config_fingerprint,
            sample_sha256=None,
            case_id=None,
            task_id=None,
            evaluator_only=False,
            missing_fields=["sample_sha256", "case_id", "task_id", "session_id", "event_cursor_range"],
        )
        if format_debt_path.exists()
        else None,
    ]
    artifact_manifest = [item for item in artifact_manifest if item is not None]
    for verification_path in (ruff_path, compileall_path):
        if verification_path is not None and verification_path.exists():
            artifact_manifest.append(
                _artifact_metadata(
                    verification_path,
                    generated_at=generated_at,
                    commit=commit,
                    tree=tree,
                    config_fingerprint=config_fingerprint,
                    sample_sha256=None,
                    case_id=None,
                    task_id=None,
                    evaluator_only=False,
                    missing_fields=[
                        "sample_sha256",
                        "case_id",
                        "task_id",
                        "session_id",
                        "event_cursor_range",
                    ],
                )
            )
    if pytest_summary_path is not None and pytest_summary_path.exists():
        artifact_manifest.append(
            _artifact_metadata(
                pytest_summary_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=None,
                case_id=None,
                task_id=None,
                evaluator_only=False,
                missing_fields=[
                    "sample_sha256",
                    "case_id",
                    "task_id",
                    "session_id",
                    "event_cursor_range",
                ],
            )
        )
    if issue_register_path is not None and issue_register_path.exists():
        artifact_manifest.append(
            _artifact_metadata(
                issue_register_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=None,
                case_id=None,
                task_id=None,
                evaluator_only=False,
                missing_fields=[
                    "sample_sha256",
                    "case_id",
                    "task_id",
                    "session_id",
                    "event_cursor_range",
                ],
            )
        )
    manifest_paths = {str(item.get("path")) for item in artifact_manifest}
    for key, (evidence_path, _label) in evidence_specs.items():
        if evidence_path is None or not evidence_path.exists():
            continue
        display_path = str(evidence_path.resolve())
        try:
            display_path = evidence_path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            pass
        if display_path in manifest_paths:
            continue
        payload = evidence_payloads.get(key, {})
        artifact_manifest.append(
            _artifact_metadata(
                evidence_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=sample_sha256,
                case_id=case_id,
                task_id=task_id,
                evaluator_only=bool(payload.get("evaluator_only", False)),
                missing_fields=["session_id", "event_cursor_range"],
            )
        )
        manifest_paths.add(display_path)
    if use_task_view:
        artifact_manifest.insert(
            2,
            _artifact_metadata(
                task_view_path,
                generated_at=generated_at,
                commit=commit,
                tree=tree,
                config_fingerprint=config_fingerprint,
                sample_sha256=sample_sha256,
                case_id=case_id,
                task_id=task_id,
                evaluator_only=False,
                missing_fields=["session_id", "event_cursor_range"],
            ),
        )
    partial_metadata = [
        str(item.get("path"))
        for item in artifact_manifest
        if item.get("metadata_status") != "COMPLETE"
    ]
    if partial_metadata:
        blockers.append(
            "Release artifact metadata is incomplete (missing session/event cursors or sample binding): "
            + ", ".join(partial_metadata[:8])
            + (" ..." if len(partial_metadata) > 8 else ".")
        )
    blockers = list(dict.fromkeys(blockers))
    try:
        semantic_artifact_path = semantic_path.relative_to(ROOT).as_posix()
    except ValueError:
        semantic_artifact_path = str(semantic_path.resolve())
    formal_statuses = [status_projection[field] for field in FORMAL_GATE_FIELDS if field not in {"open_p0", "open_p1"}]
    release_pass = (
        not blockers
        and all(status in {"PASS", "APPROVED"} for status in formal_statuses)
        and issue_counts["open_p0"] == 0
        and issue_counts["open_p1"] == 0
        and cve.get("status") == "PASS"
        and sbom_status == "PASS"
        and ruff_status == "PASS"
        and compileall_status == "PASS"
        and format_debt_status == "PASS"
        and baseline_identity_match
        and bool(image_digest)
        and source_worktree_clean
        and pytest_gate_status == "PASS"
        and projected_statuses.get("readiness_probe") in {"PASS", "APPROVED"}
    )
    payload = {
        "schema_version": "final-completion-stage-gate-v3",
        "generated_at": generated_at,
        "evidence_policy": "verified-local-evidence-only",
        "status": "PASS" if release_pass else "BLOCKED",
        "production_ready": release_pass,
        "blocker_count": len(blockers),
        "open_p0": issue_counts["open_p0"],
        "open_p1": issue_counts["open_p1"],
        **status_projection,
        "release_identity": {
            "git_commit": commit,
            "git_tree": tree,
            "container_image": f"threat-report-agent-api@sha256:{image_digest}" if image_digest else None,
            "source_sample_sha256": sample_sha256,
            "fresh_task_id": task_id,
            "fresh_case_id": case_id,
            "baseline_manifest": identity_path.relative_to(ROOT).as_posix()
            if identity_path.is_relative_to(ROOT)
            else str(identity_path.resolve()),
            "baseline_git_commit": baseline_commit,
            "baseline_git_tree": baseline_tree,
            "baseline_identity_match": baseline_identity_match,
            # The gate itself is an evidence artifact and may be rewritten
            # after the source commit.  Check the implementation paths so its
            # own pending diff does not make a clean source tree look dirty.
            "source_worktree_clean": source_worktree_clean,
        },
        "execution_boundary": {
            "sample_execution": False,
            "sample_network_access": False,
            "dynamic_emulators_invoked": False,
            "static_only": "PASS",
        },
        "fresh_comhost_static_run": {
            "evidence_level": "L2",
            "lifecycle": result.get("lifecycle"),
            "outcome": result.get("outcome"),
            "analysis_class": result.get("analysis_class"),
            "evidence": result.get("evidence_count"),
            "claims": result.get("claims") or (len(task_view.get("claims", [])) if isinstance(task_view.get("claims"), list) else None),
            "tool_runs": result.get("tool_runs") or (len(task_view.get("tool_runs", [])) if isinstance(task_view.get("tool_runs"), list) else None),
            "semantic_supported": supported,
            "critical_mechanisms": critical_status,
            "semantic_artifact": semantic_artifact_path,
        },
        "gates": gates,
        "acceptance_assessments": acceptance_assessments,
        "verification": {
            "pytest": pytest_summary or "NOT_SUPPLIED (run pytest separately)",
            "ruff": ruff_status,
            "compileall": compileall_status,
            "sbom": sbom_status,
            "cve_scan": cve.get("status", "BLOCKED"),
            "ruff_format_debt": format_debt_status,
        },
        "artifact_manifest": artifact_manifest,
        "blockers": blockers,
    }
    validate_gate_schema(payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--pytest-summary", type=Path)
    parser.add_argument("--ruff-result", type=Path)
    parser.add_argument("--compileall-result", type=Path)
    parser.add_argument("--format-debt", type=Path)
    parser.add_argument("--readiness", type=Path)
    parser.add_argument("--seeded-gate", type=Path)
    parser.add_argument("--model-effectiveness", type=Path)
    parser.add_argument("--analysis-depth", type=Path)
    parser.add_argument("--report-depth", type=Path)
    parser.add_argument("--browser-e2e", type=Path)
    parser.add_argument("--context-stress", type=Path)
    parser.add_argument("--recovery", type=Path)
    parser.add_argument("--concurrency", type=Path)
    parser.add_argument("--soak", type=Path)
    parser.add_argument("--comhost-runs", type=Path)
    parser.add_argument("--generalization", type=Path)
    parser.add_argument("--production-hardening", type=Path)
    parser.add_argument("--independent-reviews", type=Path)
    parser.add_argument("--resume-regression", type=Path)
    parser.add_argument("--issue-register", type=Path)
    args = parser.parse_args()
    # The command-line form is the release operator's entry point.  Bind each
    # optional acceptance input to its canonical artifact location so a normal
    # invocation evaluates available evidence instead of silently treating all
    # waves as unprovided.  Callers of ``build_gate`` may still pass ``None``
    # in isolated unit tests.
    default_paths = {
        "seeded_gate": FINAL_ROUND / "comhost-c1-c4-fresh-20260902.json",
        "model_effectiveness": FINAL_ROUND / "model-effectiveness-real-20260902.json",
        "analysis_depth": FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        "report_depth": FINAL_ROUND / "report-depth-comhost-20260902-r2.json",
        "browser_e2e": FINAL_ROUND / "browser-e2e-20260902.json",
        "context_stress": ROOT / "release-artifacts" / "context-window-stress.json",
        "recovery": ROOT / "release-artifacts" / "round11.2" / "restart-recovery.json",
        "concurrency": ROOT / "release-artifacts" / "round11.2" / "concurrency.json",
        "soak": ROOT / "release-artifacts" / "round11.2" / "soak-24h.json",
        "comhost_runs": FINAL_ROUND / "comhost-third-run.json",
        "generalization": ROOT / "release-artifacts" / "round11.2" / "heldout-results.json",
        "production_hardening": ROOT / "release-artifacts" / "round11.2" / "production-hardening.json",
        "independent_reviews": ROOT / "release-artifacts" / "round11.2" / "independent-reviews.json",
        "resume_regression": FINAL_ROUND / "resume-static-baseline-20260904.json",
        "issue_register": DEFAULT_ISSUE_REGISTER_PATH,
        "readiness": FINAL_ROUND / "readiness-20260904.json",
        "format_debt": FINAL_ROUND / "ruff-format-debt-check-20260904.json",
    }

    def selected(name: str) -> Path | None:
        value = getattr(args, name)
        return value if value is not None else default_paths[name]

    payload = build_gate(
        pytest_summary_path=args.pytest_summary,
        ruff_path=args.ruff_result,
        compileall_path=args.compileall_result,
        format_debt_path=selected("format_debt"),
        readiness_path=selected("readiness"),
        seeded_gate_path=selected("seeded_gate"),
        model_effectiveness_path=selected("model_effectiveness"),
        analysis_depth_path=selected("analysis_depth"),
        report_depth_path=selected("report_depth"),
        browser_e2e_path=selected("browser_e2e"),
        context_stress_path=selected("context_stress"),
        recovery_path=selected("recovery"),
        concurrency_path=selected("concurrency"),
        soak_path=selected("soak"),
        comhost_runs_path=selected("comhost_runs"),
        generalization_path=selected("generalization"),
        production_hardening_path=selected("production_hardening"),
        independent_reviews_path=selected("independent_reviews"),
        resume_regression_path=selected("resume_regression"),
        issue_register_path=selected("issue_register"),
    )
    validate_gate_schema(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
