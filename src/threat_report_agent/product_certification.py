"""Round 11 product contracts and offline certification helpers.

The module is deliberately independent from the database and the DSH plugin.
It provides the small, deterministic seams used by intake, reporting and
release evaluation.  It never executes a sample, performs network access, or
loads benchmark answers into an analysis context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence


class AnalysisResultClass(StrEnum):
    """Product-level result class, separate from task lifecycle."""

    FULL_STATIC_ANALYSIS = "FULL_STATIC_ANALYSIS"
    BOUNDED_STATIC_ANALYSIS = "BOUNDED_STATIC_ANALYSIS"
    UNSUPPORTED_ARTIFACT = "UNSUPPORTED_ARTIFACT"
    FAILED_ANALYSIS = "FAILED_ANALYSIS"


# Short alias used by API consumers that call this an analysis class.
AnalysisClass = AnalysisResultClass


class FailureRootCause(StrEnum):
    ARTIFACT_FAILURE = "ARTIFACT_FAILURE"
    SEED_DISCOVERY_FAILURE = "SEED_DISCOVERY_FAILURE"
    QUESTION_FAILURE = "QUESTION_FAILURE"
    RETRIEVAL_FAILURE = "RETRIEVAL_FAILURE"
    DELIVERY_FAILURE = "DELIVERY_FAILURE"
    CONTEXT_QUALITY_FAILURE = "CONTEXT_QUALITY_FAILURE"
    ACTION_FAILURE = "ACTION_FAILURE"
    TOOL_RESULT_FAILURE = "TOOL_RESULT_FAILURE"
    MECHANISM_SYNTHESIS_FAILURE = "MECHANISM_SYNTHESIS_FAILURE"
    VERIFIER_FAILURE = "VERIFIER_FAILURE"
    CLAIM_GATE_FAILURE = "CLAIM_GATE_FAILURE"
    REPORT_FAILURE = "REPORT_FAILURE"
    BOUNDARY_CLASSIFICATION_FAILURE = "BOUNDARY_CLASSIFICATION_FAILURE"
    PRODUCT_FAILURE = "PRODUCT_FAILURE"


@dataclass(frozen=True)
class SupportedArtifact:
    artifact_class: str
    labels: tuple[str, ...]
    requirement: str
    analyzer_tools: tuple[str, ...]
    default_result: AnalysisResultClass
    notes: str = ""


SUPPORTED_ARTIFACT_MATRIX: tuple[SupportedArtifact, ...] = (
    SupportedArtifact("pe32_x86_exe", ("PE32", "x86", "EXE"), "REQUIRED", ("pe-parser", "ghidra-headless"), AnalysisResultClass.FULL_STATIC_ANALYSIS),
    SupportedArtifact("pe32plus_x64_exe", ("PE32+", "x64", "EXE"), "REQUIRED", ("pe-parser", "ghidra-headless"), AnalysisResultClass.FULL_STATIC_ANALYSIS),
    SupportedArtifact("pe_dll", ("PE", "DLL"), "REQUIRED", ("pe-parser", "ghidra-headless"), AnalysisResultClass.FULL_STATIC_ANALYSIS),
    SupportedArtifact("dotnet_pe", (".NET", "PE"), "REQUIRED", ("pe-parser", "ghidra-headless"), AnalysisResultClass.BOUNDED_STATIC_ANALYSIS, "At least triage and static report are required."),
    SupportedArtifact("archive", ("ZIP", "container"), "REQUIRED", ("python-zipfile-safe-reader",), AnalysisResultClass.FULL_STATIC_ANALYSIS, "Children retain parent provenance."),
    SupportedArtifact("script", ("PS1", "VBS", "JS", "BAT", "CMD"), "REQUIRED", ("script-parser",), AnalysisResultClass.FULL_STATIC_ANALYSIS),
    SupportedArtifact("carrier", ("PDF", "OLE", "OOXML"), "REQUIRED", ("document-carrier-parser",), AnalysisResultClass.BOUNDED_STATIC_ANALYSIS, "Carrier-level static analysis; children are analyzed when safely recoverable."),
    SupportedArtifact("damaged_binary", ("damaged", "truncated"), "REQUIRED", ("pe-parser", "builtin-static-analyzer"), AnalysisResultClass.BOUNDED_STATIC_ANALYSIS),
    SupportedArtifact("packed_pe", ("packed", "virtualized", "PE"), "REQUIRED", ("pe-parser", "ghidra-headless"), AnalysisResultClass.BOUNDED_STATIC_ANALYSIS, "Packing is a static boundary, not a product failure."),
    SupportedArtifact("elf", ("ELF",), "NEXT_VERSION", (), AnalysisResultClass.UNSUPPORTED_ARTIFACT),
    SupportedArtifact("macho", ("Mach-O",), "NEXT_VERSION", (), AnalysisResultClass.UNSUPPORTED_ARTIFACT),
)

_SUPPORTED_TYPES = {"pe", "script", "pdf", "ole", "ooxml", "zip", "archive", "carrier", "text"}
_UNSUPPORTED_TYPES = {"elf", "macho", "mach-o", "apk", "unknown", "unsupported"}
_BOUNDARY_TERMS = (
    "packed", "packers", "virtualized", "self-modif", "runtime-only", "runtime only",
    "opaque predicate", "unresolved indirect", "decompiler failed", "truncated", "damaged",
    "unsupported decoded", "static boundary", "requires runtime",
    "cannot be determined from static evidence", "not be determined from static evidence",
    "may limit the depth", "runtime-evaluated strings", "encrypted or obfuscated",
    "misclassification of a binary", "requires dynamic analysis",
    "without dynamic analysis", "cannot be definitively proven", "cannot be fully proven statically",
    "impossible to determine actual", "limiting the complexity", "limiting the depth",
    "missing custom dll", "missing required dll", "missing external component",
    "required external component", "custom dlls are not present",
)


def supported_artifact_matrix() -> tuple[dict[str, object], ...]:
    """Return a JSON-safe copy of the public support matrix."""
    return tuple(
        {
            "artifact_class": item.artifact_class,
            "labels": list(item.labels),
            "requirement": item.requirement,
            "analyzer_tools": list(item.analyzer_tools),
            "default_result": item.default_result.value,
            "notes": item.notes,
        }
        for item in SUPPORTED_ARTIFACT_MATRIX
    )


def _text(values: Iterable[object]) -> str:
    return " ".join(str(value) for value in values if value is not None).casefold()


def classify_artifact_result(
    detected_type: str,
    *,
    tool_runs: Iterable[Mapping[str, object]] = (),
    limitations: Iterable[object] = (),
    structural_limitations: Iterable[object] | None = None,
    metadata: Mapping[str, object] | None = None,
    semantic_coverage: Mapping[str, object] | None = None,
) -> AnalysisResultClass:
    """Classify one artifact without conflating a boundary with a failure.

    A supported artifact with no successful tool run is ``FAILED_ANALYSIS``.
    A successful run with explicit static limitations is ``BOUNDED``.  Unknown
    formats are ``UNSUPPORTED``.  The function is intentionally conservative:
    absence of an indicator never upgrades a result to a full analysis.
    """
    normalized = str(detected_type or "unknown").strip().casefold()
    if normalized in _UNSUPPORTED_TYPES or normalized not in _SUPPORTED_TYPES:
        return AnalysisResultClass.UNSUPPORTED_ARTIFACT
    runs = list(tool_runs)
    successful = any(str(row.get("status", "")).upper() == "SUCCEEDED" for row in runs)
    if not successful:
        return AnalysisResultClass.FAILED_ANALYSIS
    meta = metadata or {}
    # New callers must classify only structural static blockers. ``limitations``
    # remains the compatibility input for older integrations; passing an
    # explicit empty structural list intentionally means that runtime-only
    # unknowns do not downgrade an otherwise analyzable static result.
    if structural_limitations is None:
        boundary_values = (*limitations, *meta.values())
    else:
        boundary_values = (
            *structural_limitations,
            *[meta.get(key, "") for key in (
                "packing", "packer", "virtualization", "static_boundary",
                "code_recovery_failure", "decompiler_status", "truncated",
            )],
        )
    boundary = _text(boundary_values)
    if any(term in boundary for term in _BOUNDARY_TERMS):
        return AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    if semantic_coverage is not None:
        verified = float(semantic_coverage.get("verified_mechanism_coverage", 0.0) or 0.0)
        flow = float(semantic_coverage.get("relation_flow_coverage", 0.0) or 0.0)
        if verified <= 0.0 and flow <= 0.0:
            # A successful parser with no semantic closure is not a full
            # analysis. The result remains usable but is explicitly bounded
            # until targeted static investigation produces a supported path.
            return AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    return AnalysisResultClass.FULL_STATIC_ANALYSIS


def aggregate_result_class(classes: Iterable[AnalysisResultClass | str]) -> AnalysisResultClass:
    """Aggregate child classes using the strictest truthful task result."""
    values = [AnalysisResultClass(item) for item in classes]
    if not values:
        return AnalysisResultClass.FAILED_ANALYSIS
    if AnalysisResultClass.FAILED_ANALYSIS in values:
        return AnalysisResultClass.FAILED_ANALYSIS
    if all(item == AnalysisResultClass.UNSUPPORTED_ARTIFACT for item in values):
        return AnalysisResultClass.UNSUPPORTED_ARTIFACT
    if AnalysisResultClass.BOUNDED_STATIC_ANALYSIS in values or AnalysisResultClass.UNSUPPORTED_ARTIFACT in values:
        return AnalysisResultClass.BOUNDED_STATIC_ANALYSIS
    return AnalysisResultClass.FULL_STATIC_ANALYSIS


_FORBIDDEN_RUNTIME_WORDING = (
    r"\bconnected\b", r"\bdownloaded successfully\b", r"\bexecuted\b",
    r"\bpersisted successfully\b", r"\bserver responded\b", r"\bc2 active\b",
    r"\bprocess spawned\b", r"\bregistry modification succeeded\b",
    r"\bobserved at runtime\b", r"\bdynamic_observed\b",
)

#: Conservative rewrites that turn an unqualified runtime claim into a conditional one.
#:
#: ONE definition, shared by BOTH publication paths. MEASURED why that matters: the English path
#: (`reporting._static_safe_text`) repaired model prose before checking it, while the published Chinese path
#: (`analyst_report.render_official_markdown`) only RAISED. So a single `connected` written by the model
#: destroyed the entire report - task `8e75f6dc` (白象) ended `FAILED_ANALYSIS` /
#: `REPORT_SYNTHESIS_FAILURE` with `report_available: false`, discarding 5,988 evidence rows and 12 claims
#: because of one word. `_static_safe_text`'s own docstring already stated the requirement this violated:
#: "A single unqualified runtime verb must not abort an otherwise valid static report."
#:
#: Order matters: the more specific phrase must precede its own prefix (`executed successfully` before
#: `executed`).
_STATIC_RUNTIME_REWRITES: tuple[tuple[str, str], ...] = (
    (r"\bconnected\b", "would connect"),
    (r"\bdownloaded successfully\b", "would download"),
    (r"\bexecuted successfully\b", "would execute"),
    (r"\bprocess spawned\b", "process creation would occur"),
    (r"\bregistry modification succeeded\b", "registry modification may succeed"),
    (r"\bserver responded\b", "a server response would be expected"),
    (r"\bc2 active\b", "C2 activity would be possible"),
    (r"\bobserved at runtime\b", "would be observed at runtime"),
    (r"\bdynamic_observed\b", "dynamic observation candidate"),
    (r"\bpersisted successfully\b", "would persist"),
    (r"\bexecuted\b", "would execute"),
)


def repair_static_runtime_wording(text: str) -> str:
    """Rewrite unqualified runtime claims into conditional ones.

    Callers must STILL run `static_wording_violations` on the result. This table is deliberately small and
    does not cover every banned pattern, so a residue means the wording is genuinely unpublishable rather
    than merely unqualified - and that difference must stay visible instead of being silently swallowed.
    """
    if not text:
        return text
    for pattern, replacement in _STATIC_RUNTIME_REWRITES:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
    return text


def static_wording_violations(text: str) -> list[str]:
    """Find unqualified runtime claims in a static-only report."""
    violations: list[str] = []
    # Conditional/negative wording is explicitly allowed ("would attempt",
    # "if executed", "not observed").  Evaluate the smallest punctuation
    # delimited clause containing the match.  Looking only at the immediately
    # preceding token incorrectly rejects natural boundary statements such as
    # "No sample code was executed during this review".
    def quoted_span(line: str, position: int) -> tuple[int, int] | None:
        """Return the quote bounds containing *position*, if any.

        Report projections commonly serialize a detail as ``- detail: "..."``
        or as a JSON value.  Punctuation in that value is prose, not a clause
        boundary.  Double quotes and Markdown backticks are unambiguous here;
        single quotes are accepted only at a token boundary so contractions
        (for example ``can't``) remain ordinary prose.
        """
        quote_start: int | None = None
        quote_char: str | None = None
        escaped = False
        for index, character in enumerate(line):
            if quote_start is None:
                previous = line[index - 1] if index else ""
                single_quote_start = (
                    character == "'"
                    and (not previous or not (previous.isalnum() or previous == "_"))
                    and index + 1 < len(line)
                    and not line[index + 1].isspace()
                )
                if character in {'"', '`'} or single_quote_start:
                    quote_start = index
                    quote_char = character
                    escaped = False
                continue
            if escaped:
                escaped = False
                continue
            if character == "\\" and quote_char == '"':
                escaped = True
                continue
            # An apostrophe in a contraction/possessive is not a closing
            # delimiter (``can't`` / ``sample's``).
            if character == quote_char == "'" and index + 1 < len(line) and line[index + 1].isalnum():
                continue
            if character == quote_char:
                if quote_start < position < index:
                    return quote_start, index
                quote_start = None
                quote_char = None
        if quote_start is not None and quote_start < position:
            # An unterminated value is still safer to evaluate as one quoted
            # span than to let its internal punctuation change the meaning.
            return quote_start, len(line)
        return None

    def qualified(line: str, match: re.Match[str]) -> bool:
        start = match.start()
        quoted = quoted_span(line, start)
        if quoted is not None:
            quote_start, quote_end = quoted
            clause_start = quote_start + 1
            clause_end = quote_end
        else:
            left_candidates = [line.rfind(mark, 0, start) for mark in ".;:!?"]
            clause_start = max(left_candidates, default=-1) + 1
            right_candidates = [line.find(mark, match.end()) for mark in ".;:!?"]
            right_candidates = [item for item in right_candidates if item >= 0]
            clause_end = min(right_candidates, default=len(line))
        clause = line[clause_start:clause_end]
        prefix = line[clause_start:start]
        normalized_prefix = prefix.lower()
        normalized_clause = clause.lower()

        # Explicit negation may precede or follow an auxiliary verb.  The
        # bounded span supports long lists ("No sample, script, macro ...")
        # without allowing a negation from an unrelated sentence to qualify a
        # later assertion.
        negative = bool(
            re.search(r"\b(?:no|not|never|without|neither)\s*$", normalized_prefix)
            or re.search(
                r"\b(?:no|not|never|without|neither)\b[\w\s,()/\\-]{0,180}"
                r"\b(?:was|were|is|are|be|been|being|have|has|had|did|do|does)\s*$",
                normalized_prefix,
            )
            or re.search(
                r"\b(?:was|were|is|are|be|been|being|have|has|had|did|do|does)\b"
                r"[\w\s,()/\\-]{0,80}\b(?:no|not|never|without|neither)\s*$",
                normalized_prefix,
            )
        )
        if negative:
            return True

        # Modal and conditional language describes a hypothetical path rather
        # than an observation.  Keep this scoped to the same clause.
        if re.search(r"\bif\b", normalized_clause):
            return True
        if re.search(r"\b(?:would|could|may|might|can|cannot|can't)\b", normalized_prefix):
            return True
        return False

    for line in str(text).splitlines():
        for pattern in _FORBIDDEN_RUNTIME_WORDING:
            for match in re.finditer(pattern, line, flags=re.IGNORECASE):
                if not qualified(line, match):
                    violations.append(pattern)
    return violations


def analysis_coverage(
    *,
    artifact_parse: float,
    code_recovery: float,
    function_coverage: float,
    data_reference_coverage: float,
    mechanism_investigation: float,
    verifier_coverage: float,
    report_synthesis: float,
    gaps: Iterable[str] = (),
    pipeline_completion: float | None = None,
    pipeline_dimensions: Mapping[str, float] | None = None,
    verified_mechanism_coverage: float | None = None,
    relation_flow_coverage: float | None = None,
    semantic_flow_nodes: int | None = None,
    semantic_flow_edges: int | None = None,
    behavior_flow_present: bool | None = None,
    coverage_applicable: bool | None = None,
    artifact_verified_mechanism_coverage: float | None = None,
    mechanism_count: int | None = None,
    verified_mechanism_count: int | None = None,
) -> dict[str, object]:
    """Build separate pipeline and semantic coverage views.

    ``dimensions`` and ``score`` remain the semantic view for compatibility.
    Pipeline completion is deliberately independent: a successful parser run
    can be 100% complete while mechanism recovery is only partially covered.
    """
    dimensions = {
        "artifact_parse": artifact_parse,
        "code_recovery": code_recovery,
        "function_coverage": function_coverage,
        "data_reference_coverage": data_reference_coverage,
        "mechanism_investigation": mechanism_investigation,
        "verifier_coverage": verifier_coverage,
        "report_synthesis": report_synthesis,
    }
    if verified_mechanism_coverage is not None:
        dimensions["verified_mechanism_coverage"] = verified_mechanism_coverage
    if relation_flow_coverage is not None:
        dimensions["relation_flow_coverage"] = relation_flow_coverage
    normalized = {key: max(0.0, min(1.0, float(value))) for key, value in dimensions.items()}
    score = round(sum(normalized.values()) / len(normalized) * 100, 2)
    # A completed parser/report pipeline must not look semantically healthy
    # when it recovered neither a verified mechanism nor a semantic relation
    # flow.  Keep the two dimensions optional for legacy callers, but apply
    # the hard cap whenever this Round 11.1 contract is present.
    if (
        "verified_mechanism_coverage" in normalized
        and "relation_flow_coverage" in normalized
        and normalized["verified_mechanism_coverage"] <= 0.0
        and normalized["relation_flow_coverage"] <= 0.0
    ):
        score = min(score, 60.0)
    normalized_gaps = list(dict.fromkeys(str(item) for item in gaps))
    if pipeline_completion is None:
        pipeline_completion = normalized.get("report_synthesis", 0.0)
    pipeline = {
        "score": round(max(0.0, min(1.0, float(pipeline_completion))) * 100, 2),
        "dimensions": {
            key: max(0.0, min(1.0, float(value)))
            for key, value in (pipeline_dimensions or {"report_synthesis": report_synthesis}).items()
        },
    }
    semantic = {"score": score, "dimensions": normalized, "gaps": normalized_gaps}
    result = {
        "score": score,
        "dimensions": normalized,
        "gaps": normalized_gaps,
        "semantic_coverage": semantic,
        "pipeline_completion": pipeline,
    }
    if semantic_flow_nodes is not None:
        result["semantic_flow_nodes"] = max(0, int(semantic_flow_nodes))
    if semantic_flow_edges is not None:
        result["semantic_flow_edges"] = max(0, int(semantic_flow_edges))
    if behavior_flow_present is not None:
        result["behavior_flow_present"] = bool(behavior_flow_present)
    if coverage_applicable is not None:
        result["coverage_applicable"] = bool(coverage_applicable)
    if artifact_verified_mechanism_coverage is not None:
        result["artifact_verified_mechanism_coverage"] = max(
            0.0, min(1.0, float(artifact_verified_mechanism_coverage))
        )
    if mechanism_count is not None:
        result["mechanism_count"] = max(0, int(mechanism_count))
    if verified_mechanism_count is not None:
        result["verified_mechanism_count"] = max(0, int(verified_mechanism_count))
    return result


def semantic_flow_metrics(mechanisms: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Measure the report-visible semantic flow contract.

    Only verifier-accepted mechanisms with complete provenance participate.
    The same ordered fields used by the V3 report renderer form each flow:
    input -> transformation/control -> output -> consumer.  Low-level CFG or
    instruction labels are intentionally ignored here.
    """
    from threat_report_agent.investigation.mechanism_completeness import has_semantic_value
    from threat_report_agent.mechanism_ready import inspect_mechanism_ready

    eligible = 0
    participating = 0
    node_order: list[str] = []
    edge_count = 0
    for mechanism in mechanisms:
        if not isinstance(mechanism, Mapping):
            continue
        status = str(mechanism.get("status", "")).upper()
        if status not in {"VERIFIED", "SUPPORTED", "CONFIRMED"}:
            continue
        if not inspect_mechanism_ready(mechanism).critical_ready:
            continue
        eligible += 1
        chain: list[str] = []
        for key in ("inputs", "transformation_or_control", "outputs", "consumers"):
            value = mechanism.get(key)
            if not has_semantic_value(key, value):
                continue
            if isinstance(value, str):
                values = (value,)
            elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
                values = tuple(str(item) for item in value)
            else:
                values = (str(value),)
            for item in values:
                label = item.strip()
                if not label or (chain and chain[-1] == label):
                    continue
                chain.append(label)
        if len(chain) < 3 or not has_semantic_value("evidence_ids", mechanism.get("evidence_ids")):
            continue
        participating += 1
        edge_count += len(chain) - 1
        for node in chain:
            if node not in node_order:
                node_order.append(node)
    applicable = eligible > 0
    return {
        "semantic_flow_nodes": len(node_order),
        "semantic_flow_edges": edge_count,
        "eligible_mechanisms": eligible,
        "participating_mechanisms": participating,
        "relation_flow_coverage": participating / eligible if applicable else 0.0,
        "coverage_applicable": applicable,
        "behavior_flow_present": len(node_order) >= 3 and edge_count >= 2 and participating > 0,
    }


def mechanism_coverage_metrics(
    mechanisms: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Measure semantic closure at mechanism granularity.

    An artifact can contain many independent mechanisms. Counting an artifact
    as verified when only one mechanism is closed overstates coverage,
    especially for PE samples with large candidate sets.
    """
    from threat_report_agent.mechanism_ready import inspect_mechanism_ready

    rows = [
        row
        for row in mechanisms
        if isinstance(row, Mapping)
        and str(row.get("status", "")).upper() != "NOT_APPLICABLE"
    ]
    total = len(rows)
    verified = sum(
        1
        for row in rows
        if str(row.get("status", "")).upper() in {"VERIFIED", "SUPPORTED", "CONFIRMED"}
        and inspect_mechanism_ready(row).critical_ready
    )
    return {
        "mechanism_count": total,
        "verified_mechanism_count": verified,
        "verified_mechanism_coverage": verified / total if total else 0.0,
    }


@dataclass(frozen=True)
class CorpusEntry:
    sample_id: str
    path: str
    sha256: str
    category: str
    split: str
    expected_analysis_class: str = "FULL"
    critical_mechanisms: tuple[str, ...] = ()
    critical_iocs: tuple[str, ...] = ()
    negative_gold: tuple[str, ...] = ()
    important_unknowns: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "sample_id": self.sample_id,
            "path": self.path,
            "sha256": self.sha256,
            "category": self.category,
            "split": self.split,
            "expected_analysis_class": self.expected_analysis_class,
            "critical_mechanisms": list(self.critical_mechanisms),
            "critical_iocs": list(self.critical_iocs),
            "negative_gold": list(self.negative_gold),
            "important_unknowns": list(self.important_unknowns),
        }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_corpus_split(entries: Iterable[Mapping[str, object]]) -> list[str]:
    """Validate corpus counts and the development/certification separation."""
    rows = list(entries)
    errors: list[str] = []
    dev = [row for row in rows if row.get("split") == "development"]
    cert = [row for row in rows if row.get("split") == "certification"]
    dev_malware = sum(str(row.get("category", "")).casefold() == "malware" for row in dev)
    dev_benign = sum(str(row.get("category", "")).casefold() in {"benign", "control"} for row in dev)
    cert_malware = sum(str(row.get("category", "")).casefold() == "malware" for row in cert)
    cert_benign = sum(str(row.get("category", "")).casefold() in {"benign", "control"} for row in cert)
    if dev_malware < 15 or dev_benign < 5:
        errors.append(f"development split requires >=15 malware and >=5 benign (got {dev_malware}/{dev_benign})")
    if cert_malware < 5 or cert_benign < 5:
        errors.append(f"certification split requires >=5 malware and >=5 benign (got {cert_malware}/{cert_benign})")
    if len([row for row in rows if str(row.get("category", "")).casefold() == "malware"]) < 20:
        errors.append("corpus requires >=20 malware entries")
    if len([row for row in rows if str(row.get("category", "")).casefold() in {"benign", "control"}]) < 10:
        errors.append("corpus requires >=10 benign/control entries")
    sample_ids = [str(row.get("sample_id", "")) for row in rows]
    if len(sample_ids) != len(set(sample_ids)):
        errors.append("sample_id values must be unique")
    hashes = [str(row.get("sha256", "")) for row in rows]
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes):
        errors.append("every corpus entry requires a lowercase SHA-256")
    return errors


def write_json(path: str | Path, payload: object) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def evaluate_gold(
    results: Iterable[Mapping[str, object]],
    gold: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    """Compute conservative mechanism/unknown/traceability metrics offline."""
    result_by_id = {str(row.get("sample_id")): row for row in results}
    rows = list(gold)
    tp = fp = fn = unsupported = false_refuted = 0
    unknown_ok = unknown_total = 0
    trace_ok = trace_total = 0
    for expected in rows:
        sample_id = str(expected.get("sample_id"))
        actual = result_by_id.get(sample_id, {})
        actual_mechanisms = {str(item) for item in actual.get("critical_mechanisms", [])}
        expected_mechanisms = {str(item) for item in expected.get("critical_mechanisms", [])}
        tp += len(actual_mechanisms & expected_mechanisms)
        fp += len(actual_mechanisms - expected_mechanisms)
        fn += len(expected_mechanisms - actual_mechanisms)
        unsupported += sum(1 for item in actual.get("claims", []) if isinstance(item, Mapping) and item.get("critical") and not item.get("evidence_ids"))
        false_refuted += sum(1 for item in expected.get("negative_gold", []) if item in actual_mechanisms)
        expected_unknowns = {str(item) for item in expected.get("important_unknowns", [])}
        actual_unknowns = {str(item) for item in actual.get("unknowns", [])}
        if expected_unknowns:
            unknown_total += len(expected_unknowns)
            unknown_ok += len(expected_unknowns & actual_unknowns)
        trace_total += len(actual.get("core_findings", []))
        trace_ok += sum(1 for item in actual.get("core_findings", []) if isinstance(item, Mapping) and item.get("mechanism_id") and item.get("claim_id") and item.get("evidence_ids"))
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {
        "critical_mechanism_precision": round(precision, 4),
        "critical_mechanism_recall": round(recall, 4),
        "critical_unsupported_claims": unsupported,
        "negative_gold_violations": false_refuted,
        "unknown_calibration": round(unknown_ok / unknown_total, 4) if unknown_total else None,
        "traceability": round(trace_ok / trace_total, 4) if trace_total else 1.0,
        "sample_count": len(rows),
    }


def release_gate(
    metrics: Mapping[str, object],
    *,
    corpus_errors: Iterable[str] = (),
    external_blockers: Iterable[str] = (),
) -> dict[str, object]:
    """Return a truthful Round 11 gate; external verification cannot be faked."""
    blockers = list(dict.fromkeys(str(item) for item in (*corpus_errors, *external_blockers) if item))
    # Every metric below is a release contract, rather than an optional
    # dashboard field.  A missing value means the run was not performed and
    # therefore blocks release.  This prevents a partial evaluator payload
    # from accidentally being interpreted as a passing certification.
    minimums = {
        "evidence_retrieval_recall": 0.90,
        "evidence_delivery_recall": 0.90,
        "critical_mechanism_delivery_recall": 0.95,
        "model_utilization": 0.70,
        "thread_discovery_recall": 0.70,
        "critical_thread_discovery_recall": 0.85,
        "case_productivity": 0.50,
        "critical_thread_productivity": 0.60,
        "context_precision": 0.70,
        "critical_mechanism_precision": 0.95,
        "critical_mechanism_recall": 0.80,
        "mechanism_completeness": 0.80,
        "boundary_classification_precision": 0.95,
        "full_report_quality_pass_rate": 0.80,
        "unknown_calibration": 0.85,
        "core_finding_mechanism_coverage": 1.0,
        "traceability": 1.0,
        "analysis_completion_rate": 0.95,
    }
    maximums = {
        "invalid_action_rate": 0.02,
        "duplicate_action_rate": 0.05,
        "failed_analysis_rate": 0.05,
        "report_bloat_violation_rate": 0.0,
        "benign_critical_false_positive_rate": 0.0,
    }
    for key, minimum in minimums.items():
        value = metrics.get(key)
        if value is None:
            blockers.append(f"{key} was not measured")
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            blockers.append(f"{key} is not numeric: {value!r}")
            continue
        if numeric < minimum:
            blockers.append(f"{key} below release threshold: {numeric!r} < {minimum}")
    for key, maximum in maximums.items():
        value = metrics.get(key)
        if value is None:
            blockers.append(f"{key} was not measured")
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            blockers.append(f"{key} is not numeric: {value!r}")
            continue
        if numeric > maximum:
            blockers.append(f"{key} above release threshold: {numeric!r} > {maximum}")
    for key in ("critical_unsupported_claims", "negative_gold_violations", "false_refuted_from_absence"):
        value = metrics.get(key)
        if value is None:
            blockers.append(f"{key} was not measured")
        elif int(value or 0) != 0:
            blockers.append(f"{key} must be zero")
    # These checks are represented as explicit booleans by integration and
    # reliability runners.  They are required because unit tests cannot
    # establish browser, restart, concurrency, or soak behavior.
    for key in (
        "security_audit_pass",
        "browser_e2e_pass",
        "restart_recovery_pass",
        "concurrency_pass",
        "soak_pass",
        "independent_review_pass",
        "dsh_core_diff_zero",
        "dangerous_tool_exposure_zero",
        "sample_execution_zero",
        "sample_network_zero",
        "cross_case_isolation_pass",
    ):
        value = metrics.get(key)
        if value is not True:
            blockers.append(f"{key} was not proven")
    return {
        "status": "PASS" if not blockers else "BLOCKED",
        "blocker_count": len(blockers),
        "blockers": blockers,
        "metrics": dict(metrics),
    }
