"""Signal extraction and context-aware fact matching for the analysis workflow.

The workflow document describes a small, searchable intermediate language rather
than a second report format.  This module owns that language and deliberately
keeps it independent from PE/Ghidra implementation details.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml


DIMENSIONS = (
    "loading_chain",
    "cryptography",
    "c2_design",
    "anti_analysis",
    "build_system",
    "codenames",
)
SIGNAL_TYPES = ("string", "constant", "all", "concept", "technique")
VERDICTS = ("EXCLUDE_NSA", "POSSIBLE_MATCH", "INCONCLUSIVE")


@dataclass(frozen=True)
class Signal:
    dimension: str
    type: str
    value: str
    label: str
    context_tags: tuple[str, ...] = ()
    context_mismatch_keywords: tuple[str, ...] = ()
    context_note: str = ""
    evidence_ids: tuple[str, ...] = ()
    anchors: tuple[dict[str, object], ...] = ()
    confidence: str = "MEDIUM"

    def __post_init__(self) -> None:
        if self.dimension not in DIMENSIONS:
            raise ValueError(f"unsupported signal dimension: {self.dimension}")
        if self.type not in SIGNAL_TYPES:
            raise ValueError(f"unsupported signal type: {self.type}")
        if not self.value.strip():
            raise ValueError("signal value cannot be empty")

    def as_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension,
            "type": self.type,
            "value": self.value,
            "label": self.label,
            "context_tags": list(self.context_tags),
            "context_mismatch_keywords": list(self.context_mismatch_keywords),
            "context_note": self.context_note,
            "evidence_ids": list(self.evidence_ids),
            "anchors": list(self.anchors),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class FactMatch:
    fact_id: str
    pattern_type: str
    indicator_type: str
    indicator_value: str
    signal_value: str
    status: str
    score: float
    reason: str
    signal_dimension: str
    evidence_ids: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "fact_id": self.fact_id,
            "pattern_type": self.pattern_type,
            "indicator_type": self.indicator_type,
            "indicator_value": self.indicator_value,
            "signal_value": self.signal_value,
            "status": self.status,
            "score": self.score,
            "reason": self.reason,
            "signal_dimension": self.signal_dimension,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class AttributionAssessment:
    expected_verdict: str
    actual_verdict: str
    hit_count: int
    mismatch_count: int
    partial_count: int
    valid_match_rate: float
    matched_fact_ids: tuple[str, ...]
    excluded_fact_ids: tuple[str, ...]
    rationale: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "hit_count": self.hit_count,
            "mismatch_count": self.mismatch_count,
            "partial_count": self.partial_count,
            "valid_match_rate": self.valid_match_rate,
            "matched_fact_ids": list(self.matched_fact_ids),
            "excluded_fact_ids": list(self.excluded_fact_ids),
            "rationale": list(self.rationale),
        }


@dataclass(frozen=True)
class AnalysisProfile:
    name: str
    description: str
    differential_note: str
    if_excluded_check: tuple[str, ...]
    signals: tuple[Signal, ...]
    matches: tuple[FactMatch, ...]
    assessment: AttributionAssessment
    knowledge_snapshot: str
    dimension_coverage: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "differential_note": self.differential_note,
            "if_excluded_check": list(self.if_excluded_check),
            "expected_verdict": self.assessment.expected_verdict,
            "actual_verdict": self.assessment.actual_verdict,
            "dimension_coverage": dict(self.dimension_coverage),
            "signals": [item.as_dict() for item in self.signals],
            "matches": [item.as_dict() for item in self.matches],
            "assessment": self.assessment.as_dict(),
            "knowledge_snapshot": self.knowledge_snapshot,
        }


@dataclass(frozen=True)
class FactLibrary:
    facts: tuple[dict[str, Any], ...]
    sha256: str
    source: str

    @classmethod
    def load_builtin(cls, path: str | Path | None = None) -> "FactLibrary":
        """Return the production-safe fact library.

        Sample-specific attribution facts are evaluator inputs and must never
        be silently included in a customer analysis.  Callers running an
        evaluator may pass an explicit path; production callers receive an
        immutable empty snapshot that still participates in traceability.
        """
        if path is None:
            raw = b"facts: []\n"
            return cls((), hashlib.sha256(raw).hexdigest(), "production-empty")
        return cls.load_from_path(path)

    @classmethod
    def load_from_path(cls, path: str | Path) -> "FactLibrary":
        """Load evaluator-owned facts only from an explicit path."""
        raw: bytes | None = None
        candidate = Path(path)
        if candidate.is_file():
            raw = candidate.read_bytes()
        if raw is None:
            raise FileNotFoundError(candidate)
        source = str(candidate)
        payload = yaml.safe_load(raw.decode("utf-8")) or {}
        facts = tuple(item for item in payload.get("facts", []) if isinstance(item, dict))
        return cls(facts, hashlib.sha256(raw).hexdigest(), source)

    def match(self, profile: AnalysisProfile) -> tuple[FactMatch, ...]:
        matches: list[FactMatch] = []
        for signal in profile.signals:
            value = _normal(signal.value)
            if not value:
                continue
            for fact in self.facts:
                fact_id = str(fact.get("id", ""))
                if not fact_id:
                    continue
                for indicator in fact.get("indicators", ()):
                    if not isinstance(indicator, Mapping):
                        continue
                    indicator_value = str(indicator.get("value", ""))
                    if not _indicator_matches(value, _normal(indicator_value)):
                        continue
                    fact_context = _normal(
                        " ".join(
                            str(fact.get(field, ""))
                            for field in ("pattern_type", "description", "mechanism", "purpose", "source")
                        )
                    )
                    mismatches = [
                        keyword
                        for keyword in signal.context_mismatch_keywords
                        if _normal(keyword) in fact_context and _normal(keyword) != value
                    ]
                    status = "MISMATCH" if mismatches else "HIT"
                    if status == "HIT" and signal.type == "concept":
                        status = "PARTIAL"
                    score = 1.0 if status == "HIT" else 0.0 if status == "MISMATCH" else 0.5
                    reason = (
                        f"indicator matched {fact_id}"
                        if status == "HIT"
                        else f"same indicator matched but context conflicts: {', '.join(mismatches)}"
                        if status == "MISMATCH"
                        else "concept-level match requires corroborating concrete evidence"
                    )
                    matches.append(
                        FactMatch(
                            fact_id=fact_id,
                            pattern_type=str(fact.get("pattern_type", "unknown")),
                            indicator_type=str(indicator.get("type", "unknown")),
                            indicator_value=indicator_value,
                            signal_value=signal.value,
                            status=status,
                            score=score,
                            reason=reason,
                            signal_dimension=signal.dimension,
                            evidence_ids=signal.evidence_ids,
                        )
                    )
        unique: dict[tuple[str, str, str], FactMatch] = {}
        for item in matches:
            key = (item.fact_id, item.signal_value, item.status)
            prior = unique.get(key)
            if prior is None or item.score > prior.score:
                unique[key] = item
        return tuple(sorted(unique.values(), key=lambda item: (item.status, item.fact_id, item.signal_value)))


def build_profile(
    observations: Iterable[Any],
    *,
    name: str,
    artifact_id: str | None = None,
    fact_library: FactLibrary | None = None,
) -> AnalysisProfile:
    """Build a bounded six-dimension profile from StaticFact or Evidence rows."""
    library = fact_library or FactLibrary.load_builtin()
    signals = _extract_signals(observations, fact_library=library)
    coverage = {dimension: sum(item.dimension == dimension for item in signals) for dimension in DIMENSIONS}
    tentative = AnalysisProfile(
        name=name,
        description=_describe_profile(signals),
        differential_note="Concrete indicators are separated from context-dependent concepts; static evidence only.",
        if_excluded_check=(
            "Review MISMATCH rows before assigning a family or organization.",
            "Validate any candidate with function/RVA and independent evidence.",
        ),
        signals=tuple(signals),
        matches=(),
        assessment=AttributionAssessment(
            expected_verdict="INCONCLUSIVE",
            actual_verdict="INCONCLUSIVE",
            hit_count=0,
            mismatch_count=0,
            partial_count=0,
            valid_match_rate=0.0,
            matched_fact_ids=(),
            excluded_fact_ids=(),
            rationale=(),
        ),
        knowledge_snapshot=library.sha256,
        dimension_coverage=coverage,
    )
    matches = library.match(tentative)
    assessment = _assess(matches, signals)
    expected = _expected_verdict(signals, matches)
    assessment = AttributionAssessment(
        expected_verdict=expected,
        actual_verdict=assessment.actual_verdict,
        hit_count=assessment.hit_count,
        mismatch_count=assessment.mismatch_count,
        partial_count=assessment.partial_count,
        valid_match_rate=assessment.valid_match_rate,
        matched_fact_ids=assessment.matched_fact_ids,
        excluded_fact_ids=assessment.excluded_fact_ids,
        rationale=assessment.rationale,
    )
    return AnalysisProfile(
        **{**tentative.__dict__, "matches": matches, "assessment": assessment}
    )


def _extract_signals(
    observations: Iterable[Any],
    *,
    fact_library: FactLibrary | None = None,
) -> list[Signal]:
    rows = list(observations)
    signals: list[Signal] = []
    seen: set[tuple[str, str, str]] = set()

    # The parser emits structured PE/import/function rows rather than one
    # canonical text field.  Keep the extraction layer tolerant of those
    # shapes, while bounding recursion so a malformed tool result cannot
    # inflate the profile or the model context.
    def flatten(value: Any, *, limit: int = 64) -> list[str]:
        result: list[str] = []
        if isinstance(value, str):
            if value.strip():
                result.append(value.strip())
            return result
        if isinstance(value, Mapping):
            for key, item in value.items():
                if len(result) >= limit:
                    break
                if key in {"sha256", "md5", "sha1", "file_offset", "rva", "offset"}:
                    continue
                result.extend(flatten(item, limit=limit - len(result)))
            return result[:limit]
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if len(result) >= limit:
                    break
                result.extend(flatten(item, limit=limit - len(result)))
        elif value is not None and isinstance(value, (int, float, bool)):
            result.append(str(value))
        return result[:limit]

    catalog: list[tuple[str, str, str, str]] = []
    if fact_library is not None:
        for fact in fact_library.facts:
            pattern = str(fact.get("pattern_type", ""))
            dimension = _fact_dimension(pattern)
            if dimension is None:
                continue
            for indicator in fact.get("indicators", ()):
                if not isinstance(indicator, Mapping):
                    continue
                candidate = str(indicator.get("value", "")).strip()
                if len(candidate) < 4 or candidate.lower() in {"unknown", "n/a", "none"}:
                    continue
                indicator_type = str(indicator.get("type", "all"))
                signal_type = indicator_type if indicator_type in SIGNAL_TYPES else "all"
                catalog.append((dimension, signal_type, candidate, pattern))

    def add(
        dimension: str,
        type_: str,
        value: Any,
        label: str,
        row: Any,
        *,
        tags: tuple[str, ...] = (),
        mismatch: tuple[str, ...] = (),
        note: str = "",
        confidence: str = "MEDIUM",
    ) -> None:
        text = str(value).strip()
        if not text:
            return
        key = (dimension, type_, text.lower())
        if key in seen:
            return
        seen.add(key)
        evidence_id = str(getattr(row, "id", ""))
        anchor = getattr(row, "anchor", {})
        signals.append(
            Signal(
                dimension,
                type_,
                text,
                label,
                tags,
                mismatch,
                note,
                (evidence_id,) if evidence_id else (),
                (dict(anchor),) if isinstance(anchor, Mapping) else (),
                confidence,
            )
        )

    for row in rows:
        kind = str(getattr(row, "kind", ""))
        module = str(getattr(row, "module", ""))
        value = getattr(row, "value", {})
        if not isinstance(value, Mapping):
            continue
        raw = str(value.get("text", value.get("indicator", value.get("api", ""))))
        flattened = " ".join(flatten(value))
        lowered = raw.lower()
        flattened_lowered = flattened.lower()

        # Match only values observed in the sample.  The catalog supplies
        # searchable vocabulary; it never creates a signal by itself.
        for dimension, signal_type, candidate, pattern in catalog:
            if _contains_observed(flattened_lowered, candidate.lower()):
                add(
                    dimension,
                    signal_type,
                    candidate,
                    f"Known {pattern} indicator",
                    row,
                    tags=("fact-catalog", "observed-value"),
                    mismatch=_catalog_mismatch(pattern),
                    note="Catalog value was observed in static evidence; corroborate call-site context.",
                    confidence="HIGH" if dimension == "codenames" else "MEDIUM",
                )

        for api in _structured_apis(value):
            for dimension, label, tags in _api_signal_dimensions(api):
                add(dimension, "all", api, label, row, tags=tags, note="API/import evidence; call order and data flow remain static hypotheses.")
        if kind in {"string", "script_indicator", "document_url", "network_indicator"}:
            if _is_network_reference(raw):
                add("c2_design", "string", raw, "Network endpoint or domain", row, tags=("endpoint",), note="Endpoint reference; purpose requires call-site correlation.")
            if re.search(r"\{[0-9a-f]{8}-[0-9a-f-]{27,}\}", raw, re.I):
                add("codenames", "string", raw, "GUID/CLSID", row, tags=("guid", "component-identity"), confidence="HIGH")
            if ".pdb" in lowered:
                add("build_system", "string", raw, "PDB path", row, tags=("debug-artifact",), confidence="HIGH")
            if re.search(r"(?:warriorpride|peddlecheap|unitedrake|danderspritz|killsuit|divesbar|straitbizarre|epme|solartime)", raw, re.I):
                add("codenames", "string", raw, "Internal codename or component name", row, tags=("internal-codename",), confidence="HIGH")
            if re.search(r"(?:user-agent|content-type|beacon|/index\.php|\.php\b|/gate\b)", raw, re.I):
                add("c2_design", "string", raw, "C2 protocol or beacon marker", row, tags=("beacon", "protocol"), mismatch=("binary protocol",), note="Protocol marker requires HTTP call-path evidence.")
        if kind in {"loader_indicator", "mechanism_resource_extraction", "mechanism_dynamic_resolution", "mechanism_memory_permission", "function_call", "function_mechanism"} or module == "loader":
            if raw or value.get("apis"):
                candidate = raw or ", ".join(str(item) for item in value.get("apis", []))
                add("loading_chain", "all", candidate, "Loader, resolver, or memory preparation signal", row, tags=("loader", "staged-loading"), mismatch=("kernel driver", "SMB",), note="API presence indicates a possible loading step; call order and data flow are required.")
        if kind in {"crypto_indicator", "encoded_blob", "high_entropy_section", "mechanism_decryption", "function_mechanism"} or module == "decryption":
            candidate = raw or str(value.get("section", ""))
            if candidate:
                add("cryptography", "all" if not re.fullmatch(r"0x[0-9a-f]+", candidate, re.I) else "constant", candidate, "Cryptography, encoding, or high-entropy signal", row, tags=("crypto", "obfuscation"), mismatch=("AES-128", "RSA-2048", "LCG"), note="Algorithm and purpose require implementation-level corroboration.")
        if kind in {"anti_analysis_indicator", "mechanism_environment_check", "mechanism_service_query"} or module == "anti_analysis":
            candidate = raw or ", ".join(str(item) for item in value.get("apis", []))
            add("anti_analysis", "all", candidate, "Environment, debugger, VM, or service check", row, tags=("anti-analysis",), mismatch=("PEB modification", "process hiding"), note="A check is not proof that execution took an evasion branch.")
        if kind in {"pe_structure", "file_identity", "pe_header_anomaly"}:
            timestamp = value.get("timestamp")
            if timestamp is not None:
                add("build_system", "constant", str(timestamp), "PE build timestamp", row, tags=("pe-header",))
            for section in value.get("sections", []) if isinstance(value.get("sections"), list) else []:
                if isinstance(section, Mapping) and float(section.get("entropy", 0)) >= 7.2:
                    add("build_system", "constant", f"{section.get('name')} entropy={section.get('entropy')}", "High-entropy section layout", row, tags=("section-layout", "packing-indicator"))
            for imported in value.get("imports", []) if isinstance(value.get("imports"), list) else []:
                if isinstance(imported, Mapping):
                    for fn in imported.get("functions", []):
                        fn_text = str(fn)
                        for dimension, label, tags in _api_signal_dimensions(fn_text):
                            add(dimension, "all", fn_text, label, row, tags=tags, note="Import evidence; call order and data flow remain static hypotheses.")

            characteristics = value.get("dll_characteristics")
            if characteristics is not None:
                add("build_system", "constant", str(characteristics), "PE DLL characteristics", row, tags=("pe-header",))
            for key in ("rich_header", "compiler", "language", "pdb_path"):
                if value.get(key):
                    add("build_system", "string", str(value[key]), f"PE {key.replace('_', ' ')}", row, tags=("build-artifact",))
        if kind in {"code_api_call", "function_call"}:
            api = str(value.get("api", value.get("name", "")))
            if api and any(term in api.lower() for term in ("loadlibrary", "getprocaddress", "virtualalloc", "virtualprotect", "createremotethread", "writeprocessmemory")):
                add("loading_chain", "all", api, "RVA-level loader or injection API", row, tags=("rva-call-site", "loader"), mismatch=("SMB", "kernel backdoor"), confidence="HIGH")
            if api and any(term in api.lower() for term in ("isdebuggerpresent", "ntqueryinformationprocess", "cpuid", "virtualquery")):
                add("anti_analysis", "all", api, "RVA-level anti-analysis API", row, tags=("rva-call-site", "anti-analysis"), confidence="HIGH")

        if kind in {"embedded_artifact", "pe_resource", "decoded_artifact", "mechanism_resource_payload"}:
            add("loading_chain", "concept", kind, "Embedded or extracted payload relationship", row, tags=("payload-boundary",), note="Static containment/extraction does not prove execution.")
        if kind in {"high_entropy_section", "encoded_blob", "mechanism_decode", "mechanism_decompression"}:
            add("cryptography", "concept", kind, "Encoding, compression, or decryption mechanism", row, tags=("decode-boundary",), note="Algorithm and purpose require implementation-level corroboration.")
        if module == "c2_network":
            add("c2_design", "concept", raw or kind, "C2/network evidence", row, tags=("network-evidence",))
        if module == "loader":
            add("loading_chain", "concept", raw or kind, "Loader mechanism evidence", row, tags=("loader",))
        if module == "decryption":
            add("cryptography", "concept", raw or kind, "Decryption mechanism evidence", row, tags=("crypto",))
        if module == "anti_analysis":
            add("anti_analysis", "concept", raw or kind, "Anti-analysis mechanism evidence", row, tags=("anti-analysis",))

    # A minimum signal makes a clean dimension explicit without inventing a value.
    return signals[:256]


def _fact_dimension(pattern_type: str) -> str | None:
    lowered = pattern_type.lower()
    if any(token in lowered for token in ("codename", "internal", "attribution", "component-name")):
        return "codenames"
    if any(token in lowered for token in ("crypto", "decrypt", "encrypt", "xor", "rc4", "aes", "obfuscat")):
        return "cryptography"
    if any(token in lowered for token in ("c2", "beacon", "network", "smb", "http", "protocol", "tdi")):
        return "c2_design"
    if any(token in lowered for token in ("anti", "evasion", "debug", "vm", "hide")):
        return "anti_analysis"
    if any(token in lowered for token in ("build", "compiler", "rich", "pdb", "section")):
        return "build_system"
    if any(token in lowered for token in ("load", "loader", "resource", "inject", "persistence", "driver", "thread")):
        return "loading_chain"
    return None


def _catalog_mismatch(pattern_type: str) -> tuple[str, ...]:
    lowered = pattern_type.lower()
    terms: list[str] = []
    if any(token in lowered for token in ("kernel", "driver", "smb")):
        terms.extend(("kernel driver", "SMB", "kernel backdoor"))
    if any(token in lowered for token in ("aes", "rsa")):
        terms.extend(("RC4", "XOR", "shellcode unpacking"))
    if any(token in lowered for token in ("http", "beacon", "c2")):
        terms.extend(("binary protocol", "SMB"))
    return tuple(terms)


def _contains_observed(text: str, candidate: str) -> bool:
    if not text or not candidate:
        return False
    if candidate in text:
        return True
    # Short catalog tokens such as API names should be bounded to avoid
    # matching a larger unrelated identifier.
    if len(candidate) < 8:
        return re.search(rf"(?<![a-z0-9_]){re.escape(candidate)}(?![a-z0-9_])", text, re.I) is not None
    return False


def _is_network_reference(value: str) -> bool:
    """Recognize endpoint-like strings without treating DLL/path suffixes as domains."""
    if re.search(r"https?://|wss?://", value, re.I):
        return True
    if re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])", value):
        return True
    # Keep this list intentionally conservative.  A generic alphabetic TLD
    # pattern turns `KERNEL32.dll`, `logFile.txt`, and similar Windows strings
    # into false C2 indicators.
    return re.search(
        r"(?<![\\\w.-])(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|cn|ru|top|xyz|info|biz|io|cc|me|su|in|co|uk)(?![\\\w.-])",
        value,
        re.I,
    ) is not None


def _structured_apis(value: Mapping[str, Any]) -> tuple[str, ...]:
    candidates: list[str] = []
    for key in ("api", "name", "indicator"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            candidates.append(item.strip())
    for key in ("apis", "functions", "imports", "calls"):
        item = value.get(key)
        if isinstance(item, (list, tuple)):
            for nested in item:
                if isinstance(nested, str):
                    candidates.append(nested.strip())
                elif isinstance(nested, Mapping):
                    for field in ("api", "name", "target_name", "target_function"):
                        if nested.get(field):
                            candidates.append(str(nested[field]).strip())
    return tuple(dict.fromkeys(item for item in candidates if item))


def _api_signal_dimensions(api: str) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    lowered = api.lower()
    result: list[tuple[str, str, tuple[str, ...]]] = []
    if any(token in lowered for token in ("loadlibrary", "getprocaddress", "virtualalloc", "virtualprotect", "mapviewofsection", "createremotethread", "writerprocessmemory", "writeprocessmemory", "ntcreatesection", "queueuserapc", "setthreadcontext", "openprocess")):
        result.append(("loading_chain", "Loader, resolver, or injection API", ("loader", "api")))
    if any(token in lowered for token in ("crypt", "bcrypt", "aes", "rc4", "chacha", "xor", "decrypt", "encrypt")):
        result.append(("cryptography", "Cryptography or decode API", ("crypto", "api")))
    if any(token in lowered for token in ("winhttp", "wininet", "httpopen", "httpsend", "wsastartup", "socket", "connect", "curl", "deviceiocontrol", "winpcap")):
        result.append(("c2_design", "Network or protocol API", ("network-api", "api")))
    if any(token in lowered for token in ("isdebugger", "debugger", "ntqueryinformationprocess", "cpuid", "virtualquery", "globalmemorystatus", "getsysteminfo", "openscmanager", "openservice", "queryservicestatus")):
        result.append(("anti_analysis", "Environment, debugger, or service check API", ("anti-analysis", "api")))
    return tuple(result)


def _assess(matches: tuple[FactMatch, ...], signals: list[Signal]) -> AttributionAssessment:
    hits = [item for item in matches if item.status == "HIT"]
    mismatches = [item for item in matches if item.status == "MISMATCH"]
    partial = [item for item in matches if item.status == "PARTIAL"]
    matched_ids = tuple(sorted({item.fact_id for item in hits + partial}))
    excluded_ids = tuple(sorted({item.fact_id for item in mismatches}))
    rate = round(len(set(item.fact_id for item in hits)) / max(1, len(set(item.fact_id for item in matches))), 4)
    if not matches or not hits:
        verdict = "EXCLUDE_NSA"
    elif rate >= 0.4 and len(hits) >= 2:
        verdict = "POSSIBLE_MATCH"
    elif rate < 0.15 and len(hits) < 2:
        verdict = "EXCLUDE_NSA"
    elif hits or partial:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "EXCLUDE_NSA"
    rationale = [
        f"{len(signals)} concrete signals extracted across {len({item.dimension for item in signals})} dimensions.",
        f"{len(hits)} valid fact matches, {len(partial)} partial matches, {len(mismatches)} context mismatches.",
        "A fact match is supporting evidence, not conclusive attribution." if hits else "No validated fact match was established.",
    ]
    return AttributionAssessment("INCONCLUSIVE", verdict, len(hits), len(mismatches), len(partial), rate, matched_ids, excluded_ids, tuple(rationale))


def _expected_verdict(signals: list[Signal], matches: tuple[FactMatch, ...]) -> str:
    if any(item.confidence == "HIGH" and item.dimension == "codenames" for item in signals):
        return "POSSIBLE_MATCH" if any(item.status == "HIT" for item in matches) else "INCONCLUSIVE"
    if not matches or not any(item.status == "HIT" for item in matches):
        return "EXCLUDE_NSA"
    return "INCONCLUSIVE"


def _describe_profile(signals: list[Signal]) -> str:
    dimensions = ", ".join(dimension.replace("_", " ") for dimension in DIMENSIONS if any(item.dimension == dimension for item in signals))
    return f"Static profile with concrete signals in: {dimensions or 'no recognized dimensions'}."


def _normal(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _indicator_matches(signal: str, indicator: str) -> bool:
    if not signal or not indicator:
        return False
    if signal == indicator:
        return True
    # Never let a one-character/short numeric observation such as `0` match
    # every catalog indicator that happens to contain that character.
    if len(indicator) >= 5 and len(signal) >= 5 and (indicator in signal or signal in indicator):
        return True
    return False
