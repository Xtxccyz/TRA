"""Correctness verification for a report body: not "is the fact present" but "is the fact right".

Why this module exists inside the product, not only in `.scratch/`.

The pipeline already had an existence check - the acceptance instrument asserts that 24 benchmark
facts appear in the published body - and the body passed 24/24 while containing a YARA rule whose
declared `sha256` indicators could not identify the sample:

    $s0 = "0b05c0df699028e6cfc4c02147e91b7a4ecbc79569004caaf550ebcdb25c63a3" // sha256
    $s5 = "168d16f912e21ee7d521f5d0a59b08f96161b9e5b98aae21f6d5e0d7ca8a0db6" // sha256
    sample file_identity.sha256 = 6bb6bfcbe68de69077b567789d5970c6613b1d4fb89becc4cf7a2f9a49861145

The first is the digest the rule NAME was derived from; the second is the digest of PE resource payload
`RT_ICON[5]`. Both strings really are in the text, so existence checking cannot see the error. Deploying
that rule would produce a hunting artefact that never fires on the sample it was written for.

This module implements the mechanically decidable error classes from
`.agents/skills/analysis-verification/METHODOLOGY.md`:

    EC-4  a bounded list published as if complete
    EC-5  a declared indicator that cannot identify this sample
    EC-6  a static observation stated as runtime fact (delegates to `static_wording_violations`)

EC-1 (absence-as-proof), EC-2 (string vs behaviour) and EC-3 (wrong join) need the evidence graph, not
the text, so they stay with the model-driven half of the skill. An earlier attempt to do EC-2 lexically
produced twelve findings on a real body and every one was wrong; a checker with a 100% false-positive
rate trains the reader to ignore it, which is how a real finding gets missed.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Mapping, NamedTuple

from threat_report_agent.reporting import _is_file_hash_source

#: `$sN = "value" // label` - the YARA projection's own string declaration.
_YARA_STRING_RE = re.compile(r'\$(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(?://\s*(\S+))?')
_YARA_RULE_NAME_RE = re.compile(r"^\s*rule\s+(\w+)\s*\{", re.MULTILINE)
#: `共 N 条/项/个` - a stated size for a following list.
_COUNT_RE = re.compile(r"共\s*(\d+)\s*[条项个]")
#: Wording that turns a count into an honest boundary rather than a completeness claim.
_BOUNDARY_MARKERS = (
    "边界", "节选", "差额", "其余", "未列出", "以下为", "以上为", "本次列出",
    "boundary", "selected", "partial", "shown", "omitted", "difference",
)
#: Indicator labels whose value must be a literal substring of the sample.
_LITERAL_LABELS = frozenset({"url", "ipv4", "registry_subkey", "scheduled_task"})


def _walk(node: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(node, Mapping):
        if node.get("type"):
            yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _yara_unescape(value: str) -> str:
    """Undo YARA string escaping so a rule literal can be compared with raw evidence text.

    `SOFTWARE\\Microsoft\\...` inside a rule means one backslash; comparing the escaped form against
    recovered text reported five correct indicators as broken before this existed.
    """
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}.get(
                value[index + 1], value[index + 1]
            ))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _document_identities(document: Mapping[str, Any]) -> tuple[str, dict[str, str]]:
    """The sample's own digest, plus every digest the document records for an INTERNAL object.

    A digest nested inside `pe_structure.resources.entries[*]` identifies a region of the file, never
    the file. Knowing which is which is what lets the check say "this indicator is a resource digest"
    instead of only "this indicator is not the sample hash".

    The file hash is found in the projected IOC rows, NOT in a row typed `file_identity`: a report
    document carries `{"type": "ioc", "category": "sha256", "source": "static_triage/file_identity"}`
    and no row whose `type` is `file_identity` at all. The first version of this function keyed on
    `type in {"file_identity", "artifact", "identity"}` and therefore resolved NOTHING on a real
    document - which made the self-reference check fire on the one rule the fix had just made correct,
    and the pipeline recorded `error_count: 1` on a verified-good report.
    """
    sample = ""
    internal: dict[str, str] = {}
    for row in _walk(document):
        row_type = str(row.get("type") or "")
        source = str(row.get("source") or "")
        if row_type == "ioc" and str(row.get("category") or "").casefold() == "sha256":
            value = str(row.get("value") or "").casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                continue
            if _is_file_hash_source(source):
                if not sample:
                    sample = value
            else:
                # Provenance decides, using the SAME predicate the projection uses. An earlier version
                # asked `"artifact" in source`, which classified `investigation/decoded_artifact` as a
                # file identity; that made the checker blind to the exact defect it exists to report,
                # because a decoded-payload digest then passed as the sample's own hash.
                internal[value] = f"IOC row source={source or 'unknown'}"
            continue
        if not sample:
            for key in ("sha256", "content_sha256", "sample_sha256"):
                candidate = row.get(key)
                if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
                    if row_type in {"file_identity", "artifact", "identity"} or _is_file_hash_source(
                        source
                    ):
                        sample = candidate.casefold()
                        break
        for digest, label in _object_digests(row, row_type):
            internal.setdefault(digest, label)
    return sample, internal


def _object_digests(row: Mapping[str, Any], row_type: str) -> list[tuple[str, str]]:
    """Every digest this row records for an object INSIDE the file, with a readable label.

    A resource digest reaches the document in three shapes - a `resource` mapping
    (`investigation/embedded_object`), a flat `sha256` key (`investigation/bytes_read`,
    `investigation/decoded_artifact`), or an `entries` list (PE resource directory) - and the first version
    of this resolver only looked at `entries`. The two shapes it missed are precisely the ones that reached
    the detection rule, so every finding read "no evidence row owns this digest" when a row did.
    """
    out: list[tuple[str, str]] = []
    resource = row.get("resource")
    if isinstance(resource, Mapping):
        digest = resource.get("sha256")
        if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            out.append(
                (
                    digest.casefold(),
                    f"{row_type or 'object'} resource name={resource.get('name')} "
                    f"type={resource.get('type') or resource.get('type_id')}",
                )
            )
    entries = row.get("entries")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            digest = entry.get("sha256")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                out.append(
                    (
                        digest.casefold(),
                        f"{row_type or 'resource'} entry name={entry.get('name')} "
                        f"type={entry.get('type') or entry.get('type_id')}",
                    )
                )
    flat = row.get("sha256")
    if (
        isinstance(flat, str)
        and re.fullmatch(r"[0-9a-fA-F]{64}", flat)
        and not _is_file_hash_source(row.get("source"))
    ):
        label = f"{row_type or 'object'}"
        selector = row.get("selector")
        if isinstance(selector, Mapping) and selector.get("target"):
            label = f"{label} target={selector.get('target')}"
        offset = row.get("offset")
        if offset is not None:
            label = f"{label} offset={offset}"
        out.append((flat.casefold(), label))
    return out


def _declares_its_own_boundary(line: str) -> bool:
    folded = line.casefold()
    if any(marker in line or marker in folded for marker in _BOUNDARY_MARKERS):
        return True
    # `（差额为 …）` / `（其余未命中任何分析相关类别）` - a parenthesised explanation.
    return "（" in line and "）" in line


#: Corrections whose effect is visible in a rendered body, as detectable markers.
#:
#: WHY THIS EXISTS. `report_revisions.markdown` is written once, at row creation, so every renderer fix
#: changes only what a FUTURE revision says. Measured on this deployment:
#:
#:     342 of 345 tasks   newest published revision lacks a section added since round 77
#:      20 revisions      still carry `rule threat_static_<16-hex>` - a rule named after a digest (EC-5)
#:       5 revisions      carry the IOC quick-reference;  8 carry the runtime sequence
#:
#: A reader of those reports has no way to tell they predate corrections that would change their content.
#: Recording which markers a body satisfies lets a consumer answer "is this current, and what is missing"
#: without re-rendering every stored document.
#:
#: Each marker is derived from the BODY rather than from a hand-maintained version integer. A counter bumped
#: by hand drifts the first time a fix ships without anyone remembering to bump it - a failure this project
#: has hit with version strings that were written once and never updated. `negative=True` marks a correction
#: whose fix is the ABSENCE of a pattern (the EC-5 digest-named rule), so a body satisfies it by not
#: containing it.
class CorrectionMarker(NamedTuple):
    id: str
    detail: str
    pattern: str
    negative: bool = False


CORRECTION_MARKERS: tuple[CorrectionMarker, ...] = (
    CorrectionMarker(
        "import_module_list",
        "the import section lists the modules present in the import table (round 77)",
        "导入表模块清单",
    ),
    CorrectionMarker(
        "resource_directory",
        "the resource directory is named with per-type counts (round 78)",
        "资源目录",
    ),
    CorrectionMarker(
        "runtime_sequence",
        "the statically reconstructed runtime order is published (round 84)",
        "运行时序",
    ),
    CorrectionMarker(
        "ioc_quick_reference",
        "a labelled IOC quick-reference table is published (round 85)",
        "IOC / 指标速查",
    ),
    CorrectionMarker(
        "tls_callbacks",
        "recovered TLS callback entries are published (round 85)",
        "TLS 回调入口",
    ),
    CorrectionMarker(
        "file_hash_provenance",
        "the detection rule carries a NAME rather than a digest, so its `sha256` slot is a file hash "
        "(rounds 80-82)",
        r"rule\s+threat_static_[0-9a-fA-F]{16}\b",
        negative=True,
    ),
)


def renderer_corrections(markdown: str) -> dict[str, bool]:
    """Which body-visible corrections a rendered report satisfies.

    A `False` value means the body predates that correction (for additive markers) or still exhibits the
    defect (for negative ones). It is NOT an error: a section can be legitimately absent because the sample
    had nothing to put in it - a DLL with no TLS callbacks has no TLS section - which is why this records
    what is present rather than asserting completeness.
    """
    text = str(markdown or "")
    result: dict[str, bool] = {}
    for marker in CORRECTION_MARKERS:
        found = re.search(marker.pattern, text) is not None
        result[marker.id] = (not found) if marker.negative else found
    return result


def stale_corrections(markdown: str) -> list[str]:
    """The correction ids a body does not satisfy, in marker order.

    The list is what a reviewer acts on: "missing runtime_sequence" says which regeneration would change
    this body, which a boolean "stale" cannot.
    """
    corrections = renderer_corrections(markdown)
    return [marker.id for marker in CORRECTION_MARKERS if not corrections[marker.id]]


def corrections_summary(markdown: str) -> dict[str, object]:
    """JSON-safe record for a revision, so staleness travels with the published artefact."""
    corrections = renderer_corrections(markdown)
    missing = stale_corrections(markdown)
    return {
        "markers": corrections,
        "missing": missing,
        "current": not missing,
        "checked": len(CORRECTION_MARKERS),
        "note": (
            "A missing marker means this body predates that correction; a section can also be legitimately "
            "absent because the sample had nothing to report for it."
        ),
    }


def verify_report_correctness(
    markdown: str,
    document: Mapping[str, Any] | None = None,
    *,
    sample_strings: str = "",
) -> list[dict[str, str]]:
    """Findings for a report body, each `{ec, severity, title, detail, evidence, fix}`.

    `document` supplies file identity and internal digests; without it the EC-5 comparison degrades to
    "this value is not a known digest" rather than naming what it actually is. `sample_strings` is the
    concatenated recovered string/decode evidence, used to test whether a literal indicator could ever
    match; pass an empty string to skip that half.
    """
    findings: list[dict[str, str]] = []
    doc = document or {}
    sample_sha, internal = _document_identities(doc)

    def add(ec: str, severity: str, title: str, detail: str, evidence: str, fix: str) -> None:
        findings.append(
            {"ec": ec, "severity": severity, "title": title, "detail": detail,
             "evidence": evidence, "fix": fix}
        )

    # ------------------------------------------------------------------ EC-5
    rule_names = _YARA_RULE_NAME_RE.findall(markdown)
    declared = _YARA_STRING_RE.findall(markdown)
    for rule_name in rule_names:
        for ident, value, label in declared:
            if (label or "").casefold() != "sha256" or len(value) != 64:
                continue
            digest = value.casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                continue
            if sample_sha and digest == sample_sha:
                continue
            source = internal.get(digest)
            evidence = f"${ident} = {value[:24]}... // {label}"
            if source:
                add(
                    "EC-5", "ERROR",
                    f"rule {rule_name}: ${ident} is a COMPUTED digest labelled `sha256`",
                    f"${ident} is the SHA-256 of {source}, not of the sample. Deployed as a `sha256` "
                    "indicator it can never match the sample.",
                    evidence,
                    "label it as the resource digest it is, or drop it from the rule; a file IOC must "
                    "be the sample's own hash",
                )
                continue
            if rule_name.casefold().endswith(digest[:16]):
                # Only self-referential when the digest is NOT the sample's own hash. Once the
                # projection derives the rule name from `file_identity.sha256`, the name and the hash
                # legitimately coincide (`rule threat_static_6bb6bfcbe68de690` with
                # `$s0 = "6bb6bfcb..."`), and flagging that is a false positive - and a costly one,
                # because it fires on exactly the artefact this check exists to produce.
                #
                # The defect being caught is narrower: the rule name derived from a digest that
                # identifies the REPORT (a projection fingerprint), leaving the rule keyed on a value
                # no sample can match. Measured on task `ce7e310e` before the projection fix:
                # `$s0 = 0b05c0df...` was the rule's own name suffix while the sample's hash was
                # `6bb6bfcb...`.
                if sample_sha and digest == sample_sha:
                    continue
                add(
                    "EC-5", "ERROR",
                    f"rule {rule_name}: ${ident} is the rule's OWN name suffix labelled `sha256`",
                    "The rule name is derived from this digest and the digest is not the sample's "
                    "file hash, so the value identifies the report rather than any sample.",
                    f"{evidence}  (rule name {rule_name})",
                    "remove it from `strings:`, or relabel it as the projection fingerprint",
                )
                continue
            add(
                "EC-5", "WARN",
                f"rule {rule_name}: ${ident} labelled `sha256` is not the sample's file hash",
                "No evidence row in the document owns this digest, so it is neither the file hash "
                "nor a known internal digest.",
                f"{evidence}  sample={sample_sha[:24] or 'UNKNOWN'}",
                "trace which projection produced it; if it is derived, relabel it",
            )

    if sample_strings:
        for ident, value, label in declared:
            if (label or "").casefold() not in _LITERAL_LABELS:
                continue
            literal = _yara_unescape(value)
            if literal and literal not in sample_strings:
                add(
                    "EC-5", "WARN",
                    f"${ident} labelled `{label}` is not a literal substring of any recovered string",
                    "The value was rewritten, concatenated or truncated between the evidence and the "
                    "rule, so a raw `any of them` match cannot fire on it.",
                    f'${ident} = "{value[:70]}"',
                    "emit the value verbatim from the evidence row, or state the transformation",
                )

    # ------------------------------------------------------------------ EC-4
    lines = markdown.splitlines()
    for index, line in enumerate(lines):
        match = _COUNT_RE.search(line)
        if not match or _declares_its_own_boundary(line):
            continue
        size = int(match.group(1))
        listed = 0
        for follower in lines[index + 1:]:
            stripped = follower.strip()
            if not stripped or stripped.startswith("#"):
                if listed:
                    break
                continue
            if stripped.startswith(("-", "*", "•")):
                listed += 1
                continue
            if listed:
                break
        if listed and listed != size:
            add(
                "EC-4", "WARN" if abs(listed - size) <= 2 else "ERROR",
                "a stated count does not match the items listed, with no stated boundary",
                f"the line declares {size} but {listed} items follow it, and it does not say the "
                "list is bounded",
                line.strip()[:110],
                "list them all, or state the boundary (shown N of M, and where the rest went)",
            )

    # ------------------------------------------------------------------ EC-6
    try:
        from threat_report_agent.product_certification import static_wording_violations
    except ImportError:
        static_wording_violations = None
    if static_wording_violations is not None:
        for violation in static_wording_violations(markdown):
            add(
                "EC-6", "ERROR",
                "unqualified runtime claim in a static-only report",
                str(violation)[:300],
                "(static_wording_violations)",
                "qualify the clause with its static/emulated/observed boundary",
            )

    return findings


def correctness_summary(findings: Iterable[Mapping[str, str]]) -> dict[str, object]:
    """A compact, JSON-safe summary for the report document and the audit trail."""
    items = list(findings)
    by_ec: dict[str, int] = {}
    for item in items:
        key = str(item.get("ec") or "?")
        by_ec[key] = by_ec.get(key, 0) + 1
    return {
        "findings": items,
        "by_class": by_ec,
        "error_count": sum(1 for item in items if item.get("severity") == "ERROR"),
        "checked": ["EC-4", "EC-5", "EC-6"],
        "not_checked": {
            "EC-1": "absence-as-proof needs the argument",
            "EC-2": "string-vs-behaviour needs the evidence graph",
            "EC-3": "join strength needs the instruction window",
        },
        "skill": "analysis-verification",
        "methodology": ".agents/skills/analysis-verification/METHODOLOGY.md",
    }


def dumps(summary: Mapping[str, object]) -> str:
    return json.dumps(summary, ensure_ascii=False, sort_keys=True)
