"""Quantified simulated gold-bar for official report output.

The bar measures gold Resume *structure and HOW density*, never gold plaintext.
A simulated ledger that recovers PE, parameterized calls, decoded constants,
threads, decode unknowns and isolated-emu status must score at least 90/100
with zero blocking failures before a human rebuild/T5 run is requested.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal, Mapping

GOLD_BAR_PASS_SCORE = 90
GOLD_BAR_TOTAL = 100

_PARAMETERIZED_CALL = re.compile(
    r"\b[A-Za-z][A-Za-z0-9_]{2,}\([^)\n]{0,200}?="
)
_DECODED_CONSTANTS = (
    "CALG_RC4",
    "CALG_AES",
    "PAGE_EXECUTE_READWRITE",
    "CREATE_SUSPENDED",
    "STILL_ACTIVE",
    "EXTENDED_STARTUPINFO_PRESENT",
)
_EMU_STATUSES = (
    "SUCCEEDED",
    "DEFERRED_TO_WORKER",
    "DISABLED_BY_POLICY",
    "NOT_ATTEMPTED",
    "FAILED",
    "UNSUPPORTED",
    "WORKER_REQUIRED",
)
_MODULE_TOKENS = (
    "network",
    "persistence",
    "execution",
    "thread",
    "config_crypto",
    "loader",
    "dynamic_resolution",
    "timing_query",
    "file_io",
    "process",
    "crypto",
    "defense",
)


@dataclass(frozen=True)
class GoldBarCheck:
    check_id: str
    points: int
    blocking: bool
    passed: bool
    detail: str


@dataclass(frozen=True)
class GoldBarResult:
    score: int
    total: int = GOLD_BAR_TOTAL
    checks: tuple[GoldBarCheck, ...] = ()

    @property
    def blocking_failures(self) -> tuple[GoldBarCheck, ...]:
        return tuple(item for item in self.checks if item.blocking and not item.passed)

    @property
    def passed(self) -> bool:
        return self.score >= GOLD_BAR_PASS_SCORE and not self.blocking_failures


def score_official_markdown(
    markdown: str,
    *,
    rich_ledger: bool = True,
    emu_succeeded: bool = False,
) -> GoldBarResult:
    """Score an authoritative markdown report against the simulated gold bar."""
    text = str(markdown or "")
    folded = text.casefold()
    checks: list[GoldBarCheck] = []

    def add(check_id: str, points: int, blocking: bool, passed: bool, detail: str) -> None:
        checks.append(GoldBarCheck(check_id, points, blocking, passed, detail))

    add(
        "pe_basics",
        8,
        True,
        "PE basics (static header)" in text
        and ("image_base=" in folded or "image_base=" in text)
        and "entry_rva=" in folded,
        "PE header with image_base and entry_rva",
    )
    import_hits = re.findall(r"`(?:[A-Za-z0-9_.]+!)?[A-Za-z][A-Za-z0-9_]{2,}`", text)
    add(
        "imports",
        8,
        True,
        len({item.strip("`") for item in import_hits}) >= 8,
        f"distinct import/API names={len(set(import_hits))}",
    )
    parameterized = _PARAMETERIZED_CALL.findall(text)
    add(
        "ordered_how",
        12,
        True,
        "Ordered static call sequence (reconstructed)" in text and len(parameterized) >= 5,
        f"parameterized_calls={len(parameterized)}",
    )
    decoded = [name for name in _DECODED_CONSTANTS if name in text]
    add(
        "decoded_constants",
        10,
        True,
        bool(decoded),
        f"decoded={decoded[:4]}",
    )
    add(
        "unique_threads",
        8,
        True,
        "Unique OS threads / callbacks" in text
        and ("start=" in folded or "UNKNOWN(start" in text),
        "unique thread start recovered or UNKNOWN",
    )
    emu_hit = next((status for status in _EMU_STATUSES if status in text), "")
    add(
        "emu_status",
        8,
        True,
        "Controlled emulation (isolated worker" in text and bool(emu_hit),
        f"emu_status={emu_hit or 'missing'}",
    )
    how_blocks = [
        line for line in text.splitlines()
        if line.strip().startswith("- How:") or line.strip().startswith("- How：")
        or "  - How:" in line
    ]
    long_how = [line for line in how_blocks if len(line) >= 80]
    add(
        "module_how",
        8,
        True,
        "Module deep-dives (static reconstruction)" in text or len(long_how) >= 3,
        f"long_how_blocks={len(long_how)} deep_dives={'Module deep-dives' in text}",
    )
    add(
        "unknowns",
        6,
        True,
        "UNKNOWN(" in text or "## 9. Unknowns" in text or "Unknowns / Static Boundaries" in text,
        "explicit unknowns retained",
    )
    add(
        "markdown_size",
        6,
        True if rich_ledger else False,
        len(text) >= (12_000 if rich_ledger else 1_500),
        f"markdown_chars={len(text)}",
    )
    add(
        "decode_or_config",
        6,
        False,
        "Static Decode Result" in text or "decoded preview" in folded or "XOR" in text or "CALG_" in text,
        "decode/config projection",
    )
    add(
        "ioc_section",
        4,
        False,
        "## 6. IOC / Indicators" in text,
        "IOC section present",
    )
    dynamic_claimed = (
        "DYNAMIC_OBSERVED" in text
        or "sample execution: **true**" in folded
        or "sandbox/dynamic analysis: **true**" in folded
    )
    add(
        "no_false_dynamic",
        4,
        True,
        (not dynamic_claimed) or emu_succeeded,
        "no host/runtime overclaim",
    )
    module_hits = [token for token in _MODULE_TOKENS if token in folded]
    add(
        "multi_module",
        6,
        True,
        len(set(module_hits)) >= 2 or "Module deep-dives" in text,
        f"module_tokens={sorted(set(module_hits))[:8]}",
    )
    add(
        "runtime_sequence",
        6,
        False,
        "Runtime sequence (static reconstruction)" in text or "Phase 1" in text,
        "catalog runtime sequence",
    )
    score = sum(item.points for item in checks if item.passed)
    return GoldBarResult(score=score, checks=tuple(checks))


def format_gold_bar(result: GoldBarResult) -> str:
    lines = [
        f"gold_bar score={result.score}/{result.total} passed={result.passed}",
        f"blocking_failures={len(result.blocking_failures)}",
    ]
    for item in result.checks:
        mark = "PASS" if item.passed else "FAIL"
        block = " BLOCK" if item.blocking and not item.passed else ""
        lines.append(f"- {item.check_id} {mark} +{item.points}{block}: {item.detail}")
    return "\n".join(lines)


def gold_bar_from_document(
    document: Mapping[str, object],
    markdown: str,
    *,
    rich_ledger: bool = True,
) -> GoldBarResult:
    del document
    return score_official_markdown(markdown, rich_ledger=rich_ledger)


@dataclass(frozen=True)
class T5BarDecision:
    """T5 acceptance overlay. Never mutates `score_official_markdown` checks."""

    gold: GoldBarResult
    accepted: bool
    sample_kind: str
    policy: str
    reason: str


_BENIGN_FALSE_MALICIOUS = (
    re.compile(r"severity\s*[:=]\s*\**\s*(HIGH|CRITICAL)\b", re.I),
    re.compile(r"\bconfirmed\s+C2\b", re.I),
    re.compile(r"\bfamily\s*[:=]\s*(?!unknown\b|n/?a\b)\S+", re.I),
    re.compile(r"\bverdict\s*[:=]\s*malicious\b", re.I),
)


def _false_malicious_reasons(markdown: str) -> tuple[str, ...]:
    text = str(markdown or "")
    reasons: list[str] = []
    for pattern in _BENIGN_FALSE_MALICIOUS:
        hit = pattern.search(text)
        if hit:
            reasons.append(hit.group(0).strip())
    folded = text.casefold()
    if re.search(r"\bmalicious\b", folded) and not re.search(
        r"malicious[`\"'\s:=]*0\b|not malicious|zero false-malicious|unassessed",
        folded,
    ):
        reasons.append("malicious-positive-claim")
    return tuple(reasons)


def evaluate_t5_sample_bar(
    markdown: str,
    *,
    sample_kind: Literal["malware", "benign"] = "malware",
    rich_ledger: bool = True,
) -> T5BarDecision:
    """Accept T5 output without weakening the numeric gold scorer.

    Malware still requires gold ≥90 and blocking=0. Benign samples may keep a
    decoded_constants blocking miss when the report has no false-malicious
    claims; that exemption is an explicit policy, not a silent PASS.
    """
    gold = score_official_markdown(markdown, rich_ledger=rich_ledger)
    kind = str(sample_kind or "malware")
    if kind == "benign":
        false_hits = _false_malicious_reasons(markdown)
        if false_hits:
            return T5BarDecision(
                gold=gold,
                accepted=False,
                sample_kind=kind,
                policy="benign_zero_false_malicious",
                reason="false-malicious:" + ",".join(false_hits[:3]),
            )
        blocking_ids = tuple(item.check_id for item in gold.blocking_failures)
        if gold.passed:
            return T5BarDecision(
                gold=gold,
                accepted=True,
                sample_kind=kind,
                policy="strict",
                reason="gold passed",
            )
        if (
            gold.score >= GOLD_BAR_PASS_SCORE
            and blocking_ids == ("decoded_constants",)
        ):
            return T5BarDecision(
                gold=gold,
                accepted=True,
                sample_kind=kind,
                policy="benign_unresolved_constants",
                reason="benign allows decoded_constants miss; gold.passed remains False",
            )
        return T5BarDecision(
            gold=gold,
            accepted=False,
            sample_kind=kind,
            policy="benign_unresolved_constants",
            reason=f"gold not eligible for benign exemption blocking={blocking_ids}",
        )
    return T5BarDecision(
        gold=gold,
        accepted=gold.passed,
        sample_kind=kind,
        policy="strict",
        reason="malware requires gold ≥90 and blocking=0",
    )
