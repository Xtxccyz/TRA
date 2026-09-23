"""

STATUS - READ THIS BEFORE ASSUMING AUTHORED TOOLS ARE GATED (measured round 96):

    NO production module imports this module, and none of its concepts (`host_write`, `nondeterminism`,
    `launch_intent`, `authored_tool`) appears anywhere else in production. It is a COMPLETE and TESTED implementation
    (`tests/test_tool_authoring.py`, 51 cases) whose door is simply not wired to anything yet.

    That makes it an implemented-but-unwired capability, not dead code: ADR-0037 (accepted) decides the product gains
    tool authoring, and this module is its non-negotiable admission gate. `tests/test_model_package_contract.py`-style
    frozen pins in `tests/test_tools_package_contract.py` keep it that way, so wiring it up OR retiring it must be a
    deliberate, recorded act rather than a quiet side effect.

    DO NOT delete it to "remove dead code": that would drop an accepted ADR's admission gate silently. DO NOT assume a
    live gate either - if you are reading this because authored tools appear to run unguarded, the cause is that this
    module has no caller, and the fix belongs to the capability axis (wire the gate), not to a structural step.
Tool authoring spec and policy gate (ADR-0037).

ADR-0037 lets the analysis system create tools for gaps that no existing
``ActionType`` can answer, under one non-negotiable boundary: **the submitted
sample is never started, loaded or otherwise executed on the host**.  This
module is only the *specification and admission gate* for such tools.  It does
not run anything, does not write anything and does not talk to the network: it
is a pure, deterministic judgement over a declarative request.

Terminology (see ``CONTEXT.md``): Unicorn / Speakeasy / Qiling emulation on the
isolated worker is **static analysis**, and its evidence nature is
``EMULATION_OBSERVED``.  Only a full sandbox run of the sample would produce
``DYNAMIC_OBSERVED``; this product does not do that, so authored tools may only
ever emit ``STATIC_DERIVED`` or ``EMULATION_OBSERVED``
(:func:`authored_tool_evidence_nature`).

How the source text is judged (a deliberate tradeoff)
-----------------------------------------------------
The submitted ``source_code`` is judged by *static text matching only*.  It is
never passed to ``exec``, ``eval`` or ``compile``: the gate must not execute the
code it is judging.  Concretely:

* Comments, string literals and f-strings are stripped by a tokenizer pass
  (``tokenize``, in memory, no file/process involvement) before marker matching.
  A tool that merely *names* dangerous APIs in its documentation - or holds
  sample-derived constants such as ``"socket"`` or ``"HKEY_LOCAL_MACHINE"`` -
  is therefore **accepted**.  This is intentional: security tooling legitimately
  names the APIs it looks for, and the previous "any occurrence anywhere"
  rule made the whole feature unusable for its actual purpose.
* What a string literal can no longer smuggle in is covered by indirection
  guards: ``__import__``, ``importlib``, ``eval``, ``exec``, ``compile``,
  ``getattr``/``setattr``, ``globals``/``locals``/``vars``, ``__dict__``,
  ``builtins``, ``marshal`` and ``pickle`` are all rejected as
  :data:`VIOLATION_SAMPLE_EXECUTION`, so
  ``__import__("sub" + "process").run(...)`` cannot hide behind string
  concatenation.
* If the tokenizer cannot scan the text, the gate **fails closed**: the raw
  source is scanned as plain text as well and
  :data:`VIOLATION_SOURCE_UNSCANNABLE` is reported.
* Prose fields (``purpose``, ``failure_modes``) are *not* matched against the
  code marker sets, because a purpose such as "join the decoded buffer to the
  socket API argument" describes the analysis target, not a capability the tool
  receives.  They are matched against a narrow launch-intent vocabulary
  ("run the sample", "execute_sample", ``DYNAMIC_OBSERVED``, ...) so a request
  that *declares* sample execution is still rejected.

Known limits, stated honestly: this is a *text* gate, not a proof.  Code that
reaches host capability while avoiding every guarded construct - for instance a
hand-rolled native call built from byte tables, or capability hidden inside a
value the tokenizer cannot attribute - is not statically decidable here.  The
gate is therefore the cheap first line, not the last one: real enforcement stays
with the isolated worker contract (no network, read-only root filesystem,
``cap_drop ALL``, temp output dir, CPU/wall/instruction/output ceilings) that the
future execution seam must apply, exactly as ADR-0037 requires.
"""

from __future__ import annotations

import io
import keyword
import re
import tokenize
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

TOOL_AUTHORING_POLICY_KIND: Final[str] = "authored-tool"

# --------------------------------------------------------------------------
# Evidence nature
# --------------------------------------------------------------------------

EVIDENCE_NATURE_STATIC_DERIVED: Final[str] = "STATIC_DERIVED"
EVIDENCE_NATURE_EMULATION_OBSERVED: Final[str] = "EMULATION_OBSERVED"
# Exported so callers and tests can assert that authored tools never reach it.
EVIDENCE_NATURE_DYNAMIC_OBSERVED: Final[str] = "DYNAMIC_OBSERVED"

#: The only evidence natures an authored tool may ever produce.  A full sandbox
#: run of the sample would be ``DYNAMIC_OBSERVED``; this product never does it.
AUTHORED_TOOL_EVIDENCE_NATURES: Final[tuple[str, ...]] = (
    EVIDENCE_NATURE_STATIC_DERIVED,
    EVIDENCE_NATURE_EMULATION_OBSERVED,
)

# --------------------------------------------------------------------------
# Resource ceilings
# --------------------------------------------------------------------------

TOOL_LIMIT_WALL_SECONDS: Final[str] = "wall_seconds"
TOOL_LIMIT_CPU_SECONDS: Final[str] = "cpu_seconds"
TOOL_LIMIT_INSTRUCTION_BUDGET: Final[str] = "instruction_budget"
TOOL_LIMIT_MAX_OUTPUT_BYTES: Final[str] = "max_output_bytes"

TOOL_LIMIT_KEYS: Final[tuple[str, ...]] = (
    TOOL_LIMIT_WALL_SECONDS,
    TOOL_LIMIT_CPU_SECONDS,
    TOOL_LIMIT_INSTRUCTION_BUDGET,
    TOOL_LIMIT_MAX_OUTPUT_BYTES,
)

#: Budgets applied when a request declares no limits at all.  They mirror the
#: existing controlled-emulation defaults (``simulation_instruction_budget`` and
#: ``simulation_max_output_bytes``) so an authored tool never gets a wider
#: budget than the emu-worker it sits next to.
DEFAULT_TOOL_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        TOOL_LIMIT_WALL_SECONDS: 30,
        TOOL_LIMIT_CPU_SECONDS: 10,
        TOOL_LIMIT_INSTRUCTION_BUDGET: 100_000,
        TOOL_LIMIT_MAX_OUTPUT_BYTES: 65_536,
    }
)

#: Absolute ceilings.  No request, default or later mutation may exceed them;
#: the gate also clamps the limits it hands back to a caller.
HARD_TOOL_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        TOOL_LIMIT_WALL_SECONDS: 120,
        TOOL_LIMIT_CPU_SECONDS: 60,
        TOOL_LIMIT_INSTRUCTION_BUDGET: 1_000_000,
        TOOL_LIMIT_MAX_OUTPUT_BYTES: 262_144,
    }
)

# --------------------------------------------------------------------------
# Stable violation constants
# --------------------------------------------------------------------------

VIOLATION_SAMPLE_EXECUTION: Final[str] = "SAMPLE_EXECUTION_FORBIDDEN"
VIOLATION_NETWORK_ACCESS: Final[str] = "NETWORK_ACCESS_FORBIDDEN"
VIOLATION_HOST_WRITE: Final[str] = "HOST_WRITE_FORBIDDEN"
VIOLATION_SOURCE_UNSCANNABLE: Final[str] = "SOURCE_UNSCANNABLE"
VIOLATION_SOURCE_CODE_REQUIRED: Final[str] = "SOURCE_CODE_REQUIRED"
VIOLATION_OUTPUT_SCHEMA_REQUIRED: Final[str] = "OUTPUT_SCHEMA_REQUIRED"
VIOLATION_FAILURE_MODES_REQUIRED: Final[str] = "FAILURE_MODES_REQUIRED"
VIOLATION_TOOL_NAME_UNSAFE: Final[str] = "TOOL_NAME_UNSAFE"
VIOLATION_PURPOSE_REQUIRED: Final[str] = "PURPOSE_REQUIRED"
VIOLATION_GAP_KIND_REQUIRED: Final[str] = "GAP_KIND_REQUIRED"
VIOLATION_PROPOSED_BY_UNKNOWN: Final[str] = "PROPOSED_BY_UNKNOWN"
VIOLATION_INPUT_SELECTORS_REQUIRED: Final[str] = "INPUT_SELECTORS_REQUIRED"
VIOLATION_INPUT_SELECTOR_INVALID: Final[str] = "INPUT_SELECTOR_INVALID"
VIOLATION_INPUT_SELECTOR_KEY_UNKNOWN: Final[str] = "INPUT_SELECTOR_KEY_UNKNOWN"
VIOLATION_RESOURCE_LIMIT_MISSING: Final[str] = "RESOURCE_LIMIT_MISSING"
VIOLATION_RESOURCE_LIMIT_INVALID: Final[str] = "RESOURCE_LIMIT_INVALID"
VIOLATION_RESOURCE_LIMIT_UNKNOWN_KEY: Final[str] = "RESOURCE_LIMIT_UNKNOWN_KEY"
VIOLATION_RESOURCE_LIMIT_EXCEEDED: Final[str] = "RESOURCE_LIMIT_EXCEEDED"
VIOLATION_NON_DETERMINISTIC: Final[str] = "NON_DETERMINISTIC_SOURCE"

#: Canonical order of every violation this gate can report.  Decisions always
#: emit their violations in this order, and never repeat one, so downstream
#: audit rows and tests stay stable.
TOOL_AUTHORING_VIOLATIONS: Final[tuple[str, ...]] = (
    VIOLATION_SAMPLE_EXECUTION,
    VIOLATION_NETWORK_ACCESS,
    VIOLATION_HOST_WRITE,
    VIOLATION_SOURCE_UNSCANNABLE,
    VIOLATION_SOURCE_CODE_REQUIRED,
    VIOLATION_OUTPUT_SCHEMA_REQUIRED,
    VIOLATION_FAILURE_MODES_REQUIRED,
    VIOLATION_PURPOSE_REQUIRED,
    VIOLATION_GAP_KIND_REQUIRED,
    VIOLATION_PROPOSED_BY_UNKNOWN,
    VIOLATION_TOOL_NAME_UNSAFE,
    VIOLATION_INPUT_SELECTORS_REQUIRED,
    VIOLATION_INPUT_SELECTOR_INVALID,
    VIOLATION_INPUT_SELECTOR_KEY_UNKNOWN,
    VIOLATION_RESOURCE_LIMIT_MISSING,
    VIOLATION_RESOURCE_LIMIT_INVALID,
    VIOLATION_RESOURCE_LIMIT_UNKNOWN_KEY,
    VIOLATION_RESOURCE_LIMIT_EXCEEDED,
    VIOLATION_NON_DETERMINISTIC,
)

TOOL_AUTHORING_ACCEPTED: Final[str] = "AUTHORED_TOOL_ACCEPTED"
TOOL_AUTHORING_REJECTED: Final[str] = "AUTHORED_TOOL_REJECTED"

# --------------------------------------------------------------------------
# Declarative vocabularies
# --------------------------------------------------------------------------

#: Keys a declarative input selector may carry.  Selectors must be flat
#: mappings of scalars (or lists of scalars) so the accepted spec stays
#: JSON-serialisable for the audit chain and cannot smuggle nested capability
#: declarations past the key check.  Selector *values* are deliberately open
#: vocabulary: only ``kind`` is required, and its value is not policed while
#: the execution seam is still being designed.
INPUT_SELECTOR_KEYS: Final[frozenset[str]] = frozenset(
    {
        "artifact_id",
        "byte_length",
        "byte_offset",
        "byte_range",
        "decoder",
        "encoding",
        "evidence_id",
        "field",
        "function",
        "index",
        "kind",
        "label",
        "line",
        "name",
        "offset",
        "rva",
        "sha256",
        "tool_run_id",
        "window",
    }
)

PROPOSED_BY_VALUES: Final[frozenset[str]] = frozenset({"model", "deterministic"})

TOOL_NAME_MIN_LENGTH: Final[int] = 3
TOOL_NAME_MAX_LENGTH: Final[int] = 64
TOOL_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

# --------------------------------------------------------------------------
# Static text markers
# --------------------------------------------------------------------------

# Starting, loading or otherwise running the submitted sample, plus the
# indirection that would hide it.  This is the single hard boundary.
_SAMPLE_EXECUTION_MARKERS: Final[tuple[str, ...]] = (
    r"\bsubprocess\b",
    r"\bos\s*\.\s*system\b",
    r"\bos\s*\.\s*popen\b",
    # Name-only forms catch the alias path (`import os as _o; _o.system(...)`);
    # the `os` import itself is refused under HOST_WRITE_FORBIDDEN.
    r"\bsystem\s*\(",
    r"\bpopen\s*\(",
    r"\bos\s*\.\s*exec\w*",
    r"\bos\s*\.\s*spawn\w*",
    r"\bos\s*\.\s*posix_spawn\w*",
    r"\bos\s*\.\s*fork\b",
    r"\bos\s*\.\s*startfile\b",
    r"\bshell\s*=\s*true\b",
    r"\bcreateprocess\w*",
    r"\bshellexecute\w*",
    r"\bwinexec\b",
    r"\bcreateremotethread\w*",
    r"\bvirtualallocex\b",
    r"\bwriteprocessmemory\b",
    r"\bloadlibrary\w*",
    r"\bgetprocaddress\b",
    r"\brunpy\b",
    r"\bctypes\b",
    r"\bwin32\w*",
    r"\bpythoncom\b",
    r"\bpywintypes\b",
    r"\bmultiprocessing\b",
    r"\bpty\b",
    r"(?<![\w.])eval\s*\(",
    r"(?<![\w.])exec\s*\(",
    r"(?<![\w.])compile\s*\(",
    r"(?<![\w.])__import__\s*\(",
    r"\bimportlib\b",
    r"\bimport_module\b",
    r"\bbuiltins\b",
    r"\bmarshal\b",
    r"\bpickle\b",
    r"(?<![\w.])getattr\s*\(",
    r"(?<![\w.])setattr\s*\(",
    r"(?<![\w.])delattr\s*\(",
    r"(?<![\w.])globals\s*\(",
    r"(?<![\w.])locals\s*\(",
    r"(?<![\w.])vars\s*\(",
    r"\b__dict__\b",
    r"\b__globals__\b",
    r"\b__subclasses__\b",
    r"\b__builtins__\b",
    r"\b__getattribute__\b",
    r"\b__loader__\b",
)

#: Narrow vocabulary for prose and machine-readable declarations.  Matching is
#: adjacency-bound: "recover the launch command for the sample" stays accepted,
#: "run the sample" / "sample_execution" / "DYNAMIC_OBSERVED" do not.
_DECLARED_LAUNCH_INTENT_MARKERS: Final[tuple[str, ...]] = (
    r"\bsample[\s_-]*execution\b",
    r"\bexecut\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\brun\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\blaunch\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\bstart\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\binvoke\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\b(?:observ|watch|monitor|instrument)\w*[\s_-]*(?:the[\s_-]*)?sample\b",
    r"\blive[\s_-]*(?:sandbox|run|execution|observation)\b",
    r"\bsample[\s_-]*runtime\b",
    r"\bruntime[\s_-]*(?:observation|trace|behavio\w*)\b",
    r"\bhost[\s_-]*execution\b",
    r"\bnative[\s_-]*execution\b",
    r"\bsandbox[\s_-]*(?:run|execution)\b",
    r"\bdynamic[\s_-]*(?:analysis|observation|execution)\b",
    r"\bdynamic_observed\b",
    r"\bsample_observation\b",
)

_NETWORK_MARKERS: Final[tuple[str, ...]] = (
    r"\bsocket\b",
    r"\bsocketserver\b",
    r"\bssl\b",
    r"\burllib\b",
    r"\burllib3\b",
    r"\brequests\b",
    r"\bhttpx\b",
    r"\baiohttp\b",
    r"\bhttp\s*\.\s*client\b",
    r"\bimport\s+http\b",
    r"\bfrom\s+http\b",
    r"\bhttplib\b",
    r"\bftplib\b",
    r"\bsmtplib\b",
    r"\bpoplib\b",
    r"\bimaplib\b",
    r"\btelnetlib\b",
    r"\bparamiko\b",
    r"\bxmlrpc\b",
    r"\bwebbrowser\b",
    r"\bpycurl\b",
    r"\bwininet\b",
    r"\bwinhttp\b",
    r"\bws2_32\b",
    r"\binternetopen\w*",
    r"\burldownloadtofile\w*",
    r"\bgetaddrinfo\b",
    r"\bgethostbyname\b",
    r"\bsockaddr\w*",
    r"\bsendto\b",
    r"\brecvfrom\b",
)

#: Host filesystem, registry and process-environment access.  Authored tools
#: consume *granted bytes* and return values, so host paths are out of contract
#: even for reading - this is why a plain ``open(...)`` is reported here.
#: ``os`` is matched at the import statement as well, because aliasing
#: (``import os as _os``) defeats attribute-level matching and a byte-level tool
#: needs none of that module.
_HOST_WRITE_MARKERS: Final[tuple[str, ...]] = (
    r"(?<![\w.])open\s*\(",
    r"\bimport\s+os\b",
    r"\bfrom\s+os\b",
    r"\bio\s*\.\s*open\b",
    r"\bos\s*\.\s*open\b",
    r"\bos\s*\.\s*remove\b",
    r"\bos\s*\.\s*unlink\b",
    r"\bos\s*\.\s*rename\b",
    r"\bos\s*\.\s*replace\b",
    r"\bos\s*\.\s*mkdir\b",
    r"\bos\s*\.\s*makedirs\b",
    r"\bos\s*\.\s*rmdir\b",
    r"\bos\s*\.\s*removedirs\b",
    r"\bos\s*\.\s*chmod\b",
    r"\bos\s*\.\s*chown\b",
    r"\bos\s*\.\s*truncate\b",
    r"\bos\s*\.\s*symlink\b",
    r"\bos\s*\.\s*link\b",
    r"\bos\s*\.\s*utime\b",
    r"\bos\s*\.\s*environ\b",
    r"\bos\s*\.\s*getenv\b",
    r"\bos\s*\.\s*putenv\b",
    r"\bshutil\b",
    r"\bwinreg\b",
    r"\bregsetvalue\w*",
    r"\bregcreatekey\w*",
    r"\bregdeletekey\w*",
    r"\bregdeletevalue\w*",
    r"\bregistry\b",
    r"\bhkey_\w+",
    r"\bwindll\b",
    r"\bwin32file\b",
    r"\bwin32security\b",
    r"\bsys\s*\.\s*path\b",
    r"\.write_text\b",
    r"\.write_bytes\b",
    r"\.mkdir\b",
    r"\.rmdir\b",
    r"\.unlink\b",
    r"\.rename\b",
    r"\.touch\b",
    r"\.chmod\b",
    r"\.symlink_to\b",
    r"\.hardlink_to\b",
    r"\.extractall\b",
    r"\.extract\s*\(",
)

#: Reproducibility: the same granted bytes must always produce the same output.
_NON_DETERMINISM_MARKERS: Final[tuple[str, ...]] = (
    r"\bimport\s+random\b",
    r"\bfrom\s+random\s+import\b",
    r"\brandom\s*\.\s*\w+",
    r"\bimport\s+secrets\b",
    r"\bfrom\s+secrets\s+import\b",
    r"\bsecrets\s*\.\s*\w+",
    r"\buuid\s*\.\s*uuid1\b",
    r"\buuid\s*\.\s*uuid4\b",
    r"\bos\s*\.\s*urandom\b",
    r"\bos\s*\.\s*getpid\b",
    r"\bos\s*\.\s*getppid\b",
    r"\btime\s*\.\s*time\b",
    r"\btime\s*\.\s*monotonic\b",
    r"\btime\s*\.\s*perf_counter\b",
    r"\btime\s*\.\s*process_time\b",
    r"\bdatetime\s*\.\s*(?:now|utcnow|today)\b",
    r"\bdate\s*\.\s*today\b",
    r"(?<![\w.])hash\s*\(",
    r"(?<![\w.])id\s*\(",
    r"\bthreading\b",
    r"\bconcurrent\b",
    r"\basyncio\b",
)


def _compile_markers(patterns: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


_EXECUTION_PATTERNS = _compile_markers(_SAMPLE_EXECUTION_MARKERS)
_LAUNCH_INTENT_PATTERNS = _compile_markers(_DECLARED_LAUNCH_INTENT_MARKERS)
_NETWORK_PATTERNS = _compile_markers(_NETWORK_MARKERS)
_HOST_WRITE_PATTERNS = _compile_markers(_HOST_WRITE_MARKERS)
_NON_DETERMINISM_PATTERNS = _compile_markers(_NON_DETERMINISM_MARKERS)

_MAX_SCHEMA_NODES: Final[int] = 256
_MAX_SCHEMA_DEPTH: Final[int] = 6


# --------------------------------------------------------------------------
# Public spec objects
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolAuthoringRequest:
    """One declarative request to create a tool for an uncovered gap.

    Every field is optional at construction time so a partial model proposal is
    representable; the gate then rejects whatever is missing.  ``purpose`` and
    ``gap_kind`` are required by the gate because ADR-0037 needs the trigger gap
    and the rationale in the audit chain, and ``source_code`` must be a
    deterministic implementation: the same granted bytes must always yield the
    same output.
    """

    tool_name: str = ""
    purpose: str = ""
    gap_kind: str = ""
    mechanism_type: str = ""
    artifact_id: str = ""
    thread_id: str = ""
    input_selectors: tuple[dict[str, object], ...] = ()
    source_code: str = ""
    output_schema: dict[str, object] = field(default_factory=dict)
    failure_modes: tuple[str, ...] = ()
    proposed_by: str = "model"
    resource_limits: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolAuthoringDecision:
    """Outcome of the policy gate.

    ``resource_limits`` always carries the effective four budgets, clamped to
    :data:`HARD_TOOL_LIMITS`, so a caller that ignores ``accepted`` still cannot
    hand an over-budget tool to a worker.
    """

    accepted: bool = False
    violations: tuple[str, ...] = ()
    reason: str = ""
    resource_limits: dict[str, object] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Public functions
# --------------------------------------------------------------------------


def evaluate_tool_authoring_request(request: ToolAuthoringRequest) -> ToolAuthoringDecision:
    """Decide whether one authored-tool request may reach a worker.

    Pure and side-effect free: no file, network or process access, and the
    submitted ``source_code`` is only ever matched as text.  The verdict is
    conservative on purpose - this gate becomes the admission check in front of
    real execution - so anything it cannot prove declarative and reproducible is
    rejected with a stable :data:`TOOL_AUTHORING_VIOLATIONS` entry.
    """
    if not isinstance(request, ToolAuthoringRequest):
        raise TypeError("evaluate_tool_authoring_request expects a ToolAuthoringRequest")

    found: set[str] = set()
    resolved_limits, limit_findings = _resolve_resource_limits(request.resource_limits)
    found.update(limit_findings)

    source_code = request.source_code if isinstance(request.source_code, str) else ""
    if not source_code.strip():
        found.add(VIOLATION_SOURCE_CODE_REQUIRED)
    if not isinstance(request.purpose, str) or not request.purpose.strip():
        found.add(VIOLATION_PURPOSE_REQUIRED)
    if not isinstance(request.gap_kind, str) or not request.gap_kind.strip():
        found.add(VIOLATION_GAP_KIND_REQUIRED)
    if not isinstance(request.proposed_by, str) or request.proposed_by not in PROPOSED_BY_VALUES:
        found.add(VIOLATION_PROPOSED_BY_UNKNOWN)
    if not _is_safe_tool_name(request.tool_name):
        found.add(VIOLATION_TOOL_NAME_UNSAFE)
    if not isinstance(request.output_schema, Mapping) or not request.output_schema:
        found.add(VIOLATION_OUTPUT_SCHEMA_REQUIRED)
    if not isinstance(request.failure_modes, (tuple, list)) or not request.failure_modes:
        found.add(VIOLATION_FAILURE_MODES_REQUIRED)
    elif any(not str(mode).strip() for mode in request.failure_modes):
        found.add(VIOLATION_FAILURE_MODES_REQUIRED)
    found.update(_selector_violations(request.input_selectors))

    code_text, scannable = _code_only_text(source_code) if source_code.strip() else ("", True)
    if not scannable:
        found.add(VIOLATION_SOURCE_UNSCANNABLE)

    mechanism_tokens = _declared_tokens(
        (request.mechanism_type, request.gap_kind, *_declared_selector_keys(request.input_selectors))
    )
    schema_keys = _declared_keys(request.output_schema)
    capability_text = " \n ".join((code_text, mechanism_tokens, " ".join(schema_keys)))
    intent_text = " \n ".join(
        (
            str(request.purpose),
            " ".join(str(mode) for mode in _as_sequence(request.failure_modes)),
            " ".join(_selector_values(request.input_selectors)),
            capability_text,
        )
    )

    if _matches(capability_text, _EXECUTION_PATTERNS) or _matches(
        intent_text, _LAUNCH_INTENT_PATTERNS
    ):
        found.add(VIOLATION_SAMPLE_EXECUTION)
    if _matches(capability_text, _NETWORK_PATTERNS):
        found.add(VIOLATION_NETWORK_ACCESS)
    if _matches(capability_text, _HOST_WRITE_PATTERNS):
        found.add(VIOLATION_HOST_WRITE)
    if _matches(capability_text, _NON_DETERMINISM_PATTERNS):
        found.add(VIOLATION_NON_DETERMINISTIC)

    violations = tuple(item for item in TOOL_AUTHORING_VIOLATIONS if item in found)
    if violations:
        return ToolAuthoringDecision(
            accepted=False,
            violations=violations,
            reason=f"{TOOL_AUTHORING_REJECTED}: {', '.join(violations)}",
            resource_limits=dict(resolved_limits),
        )
    return ToolAuthoringDecision(
        accepted=True,
        violations=(),
        reason=TOOL_AUTHORING_ACCEPTED,
        resource_limits=dict(resolved_limits),
    )


def authored_tool_evidence_nature(*, emulated: bool) -> str:
    """Evidence nature for the output of an authored tool.

    ``EMULATION_OBSERVED`` when the output came from a real isolated-worker
    emulation run (Unicorn / Speakeasy / Qiling on granted windows - still
    static analysis), otherwise ``STATIC_DERIVED``.  Never
    ``DYNAMIC_OBSERVED``: that would require the sample to have actually run.

    Callers must only pass ``emulated=True`` once a real worker result exists.
    ``DEFERRED_TO_WORKER`` / ``WORKER_REQUIRED`` placeholders are not an
    emulation attempt and keep the output at ``STATIC_DERIVED``.
    """
    if not isinstance(emulated, bool):
        raise TypeError("emulated must be a bool; evidence nature is never guessed from truthiness")
    return EVIDENCE_NATURE_EMULATION_OBSERVED if emulated else EVIDENCE_NATURE_STATIC_DERIVED


def authored_tool_policy_metadata(
    request: ToolAuthoringRequest, decision: ToolAuthoringDecision
) -> dict[str, object]:
    """Descriptor the policy layer can record for an authored tool.

    ``policy.require_tool`` looks tools up by name in the static registry; an
    authored tool is not in that registry yet, so this returns the equivalent
    declarative facts (kind, no sample execution, no network, clamped budgets,
    evidence ceiling) for the orchestrator to keep next to the audit row.
    """
    limits, _ = _resolve_resource_limits(decision.resource_limits)
    return {
        "kind": TOOL_AUTHORING_POLICY_KIND,
        "tool_name": str(request.tool_name),
        "artifact_id": str(request.artifact_id),
        "thread_id": str(request.thread_id),
        "gap_kind": str(request.gap_kind),
        "accepted": bool(decision.accepted),
        "violations": list(decision.violations),
        "sample_execution": False,
        "network_access": False,
        "read_only_inputs": True,
        TOOL_LIMIT_WALL_SECONDS: limits[TOOL_LIMIT_WALL_SECONDS],
        "max_cpu_seconds": limits[TOOL_LIMIT_CPU_SECONDS],
        TOOL_LIMIT_INSTRUCTION_BUDGET: limits[TOOL_LIMIT_INSTRUCTION_BUDGET],
        TOOL_LIMIT_MAX_OUTPUT_BYTES: limits[TOOL_LIMIT_MAX_OUTPUT_BYTES],
        "evidence_nature_ceiling": EVIDENCE_NATURE_EMULATION_OBSERVED,
    }


# --------------------------------------------------------------------------
# Private helpers
# --------------------------------------------------------------------------

_EXTRA_TOKEN_TYPES: Final[tuple[int, ...]] = tuple(
    token_type
    for token_type in (
        getattr(tokenize, "FSTRING_START", None),
        getattr(tokenize, "FSTRING_MIDDLE", None),
        getattr(tokenize, "FSTRING_END", None),
    )
    if token_type is not None
)

_DROPPED_TOKEN_TYPES: Final[frozenset[int]] = frozenset(
    (tokenize.COMMENT, tokenize.STRING, *_EXTRA_TOKEN_TYPES)
)

_POSITION_TOKEN_TYPES: Final[frozenset[int]] = frozenset(
    {
        tokenize.NEWLINE,
        tokenize.NL,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENDMARKER,
    }
)


def _code_only_text(source: str) -> tuple[str, bool]:
    """Strip comments and string literals; report whether that was possible.

    Returns ``(text, scannable)``.  When the source cannot be tokenized the raw
    source is returned with ``scannable=False`` so the caller fails closed by
    scanning it as plain text and reporting :data:`VIOLATION_SOURCE_UNSCANNABLE`.
    Tokenizing is pure in-memory text work and never executes the source.
    """
    pieces: list[str] = []
    previous = ""
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in _DROPPED_TOKEN_TYPES:
                continue
            text = "\n" if token.type in _POSITION_TOKEN_TYPES else token.string
            if not text:
                continue
            # Keep dotted attribute access adjacent so `re.compile(` is not
            # mistaken for a bare `compile(` call.
            if text == "." or previous == ".":
                pieces.append(text)
            else:
                pieces.append(" " + text)
            previous = text
    except (IndentationError, SyntaxError, tokenize.TokenError, ValueError):
        return source, False
    return "".join(pieces), True


def _matches(text: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(pattern.search(text) is not None for pattern in patterns)


def _as_sequence(value: object) -> tuple[object, ...]:
    if isinstance(value, (tuple, list)):
        return tuple(value)
    return ()


def _is_auditable_value(value: object) -> bool:
    if value is None or isinstance(value, (str, bool, int, float)):
        return True
    if isinstance(value, (tuple, list)):
        return all(
            item is None or isinstance(item, (str, bool, int, float)) for item in value
        )
    return False


def _selector_violations(selectors: object) -> tuple[str, ...]:
    if not isinstance(selectors, (tuple, list)):
        return (VIOLATION_INPUT_SELECTOR_INVALID,)
    if not selectors:
        return (VIOLATION_INPUT_SELECTORS_REQUIRED,)
    found: list[str] = []
    for selector in selectors:
        if not isinstance(selector, Mapping) or not selector:
            found.append(VIOLATION_INPUT_SELECTOR_INVALID)
            continue
        if not isinstance(selector.get("kind"), str) or not str(selector.get("kind")).strip():
            found.append(VIOLATION_INPUT_SELECTOR_INVALID)
        if any(key not in INPUT_SELECTOR_KEYS for key in selector):
            found.append(VIOLATION_INPUT_SELECTOR_KEY_UNKNOWN)
        if any(not _is_auditable_value(value) for value in selector.values()):
            found.append(VIOLATION_INPUT_SELECTOR_INVALID)
    return tuple(found)


def _declared_selector_keys(selectors: object) -> tuple[str, ...]:
    """Selector keys, rendered as text so a mechanism cannot hide in a key."""
    return tuple(
        str(key)
        for selector in _as_sequence(selectors)
        if isinstance(selector, Mapping)
        for key in selector
    )


def _selector_values(selectors: object) -> tuple[str, ...]:
    values: list[str] = []
    for selector in _as_sequence(selectors):
        if isinstance(selector, Mapping):
            values.extend(str(value) for value in selector.values())
    return tuple(values)


def _declared_tokens(parts: tuple[object, ...]) -> str:
    return " ".join(str(part) for part in parts if part)


def _declared_keys(value: object) -> tuple[str, ...]:
    keys: list[str] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack and len(keys) < _MAX_SCHEMA_NODES:
        node, depth = stack.pop()
        if depth > _MAX_SCHEMA_DEPTH:
            continue
        if isinstance(node, Mapping):
            for key, item in node.items():
                keys.append(str(key))
                stack.append((item, depth + 1))
        elif isinstance(node, (tuple, list)):
            for item in node:
                stack.append((item, depth + 1))
    return tuple(keys)


def _is_safe_tool_name(tool_name: object) -> bool:
    if not isinstance(tool_name, str):
        return False
    if not TOOL_NAME_MIN_LENGTH <= len(tool_name) <= TOOL_NAME_MAX_LENGTH:
        return False
    if TOOL_NAME_PATTERN.match(tool_name) is None:
        return False
    return not keyword.iskeyword(tool_name)


def _resolve_resource_limits(declared: object) -> tuple[dict[str, int], tuple[str, ...]]:
    """Resolve effective budgets and report limit violations.

    Declaring limits is all-or-nothing: an empty mapping means "use
    :data:`DEFAULT_TOOL_LIMITS`", while a non-empty mapping must name every
    known key.  Returned values are always clamped to :data:`HARD_TOOL_LIMITS`.
    """
    resolved: dict[str, int] = {key: int(DEFAULT_TOOL_LIMITS[key]) for key in TOOL_LIMIT_KEYS}
    if declared is None:
        return resolved, ()
    if not isinstance(declared, Mapping):
        return resolved, (VIOLATION_RESOURCE_LIMIT_INVALID,)
    if not declared:
        return resolved, ()

    found: list[str] = []
    if any(key not in TOOL_LIMIT_KEYS for key in declared):
        found.append(VIOLATION_RESOURCE_LIMIT_UNKNOWN_KEY)
    if any(key not in declared for key in TOOL_LIMIT_KEYS):
        found.append(VIOLATION_RESOURCE_LIMIT_MISSING)
    for key in TOOL_LIMIT_KEYS:
        if key not in declared:
            continue
        value = declared[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            found.append(VIOLATION_RESOURCE_LIMIT_INVALID)
            continue
        ceiling = int(HARD_TOOL_LIMITS[key])
        resolved[key] = min(value, ceiling)
        if value > ceiling:
            found.append(VIOLATION_RESOURCE_LIMIT_EXCEEDED)
    return resolved, tuple(found)
