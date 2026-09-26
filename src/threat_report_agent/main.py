from __future__ import annotations

import json
import io
import os
import zipfile
from contextlib import asynccontextmanager
from datetime import date, datetime
from pathlib import Path
import logging
import sys
import threading
import time
import traceback
from typing import Annotated, Literal

from fastapi import (
    BackgroundTasks,
    Body,
    FastAPI,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, SecretStr, model_validator
from sqlalchemy import text

from threat_report_agent.config import Settings
from threat_report_agent.investigation import normalize_target_selector
from threat_report_agent.auth import require_permission, AuthAdapter
from threat_report_agent.contracts import BackgroundContextInput
from threat_report_agent.content_store import LocalContentStore, S3ContentStore
from threat_report_agent.database import Database
from threat_report_agent.observability import (
    HTTP_DURATION,
    HTTP_REQUESTS,
    configure_observability,
    metrics_payload,
)
from threat_report_agent.report.reporting import (
    REPORT_MODULES,
    markdown_to_docx,
    markdown_to_pdf,
)
from threat_report_agent.model.model_gateway import model_provider_family, supported_provider_contracts
from threat_report_agent.service import AnalysisService, ContextMismatchError


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)


class CaseArchiveRequest(BaseModel):
    actor: str = Field(default="case-reviewer", min_length=1, max_length=160)


class DailyAuditSealRequest(BaseModel):
    utc_day: date
    actor: str = Field(default="audit-sealer", min_length=1, max_length=160)


class EvidencePurgeRequestCreate(BaseModel):
    requested_by: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=4000)


class EvidencePurgeReviewRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=160)
    approve: bool


class EvidencePurgeExecuteRequest(BaseModel):
    admin: str = Field(min_length=1, max_length=160)


class RetentionFreezeRequest(BaseModel):
    frozen: bool
    reason: str = Field(min_length=1, max_length=4000)


class ModelPayloadExpiryRequest(BaseModel):
    now: datetime | None = None


class AnalysisPackageReplayRequest(BaseModel):
    package: dict[str, object]
    selected_modules: list[str] | None = None


class ReportModulesRequest(BaseModel):
    modules: list[str]


class ReportEditRequest(BaseModel):
    markdown: str = Field(min_length=1)
    author: str = Field(default="demo-analyst", min_length=1, max_length=160)


class ReportApprovalRequest(BaseModel):
    note: str = Field(default="", max_length=2000)


class GateDecisionRequest(BaseModel):
    decision: Literal["APPROVE", "REJECT"]
    archive_password: SecretStr | None = None
    note: str = Field(default="", max_length=2000)


class ModelProviderConfigurationRequest(BaseModel):
    provider: str = Field(default="", max_length=80)
    base_url: str = Field(default="", max_length=512)
    model: str = Field(default="", max_length=160)
    api_style: Literal[
        "openai", "openai-compatible", "chat-completions", "anthropic", "messages"
    ] = "openai"
    enabled: bool = True
    stream: bool = True
    supports_json_mode: bool = True
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    disable_reasoning: bool = True
    api_key: SecretStr | None = None
    clear_api_key: bool = False


class ModelConfigurationRequest(BaseModel):
    expected_revision: int | None = Field(default=None, ge=0)
    enabled: bool = False
    context_max_bytes: int = Field(default=2_000_000, ge=1024, le=50_000_000)
    timeout_s: float = Field(default=180.0, ge=5.0, le=600.0)
    max_tokens: int = Field(default=2048, ge=256, le=32768)
    primary: ModelProviderConfigurationRequest
    fallback: ModelProviderConfigurationRequest


class RelationCreateRequest(BaseModel):
    source_artifact_id: str
    target_artifact_id: str
    relation_type: Literal[
        "CONTAINS", "DROPS", "EXTRACTED_FROM", "LOADS", "DECRYPTS", "EXECUTES", "INJECTS"
    ]
    evidence_id: str | None = None
    claim_id: str | None = None


class WorkbenchSessionLinkRequest(BaseModel):
    dsh_session_id: str = Field(min_length=1, max_length=200)
    profile: str = Field(default="threat-static", min_length=1, max_length=80)


class SessionAnalysisStartRequest(BaseModel):
    artifact_id: str | None = Field(default=None, max_length=36)


class SessionAnalysisBindRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=36)


class SessionArtifactImportRequest(BaseModel):
    case_id: str | None = Field(default=None, max_length=36)
    case_title: str = Field(default="静态分析任务", min_length=1, max_length=240)
    workspace_id: str | None = Field(default=None, max_length=200)


class WorkspaceArtifactImportRequest(BaseModel):
    relative_path: str = Field(min_length=1, max_length=1024)
    case_id: str | None = Field(default=None, max_length=36)
    workspace_id: str | None = Field(default=None, max_length=200)


class WorkbenchStartAnalysisRequest(BaseModel):
    artifact_id: str | None = Field(default=None, max_length=36)
    selected_modules: list[str] | None = None


class WorkbenchAnalysisIntentRequest(BaseModel):
    question: str = Field(default="", max_length=1000)


class WorkbenchBindAnalysisRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=36)


class SessionAnalysisUnbindRequest(BaseModel):
    # Only DSH new-session reuse should discard staged artifacts. Body-less
    # unbind remains the backward-compatible close/retry behavior.
    discard_staged: bool = False


class EvidenceQueryRequest(BaseModel):
    task_id: str
    kind: str | None = None
    module: str | None = None
    artifact_id: str | None = None
    limit: int = Field(default=100, ge=1, le=500)


_FAILURE_INTERPRETATION_TOKENS = ("NO_NEW_EVIDENCE", "STATIC_BOUNDARY", "UNKNOWN", "MODEL_TRANSPORT_FAILURE")

#: Prose markers that can only describe the MODEL/TRANSPORT side of a failed action, never the artifact. Deliberately
#: excludes a bare `TIMEOUT`/`TIMED_OUT`, which can equally describe a TOOL timeout (a real extraction gap).
_MODEL_TRANSPORT_MARKERS = (
    "402",
    "401",
    "429",
    "MODEL_",
    "PROVIDER",
    "TRANSPORT",
    "EMPTY_REPLY",
    "EMPTY REPLY",
    "RATE_LIMIT",
    "UNAVAILABLE",
    "DEPENDENCY",
)


def _coerce_failure_interpretation(raw: object) -> tuple[str, str]:
    """Map DSH prose onto the catalog token; leftover text belongs in failure_meaning.

    TRANSPORT IS CHECKED FIRST, ON PURPOSE. MEASURED (B00/B04 handoff): a client that writes
    "could not establish STATIC_BOUNDARY: provider returned 402" must be recorded as a MODEL transport failure. The
    substring loop below would otherwise see `STATIC_BOUNDARY` and file a platform fault as a property of the SAMPLE.
    """
    text = str(raw or "").strip()
    if text in _FAILURE_INTERPRETATION_TOKENS:
        return text, ""
    folded_early = text.upper().replace("-", "_").replace(" ", "_")
    if any(marker.replace(" ", "_") in folded_early for marker in _MODEL_TRANSPORT_MARKERS):
        return "MODEL_TRANSPORT_FAILURE", text
    folded = text.upper().replace("-", "_")
    token = "UNKNOWN"
    for candidate in ("NO_NEW_EVIDENCE", "STATIC_BOUNDARY", "UNKNOWN"):
        if candidate in folded.replace(" ", "_") or candidate in text.upper():
            token = candidate
            break
    leftover = text if text != token else ""
    return token, leftover


class WorkbenchActionRequest(BaseModel):
    action_type: str = Field(min_length=1, max_length=64)
    target_artifact_id: str = Field(min_length=1, max_length=36)
    hypothesis_id: str | None = Field(default=None, max_length=120)
    reason: str = Field(min_length=1, max_length=2000)
    # Model-origin actions must carry this plan-first contract through the
    # Workbench API. Human queries may omit it and remain evidence-only.
    question: str = Field(default="", max_length=1200)
    hypothesis: str = Field(default="", max_length=1200)
    alternatives: list[str] = Field(default_factory=list, max_length=8)
    missing_evidence: list[str] = Field(default_factory=list, max_length=16)
    failure_meaning: str = Field(default="", max_length=1200)
    target_selector: dict[str, str | int]
    expected_evidence_kinds: list[str] = Field(min_length=1, max_length=32)
    success_condition: str = Field(default="new_targeted_evidence", min_length=1, max_length=160)
    failure_interpretation: Literal[
        "UNKNOWN", "NO_NEW_EVIDENCE", "STATIC_BOUNDARY", "MODEL_TRANSPORT_FAILURE"
    ] = "UNKNOWN"

    @model_validator(mode="before")
    @classmethod
    def _accept_prose_failure_interpretation(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        updated = dict(data)
        raw = updated.get("failure_interpretation")
        if raw not in (None, *_FAILURE_INTERPRETATION_TOKENS):
            token, leftover = _coerce_failure_interpretation(raw)
            updated["failure_interpretation"] = token
            meaning = str(updated.get("failure_meaning") or "").strip()
            extra = leftover.strip()
            if extra and extra not in {token, meaning}:
                updated["failure_meaning"] = (f"{meaning}; {extra}" if meaning else extra)[:1200]
        success = updated.get("success_condition")
        if isinstance(success, str) and len(success) > 160:
            leftover_success = success[160:].strip()
            updated["success_condition"] = success[:160]
            if leftover_success:
                meaning = str(updated.get("failure_meaning") or "").strip()
                if leftover_success not in meaning:
                    updated["failure_meaning"] = (
                        f"{meaning}; {leftover_success}" if meaning else leftover_success
                    )[:1200]
        selector = updated.get("target_selector")
        if isinstance(selector, dict):
            updated["target_selector"] = normalize_target_selector(selector)
        return updated
    # Model/Workbench provenance is audit metadata only.  The backend still
    # validates the catalog, target and evidence scope before execution.
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    origin: Literal["model", "deterministic_fallback", "human"] | None = None
    planner_turn_id: str | None = Field(default=None, max_length=200)
    model_call_id: str | None = Field(default=None, max_length=160)
    model_run_id: str | None = Field(default=None, max_length=160)
    model_provider: str | None = Field(default=None, max_length=120)
    model_name: str | None = Field(default=None, max_length=160)
    # OpenAI-compatible gateways conventionally call these fields provider
    # and model; accept both spellings at the Workbench boundary.
    provider: str | None = Field(default=None, max_length=120)
    model: str | None = Field(default=None, max_length=160)
    prompt_sha256: str | None = Field(default=None, max_length=64)
    profile_digest: str | None = Field(default=None, max_length=64)
    policy_digest: str | None = Field(default=None, max_length=64)
    action_validation_digest: str | None = Field(default=None, max_length=64)
    action_validation: dict[str, object] = Field(default_factory=dict)
    model_provenance: dict[str, object] = Field(default_factory=dict)


class WorkbenchCurrentEvidenceRequest(BaseModel):
    kind: str | None = Field(default=None, max_length=120)
    module: str | None = Field(default=None, max_length=120)
    artifact_id: str | None = Field(default=None, max_length=36)
    limit: int = Field(default=100, ge=1, le=500)
    filter_text: str | None = Field(
        default=None,
        max_length=120,
        description=(
            "Match stored evidence whose anchor or value carries this text. Use a "
            "function entry (0x140038ae0 / FUN_140038ae0) or an address to drill into "
            "one function instead of paging a flat list."
        ),
    )


class WorkbenchReportFileRequest(BaseModel):
    """One bounded report write: a flat markdown file name and its content."""

    filename: str = Field(min_length=1, max_length=200)
    markdown: str = Field(min_length=1, max_length=400000)


class WorkbenchModelRequest(BaseModel):
    """DSH-facing model gateway request with a closed response contract."""

    operation: Literal["planning", "claims"]
    case_id: str = Field(min_length=1, max_length=36)
    session_id: str = Field(min_length=1, max_length=200)
    turn_id: str = Field(min_length=1, max_length=200)
    step_id: str = Field(min_length=1, max_length=200)
    thread_id: str = Field(default="", max_length=160)
    module: str = Field(min_length=1, max_length=64)
    prompt_id: str = Field(min_length=1, max_length=120)
    prompt_version: str = Field(min_length=1, max_length=80)
    prompt_sha256: str = Field(min_length=64, max_length=64)
    messages: list[dict[str, str]] = Field(min_length=1, max_length=32)
    timeout_s: float = Field(default=180.0, ge=5.0, le=600.0)
    max_tokens: int = Field(default=2048, ge=256, le=32768)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    top_p: float | None = Field(default=None, gt=0.0, le=1.0)
    stream: bool | None = None
    structured_output: bool | None = None
    disable_reasoning: bool | None = None


def _service(request: Request) -> AnalysisService:
    return request.app.state.analysis_service


def _require_task_scope(request: Request, task_id: str, permission: str) -> None:
    """Authorize a task projection against the caller's DSH session context.

    Workbench clients always send the host-injected ``X-DSH-Session-ID``.
    Legacy admin/auditor callers may omit it for explicit operational review;
    ordinary principals must provide a bound session to prevent task IDOR.
    """
    principal = require_permission(request, permission)
    session_id = request.headers.get("X-DSH-Session-ID", "").strip()
    if session_id:
        try:
            _service(request).assert_task_bound_to_session(task_id, session_id)
        except ContextMismatchError as exc:
            raise HTTPException(
                status_code=403, detail={"code": exc.code, "message": str(exc)}
            ) from exc
        return
    if principal.roles.isdisjoint({"admin", "auditor"}):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "CONTEXT_MISMATCH",
                "message": "X-DSH-Session-ID is required for task access",
            },
        )


def _not_found(exc: LookupError) -> HTTPException:
    return HTTPException(status_code=404, detail=str(exc))


def _parse_modules(raw: str) -> list[str] | None:
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = [part.strip() for part in raw.split(",") if part.strip()]
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise HTTPException(status_code=422, detail="selected_modules must be a JSON string array")
    return parsed


def _package_uploads(
    uploads: list[UploadFile],
    *,
    max_bytes: int,
) -> tuple[str, bytes, str]:
    """Build one immutable submission from one or more uploaded files.

    Multiple files are wrapped in an uncompressed ZIP so the existing bounded
    intake path, Artifact tree, and audit chain remain the single analysis path.
    Upload names are reduced to safe basenames and made unique deterministically.
    """
    if not uploads:
        raise HTTPException(status_code=422, detail="at least one sample file is required")
    contents: list[tuple[str, bytes]] = []
    total = 0
    used: set[str] = set()
    for index, upload in enumerate(uploads, 1):
        name = Path((upload.filename or f"sample-{index}.bin").replace("\\", "/")).name
        if not name or name in {".", ".."}:
            name = f"sample-{index}.bin"
        stem = Path(name).stem or f"sample-{index}"
        suffix = Path(name).suffix
        candidate = name
        duplicate = 2
        while candidate in used:
            candidate = f"{stem}-{duplicate}{suffix}"
            duplicate += 1
        used.add(candidate)
        content = upload.file.read(max_bytes - total + 1)
        total += len(content)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail="combined uploaded sample files exceed the configured size limit",
            )
        contents.append((candidate, content))
    if len(contents) == 1:
        filename, content = contents[0]
        source_kind = "zip" if zipfile.is_zipfile(io.BytesIO(content)) else "file"
        return filename, content, source_kind
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in contents:
            archive.writestr(name, content)
    return "batch-submission.zip", output.getvalue(), "zip"


def _enable_stack_dump_on_signal() -> None:
    """Let an operator dump every Python thread's stack without ptrace or a restart.

    Why this exists. A run stalled at 7,332 evidence rows with one API thread in state `R` burning
    100% CPU and the GIL held for minutes, so nothing else in the process - including the HTTP event
    loop - could make progress. Diagnosing it the normal way was impossible in this deployment:

      * `py-spy` needs `CAP_SYS_PTRACE`, which the API container does not carry (`Permission denied`
        on `process_vm_readv`), and adding it means recreating the container, which kills the very run
        being profiled;
      * `/proc/1/task/*/stat` showed WHICH thread was hot but not what it was executing, and the
        thread's `wchan` was `0`, i.e. running in userspace;
      * a throwaway profiler container could not be pulled because this host has no Docker Hub egress.

    `faulthandler` needs no privileges at all: it is stdlib, it installs a signal handler, and on that
    signal it writes the traceback of EVERY thread to stderr, which the container log already keeps.
    That turns "one thread is spinning somewhere in 250k lines of code" into a named file and line.

    `SIGUSR1` is used rather than `SIGABRT` because aborting the process would destroy the run; the
    dump is additive. Enable with `THREAT_STACK_DUMP=1` (or leave it off and lose nothing - the cost
    when enabled is one signal handler).

        docker kill -s USR1 threat-report-agent-api-1
        docker logs threat-report-agent-api-1 --tail 200
    """
    import faulthandler  # noqa: PLC0415 - only needed when the operator opts in
    import signal  # noqa: PLC0415

    if str(os.getenv("THREAT_STACK_DUMP", "")).strip().casefold() not in {"1", "true", "yes", "on"}:
        return
    try:
        faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)
    except (AttributeError, ValueError, OSError):
        # A platform without SIGUSR1 (Windows) loses the facility, not the service.
        return
    logging.getLogger("threat_report_agent.operational").info(
        "stack dump armed: send SIGUSR1 to dump all thread stacks to stderr"
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or Settings.from_environment()
    _enable_stack_dump_on_signal()
    database = Database(app_settings.database_url)
    content_store = (
        S3ContentStore(
            app_settings.object_store_endpoint,
            app_settings.object_store_bucket,
            app_settings.object_store_access_key,
            app_settings.object_store_secret_key,
            audit_bucket=app_settings.audit_seal_bucket or None,
            audit_object_lock_mode=app_settings.audit_object_lock_mode,
            audit_object_lock_days=app_settings.audit_object_lock_days,
        )
        if app_settings.content_store_backend == "s3"
        else LocalContentStore(app_settings.content_store_path)
    )
    analysis_service = AnalysisService(app_settings, database, content_store)
    tracer = configure_observability("threat-report-agent")
    operational_logger = logging.getLogger("threat_report_agent.operational")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        database.create_schema()
        analysis_service.reload_model_configuration()
        # Analysis runs as in-process BackgroundTasks, so a restart silently ends
        # any run that was in flight and leaves its row RUNNING forever.  At this
        # point we are by definition the only process and own no in-flight work,
        # so every RUNNING/FINALIZING row is orphaned.  Fail them through the
        # normal failure contract; the retry machinery then decides what may run
        # again.  Without this the workbench waits on a session that can never
        # complete.
        try:
            reconciled = analysis_service.reconcile_orphaned_analysis_runs()
        except Exception:  # noqa: BLE001 - startup must not be blocked by this
            operational_logger.exception("orphaned analysis run reconciliation failed")
        else:
            if reconciled:
                operational_logger.warning(
                    "reconciled orphaned analysis runs",
                    extra={"task_ids": reconciled},
                )
        try:
            yield
        finally:
            # Release pooled SQLite/PostgreSQL connections when the app is
            # stopped. This is required for Windows temporary-database tests
            # and prevents stale handles during worker/API restarts.
            # ``sqlite://`` uses StaticPool and an in-memory database; disposing
            # that engine would erase its schema while a test may still reuse
            # the service object after TestClient exits.
            database_name = str(database.engine.url.database or "")
            if database.engine.dialect.name != "sqlite" or database_name not in {"", ":memory:"}:
                database.engine.dispose()

    app = FastAPI(
        title="Threat Report Agent",
        version="0.1.0",
        description="Evidence-backed static malware analysis control plane.",
        lifespan=lifespan,
    )

    @app.get("/internal/thread-stacks", tags=["internal"])
    def internal_thread_stacks(samples: int = 1) -> dict[str, object]:
        """Live Python stacks for every thread, for runaway-loop diagnosis.

        Added because a real sample drove the API to 99.9% CPU on one pure-Python
        thread while the database received no writes for many minutes, and there
        was no way to see where the time went: no debugger, no profiler, and
        ``py-spy`` cannot read ``/proc/1/root`` in this deployment.  Sampling the
        running process is the only diagnostic that does not require guessing from
        table counts, and it is reusable for every future "it hangs" report.

        Read-only and stdlib-only (``sys._current_frames``), but it exposes source
        paths and line numbers, so callers must pass the same permission gate as
        other diagnostic surfaces.

        Pass ``samples`` > 1 to aggregate: each sample attributes one hit to every
        frame in the stack, so the deepest frame with a large count is where the
        time actually goes.  That is what turns "it hangs" into a line number.
        """

        def collect() -> list[dict[str, object]]:
            frames = sys._current_frames()
            snapshot = []
            for thread in threading.enumerate():
                frame = frames.get(thread.ident)
                stack = (
                    [
                        f"{item.filename}:{item.lineno} in {item.name}"
                        for item in traceback.extract_stack(frame)
                    ]
                    if frame is not None
                    else []
                )
                snapshot.append(
                    {
                        "name": thread.name,
                        "ident": thread.ident,
                        "daemon": thread.daemon,
                        "alive": thread.is_alive(),
                        "depth": len(stack),
                        "stack": stack[-40:],
                    }
                )
            return snapshot

        import collections

        totals: collections.Counter[str] = collections.Counter()
        busiest: dict[str, object] = {}
        # Frames belonging to this endpoint and to threads parked in a long-poll
        # wait are noise: the first version of this probe reported its own
        # `collect()` as a top frame and `workbench_wait_for_analysis_update` as the
        # hottest function, which is the request that is *waiting*, not working.
        ignored_paths = ("/main.py", "/starlette/", "/anyio/", "/uvicorn/")
        ignored_names = {"collect", "internal_thread_stacks", "workbench_wait_for_analysis_update"}
        for _ in range(max(1, min(samples, 200))):
            for thread in collect():
                # Only worker threads executing Python can be in a compute loop;
                # the event loop's idle poll would otherwise dominate the counts.
                if thread["name"] in {"MainThread"} or not thread["stack"]:
                    continue
                frames = [
                    frame
                    for frame in thread["stack"]
                    if not any(path in frame for path in ignored_paths)
                    and frame.rsplit(" in ", 1)[-1] not in ignored_names
                ]
                if frames:
                    totals[frames[-1]] += 1
                    busiest = thread
            if samples > 1:
                time.sleep(0.01)
        return {
            "threads": collect(),
            "samples": samples,
            "hottest_frame": totals.most_common(20),
            "busiest_thread": busiest,
        }


    # The product workbench is served by DSH on port 3080 and uses the
    # same bounded backend API for upload and evidence projections. Keep the
    # allow-list explicit; arbitrary origins must not gain access to cases.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:3080",
            "http://localhost:3080",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        # Session identity is injected by the DSH host and is required on
        # every task/artifact projection request.  It must be explicitly
        # allowed here because the workbench is served from port 3080 while
        # the API listens on port 8000.
        allow_headers=[
            "Accept",
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-DSH-Session-ID",
        ],
    )
    app.state.settings = app_settings
    app.state.database = database
    app.state.analysis_service = analysis_service
    app.state.auth_adapter = AuthAdapter(
        environment=app_settings.environment,
        allow_demo=app_settings.allow_demo_auth,
        jwt_secret=app_settings.auth_jwt_secret,
        jwt_issuer=app_settings.auth_jwt_issuer,
        jwt_audience=app_settings.auth_jwt_audience,
        jwks_url=app_settings.auth_jwks_url,
    )
    #: The served workbench assets live in `assets/`, NOT in `static/`: plan 7.7 makes `static/` the
    #: static-recovery PACKAGE, and `packages.find` has no excludes, so an asset directory named `static`
    #: could not become a package without changing published artefacts. The MOUNT URL stays `/static`, so
    #: no client sees a difference between the directory name and the URL.
    asset_path = Path(__file__).parent / "assets"
    app.mount("/static", StaticFiles(directory=asset_path, check_dir=False), name="static")

    @app.middleware("http")
    async def observe_request(request: Request, call_next):
        started = time.perf_counter()
        with tracer.start_as_current_span(f"{request.method} {request.url.path}") as span:
            span_context = span.get_span_context()
            trace_id = f"{span_context.trace_id:032x}"
            request.state.trace_id = trace_id
            response = await call_next(request)
            route = request.scope.get("route")
            route_path = getattr(route, "path", request.url.path)
            duration = time.perf_counter() - started
            HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
            HTTP_DURATION.labels(request.method, route_path).observe(duration)
            response.headers["X-Trace-ID"] = trace_id
            operational_logger.info(
                "http.request.completed",
                extra={
                    "operational_fields": {
                        "method": request.method,
                        "route": route_path,
                        "status": response.status_code,
                        "duration_seconds": round(duration, 6),
                        "trace_id": trace_id,
                    }
                },
            )
            return response

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(asset_path / "index.html")

    @app.get("/healthz", tags=["system"])
    def healthz() -> dict[str, object]:
        runtime_settings = analysis_service.settings
        return {
            "status": "ok",
            "environment": runtime_settings.environment,
            "capabilities": {
                "deterministic_static_analysis": True,
                "all_static_modules": True,
                "report_formats": ["markdown", "docx", "pdf", "json"],
                "primary_model_configured": runtime_settings.primary_model.configured,
                "fallback_model_configured": runtime_settings.fallback_model.configured,
                "configured_model_families": [
                    family
                    for family, provider in (
                        (model_provider_family(runtime_settings.primary_model), runtime_settings.primary_model),
                        (model_provider_family(runtime_settings.fallback_model), runtime_settings.fallback_model),
                    )
                    if provider.configured
                ],
                "model_provider_contracts": supported_provider_contracts(),
                "model_context_max_bytes": runtime_settings.model_context_max_bytes,
                "model_call_timeout_s": runtime_settings.model_timeout_s,
                "model_call_max_tokens": runtime_settings.model_max_tokens,
                "agent_mode": (
                    "model_agent_with_deterministic_fallback"
                    if runtime_settings.model_calls_enabled
                    and (
                        runtime_settings.primary_model.configured
                        or runtime_settings.fallback_model.configured
                    )
                    else (
                        "model_agent_unconfigured_fallback"
                        if runtime_settings.model_calls_enabled
                        else "deterministic_static_agent"
                    )
                ),
                "ghidra_home_configured": bool(runtime_settings.ghidra_home),
            },
        }

    @app.get("/readyz", tags=["system"])
    def readyz() -> Response:
        """Report whether the API can serve analysis requests.

        Liveness is intentionally separate from readiness: a running process
        with an unavailable database must not receive uploads.  The probe is
        bounded to a single local ``SELECT 1`` and never touches sample data.
        """
        checks: dict[str, str] = {}
        try:
            with analysis_service.database.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:  # pragma: no cover - exercised with injected DB failures
            checks["database"] = type(exc).__name__
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "checks": checks},
            )

        return JSONResponse(status_code=200, content={"status": "ready", "checks": checks})

    @app.get("/metrics", tags=["system"])
    def metrics() -> Response:
        payload, media_type = metrics_payload()
        return Response(payload, media_type=media_type)

    @app.get("/api/v1/meta", tags=["system"])
    def meta() -> dict[str, object]:
        policy = analysis_service.policy
        return {
            "analysis_modules": [
                "intake",
                "static_triage",
                "decryption",
                "loader",
                "c2_network",
                "anti_analysis",
                "attribution",
            ],
            "report_modules": list(REPORT_MODULES),
            "preset_catalog": {
                "digest": policy.catalog_digest,
                "presets": [preset.model_dump(mode="json") for preset in policy.list_presets()],
            },
            "analysis_policy": {
                "sample_execution": False,
                "network_contact": False,
                "evaluation_baseline_in_context": False,
                "report_selection_changes_analysis": False,
            },
            "input_channels": [
                {"id": "task_request", "trust_zone": "control"},
                {"id": "sample_package", "trust_zone": "untrusted_sample"},
                {"id": "background_context", "trust_zone": "untrusted_background"},
                {"id": "knowledge_snapshot", "trust_zone": "versioned_knowledge"},
            ],
        }

    # Stable DSH-facing domain contract.  These routes intentionally expose
    # projections and capability metadata rather than database/Temporal
    # handles, allowing the Workbench to evolve out-of-tree.
    @app.get("/api/v1/workbench/capabilities/static-actions", tags=["workbench"])
    def workbench_capabilities(request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        return _service(request).workbench_capabilities()

    @app.get("/api/v1/workbench/analysis-planner-model", tags=["workbench", "model"])
    def workbench_analysis_planner_model(request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        return _service(request).workbench_analysis_planner_model_view()

    @app.get(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis-context",
        tags=["workbench", "context"],
    )
    def workbench_analysis_context(dsh_session_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_analysis_context(dsh_session_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/workbench/sessions/{dsh_session_id}/artifacts",
        tags=["workbench", "artifacts"],
    )
    def workbench_session_artifacts(dsh_session_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_session_artifacts(dsh_session_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/workbench/sessions/{dsh_session_id}/workspace-artifacts",
        tags=["workbench", "artifacts"],
    )
    def list_workbench_workspace_artifacts(
        dsh_session_id: str, request: Request, relative_dir: str = ".", limit: int = 256
    ) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_list_workspace_artifacts(
                dsh_session_id, relative_dir=relative_dir, limit=limit
            )
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/workspace-artifacts/import",
        status_code=201,
        tags=["workbench", "artifacts"],
    )
    def import_workbench_workspace_artifact(
        dsh_session_id: str,
        payload: WorkspaceArtifactImportRequest,
        request: Request,
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            return _service(request).workbench_import_workspace_artifact(
                dsh_session_id,
                relative_path=payload.relative_path,
                case_id=payload.case_id,
                workspace_id=payload.workspace_id,
                actor=principal.subject,
            )
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/artifacts",
        status_code=201,
        tags=["workbench", "artifacts"],
    )
    def attach_workbench_artifacts(
        dsh_session_id: str,
        request: Request,
        sample: Annotated[list[UploadFile], File()],
        case_id: Annotated[str | None, Form()] = None,
        workspace_id: Annotated[str | None, Form()] = None,
    ) -> dict[str, object]:
        require_permission(request, "task:submit")
        settings_for_request: Settings = request.app.state.settings
        if not sample:
            raise HTTPException(status_code=422, detail="at least one artifact is required")
        total = 0
        files: list[tuple[str, bytes]] = []
        try:
            for upload in sample:
                content = upload.file.read(settings_for_request.max_sample_bytes - total + 1)
                total += len(content)
                if total > settings_for_request.max_sample_bytes:
                    raise HTTPException(status_code=413, detail="uploaded artifacts exceed configured size limit")
                files.append((upload.filename or "sample.bin", content))
            result = _service(request).attach_session_artifacts(
                dsh_session_id,
                files,
                workspace_id=workspace_id,
                case_id=case_id,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # Keep the context projection available both as the response body
        # (legacy Workbench clients) and under an explicit envelope (vNext
        # clients). Upload remains Artifact-only; no Task is created here.
        return {"context": result, **result}

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/start",
        status_code=202,
        tags=["workbench", "analysis"],
    )
    def start_workbench_analysis(
        dsh_session_id: str,
        payload: WorkbenchStartAnalysisRequest,
        request: Request,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            result = _service(request).workbench_start_static_analysis(
                dsh_session_id,
                artifact_id=payload.artifact_id,
                selected_modules=payload.selected_modules,
                actor=principal.subject,
            )
            if result.get("created") and result.get("task_id"):
                background_tasks.add_task(
                    _service(request).execute_submission_task,
                    task_id=str(result["task_id"]),
                    actor=principal.subject,
                )
            return result
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/intent",
        tags=["workbench", "analysis"],
    )
    def dispatch_workbench_analysis_intent(
        dsh_session_id: str,
        payload: WorkbenchAnalysisIntentRequest,
        request: Request,
        background_tasks: BackgroundTasks,
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            result = _service(request).workbench_dispatch_analysis_intent(
                dsh_session_id,
                question=payload.question,
                actor=principal.subject,
            )
            if result.get("created") and result.get("task_id"):
                background_tasks.add_task(
                    _service(request).execute_submission_task,
                    task_id=str(result["task_id"]),
                    actor=principal.subject,
                )
            return result
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except ValueError as exc:
            status = 409 if str(exc).startswith("NO_ACTIVE_ANALYSIS") else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.get(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/status",
        tags=["workbench", "analysis"],
    )
    def workbench_analysis_status(dsh_session_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_analysis_status(dsh_session_id)["context"]
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/wait",
        tags=["workbench", "analysis"],
    )
    def wait_workbench_analysis(
        dsh_session_id: str,
        request: Request,
        after_seq: int = 0,
        timeout_seconds: int = 180,
    ) -> dict[str, object]:
        """Wait for a state/event change without replaying full task context."""
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_wait_for_analysis_update(
                dsh_session_id, after_seq=after_seq, timeout_seconds=timeout_seconds
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/actions",
        status_code=202,
        tags=["workbench", "investigation"],
    )
    def submit_session_workbench_action(
        dsh_session_id: str,
        payload: WorkbenchActionRequest,
        request: Request,
    ) -> dict[str, object]:
        """Submit one policy-gated static action for the bound session task."""
        require_permission(request, "task:submit")
        try:
            return _service(request).workbench_submit_session_action(
                dsh_session_id, payload.model_dump(mode="json")
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except ValueError as exc:
            status = 409 if str(exc).startswith("NO_ACTIVE_ANALYSIS") else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/evidence/query",
        tags=["workbench", "evidence"],
    )
    def query_session_workbench_evidence(
        dsh_session_id: str,
        payload: WorkbenchCurrentEvidenceRequest,
        request: Request,
    ) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).workbench_query_current_evidence(
                dsh_session_id,
                kind=payload.kind,
                module=payload.module,
                artifact_id=payload.artifact_id,
                limit=payload.limit,
                filter_text=payload.filter_text,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/bind",
        tags=["workbench", "analysis"],
    )
    def bind_workbench_analysis(
        dsh_session_id: str,
        payload: WorkbenchBindAnalysisRequest,
        request: Request,
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            return _service(request).workbench_bind_existing_analysis(
                dsh_session_id, payload.task_id, actor=principal.subject
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/analysis/unbind",
        tags=["workbench", "analysis"],
    )
    def unbind_workbench_analysis(
        dsh_session_id: str,
        request: Request,
        payload: SessionAnalysisUnbindRequest | None = Body(default=None),
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            return _service(request).workbench_unbind_analysis(
                dsh_session_id,
                actor=principal.subject,
                discard_staged=bool(payload and payload.discard_staged),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/report/analyst-draft",
        status_code=201,
        tags=["workbench", "reports"],
    )
    def workbench_submit_analyst_draft(
        dsh_session_id: str,
        request: Request,
        payload: ReportEditRequest = Body(),
    ) -> dict[str, object]:
        """Agent-authored narrative for the session's bound task.

        Session-scoped because the DSH client only permits ``/api/v1/workbench/``
        paths.  The narrative is admitted only through 报告合成门 (ADR-0036); a
        422 lists the violations so the agent can revise.
        """
        principal = require_permission(request, "report:edit")
        try:
            return _service(request).workbench_submit_analyst_draft(
                dsh_session_id,
                payload.markdown,
                actor=principal.subject,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/workbench/sessions/{dsh_session_id}/report/file",
        status_code=201,
        tags=["workbench", "reports"],
    )
    def workbench_write_report_file(
        dsh_session_id: str,
        request: Request,
        payload: WorkbenchReportFileRequest,
    ) -> dict[str, object]:
        """Write the agent's report document into the deployment's report root.

        The analyst deliverable is a file; this is the one bounded write the
        product exposes, because the host bundle disables DSH's own file tools
        and they could not be re-enabled from a preset.
        """
        principal = require_permission(request, "report:edit")
        try:
            return _service(request).workbench_write_report_file(
                dsh_session_id,
                filename=payload.filename,
                markdown=payload.markdown,
                actor=principal.subject,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/workbench/cases/{case_id}", tags=["workbench", "cases"])
    def workbench_case(case_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "case:read")
        try:
            return _service(request).workbench_case(case_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/artifacts/{artifact_id}", tags=["workbench", "artifacts"])
    def workbench_artifact(artifact_id: str, request: Request) -> dict[str, object]:
        principal = require_permission(request, "task:read")
        try:
            view = _service(request).workbench_artifact(artifact_id)
            session_id = request.headers.get("X-DSH-Session-ID", "").strip()
            if session_id:
                task_id = str(view.get("task_id") or "")
                if task_id:
                    _require_task_scope(request, task_id, "task:read")
                elif principal.roles.isdisjoint({"admin", "auditor"}):
                    raise HTTPException(status_code=403, detail={"code": "CONTEXT_MISMATCH", "message": "artifact is not attached to a task"})
            elif principal.roles.isdisjoint({"admin", "auditor"}):
                raise HTTPException(status_code=403, detail={"code": "CONTEXT_MISMATCH", "message": "X-DSH-Session-ID is required for artifact access"})
            return view
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}", tags=["workbench"])
    def workbench_task(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            return _service(request).workbench_domain_view(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/session", tags=["workbench"])
    def workbench_session(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            return {"link": _service(request).workbench_session_link(task_id)}
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.post("/api/v1/workbench/tasks/{task_id}/session", status_code=201, tags=["workbench"])
    def link_workbench_session(
        task_id: str, payload: WorkbenchSessionLinkRequest, request: Request
    ) -> dict[str, object]:
        require_permission(request, "task:submit")
        try:
            return _service(request).workbench_link_session(
                task_id, payload.dsh_session_id, profile=payload.profile
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/workbench/sessions/{dsh_session_id}/task", tags=["workbench"])
    def workbench_session_task(dsh_session_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            context = _service(request).workbench_analysis_context_v3(dsh_session_id)
            task_id = context.get("active_task_id")
            if not task_id:
                return {"link": None, "state": context["state"], "code": context.get("code")}
            link = _service(request).workbench_session_link(str(task_id))
            return {"link": link or {"task_id": task_id, "dsh_session_id": dsh_session_id}}
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/events", tags=["workbench"])
    def workbench_task_events(
        task_id: str, request: Request, after_seq: int = 0, limit: int = 500
    ) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            return _service(request).workbench_events(
                task_id, after_seq=after_seq, limit=limit
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/workbench/evidence/query", tags=["workbench", "evidence"])
    def workbench_evidence_query(
        payload: EvidenceQueryRequest, request: Request
    ) -> dict[str, object]:
        _require_task_scope(request, payload.task_id, "task:read")
        try:
            return _service(request).workbench_query_evidence(
                task_id=payload.task_id,
                kind=payload.kind,
                module=payload.module,
                artifact_id=payload.artifact_id,
                limit=payload.limit,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/threads", tags=["workbench", "investigation"])
    def workbench_threads(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            view = _service(request).workbench_domain_view(task_id)
            return {"schema_version": 1, "task_id": task_id, "items": view["threads"]}
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/hypotheses", tags=["workbench", "investigation"])
    def workbench_hypotheses(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            view = _service(request).workbench_domain_view(task_id)
            return {"schema_version": 1, "task_id": task_id, "items": view["hypotheses"]}
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/actions", tags=["workbench", "investigation"])
    def workbench_actions(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            view = _service(request).workbench_domain_view(task_id)
            return {"schema_version": 1, "task_id": task_id, "items": view["actions"]}
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/actions/{action_id}", tags=["workbench", "investigation"])
    def workbench_action(action_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            value = _service(request).workbench_action(action_id)
            _require_task_scope(request, str(value["task_id"]), "task:read")
            return value
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/actions/{action_id}", tags=["workbench", "investigation"])
    def workbench_task_action(task_id: str, action_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:read")
        try:
            return _service(request).workbench_action_for_task(task_id, action_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/threads/{thread_id}", tags=["workbench", "investigation"])
    def workbench_thread(thread_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            value = _service(request).workbench_thread(thread_id)
            _require_task_scope(request, str(value["task_id"]), "task:read")
            return value
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/workbench/threads/{thread_id}/context", tags=["workbench", "investigation"])
    def workbench_thread_context(thread_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            thread = _service(request).workbench_thread(thread_id)
            _require_task_scope(request, str(thread["task_id"]), "task:read")
            return {
                "schema_version": 1,
                "thread_id": thread_id,
                "question": thread["question"],
                "state": thread["state"],
                "hypotheses": thread["hypotheses"],
                "recent_actions": thread["actions"][-16:],
                "evidence_ids": thread["evidence_ids"][:128],
            }
        except LookupError as exc:
            raise _not_found(exc) from exc

    for _collection_name in ("mechanisms", "claims", "relations", "sample-timeline"):
        _collection_key = "sample_timeline" if _collection_name == "sample-timeline" else _collection_name

        def _collection_endpoint(task_id: str, request: Request, _key: str = _collection_key) -> dict[str, object]:
            _require_task_scope(request, task_id, "task:read")
            try:
                return _service(request).workbench_collection(task_id, _key)
            except LookupError as exc:
                raise _not_found(exc) from exc

        app.add_api_route(
            f"/api/v1/workbench/tasks/{{task_id}}/{_collection_name}",
            _collection_endpoint,
            methods=["GET"],
            tags=["workbench", "analysis"],
            name=f"workbench_{_collection_key}",
        )

    @app.post("/api/v1/workbench/tasks/{task_id}/actions", status_code=202, tags=["workbench", "investigation"])
    def workbench_submit_action(
        task_id: str, payload: WorkbenchActionRequest, request: Request
    ) -> dict[str, object]:
        _require_task_scope(request, task_id, "task:submit")
        try:
            return _service(request).workbench_submit_action(
                task_id,
                payload.model_dump(mode="json"),
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/workbench/tasks/{task_id}/report", tags=["workbench", "reports"])
    def workbench_report(task_id: str, request: Request) -> dict[str, object]:
        _require_task_scope(request, task_id, "report:read")
        try:
            view = _service(request).workbench_domain_view(task_id)
            revision_id = view["report"]["revision_id"]
            return {
                "task_id": task_id,
                "revision": _service(request).get_report_revision(revision_id)
                if revision_id
                else None,
            }
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.post("/api/v1/workbench/model/complete", tags=["workbench", "model"])
    def workbench_model_complete(
        payload: WorkbenchModelRequest, request: Request
    ) -> dict[str, object]:
        """Route DSH model turns through the existing audited gateway."""
        require_permission(request, "model:invoke")
        try:
            return _service(request).workbench_model_complete(payload.model_dump(mode="json"))
        except ContextMismatchError as exc:
            raise HTTPException(status_code=403, detail={"code": exc.code, "message": str(exc)}) from exc
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            status = 409 if str(exc).startswith("NO_ACTIVE_ANALYSIS") else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    @app.get("/api/v1/model-config", tags=["model"])
    def model_config(request: Request) -> dict[str, object]:
        require_permission(request, "model:read")
        return _service(request).model_configuration_view()

    @app.put("/api/v1/model-config", tags=["model"])
    def update_model_config(
        payload: ModelConfigurationRequest,
        request: Request,
    ) -> dict[str, object]:
        principal = require_permission(request, "model:configure")
        body = payload.model_dump(exclude_none=False)
        for slot in ("primary", "fallback"):
            route = body[slot]
            api_key = getattr(payload, slot).api_key
            if api_key is not None:
                route["api_key"] = api_key.get_secret_value()
        try:
            return _service(request).update_model_configuration(body, actor=principal.subject)
        except ValueError as exc:
            message = str(exc)
            status = 409 if "revision conflict" in message else 422
            raise HTTPException(status_code=status, detail=message) from exc

    @app.get("/api/v1/cases", tags=["cases"])
    def list_cases(request: Request) -> list[dict[str, object]]:
        require_permission(request, "case:read")
        return _service(request).list_cases()

    @app.post("/api/v1/cases", status_code=201, tags=["cases"])
    def create_case(payload: CaseCreate, request: Request) -> dict[str, object]:
        principal = require_permission(request, "case:create")
        case = _service(request).create_case(payload.title, actor=principal.subject)
        return {
            "id": case.id,
            "title": case.title,
            "status": case.status,
            "created_at": case.created_at.isoformat(),
        }

    @app.post("/api/v1/cases/{case_id}/archive", tags=["cases", "retention"])
    def archive_case(
        case_id: str, payload: CaseArchiveRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "report:approve")
        try:
            return _service(request).archive_case(case_id, actor=principal.subject)
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/cases/{case_id}/retention-freeze", tags=["retention"])
    def set_retention_freeze(
        case_id: str, payload: RetentionFreezeRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "retention:freeze")
        try:
            return _service(request).set_retention_freeze(
                case_id,
                frozen=payload.frozen,
                actor=principal.subject,
                reason=payload.reason,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/retention/model-payload-expiry", tags=["retention"])
    def expire_model_payloads(
        payload: ModelPayloadExpiryRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "retention:execute")
        return {
            "disposed": _service(request).expire_model_payloads(
                now=payload.now, actor=principal.subject
            )
        }

    @app.post("/api/v1/audit/daily-seals", tags=["audit"])
    def seal_daily_audit(payload: DailyAuditSealRequest, request: Request) -> dict[str, object]:
        principal = require_permission(request, "audit:seal")
        try:
            created = _service(request).run_daily_audit_sealer(
                utc_day=payload.utc_day, actor=principal.subject
            )
            return {"utc_day": payload.utc_day.isoformat(), "created": created}
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/cases/{case_id}/evidence-purge-requests", status_code=201, tags=["retention"]
    )
    def request_evidence_purge(
        case_id: str, payload: EvidencePurgeRequestCreate, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "purge:request")
        try:
            return _service(request).request_evidence_purge(
                case_id,
                requested_by=principal.subject,
                reason=payload.reason,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/evidence-purge-requests/{request_id}/review", tags=["retention"])
    def review_evidence_purge(
        request_id: str, payload: EvidencePurgeReviewRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "purge:review")
        try:
            return _service(request).review_evidence_purge(
                request_id, reviewer=principal.subject, approve=payload.approve
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/evidence-purge-requests/{request_id}/execute", tags=["retention"])
    def execute_evidence_purge(
        request_id: str, payload: EvidencePurgeExecuteRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "purge:execute")
        try:
            return _service(request).execute_evidence_purge(request_id, admin=principal.subject)
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/cases/{case_id}/tasks", status_code=202, tags=["analysis"])
    def submit_analysis(
        case_id: str,
        background_tasks: BackgroundTasks,
        request: Request,
        sample: Annotated[list[UploadFile], File()],
        idempotency_key: Annotated[
            str | None,
            Header(alias="Idempotency-Key"),
        ] = None,
        background_context: Annotated[str, Form()] = "",
        background_source: Annotated[str, Form()] = "user_supplied",
        background_observed_at: Annotated[datetime | None, Form()] = None,
        background_confidence: Annotated[
            Literal["UNVERIFIED", "LOW", "MEDIUM", "HIGH"], Form()
        ] = "UNVERIFIED",
        background_human_confirmed: Annotated[bool, Form()] = False,
        selected_modules: Annotated[str, Form()] = "",
    ) -> dict[str, object]:
        require_permission(request, "task:submit")
        settings_for_request: Settings = request.app.state.settings
        filename, content, source_kind = _package_uploads(
            sample,
            max_bytes=settings_for_request.max_sample_bytes,
        )
        modules = _parse_modules(selected_modules)
        try:
            result, created = _service(request).create_submission_task(
                case_id=case_id,
                filename=filename,
                submitted_size=len(content),
                content=content,
                source_kind=source_kind,
                background_context=background_context,
                background_context_input=BackgroundContextInput(
                    content=background_context,
                    source=background_source,
                    **(
                        {"observed_at": background_observed_at}
                        if background_observed_at is not None
                        else {}
                    ),
                    confidence=background_confidence,
                    human_confirmed=background_human_confirmed,
                ),
                selected_modules=modules,
                idempotency_key=idempotency_key,
                trace_id=request.state.trace_id,
            )
            if created:
                background_tasks.add_task(
                    _service(request).execute_submission_task,
                    task_id=result.task_id,
                )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "case_id": result.case_id,
            "task_id": result.task_id,
            "lifecycle": result.lifecycle,
            "outcome": result.outcome,
            "report_revision_id": result.report_revision_id,
            "gate_id": result.gate_id,
        }

    @app.get("/api/v1/tasks/{task_id}", tags=["analysis"])
    def task_detail(task_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).task_view(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/tasks/{task_id}/status", tags=["analysis"])
    def task_status(task_id: str, request: Request) -> dict[str, object]:
        """Return bounded lifecycle counters for efficient client polling."""
        require_permission(request, "task:read")
        try:
            return _service(request).task_status(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.post("/api/v1/tasks/{task_id}/cancel", tags=["analysis"])
    def cancel_task(task_id: str, request: Request) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            return _service(request).cancel_task(task_id, actor=principal.subject)
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post(
        "/api/v1/tasks/{task_id}/tool-runs/{tool_run_id}/cancel",
        tags=["analysis"],
    )
    def cancel_tool_run(
        task_id: str,
        tool_run_id: str,
        request: Request,
    ) -> dict[str, object]:
        principal = require_permission(request, "task:submit")
        try:
            return _service(request).cancel_tool_run(
                task_id,
                tool_run_id,
                actor=principal.subject,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/gates/{gate_id}/decision", tags=["analysis"])
    def decide_gate(
        gate_id: str,
        payload: GateDecisionRequest,
        request: Request,
    ) -> dict[str, object]:
        require_permission(request, "gate:decide")
        try:
            return _service(request).decide_input_gate(
                gate_id,
                decision=payload.decision,
                archive_password=(
                    payload.archive_password.get_secret_value()
                    if payload.archive_password is not None
                    else None
                ),
                note=payload.note,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/tasks/{task_id}/audit", tags=["audit"])
    def task_audit(task_id: str, request: Request) -> list[dict[str, object]]:
        require_permission(request, "audit:read")
        try:
            return _service(request).list_audit_events(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/tasks/{task_id}/events", tags=["analysis"])
    def task_events(
        task_id: str,
        request: Request,
        after_sequence: int = 0,
    ) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            task = _service(request).task_view(task_id)
            events = [
                event
                for event in _service(request).list_audit_events(task_id)
                if int(event["chain_sequence"]) > after_sequence
            ]
        except LookupError as exc:
            raise _not_found(exc) from exc
        return {
            "task_id": task_id,
            "trace_id": task["trace_id"],
            "lifecycle": task["lifecycle"],
            "outcome": task["outcome"],
            "events": events,
            "next_sequence": (int(events[-1]["chain_sequence"]) if events else after_sequence),
        }

    @app.get("/api/v1/tasks/{task_id}/analysis-trace", tags=["analysis", "audit"])
    def task_analysis_trace(task_id: str, request: Request) -> dict[str, object]:
        """Return the safe system-level analysis process view.

        The endpoint intentionally omits prompts, raw model payloads, and
        private chain-of-thought while retaining evidence and validation links.
        """
        require_permission(request, "task:read")
        try:
            return _service(request).analysis_trace(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/tasks/{task_id}/audit/integrity", tags=["audit"])
    def task_audit_integrity(task_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "audit:read")
        try:
            return _service(request).audit_integrity(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/tasks/{task_id}/analysis-package", tags=["analysis"])
    def analysis_package(task_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).analysis_package(task_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.post("/api/v1/analysis-packages/replay", tags=["analysis"])
    def replay_analysis_package(
        payload: AnalysisPackageReplayRequest, request: Request
    ) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).replay_analysis_package(
                payload.package, selected_modules=payload.selected_modules
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/tasks/{task_id}/relations", status_code=201, tags=["analysis"])
    def create_relation(
        task_id: str,
        payload: RelationCreateRequest,
        request: Request,
    ) -> dict[str, object]:
        require_permission(request, "task:submit")
        try:
            return _service(request).add_component_relation(
                task_id=task_id,
                source_artifact_id=payload.source_artifact_id,
                target_artifact_id=payload.target_artifact_id,
                relation_type=payload.relation_type,
                evidence_id=payload.evidence_id,
                claim_id=payload.claim_id,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/evidence/{evidence_id}", tags=["evidence"])
    def evidence_detail(evidence_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "task:read")
        try:
            return _service(request).get_evidence(evidence_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.get("/api/v1/reports/{revision_id}", tags=["reports"])
    def report_detail(revision_id: str, request: Request) -> dict[str, object]:
        require_permission(request, "report:read")
        try:
            return _service(request).get_report_revision(revision_id)
        except LookupError as exc:
            raise _not_found(exc) from exc

    @app.post("/api/v1/tasks/{task_id}/reports", status_code=201, tags=["reports"])
    def recompose_report(
        task_id: str,
        payload: ReportModulesRequest,
        request: Request,
    ) -> dict[str, object]:
        principal = require_permission(request, "report:edit")
        try:
            return _service(request).recompose_report(
                task_id, payload.modules, actor=principal.subject
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/reports/{revision_id}/edits", status_code=201, tags=["reports"])
    def edit_report(
        revision_id: str,
        request: Request,
        payload: ReportEditRequest = Body(),
    ) -> dict[str, object]:
        principal = require_permission(request, "report:edit")
        try:
            return _service(request).edit_report(
                revision_id,
                payload.markdown,
                principal.subject,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/reports/{revision_id}/analyst-draft",
        status_code=201,
        tags=["reports"],
    )
    def submit_analyst_draft(
        revision_id: str,
        request: Request,
        payload: ReportEditRequest = Body(),
    ) -> dict[str, object]:
        """Agent-authored narrative, admitted only through 报告合成门 (ADR-0036).

        422 carries the gate violations, so the caller can see exactly which fact
        it introduced that the deterministic fragments do not contain.
        """
        principal = require_permission(request, "report:edit")
        try:
            return _service(request).submit_analyst_draft(
                revision_id,
                payload.markdown,
                actor=principal.subject,
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/reports/{revision_id}/approve", tags=["reports", "gates"])
    def approve_report(
        revision_id: str, payload: ReportApprovalRequest, request: Request
    ) -> dict[str, object]:
        principal = require_permission(request, "report:approve")
        try:
            return _service(request).approve_report(
                revision_id, actor=principal.subject, note=payload.note
            )
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/v1/reports/{revision_id}/publish", tags=["reports"])
    def publish_report(revision_id: str, request: Request) -> dict[str, object]:
        principal = require_permission(request, "report:publish")
        try:
            return _service(request).publish_report(revision_id, actor=principal.subject)
        except LookupError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/reports/{revision_id}/download", tags=["reports"])
    def download_report(
        revision_id: str,
        format: Literal["markdown", "docx", "pdf", "json"],
        request: Request,
    ) -> Response:
        require_permission(request, "report:read")
        try:
            revision = _service(request).get_report_revision(revision_id)
        except LookupError as exc:
            raise _not_found(exc) from exc
        filename = f"threat-report-{revision_id}"
        if format == "markdown":
            return Response(
                revision["markdown"],
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
            )
        if format == "docx":
            content = markdown_to_docx(str(revision["markdown"]))
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            suffix = "docx"
        elif format == "pdf":
            content = markdown_to_pdf(str(revision["markdown"]))
            media_type = "application/pdf"
            suffix = "pdf"
        else:
            return JSONResponse(
                revision["document"],
                headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
            )
        return Response(
            content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}.{suffix}"'},
        )

    return app


app = create_app()
