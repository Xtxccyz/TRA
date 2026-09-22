from __future__ import annotations

from dataclasses import dataclass
from os import getenv
from pathlib import Path


def _value(name: str, default: str = "") -> str:
    return getenv(name, default).strip()


def _boolean(name: str, default: bool = False) -> bool:
    value = _value(name, "true" if default else "false").lower()
    if value not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError(f"{name} must be a boolean")
    return value in {"true", "1", "yes"}


def _local_ghidra_home() -> str:
    candidate = (
        Path(__file__).resolve().parents[2] / ".tools" / "ghidra-12.1.2" / "ghidra_12.1.2_PUBLIC"
    )
    return str(candidate) if candidate.is_dir() else ""


def _local_java_home() -> str:
    """Find a bundled or system JDK suitable for the local Ghidra runner.

    The repository ships a pinned JDK for repeatable static analysis.  Looking
    only under ``Program Files`` made a clean workstation silently report
    Ghidra as unavailable even though the bundled runtime was present.
    """

    workspace_root = Path(__file__).resolve().parents[2]
    bundled_root = workspace_root / ".tools" / "jdk-21"
    bundled = sorted(
        (
            candidate
            for candidate in bundled_root.iterdir()
            if candidate.is_dir()
            and any((candidate / "bin" / executable).is_file() for executable in ("java.exe", "java"))
        ),
        key=str,
    ) if bundled_root.is_dir() else []
    if bundled:
        return str(bundled[-1])

    system_root = Path("C:/Program Files/Eclipse Adoptium")
    system = sorted(
        (
            candidate
            for candidate in system_root.glob("jdk-21*-hotspot")
            if candidate.is_dir()
            and any((candidate / "bin" / executable).is_file() for executable in ("java.exe", "java"))
        ),
        key=str,
    ) if system_root.is_dir() else []
    return str(system[-1]) if system else ""


@dataclass(frozen=True)
class ModelProviderSettings:
    provider: str
    base_url: str
    model: str
    api_key: str
    api_style: str = "openai"
    enabled: bool = True
    stream: bool = True
    supports_json_mode: bool = True
    temperature: float = 0.0
    top_p: float = 1.0
    disable_reasoning: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("model temperature must be between 0 and 2")
        if not 0.0 < self.top_p <= 1.0:
            raise ValueError("model top_p must be greater than 0 and at most 1")

    @property
    def configured(self) -> bool:
        return self.enabled and bool(self.base_url and self.model and self.api_key)

    @property
    def has_route(self) -> bool:
        """Return whether the user supplied any identity for this slot."""
        return bool(self.provider or self.base_url or self.model or self.api_key)


@dataclass(frozen=True)
class Settings:
    environment: str
    database_url: str
    object_store_endpoint: str
    object_store_bucket: str
    object_store_access_key: str
    object_store_secret_key: str
    content_store_backend: str
    content_store_path: str
    temporal_address: str
    ghidra_home: str
    java_home: str
    max_sample_files: int
    max_sample_bytes: int
    max_archive_depth: int
    primary_model: ModelProviderSettings
    fallback_model: ModelProviderSettings
    model_calls_enabled: bool = False
    model_context_max_bytes: int = 2_000_000
    model_timeout_s: float = 180.0
    model_max_tokens: int = 2048
    # One investigation round for one seed thread must be able to work through
    # the whole frontier the planner queued for it, not a page of it.  This is
    # the same degenerate-input guard as ``static_abstract_execution_max_steps``
    # and ``AnalysisService._MAX_GHIDRA_FUNCTIONS``: 65_536 is one investigation
    # action per function the Ghidra exporter can deliver, so a frontier the
    # rest of the pipeline is willing to produce is never truncated by a quota
    # here.  The queue only executes actions the planner actually queued, so a
    # large guard costs nothing on a small binary; the invocation-level action
    # budget (``investigation_task_max_actions``) remains the scheduling bound.
    investigation_max_steps: int = 65_536
    # How many static analyses may execute at the same time.
    #
    # Static analysis is CPU-bound and runs in-process, and nothing bounded this
    # before: on 2026-09-18 three tasks ran concurrently, each pinned a CPU, and
    # NONE reached a report revision - so the workbench appeared to answer every
    # new submission with whatever sample had last finished.  Default 1 keeps the
    # machine honest; a larger value trades latency for throughput only when the
    # host genuinely has spare cores.
    max_concurrent_analyses: int = 1
    # Loop protection for ``InvestigationLoopDriver.run_until_converged`` rather
    # than a depth quota: a bounded round count keeps a self-replenishing
    # frontier from looping forever, while the per-round step budget above is
    # what bounds real work.  Each round re-plans from accumulated evidence.
    investigation_max_rounds: int = 4
    # A task-wide cap prevents one artifact with many seed clusters from
    # multiplying the per-thread round budget into an unbounded action storm.
    # The cap is shared by seed threads within one invocation, not the task
    # lifetime. Durable action keys prevent replay on subsequent invocations.
    # The environment can raise it: the validation bound is a degenerate-input
    # guard, not a ceiling an operator cannot cross.
    investigation_task_max_actions: int = 64
    audit_seal_secret: str = ""
    gate_secret_key: str = ""
    model_config_secret_key: str = ""
    tool_execution_mode: str = "local"
    tool_task_queue: str = "static-ghidra"
    tool_allowed_tools: tuple[str, ...] = ()
    control_task_queue: str = "static-control"
    intake_task_queue: str = "static-intake"
    parser_task_queue: str = "static-parser"
    script_task_queue: str = "static-script"
    document_task_queue: str = "static-document"
    ghidra_task_queue: str = "static-ghidra"
    emu_task_queue: str = "static-emu"
    allow_demo_auth: bool = True
    model_payload_retention_days: int = 180
    auth_jwt_secret: str = ""
    auth_jwt_issuer: str = ""
    auth_jwt_audience: str = ""
    auth_jwks_url: str = ""
    audit_seal_bucket: str = ""
    audit_object_lock_mode: str = "COMPLIANCE"
    audit_object_lock_days: int = 3650
    # Optional host-side workspace root used by the static-only workspace
    # import tools. An empty value deliberately disables host path access.
    workbench_workspace_root: str = ""
    simulation_profile: str = "static-only"
    simulation_worker_identity: str = ""
    simulation_worker_image_digest: str = ""
    simulation_allowed_simulators: tuple[str, ...] = ()
    simulation_allow_local_process: bool = False
    simulation_qiling_rootfs: str = ""
    simulation_timeout_seconds: int = 8
    # MEASURED: the previous default of 100_000 is too small to drive VB6 runtime semantics to
    # completion. Starting Speakeasy at the recovered literal-table constructor executes **1,031
    # modelled API calls** (1,028 of them `__vbaStrCopy`) and yields 256 API observations - and that run
    # needed a budget of 900_000. At 100_000 the emulation was cut off after a single `__vbaChkstk`
    # (`modelled_calls=1`, `elapsed_ms=24` versus 351 for the full run), because the candidate projection
    # is worthless if the budget cannot reach the point where the sample does real work.
    #
    # The value is not unbounded: validation below still caps it at 5_000_000, and the cap exists for a
    # genuine reason (a crafted image must not occupy a worker indefinitely).
    simulation_instruction_budget: int = 900_000
    simulation_max_output_bytes: int = 65536
    simulation_max_input_bytes: int = 4_194_304
    # Static abstract execution walks the instruction and call records a static
    # tool already exported; it never loads or runs the sample.  The bound is a
    # degenerate-input guard for a crafted image, not an analysis quota: the
    # Ghidra exporter stops one function at 10_000 instruction rows
    # (ExportStaticFacts.java), so every function the pipeline can deliver is
    # analysed in full.  Distinct from investigation_max_steps, which bounds
    # interactive planning rather than static code analysis.
    static_abstract_execution_max_steps: int = 65_536
    # Workbench investigation uses the DSH conversation model (Settings → 模型).
    # Backend analysis-planner-agent is not a second user-facing route.
    dsh_conversation_owns_planning: bool = True

    def __post_init__(self) -> None:
        if self.environment.lower() == "production" and self.tool_execution_mode != "temporal":
            raise ValueError("production tool execution must use temporal Worker isolation")
        if (
            self.environment.lower() == "production"
            and not self.auth_jwt_secret
            and not self.auth_jwks_url
        ):
            raise ValueError("AUTH_JWT_SECRET or AUTH_JWKS_URL is required in production")
        if self.environment.lower() == "production" and not self.gate_secret_key:
            raise ValueError("GATE_SECRET_KEY is required in production")
        if self.environment.lower() not in {"test", "development", "demo"} and self.allow_demo_auth:
            raise ValueError(
                "demo authentication must be disabled outside non-production environments"
            )
        if self.audit_object_lock_mode.upper() not in {"GOVERNANCE", "COMPLIANCE"}:
            raise ValueError("audit object lock mode must be GOVERNANCE or COMPLIANCE")
        if self.audit_object_lock_days < 1:
            raise ValueError("audit object lock days must be positive")
        if self.model_context_max_bytes < 1024:
            raise ValueError("model context budget must be at least 1024 bytes")
        if self.model_timeout_s < 5 or self.model_timeout_s > 600:
            raise ValueError("model timeout must be between 5 and 600 seconds")
        if self.model_max_tokens < 256 or self.model_max_tokens > 32768:
            raise ValueError("model max tokens must be between 256 and 32768")
        # Deliberately generous on both ends, mirroring
        # ``static_abstract_execution_max_steps``: the lower bound only rejects a
        # nonsensical zero (an operator may pin a tiny budget for a test) and the
        # upper bound only rejects a value that could not be walked.  The former
        # 4..128 window was an analysis quota, not a guard: a 551KB PE with 703
        # recovered functions cannot close its deep contract inside 128 actions,
        # and no environment value could raise it.
        if self.investigation_max_steps < 1 or self.investigation_max_steps > 1_000_000:
            raise ValueError("investigation max steps is out of range")
        # Loop protection, not a depth quota (see ``investigation_max_rounds``).
        if self.investigation_max_rounds < 1 or self.investigation_max_rounds > 8:
            raise ValueError("investigation max rounds must be between 1 and 8")
        # Same degenerate-input guard as above: an operator must be able to raise
        # the per-invocation scheduling bound from the environment.
        if (
            self.investigation_task_max_actions < 1
            or self.investigation_task_max_actions > 1_000_000
        ):
            raise ValueError("investigation task max actions is out of range")
        profile = self.simulation_profile.strip().casefold()
        if profile not in {"static-only", "static-first-controlled-emulation", "controlled-worker-v1"}:
            raise ValueError("simulation profile is not a known capability image")
        if self.simulation_timeout_seconds < 1 or self.simulation_timeout_seconds > 60:
            raise ValueError("simulation timeout must be between 1 and 60 seconds")
        if self.simulation_instruction_budget < 1 or self.simulation_instruction_budget > 5_000_000:
            raise ValueError("simulation instruction budget is out of range")
        # Deliberately generous on both ends: the lower bound only rejects a
        # nonsensical zero (an operator may pin a tiny budget for a test) and
        # the upper bound only rejects a value that could not be walked.
        if (
            self.static_abstract_execution_max_steps < 1
            or self.static_abstract_execution_max_steps > 1_000_000
        ):
            raise ValueError("static abstract execution max steps is out of range")
        if (
            self.environment.lower() == "production"
            and profile == "static-first-controlled-emulation"
            and self.simulation_allow_local_process
        ):
            raise ValueError("production must not enable local-process emulation")

    def task_queue_for(self, tool_name: str) -> str:
        return {
            "python-zipfile-safe-reader": self.intake_task_queue,
            "script-parser": self.script_task_queue,
            "document-carrier-parser": self.document_task_queue,
            "ghidra-headless": self.ghidra_task_queue,
            "controlled-emulator": self.emu_task_queue,
        }.get(tool_name, self.parser_task_queue)

    @staticmethod
    def _provider_from_env(prefix: str, *, default_enabled: bool) -> ModelProviderSettings:
        """Load one user-owned model slot. The product does not ship a model."""
        model = _value(f"{prefix}_MODEL")
        base_url = _value(f"{prefix}_BASE_URL")
        api_key = _value(f"{prefix}_API_KEY")
        enabled_override = _value(f"{prefix}_ENABLED")
        if enabled_override:
            enabled = _boolean(f"{prefix}_ENABLED", default_enabled)
        elif default_enabled:
            enabled = True
        else:
            enabled = bool(model and base_url and api_key)
        return ModelProviderSettings(
            provider=_value(f"{prefix}_PROVIDER"),
            base_url=base_url,
            model=model,
            api_key=api_key,
            api_style=_value(f"{prefix}_API_STYLE", "openai").lower(),
            enabled=enabled,
            stream=_boolean(f"{prefix}_STREAM", True),
            supports_json_mode=_boolean(f"{prefix}_JSON_MODE", True),
            temperature=float(_value(f"{prefix}_TEMPERATURE", "0.0")),
            top_p=float(_value(f"{prefix}_TOP_P", "1.0")),
            disable_reasoning=_boolean(f"{prefix}_DISABLE_REASONING", True),
        )

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            environment=_value("APP_ENV", "development"),
            database_url=_value(
                "DATABASE_URL",
                "postgresql+psycopg://threat_agent:threat_agent@localhost:5432/threat_agent",
            ),
            object_store_endpoint=_value("OBJECT_STORE_ENDPOINT", "http://localhost:9000"),
            object_store_bucket=_value("OBJECT_STORE_BUCKET", "analysis-content"),
            object_store_access_key=_value("OBJECT_STORE_ACCESS_KEY", "threat_agent"),
            object_store_secret_key=_value(
                "OBJECT_STORE_SECRET_KEY", "change-this-before-deployment"
            ),
            content_store_backend=_value("CONTENT_STORE_BACKEND", "local").lower(),
            content_store_path=_value("CONTENT_STORE_PATH", ".data/content"),
            temporal_address=_value("TEMPORAL_ADDRESS", "localhost:7233"),
            ghidra_home=_value("GHIDRA_HOME", _local_ghidra_home()),
            java_home=_value("JAVA_HOME", _local_java_home()),
            max_sample_files=int(_value("MAX_SAMPLE_FILES", "1000")),
            max_sample_bytes=int(_value("MAX_SAMPLE_BYTES", "536870912")),
            max_archive_depth=int(_value("MAX_ARCHIVE_DEPTH", "3")),
            primary_model=cls._provider_from_env("MODEL_PRIMARY", default_enabled=True),
            fallback_model=cls._provider_from_env("MODEL_FALLBACK", default_enabled=False),
            model_calls_enabled=_boolean("MODEL_CALLS_ENABLED", False),
            dsh_conversation_owns_planning=_boolean(
                "DSH_CONVERSATION_OWNS_PLANNING", True
            ),
            model_context_max_bytes=int(_value("MODEL_CONTEXT_MAX_BYTES", "2000000")),
            model_timeout_s=float(_value("MODEL_CALL_TIMEOUT_S", "180")),
            model_max_tokens=int(_value("MODEL_CALL_MAX_TOKENS", "2048")),
            investigation_max_steps=int(_value("INVESTIGATION_MAX_STEPS", "65536")),
            investigation_max_rounds=int(_value("INVESTIGATION_MAX_ROUNDS", "4")),
            max_concurrent_analyses=int(_value("MAX_CONCURRENT_ANALYSES", "1")),
            investigation_task_max_actions=int(
                _value("INVESTIGATION_TASK_MAX_ACTIONS", "64")
            ),
            audit_seal_secret=_value("AUDIT_SEAL_SECRET"),
            gate_secret_key=_value("GATE_SECRET_KEY"),
            model_config_secret_key=_value("MODEL_CONFIG_SECRET_KEY"),
            tool_execution_mode=_value(
                "TOOL_EXECUTION_MODE",
                "temporal" if _value("APP_ENV", "development") == "production" else "local",
            ).lower(),
            tool_task_queue=_value("TOOL_TASK_QUEUE", "static-ghidra"),
            tool_allowed_tools=tuple(
                item.strip() for item in _value("TOOL_ALLOWED_TOOLS").split(",") if item.strip()
            ),
            control_task_queue=_value("CONTROL_TASK_QUEUE", "static-control"),
            intake_task_queue=_value("INTAKE_TASK_QUEUE", "static-intake"),
            parser_task_queue=_value("PARSER_TASK_QUEUE", "static-parser"),
            script_task_queue=_value("SCRIPT_TASK_QUEUE", "static-script"),
            document_task_queue=_value("DOCUMENT_TASK_QUEUE", "static-document"),
            ghidra_task_queue=_value("GHIDRA_TASK_QUEUE", "static-ghidra"),
            emu_task_queue=_value("EMU_TASK_QUEUE", "static-emu"),
            allow_demo_auth=_boolean(
                "ALLOW_DEMO_AUTH",
                _value("APP_ENV", "development").lower() in {"test", "development", "demo"},
            ),
            model_payload_retention_days=int(_value("MODEL_PAYLOAD_RETENTION_DAYS", "180")),
            auth_jwt_secret=_value("AUTH_JWT_SECRET"),
            auth_jwt_issuer=_value("AUTH_JWT_ISSUER"),
            auth_jwt_audience=_value("AUTH_JWT_AUDIENCE"),
            auth_jwks_url=_value("AUTH_JWKS_URL"),
            audit_seal_bucket=_value("AUDIT_SEAL_BUCKET"),
            audit_object_lock_mode=_value("AUDIT_OBJECT_LOCK_MODE", "COMPLIANCE").upper(),
            audit_object_lock_days=int(_value("AUDIT_OBJECT_LOCK_DAYS", "3650")),
            workbench_workspace_root=_value("WORKBENCH_WORKSPACE_ROOT"),
            simulation_profile=_value("SIMULATION_PROFILE", "static-only") or "static-only",
            simulation_worker_identity=_value("SIMULATION_WORKER_IDENTITY"),
            simulation_worker_image_digest=_value("SIMULATION_WORKER_IMAGE_DIGEST"),
            simulation_allowed_simulators=tuple(
                item.strip()
                for item in _value(
                    "SIMULATION_ALLOWED_SIMULATORS",
                    "unicorn,speakeasy,qiling,flare-emu",
                ).split(",")
                if item.strip()
            ),
            simulation_allow_local_process=_boolean("SIMULATION_ALLOW_LOCAL_PROCESS", False),
            simulation_qiling_rootfs=_value("SIMULATION_QILING_ROOTFS"),
            simulation_timeout_seconds=int(_value("SIMULATION_TIMEOUT_SECONDS", "8")),
            simulation_instruction_budget=int(_value("SIMULATION_INSTRUCTION_BUDGET", "900000")),
            simulation_max_output_bytes=int(_value("SIMULATION_MAX_OUTPUT_BYTES", "65536")),
            simulation_max_input_bytes=int(_value("SIMULATION_MAX_INPUT_BYTES", "4194304")),
            static_abstract_execution_max_steps=int(
                _value("STATIC_ABSTRACT_EXECUTION_MAX_STEPS", "65536")
            ),
        )
