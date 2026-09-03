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

    def task_queue_for(self, tool_name: str) -> str:
        return {
            "python-zipfile-safe-reader": self.intake_task_queue,
            "script-parser": self.script_task_queue,
            "document-carrier-parser": self.document_task_queue,
            "ghidra-headless": self.ghidra_task_queue,
        }.get(tool_name, self.parser_task_queue)

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
            primary_model=ModelProviderSettings(
                provider=_value("MODEL_PRIMARY_PROVIDER", "deepseek"),
                base_url=_value("MODEL_PRIMARY_BASE_URL"),
                model=_value("MODEL_PRIMARY_MODEL"),
                api_key=_value("MODEL_PRIMARY_API_KEY"),
                api_style=_value("MODEL_PRIMARY_API_STYLE", "openai").lower(),
                stream=_boolean("MODEL_PRIMARY_STREAM", True),
                supports_json_mode=_boolean("MODEL_PRIMARY_JSON_MODE", True),
                temperature=float(_value("MODEL_PRIMARY_TEMPERATURE", "0.0")),
                top_p=float(_value("MODEL_PRIMARY_TOP_P", "1.0")),
                disable_reasoning=_boolean("MODEL_PRIMARY_DISABLE_REASONING", True),
            ),
            fallback_model=ModelProviderSettings(
                provider=_value("MODEL_FALLBACK_PROVIDER", "glm"),
                base_url=_value("MODEL_FALLBACK_BASE_URL"),
                model=_value("MODEL_FALLBACK_MODEL"),
                api_key=_value("MODEL_FALLBACK_API_KEY"),
                api_style=_value("MODEL_FALLBACK_API_STYLE", "openai").lower(),
                stream=_boolean("MODEL_FALLBACK_STREAM", True),
                supports_json_mode=_boolean("MODEL_FALLBACK_JSON_MODE", True),
                temperature=float(_value("MODEL_FALLBACK_TEMPERATURE", "0.0")),
                top_p=float(_value("MODEL_FALLBACK_TOP_P", "1.0")),
                disable_reasoning=_boolean("MODEL_FALLBACK_DISABLE_REASONING", True),
            ),
            model_calls_enabled=_boolean("MODEL_CALLS_ENABLED", False),
            model_context_max_bytes=int(_value("MODEL_CONTEXT_MAX_BYTES", "2000000")),
            model_timeout_s=float(_value("MODEL_CALL_TIMEOUT_S", "180")),
            model_max_tokens=int(_value("MODEL_CALL_MAX_TOKENS", "2048")),
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
        )
