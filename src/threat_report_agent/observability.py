from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
import sys

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest


HTTP_REQUESTS = Counter(
    "threat_report_http_requests_total",
    "HTTP requests handled by the control plane.",
    ("method", "route", "status"),
)
HTTP_DURATION = Histogram(
    "threat_report_http_request_duration_seconds",
    "HTTP control-plane request duration.",
    ("method", "route"),
)

_configured = False


class JsonOperationalFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "operational_fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def configure_observability(service_name: str) -> trace.Tracer:
    global _configured
    if not _configured:
        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        trace.set_tracer_provider(provider)
        logger = logging.getLogger("threat_report_agent.operational")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(JsonOperationalFormatter())
            logger.addHandler(handler)
        _configured = True
    return trace.get_tracer(service_name)


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
