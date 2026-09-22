from __future__ import annotations

import json
from dataclasses import replace

import httpx

from threat_report_agent.config import ModelProviderSettings
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.model_gateway import ModelGateway
from threat_report_agent.service import AnalysisService


def test_enrichment_accepts_deepseek_envelope_and_rejects_unknown_evidence(
    test_settings,
) -> None:
    """A near-valid DeepSeek envelope is a successful model turn, not a provider outage.

    Evidence IDs that are not in the frozen manifest must still be rejected.
    """
    settings = replace(
        test_settings,
        model_calls_enabled=True,
        fallback_model=ModelProviderSettings("unused", "", "", "", enabled=False),
    )
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        untrusted = payload["messages"][1]["content"]
        context = json.loads(
            untrusted.split("<untrusted-analysis-data>\n", 1)[1].split(
                "\n</untrusted-analysis-data>", 1
            )[0]
        )
        allowed = list(context.get("allowed_evidence_ids") or [])
        cited = allowed[0] if allowed else "missing-allowed-id"
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "reasoning": "COM host leftover reasoning; ignore.",
                                    "claims": [
                                        {
                                            "module": "loader",
                                            "subject": "sample.py",
                                            "action": "references",
                                            "target": "VirtualAlloc",
                                            "mechanism": "static import",
                                            "statement": (
                                                "The script references a loader-related indicator."
                                            ),
                                            "supporting_evidence_ids": [cited],
                                            "confidence": "low",
                                            "status": "INFERRED",
                                        },
                                        {
                                            "module": "loader",
                                            "subject": "sample.py",
                                            "action": "contacts",
                                            "target": "invented.example",
                                            "mechanism": "static import",
                                            "statement": "The model invented an endpoint.",
                                            "supporting_evidence_ids": [
                                                "invented-not-in-manifest"
                                            ],
                                            "confidence": "HIGH",
                                            "status": "SUPPORTED",
                                        },
                                    ],
                                    "limitations": "Consumer remains UNKNOWN.",
                                }
                            )
                        }
                    }
                ]
            },
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("deepseek enrichment binding")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nprint('ok')",
    )

    task = service.task_view(result.task_id)
    enrichment = [
        item
        for item in task["model_calls"]
        if item.get("phase") == "enrichment" or item.get("prompt_id") == "static-analysis-agent"
    ]
    assert enrichment, task["model_calls"]
    assert enrichment[-1]["status"] == "SUCCEEDED"
    assert enrichment[-1]["error_type"] is None
    limitations = " ".join(str(item) for item in task["limitations"])
    assert "Model analysis providers failed" not in limitations
    assert "Consumer remains UNKNOWN." in limitations

    model_claims = [item for item in task["claims"] if item.get("model_call_id")]
    cited_ids = {
        link["evidence_id"]
        for claim in model_claims
        for link in task.get("claim_evidence", [])
        if link.get("claim_id") == claim["id"]
    }
    assert "invented-not-in-manifest" not in cited_ids
    assert all(
        "invented-not-in-manifest" not in str(item.get("evidence_ids", []))
        for item in model_claims
    )

    audit_reasons = [
        str((event.get("payload") or {}).get("reason", ""))
        for event in service.list_audit_events(result.task_id)
        if event.get("event_type") == "claim.validation"
    ]
    assert any("unknown Evidence" in reason for reason in audit_reasons)


def test_enrichment_reports_schema_mismatch_not_provider_outage(test_settings) -> None:
    """A true envelope mismatch must not be recorded as a model-provider outage."""
    settings = replace(
        test_settings,
        model_calls_enabled=True,
        fallback_model=ModelProviderSettings("unused", "", "", "", enabled=False),
    )
    service = AnalysisService(
        settings, Database(settings.database_url), LocalContentStore(settings.content_store_path)
    )
    service.database.create_schema()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps({"claims": "not-an-array"})}}]},
        )

    service.model_gateway = ModelGateway(
        settings.primary_model,
        settings.fallback_model,
        transport=httpx.MockTransport(handler),
    )
    case = service.create_case("schema mismatch enrichment")
    result = service.analyze_submission(
        case_id=case.id,
        filename="sample.py",
        content=b"import socket\nprint('ok')",
    )
    task = service.task_view(result.task_id)
    enrichment = [
        item
        for item in task["model_calls"]
        if item.get("phase") == "enrichment" or item.get("prompt_id") == "static-analysis-agent"
    ]
    assert enrichment
    assert enrichment[-1]["status"] == "FAILED"
    assert enrichment[-1]["error_type"] == "ValidationError"
    assert enrichment[-1]["http_status"] is None
    limitations = " ".join(str(item) for item in task["limitations"])
    assert "Model analysis providers failed" not in limitations
    assert "atomic-claim envelope" in limitations

