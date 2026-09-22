from __future__ import annotations

import base64
import hashlib
import hmac
import json
import io
from dataclasses import replace

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from threat_report_agent.main import create_app
from threat_report_agent.service import AnalysisService
from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database


def test_production_api_requires_server_side_principal(test_settings) -> None:
    settings = replace(
        test_settings,
        environment="production",
        tool_execution_mode="temporal",
        allow_demo_auth=False,
        audit_seal_secret="independent-sealer-secret",
        auth_jwt_secret="production-jwt-secret",
    )
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/v1/cases", json={"title": "unauthenticated"}).status_code == 401
        assert (
            client.post(
                "/api/v1/cases",
                json={"title": "header spoof"},
                headers={"X-Principal-Id": "alice", "X-Principal-Roles": "admin"},
            ).status_code
            == 401
        )


def test_production_jwt_principal_is_verified(test_settings) -> None:
    secret = b"production-jwt-secret"

    def encode(value: dict[str, object]) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
            .decode()
            .rstrip("=")
        )

    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode({"sub": "alice", "roles": ["analyst"]})
    signing_input = f"{header}.{payload}".encode()
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
        .decode()
        .rstrip("=")
    )
    token = f"{header}.{payload}.{signature}"
    settings = replace(
        test_settings,
        environment="production",
        tool_execution_mode="temporal",
        allow_demo_auth=False,
        audit_seal_secret="independent-sealer-secret",
        auth_jwt_secret=secret.decode(),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/cases",
            json={"title": "jwt-authenticated"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 201


def test_production_oidc_jwks_principal_is_verified_and_rejects_invalid_tokens(
    test_settings, monkeypatch
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()

    def b64(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "acceptance-key",
                "n": b64(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")),
                "e": b64(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")),
            }
        ]
    }

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return jwks

    monkeypatch.setattr("threat_report_agent.auth.httpx.get", lambda *_args, **_kwargs: Response())

    def token(*, issuer: str = "https://issuer.test", audience: str = "threat-api", kid: str = "acceptance-key", signing_key=None) -> str:
        def encode(value: dict[str, object]) -> str:
            return b64(json.dumps(value, separators=(",", ":")).encode())

        header = encode({"alg": "RS256", "typ": "JWT", "kid": kid})
        payload = encode({"sub": "oidc-user", "roles": ["analyst"], "iss": issuer, "aud": audience})
        signing_input = f"{header}.{payload}".encode()
        signature = (signing_key or private_key).sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{header}.{payload}.{b64(signature)}"

    settings = replace(
        test_settings,
        environment="production",
        tool_execution_mode="temporal",
        allow_demo_auth=False,
        audit_seal_secret="independent-sealer-secret",
        auth_jwt_issuer="https://issuer.test",
        auth_jwt_audience="threat-api",
        auth_jwks_url="https://issuer.test/.well-known/jwks.json",
    )
    with TestClient(create_app(settings)) as client:
        valid = client.post(
            "/api/v1/cases",
            json={"title": "oidc-authenticated"},
            headers={"Authorization": f"Bearer {token()}"},
        )
        bad_issuer = client.post(
            "/api/v1/cases",
            json={"title": "bad-issuer"},
            headers={"Authorization": f"Bearer {token(issuer='https://wrong.test')}"},
        )
        bad_audience = client.post(
            "/api/v1/cases",
            json={"title": "bad-audience"},
            headers={"Authorization": f"Bearer {token(audience='other-api')}"},
        )
        unknown_kid = client.post(
            "/api/v1/cases",
            json={"title": "unknown-kid"},
            headers={"Authorization": f"Bearer {token(kid='missing-key')}"},
        )
        invalid_signature = client.post(
            "/api/v1/cases",
            json={"title": "invalid-signature"},
            headers={
                "Authorization": f"Bearer {token(signing_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))}"
            },
        )
    assert valid.status_code == 201
    assert bad_issuer.status_code == 401
    assert bad_audience.status_code == 401
    assert unknown_kid.status_code == 401
    assert invalid_signature.status_code == 401


def test_unknown_required_artifact_cannot_report_complete(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("unknown format")
    result = service.analyze_submission(
        case_id=case.id, filename="unknown.bin", content=b"\x00\x01\x02\x03\x00\xff"
    )
    task = service.task_view(result.task_id)
    assert task["outcome"] == "PARTIAL"
    assert any(
        "unknown" in item.lower() or "unsupported" in item.lower() for item in task["limitations"]
    )


def test_static_decode_materializes_non_executable_child_artifact(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("decode child")
    encoded = base64.b64encode(b"decoded payload " * 8).decode()
    result = service.analyze_submission(
        case_id=case.id,
        filename="payload.py",
        content=f"blob = '{encoded}'".encode(),
    )
    task = service.task_view(result.task_id)
    children = [item for item in task["artifacts"] if item["role"] == "DECODED_PAYLOAD"]
    assert children
    assert children[0]["parent_artifact_id"] == task["artifacts"][0]["id"]
    # Opaque decoded bytes remain in the static queue, but do not create a
    # false deep-disassembly failure for the parent task.
    assert children[0]["obligation"] == "SUPPORTING"
    assert any(item["kind"] == "decoded_artifact" for item in task["evidence"])


def test_pdf_attachment_reenters_static_analysis_pipeline(test_settings) -> None:
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_attachment("payload.py", b"import socket\nprint('child')")
    output = io.BytesIO()
    writer.write(output)
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("pdf recursive child")

    result = service.analyze_submission(
        case_id=case.id, filename="carrier.pdf", content=output.getvalue()
    )
    task = service.task_view(result.task_id)
    child = next(item for item in task["artifacts"] if item["role"] == "EMBEDDED_OBJECT")
    assert any(
        item["artifact_id"] == child["id"] and item["kind"] == "script_import"
        for item in task["evidence"]
    )
    assert any(
        item["relation_type"] == "CONTAINS" and item["target_artifact_id"] == child["id"]
        for item in task["relations"]
    )


def test_report_gate_transitions_are_audited(test_settings) -> None:
    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    service.database.create_schema()
    case = service.create_case("report gate")
    result = service.analyze_submission(case_id=case.id, filename="sample.py", content=b"print(1)")
    approved = service.approve_report(result.report_revision_id, actor="reviewer")
    assert approved["status"] == "APPROVED"
    published = service.publish_report(result.report_revision_id, actor="publisher")
    assert published["status"] == "PUBLISHED"
