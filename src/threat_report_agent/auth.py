from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import time

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from fastapi import HTTPException, Request


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str]
    auth_source: str = "header"

    def has(self, permission: str) -> bool:
        role_permissions = {
            "analyst": {
                "case:read",
                "case:create",
                "task:submit",
                "task:read",
                "report:read",
                "report:edit",
                "model:invoke",
            },
            "reviewer": {
                "case:read",
                "task:read",
                "report:read",
                "report:approve",
                "purge:review",
                "gate:decide",
            },
            "operator": {
                "case:read",
                "task:read",
                "task:submit",
                "gate:decide",
                "audit:read",
                "model:invoke",
            },
            "auditor": {
                "case:read",
                "task:read",
                "report:read",
                "audit:read",
                "audit:seal",
                "model:read",
            },
            "service_account": {"audit:seal", "retention:execute"},
            "admin": {
                "case:read",
                "case:create",
                "task:submit",
                "task:read",
                "report:read",
                "report:edit",
                "report:approve",
                "report:publish",
                "gate:decide",
                "purge:request",
                "purge:review",
                "purge:execute",
                "audit:read",
                "audit:seal",
                "model:read",
                "model:invoke",
                "model:configure",
                "retention:freeze",
                "retention:execute",
            },
        }
        return any(permission in role_permissions.get(role, set()) for role in self.roles)


class AuthAdapter:
    """Deployment-neutral identity adapter; replace with OIDC/JWT in production."""

    def __init__(
        self,
        *,
        environment: str,
        allow_demo: bool = False,
        jwt_secret: str = "",
        jwt_issuer: str = "",
        jwt_audience: str = "",
        jwks_url: str = "",
    ) -> None:
        self.environment = environment.lower()
        self.allow_demo = allow_demo
        self.jwt_secret = jwt_secret.encode("utf-8")
        self.jwt_issuer = jwt_issuer
        self.jwt_audience = jwt_audience
        self.jwks_url = jwks_url
        self._jwks_cache: tuple[float, dict[str, object]] | None = None

    def resolve(self, request: Request) -> Principal:
        authorization = request.headers.get("Authorization", "")
        if self.environment == "production":
            if not authorization.startswith("Bearer ") or not (self.jwt_secret or self.jwks_url):
                raise HTTPException(status_code=401, detail="signed Bearer token required")
            return self._verify_jwt(authorization[7:].strip())
        subject = request.headers.get("X-Principal-Id", "").strip()
        roles = frozenset(
            item.strip().lower()
            for item in request.headers.get("X-Principal-Roles", "").split(",")
            if item.strip()
        )
        if subject and roles:
            return Principal(subject, roles)
        if self.allow_demo and self.environment in {"test", "development", "demo"}:
            return Principal(
                "demo-user", frozenset({"admin", "analyst", "reviewer", "auditor"}), "demo"
            )
        raise HTTPException(status_code=401, detail="authenticated Principal required")

    def _verify_jwt(self, token: str) -> Principal:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
            signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
            actual = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
            header = json.loads(
                base64.urlsafe_b64decode(encoded_header + "=" * (-len(encoded_header) % 4))
            )
            algorithm = header.get("alg")
            if algorithm == "HS256" and self.jwt_secret:
                expected = hmac.new(self.jwt_secret, signing_input, hashlib.sha256).digest()
                if not hmac.compare_digest(expected, actual):
                    raise ValueError("invalid signature")
            elif algorithm == "RS256" and self.jwks_url:
                self._verify_rs256(signing_input, actual, str(header.get("kid", "")))
            else:
                raise ValueError("unsupported JWT algorithm")
            payload = json.loads(
                base64.urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4))
            )
            if payload.get("exp") is not None and float(payload["exp"]) <= time.time():
                raise ValueError("expired token")
            if self.jwt_issuer and payload.get("iss") != self.jwt_issuer:
                raise ValueError("unexpected issuer")
            if self.jwt_audience:
                audience = payload.get("aud", [])
                audience_values = {audience} if isinstance(audience, str) else set(audience)
                if self.jwt_audience not in audience_values:
                    raise ValueError("unexpected audience")
            subject = str(payload["sub"])
            raw_roles = payload.get("roles", payload.get("role", []))
            roles = {raw_roles} if isinstance(raw_roles, str) else set(raw_roles)
            if not subject or not roles:
                raise ValueError("token has no subject or roles")
            return Principal(subject, frozenset(str(role).lower() for role in roles), "jwt")
        except (
            ValueError,
            KeyError,
            TypeError,
            json.JSONDecodeError,
            InvalidSignature,
            httpx.HTTPError,
        ) as exc:
            raise HTTPException(status_code=401, detail="invalid Bearer token") from exc

    def _verify_rs256(self, signing_input: bytes, signature: bytes, key_id: str) -> None:
        if not key_id:
            raise ValueError("JWT key id is required")
        now = time.time()
        if self._jwks_cache is None or self._jwks_cache[0] <= now:
            # trust_env=False because httpx reads proxy configuration in
            # Client.__init__ and raises before any request exists.  This host sets
            # NO_PROXY=localhost,127.0.0.1,::1,[::1]; httpx turns the bracketed
            # entry into the mount key `all://*[::1]`, fails to parse it, and dies
            # with InvalidURL("Invalid port: ':1]'").  InvalidURL is not an
            # httpx.HTTPError, so it escaped the handler below and surfaced as a
            # 500 instead of a clean auth failure.  A JWKS endpoint is fetched
            # directly and must not be routed through an interception proxy.
            response = httpx.get(self.jwks_url, timeout=10.0, trust_env=False)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("invalid JWKS response")
            self._jwks_cache = (now + 300, payload)
        jwks = self._jwks_cache[1]
        key = next(
            (
                item
                for item in jwks.get("keys", [])  # type: ignore[union-attr]
                if isinstance(item, dict) and item.get("kid") == key_id
            ),
            None,
        )
        if key is None or key.get("kty") != "RSA":
            raise ValueError("JWT signing key was not found")
        modulus = int.from_bytes(
            base64.urlsafe_b64decode(str(key["n"]) + "=" * (-len(str(key["n"])) % 4)),
            "big",
        )
        exponent = int.from_bytes(
            base64.urlsafe_b64decode(str(key["e"]) + "=" * (-len(str(key["e"])) % 4)),
            "big",
        )
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())


def require_permission(request: Request, permission: str) -> Principal:
    principal: Principal | None = getattr(request.state, "principal", None)
    if principal is None:
        principal = request.app.state.auth_adapter.resolve(request)
        request.state.principal = principal
    if not principal.has(permission):
        raise HTTPException(status_code=403, detail=f"missing permission: {permission}")
    return principal
