from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
from typing import Callable, Protocol
from urllib.request import Request, urlopen

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


@dataclass(frozen=True)
class StoredContent:
    sha256: str
    size: int
    storage_key: str


@dataclass(frozen=True)
class ToolRunStorageGrant:
    input_storage_key: str
    input_url: str
    output_storage_key: str
    output_url: str


class ScopedToolRunContentStore:
    """HTTP adapter constrained to one ToolRun input and output object."""

    def __init__(
        self,
        grant: ToolRunStorageGrant,
        *,
        opener: Callable[..., object] = urlopen,
    ) -> None:
        self.grant = grant
        self._opener = opener

    def read(self, storage_key: str) -> bytes:
        if storage_key != self.grant.input_storage_key:
            raise ValueError("object key is outside the ToolRun grant")
        request = Request(self.grant.input_url, method="GET")
        with self._opener(request, timeout=60) as response:  # type: ignore[attr-defined]
            content = response.read()
        expected = Path(storage_key).name
        if len(expected) != 64 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("scoped input hash mismatch")
        return content

    def put(self, content: bytes) -> StoredContent:
        request = Request(
            self.grant.output_url,
            data=content,
            method="PUT",
            headers={"Content-Type": "application/octet-stream"},
        )
        with self._opener(request, timeout=60):  # type: ignore[attr-defined]
            pass
        return StoredContent(
            sha256=hashlib.sha256(content).hexdigest(),
            size=len(content),
            storage_key=self.grant.output_storage_key,
        )


class ContentStore(Protocol):
    def put(self, content: bytes) -> StoredContent: ...

    def put_immutable(self, content: bytes) -> StoredContent: ...

    def read(self, storage_key: str) -> bytes: ...

    def delete(self, storage_key: str) -> None: ...


class LocalContentStore:
    """Content-addressed development adapter with write-once blob semantics."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, content: bytes) -> StoredContent:
        digest = hashlib.sha256(content).hexdigest()
        relative = Path(digest[:2]) / digest[2:4] / digest
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError("content store hash mismatch for existing immutable blob")
        else:
            temporary = target.with_name(f".{digest}.{os.getpid()}.tmp")
            try:
                temporary.write_bytes(content)
                try:
                    temporary.replace(target)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        return StoredContent(digest, len(content), relative.as_posix())

    def put_immutable(self, content: bytes) -> StoredContent:
        """Write-once audit payload under a distinct local namespace."""
        digest = hashlib.sha256(content).hexdigest()
        relative = Path("audit") / "sha256" / digest[:2] / digest[2:4] / digest
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError("audit store hash mismatch for existing immutable blob")
        else:
            temporary = target.with_name(f".{digest}.{os.getpid()}.tmp")
            try:
                temporary.write_bytes(content)
                try:
                    temporary.replace(target)
                except FileExistsError:
                    pass
            finally:
                temporary.unlink(missing_ok=True)
        return StoredContent(digest, len(content), relative.as_posix())

    def read(self, storage_key: str) -> bytes:
        target = (self.root / storage_key).resolve()
        if self.root not in target.parents:
            raise ValueError("content key escapes the content store")
        content = target.read_bytes()
        expected = Path(storage_key).name
        if len(expected) != 64 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("content store hash mismatch")
        return content

    def delete(self, storage_key: str) -> None:
        if storage_key.replace("\\", "/").startswith("audit/"):
            raise PermissionError("audit seal objects are immutable")
        target = (self.root / storage_key).resolve()
        if self.root not in target.parents:
            raise ValueError("content key escapes the content store")
        target.unlink(missing_ok=True)


class S3ContentStore:
    """S3-compatible immutable content-addressed store (MinIO in the platform stack)."""

    def __init__(
        self,
        endpoint: str | object,
        bucket: str,
        access_key: str = "",
        secret_key: str = "",
        client: object | None = None,
        *,
        audit_bucket: str | None = None,
        audit_object_lock_mode: str = "COMPLIANCE",
        audit_object_lock_days: int = 3650,
    ) -> None:
        self.bucket = bucket
        self.audit_bucket = audit_bucket or f"{bucket}-audit-seals"
        if self.audit_bucket == self.bucket:
            raise ValueError("audit bucket must be distinct from the business content bucket")
        self.audit_object_lock_mode = audit_object_lock_mode.upper()
        if self.audit_object_lock_mode not in {"GOVERNANCE", "COMPLIANCE"}:
            raise ValueError("audit object lock mode must be GOVERNANCE or COMPLIANCE")
        if audit_object_lock_days < 1:
            raise ValueError("audit object lock days must be positive")
        self.audit_object_lock_days = audit_object_lock_days
        if client is not None:
            self.client = client
        elif not isinstance(endpoint, str):
            self.client = endpoint
        else:
            self.client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                config=Config(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                ),
            )

    @staticmethod
    def _key(digest: str) -> str:
        return f"sha256/{digest[:2]}/{digest[2:4]}/{digest}"

    def _ensure_bucket(self) -> None:
        if not hasattr(self.client, "head_bucket"):
            return
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            self.client.create_bucket(Bucket=self.bucket)

    def _ensure_audit_bucket(self) -> None:
        if not hasattr(self.client, "head_bucket"):
            return
        try:
            self.client.head_bucket(Bucket=self.audit_bucket)
        except ClientError:
            self.client.create_bucket(
                Bucket=self.audit_bucket,
                ObjectLockEnabledForBucket=True,
            )
        if hasattr(self.client, "get_object_lock_configuration"):
            try:
                configuration = self.client.get_object_lock_configuration(Bucket=self.audit_bucket)
            except ClientError as exc:
                raise RuntimeError("audit bucket Object Lock configuration could not be verified") from exc
            enabled = configuration.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
            if enabled != "Enabled":
                raise RuntimeError("audit bucket must have Object Lock enabled")

    def put(self, content: bytes) -> StoredContent:
        digest = hashlib.sha256(content).hexdigest()
        key = self._key(digest)
        self._ensure_bucket()
        try:
            response = self._head_object_with_retry(key)
            if response.get("Metadata", {}).get("sha256") != digest:
                raise ValueError("content store hash mismatch for existing immutable blob")
        except (ClientError, KeyError) as exc:
            if isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") not in {
                "404",
                "NoSuchKey",
                "NotFound",
            }:
                raise
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                Metadata={"sha256": digest},
            )
        return StoredContent(digest, len(content), key)

    def _head_object_with_retry(self, key: str) -> dict[str, object]:
        """Read an immutable object with a bounded retry for transient MinIO startup errors.

        Compose can report MinIO healthy just before its S3 endpoint is ready
        for a request.  Retrying only transient service responses keeps that
        startup race from failing an otherwise valid analysis, while still
        surfacing authentication, permission, and transport errors immediately.
        """
        transient_codes = {"429", "500", "502", "503", "504", "SlowDown", "ServiceUnavailable"}
        for attempt in range(3):
            try:
                return self.client.head_object(Bucket=self.bucket, Key=key)
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                if code not in transient_codes or attempt == 2:
                    raise
                time.sleep(0.2 * (2**attempt))
        raise RuntimeError("unreachable")

    def put_immutable(self, content: bytes) -> StoredContent:
        """Store an audit payload in an Object Lock-enabled bucket."""
        digest = hashlib.sha256(content).hexdigest()
        key = f"audit/sha256/{digest[:2]}/{digest[2:4]}/{digest}"
        self._ensure_audit_bucket()
        try:
            response = self.client.head_object(Bucket=self.audit_bucket, Key=key)
            if response.get("Metadata", {}).get("sha256") != digest:
                raise ValueError("audit store hash mismatch for existing immutable blob")
        except (ClientError, KeyError) as exc:
            if isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") not in {
                "404",
                "NoSuchKey",
                "NotFound",
            }:
                raise
            retain_until = datetime.now(UTC) + timedelta(days=self.audit_object_lock_days)
            self.client.put_object(
                Bucket=self.audit_bucket,
                Key=key,
                Body=content,
                Metadata={"sha256": digest, "purpose": "audit-seal"},
                ObjectLockMode=self.audit_object_lock_mode,
                ObjectLockRetainUntilDate=retain_until,
            )
        return StoredContent(digest, len(content), key)

    def _bucket_for_key(self, storage_key: str) -> str:
        return self.audit_bucket if storage_key.replace("\\", "/").startswith("audit/") else self.bucket

    def read(self, storage_key: str) -> bytes:
        body = self.client.get_object(Bucket=self._bucket_for_key(storage_key), Key=storage_key)["Body"]
        content = body.read() if hasattr(body, "read") else body
        expected = Path(storage_key).name
        if len(expected) != 64 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("content store hash mismatch")
        return content

    def delete(self, storage_key: str) -> None:
        if storage_key.replace("\\", "/").startswith("audit/"):
            raise PermissionError("audit seal objects are immutable")
        self.client.delete_object(Bucket=self.bucket, Key=storage_key)

    def issue_tool_run_access(
        self,
        input_storage_key: str,
        tool_run_id: str,
        *,
        expires_in: int = 3600,
    ) -> ToolRunStorageGrant:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", tool_run_id):
            raise ValueError("invalid ToolRun id for scoped object access")
        if not 60 <= expires_in <= 604800:
            raise ValueError("scoped object access expiry must be between 60 and 604800 seconds")
        output_storage_key = f"tool-runs/{tool_run_id}/output.json"
        input_params = {"Bucket": self.bucket, "Key": input_storage_key}
        output_params = {"Bucket": self.bucket, "Key": output_storage_key}
        return ToolRunStorageGrant(
            input_storage_key=input_storage_key,
            input_url=self.client.generate_presigned_url(
                "get_object",
                Params=input_params,
                ExpiresIn=expires_in,
                HttpMethod="GET",
            ),
            output_storage_key=output_storage_key,
            output_url=self.client.generate_presigned_url(
                "put_object",
                Params=output_params,
                ExpiresIn=expires_in,
                HttpMethod="PUT",
            ),
        )

    @staticmethod
    def _tool_run_output_key(tool_run_id: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", tool_run_id):
            raise ValueError("invalid ToolRun id for scoped object access")
        return f"tool-runs/{tool_run_id}/output.json"

    def read_tool_run_output(self, tool_run_id: str, storage_key: str) -> bytes:
        if storage_key != self._tool_run_output_key(tool_run_id):
            raise ValueError("staged output key is outside the ToolRun grant")
        body = self.client.get_object(Bucket=self.bucket, Key=storage_key)["Body"]
        return body.read() if hasattr(body, "read") else body

    def delete_tool_run_output(self, tool_run_id: str, storage_key: str) -> None:
        if storage_key != self._tool_run_output_key(tool_run_id):
            raise ValueError("staged output key is outside the ToolRun grant")
        self.client.delete_object(Bucket=self.bucket, Key=storage_key)
