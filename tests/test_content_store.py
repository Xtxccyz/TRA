import hashlib

from botocore.exceptions import ClientError
import pytest

from threat_report_agent.content_store import (
    S3ContentStore,
    ScopedToolRunContentStore,
    ToolRunStorageGrant,
)


class FakeS3:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, object]] = {}
        self.presigned: list[dict[str, object]] = []

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        if (Bucket, Key) not in self.items:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        item = self.items[(Bucket, Key)]
        return {"ContentLength": len(item["Body"]), "Metadata": item["Metadata"]}

    def head_bucket(self, *, Bucket: str) -> None:
        return None

    def create_bucket(self, *, Bucket: str) -> None:
        return None

    def put_object(
        self, *, Bucket: str, Key: str, Body: bytes, Metadata: dict[str, str], **_: object
    ) -> None:
        self.items[(Bucket, Key)] = {"Body": Body, "Metadata": Metadata}

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        class Body:
            def read(self) -> bytes:
                return self.content

            def __init__(self, content: bytes) -> None:
                self.content = content

        return {"Body": Body(self.items[(Bucket, Key)]["Body"])}

    def generate_presigned_url(
        self,
        operation: str,
        *,
        Params: dict[str, str],
        ExpiresIn: int,
        HttpMethod: str,
    ) -> str:
        self.presigned.append(
            {
                "operation": operation,
                "params": Params,
                "expires_in": ExpiresIn,
                "http_method": HttpMethod,
            }
        )
        return f"http://minio.test/{operation}/{Params['Key']}"


class MissingAuditBucketS3(FakeS3):
    def __init__(self) -> None:
        super().__init__()
        self.created_bucket: dict[str, object] | None = None
        self.lock_put: dict[str, object] | None = None

    def head_bucket(self, *, Bucket: str) -> None:
        if Bucket == "audit-seals":
            raise ClientError({"Error": {"Code": "404"}}, "HeadBucket")

    def create_bucket(self, **kwargs: object) -> None:
        self.created_bucket = kwargs

    def put_object(self, **kwargs: object) -> None:
        self.lock_put = kwargs
        super().put_object(
            Bucket=str(kwargs["Bucket"]),
            Key=str(kwargs["Key"]),
            Body=kwargs["Body"],  # type: ignore[arg-type]
            Metadata=kwargs["Metadata"],  # type: ignore[arg-type]
        )


class UnlockedAuditBucketS3(FakeS3):
    def get_object_lock_configuration(self, *, Bucket: str) -> dict[str, object]:
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}


class TransientHeadS3(FakeS3):
    def __init__(self) -> None:
        super().__init__()
        self.head_attempts = 0

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        self.head_attempts += 1
        if self.head_attempts == 1:
            raise ClientError({"Error": {"Code": "503"}}, "HeadObject")
        return super().head_object(Bucket=Bucket, Key=Key)


def test_s3_store_retries_transient_head_object_failure(monkeypatch) -> None:
    client = TransientHeadS3()
    store = S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
        client=client,
    )
    monkeypatch.setattr("threat_report_agent.content_store.time.sleep", lambda _: None)

    stored = store.put(b"retry transient minio")

    assert stored.size == len(b"retry transient minio")
    assert client.head_attempts == 2


def test_s3_store_uses_content_addressed_write_once_keys() -> None:
    store = S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
        client=FakeS3(),
    )

    stored = store.put(b"never execute this")

    assert stored.sha256 == hashlib.sha256(b"never execute this").hexdigest()
    assert store.read(stored.storage_key) == b"never execute this"
    assert stored.storage_key.startswith("sha256/")


def test_s3_store_issues_one_input_and_one_output_url_per_tool_run() -> None:
    client = FakeS3()
    store = S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
        client=client,
    )
    input_key = "sha256/aa/bb/" + "c" * 64

    grant = store.issue_tool_run_access(input_key, "tool-run-123", expires_in=1200)

    assert grant.input_storage_key == input_key
    assert grant.output_storage_key == "tool-runs/tool-run-123/output.json"
    assert grant.input_url.endswith(f"get_object/{input_key}")
    assert grant.output_url.endswith("put_object/tool-runs/tool-run-123/output.json")
    assert client.presigned == [
        {
            "operation": "get_object",
            "params": {"Bucket": "analysis-content", "Key": input_key},
            "expires_in": 1200,
            "http_method": "GET",
        },
        {
            "operation": "put_object",
            "params": {
                "Bucket": "analysis-content",
                "Key": "tool-runs/tool-run-123/output.json",
            },
            "expires_in": 1200,
            "http_method": "PUT",
        },
    ]


def test_s3_store_configures_sigv4_path_style_for_minio(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_client(service_name: str, **kwargs: object) -> FakeS3:
        captured["service_name"] = service_name
        captured.update(kwargs)
        return FakeS3()

    monkeypatch.setattr("threat_report_agent.content_store.boto3.client", fake_client)

    S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
    )

    config = captured["config"]
    assert captured["service_name"] == "s3"
    assert config.signature_version == "s3v4"
    assert config.s3["addressing_style"] == "path"


def test_s3_audit_payload_uses_distinct_object_lock_bucket() -> None:
    client = MissingAuditBucketS3()
    store = S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
        client=client,
        audit_bucket="audit-seals",
        audit_object_lock_mode="COMPLIANCE",
        audit_object_lock_days=30,
    )

    stored = store.put_immutable(b"signed audit payload")

    assert client.created_bucket == {
        "Bucket": "audit-seals",
        "ObjectLockEnabledForBucket": True,
    }
    assert client.lock_put is not None
    assert client.lock_put["Bucket"] == "audit-seals"
    assert client.lock_put["ObjectLockMode"] == "COMPLIANCE"
    assert client.lock_put["ObjectLockRetainUntilDate"] is not None
    assert stored.storage_key.startswith("audit/sha256/")
    assert store.read(stored.storage_key) == b"signed audit payload"
    with pytest.raises(PermissionError, match="immutable"):
        store.delete(stored.storage_key)


def test_s3_audit_payload_fails_closed_without_object_lock() -> None:
    store = S3ContentStore(
        "http://minio.test",
        "analysis-content",
        "access-key",
        "secret-key",
        client=UnlockedAuditBucketS3(),
        audit_bucket="audit-seals",
    )

    with pytest.raises(RuntimeError, match="Object Lock"):
        store.put_immutable(b"unprotected audit payload")


def test_scoped_tool_store_rejects_every_object_outside_its_grant() -> None:
    input_content = b"scoped input"
    calls: list[tuple[str, str, bytes | None]] = []

    class Response:
        def __init__(self, content: bytes = b"") -> None:
            self.content = content

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return self.content

    def open_request(request, *, timeout: int):
        calls.append((request.get_method(), request.full_url, request.data))
        assert timeout == 60
        return Response(input_content if request.get_method() == "GET" else b"")

    grant = ToolRunStorageGrant(
        input_storage_key="sha256/aa/bb/" + hashlib.sha256(input_content).hexdigest(),
        input_url="http://minio.test/scoped-input",
        output_storage_key="tool-runs/run-1/output.json",
        output_url="http://minio.test/scoped-output",
    )
    store = ScopedToolRunContentStore(grant, opener=open_request)

    assert store.read(grant.input_storage_key) == input_content
    stored = store.put(b'{"kind":"static"}')
    assert stored.storage_key == grant.output_storage_key
    with pytest.raises(ValueError, match="outside the ToolRun grant"):
        store.read("sha256/ff/ff/" + "f" * 64)
    assert calls == [
        ("GET", grant.input_url, None),
        ("PUT", grant.output_url, b'{"kind":"static"}'),
    ]
