from __future__ import annotations

import io
import zipfile

import py7zr
import pytest

from threat_report_agent.intake import IntakeGateRequired, expand_directory, expand_submission


def make_zip(path: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(path, content)
    return output.getvalue()


def make_nested_zip() -> bytes:
    inner = make_zip("payload.bin", b"nested payload")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("inner.zip", inner)
    return output.getvalue()


def make_7z(path: str, content: bytes, *, password: str | None = None) -> bytes:
    output = io.BytesIO()
    with py7zr.SevenZipFile(
        output,
        "w",
        # Keep the in-memory fixture deterministic on constrained CI/worker
        # hosts.  py7zr's default preset is tuned for large archives and can
        # allocate hundreds of megabytes even for this tiny test payload.
        filters=[{"id": py7zr.FILTER_LZMA2, "preset": 0}],
        password=password,
        header_encryption=bool(password),
    ) as archive:
        archive.writestr(content, path)
    return output.getvalue()


def mark_zip_entry_encrypted(content: bytes) -> bytes:
    data = bytearray(content)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        offset = 0
        while True:
            offset = data.find(signature, offset)
            if offset < 0:
                break
            flags = int.from_bytes(data[offset + flag_offset : offset + flag_offset + 2], "little")
            data[offset + flag_offset : offset + flag_offset + 2] = (flags | 0x1).to_bytes(
                2, "little"
            )
            offset += len(signature)
    return bytes(data)


def test_zip_preserves_container_path_and_parent() -> None:
    content = make_zip("folder/payload.txt", b"sample")

    entries = expand_submission(
        "bundle.zip",
        content,
        max_files=10,
        max_bytes=1024 * 1024,
        max_depth=2,
    )

    assert [entry.logical_path for entry in entries] == [
        "bundle.zip",
        "bundle.zip!/folder/payload.txt",
    ]
    assert entries[1].parent_path == "bundle.zip"


def test_zip_path_traversal_requires_input_gate() -> None:
    content = make_zip("../escape.bin", b"not executed")

    with pytest.raises(IntakeGateRequired, match="unsafe path"):
        expand_submission(
            "bundle.zip",
            content,
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=2,
        )


def test_7z_expands_through_the_same_bounded_static_intake_path() -> None:
    content = make_7z("nested/stage.py", b"import socket\n")

    entries = expand_submission(
        "bundle.7z",
        content,
        max_files=10,
        max_bytes=1024 * 1024,
        max_depth=2,
    )

    assert [entry.logical_path for entry in entries] == [
        "bundle.7z",
        "bundle.7z!/nested/stage.py",
    ]
    assert entries[0].is_container is True
    assert entries[1].content == b"import socket\n"


def test_encrypted_7z_requires_the_existing_input_gate_password() -> None:
    content = make_7z("payload.bin", b"static bytes", password="unit-secret")

    with pytest.raises(IntakeGateRequired, match="requires a password"):
        expand_submission(
            "bundle.7z",
            content,
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=2,
        )

    with pytest.raises(IntakeGateRequired, match="password was rejected"):
        expand_submission(
            "bundle.7z",
            content,
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=2,
            archive_password="wrong",
        )

    entries = expand_submission(
        "bundle.7z",
        content,
        max_files=10,
        max_bytes=1024 * 1024,
        max_depth=2,
        archive_password="unit-secret",
    )
    assert entries[-1].content == b"static bytes"


def test_corrupt_deflate_zip_requires_input_gate() -> None:
    content = bytearray(make_zip("payload.bin", b"ABCD" * 100))
    filename_size = int.from_bytes(content[26:28], "little")
    extra_size = int.from_bytes(content[28:30], "little")
    payload_offset = 30 + filename_size + extra_size
    content[payload_offset] ^= 0xFF

    with pytest.raises(IntakeGateRequired, match="could not be read"):
        expand_submission(
            "bundle.zip",
            bytes(content),
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=2,
        )


def test_directory_preserves_relative_paths(tmp_path) -> None:
    sample_dir = tmp_path / "sample-folder"
    nested = sample_dir / "sub"
    nested.mkdir(parents=True)
    (sample_dir / "loader.txt").write_bytes(b"VirtualAlloc")
    (nested / "config.txt").write_bytes(b"http://evil.example.com")

    entries = expand_directory(sample_dir, max_files=10, max_bytes=1024 * 1024)

    assert [entry.logical_path for entry in entries] == [
        "sample-folder/loader.txt",
        "sample-folder/sub/config.txt",
    ]
    assert all(entry.discovery == "submitted_folder" for entry in entries)


def test_directory_recursively_expands_nested_zip(tmp_path) -> None:
    sample_dir = tmp_path / "sample-folder"
    sample_dir.mkdir()
    (sample_dir / "outer.zip").write_bytes(make_nested_zip())

    entries = expand_directory(
        sample_dir,
        max_files=10,
        max_bytes=1024 * 1024,
        max_depth=2,
    )

    assert [entry.logical_path for entry in entries] == [
        "sample-folder/outer.zip",
        "sample-folder/outer.zip!/inner.zip",
        "sample-folder/outer.zip!/inner.zip!/payload.bin",
    ]
    assert entries[1].parent_path == "sample-folder/outer.zip"
    assert entries[2].parent_path == "sample-folder/outer.zip!/inner.zip"
    assert entries[1].is_container is True


def test_directory_nested_zip_depth_is_bounded(tmp_path) -> None:
    sample_dir = tmp_path / "sample-folder"
    sample_dir.mkdir()
    (sample_dir / "outer.zip").write_bytes(make_nested_zip())

    with pytest.raises(IntakeGateRequired, match="depth"):
        expand_directory(
            sample_dir,
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=1,
        )


def test_directory_archive_limits_apply_across_multiple_archives(tmp_path) -> None:
    sample_dir = tmp_path / "sample-folder"
    sample_dir.mkdir()
    first = make_zip("first.bin", b"a" * 2048)
    second = make_zip("second.bin", b"b" * 2048)
    (sample_dir / "first.zip").write_bytes(first)
    (sample_dir / "second.zip").write_bytes(second)

    with pytest.raises(IntakeGateRequired, match="file count"):
        expand_directory(
            sample_dir,
            max_files=3,
            max_bytes=1024 * 1024,
            max_depth=1,
        )

    with pytest.raises(IntakeGateRequired, match="size"):
        expand_directory(
            sample_dir,
            max_files=10,
            max_bytes=len(first) + len(second) + 2048 * 2 - 1,
            max_depth=1,
        )


def test_directory_encrypted_zip_requires_password(tmp_path) -> None:
    sample_dir = tmp_path / "sample-folder"
    sample_dir.mkdir()
    archive = mark_zip_entry_encrypted(make_zip("payload.bin", b"secret"))
    (sample_dir / "archive.zip").write_bytes(archive)

    with pytest.raises(IntakeGateRequired, match="password"):
        expand_directory(
            sample_dir,
            max_files=10,
            max_bytes=1024 * 1024,
            max_depth=1,
        )
