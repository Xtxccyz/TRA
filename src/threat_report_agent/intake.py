from __future__ import annotations

import io
import zipfile
import zlib
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath


class IntakeError(ValueError):
    pass


class IntakeGateRequired(IntakeError):
    def __init__(self, reason: str, context: dict[str, object] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.context = context or {}


@dataclass(frozen=True)
class PackageEntry:
    logical_path: str
    content: bytes
    parent_path: str | None
    discovery: str
    is_container: bool = False
    content_sha256: str | None = None
    storage_key: str | None = None
    stored_size: int | None = None
    detected_type: str | None = None
    mime_type: str | None = None
    type_source: str | None = None

    @property
    def size(self) -> int:
        return self.stored_size if self.stored_size is not None else len(self.content)


def _safe_member_name(name: str) -> str:
    normalized = name.replace(chr(92), "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise IntakeGateRequired("Archive contains an unsafe path", {"entry": name})
    clean = "/".join(part for part in path.parts if part not in {"", "."})
    if not clean:
        raise IntakeGateRequired("Archive contains an empty path", {"entry": name})
    return clean


def _expand_zip(
    archive_content: bytes,
    archive_path: str,
    depth: int,
    *,
    max_files: int,
    max_bytes: int,
    max_depth: int,
    archive_password: str | None,
    entries: list[PackageEntry],
    seen_paths: set[str],
    total_size: int,
) -> int:
    if depth > max_depth:
        raise IntakeGateRequired(
            "Nested archive depth exceeds the configured limit",
            {"archive": archive_path, "max_depth": max_depth},
        )
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_content))
    except zipfile.BadZipFile as exc:
        raise IntakeGateRequired(
            "ZIP structure is invalid or unsupported", {"archive": archive_path}
        ) from exc
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            encrypted = bool(info.flag_bits & 0x1)
            if encrypted and archive_password is None:
                raise IntakeGateRequired(
                    "Encrypted ZIP entry requires a password",
                    {"archive": archive_path, "entry": info.filename},
                )
            member_name = _safe_member_name(info.filename)
            logical_path = f"{archive_path}!/{member_name}"
            if logical_path in seen_paths:
                raise IntakeGateRequired(
                    "Archive contains duplicate logical paths", {"entry": logical_path}
                )
            if len(entries) >= max_files:
                raise IntakeGateRequired(
                    "Sample package exceeds the configured file count",
                    {"max_files": max_files},
                )
            if info.file_size < 0 or total_size + info.file_size > max_bytes:
                raise IntakeGateRequired(
                    "Expanded sample package exceeds the configured size limit",
                    {"entry": logical_path, "max_bytes": max_bytes},
                )
            try:
                member_content = archive.read(
                    info,
                    pwd=archive_password.encode("utf-8") if encrypted else None,
                )
            except (
                EOFError,
                NotImplementedError,
                RuntimeError,
                zipfile.BadZipFile,
                zlib.error,
            ) as exc:
                raise IntakeGateRequired(
                    "Encrypted ZIP password was rejected"
                    if encrypted
                    else "ZIP entry could not be read",
                    {"archive": archive_path, "entry": info.filename},
                ) from exc
            if len(member_content) != info.file_size:
                raise IntakeGateRequired(
                    "Archive entry size does not match metadata", {"entry": logical_path}
                )
            total_size += len(member_content)
            is_container = zipfile.is_zipfile(io.BytesIO(member_content))
            entries.append(
                PackageEntry(
                    logical_path=logical_path,
                    content=member_content,
                    parent_path=archive_path,
                    discovery="archive_extracted",
                    is_container=is_container,
                )
            )
            seen_paths.add(logical_path)
            if is_container:
                total_size = _expand_zip(
                    member_content,
                    logical_path,
                    depth + 1,
                    max_files=max_files,
                    max_bytes=max_bytes,
                    max_depth=max_depth,
                    archive_password=archive_password,
                    entries=entries,
                    seen_paths=seen_paths,
                    total_size=total_size,
                )
    return total_size


def expand_submission(
    filename: str,
    content: bytes,
    *,
    max_files: int,
    max_bytes: int,
    max_depth: int,
    archive_password: str | None = None,
) -> list[PackageEntry]:
    if len(content) > max_bytes:
        raise IntakeGateRequired(
            "Submitted package exceeds the configured size limit",
            {"size": len(content), "max_bytes": max_bytes},
        )
    root_name = PurePosixPath(filename.replace(chr(92), "/")).name or "sample.bin"
    root_is_container = zipfile.is_zipfile(io.BytesIO(content))
    entries = [
        PackageEntry(
            logical_path=root_name,
            content=content,
            parent_path=None,
            discovery="submitted",
            is_container=root_is_container,
        )
    ]
    seen_paths = {root_name}
    if root_is_container:
        _expand_zip(
            content,
            root_name,
            1,
            max_files=max_files,
            max_bytes=max_bytes,
            max_depth=max_depth,
            archive_password=archive_password,
            entries=entries,
            seen_paths=seen_paths,
            total_size=len(content),
        )
    return entries


def expand_directory_entries(
    submitted_entries: list[PackageEntry],
    *,
    max_files: int,
    max_bytes: int,
    max_depth: int,
    archive_password: str | None = None,
) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    seen_paths: set[str] = set()
    total_size = 0
    for submitted in submitted_entries:
        if submitted.parent_path is not None:
            raise IntakeError("Directory root entries cannot have a parent")
        if len(entries) >= max_files:
            raise IntakeGateRequired(
                "Sample folder exceeds the configured file count",
                {"max_files": max_files},
            )
        if total_size + submitted.size > max_bytes:
            raise IntakeGateRequired(
                "Sample folder exceeds the configured size limit",
                {"path": submitted.logical_path, "max_bytes": max_bytes},
            )
        if submitted.logical_path in seen_paths:
            raise IntakeGateRequired(
                "Sample folder contains duplicate logical paths",
                {"path": submitted.logical_path},
            )
        is_container = zipfile.is_zipfile(io.BytesIO(submitted.content))
        root = replace(submitted, is_container=is_container)
        entries.append(root)
        seen_paths.add(root.logical_path)
        total_size += root.size
        if is_container:
            total_size = _expand_zip(
                root.content,
                root.logical_path,
                1,
                max_files=max_files,
                max_bytes=max_bytes,
                max_depth=max_depth,
                archive_password=archive_password,
                entries=entries,
                seen_paths=seen_paths,
                total_size=total_size,
            )
    return entries


def expand_directory(
    directory: str | Path,
    *,
    max_files: int,
    max_bytes: int,
    max_depth: int = 3,
    archive_password: str | None = None,
    expand_archives: bool = True,
) -> list[PackageEntry]:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise IntakeError(f"Directory does not exist: {root}")
    entries: list[PackageEntry] = []
    seen_paths: set[str] = set()
    total_size = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise IntakeGateRequired(
                "Sample folder contains a symbolic link",
                {"path": path.relative_to(root).as_posix()},
            )
        if not path.is_file():
            continue
        if len(entries) >= max_files:
            raise IntakeGateRequired(
                "Sample folder exceeds the configured file count",
                {"max_files": max_files},
            )
        size = path.stat().st_size
        if total_size + size > max_bytes:
            raise IntakeGateRequired(
                "Sample folder exceeds the configured size limit",
                {"path": path.relative_to(root).as_posix(), "max_bytes": max_bytes},
            )
        content = path.read_bytes()
        total_size += len(content)
        relative = path.relative_to(root).as_posix()
        logical_path = f"{root.name}/{relative}"
        if logical_path in seen_paths:
            raise IntakeGateRequired(
                "Sample folder contains duplicate logical paths",
                {"path": logical_path},
            )
        is_container = zipfile.is_zipfile(io.BytesIO(content))
        entries.append(
            PackageEntry(
                logical_path=logical_path,
                content=content,
                parent_path=None,
                discovery="submitted_folder",
                is_container=is_container,
            )
        )
        seen_paths.add(logical_path)
    if not entries:
        raise IntakeGateRequired("Sample folder contains no files", {"directory": root.name})
    if not expand_archives:
        return entries
    return expand_directory_entries(
        entries,
        max_files=max_files,
        max_bytes=max_bytes,
        max_depth=max_depth,
        archive_password=archive_password,
    )
