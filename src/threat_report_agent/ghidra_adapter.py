from __future__ import annotations

import json
import os
import re
import signal
import struct
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from threat_report_agent.static_analysis import function_fuzzy_fingerprint


GHIDRA_OUTPUT_SCHEMA_VERSION = "1.0"


def validate_ghidra_output(output: object) -> dict[str, object]:
    """Validate and normalize the versioned JSON emitted by the Ghidra exporter.

    Worker images may lag the API image during a rolling deployment.  A missing
    schema field is therefore treated as the original 1.0 contract and
    backfilled, while malformed collections are rejected before evidence is
    materialized.
    """
    if not isinstance(output, dict):
        raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
    normalized = dict(output)
    schema_version = normalized.get("schema_version")
    if schema_version is None:
        normalized["schema_version"] = GHIDRA_OUTPUT_SCHEMA_VERSION
    elif schema_version != GHIDRA_OUTPUT_SCHEMA_VERSION:
        raise ValueError("GHIDRA_OUTPUT_UNSUPPORTED_SCHEMA")

    functions = normalized.get("functions")
    symbols = normalized.get("symbols")
    if not isinstance(functions, list) or not isinstance(symbols, list):
        raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
    for function in functions:
        if not isinstance(function, dict):
            raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
        for field in ("mnemonics", "references_from", "xrefs_to_entry", "cfg_blocks"):
            value = function.get(field)
            if value is not None and not isinstance(value, list):
                raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
        mnemonics = function.get("mnemonics", [])
        if not all(isinstance(item, str) for item in mnemonics):
            raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
    if not all(isinstance(symbol, dict) for symbol in symbols):
        raise ValueError("GHIDRA_OUTPUT_INVALID_SCHEMA")
    return normalized


@dataclass(frozen=True)
class GhidraRun:
    status: str
    output: dict[str, object]
    stdout: str
    stderr: str
    error: str | None = None


class GhidraHeadlessRunner:
    """Runs Ghidra against a copy of submitted content; it never executes the program."""

    def __init__(self, ghidra_home: str | Path, java_home: str | Path = "") -> None:
        self.ghidra_home = Path(ghidra_home).resolve()
        self.java_home = Path(java_home).resolve() if java_home else None
        self.export_script = Path(__file__).parent / "ghidra_scripts" / "ExportStaticFacts.java"

    @property
    def headless_path(self) -> Path:
        suffix = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        return self.ghidra_home / "support" / suffix

    @property
    def java_path(self) -> Path | None:
        if self.java_home is None:
            return None
        executable = "java.exe" if os.name == "nt" else "java"
        return self.java_home / "bin" / executable

    def configuration(self) -> dict[str, object]:
        return {
            "available": self.headless_path.is_file()
            and self.export_script.is_file()
            and (self.java_path is None or self.java_path.is_file()),
            "ghidra_home": str(self.ghidra_home),
            "java_home": str(self.java_home) if self.java_home else None,
            "headless_path": str(self.headless_path),
            "export_script": str(self.export_script),
        }

    @staticmethod
    def safe_input_name(logical_path: str) -> str:
        suffix = re.sub(r"[^A-Za-z0-9.]", "_", Path(logical_path).suffix)[:32]
        return "sample" + (suffix if suffix else ".bin")

    @staticmethod
    def _prepare_analysis_content(
        content: bytes,
        processor: str | None,
    ) -> tuple[bytes, str | None]:
        """Apply a narrowly scoped repair for a zeroed PE Machine field.

        Some malware samples intentionally or accidentally clear the COFF
        Machine field.  Ghidra then selects a 16-bit language despite the
        PE32 optional header and produces unrelated functions.  The original
        artifact is never changed: only the temporary Ghidra input receives
        the I386 value after a verified x86 processor override.
        """
        if processor != "x86:LE:32:default" or len(content) < 0x40:
            return content, None
        if content[:2] != b"MZ":
            return content, None
        pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
        if pe_offset < 0 or pe_offset + 26 > len(content):
            return content, None
        if content[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return content, None
        machine = struct.unpack_from("<H", content, pe_offset + 4)[0]
        optional_magic = struct.unpack_from("<H", content, pe_offset + 24)[0]
        if machine != 0 or optional_magic != 0x10B:
            return content, None
        normalized = bytearray(content)
        struct.pack_into("<H", normalized, pe_offset + 4, 0x014C)
        return bytes(normalized), "PE_MACHINE_ZERO_NORMALIZED_TO_I386"

    def analyze(
        self,
        content: bytes,
        logical_path: str,
        timeout_seconds: int = 600,
        cancellation_requested: Callable[[], bool] | None = None,
        processor: str | None = None,
    ) -> GhidraRun:
        configuration = self.configuration()
        if not configuration["available"]:
            return GhidraRun("FAILED", {}, "", "", "GHIDRA_HEADLESS_UNAVAILABLE")
        safe_name = self.safe_input_name(logical_path)
        with tempfile.TemporaryDirectory(prefix="threat-report-ghidra-") as temporary:
            root = Path(temporary)
            input_path = root / safe_name
            output_path = root / "static-facts.json"
            project_directory = root / "project"
            project_directory.mkdir()
            analysis_content, _ = self._prepare_analysis_content(content, processor)
            input_path.write_bytes(analysis_content)
            command = [
                str(self.headless_path),
                str(project_directory),
                "analysis",
            ]
            if processor:
                # Ghidra normally derives the language from the file header.
                # A malformed PE may have an empty Machine field, so callers
                # may provide a verified processor override for a bounded
                # retry. Keep it as one argument to avoid shell interpretation.
                command.extend(["-processor", processor])
            command.extend([
                "-import",
                str(input_path),
                "-overwrite",
                "-scriptPath",
                str(self.export_script.parent),
                "-postScript",
                self.export_script.name,
                str(output_path),
            ])
            environment = os.environ.copy()
            if self.java_home:
                environment["JAVA_HOME"] = str(self.java_home)
                environment["PATH"] = (
                    str(self.java_home / "bin") + os.pathsep + environment.get("PATH", "")
                )
            if cancellation_requested is None:
                try:
                    completed = subprocess.run(
                        command,
                        cwd=root,
                        env=environment,
                        capture_output=True,
                        text=True,
                        errors="replace",
                        timeout=timeout_seconds,
                        check=False,
                        shell=False,
                    )
                except subprocess.TimeoutExpired as exc:
                    return GhidraRun(
                        "TIMED_OUT", {}, exc.stdout or "", exc.stderr or "", "GHIDRA_TIMEOUT"
                    )
                return self._read_completed_run(
                    completed.returncode,
                    completed.stdout,
                    completed.stderr,
                    output_path,
                )

            process_options: dict[str, object] = {}
            if os.name == "nt":
                process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                process_options["start_new_session"] = True
            process = subprocess.Popen(
                command,
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                shell=False,
                **process_options,
            )
            deadline = time.monotonic() + timeout_seconds
            while True:
                if cancellation_requested():
                    self._terminate_process_tree(process)
                    stdout, stderr = process.communicate()
                    return GhidraRun("CANCELLED", {}, stdout, stderr, "GHIDRA_CANCELLED")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_process_tree(process)
                    stdout, stderr = process.communicate()
                    return GhidraRun("TIMED_OUT", {}, stdout, stderr, "GHIDRA_TIMEOUT")
                try:
                    stdout, stderr = process.communicate(timeout=min(0.5, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            return self._read_completed_run(process.returncode, stdout, stderr, output_path)

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                process.terminate()
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            if os.name == "nt":
                process.kill()
            else:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except OSError:
                    process.kill()
            process.wait(timeout=5)

    @staticmethod
    def _read_completed_run(
        returncode: int,
        stdout: str,
        stderr: str,
        output_path: Path,
    ) -> GhidraRun:
        if returncode != 0 or not output_path.is_file():
            return GhidraRun("FAILED", {}, stdout, stderr, "GHIDRA_HEADLESS_FAILED")
        try:
            output = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return GhidraRun("FAILED", {}, stdout, stderr, "GHIDRA_OUTPUT_INVALID_JSON")
        try:
            output = validate_ghidra_output(output)
        except ValueError as exc:
            return GhidraRun("FAILED", {}, stdout, stderr, str(exc))
        for function in output.get("functions", []):
            mnemonics = function.get("mnemonics", [])
            function["fuzzy_fingerprint"] = function_fuzzy_fingerprint(mnemonics)
        return GhidraRun("SUCCEEDED", output, stdout, stderr)
