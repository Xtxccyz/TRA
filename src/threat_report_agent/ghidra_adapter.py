from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from threat_report_agent.static.static_analysis import function_fuzzy_fingerprint


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

    def environment(self) -> dict[str, str]:
        """The child environment for every headless launch. ONE implementation, two callers."""
        environment = os.environ.copy()
        if self.java_home:
            environment["JAVA_HOME"] = str(self.java_home)
            environment["PATH"] = (
                str(self.java_home / "bin") + os.pathsep + environment.get("PATH", "")
            )
        return environment

    def _headless_command(
        self,
        project_directory: str | Path,
        *,
        import_path: str | Path | None = None,
        processor: str | None = None,
        script: str | Path | None = None,
        script_args: Sequence[str] = (),
    ) -> list[str]:
        """The ONE place a `analyzeHeadless` command line is built.

        Argument ORDER is part of this function's contract: `[headless, project, analysis]`, then the optional
        `-processor <value>`, then `-import <path> -overwrite`, then `-scriptPath <dir> -postScript <name> <args...>`.
        The existing adapter tests index into positions 3/4, and the export script reads its output path as the
        LAST argument, so a new script argument must be inserted BEFORE it - never appended after.
        """
        command = [str(self.headless_path), str(project_directory), "analysis"]
        if processor:
            # Ghidra normally derives the language from the file header.  A malformed PE may have an empty
            # Machine field, so callers may provide a verified processor override for a bounded retry. Keep it
            # as one argument to avoid shell interpretation.
            command.extend(["-processor", processor])
        if import_path is not None:
            command.extend(["-import", str(import_path), "-overwrite"])
        if script is not None:
            script_path = Path(script)
            command.extend(["-scriptPath", str(script_path.parent), "-postScript", script_path.name])
            command.extend(str(argument) for argument in script_args)
        return command

    def _export_script_args(
        self,
        output_path: str | Path,
        requested_entries: Sequence[str],
        decompile_budget_seconds: int,
    ) -> list[str]:
        """Script arguments for `ExportStaticFacts.java`.

        With no requested entries the legacy single-argument form is emitted verbatim, so a caller that does not
        ask for pseudo-C produces exactly the command it produced before this seam existed. With requested
        entries the entry list and the PER-DECOMPILE budget are passed FIRST and the output path stays last.
        Every entry is normalised through `entry_identity`, which returns None for anything that is not a hex
        address, so no caller-controlled string other than a normalised address can reach the command line.

        The budget is the run's own external deadline, passed in by the caller - this function does not choose a
        decompile timeout.
        """
        identities = [identity for identity in (entry_identity(item) for item in requested_entries) if identity]
        if not identities:
            return [str(output_path)]
        return [",".join(identities), str(int(decompile_budget_seconds)), str(output_path)]

    def serve_follow_up_queries(
        self,
        content: bytes,
        logical_path: str,
        frozen: "FrozenDump",
        *,
        entries: Sequence[str] = (),
        timeout_seconds: int = 600,
        deadline_source: Mapping[str, object] | None = None,
        cancellation_requested: Callable[[], bool] | None = None,
        deadline_at: float | None = None,
        run_started_at: float | None = None,
    ) -> dict[str, object]:
        """Start the RESIDENT service once, ask it every follow-up question, then shut it down.

        This is the whole resident lifecycle in one call, because the lifecycle is the seam: a caller that had to
        launch the process, poll for readiness, open the socket and remember to shut it down would get one of
        those wrong. `entries` defaults to the entries the frozen dump was asked to record.

        The resident is started strictly AFTER the one-shot export that produced `frozen` has exited and is shut
        down before this method returns: it shares `$HOME=/work` - and therefore Ghidra's config and packed-db
        cache - with any concurrent headless run, and the gate owner's own measurement
        (`.scratch/ghidra-c3/preflight/p6-concurrency-relation.json`) shows a THIRD concurrent launcher in the
        same container dies with `Unable to prompt user for JDK path, no TTY detected`. Serialising the resident
        against the exporter removes that race instead of hoping it does not fire.
        """
        configuration = self.configuration()
        started = run_started_at if run_started_at is not None else time.monotonic()
        if deadline_at is None:
            deadline_at = started + float(timeout_seconds)
        if not configuration["available"]:
            return _follow_up_summary(
                frozen,
                [],
                [],
                deadline_source=deadline_source,
                transcript="",
                resident_error="GHIDRA_HEADLESS_UNAVAILABLE",
            )
        wanted = [identity for identity in (entry_identity(item) for item in entries) if identity]
        if not wanted:
            wanted = [identity for identity in frozen.requested_entries if identity]
        resident_script = self.export_script.parent / "ServeFollowUpQueries.java"
        if not resident_script.is_file():
            return _follow_up_summary(
                frozen,
                wanted,
                [],
                deadline_source=deadline_source,
                transcript="",
                resident_error="GHIDRA_RESIDENT_SCRIPT_MISSING",
            )
        with tempfile.TemporaryDirectory(prefix="threat-report-ghidra-followup-") as temporary:
            root = Path(temporary)
            input_path = root / self.safe_input_name(logical_path)
            input_path.write_bytes(content)
            project_directory = root / "project"
            project_directory.mkdir()
            ready_path = root / "resident.port"
            transcript_path = root / "resident.transcript"
            command = self._headless_command(
                project_directory,
                import_path=input_path,
                script=resident_script,
                script_args=[str(ready_path), str(transcript_path), str(int(timeout_seconds))],
            )
            process_options: dict[str, object] = {}
            if os.name == "nt":
                process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                process_options["start_new_session"] = True
            process = subprocess.Popen(
                command,
                cwd=root,
                env=self.environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                shell=False,
                **process_options,
            )
            deadline = float(deadline_at)
            port: int | None = None
            resident_error: str | None = None
            summary: dict[str, object] | None = None
            try:
                while time.monotonic() < deadline:
                    if ready_path.is_file():
                        candidate = ready_path.read_text(encoding="utf-8").strip()
                        if candidate.isdigit() and int(candidate) > 0:
                            port = int(candidate)
                            break
                    if process.poll() is not None:
                        break
                    if cancellation_requested is not None and cancellation_requested():
                        resident_error = "GHIDRA_FOLLOW_UP_CANCELLED"
                        break
                    time.sleep(0.1)
                if port is None and resident_error is None:
                    resident_error = "GHIDRA_RESIDENT_UNAVAILABLE"
                # THE QUERY LOOP RUNS WHILE THE RESIDENT IS ALIVE. MEASURED (P-7 container acceptance, first
                # run): an earlier version of this refactor called `run_resident_queries` AFTER the `finally`
                # block below had already shut the resident down, so every query came back
                # `GHIDRA_RESIDENT_UNAVAILABLE` - the injected-transport tests cannot see that ordering, and the
                # container caught it. The loop itself is still the ONE shared implementation, so the deadline,
                # the cancellation check, `stopped_reason` and the published set difference cannot drift between
                # this real-socket path and the focused tests.
                if resident_error is None:
                    summary = run_resident_queries(
                        frozen,
                        entries=wanted,
                        deadline_at=deadline,
                        deadline_source=deadline_source,
                        run_started_at=started,
                        timeout_seconds=timeout_seconds,
                        transport_factory=lambda sealed_dump: loopback_query_transport(int(port)),
                        cancellation_requested=cancellation_requested,
                    )
            finally:
                transcript = (
                    transcript_path.read_text(encoding="utf-8", errors="replace")
                    if transcript_path.is_file()
                    else ""
                )
                shutdown = self._shutdown_resident(process, port)
            if summary is None:
                summary = run_resident_queries(
                    frozen,
                    entries=wanted,
                    deadline_at=deadline,
                    deadline_source=deadline_source,
                    run_started_at=started,
                    timeout_seconds=timeout_seconds,
                    resident_error=resident_error or "GHIDRA_RESIDENT_UNAVAILABLE",
                )
            summary["resident"] = {
                "shutdown": dict(shutdown or {}),
                "transcript": str(transcript or "")[-4000:],
                "error": resident_error or "",
            }
            return summary

    def follow_up_batch(
        self,
        content: bytes,
        logical_path: str,
        export_output: Mapping[str, object],
        *,
        entries: Sequence[str],
        timeout_seconds: int,
        dump_directory: str | Path,
        deadline_source: Mapping[str, object] | None = None,
        cancellation_requested: Callable[[], bool] | None = None,
    ) -> dict[str, object]:
        """Freeze the one-shot export, then answer follow-up queries about it. One call, three phases.

        Phase 1 is the comparison export: the SAME bytes are exported a second time so the dump can be sealed
        WITH its measured instability (plan §10.2 C3). Without that second measurement a dump could only claim
        its fields are stable, which `.scratch/u1-b2-decision.md` already falsified.

        Phase 2 seals D content-addressed and read-only.

        Phase 3 runs the resident service and asks it about every requested entry, each answer being compared
        against D's own record for that `entry` (never against the comparison export - that is what §10.1
        forbids).

        A failure in phase 1 is terminal for the batch: a dump that cannot be sealed with its instability record
        is not evidence, so the batch returns BLOCKED with an explicit limitation and publishes nothing.

        THE DEADLINE IS ONE ABSOLUTE INSTANT FOR THE WHOLE BATCH (P-7). It is read from the NAMED source the
        caller passed (`deadline_source["value"]`), never chosen here and never shrunk: §11.2 forbids a smaller
        number invented inside product code, and the gate owner's measurement
        (`.scratch/ghidra-c3/preflight/p7-export-deadline-probe.json`) shows the one-shot export finishes 81/81
        entries in ~10 s, so the phase a small deadline can honestly stop is the RESIDENT one. The comparison
        export is therefore bounded by what is LEFT of that instant, and the resident phase gets the same
        instant - not a fresh budget.
        """
        identities = sorted(
            {identity for identity in (entry_identity(item) for item in entries) if identity},
            key=lambda item: int(item, 16),
        )
        started = time.monotonic()
        deadline, deadline_record = _resolve_deadline(None, timeout_seconds, deadline_source)
        if not identities:
            return self._batch_failure(
                "GHIDRA_FOLLOW_UP_NO_REQUESTED_ENTRIES",
                "no entry was requested, so there is nothing to decompile and nothing to query; an empty request "
                "set must not be reported as a successful follow-up",
                deadline=deadline_record,
            )
        if deadline - time.monotonic() <= 0:
            # The named deadline was already spent before the dump could be sealed. This is a FAILED batch, not a
            # stopped one: nothing was measured, so no per-entry outcome and no set difference exists to publish,
            # and it is given its own reason rather than being reported as a deadline-stopped run.
            return self._batch_failure(
                "GHIDRA_FOLLOW_UP_DEADLINE_BEFORE_COMPARISON_EXPORT",
                "the named external deadline was already reached before the comparison export, so no dump was "
                "sealed and no requested entry was queried",
                deadline=deadline_record,
            )
        comparison = self.analyze(
            content,
            logical_path,
            max(1, int(deadline - time.monotonic())),
            cancellation_requested=cancellation_requested,
            requested_entries=identities,
        )
        if comparison.status != "SUCCEEDED":
            return self._batch_failure(
                "GHIDRA_FROZEN_DUMP_COMPARISON_EXPORT_FAILED",
                f"the second (comparison) export did not succeed ({comparison.status}/{comparison.error}), so the "
                "dump's instability could not be measured and it must not be sealed",
                deadline=deadline_record,
            )
        instability = compute_dump_instability(export_output, comparison.output)
        frozen = seal_frozen_dump(
            export_output,
            instability,
            dump_directory,
            requested_entries=identities,
        )
        summary = self.serve_follow_up_queries(
            content,
            logical_path,
            frozen,
            entries=identities,
            timeout_seconds=timeout_seconds,
            deadline_source=deadline_record,
            cancellation_requested=cancellation_requested,
            deadline_at=deadline,
            run_started_at=started,
        )
        summary["frozen_dump_path"] = str(frozen.path)
        summary["instability"] = {
            "identity_key": instability["identity_key"],
            "candidate_fields": instability["candidate_fields"],
            "excluded_fields": instability["excluded_fields"],
            "unstable_fields": instability["unstable_fields"],
            "unstable_field_entries": instability["unstable_field_entries"],
            "stable_fields": instability["stable_fields"],
            "function_entries": instability["function_entries"],
            "document_fields": instability["document_fields"],
            "symbols": instability["symbols"],
            "source_note": instability["source_note"],
        }
        return summary

    @staticmethod
    def _batch_failure(code: str, detail: str, *, deadline: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema_version": GHIDRA_FOLLOW_UP_SCHEMA_VERSION,
            "status": "BLOCKED",
            "identity_key": ENTRY_IDENTITY_KEY,
            "dump_sha256": "",
            "requested_entries": [],
            "processed_entries": [],
            "unprocessed_entries": [],
            "entry_set_difference": {
                "identity_key": ENTRY_IDENTITY_KEY,
                "enumerated_set": [],
                "retrieved_set": [],
                "expected_minus_actual": [],
                "actual_minus_expected": [],
            },
            "outcomes": [],
            "limitations": [f"Ghidra resident follow-up query is BLOCKED ({code}): {detail}"],
            "summary_limitation": (
                f"Ghidra resident follow-up query is BLOCKED ({code}): {detail} No pseudo-C is published."
            ),
            "deadline": dict(deadline),
            "resident": {"shutdown": {}, "transcript": ""},
        }

    def _shutdown_resident(
        self, process: subprocess.Popen[str], port: int | None
    ) -> dict[str, object]:
        """Ask the resident to stop, then make sure the process is GONE before returning.

        The resident shares `$HOME=/work` with the exporter, so "the script returned" is not good enough: a JVM
        still tearing down while the next headless launch starts is the exact race the gate owner measured. The
        process exit code is reported so a caller can tell an orderly shutdown from a killed one.
        """
        asked = False
        if port is not None and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                    connection.sendall(b'{"op":"shutdown"}\n')
                    connection.shutdown(socket.SHUT_WR)
                    connection.makefile("r", encoding="utf-8").readline()
                asked = True
            except OSError:
                asked = False
        if process.poll() is None:
            try:
                process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self._terminate_process_tree(process)
                process.communicate()
        # P-7 DIAGNOSTIC (gate-owner finding #11): `analyzeHeadless` reports a post-script that throws by
        # `REPORT SCRIPT ERROR ... file:line` and can still exit 0, so a resident that "exited cleanly" without
        # ever answering is invisible unless its OWN output is captured. The process writes to a pipe; whatever it
        # produced is read here and returned with the exit code, so the next failure of this shape diagnoses itself
        # instead of needing two probes to see.
        output = ""
        try:
            stream = process.stdout
            if stream is not None:
                remaining = stream.read()
                output = remaining if isinstance(remaining, str) else str(remaining or "")
        except (OSError, ValueError):
            output = ""
        if not output:
            declared = getattr(process, "args", None)
            output = f"(the resident produced no stdout; launch command={declared!r})" if declared else ""
        return {
            "shutdown_requested": asked,
            "exit_code": process.returncode,
            "stdout_tail": str(output)[-2000:],
            "stdout_chars": len(str(output)),
        }

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
        requested_entries: Sequence[str] = (),
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
            command = self._headless_command(
                project_directory,
                import_path=input_path,
                processor=processor,
                script=self.export_script,
                script_args=self._export_script_args(output_path, requested_entries, timeout_seconds),
            )
            environment = self.environment()
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


# =====================================================================================================================
# P-6 / plan §10 (route B2): the frozen dump D, and the resident service that only answers follow-up queries.
#
# WHAT IS DIFFERENT HERE FROM EVERY OTHER GHIDRA CODE PATH IN THIS REPOSITORY. The one-shot headless export stays
# the producer of the dump - B2 forbids moving production into the resident service - and the resident service is
# asked ONLY about functions the frozen dump already contains. Every comparison a caller can make is therefore
# relative to the frozen bytes of D, never to a fresh headless run: `.scratch/u1-b2-decision.md` measured that two
# headless runs of identical bytes differ in 8 function fields and 4 of 8,826 symbols, so "compare against another
# run" is not a weaker check, it is a WRONG one.
#
# The identity key is `entry` (plan §10.1). Not the index in `functions`, not `fuzzy_fingerprint` (8/704 unstable),
# not the symbol order (substitutions were measured). `entry_identity` is the single normalisation both ends use.
# =====================================================================================================================

GHIDRA_FROZEN_DUMP_SCHEMA_VERSION = "1.0"
GHIDRA_RESIDENT_QUERY_SCHEMA_VERSION = "1.0"
GHIDRA_FOLLOW_UP_SCHEMA_VERSION = "1.0"
FROZEN_DUMP_KIND = "frozen_static_facts_dump"
ENTRY_IDENTITY_KEY = "entry"
SYMBOL_IDENTITY_KEY = "name|address|type"

#: Per-function fields that are EXCLUDED from the instability comparison, each with the reason it cannot be
#: compared. This is a declared exclusion list, not a silent one: `compute_dump_instability` publishes it in the
#: record, so a reader can see exactly which fields the reported stable/unstable split is about.
INSTABILITY_EXCLUDED_FIELDS: dict[str, str] = {
    "decompile_millis": "wall time of one decompiler call; a duration is not an observable of the program",
}

#: Document-level fields compared for instability (the per-function fields are discovered from the dumps
#: themselves, so this list can never be a stale transcription of the exporter's schema).
DOCUMENT_LEVEL_FIELDS: tuple[str, ...] = ("strings", "symbols", "image_base")


class FrozenDumpError(RuntimeError):
    """A frozen dump may not be used as evidence."""


class FrozenDumpIncomplete(FrozenDumpError):
    """The dump is readable but is missing its measured instability record (plan §10.2 C3)."""


class FrozenDumpTampered(FrozenDumpError):
    """The dump's bytes no longer hash to the digest that sealed them (plan §10.1)."""


class FollowUpUnavailable(RuntimeError):
    """The resident service could not answer at all: down, unloaded, or past its external deadline (C4)."""


def entry_identity(value: object) -> str | None:
    """The identity of a function: its `entry`, normalised to lower-case hex without a prefix or leading zeros.

    Ghidra prints an address padded to the address space (`00401000` on 32-bit, `140001000` on 64-bit) while a
    caller may write `0x401000`, so BOTH ends normalise and the raw `entry` string is still exported unchanged.
    Anything that is not a hex address returns None, which is also what keeps a caller-controlled string out of
    the headless command line.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text[:2].lower() == "0x":
        text = text[2:]
    if not text or any(character not in "0123456789abcdefABCDEF" for character in text):
        return None
    return format(int(text, 16), "x")


def run_follow_up_batch(
    runner: "GhidraHeadlessRunner",
    content: bytes,
    logical_path: str,
    export_output: Mapping[str, object],
    *,
    entries: Sequence[str],
    timeout_seconds: int,
    deadline_source: Mapping[str, object] | None = None,
    cancellation_requested: Callable[[], bool] | None = None,
    content_store: object | None = None,
) -> dict[str, object]:
    """`runner.follow_up_batch` plus the durability seam, in one call, for BOTH product call sites.

    The dump directory is a temporary one, so a sealed dump would not outlive the tool run that produced it.
    When a content store is available the sealed BYTES are written to it as well; the store is content-addressed
    by the same digest, so `frozen_dump_sha256`/`frozen_dump_storage_key` name bytes a later reader can re-verify
    with `open_frozen_dump(..., expected_sha256=...)`. `sealed_digest_matches_store` records that the local seal,
    the store's digest and the batch's declared dump digest are the SAME digest - three independent readings of
    one artifact, not one reading repeated.
    """
    with tempfile.TemporaryDirectory(prefix="threat-report-frozen-dump-") as dump_directory:
        summary = runner.follow_up_batch(
            content,
            logical_path,
            export_output,
            entries=entries,
            timeout_seconds=timeout_seconds,
            dump_directory=dump_directory,
            deadline_source=deadline_source,
            cancellation_requested=cancellation_requested,
        )
        path = str(summary.get("frozen_dump_path") or "")
        if path and Path(path).is_file():
            sealed = Path(path).read_bytes()
            local_digest = hashlib.sha256(sealed).hexdigest()
            if content_store is not None:
                stored = content_store.put(sealed)
                summary["frozen_dump_sha256"] = stored.sha256
                summary["frozen_dump_storage_key"] = stored.storage_key
                summary["sealed_digest_matches_store"] = bool(
                    local_digest == stored.sha256 == summary.get("dump_sha256")
                )
            else:
                summary["sealed_digest_matches_store"] = bool(local_digest == summary.get("dump_sha256"))
            summary["frozen_dump_bytes"] = len(sealed)
    summary.pop("frozen_dump_path", None)
    return summary


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _function_index(document: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    """`entry` identity -> function record. Built from the dump's own `entry` field, never from a position."""
    index: dict[str, Mapping[str, object]] = {}
    functions = document.get("functions")
    if not isinstance(functions, list):
        return index
    for item in functions:
        if not isinstance(item, Mapping):
            continue
        identity = entry_identity(item.get("entry"))
        if identity is not None:
            index[identity] = item
    return index


def _symbol_identities(document: Mapping[str, object]) -> set[str]:
    identities: set[str] = set()
    symbols = document.get("symbols")
    if not isinstance(symbols, list):
        return identities
    for item in symbols:
        if not isinstance(item, Mapping):
            continue
        identities.add(
            "|".join(
                str(item.get(field, "")) for field in ("name", "address", "type")
            )
        )
    return identities


def compute_dump_instability(
    document_a: Mapping[str, object],
    document_b: Mapping[str, object],
) -> dict[str, object]:
    """The comparison artifact: what actually differs between two exports of the SAME bytes.

    Plan §10.2's last line forbids carrying the historical "8 fields / 4-of-8826 symbols" forward as a gate. So
    this function measures the set from the two documents it is given: the candidate fields are DISCOVERED from
    the dumps (the union of every function-record key), the differing ENTRY SETS are enumerated per field, and
    the symbol set-difference is enumerated by symbol identity. A field with no differing entry is reported as
    stable, and a run whose exports happen to be identical reports an EMPTY unstable set - which is a measurement,
    not a vacuous pass, because `seal_frozen_dump` still demands the record's presence and shape.
    """
    index_a = _function_index(document_a)
    index_b = _function_index(document_b)
    entries_a, entries_b = set(index_a), set(index_b)
    common = sorted(entries_a & entries_b, key=lambda item: int(item, 16))
    candidates: set[str] = set()
    for record in list(index_a.values()) + list(index_b.values()):
        candidates.update(str(key) for key in record)
    candidate_fields = sorted(candidates - set(INSTABILITY_EXCLUDED_FIELDS))
    unstable_field_entries: dict[str, list[str]] = {}
    for field in candidate_fields:
        differing = [
            identity
            for identity in common
            if _canonical(index_a[identity].get(field)) != _canonical(index_b[identity].get(field))
        ]
        if differing:
            unstable_field_entries[field] = differing
    document_field_entries: dict[str, list[str]] = {}
    for field in DOCUMENT_LEVEL_FIELDS:
        if field == "symbols":
            continue
        if _canonical(document_a.get(field)) != _canonical(document_b.get(field)):
            document_field_entries[field] = ["<document>"]
    symbols_a, symbols_b = _symbol_identities(document_a), _symbol_identities(document_b)
    return {
        "schema_version": "1.0",
        "identity_key": ENTRY_IDENTITY_KEY,
        "symbol_identity_key": SYMBOL_IDENTITY_KEY,
        "compared": {
            "a": "one-shot headless export of the frozen input bytes (the dump that gets sealed)",
            "b": "a SECOND one-shot headless export of the same bytes, run for this measurement only",
        },
        "candidate_fields": candidate_fields,
        "excluded_fields": dict(INSTABILITY_EXCLUDED_FIELDS),
        "unstable_fields": sorted(unstable_field_entries),
        "unstable_field_entries": unstable_field_entries,
        "stable_fields": [field for field in candidate_fields if field not in unstable_field_entries],
        "function_entries": {
            "common": common,
            "only_in_a": sorted(entries_a - entries_b, key=lambda item: int(item, 16)),
            "only_in_b": sorted(entries_b - entries_a, key=lambda item: int(item, 16)),
        },
        "document_fields": {
            "unstable": sorted(document_field_entries),
            "field_entries": document_field_entries,
        },
        "symbols": {
            "common": sorted(symbols_a & symbols_b),
            "only_in_a": sorted(symbols_a - symbols_b),
            "only_in_b": sorted(symbols_b - symbols_a),
        },
        "source_note": (
            "The historical observation '8 unstable fields / 4 of 8,826 symbols' "
            "(`.scratch/u1-b2-decision.md`) is a SOURCE NOTE ONLY. It is not a gate, not a threshold and not a "
            "completion count: the unstable field set above is recomputed from the current frozen dump's own "
            "comparison artifact and its members are enumerated."
        ),
    }


def _require_instability_record(instability: object) -> dict[str, object]:
    """The readability contract of a sealed dump: no instability record, no usable dump (C3)."""
    if not isinstance(instability, Mapping) or not instability:
        raise FrozenDumpIncomplete(
            "GHIDRA_FROZEN_DUMP_WITHOUT_INSTABILITY_RECORD: a dump stored without the instability record it was "
            "measured with must be rejected as incomplete (plan §10.2 C3)"
        )
    required = ("identity_key", "candidate_fields", "unstable_fields", "unstable_field_entries",
                "function_entries", "symbols", "excluded_fields")
    missing = [key for key in required if key not in instability]
    if missing:
        raise FrozenDumpIncomplete(
            f"GHIDRA_FROZEN_DUMP_INSTABILITY_RECORD_INCOMPLETE: the instability record is missing {missing}"
        )
    if str(instability.get("identity_key")) != ENTRY_IDENTITY_KEY:
        raise FrozenDumpIncomplete(
            "GHIDRA_FROZEN_DUMP_IDENTITY_KEY: the record's identity key is "
            f"{instability.get('identity_key')!r}, not {ENTRY_IDENTITY_KEY!r}"
        )
    symbols = instability.get("symbols")
    if not isinstance(symbols, Mapping) or not {"common", "only_in_a", "only_in_b"} <= set(symbols):
        raise FrozenDumpIncomplete(
            "GHIDRA_FROZEN_DUMP_SYMBOL_SET_DIFF: the instability record carries no symbol set-difference"
        )
    functions = instability.get("function_entries")
    if not isinstance(functions, Mapping) or not {"common", "only_in_a", "only_in_b"} <= set(functions):
        raise FrozenDumpIncomplete(
            "GHIDRA_FROZEN_DUMP_ENTRY_SET_DIFF: the instability record carries no function entry set-difference"
        )
    return dict(instability)


@dataclass(frozen=True)
class FrozenDump:
    """A sealed dump: readable, immutable, and only usable while its bytes still hash to its own address."""

    path: Path
    dump_sha256: str
    payload: Mapping[str, object]

    @property
    def document(self) -> Mapping[str, object]:
        document = self.payload.get("dump")
        return document if isinstance(document, Mapping) else {}

    @property
    def instability(self) -> Mapping[str, object]:
        record = self.payload.get("instability")
        return record if isinstance(record, Mapping) else {}

    @property
    def requested_entries(self) -> tuple[str, ...]:
        raw = self.payload.get("requested_entries")
        if not isinstance(raw, list):
            return ()
        return tuple(str(item) for item in raw)

    def function_records(self) -> dict[str, Mapping[str, object]]:
        return _function_index(self.document)

    def record_for_entry(self, entry: object) -> Mapping[str, object] | None:
        identity = entry_identity(entry)
        if identity is None:
            return None
        return self.function_records().get(identity)

    def recorded_pseudo_c(self, entry: object) -> Mapping[str, object] | None:
        record = self.record_for_entry(entry)
        if record is None:
            return None
        pseudo = record.get("pseudo_c")
        return pseudo if isinstance(pseudo, Mapping) else None

    def current_sha256(self) -> str:
        """The digest of the bytes ON DISK right now - re-read, never the value cached at seal time."""
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def verify(self) -> str:
        actual = self.current_sha256()
        if actual != self.dump_sha256:
            raise FrozenDumpTampered(
                f"GHIDRA_FROZEN_DUMP_TAMPERED: {self.path.name} hashes to {actual[:16]} but was sealed as "
                f"{self.dump_sha256[:16]}"
            )
        return actual


def seal_frozen_dump(
    document: Mapping[str, object],
    instability: Mapping[str, object],
    directory: str | Path,
    *,
    requested_entries: Iterable[object] = (),
) -> FrozenDump:
    """Write D to a content-addressed path, then make it read-only and re-verify its own digest.

    The file name IS the digest of its bytes. That is what makes "replacing D" detectable: a reader compares the
    bytes to the name it was handed, so a substituted file with different contents cannot be mistaken for D even
    if it is a perfectly valid dump.
    """
    record = _require_instability_record(instability)
    identities = sorted(
        {identity for identity in (entry_identity(item) for item in requested_entries) if identity},
        key=lambda item: int(item, 16),
    )
    payload = {
        "schema_version": GHIDRA_FROZEN_DUMP_SCHEMA_VERSION,
        "kind": FROZEN_DUMP_KIND,
        "identity_key": ENTRY_IDENTITY_KEY,
        "requested_entries": identities,
        "instability": record,
        "dump": document,
    }
    encoded = _canonical(payload).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{digest}.json"
    path.write_bytes(encoded)
    path.chmod(0o444)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise FrozenDumpTampered("GHIDRA_FROZEN_DUMP_SEAL_FAILED: the sealed file does not hash to its address")
    return FrozenDump(path=path, dump_sha256=digest, payload=payload)


def open_frozen_dump(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
) -> FrozenDump:
    """Read a sealed dump, or refuse. Readable is not the same as trusted (plan §10.1)."""
    target = Path(path)
    raw = target.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise FrozenDumpTampered(
            f"GHIDRA_FROZEN_DUMP_REPLACED: {target.name} hashes to {digest[:16]}, not the expected "
            f"{expected_sha256[:16]}"
        )
    stem = target.stem
    if len(stem) == 64 and all(character in "0123456789abcdef" for character in stem) and stem != digest:
        raise FrozenDumpTampered(
            f"GHIDRA_FROZEN_DUMP_REPLACED: {target.name} is not its own content address (it hashes to "
            f"{digest[:16]})"
        )
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrozenDumpIncomplete(f"GHIDRA_FROZEN_DUMP_UNREADABLE: {exc}") from exc
    if not isinstance(payload, Mapping) or payload.get("kind") != FROZEN_DUMP_KIND:
        raise FrozenDumpIncomplete(
            f"GHIDRA_FROZEN_DUMP_KIND: {target.name} is not a {FROZEN_DUMP_KIND}"
        )
    document = payload.get("dump")
    if not isinstance(document, Mapping) or not isinstance(document.get("functions"), list):
        raise FrozenDumpIncomplete("GHIDRA_FROZEN_DUMP_NO_FUNCTIONS: the dump carries no function table")
    if str(payload.get("identity_key")) != ENTRY_IDENTITY_KEY:
        raise FrozenDumpIncomplete(
            f"GHIDRA_FROZEN_DUMP_IDENTITY_KEY: the dump's identity key is {payload.get('identity_key')!r}"
        )
    _require_instability_record(payload.get("instability"))
    return FrozenDump(path=target, dump_sha256=digest, payload=payload)


@dataclass(frozen=True)
class FollowUpLimitation:
    """A queryable reason a follow-up query did not produce pseudo-C (plan §10.2 C4)."""

    code: str
    detail: str
    status: str

    def as_dict(self) -> dict[str, object]:
        return {"code": self.code, "detail": self.detail, "status": self.status}


@dataclass(frozen=True)
class FollowUpOutcome:
    """One follow-up query, bound to the frozen dump's digest before AND after the round trip."""

    status: str
    entry: str
    entry_identity: str
    pseudo_c: str | None
    agreement: str
    dump_sha256_before: str
    dump_sha256_after: str
    limitation: FollowUpLimitation | None = None
    resident_entry: str = ""
    decompile_millis: int | None = None
    schema_version: str = GHIDRA_FOLLOW_UP_SCHEMA_VERSION

    @property
    def limitation_text(self) -> str:
        if self.limitation is None:
            return ""
        return (
            f"Ghidra resident follow-up query for entry {self.entry_identity} is {self.limitation.status} "
            f"({self.limitation.code}): {self.limitation.detail} No pseudo-C was produced for this entry."
        )

    def as_evidence(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "entry": self.entry,
            "entry_identity": self.entry_identity,
            "resident_entry": self.resident_entry,
            "agreement_with_frozen_dump": self.agreement,
            "dump_sha256_before_query": self.dump_sha256_before,
            "dump_sha256_after_query": self.dump_sha256_after,
            "pseudo_c_present": self.pseudo_c is not None,
            "pseudo_c_sha256": (
                hashlib.sha256(self.pseudo_c.encode("utf-8")).hexdigest() if self.pseudo_c is not None else None
            ),
            # P-7: the TEXT travels with the outcome. Before this step the summary published only a digest and a
            # boolean, so no downstream consumer could put the decompiled function into Evidence or the report -
            # "the pseudo-C reached the reader" would have been unbacked. It is published ONLY for a SUCCEEDED
            # outcome; every other status carries None here by construction.
            "pseudo_c": self.pseudo_c,
            "decompile_millis": self.decompile_millis,
            "limitation": self.limitation.as_dict() if self.limitation else None,
        }


def loopback_query_transport(
    port: int,
    host: str = "127.0.0.1",
    connect_timeout_seconds: float = 5.0,
) -> Callable[[Mapping[str, object], float], Mapping[str, object]]:
    """The shipped transport: one JSON line out, one JSON line back, over the resident's loopback socket.

    THE TAXONOMY IS THE POINT OF THIS FUNCTION, and it is taken from the WIRE EVENT, never from a guess. The
    gate owner's independent adversarial pass (`.scratch/ghidra-c3/preflight/p6-adversarial-findings.md`, finding
    F-1) measured that an earlier version collapsed two different events onto one reason: a peer that accepts
    and then CLOSES WITHOUT ANSWERING produces `ConnectionResetError` on both Windows (WinError 10054) and the
    deployed Linux image (Errno 104), which the old code reported as `GHIDRA_RESIDENT_UNAVAILABLE` - i.e. a
    resident that died mid-answer was told to the analyst as "nothing is listening". The terminal state was
    right, the REASON was wrong, and the unit tests could not see it because they injected the exception instead
    of producing it. So:

      * connect refused                        -> GHIDRA_RESIDENT_UNAVAILABLE   (DOWN)
      * connect itself timed out               -> GHIDRA_RESIDENT_CONNECT_TIMEOUT
      * accepted, then reset before an answer  -> GHIDRA_RESIDENT_CLOSED_MID_ANSWER
      * connected and silent past the deadline -> GHIDRA_FOLLOW_UP_TIMEOUT
      * answered with a clean empty body       -> GHIDRA_RESIDENT_UNLOADED      (program no longer loaded)

    Almost every failure a caller cares about is a CONNECTION failure, not a parse failure, so each of these
    raises `FollowUpUnavailable` - the signal C4 needs - rather than returning an empty mapping that a caller
    could read as "no answer yet".
    """

    def transport(request: Mapping[str, object], deadline_seconds: float) -> Mapping[str, object]:
        payload = _canonical(request).encode("utf-8") + b"\n"
        # PHASE 1: connect. A failure here says nothing about the resident's program, only about its socket.
        try:
            connection = socket.create_connection(
                (host, int(port)), timeout=max(0.5, min(connect_timeout_seconds, deadline_seconds))
            )
        except ConnectionRefusedError as exc:
            raise FollowUpUnavailable(
                "GHIDRA_RESIDENT_UNAVAILABLE: nothing is listening on the resident follow-up port "
                f"({type(exc).__name__}); the resident is DOWN"
            ) from exc
        except socket.timeout as exc:
            raise FollowUpUnavailable(
                "GHIDRA_RESIDENT_CONNECT_TIMEOUT: the resident follow-up port did not accept the connection "
                "before the connect deadline; nothing is known about the program"
            ) from exc
        except OSError as exc:
            raise FollowUpUnavailable(
                f"GHIDRA_RESIDENT_UNAVAILABLE: {type(exc).__name__}: {exc}"
            ) from exc
        # PHASE 2: ask, and read the answer.
        try:
            with connection:
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                connection.settimeout(max(0.5, deadline_seconds))
                line = connection.makefile("r", encoding="utf-8").readline()
        except socket.timeout as exc:
            raise FollowUpUnavailable(
                "GHIDRA_FOLLOW_UP_TIMEOUT: the connection was accepted and then stayed silent past the external "
                "deadline"
            ) from exc
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
            raise FollowUpUnavailable(
                f"GHIDRA_RESIDENT_CLOSED_MID_ANSWER: the resident accepted the connection and then closed it "
                f"without answering ({type(exc).__name__}, {exc}); the program it was serving is gone from under "
                "the query"
            ) from exc
        except OSError as exc:
            raise FollowUpUnavailable(
                f"GHIDRA_RESIDENT_UNAVAILABLE: {type(exc).__name__}: {exc}"
            ) from exc
        if not line.strip():
            raise FollowUpUnavailable(
                "GHIDRA_RESIDENT_UNLOADED: the resident half-closed the connection with no answer body - the "
                "program it was serving is no longer loaded. This is NOT 'down' (the connection was accepted) and "
                "NOT 'timeout' (the peer finished, it did not stall)."
            )
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FollowUpUnavailable(f"GHIDRA_RESIDENT_UNREADABLE_ANSWER: {exc}") from exc
        if not isinstance(decoded, Mapping):
            raise FollowUpUnavailable("GHIDRA_RESIDENT_UNREADABLE_ANSWER: the answer is not an object")
        return decoded

    return transport


def _pseudo_c_digest(pseudo: object) -> tuple[str | None, str]:
    """`(text, recomputed sha256)`. A declared digest is NEVER trusted: a service that lies about its own
    pseudo-C must be caught by recomputing from the text it actually sent."""
    if not isinstance(pseudo, Mapping):
        return None, ""
    text = pseudo.get("text")
    if not isinstance(text, str) or not text:
        return None, ""
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def follow_up_unavailable_outcome(
    frozen: FrozenDump,
    entry: object,
    code: str,
    detail: str,
    *,
    status: str = "BLOCKED",
) -> FollowUpOutcome:
    identity = entry_identity(entry) or ""
    return FollowUpOutcome(
        status=status,
        entry=str(entry),
        entry_identity=identity,
        pseudo_c=None,
        agreement="NO_QUERY",
        dump_sha256_before=frozen.dump_sha256,
        dump_sha256_after=frozen.current_sha256(),
        limitation=FollowUpLimitation(code=code, detail=detail, status=status),
    )


def query_frozen_dump(
    frozen: FrozenDump,
    entry: object,
    *,
    transport: Callable[[Mapping[str, object], float], Mapping[str, object]],
    deadline_seconds: float,
) -> FollowUpOutcome:
    """Ask the resident about ONE `entry` of the frozen dump, and accept only agreement with D.

    The dump's digest is re-read from disk BEFORE and AFTER the round trip, so a query that ran against a dump
    somebody rewrote mid-flight cannot return SUCCEEDED. `SUCCEEDED` additionally requires the pseudo-C the
    resident produced to be byte-identical (by recomputed SHA-256) to the pseudo-C D recorded for that entry;
    everything else is `PARTIAL` or `BLOCKED` with a queryable limitation and NO pseudo-C (plan §10.2 C1/C4).
    """
    identity = entry_identity(entry)
    before = frozen.verify()
    if identity is None:
        return FollowUpOutcome(
            status="BLOCKED",
            entry=str(entry),
            entry_identity="",
            pseudo_c=None,
            agreement="NOT_COMPARABLE",
            dump_sha256_before=before,
            dump_sha256_after=before,
            limitation=FollowUpLimitation(
                code="GHIDRA_FOLLOW_UP_ENTRY_NOT_AN_ADDRESS",
                detail=f"{entry!r} is not a hex entry address, so it cannot identify a function in D",
                status="BLOCKED",
            ),
        )
    recorded = frozen.recorded_pseudo_c(identity)
    if frozen.record_for_entry(identity) is None:
        return FollowUpOutcome(
            status="PARTIAL",
            entry=str(entry),
            entry_identity=identity,
            pseudo_c=None,
            agreement="NOT_IN_FROZEN_DUMP",
            dump_sha256_before=before,
            dump_sha256_after=frozen.current_sha256(),
            limitation=FollowUpLimitation(
                code="GHIDRA_FOLLOW_UP_ENTRY_NOT_IN_FROZEN_DUMP",
                detail=(
                    f"entry {identity} is not a function of the frozen dump; the resident service is only ever "
                    "asked about functions D already contains"
                ),
                status="PARTIAL",
            ),
        )
    request = {
        "schema_version": GHIDRA_RESIDENT_QUERY_SCHEMA_VERSION,
        "op": "query",
        "entry": identity,
        "dump_sha256": frozen.dump_sha256,
    }
    try:
        answer = transport(request, deadline_seconds)
    except FollowUpUnavailable as exc:
        return follow_up_unavailable_outcome(frozen, identity, str(exc).split(":", 1)[0], str(exc))
    except TimeoutError:
        return follow_up_unavailable_outcome(
            frozen,
            identity,
            "GHIDRA_FOLLOW_UP_TIMEOUT",
            "the resident did not answer before the external deadline",
        )
    after = frozen.verify()
    error = answer.get("error")
    if error:
        code = str(error).split(":", 1)[0]
        return FollowUpOutcome(
            status="PARTIAL",
            entry=str(entry),
            entry_identity=identity,
            pseudo_c=None,
            agreement="RESIDENT_ERROR",
            dump_sha256_before=before,
            dump_sha256_after=after,
            resident_entry=str(answer.get("entry") or ""),
            limitation=FollowUpLimitation(
                code=f"GHIDRA_RESIDENT_{code}",
                detail=f"the resident answered with an error for entry {identity}: {error}",
                status="PARTIAL",
            ),
        )
    text, digest = _pseudo_c_digest(answer.get("pseudo_c"))
    if text is None:
        return FollowUpOutcome(
            status="PARTIAL",
            entry=str(entry),
            entry_identity=identity,
            pseudo_c=None,
            agreement="NO_PSEUDO_C",
            dump_sha256_before=before,
            dump_sha256_after=after,
            resident_entry=str(answer.get("entry") or ""),
            limitation=FollowUpLimitation(
                code="GHIDRA_RESIDENT_RETURNED_NO_PSEUDO_C",
                detail=f"the resident answered for entry {identity} without a pseudo-C body",
                status="PARTIAL",
            ),
        )
    millis = answer.get("decompile_millis")
    if recorded is None:
        return FollowUpOutcome(
            status="PARTIAL",
            entry=str(entry),
            entry_identity=identity,
            pseudo_c=None,
            agreement="FROZEN_DUMP_HAS_NO_PSEUDO_C",
            dump_sha256_before=before,
            dump_sha256_after=after,
            resident_entry=str(answer.get("entry") or ""),
            decompile_millis=int(millis) if isinstance(millis, (int, float)) else None,
            limitation=FollowUpLimitation(
                code="GHIDRA_FROZEN_DUMP_HAS_NO_PSEUDO_C_FOR_ENTRY",
                detail=(
                    f"the frozen dump holds no pseudo-C record for entry {identity}, so a resident answer cannot "
                    "be checked against it and is not published"
                ),
                status="PARTIAL",
            ),
        )
    _, recorded_digest = _pseudo_c_digest(recorded)
    if digest != recorded_digest:
        return FollowUpOutcome(
            status="BLOCKED",
            entry=str(entry),
            entry_identity=identity,
            pseudo_c=None,
            agreement="DISAGREES_WITH_FROZEN_DUMP",
            dump_sha256_before=before,
            dump_sha256_after=after,
            resident_entry=str(answer.get("entry") or ""),
            decompile_millis=int(millis) if isinstance(millis, (int, float)) else None,
            limitation=FollowUpLimitation(
                code="GHIDRA_FOLLOW_UP_PSEUDO_C_DISAGREES_WITH_FROZEN_DUMP",
                detail=(
                    f"the resident returned pseudo-C {digest[:16]} for entry {identity} while the frozen dump "
                    f"records {recorded_digest[:16]}; the two disagree, so neither is published"
                ),
                status="BLOCKED",
            ),
        )
    return FollowUpOutcome(
        status="SUCCEEDED",
        entry=str(entry),
        entry_identity=identity,
        pseudo_c=text,
        agreement="AGREES_WITH_FROZEN_DUMP",
        dump_sha256_before=before,
        dump_sha256_after=after,
        resident_entry=str(answer.get("entry") or ""),
        decompile_millis=int(millis) if isinstance(millis, (int, float)) else None,
    )


def _follow_up_summary(
    frozen: FrozenDump,
    wanted: Sequence[str],
    outcomes: Sequence[FollowUpOutcome],
    *,
    deadline_source: Mapping[str, object] | None,
    transcript: str,
    resident_error: str | None = None,
    resident_shutdown: Mapping[str, object] | None = None,
    stopped_reason: str = "",
    stopped_phase: str = "",
    stopped_after_seconds: float | None = None,
    unanswered_code: str = "",
    unanswered_detail: str = "",
    unanswered_status: str = "PARTIAL",
) -> dict[str, object]:
    """Turn the per-entry outcomes into one publishable record: SETS, a status, and the limitations.

    Every requested entry gets exactly one outcome. An entry the resident never got to is filled in with the
    reason it was not answered, so `requested_minus_processed` can never be silently empty because a loop was cut
    short.

    P-7 adds the STOP contract (plan §11.3 H2): when the loop was cut short by its deadline, the summary carries
    `stopped_reason` / `stopped_phase` / the measured `stopped_after_seconds`, and every unqueried entry is
    filled with `unanswered_code` instead of vanishing. A summary that stopped for no reason carries NO
    `stopped_reason` key at all - the field is evidence of a stop, never a label on a successful run.
    """
    completed = list(outcomes)
    answered = {outcome.entry_identity for outcome in completed}
    filler_code = unanswered_code or resident_error or ""
    if filler_code:
        for identity in wanted:
            if identity not in answered:
                completed.append(
                    follow_up_unavailable_outcome(
                        frozen,
                        identity,
                        filler_code,
                        unanswered_detail
                        or _RESIDENT_ERROR_DETAIL.get(
                            filler_code, "the resident follow-up service did not answer this entry"
                        ),
                        status=unanswered_status if unanswered_code else "BLOCKED",
                    )
                )
    successful = [outcome.entry_identity for outcome in completed if outcome.status == "SUCCEEDED"]
    statuses = {outcome.status for outcome in completed}
    if not completed:
        status = "PARTIAL"
    elif "BLOCKED" in statuses:
        status = "BLOCKED"
    elif "PARTIAL" in statuses:
        status = "PARTIAL"
    else:
        status = "SUCCEEDED"
    limitations = [outcome.limitation_text for outcome in completed if outcome.limitation is not None]
    requested = [identity for identity in wanted]
    summary: dict[str, object] = {
        "schema_version": GHIDRA_FOLLOW_UP_SCHEMA_VERSION,
        "status": status,
        "identity_key": ENTRY_IDENTITY_KEY,
        "dump_sha256": frozen.dump_sha256,
        "dump_sha256_after_all_queries": frozen.current_sha256(),
        "requested_entries": requested,
        "processed_entries": successful,
        "unprocessed_entries": sorted(set(requested) - set(successful), key=lambda item: int(item, 16)),
        "entry_set_difference": {
            "identity_key": ENTRY_IDENTITY_KEY,
            "enumerated_set": requested,
            "retrieved_set": successful,
            "expected_minus_actual": sorted(set(requested) - set(successful), key=lambda item: int(item, 16)),
            "actual_minus_expected": sorted(set(successful) - set(requested), key=lambda item: int(item, 16)),
        },
        "outcomes": [outcome.as_evidence() for outcome in completed],
        "limitations": limitations,
        "summary_limitation": follow_up_summary_limitation(status, completed, frozen),
        "deadline": dict(deadline_source or {}),
        "resident": {
            "shutdown": dict(resident_shutdown or {}),
            "transcript": transcript[-4000:],
        },
    }
    if stopped_reason:
        summary["stopped_reason"] = stopped_reason
        summary["stopped_phase"] = stopped_phase
        summary["stopped_after_seconds"] = stopped_after_seconds
        summary["stopped_detail"] = (
            f"the run stopped in phase {stopped_phase or 'unknown'} with reason {stopped_reason} after "
            f"{stopped_after_seconds}s; {len(summary['unprocessed_entries'])} of {len(requested)} requested "
            "entry(ies) were not queried and no pseudo-C is published for them"
        )
    return summary


_RESIDENT_ERROR_DETAIL: dict[str, str] = {
    "GHIDRA_RESIDENT_UNAVAILABLE": (
        "nothing is listening on the follow-up port: the CONNECT was refused, so the resident is DOWN"
    ),
    "GHIDRA_RESIDENT_CONNECT_TIMEOUT": (
        "the follow-up port did not accept the connection before the connect deadline; nothing is known about "
        "the program (CONNECT TIMEOUT - distinct from an answer that never arrives)"
    ),
    "GHIDRA_RESIDENT_CLOSED_MID_ANSWER": (
        "the resident accepted the connection and then closed it without answering (RESET mid-answer): the "
        "program it was serving is gone from under the query"
    ),
    "GHIDRA_RESIDENT_UNLOADED": (
        "the resident half-closed the connection with an empty answer body: the program it was serving is no "
        "longer loaded (UNLOADED - distinguishable from down and from timeout by the wire event that produced it)"
    ),
    "GHIDRA_FOLLOW_UP_TIMEOUT": (
        "the connection was accepted and then stayed silent past the external deadline (TIMEOUT)"
    ),
    "GHIDRA_FOLLOW_UP_CANCELLED": "the follow-up batch was cancelled before this entry was queried",
    "GHIDRA_HEADLESS_UNAVAILABLE": "the Ghidra headless launcher is not available on this worker",
    "GHIDRA_RESIDENT_SCRIPT_MISSING": "the resident follow-up script is not installed next to the adapter",
    "GHIDRA_FOLLOW_UP_NO_REQUESTED_ENTRIES": (
        "the caller requested no entry, so there is nothing to decompile and nothing to query"
    ),
    "GHIDRA_FROZEN_DUMP_COMPARISON_EXPORT_FAILED": (
        "the comparison export failed, so the dump's instability could not be measured and the dump was not sealed"
    ),
}


# ---------------------------------------------------------------------------------------------------------------------
# P-7: the deadline that STOPS a run, and the set difference it publishes when it does (plan §11.2/§11.3)
# ---------------------------------------------------------------------------------------------------------------------
#: The published stop reasons. `external_deadline` is §11.3's H2 token; `cancelled` reuses C4's existing
#: cancellation signal instead of inventing a second word for the same event. A run that stopped for neither
#: reason carries NO `stopped_reason` key at all - a reason that was never reached must not be fabricated.
STOPPED_REASON_EXTERNAL_DEADLINE = "external_deadline"
STOPPED_REASON_CANCELLED = "cancelled"
#: Which phase the deadline stopped. The measured relation (gate-owner messages #1/#2) is
#: `~10 s export + N x ~0.3 s resident`, so with a deadline too small to finish, the phase that runs out is the
#: resident query loop - the export finishes 81/81 entries in ~10 s and cannot honestly be starved on this input.
STOP_PHASE_RESIDENT_QUERY = "resident_query"
STOP_DETAIL_EXTERNAL_DEADLINE = (
    "the external deadline named by the follow-up batch was reached before this entry was queried, so it is "
    "published as unprocessed and NO pseudo-C is published for it"
)
_RESIDENT_ERROR_DETAIL["GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE"] = STOP_DETAIL_EXTERNAL_DEADLINE


def _resolve_deadline(
    deadline_at: float | None,
    timeout_seconds: int | None,
    deadline_source: Mapping[str, object] | None,
) -> tuple[float, dict[str, object]]:
    """`(absolute monotonic instant, the named record that justifies it)`.

    THE VALUE IS READ FROM THE NAMED SOURCE, not chosen here: when `deadline_source` carries a numeric `value`,
    that value is the deadline. A caller that passes only a positional number gets a record whose `source` says
    `UNSOURCED`, so a bare number can never be read later as a policy value (plan §11.2: "artifact 必须给出该
    deadline 的 policy/DB 来源和值"). Nothing in this module shrinks the deadline.
    """
    record = dict(deadline_source or {})
    raw = record.get("value")
    seconds: float | None = None
    if isinstance(raw, bool):
        seconds = None
    elif isinstance(raw, (int, float)):
        seconds = float(raw)
    elif isinstance(raw, str) and raw.strip().isdigit():
        seconds = float(raw.strip())
    if seconds is None:
        seconds = float(timeout_seconds or 0)
        if not record:
            record = {
                "key": "timeout_seconds (positional argument)",
                "value": int(seconds),
                "source": "UNSOURCED: the caller passed a bare number instead of naming the policy it came from",
            }
    if deadline_at is not None:
        return float(deadline_at), record
    return time.monotonic() + max(0.0, seconds), record


def run_resident_queries(
    frozen: FrozenDump,
    *,
    entries: Sequence[str] = (),
    deadline_at: float | None = None,
    deadline_source: Mapping[str, object] | None = None,
    run_started_at: float | None = None,
    timeout_seconds: int | None = None,
    transport_factory: Callable[[FrozenDump], Callable[[Mapping[str, object], float], Mapping[str, object]]]
    | None = None,
    cancellation_requested: Callable[[], bool] | None = None,
    resident_error: str | None = None,
    transcript: str = "",
    resident_shutdown: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """The ONE resident query loop: ask about the requested entries until the deadline, then SAY what stopped it.

    WHY THIS IS A MODULE FUNCTION AND NOT INLINED. `GhidraHeadlessRunner.serve_follow_up_queries` reaches it with
    a real loopback transport after launching the resident, and the focused tests reach it with an injected
    transport. Two loops would be two chances to disagree about the deadline, and the deadline is the whole
    point of H2: the loop checks the ABSOLUTE instant before EVERY query, so a query is never handed a fresh
    budget the reported deadline does not cover.

    The published contract when it stops:
      * `stopped_reason` = `external_deadline` (or `cancelled`), plus `stopped_phase` and the MEASURED
        `stopped_after_seconds` since the run started;
      * every requested entry still has exactly one outcome, and the unqueried ones carry
        `GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE` with a non-`SUCCEEDED` status;
      * `processed_entries` / `unprocessed_entries` and BOTH directions of the set difference stay enumerated by
        `_follow_up_summary`, so a stopped run can never read as a smaller successful one;
      * a run that stopped for neither reason carries NO `stopped_reason` key.
    """
    started = run_started_at if run_started_at is not None else time.monotonic()
    deadline, record = _resolve_deadline(deadline_at, timeout_seconds, deadline_source)
    wanted = [identity for identity in (entry_identity(item) for item in entries) if identity]
    if not wanted:
        wanted = [identity for identity in frozen.requested_entries if identity]
    outcomes: list[FollowUpOutcome] = []
    stopped_reason = ""
    stopped_phase = ""
    unanswered_code = ""
    if resident_error is None and transport_factory is not None:
        transport = transport_factory(frozen)
        for identity in wanted:
            if cancellation_requested is not None and cancellation_requested():
                stopped_reason = STOPPED_REASON_CANCELLED
                stopped_phase = STOP_PHASE_RESIDENT_QUERY
                unanswered_code = "GHIDRA_FOLLOW_UP_CANCELLED"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stopped_reason = STOPPED_REASON_EXTERNAL_DEADLINE
                stopped_phase = STOP_PHASE_RESIDENT_QUERY
                unanswered_code = "GHIDRA_FOLLOW_UP_EXTERNAL_DEADLINE"
                break
            outcomes.append(
                query_frozen_dump(frozen, identity, transport=transport, deadline_seconds=remaining)
            )
    return _follow_up_summary(
        frozen,
        wanted,
        outcomes,
        deadline_source=record,
        transcript=transcript,
        resident_error=resident_error,
        resident_shutdown=resident_shutdown,
        stopped_reason=stopped_reason,
        stopped_phase=stopped_phase,
        stopped_after_seconds=(round(time.monotonic() - started, 2) if stopped_reason else None),
        unanswered_code=unanswered_code,
        unanswered_detail=_RESIDENT_ERROR_DETAIL.get(unanswered_code, ""),
    )


def follow_up_summary_limitation(
    status: str,
    outcomes: Sequence[FollowUpOutcome],
    frozen: FrozenDump,
) -> str:
    """ONE summary line for the task's limitation list, followed by one line PER unprocessed entry.

    MEASURED (gate-owner finding #3, `.scratch/ghidra-c3/preflight/p6-independent-m4.json`): an earlier version
    of this sentence ended with "the processed/unprocessed entry sets are published as a set difference in the
    ghidra tool output, not summarised here" - and the M4 render proof then asserted that the ENTRY appeared in
    the official Markdown, which was true only of the per-outcome string the test itself had built, never of the
    string the product projects. A proof whose assertion holds only for a string production never emits is not a
    proof of the channel.

    So the projection is BOTH: this sentence names the status, the digest and the reason codes, and the caller
    (`AnalysisService._follow_up_limitations`) ALSO projects one line per unprocessed entry, each naming its
    `entry`. The reader therefore sees which function has no pseudo-C without leaving the report, and the
    enumerated sets remain published in the tool output as well. No entry is ever published with a pseudo-C
    attached when its status is not SUCCEEDED.
    """
    if status == "SUCCEEDED":
        return ""
    codes: list[str] = []
    for outcome in outcomes:
        if outcome.limitation is not None and outcome.limitation.code not in codes:
            codes.append(outcome.limitation.code)
    unprocessed = [outcome.entry_identity for outcome in outcomes if outcome.status != "SUCCEEDED"]
    return (
        f"Ghidra resident follow-up query: {status} for the frozen dump {frozen.dump_sha256[:16]} - "
        f"{len(unprocessed)} of {len(outcomes)} requested entry(ies) produced no pseudo-C "
        f"({', '.join(codes) or 'no code recorded'}). Every unprocessed entry is named in its own limitation "
        "line, and the processed/unprocessed entry sets are also published as a set difference in the ghidra "
        "tool output. No pseudo-C is published for any unprocessed entry."
    )

