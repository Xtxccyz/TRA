from pathlib import Path
import subprocess
import json

import pytest

from threat_report_agent.ghidra_adapter import GhidraHeadlessRunner, validate_ghidra_output


def test_ghidra_runner_resolves_headless_binary_and_export_script() -> None:
    workspace = Path(__file__).parents[1]
    runner = GhidraHeadlessRunner(
        workspace / ".tools" / "ghidra-12.1.2" / "ghidra_12.1.2_PUBLIC",
        Path("C:/Program Files/Eclipse Adoptium/jdk-21.0.12.8-hotspot"),
    )

    configuration = runner.configuration()

    assert configuration["available"] is True
    assert configuration["headless_path"].endswith("analyzeHeadless.bat")
    assert configuration["export_script"].endswith("ExportStaticFacts.java")


def test_ghidra_runner_uses_posix_java_executable(tmp_path, monkeypatch) -> None:
    ghidra_home = tmp_path / "ghidra"
    java_home = tmp_path / "jdk"
    (ghidra_home / "support").mkdir(parents=True)
    (ghidra_home / "support" / "analyzeHeadless").write_text("stub", encoding="utf-8")
    (java_home / "bin").mkdir(parents=True)
    (java_home / "bin" / "java").write_text("stub", encoding="utf-8")
    runner = GhidraHeadlessRunner(ghidra_home, java_home)

    monkeypatch.setattr("threat_report_agent.ghidra_adapter.os.name", "posix")

    assert runner.configuration()["available"] is True
    assert runner.java_path is not None
    assert runner.java_path.name == "java"


def test_ghidra_runner_neutralizes_untrusted_filename_for_cmd() -> None:
    assert GhidraHeadlessRunner.safe_input_name("%PATH% & calc.exe") == "sample.exe"


def test_ghidra_runner_keeps_untrusted_filename_as_one_argument(tmp_path, monkeypatch) -> None:
    runner = GhidraHeadlessRunner(tmp_path)
    runner.headless_path.parent.mkdir(parents=True)
    runner.headless_path.write_text("stub", encoding="utf-8")
    captured: dict[str, object] = {}

    class Completed:
        returncode = 1
        stdout = ""
        stderr = ""

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr("threat_report_agent.ghidra_adapter.subprocess.run", fake_run)

    result = runner.analyze(b"MZ", "sample & whoami.exe", timeout_seconds=1)

    assert result.error == "GHIDRA_HEADLESS_FAILED"
    assert captured["kwargs"]["shell"] is False
    assert captured["command"][4].endswith("sample.exe")
    assert all("&" not in argument for argument in captured["command"])


def test_ghidra_runner_accepts_explicit_processor_override(tmp_path, monkeypatch) -> None:
    runner = GhidraHeadlessRunner(tmp_path)
    runner.headless_path.parent.mkdir(parents=True)
    runner.headless_path.write_text("stub", encoding="utf-8")

    class Completed:
        returncode = 1
        stdout = ""
        stderr = ""

    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return Completed()

    monkeypatch.setattr("threat_report_agent.ghidra_adapter.subprocess.run", fake_run)
    runner.analyze(b"MZ", "fixture.exe", timeout_seconds=1, processor="x86:LE:32:default")

    command = captured["command"]
    assert command[3:5] == ["-processor", "x86:LE:32:default"]
    assert "-import" in command


def test_ghidra_runner_normalizes_only_zeroed_pe_machine_for_x86_retry() -> None:
    content = bytearray(0x200)
    content[:2] = b"MZ"
    content[0x3C:0x40] = (0x80).to_bytes(4, "little")
    content[0x80:0x84] = b"PE\x00\x00"
    content[0x98:0x9A] = (0x10B).to_bytes(2, "little")

    normalized, transform = GhidraHeadlessRunner._prepare_analysis_content(
        bytes(content), "x86:LE:32:default"
    )

    assert transform == "PE_MACHINE_ZERO_NORMALIZED_TO_I386"
    assert normalized[0x84:0x86] == (0x14C).to_bytes(2, "little")
    assert content[0x84:0x86] == b"\x00\x00"

    unchanged, no_transform = GhidraHeadlessRunner._prepare_analysis_content(
        bytes(content), None
    )
    assert unchanged == bytes(content)
    assert no_transform is None


def test_ghidra_runner_terminates_the_process_when_cancelled(tmp_path, monkeypatch) -> None:
    runner = GhidraHeadlessRunner(tmp_path)
    runner.headless_path.parent.mkdir(parents=True)
    runner.headless_path.write_text("stub", encoding="utf-8")
    process_state = {"terminated": False, "communicate_calls": 0}

    class Process:
        pid = 123
        returncode = None

        def communicate(self, timeout=None):
            process_state["communicate_calls"] += 1
            if not process_state["terminated"]:
                raise subprocess.TimeoutExpired("ghidra", timeout)
            self.returncode = -1
            return "", ""

        def poll(self):
            return self.returncode

        def terminate(self):
            process_state["terminated"] = True

        def kill(self):
            process_state["terminated"] = True

        def wait(self, timeout=None):
            self.returncode = -1
            return self.returncode

    monkeypatch.setattr(
        "threat_report_agent.ghidra_adapter.subprocess.Popen",
        lambda *args, **kwargs: Process(),
    )
    checks = iter([False, True])

    result = runner.analyze(
        b"MZ",
        "sample.exe",
        timeout_seconds=60,
        cancellation_requested=lambda: next(checks),
    )

    assert result.status == "CANCELLED"
    assert result.error == "GHIDRA_CANCELLED"
    assert process_state["terminated"] is True


def test_ghidra_runner_accepts_versioned_output_and_adds_function_fingerprint(
    tmp_path, monkeypatch
) -> None:
    runner = GhidraHeadlessRunner(tmp_path)
    runner.headless_path.parent.mkdir(parents=True)
    runner.headless_path.write_text("stub", encoding="utf-8")

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(command, **kwargs):
        Path(command[-1]).write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "functions": [
                        {
                            "name": "entry",
                            "entry": "00401000",
                            "mnemonics": ["MOV", "CALL", "RET"],
                            "xrefs_to_entry": [],
                            "cfg_blocks": [],
                        }
                    ],
                    "symbols": [],
                }
            ),
            encoding="utf-8",
        )
        return Completed()

    monkeypatch.setattr("threat_report_agent.ghidra_adapter.subprocess.run", fake_run)
    result = runner.analyze(b"MZ", "fixture.exe", timeout_seconds=1)
    assert result.status == "SUCCEEDED"
    assert result.output["schema_version"] == "1.0"
    assert result.output["functions"][0]["fuzzy_fingerprint"]


def test_ghidra_runner_classifies_malformed_output(tmp_path, monkeypatch) -> None:
    runner = GhidraHeadlessRunner(tmp_path)
    runner.headless_path.parent.mkdir(parents=True)
    runner.headless_path.write_text("stub", encoding="utf-8")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command, **kwargs):
        Path(command[-1]).write_text("not-json", encoding="utf-8")
        return Completed()

    monkeypatch.setattr("threat_report_agent.ghidra_adapter.subprocess.run", fake_run)
    result = runner.analyze(b"MZ", "fixture.exe", timeout_seconds=1)
    assert result.status == "FAILED"
    assert result.error == "GHIDRA_OUTPUT_INVALID_JSON"


def test_validate_ghidra_output_backfills_legacy_schema_and_rejects_bad_rows() -> None:
    legacy = {"functions": [], "symbols": []}

    normalized = validate_ghidra_output(legacy)

    assert normalized["schema_version"] == "1.0"
    assert normalized is not legacy

    with pytest.raises(ValueError, match="GHIDRA_OUTPUT_INVALID_SCHEMA"):
        validate_ghidra_output({"functions": [{}], "symbols": "not-a-list"})
