"""Contract tests for the authored-tool spec and policy gate (ADR-0037).

These tests were written before ``threat_report_agent.tool_authoring`` existed.
They lock the public names the investigation loop and the policy layer will wire
up later: ``ToolAuthoringRequest``, ``ToolAuthoringDecision``,
``evaluate_tool_authoring_request``, ``DEFAULT_TOOL_LIMITS``,
``HARD_TOOL_LIMITS``, ``TOOL_AUTHORING_POLICY_KIND`` and
``authored_tool_evidence_nature``.

Terminology: the isolated Unicorn/Speakeasy/Qiling path is static analysis and
produces ``EMULATION_OBSERVED``.  ``DYNAMIC_OBSERVED`` would mean the sample
actually ran, which this product never does and authored tools never produce.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path

import pytest

from threat_report_agent import tool_authoring as ta

LIMIT_KEYS = {"wall_seconds", "cpu_seconds", "instruction_budget", "max_output_bytes"}

DETERMINISTIC_SOURCE = '''
import hashlib
import struct


def decode_config(blob: bytes) -> dict[str, object]:
    """XOR-decode the granted window; no host, no network, no clock."""
    key = blob[:4]
    out = bytearray()
    for index, byte in enumerate(blob[4:]):
        out.append(byte ^ key[index % 4])
    payload = bytes(out)
    return {
        "recovered_sha256": hashlib.sha256(payload).hexdigest(),
        "first_u32": struct.unpack_from("<I", payload, 0)[0],
    }
'''

DOCSTRING_ONLY_SOURCE = '''"""Decode the configuration window.

Documentation only: this helper never shells out and never imports subprocess,
never calls os.system and never opens a socket.
"""


def decode(blob: bytes) -> bytes:
    return bytes(byte ^ 0x5A for byte in blob)
'''


def _request(**overrides: object) -> ta.ToolAuthoringRequest:
    values: dict[str, object] = {
        "tool_name": "xor_config_decoder",
        "purpose": "recover the consumer join for the decoded configuration window",
        "gap_kind": "consumer",
        "mechanism_type": "byte_window_decode",
        "artifact_id": "artifact-0001",
        "thread_id": "thread-consumer-1",
        "input_selectors": ({"kind": "artifact_slice", "byte_offset": 512},),
        "source_code": DETERMINISTIC_SOURCE,
        "output_schema": {
            "type": "object",
            "properties": {"recovered_sha256": {"type": "string"}},
        },
        "failure_modes": ("xor key not recoverable from the granted window",),
        "proposed_by": "model",
    }
    values.update(overrides)
    return ta.ToolAuthoringRequest(**values)  # type: ignore[arg-type]


def test_module_constants_are_the_documented_ones() -> None:
    assert ta.TOOL_AUTHORING_POLICY_KIND == "authored-tool"
    assert set(ta.DEFAULT_TOOL_LIMITS) == LIMIT_KEYS
    assert set(ta.HARD_TOOL_LIMITS) == LIMIT_KEYS
    assert ta.AUTHORED_TOOL_EVIDENCE_NATURES == ("STATIC_DERIVED", "EMULATION_OBSERVED")
    assert ta.AUTHORED_TOOL_EVIDENCE_NATURES.count("DYNAMIC_OBSERVED") == 0
    assert ta.EVIDENCE_NATURE_DYNAMIC_OBSERVED not in ta.AUTHORED_TOOL_EVIDENCE_NATURES


def test_defaults_stay_inside_the_hard_ceilings() -> None:
    for key in LIMIT_KEYS:
        assert 0 < ta.DEFAULT_TOOL_LIMITS[key] <= ta.HARD_TOOL_LIMITS[key]


def test_hard_limits_cannot_be_raised_at_runtime() -> None:
    with pytest.raises(TypeError):
        ta.HARD_TOOL_LIMITS["wall_seconds"] = 10**9  # type: ignore[index]
    with pytest.raises(TypeError):
        ta.DEFAULT_TOOL_LIMITS["wall_seconds"] = 10**9  # type: ignore[index]


def test_request_is_a_frozen_dataclass_with_the_declared_fields() -> None:
    assert dataclasses.is_dataclass(ta.ToolAuthoringRequest)
    names = {field.name for field in dataclasses.fields(ta.ToolAuthoringRequest)}
    assert names >= {
        "tool_name",
        "purpose",
        "gap_kind",
        "mechanism_type",
        "artifact_id",
        "thread_id",
        "input_selectors",
        "source_code",
        "output_schema",
        "failure_modes",
        "proposed_by",
    }
    names = {field.name for field in dataclasses.fields(ta.ToolAuthoringDecision)}
    assert names >= {"accepted", "violations", "reason", "resource_limits"}


def test_valid_request_is_accepted() -> None:
    decision = ta.evaluate_tool_authoring_request(_request())
    assert decision.accepted is True
    assert decision.violations == ()
    assert decision.reason == ta.TOOL_AUTHORING_ACCEPTED
    assert set(decision.resource_limits) == LIMIT_KEYS
    for key in LIMIT_KEYS:
        assert decision.resource_limits[key] == ta.DEFAULT_TOOL_LIMITS[key]


def test_declared_limits_within_ceilings_are_echoed() -> None:
    limits = {
        "wall_seconds": 12,
        "cpu_seconds": 4,
        "instruction_budget": 20_000,
        "max_output_bytes": 4_096,
    }
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=limits))
    assert decision.accepted is True
    assert decision.resource_limits == limits


def test_rejected_decision_still_reports_bounded_limits() -> None:
    limits = {
        "wall_seconds": ta.HARD_TOOL_LIMITS["wall_seconds"] + 1,
        "cpu_seconds": 4,
        "instruction_budget": 20_000,
        "max_output_bytes": 4_096,
    }
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=limits))
    assert decision.accepted is False
    for key in LIMIT_KEYS:
        assert decision.resource_limits[key] <= ta.HARD_TOOL_LIMITS[key]


# --------------------------------------------------------------------------
# Rejection class 1: running the submitted sample (the one hard boundary)
# --------------------------------------------------------------------------

EXECUTION_SOURCES = [
    pytest.param("import subprocess\n", id="import-subprocess"),
    pytest.param("subprocess.run([target])\n", id="subprocess-call"),
    pytest.param("import os\nos.system(command)\n", id="os-system"),
    pytest.param("import os\nos.popen(command)\n", id="os-popen"),
    pytest.param("import os\nos.execv(path, args)\n", id="os-execv"),
    pytest.param("import os\nos.spawnl(mode, path)\n", id="os-spawn"),
    pytest.param("subprocess.call([target], shell=True)\n", id="shell-true"),
    pytest.param("import ctypes\nctypes.CDLL(sample_path)\n", id="ctypes-cdll"),
    pytest.param("import ctypes\nctypes.windll.kernel32.LoadLibraryW(name)\n", id="ctypes-windll"),
    pytest.param("import runpy\nrunpy.run_path(target)\n", id="runpy"),
    pytest.param("import win32process\nwin32process.CreateProcess(...)\n", id="win32process"),
    pytest.param("kernel32.CreateProcessW(None, command, ...)\n", id="create-process"),
    pytest.param("payload = eval(sample_text)\n", id="eval"),
    pytest.param("exec(sample_bytes.decode())\n", id="exec"),
    pytest.param("code = compile(sample_text, '<sample>', 'exec')\n", id="compile"),
    pytest.param("__import__('sub' + 'process').run([target])\n", id="dunder-import"),
    pytest.param("import importlib\nimportlib.import_module(name)\n", id="importlib"),
    pytest.param("getattr(os, 'system')(command)\n", id="getattr-system"),
    pytest.param("import pickle\npickle.loads(sample_blob)\n", id="pickle-loads"),
    pytest.param("import multiprocessing\nmultiprocessing.Process(target=main)\n", id="multiprocessing"),
]


@pytest.mark.parametrize("source", EXECUTION_SOURCES)
def test_sample_execution_is_rejected(source: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations
    assert decision.reason.startswith(ta.TOOL_AUTHORING_REJECTED)


@pytest.mark.parametrize(
    "purpose",
    [
        "run the sample and record the API trace",
        "execute_sample then read the dropped file",
        "dynamic analysis of the loader stage",
        "sandbox run of the loader stage",
        "observe the sample in a live sandbox",
    ],
)
def test_declared_launch_intent_is_rejected_without_a_source_call(purpose: str) -> None:
    decision = ta.evaluate_tool_authoring_request(
        _request(purpose=purpose, source_code="value = 1\n")
    )
    assert decision.accepted is False
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


def test_run_sample_identifier_in_source_is_rejected() -> None:
    """A helper literally named `run_sample` claims the forbidden capability."""
    decision = ta.evaluate_tool_authoring_request(
        _request(source_code="def run_sample(blob: bytes) -> bytes:\n    return blob\n")
    )
    assert decision.accepted is False
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


def test_sample_byte_handling_identifiers_stay_accepted() -> None:
    """`sample_bytes`/`sample_window` describe data, not execution."""
    source = (
        "def decode_sample_window(sample_bytes: bytes, sample_window: int) -> bytes:\n"
        "    return sample_bytes[:sample_window]\n"
    )
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is True
    assert decision.violations == ()


@pytest.mark.parametrize(
    "purpose",
    [
        "recover the CreateProcess flags used by the loader",
        "join the decoded buffer to the socket API argument",
        "extract the registry key written by the persistence routine",
        "decode the configuration consumed by the download routine",
    ],
)
def test_analysis_prose_naming_dangerous_apis_is_still_accepted(purpose: str) -> None:
    """Prose describes the analysis target; only code and mechanisms grant powers."""
    decision = ta.evaluate_tool_authoring_request(
        _request(purpose=purpose, source_code="value = 1\n")
    )
    assert decision.accepted is True
    assert decision.violations == ()


# --------------------------------------------------------------------------
# Rejection class 2: network access
# --------------------------------------------------------------------------

NETWORK_SOURCES = [
    pytest.param("import socket\n", id="socket"),
    pytest.param("import urllib.request\n", id="urllib"),
    pytest.param("import requests\n", id="requests"),
    pytest.param("import http.client\n", id="http-client"),
    pytest.param("import ftplib\n", id="ftplib"),
    pytest.param("import smtplib\n", id="smtplib"),
    pytest.param("import paramiko\n", id="paramiko"),
    pytest.param("import telnetlib\n", id="telnetlib"),
    pytest.param("import httpx\n", id="httpx"),
    pytest.param("import aiohttp\n", id="aiohttp"),
]


@pytest.mark.parametrize("source", NETWORK_SOURCES)
def test_network_access_is_rejected(source: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_NETWORK_ACCESS in decision.violations


# --------------------------------------------------------------------------
# Rejection class 3: host/persistent writes
# --------------------------------------------------------------------------

HOST_WRITE_SOURCES = [
    pytest.param("handle = open(path, 'w')\n", id="open-write"),
    pytest.param("handle = open(path, 'a')\n", id="open-append"),
    pytest.param("handle = open(path, 'rb')\n", id="open-read"),
    pytest.param("import os\nos.remove(path)\n", id="os-remove"),
    pytest.param("import os\nos.rename(source, target)\n", id="os-rename"),
    pytest.param("import shutil\nshutil.rmtree(directory)\n", id="shutil-rmtree"),
    pytest.param("from pathlib import Path\nPath(target).write_text(data)\n", id="path-write-text"),
    pytest.param("from pathlib import Path\nPath(target).write_bytes(data)\n", id="path-write-bytes"),
    pytest.param("import winreg\nwinreg.CreateKey(winreg.HKEY_CURRENT_USER, key)\n", id="winreg"),
    pytest.param("advapi32.RegSetValueExW(handle, name, 0, 1, data, size)\n", id="reg-set-value"),
    pytest.param("import os\nos.environ.update({'X': '1'})\n", id="environ-write"),
]


@pytest.mark.parametrize("source", HOST_WRITE_SOURCES)
def test_host_writes_are_rejected(source: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_HOST_WRITE in decision.violations


def test_host_write_rule_also_covers_ctypes_windll() -> None:
    decision = ta.evaluate_tool_authoring_request(
        _request(source_code="import ctypes\nctypes.windll.kernel32.WriteFile(...)\n")
    )
    assert decision.accepted is False
    assert ta.VIOLATION_HOST_WRITE in decision.violations
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


# --------------------------------------------------------------------------
# Rejection class 4: missing reproducible information
# --------------------------------------------------------------------------


def test_empty_source_code_is_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code="  \n\t "))
    assert decision.accepted is False
    assert ta.VIOLATION_SOURCE_CODE_REQUIRED in decision.violations


def test_empty_output_schema_is_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(output_schema={}))
    assert decision.accepted is False
    assert ta.VIOLATION_OUTPUT_SCHEMA_REQUIRED in decision.violations


def test_empty_failure_modes_are_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(failure_modes=()))
    assert decision.accepted is False
    assert ta.VIOLATION_FAILURE_MODES_REQUIRED in decision.violations


@pytest.mark.parametrize(
    "tool_name",
    ["Tool-Bad", "1bad", "bad name", "", "a", "__init__", "bad__name", "bad_", "class", "bad.tool"],
)
def test_unsafe_tool_names_are_rejected(tool_name: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(tool_name=tool_name))
    assert decision.accepted is False
    assert ta.VIOLATION_TOOL_NAME_UNSAFE in decision.violations


@pytest.mark.parametrize("tool_name", ["xor_config_decoder", "pe_section_entropy2", "t3_join"])
def test_safe_snake_case_tool_names_are_accepted(tool_name: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(tool_name=tool_name))
    assert decision.accepted is True


def test_missing_purpose_and_gap_kind_are_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(purpose=" ", gap_kind=""))
    assert decision.accepted is False
    assert ta.VIOLATION_PURPOSE_REQUIRED in decision.violations
    assert ta.VIOLATION_GAP_KIND_REQUIRED in decision.violations


def test_unknown_proposer_is_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(proposed_by="subagent"))
    assert decision.accepted is False
    assert ta.VIOLATION_PROPOSED_BY_UNKNOWN in decision.violations


@pytest.mark.parametrize("proposed_by", ["model", "deterministic"])
def test_known_proposers_are_accepted(proposed_by: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(proposed_by=proposed_by))
    assert decision.accepted is True


def test_non_deterministic_source_is_rejected() -> None:
    sources = [
        "import time\nstamp = time.time()\n",
        "import random\nkey = random.randbytes(4)\n",
        "import uuid\nrun_id = uuid.uuid4()\n",
        "import os\nsalt = os.urandom(8)\n",
        "seed = id(blob)\n",
    ]
    for source in sources:
        decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
        assert decision.accepted is False, source
        assert ta.VIOLATION_NON_DETERMINISTIC in decision.violations


# --------------------------------------------------------------------------
# Rejection class 5: input selectors
# --------------------------------------------------------------------------


def test_empty_input_selectors_are_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(input_selectors=()))
    assert decision.accepted is False
    assert ta.VIOLATION_INPUT_SELECTORS_REQUIRED in decision.violations


def test_unknown_selector_key_is_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(
        _request(input_selectors=({"kind": "artifact_slice", "byteoffset": 512},))
    )
    assert decision.accepted is False
    assert ta.VIOLATION_INPUT_SELECTOR_KEY_UNKNOWN in decision.violations


@pytest.mark.parametrize(
    "selectors",
    [
        ("not-a-mapping",),
        ({"kind": "artifact_slice", "anchor": {"rva": 4096}},),
        ({"kind": "artifact_slice", "byte_offset": object()},),
        ({"byte_offset": 512},),
    ],
)
def test_malformed_selectors_are_rejected(selectors: tuple[object, ...]) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(input_selectors=selectors))
    assert decision.accepted is False
    assert ta.VIOLATION_INPUT_SELECTOR_INVALID in decision.violations


def test_declarative_selector_vocabulary_is_open_for_values() -> None:
    selectors = (
        {"kind": "decoded_buffer", "label": "config-window", "sha256": "0" * 64},
        {"kind": "function", "name": "socket", "rva": 4096},
    )
    decision = ta.evaluate_tool_authoring_request(_request(input_selectors=selectors))
    assert decision.accepted is True


# --------------------------------------------------------------------------
# Rejection class 6: resource limits
# --------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(LIMIT_KEYS))
def test_limit_above_the_hard_ceiling_is_rejected(key: str) -> None:
    limits: dict[str, object] = {
        "wall_seconds": 10,
        "cpu_seconds": 5,
        "instruction_budget": 10_000,
        "max_output_bytes": 1_024,
    }
    limits[key] = ta.HARD_TOOL_LIMITS[key] + 1
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=limits))
    assert decision.accepted is False
    assert ta.VIOLATION_RESOURCE_LIMIT_EXCEEDED in decision.violations


def test_partially_declared_limits_are_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(
        _request(resource_limits={"wall_seconds": 10})
    )
    assert decision.accepted is False
    assert ta.VIOLATION_RESOURCE_LIMIT_MISSING in decision.violations


def test_unknown_limit_key_is_rejected() -> None:
    limits: dict[str, object] = {
        "wall_seconds": 10,
        "cpu_seconds": 5,
        "instruction_budget": 10_000,
        "max_output_bytes": 1_024,
        "memory_mb": 512,
    }
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=limits))
    assert decision.accepted is False
    assert ta.VIOLATION_RESOURCE_LIMIT_UNKNOWN_KEY in decision.violations


@pytest.mark.parametrize("value", ["10", 0, -1, None, True, 10.5])
def test_invalid_limit_values_are_rejected(value: object) -> None:
    limits: dict[str, object] = {
        "wall_seconds": value,
        "cpu_seconds": 5,
        "instruction_budget": 10_000,
        "max_output_bytes": 1_024,
    }
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=limits))
    assert decision.accepted is False
    assert ta.VIOLATION_RESOURCE_LIMIT_INVALID in decision.violations


def test_non_mapping_limits_are_rejected() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(resource_limits=(10, 5)))
    assert decision.accepted is False
    assert ta.VIOLATION_RESOURCE_LIMIT_INVALID in decision.violations


# --------------------------------------------------------------------------
# Source-text judgement: tradeoffs and fail-closed behaviour
# --------------------------------------------------------------------------


def test_documentation_mentioning_subprocess_is_accepted() -> None:
    """Deliberate tradeoff: comments/docstrings are stripped before matching.

    A tool that *names* dangerous APIs in its documentation grants no power, and
    security tooling legitimately names them.  Code-level indirection is covered
    separately by the dynamic-import guard below.
    """
    decision = ta.evaluate_tool_authoring_request(
        _request(source_code=DOCSTRING_ONLY_SOURCE, purpose="static window decode")
    )
    assert decision.accepted is True
    assert decision.violations == ()


def test_documentation_allowance_does_not_let_a_real_call_through() -> None:
    source = DOCSTRING_ONLY_SOURCE + "\nimport subprocess\nsubprocess.run([target])\n"
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


def test_string_built_module_names_are_caught_by_the_indirection_guard() -> None:
    source = 'module = __import__("sub" + "process")\nmodule.run([target])\n'
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(
            "import subprocess as sp\nsp.run([target])\n",
            ta.VIOLATION_SAMPLE_EXECUTION,
            id="aliased-subprocess",
        ),
        pytest.param(
            "import os as host\nhost.system(command)\n",
            ta.VIOLATION_SAMPLE_EXECUTION,
            id="aliased-os-exec",
        ),
        pytest.param(
            "import os as host\nhost.remove(path)\n",
            ta.VIOLATION_HOST_WRITE,
            id="aliased-os-remove",
        ),
        pytest.param(
            "import http as transport\ntransport.client.HTTPConnection(host)\n",
            ta.VIOLATION_NETWORK_ACCESS,
            id="aliased-http",
        ),
        pytest.param(
            "from subprocess import run as launch\nlaunch([target])\n",
            ta.VIOLATION_SAMPLE_EXECUTION,
            id="aliased-from-import",
        ),
    ],
)
def test_aliased_imports_do_not_evade_the_gate(source: str, expected: str) -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert expected in decision.violations


def test_re_compile_is_not_mistaken_for_dynamic_code_construction() -> None:
    """Dotted calls stay safe: `re.compile(` is a pattern, not `compile(`."""
    source = (
        "import re\n\n"
        "URL_PATTERN = re.compile(r'https?://')\n\n\n"
        "def find_urls(blob: bytes) -> list[str]:\n"
        "    return URL_PATTERN.findall(blob.decode('latin-1'))\n"
    )
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is True
    assert decision.violations == ()


def test_nested_archive_reads_from_granted_bytes_are_allowed() -> None:
    """Only bare `open(` is host access; dotted `.open(` on in-memory data is not."""
    source = (
        "import io\n"
        "import zipfile\n\n\n"
        "def entry(blob: bytes, name: str) -> bytes:\n"
        "    archive = zipfile.ZipFile(io.BytesIO(blob))\n"
        "    return archive.open(name).read()\n"
    )
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is True
    assert decision.violations == ()


def test_unscannable_source_fails_closed() -> None:
    decision = ta.evaluate_tool_authoring_request(_request(source_code="value = (1,\n"))
    assert decision.accepted is False
    assert ta.VIOLATION_SOURCE_UNSCANNABLE in decision.violations


def test_unscannable_source_is_still_scanned_as_raw_text() -> None:
    source = "# import subprocess\nvalue = (1,\n"
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_SOURCE_UNSCANNABLE in decision.violations
    assert ta.VIOLATION_SAMPLE_EXECUTION in decision.violations


def test_scanning_never_executes_the_submitted_source(tmp_path: Path) -> None:
    target = tmp_path / "must-not-exist.txt"
    source = "from pathlib import Path\n" f"Path({str(target)!r}).write_text('executed')\n"
    decision = ta.evaluate_tool_authoring_request(_request(source_code=source))
    assert decision.accepted is False
    assert ta.VIOLATION_HOST_WRITE in decision.violations
    assert not target.exists()


# --------------------------------------------------------------------------
# Decision shape, ordering and immutability
# --------------------------------------------------------------------------


def test_violations_are_deduplicated_and_canonically_ordered() -> None:
    decision = ta.evaluate_tool_authoring_request(
        _request(
            tool_name="Bad-Name",
            source_code="import subprocess\nimport socket\nos.remove(path)\n",
            output_schema={},
            failure_modes=(),
        )
    )
    assert decision.accepted is False
    assert len(set(decision.violations)) == len(decision.violations)
    expected = [item for item in ta.TOOL_AUTHORING_VIOLATIONS if item in set(decision.violations)]
    assert list(decision.violations) == expected
    assert set(decision.violations) >= {
        ta.VIOLATION_TOOL_NAME_UNSAFE,
        ta.VIOLATION_SAMPLE_EXECUTION,
        ta.VIOLATION_NETWORK_ACCESS,
        ta.VIOLATION_HOST_WRITE,
        ta.VIOLATION_OUTPUT_SCHEMA_REQUIRED,
        ta.VIOLATION_FAILURE_MODES_REQUIRED,
    }


def test_evaluation_is_deterministic() -> None:
    request = _request(source_code="import socket\n")
    first = ta.evaluate_tool_authoring_request(request)
    second = ta.evaluate_tool_authoring_request(request)
    assert first == second


def test_rejection_does_not_mutate_the_request() -> None:
    request = _request(source_code="import subprocess\n")
    snapshot = copy.deepcopy(request)
    decision = ta.evaluate_tool_authoring_request(request)
    assert decision.accepted is False
    assert request == snapshot
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.tool_name = "other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.accepted = True  # type: ignore[misc]


def test_foreign_objects_are_not_accepted_as_requests() -> None:
    with pytest.raises(TypeError):
        ta.evaluate_tool_authoring_request("xor_config_decoder")  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Evidence nature: authored tools never produce DYNAMIC_OBSERVED
# --------------------------------------------------------------------------


def test_emulated_authored_tool_output_is_emulation_observed() -> None:
    assert ta.authored_tool_evidence_nature(emulated=True) == "EMULATION_OBSERVED"


def test_non_emulated_authored_tool_output_is_static_derived() -> None:
    assert ta.authored_tool_evidence_nature(emulated=False) == "STATIC_DERIVED"


@pytest.mark.parametrize("emulated", [True, False])
def test_authored_tool_evidence_nature_never_reports_dynamic_observation(emulated: bool) -> None:
    nature = ta.authored_tool_evidence_nature(emulated=emulated)
    assert nature != "DYNAMIC_OBSERVED"
    assert nature in ta.AUTHORED_TOOL_EVIDENCE_NATURES


def test_truthy_non_bool_emulated_flag_is_rejected() -> None:
    with pytest.raises(TypeError):
        ta.authored_tool_evidence_nature(emulated=1)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Policy metadata helper for the future execution seam
# --------------------------------------------------------------------------


def test_policy_metadata_declares_no_execution_and_no_network() -> None:
    request = _request()
    decision = ta.evaluate_tool_authoring_request(request)
    metadata = ta.authored_tool_policy_metadata(request, decision)
    assert metadata["kind"] == ta.TOOL_AUTHORING_POLICY_KIND
    assert metadata["tool_name"] == "xor_config_decoder"
    assert metadata["sample_execution"] is False
    assert metadata["network_access"] is False
    assert metadata["max_cpu_seconds"] == ta.DEFAULT_TOOL_LIMITS["cpu_seconds"]
    assert metadata["evidence_nature_ceiling"] == "EMULATION_OBSERVED"
    assert metadata["evidence_nature_ceiling"] != "DYNAMIC_OBSERVED"
    assert metadata["violations"] == []
