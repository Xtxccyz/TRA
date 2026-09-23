from __future__ import annotations

import inspect
from dataclasses import replace
from types import SimpleNamespace

from sqlalchemy import select

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.emulation_plan import (
    controlled_emulation_windows,
    unicorn_granted_windows_for_worker,
)
from threat_report_agent.investigation import ActionSpec, ActionType, DeepMiningPlanner
from threat_report_agent.simulation_adapters import (
    IsolatedSimulationRunner,
    SimulationResult,
    linux_x86_64_exit_elf,
)
from threat_report_agent.emulation.policy import (
    SimulationExecutionPolicy,
    SimulationRequest,
    request_for_granted_window,
    simulation_policy_from_settings,
)
from threat_report_agent.tools.tool_execution import StaticToolActivities, ToolRunRequest


def _docker_settings(**overrides: object) -> SimpleNamespace:
    values = dict(
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs="",
        tool_execution_mode="temporal",
        simulation_timeout_seconds=8,
        simulation_instruction_budget=100_000,
        simulation_max_output_bytes=65536,
        simulation_max_input_bytes=4_194_304,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_docker_policy_enables_without_local_process() -> None:
    policy = simulation_policy_from_settings(_docker_settings())
    assert policy.enabled is True
    assert policy.isolation_kind == "docker"
    assert policy.allow_local_process is False


def test_docker_runner_requires_the_isolated_worker() -> None:
    policy = SimulationExecutionPolicy(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="controlled-emu-worker-v1",
        worker_image_digest="sha256:emu-worker-v1",
        allowed_simulators=("unicorn",),
        isolation_kind="docker",
        allow_local_process=False,
        max_timeout_seconds=8,
        max_instruction_budget=100_000,
    )
    result = IsolatedSimulationRunner(
        {"unicorn": lambda request: SimulationResult("SUCCEEDED", "unicorn")},
        policy=policy,
    ).run(
        SimulationRequest(
            "unicorn",
            "must-not-be-read.bin",
            input_bytes=b"\x90\xc3",
            worker_identity="controlled-emu-worker-v1",
            worker_image_digest="sha256:emu-worker-v1",
            timeout_seconds=8,
            instruction_budget=64,
        )
    )
    assert result.status == "WORKER_REQUIRED"
    assert result.stop_reason == "WORKER_REQUIRED"
    assert result.as_dict()["evidence_nature"] != "EMULATION_OBSERVED"


def test_docker_worker_process_may_execute_granted_bytes() -> None:
    policy = SimulationExecutionPolicy(
        enabled=True,
        profile="static-first-controlled-emulation",
        worker_identity="controlled-emu-worker-v1",
        worker_image_digest="sha256:emu-worker-v1",
        allowed_simulators=("unicorn",),
        isolation_kind="docker",
        allow_local_process=False,
        max_timeout_seconds=8,
        max_instruction_budget=100_000,
    )
    result = IsolatedSimulationRunner(
        {"unicorn": lambda request: SimulationResult("SUCCEEDED", "unicorn")},
        policy=policy,
        execute_in_process=True,
    ).run(
        SimulationRequest(
            "unicorn",
            "must-not-be-read.bin",
            input_bytes=b"\x90\xc3",
            worker_identity="controlled-emu-worker-v1",
            worker_image_digest="sha256:emu-worker-v1",
            timeout_seconds=8,
            instruction_budget=64,
        )
    )
    assert result.status == "SUCCEEDED"


def test_windows_prefer_recovered_start_over_thread_creator() -> None:
    pe = {
        "image_base": 0x400000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x2000,
                "raw_size": 0x2000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x800
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "name": "spawn_worker",
                "entry": "0x401000",
                "references_from": [{"target_name": "CreateThread"}],
            }
        ],
        [
            {
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
                    ],
                },
            }
        ],
        allow_speakeasy=False,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    assert unicorn[0]["anchor"]["function_entry"] == "0x401500"
    assert unicorn[0]["anchor"]["role"] == "os_thread_start_routine"


def test_windows_prefer_how_callsite_over_thread_creator_flood() -> None:
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x20000,
                "raw_size": 0x20000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x8000
    flood = [
        {
            "name": f"spawn_{index}",
            "entry": hex(0x140001000 + index * 0x100),
            "references_from": [{"target_name": "CreateThread"}],
        }
        for index in range(6)
    ]
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "name": "CreateProcessW",
                "entry": "0x140046948",
            },
            {
                "name": "FUN_140004605",
                "entry": "0x140004605",
                "references_from": [{"target_name": "CreateProcessW"}],
                "call_targets": [{"target_name": "CreateProcessW"}],
            },
            *flood,
        ],
        [
            {
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateProcessW",
                    "callsite": "0x140008dce",
                    "function_entry": "0x140004605",
                    "command": "FoxitPDFReader.exe",
                },
            },
            {
                "kind": "resolved_api",
                "value": {
                    "api": "GetProcAddress",
                    "resolver": "GetProcAddress",
                    "function_entry": "0x140002000",
                },
            },
        ],
        allow_speakeasy=False,
        max_windows=4,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    assert unicorn[0]["anchor"]["role"] == "how_callsite"
    assert unicorn[0]["anchor"]["function_entry"] == "0x140004605"
    entries = [item["anchor"]["function_entry"] for item in unicorn]
    assert "0x140004605" in entries
    assert "0x140002000" in entries
    assert "0x140046948" not in entries


def test_as_int_address_parses_ghidra_fun_and_bare_hex() -> None:
    from threat_report_agent.emulation_plan import _as_int_address

    assert _as_int_address("FUN_140004605") == 0x140004605
    assert _as_int_address("140004605") == 0x140004605
    assert _as_int_address("0x140004605") == 0x140004605
    assert _as_int_address("140038ae0") == 0x140038ae0
    assert _as_int_address("FUN_140038ae0") == 0x140038ae0
    assert _as_int_address("[R8]") is None
    assert _as_int_address("[0x140038ae0]") is None
    assert _as_int_address("4096") == 4096
    assert _as_int_address(0x140004605) == 0x140004605


def test_windows_grant_how_entry_from_fun_label_and_bare_hex() -> None:
    """Ghidra persist stores FUN_140004605 / 140004605, not only 0x-prefixed VA."""
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x20000,
                "raw_size": 0x20000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x8000
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "name": "FUN_140004605",
                "entry": "FUN_140004605",
                "references_from": [{"target_name": "CreateProcessW"}],
                "call_targets": [{"target_name": "CreateProcessW"}],
            },
            {
                "name": "FUN_140001500",
                "entry": "FUN_140001500",
                "references_from": [{"target_name": "CreateThread"}],
            },
        ],
        [
            {
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateProcessW",
                    "callsite": "140008dce",
                    "function_entry": "140004605",
                    "command": "FoxitPDFReader.exe",
                },
            },
        ],
        preferred_entries=("FUN_140004605",),
        allow_speakeasy=False,
        max_windows=4,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    entries = [item["anchor"]["function_entry"] for item in unicorn]
    roles = {item["anchor"]["function_entry"]: item["anchor"]["role"] for item in unicorn}
    assert "0x140004605" in entries
    assert roles["0x140004605"] == "persist_how"
    assert "0x140001500" in entries
    assert not any("[" in str(item["anchor"]["function_entry"]) for item in unicorn)


def test_windows_do_not_grant_memory_operand_as_unicorn_entry() -> None:
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x20000,
                "raw_size": 0x20000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x8000
    windows = controlled_emulation_windows(
        content,
        pe,
        [{"name": "thunk", "entry": "[R8]"}],
        [
            {
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateThread",
                    "arguments": [
                        {"index": 2, "register": "R8", "value": "[R8]", "resolved": False},
                    ],
                },
            }
        ],
        preferred_entries=("[R8]",),
        allow_speakeasy=False,
        max_windows=4,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert all(item["anchor"]["function_entry"] != "[R8]" for item in unicorn)


def test_windows_prefer_how_and_persist_entry_over_thread_start_flood() -> None:
    """CreateThread lpStartAddress flood must not starve persist HOW windows."""
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x20000,
                "raw_size": 0x20000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x8000
    thread_starts = [
        {
            "kind": "api_argument_trace",
            "value": {
                "api": "CreateThread",
                "arguments": [
                    {
                        "index": 2,
                        "register": "R8",
                        "value": hex(0x140001500 + index * 0x100),
                        "resolved": True,
                    },
                ],
            },
        }
        for index in range(6)
    ]
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "name": "FUN_140004605",
                "entry": "0x140004605",
                "references_from": [{"target_name": "CreateProcessW"}],
                "call_targets": [{"target_name": "CreateProcessW"}],
            },
            {
                "name": "FUN_140005000",
                "entry": "0x140005000",
                "planned_emulation": True,
            },
        ],
        [
            {
                "kind": "api_argument_trace",
                "value": {
                    "api": "CreateProcessW",
                    "function_entry": "0x140004605",
                    "command": "FoxitPDFReader.exe",
                    "creation_flags": "0x000f4240",
                },
            },
            *thread_starts,
        ],
        allow_speakeasy=False,
        max_windows=4,
        preferred_entries=("0x140005000",),
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    roles = [item["anchor"]["role"] for item in unicorn]
    entries = [item["anchor"]["function_entry"] for item in unicorn]
    assert roles[0] in {"persist_how", "how_callsite", "investigation_entry"}
    assert "0x140004605" in entries
    assert "0x140005000" in entries
    assert roles.count("os_thread_start_routine") < 4
    assert entries.index("0x140004605") < next(
        (
            index
            for index, role in enumerate(roles)
            if role == "os_thread_start_routine"
        ),
        len(entries),
    )


def test_unicorn_granted_windows_drop_speakeasy_and_serialize_hex() -> None:
    granted = unicorn_granted_windows_for_worker(
        (
            {
                "simulator": "speakeasy",
                "input_bytes": b"MZ" + b"\x00" * 80,
                "entry_address": 0x1000000,
                "anchor": {"role": "full_pe"},
            },
            {
                "simulator": "unicorn",
                "input_bytes": b"\x90" * 16,
                "entry_address": 0x140004605,
                "anchor": {"function_entry": "0x140004605", "role": "how_callsite"},
            },
        )
    )
    assert len(granted) == 1
    assert granted[0]["simulator"] == "unicorn"
    assert granted[0]["input_hex"] == (b"\x90" * 16).hex()
    assert granted[0]["role"] == "how_callsite"
    assert "memory_maps" not in granted[0]
    assert "input_bytes" not in granted[0]


def test_planned_investigation_entry_gets_a_unicorn_window() -> None:
    """CONTROLLED_EMULATE target= entries must not be filtered to thread creators only."""
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x20000,
                "raw_size": 0x20000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x8000
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "entry": "0x140001200",
                "planned_emulation": True,
            }
        ],
        allow_speakeasy=False,
        allow_qiling=False,
        max_windows=4,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    assert unicorn[0]["anchor"]["function_entry"] == "0x140001200"
    assert unicorn[0]["anchor"]["role"] == "investigation_entry"
    assert unicorn[0]["entry_address"] == 0x140001200
    assert unicorn[0]["memory_maps"]


def test_windows_prefer_decoded_config_xref_function(monkeypatch) -> None:
    monkeypatch.setattr(
        "threat_report_agent.emulation_plan.recover_static_xor_configs",
        lambda *_args, **_kwargs: ({"virtual_address": 0x14004C8E1},),
    )
    pe = {
        "image_base": 0x140000000,
        "sections": [
            {
                "name": ".text",
                "virtual_address": 0x1000,
                "virtual_size": 0x4000,
                "raw_size": 0x4000,
                "raw_offset": 0,
            }
        ],
    }
    content = b"\x90" * 0x4000
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "entry": "0x140001200",
                "planned_emulation": True,
            },
            {
                "entry": "0x140003000",
                "references_from": [
                    {
                        "type": "DATA",
                        "from": "0x140003010",
                        "to": "0x14004c8e1",
                        "target_name": "DAT_14004c8e1",
                    }
                ],
            },
        ],
        allow_speakeasy=False,
        allow_qiling=False,
        max_windows=4,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    assert unicorn[0]["anchor"]["role"] == "decoded_config_xref"
    assert unicorn[0]["entry_address"] == 0x140003000


def test_speakeasy_window_is_kept_when_unique_threads_exist() -> None:
    pe = {
        "image_base": 0x400000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "raw_offset": 0x40,
            }
        ],
    }
    content = b"MZ" + b"\x00" * 62 + b"\x90" * 0x200
    windows = controlled_emulation_windows(
        content,
        pe,
        [
            {
                "name": "spawn_worker",
                "entry": "0x401000",
                "references_from": [{"target_name": "CreateThread"}],
            }
        ],
        allow_speakeasy=True,
    )
    simulators = [item["simulator"] for item in windows]
    assert "unicorn" in simulators
    assert "speakeasy" in simulators


def test_windows_grant_pe_entry_when_no_thread_start_is_recovered() -> None:
    """T4: Unicorn still gets a bounded window from the PE entry when no OS thread start is known."""
    pe = {
        "image_base": 0x400000,
        "entry_rva": 0x1000,
        "sections": [
            {
                "virtual_address": 0x1000,
                "virtual_size": 0x200,
                "raw_size": 0x200,
                "raw_offset": 0x40,
            }
        ],
    }
    content = b"MZ" + b"\x00" * 62 + b"\x90" * 0x200
    windows = controlled_emulation_windows(
        content,
        pe,
        (),
        allow_speakeasy=False,
    )
    unicorn = [item for item in windows if item["simulator"] == "unicorn"]
    assert unicorn
    assert unicorn[0]["anchor"]["role"] == "pe_entry"
    assert len(unicorn[0]["input_bytes"]) >= 8


def test_qiling_window_is_granted_for_linux_elf() -> None:
    """T4/B09: the applicable Qiling path is a Linux ELF, not a Windows PE."""
    elf = linux_x86_64_exit_elf()
    windows = controlled_emulation_windows(
        elf,
        {},
        (),
        allow_speakeasy=False,
        allow_qiling=True,
    )
    qiling = [item for item in windows if item["simulator"] == "qiling"]
    assert qiling
    assert qiling[0]["input_bytes"][:4] == b"\x7fELF"
    assert qiling[0]["anchor"]["role"] == "linux_elf"


def test_qiling_window_records_pe_os_mismatch() -> None:
    """A Windows PE must NOT be dispatched to the Linux-only Qiling adapter.

    This test previously asserted `anchor.role == "os_mismatch"`, i.e. it locked in the waste: the window
    carried 64 bytes of a PE and the adapter could only ever answer `UNSUPPORTED / NOT_LINUX_ELF`, because
    the outcome was decided here at construction time. Measured across the database that produced 418
    `os_mismatch` evidence rows, none with an observation.

    The window is still emitted - so the reader learns the adapter does not apply - but it is marked as a
    skip, carries no bytes, and states the reason.
    """
    content = b"MZ" + b"\x00" * 64
    windows = controlled_emulation_windows(
        content,
        {"image_base": 0x400000, "entry_rva": 0x1000, "sections": []},
        (),
        allow_speakeasy=False,
        allow_qiling=True,
    )
    qiling = [item for item in windows if item["simulator"] == "qiling"]
    assert qiling
    assert qiling[0]["skip_reason"] == "qiling_requires_linux_elf"
    assert not qiling[0]["input_bytes"], "a window that cannot succeed must not carry bytes"
    assert qiling[0]["anchor"]["role"] == "qiling_not_applicable"
    assert "ELF" in qiling[0]["anchor"]["reason"] or "Linux" in qiling[0]["anchor"]["reason"]


def test_thread_start_routine_contract_includes_controlled_emulate() -> None:
    caller = {
        "id": "ctx-0x401000",
        "kind": "function_context",
        "nature": "STATIC_OBSERVED",
        "value": {
            "name": "spawn_worker",
            "entry": "0x401000",
            "call_targets": [{"target_name": "CreateThread", "from": "0x401000"}],
        },
        "anchor": {"function_entry": "0x401000"},
    }
    trace = {
        "id": "trace-createthread",
        "kind": "api_argument_trace",
        "nature": "STATIC_DERIVED",
        "value": {
            "api": "CreateThread",
            "function_entry": "0x401000",
            "arguments": [
                {"index": 2, "register": "R8", "value": "0x401500", "resolved": True},
            ],
        },
        "anchor": {"function_entry": "0x401000"},
    }
    planned = DeepMiningPlanner.plan_actions([caller, trace], scheduled=set(), max_actions=24)
    start_actions = [item for item in planned if item.parameters.get("target") == "0x401500"]
    assert start_actions
    required = start_actions[0].plan["deep_investigation_contract"]["required_action_types"]
    assert ActionType.CONTROLLED_EMULATE.value in required


def test_decode_and_loader_queues_include_controlled_emulate() -> None:
    decode_rows = [
        {
            "id": "ctx-decode",
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": "decode_config",
                "entry": "0x402000",
                "call_targets": [{"target_name": "CryptDecrypt"}],
            },
            "anchor": {"function_entry": "0x402000"},
        },
        {
            "id": "decode-window",
            "kind": "mechanism_decode_window",
            "nature": "STATIC_DERIVED",
            "value": {"function_entry": "0x402000", "transformation": "xor"},
            "anchor": {"function_entry": "0x402000"},
        },
    ]
    decode_actions = DeepMiningPlanner.plan_actions(decode_rows, scheduled=set(), max_actions=24)
    decode_types = {item.action_type for item in decode_actions if item.parameters.get("target") == "0x402000"}
    assert ActionType.GET_DECOMPILE in decode_types
    assert ActionType.CONTROLLED_EMULATE in decode_types

    loader_rows = [
        {
            "id": "ctx-loader",
            "kind": "function_context",
            "nature": "STATIC_OBSERVED",
            "value": {
                "name": "resolve_apis",
                "entry": "0x403000",
                "call_targets": [{"target_name": "GetProcAddress"}],
            },
            "anchor": {"function_entry": "0x403000"},
        }
    ]
    loader_actions = DeepMiningPlanner.plan_actions(loader_rows, scheduled=set(), max_actions=24)
    loader_types = {item.action_type for item in loader_actions if item.parameters.get("target") == "0x403000"}
    assert ActionType.CONTROLLED_EMULATE in loader_types


def test_worker_emulates_granted_snippet_without_opening_sample_path(
    test_settings, tmp_path
) -> None:
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn",),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    from threat_report_agent.content_store import LocalContentStore

    store = LocalContentStore(settings.content_store_path)
    snippet = bytes.fromhex("34 41 c3") + b"\x90" * 13
    source = store.put(snippet)
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-1",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "entry_address": 0x1000000,
                    "role": "os_thread_start_routine",
                }
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    assert result["status"] == "SUCCEEDED"
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))
    assert payload["kind"] == "emulation"
    assert payload["results"]
    assert payload["results"][0]["status"] == "SUCCEEDED"
    assert payload["results"][0]["simulator"] == "unicorn"
    assert all("sample" not in str(item).casefold() for item in payload["results"][0].get("limitations", []))


def test_worker_parses_hex_and_fun_granted_entry(test_settings, tmp_path) -> None:
    """JSON/Ghidra may send 0x... or FUN_ labels; do not remap those windows to 0x1000000."""
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn",),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    from threat_report_agent.content_store import LocalContentStore

    store = LocalContentStore(settings.content_store_path)
    snippet = bytes.fromhex("34 41 c3") + b"\x90" * 13
    source = store.put(snippet)
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-fun",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "input_hex": snippet.hex(),
                    "entry_address": "FUN_140004605",
                    "function_entry": "FUN_140004605",
                    "role": "persist_how",
                }
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    assert result["status"] == "SUCCEEDED"
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))
    assert payload["results"]
    blob = str(payload["results"][0])
    assert "0x140004605" in blob
    policy = simulation_policy_from_settings(settings)
    parsed = request_for_granted_window(
        policy,
        {
            "simulator": "unicorn",
            "input_bytes": snippet,
            "entry_address": "0x140004605",
            "function_entry": "FUN_140004605",
        },
    )
    assert parsed.entry_address == 0x140004605


def test_a_grant_carrying_run_still_dispatches_the_full_pe_speakeasy_window(test_settings, tmp_path) -> None:
    """MEASURED defect (plan T1a): a non-empty `granted_windows` used to suppress the full-PE emulator.

    The worker took the grant branch and never called `controlled_emulation_windows`, so the Speakeasy window
    the API had ALREADY planned was never built - and Speakeasy is the only adapter here with Windows API
    semantics. Measured on the real Resume run: 20 Unicorn runs, 9 of them "SUCCEEDED", every one with ZERO
    api observations, while Speakeasy was never dispatched once.

    This is the criterion that must fail without the fix: with grants present and Speakeasy allowed, a
    Speakeasy window has to reach the execution list.
    """
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy"),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    from threat_report_agent.content_store import LocalContentStore

    store = LocalContentStore(settings.content_store_path)
    # A minimal MZ image: `controlled_emulation_windows` builds the full-PE window whenever Speakeasy is
    # allowed and the content looks like a PE, which is the condition under test.
    source = store.put(b"MZ" + b"\x00" * 256)
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-grant-plus-fullpe",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "allow_speakeasy": True,
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "entry_address": 0x140004605,
                    "input_hex": (b"\x90" * 16).hex(),
                    "role": "how_callsite",
                }
            ],
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))

    simulators = [str(item.get("simulator")) for item in payload["results"]]
    assert "unicorn" in simulators, "the granted snippet window was dropped"
    assert "speakeasy" in simulators, (
        "a grant-carrying run did not dispatch the full-PE Speakeasy window, so the only adapter with Windows "
        f"API semantics never runs (simulators dispatched: {simulators})"
    )


def test_the_full_pe_window_does_not_spend_a_granted_window_slot(test_settings, tmp_path) -> None:
    """MEASURED regression (review, Standards/Spec axes): T1's window silently cut grants from 4 to 3.

    R5 requires T1 to be incremental dispatch - "只做增量派发，不改既有窗口". The full-PE window is PREPENDED
    to `windows` and the per-run budget then sliced `windows[:4]`, so on a grant-carrying run the Speakeasy
    window consumed one of the four slots and the fourth grant became NOT_EXECUTED / WINDOW_BUDGET_EXHAUSTED.

    The literal 4 did not change, which is exactly why this was easy to miss: the REACH changed, not the
    number, and the existing grant test carries only ONE grant so it cannot see the difference. The caller's
    grants are not T1's to spend.

    FAILS BEFORE THE FIX: the fourth unicorn window comes back NOT_EXECUTED.
    """
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy"),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    from threat_report_agent.content_store import LocalContentStore

    store = LocalContentStore(settings.content_store_path)
    source = store.put(b"MZ" + b"\x00" * 256)
    activity = StaticToolActivities(settings, store)

    granted = [
        {
            "simulator": "unicorn",
            "entry_address": 0x140004605 + index * 0x10,
            "input_hex": (b"\x90" * 16).hex(),
            "role": "how_callsite",
        }
        # Exactly the pre-existing budget: four grants is what a grant-carrying run used to execute.
        for index in range(4)
    ]
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-grant-plus-fullpe-budget",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={"allow_speakeasy": True, "granted_windows": granted},
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))

    unicorn_executed = [
        item
        for item in payload["results"]
        if str(item.get("simulator")) == "unicorn" and item.get("status") != "NOT_EXECUTED"
    ]
    assert len(unicorn_executed) == 4, (
        "the full-PE window spent a granted window slot: "
        f"{len(unicorn_executed)}/4 grants executed, statuses="
        f"{[(item.get('simulator'), item.get('status')) for item in payload['results']]}"
    )
    assert "speakeasy" in [str(item.get("simulator")) for item in payload["results"]], (
        "the full-PE window must still be dispatched - it is incremental, not a trade"
    )


def test_a_window_the_budget_excluded_is_not_counted_as_a_real_simulation() -> None:
    """MEASURED hazard (T1a audit finding F3): the truncation row could pass as a real emulation result.

    A window the per-run budget excludes never invoked a simulator, so it must be a placeholder in the
    strictest sense. Without that, the row - which carries `simulator="unicorn"` - satisfied
    `has_real_simulation_result`, and the CONTROLLED_EMULATE gate in `analysis_task_orchestration.py` reads
    that predicate as "a real simulation landed": a displaced, never-executed window could stop the loop
    retrying a capability that never ran. That is fabricated evidence.
    """
    from threat_report_agent.controlled_emulation import (
        is_placeholder_status,
        is_real_simulation_value,
    )

    assert is_placeholder_status("NOT_EXECUTED"), (
        "a window the budget excluded is not registered as a placeholder, so it can be mistaken for a run"
    )
    assert not is_real_simulation_value({"status": "NOT_EXECUTED", "simulator": "unicorn"}), (
        "a never-executed window counts as a real simulation result"
    )


def test_a_window_the_budget_excluded_does_not_change_the_overall_status() -> None:
    """MEASURED hazard (T1a audit finding F2): one truncation row flipped UNSUPPORTED into FAILED.

    `emulation_overall_from_results` returns UNSUPPORTED only when EVERY status is UNSUPPORTED/UNAVAILABLE,
    so an extra row falsified that test and the run fell through to the `current_overall == "SUCCEEDED"`
    branch and reported FAILED. A window that never ran says nothing about the outcome, so it must not
    participate in the aggregation at all.
    """
    from threat_report_agent.tools.tool_execution import emulation_overall_from_results

    only_unsupported = [
        {"status": "UNSUPPORTED", "simulator": "qiling"},
        {"status": "UNAVAILABLE", "simulator": "speakeasy"},
    ]
    with_truncation = only_unsupported + [
        {"status": "NOT_EXECUTED", "simulator": "unicorn", "stop_reason": "WINDOW_BUDGET_EXHAUSTED"}
    ]

    assert emulation_overall_from_results(only_unsupported, current_overall="SUCCEEDED")[0] == "UNSUPPORTED"
    assert (
        emulation_overall_from_results(with_truncation, current_overall="SUCCEEDED")[0] == "UNSUPPORTED"
    ), "a window that never ran changed the run's overall status"


def test_a_budget_excluded_window_is_recorded_rather_than_dropped(test_settings, tmp_path) -> None:
    """A truncated set must SAY it is truncated - the report side's own rule, applied to the worker.

    Five windows are granted but the per-run budget is four, so exactly one must appear as NOT_EXECUTED with
    the budget stop reason rather than vanishing. Without this test the new report could be deleted without
    any test noticing (T1a audit finding F1).
    """
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn",),
        simulation_allow_local_process=False,
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    from threat_report_agent.content_store import LocalContentStore

    store = LocalContentStore(settings.content_store_path)
    source = store.put(bytes.fromhex("90" * 16))
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-over-budget",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "entry_address": 0x140004000 + index * 0x10,
                    "input_hex": (b"\x90" * 16).hex(),
                }
                for index in range(5)
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))

    excluded = [item for item in payload["results"] if item.get("status") == "NOT_EXECUTED"]
    assert len(excluded) == 1, (
        f"the window the budget excluded was not recorded exactly once: {payload['results']}"
    )
    assert excluded[0]["stop_reason"] == "WINDOW_BUDGET_EXHAUSTED"
    assert payload["results"][0]["status"] != "NOT_EXECUTED", "the budget must not exclude the first window"


def test_worker_records_qiling_unsupported_without_rootfs(test_settings, tmp_path) -> None:
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "qiling"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs="",
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    store = LocalContentStore(settings.content_store_path)
    snippet = bytes.fromhex("34 41 c3") + b"\x90" * 13
    source = store.put(snippet)
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-qiling",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="granted.bin",
        parameters={
            "granted_windows": [
                {
                    "simulator": "unicorn",
                    "entry_address": 0x1000000,
                    "role": "os_thread_start_routine",
                }
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))
    qiling = [item for item in payload["results"] if item.get("simulator") == "qiling"]
    assert qiling
    assert qiling[0]["status"] == "UNSUPPORTED"
    assert qiling[0]["stop_reason"] == "ROOTFS_REQUIRED"
    assert qiling[0]["evidence_nature"] == "STATIC_INFERRED"


def test_worker_runs_qiling_linux_elf_when_rootfs_pinned(test_settings, tmp_path) -> None:
    """T4: worker must actually invoke Qiling on a benign ELF instead of ROOTFS_REQUIRED."""
    root = tmp_path / "qiling-rootfs"
    for name in ("bin", "lib", "lib64", "tmp", "proc", "dev"):
        (root / name).mkdir(parents=True)
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "qiling"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs=str(root),
        simulation_timeout_seconds=8,
        simulation_instruction_budget=64,
        content_store_path=str(tmp_path / "content"),
    )
    store = LocalContentStore(settings.content_store_path)
    source = store.put(linux_x86_64_exit_elf())
    activity = StaticToolActivities(settings, store)
    request = ToolRunRequest(
        case_id="case-1",
        task_id="task-1",
        trace_id="trace-1",
        artifact_id="artifact-1",
        tool_run_id="emu-qiling-elf",
        tool_name="controlled-emulator",
        tool_version="0.1.0",
        content_sha256=source.sha256,
        storage_key=source.storage_key,
        logical_path="t5-b09-qiling-linux.elf",
        parameters={
            "granted_windows": [
                {
                    "simulator": "qiling",
                    "entry_address": 0x400078,
                    "role": "linux_elf",
                }
            ]
        },
        max_cpu_seconds=8,
        max_memory_mb=512,
        task_queue="static-emu",
        sample_execution=False,
        network_access=False,
    )
    result = activity._execute(request)
    payload = __import__("json").loads(store.read(str(result["output_storage_key"])))
    qiling = [item for item in payload["results"] if item.get("simulator") == "qiling"]
    assert qiling
    assert qiling[0]["stop_reason"] != "ROOTFS_REQUIRED"
    assert qiling[0]["status"] in {"SUCCEEDED", "FAILED", "UNAVAILABLE"}
    explained = " ".join(
        str(item) for item in [*qiling[0].get("assumptions", []), *qiling[0].get("limitations", [])]
    ).casefold()
    assert "linux" in explained


def test_post_static_emulation_does_not_disable_policy_speakeasy() -> None:
    from threat_report_agent.service import AnalysisService

    source = inspect.getsource(AnalysisService._run_post_static_emulation)
    assert "allow_speakeasy=False" not in source


def test_post_static_emulation_needed_when_unicorn_is_only_deferred() -> None:
    """T4: Speakeasy success must not skip a Unicorn window that is still DEFERRED."""
    from threat_report_agent.controlled_emulation import (
        has_real_simulation_result,
        post_static_emulation_needed,
    )
    from threat_report_agent.service import AnalysisService

    rows = [
        SimpleNamespace(value={"status": "SUCCEEDED", "simulator": "speakeasy"}),
        SimpleNamespace(value={"status": "DEFERRED_TO_WORKER", "simulator": "unicorn"}),
    ]
    assert AnalysisService._has_real_simulation_result(rows, "speakeasy")
    assert not AnalysisService._has_real_simulation_result(rows, "unicorn")
    assert has_real_simulation_result(rows, "speakeasy")
    assert not has_real_simulation_result(rows, "unicorn")
    assert post_static_emulation_needed(
        allowed_simulators=("unicorn", "speakeasy"),
        artifact_type="pe",
        results=rows,
        planned_entries=(),
    )


def test_post_static_emulation_needed_skips_speakeasy_on_elf() -> None:
    from threat_report_agent.controlled_emulation import post_static_emulation_needed

    rows: list[object] = []
    assert not post_static_emulation_needed(
        allowed_simulators=("speakeasy",),
        artifact_type="elf",
        results=rows,
        planned_entries=(),
    )
    assert post_static_emulation_needed(
        allowed_simulators=("speakeasy",),
        artifact_type="pe",
        results=rows,
        planned_entries=(),
    )


def test_placeholder_simulation_does_not_cover_a_start_routine() -> None:
    from threat_report_agent.controlled_emulation import simulation_covers_request

    deferred = {
        "status": "DEFERRED_TO_WORKER",
        "simulator": "unicorn",
        "function_entry": "0x401000",
    }
    assert not simulation_covers_request(deferred, "0x401000")


def test_analysis_dispatches_isolated_emu_then_continues_investigation() -> None:
    """Kunglao DISPATCH then continue: emu is not a tail job after saturation."""
    from threat_report_agent.task.analysis_task_orchestration import (
        continue_investigation_after_action,
        run_analysis_task_investigation,
        run_emulation_informed_investigation,
    )
    from threat_report_agent.service import AnalysisService

    analysis = inspect.getsource(AnalysisService._run_analysis)
    workbench = inspect.getsource(AnalysisService.workbench_submit_action)
    composed = inspect.getsource(run_analysis_task_investigation)
    informed = inspect.getsource(run_emulation_informed_investigation)
    workbench_continue = inspect.getsource(continue_investigation_after_action)
    assert "run_analysis_task_investigation" in analysis
    saturate = composed.index("_run_saturated_investigation")
    after_emu = composed.index("_run_emulation_informed_investigation")
    assert saturate < after_emu
    assert "_run_post_static_emulation" in informed
    assert "_run_saturated_investigation" in informed
    assert "saturated=False" in workbench_continue
    assert "continue_investigation_after_action" in workbench


def test_saturated_investigation_dispatches_emu_before_deferred_tail() -> None:
    """Coverage placeholders must not be finalized UNKNOWN before the worker runs."""
    from threat_report_agent.task.analysis_task_orchestration import run_saturated_investigation

    source = inspect.getsource(run_saturated_investigation)
    coverage = source.index('ledger_phase="coverage"')
    emu = source.index("_run_post_static_emulation")
    tail = source.index('ledger_phase="tail"')
    assert coverage < emu < tail


def test_emulation_informed_investigation_continues_when_worker_writes_real_rows(
    test_settings, monkeypatch
) -> None:
    from threat_report_agent.service import AnalysisService

    service = AnalysisService(
        test_settings,
        Database(test_settings.database_url),
        LocalContentStore(test_settings.content_store_path),
    )
    counts = [0]
    calls: list[str] = []

    def fake_count(_task_id: str) -> int:
        return counts[0]

    def fake_emu(_task_id: str) -> list[str]:
        counts[0] = 1
        calls.append("emu")
        return []

    monkeypatch.setattr(service, "_real_simulation_result_count", fake_count)
    monkeypatch.setattr(service, "_run_post_static_emulation", fake_emu)
    monkeypatch.setattr(
        service,
        "_run_saturated_investigation",
        lambda _task_id: calls.append("investigate") or [],
    )
    monkeypatch.setattr(
        service,
        "_run_investigation_loop",
        lambda _task_id, **_kwargs: calls.append("loop") or [],
    )
    service._run_emulation_informed_investigation("task-emu")
    assert calls == ["emu", "investigate"]
    calls.clear()
    counts[0] = 0
    service._run_emulation_informed_investigation("task-emu", saturated=False)
    assert calls == ["emu", "loop"]
    calls.clear()
    monkeypatch.setattr(service, "_real_simulation_result_count", lambda _task_id: 0)
    service._run_emulation_informed_investigation("task-emu")
    assert calls == ["emu"]


def test_persist_emulation_supersedes_deferred_placeholder_rows(test_settings) -> None:
    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence, ToolRun
    from threat_report_agent.service import AnalysisService

    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("supersede deferred emu")
    with database.session_factory.begin() as session:
        stored = store.put(b"MZ" + b"\x00" * 64)
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        placeholder_run = ToolRun(
            task_id=task.id,
            artifact_id=artifact.id,
            tool_name="controlled-emulator",
            tool_version="0.1.0",
            status="SUCCEEDED",
        )
        session.add(placeholder_run)
        session.flush()
        session.add(
            Evidence(
                task_id=task.id,
                artifact_id=artifact.id,
                tool_run_id=placeholder_run.id,
                module="static_triage",
                kind="simulation_result",
                nature="STATIC_INFERRED",
                value={
                    "status": "DEFERRED_TO_WORKER",
                    "simulator": "unicorn",
                    "stop_reason": "DEFERRED_TO_WORKER",
                },
                anchor={"type": "unique_thread_emulation", "simulator": "unicorn"},
            )
        )
        task_id = task.id
        artifact_id = artifact.id
    from datetime import UTC, datetime

    service._persist_emulation_result(
        task_id=task_id,
        artifact_id=artifact_id,
        tool_run_id="emu-worker-1",
        status="SUCCEEDED",
        error=None,
        results=[
            {
                "status": "SUCCEEDED",
                "simulator": "unicorn",
                "stop_reason": "UNMAPPED_RETURN",
            }
        ],
        parameters={"scheduler": "post_static_emulation"},
        execution_metadata={"executor": "temporal"},
        started_at=datetime.now(UTC),
        scheduler="post_static_emulation",
    )
    with database.session_factory() as session:
        rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.kind == "simulation_result",
                )
            )
        )
    statuses = {
        str((row.value or {}).get("simulator")): str((row.value or {}).get("status"))
        for row in rows
        if isinstance(row.value, dict)
    }
    assert "SUCCEEDED" in {str((row.value or {}).get("status")) for row in rows}
    deferred = [
        row
        for row in rows
        if isinstance(row.value, dict)
        and str(row.value.get("status") or "").upper() == "DEFERRED_TO_WORKER"
        and str(row.value.get("simulator") or "").casefold() == "unicorn"
    ]
    assert not deferred, statuses


def test_persist_failed_unmapped_emulation_is_observed(test_settings) -> None:
    from datetime import UTC, datetime

    from threat_report_agent.models import AnalysisTask, Artifact, ContentBlob, Evidence
    from threat_report_agent.service import AnalysisService

    database = Database(test_settings.database_url)
    store = LocalContentStore(test_settings.content_store_path)
    service = AnalysisService(test_settings, database, store)
    database.create_schema()
    case = service.create_case("failed unmapped emu")
    with database.session_factory.begin() as session:
        stored = store.put(b"MZ" + b"\x00" * 64)
        session.add(
            ContentBlob(
                sha256=stored.sha256,
                size=stored.size,
                media_type="application/octet-stream",
                storage_key=stored.storage_key,
            )
        )
        session.flush()
        task = AnalysisTask(case_id=case.id, lifecycle="RUNNING")
        session.add(task)
        session.flush()
        artifact = Artifact(
            task_id=task.id,
            content_sha256=stored.sha256,
            logical_path="sample.exe",
            detected_type="pe",
            role="EXECUTABLE",
        )
        session.add(artifact)
        session.flush()
        task_id = task.id
        artifact_id = artifact.id
    service._persist_emulation_result(
        task_id=task_id,
        artifact_id=artifact_id,
        tool_run_id="emu-failed-unmapped",
        status="FAILED",
        error="UNMAPPED_RETURN",
        results=[
            {
                "status": "FAILED",
                "simulator": "unicorn",
                "stop_reason": "UNMAPPED_RETURN",
                "function_entry": "0x401000",
            }
        ],
        parameters={"scheduler": "post_static_emulation"},
        execution_metadata={"executor": "temporal"},
        started_at=datetime.now(UTC),
        scheduler="post_static_emulation",
    )
    with database.session_factory() as session:
        rows = list(
            session.scalars(
                select(Evidence).where(
                    Evidence.task_id == task_id,
                    Evidence.kind == "simulation_result",
                )
            )
        )
    assert rows
    assert rows[0].nature == "EMULATION_OBSERVED"
    assert rows[0].value["status"] == "FAILED"
    assert rows[0].value["stop_reason"] == "UNMAPPED_RETURN"
    assert "DYNAMIC_OBSERVED" not in {row.nature for row in rows}


def test_docker_controlled_emulate_does_not_record_in_process_worker_required(
    test_settings,
) -> None:
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy", "qiling"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs="",
        tool_execution_mode="temporal",
    )
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-start",
            artifact_id="artifact-1",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={
                "name": "spawn_worker",
                "entry": "0x401000",
                "call_targets": [{"target_name": "CreateThread"}],
            },
            anchor={"function_entry": "0x401000"},
        )
    ]
    action = ActionSpec(
        id="emu-1",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x401000"},
    )
    observations = service._derive_investigation_observations(
        rows,
        action,
        artifact_content=b"MZ" + b"\x00" * 64,
        pe_summary={"image_base": 0x400000},
    )
    sim_results = [item for item in observations if item["kind"] == "simulation_result"]
    by_simulator = {
        str((item.get("value") or {}).get("simulator")): item["value"]
        for item in sim_results
        if isinstance(item.get("value"), dict)
    }
    assert by_simulator["unicorn"]["status"] == "DEFERRED_TO_WORKER"
    assert "qiling" not in by_simulator
    deferred = [item for item in observations if item["kind"] == "investigation_observation"]
    assert deferred
    assert deferred[0]["value"]["deferred"] == "isolated_emu_worker"


def test_docker_controlled_emulate_cites_existing_worker_unicorn(
    test_settings,
) -> None:
    """Investigation CONTROLLED_EMULATE must not replace a real worker Unicorn row with DEFERRED."""
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy", "qiling"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs="",
    )
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="emu-worker-unicorn",
            artifact_id="artifact-1",
            kind="simulation_result",
            nature="EMULATION_OBSERVED",
            value={
                "status": "SUCCEEDED",
                "simulator": "unicorn",
                "stop_reason": "END_ADDRESS",
                "function_entry": "0x401000",
            },
            anchor={"type": "unique_thread_emulation", "simulator": "unicorn"},
        )
    ]
    action = ActionSpec(
        id="emu-1",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x401000"},
    )
    observations = service._derive_investigation_observations(
        rows,
        action,
        artifact_content=b"MZ" + b"\x00" * 64,
        pe_summary={"image_base": 0x400000, "entry_rva": 0x1000},
    )
    sim_results = [
        item["value"]
        for item in observations
        if item["kind"] == "simulation_result" and isinstance(item.get("value"), dict)
    ]
    unicorn = [item for item in sim_results if item.get("simulator") == "unicorn"]
    assert unicorn
    assert unicorn[0]["status"] == "SUCCEEDED"
    qiling = [item for item in sim_results if item.get("simulator") == "qiling"]
    assert not qiling


def test_docker_controlled_emulate_reuses_failed_worker_result(
    test_settings,
) -> None:
    """A FAILED isolated-worker row must not be replaced by another DEFERRED ticket."""
    from threat_report_agent.service import AnalysisService

    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy", "qiling"),
        simulation_allow_local_process=False,
        simulation_qiling_rootfs="",
    )
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="emu-worker-failed",
            artifact_id="artifact-1",
            kind="simulation_result",
            nature="STATIC_INFERRED",
            value={
                "status": "FAILED",
                "simulator": "unicorn",
                "stop_reason": "EXECUTION_ERROR",
                "function_entry": "0x140001420",
            },
            anchor={"type": "unique_thread_emulation", "simulator": "unicorn"},
        )
    ]
    action = ActionSpec(
        id="emu-1",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x140001420"},
    )
    observations = service._derive_investigation_observations(
        rows,
        action,
        artifact_content=b"MZ" + b"\x00" * 64,
        pe_summary={"image_base": 0x140000000, "entry_rva": 0x1420},
    )
    sim_results = [
        item["value"]
        for item in observations
        if item["kind"] == "simulation_result" and isinstance(item.get("value"), dict)
    ]
    unicorn = [item for item in sim_results if item.get("simulator") == "unicorn"]
    assert unicorn
    assert unicorn[0]["status"] == "FAILED"
    assert unicorn[0]["stop_reason"] == "EXECUTION_ERROR"
    assert all(item.get("status") != "DEFERRED_TO_WORKER" for item in sim_results)


def test_local_controlled_emulate_requests_speakeasy_when_policy_allows(
    test_settings, monkeypatch
) -> None:
    from threat_report_agent import service as service_module
    from threat_report_agent.service import AnalysisService

    captured: dict[str, object] = {}

    def fake_windows(*args: object, **kwargs: object) -> list[object]:
        captured["allow_speakeasy"] = kwargs.get("allow_speakeasy")
        return []

    monkeypatch.setattr(service_module, "controlled_emulation_windows", fake_windows)
    settings = replace(
        test_settings,
        simulation_profile="static-first-controlled-emulation",
        simulation_worker_identity="controlled-emu-worker-v1",
        simulation_worker_image_digest="sha256:emu-worker-v1",
        simulation_allowed_simulators=("unicorn", "speakeasy"),
        simulation_allow_local_process=True,
    )
    service = AnalysisService(
        settings,
        Database(settings.database_url),
        LocalContentStore(settings.content_store_path),
    )
    rows = [
        SimpleNamespace(
            id="ctx-start",
            artifact_id="artifact-1",
            kind="function_context",
            nature="STATIC_OBSERVED",
            value={"name": "spawn_worker", "entry": "0x401000"},
            anchor={"function_entry": "0x401000"},
        )
    ]
    action = ActionSpec(
        id="emu-1",
        action_type=ActionType.CONTROLLED_EMULATE,
        thread_id="thread-1",
        hypothesis_id="hypothesis-1",
        artifact_id="artifact-1",
        target_selector={"function_entry": "0x401000"},
    )
    service._derive_investigation_observations(
        rows,
        action,
        artifact_content=b"MZ" + b"\x00" * 64,
        pe_summary={"image_base": 0x400000},
    )
    assert captured["allow_speakeasy"] is False


def test_post_static_emulation_selects_elf_and_qiling() -> None:
    from threat_report_agent.controlled_emulation import post_static_emulation_needed
    from threat_report_agent.service import AnalysisService

    source = inspect.getsource(AnalysisService._run_post_static_emulation)
    assert 'detected_type.in_(("pe", "elf"))' in source
    assert post_static_emulation_needed(
        allowed_simulators=("qiling",),
        artifact_type="elf",
        results=(),
        planned_entries=(),
    )


def test_emulation_status_prefers_worker_outcome_over_deferred_placeholder() -> None:
    from threat_report_agent.report.reporting import build_emulation_status_projection

    deferred = SimpleNamespace(
        id="e-deferred",
        kind="simulation_result",
        value={"status": "DEFERRED_TO_WORKER", "simulator": "qiling"},
        anchor={},
    )
    failed = SimpleNamespace(
        id="e-unicorn",
        kind="simulation_result",
        value={"status": "FAILED", "simulator": "unicorn", "stop_reason": "EMULATOR_ERROR"},
        anchor={},
    )
    unsupported = SimpleNamespace(
        id="e-qiling",
        kind="simulation_result",
        value={"status": "UNSUPPORTED", "simulator": "qiling", "stop_reason": "NOT_LINUX_ELF"},
        anchor={},
    )
    projection = build_emulation_status_projection(
        {"e-deferred": deferred, "e-unicorn": failed, "e-qiling": unsupported}
    )
    assert projection["overall"] == "FAILED"
    assert projection["attempted"] is True
    listed = {str(item.get("status")) for item in projection["results"]}
    assert "DEFERRED_TO_WORKER" not in listed
    assert "UNSUPPORTED" in listed

    succeeded = SimpleNamespace(
        id="e-ok",
        kind="simulation_result",
        value={"status": "SUCCEEDED", "simulator": "unicorn"},
        anchor={},
    )
    ok = build_emulation_status_projection({"e-deferred": deferred, "e-ok": succeeded})
    assert ok["overall"] == "SUCCEEDED"
    superseded = SimpleNamespace(
        id="e-old",
        kind="simulation_result",
        value={"status": "SUPERSEDED_BY_WORKER", "simulator": "unicorn"},
        anchor={},
    )
    cleaned = build_emulation_status_projection({"e-old": superseded, "e-ok": succeeded})
    assert cleaned["overall"] == "SUCCEEDED"
    assert all(
        str(item.get("status")) != "SUPERSEDED_BY_WORKER" for item in cleaned["results"]
    )
    ok = build_emulation_status_projection({"e-deferred": deferred, "e-ok": succeeded})
    assert ok["overall"] == "SUCCEEDED"


def test_failed_pe_entry_emu_does_not_cover_a_later_thread_start() -> None:
    """A FAILED Unicorn row for the PE entry cannot stand in for another start routine."""
    from threat_report_agent.service import AnalysisService

    failed_entry = {
        "status": "FAILED",
        "simulator": "unicorn",
        "function_entry": "0x401000",
        "stop_reason": "EXECUTION_ERROR",
    }
    unlabeled_failed = {
        "status": "FAILED",
        "simulator": "unicorn",
        "stop_reason": "EXECUTION_ERROR",
    }
    assert AnalysisService._simulation_covers_request(failed_entry, "0x401000")
    assert not AnalysisService._simulation_covers_request(failed_entry, "0x401040")
    assert not AnalysisService._simulation_covers_request(unlabeled_failed, "0x401040")
    rows = [
        SimpleNamespace(kind="simulation_result", value=failed_entry),
        SimpleNamespace(kind="simulation_result", value=unlabeled_failed),
    ]
    matching = AnalysisService._matching_simulation_results(
        rows, {"function_entry": "0x401040"}
    )
    assert matching == ()
    assert AnalysisService._simulation_covers_request(failed_entry, "0x401000")
    reused = AnalysisService._matching_simulation_results(
        rows, {"function_entry": "0x401000"}
    )
    assert reused == ()


def test_target_selector_is_not_covered_by_unlabeled_failed_emu() -> None:
    """Live CONTROLLED_EMULATE selectors use target=, not function_entry=."""
    from threat_report_agent.service import AnalysisService

    unlabeled_failed = {
        "status": "FAILED",
        "simulator": "unicorn",
        "stop_reason": "EXECUTION_ERROR",
    }
    other_entry = {
        "status": "FAILED",
        "simulator": "unicorn",
        "function_entry": "0x140038ae0",
        "stop_reason": "EXECUTION_ERROR",
    }
    rows = [
        SimpleNamespace(kind="simulation_result", value=unlabeled_failed),
        SimpleNamespace(kind="simulation_result", value=other_entry),
    ]
    assert AnalysisService._matching_simulation_results(rows, {"target": "0x140016920"}) == ()
    assert AnalysisService._matching_simulation_results(rows, {"target": "140016920"}) == ()
    assert AnalysisService._simulation_covers_request(other_entry, "0x140038ae0")
    assert AnalysisService._matching_simulation_results(rows, {"target": "140038ae0"}) == ()


def test_simulation_covers_fun_label_and_hex_alias() -> None:
    from threat_report_agent.service import AnalysisService

    labeled = {
        "status": "SUCCEEDED",
        "simulator": "unicorn",
        "function_entry": "FUN_140038ae0",
    }
    hexed = {
        "status": "SUCCEEDED",
        "simulator": "unicorn",
        "function_entry": "0x140038ae0",
    }
    assert AnalysisService._simulation_covers_request(labeled, "0x140038ae0")
    assert AnalysisService._simulation_covers_request(labeled, "140038ae0")
    assert AnalysisService._simulation_covers_request(hexed, "FUN_140038ae0")
    assert AnalysisService._emulation_entry_key("140004605") == "0x140004605"
    assert AnalysisService._emulation_entry_key("FUN_140004605") == "0x140004605"
    assert not AnalysisService._simulation_covers_request(hexed, "[R8]")
    assert not AnalysisService._simulation_covers_request(hexed, "0x140004605")


def test_post_static_emu_still_needed_for_uncovered_start_routine() -> None:
    from threat_report_agent.service import AnalysisService

    existing = [
        SimpleNamespace(
            value={
                "status": "FAILED",
                "simulator": "unicorn",
                "function_entry": "0x401000",
            }
        )
    ]
    assert AnalysisService._has_real_simulation_result(existing, "unicorn")
    assert AnalysisService._has_uncovered_emulation_entry(
        existing, "unicorn", ("0x401000", "0x401040")
    )
    assert not AnalysisService._has_uncovered_emulation_entry(
        existing, "unicorn", ("0x401000",)
    )


def test_emulation_overall_keeps_unicorn_success_when_speakeasy_fails() -> None:
    """Leftover remainder: Speakeasy EXECUTION_ERROR must not hide Unicorn HOW."""
    from threat_report_agent.tools.tool_execution import emulation_overall_from_results

    overall, error = emulation_overall_from_results(
        [
            {"simulator": "unicorn", "status": "SUCCEEDED", "stop_reason": "UNMAPPED_DATA"},
            {"simulator": "speakeasy", "status": "FAILED", "stop_reason": "EXECUTION_ERROR"},
        ],
        current_overall="FAILED",
        current_error="EXECUTION_ERROR",
    )
    assert overall == "SUCCEEDED"
    assert error is None
    failed, failed_error = emulation_overall_from_results(
        [{"simulator": "speakeasy", "status": "FAILED", "stop_reason": "EXECUTION_ERROR"}],
        current_overall="FAILED",
        current_error="EXECUTION_ERROR",
    )
    assert failed == "FAILED"
    assert failed_error == "EXECUTION_ERROR"


def test_emu_worker_does_not_default_speakeasy_on() -> None:
    from threat_report_agent.tools.tool_execution import StaticToolActivities

    source = inspect.getsource(StaticToolActivities._execute_controlled_emulator)
    assert 'get("allow_speakeasy", False)' in source
    assert 'get("allow_speakeasy", True)' not in source
    assert "emulation_overall_from_results" in source


def test_placeholder_simulation_is_not_attempted_emulation() -> None:
    """G2 §6.4-1：占位行不得让 recovery_actions_for_gap 认为受控模拟已尝试。

    DEFERRED_TO_WORKER / WORKER_REQUIRED / SUPERSEDED_BY_WORKER 是派发票据。
    把它们当成已尝试，会让镜像内缺口被静态收工而不是等真实 emu-worker 结果。
    """
    from threat_report_agent.investigation import recovery_actions_for_gap

    attempted = [ActionType.CONTROLLED_EMULATE.value]
    for status in ("DEFERRED_TO_WORKER", "WORKER_REQUIRED", "SUPERSEDED_BY_WORKER"):
        placeholder = {
            "kind": "simulation_result",
            "value": {"status": status, "simulator": "unicorn", "function_entry": "0x140001000"},
        }
        actions = recovery_actions_for_gap(
            "DECODE_CONFIG", ("consumer",), attempted=attempted, evidence=[placeholder]
        )
        assert ActionType.CONTROLLED_EMULATE.value in actions, status

    real = {
        "kind": "simulation_result",
        "value": {"status": "SUCCEEDED", "simulator": "unicorn", "function_entry": "0x140001000"},
    }
    actions = recovery_actions_for_gap(
        "DECODE_CONFIG", ("consumer",), attempted=attempted, evidence=[real]
    )
    assert ActionType.CONTROLLED_EMULATE.value not in actions


def test_stub_emulation_cannot_be_published_as_live_network_activity() -> None:
    """G2 §6.4-3：stub 成功不得写成「运行时已外联」或活 C2。"""
    from threat_report_agent.product_certification import static_wording_violations

    assert static_wording_violations("The sample connected to the C2 server.")
    assert static_wording_violations("C2 active; the server responded to the request.")
    # The honest isolated-emulation wording stays publishable.
    assert (
        static_wording_violations(
            "Static evidence reaches network transport APIs. Isolated emulation stubs "
            "WinHTTP, so no runtime network access was performed and the request body "
            "remains UNKNOWN(request)."
        )
        == []
    )


