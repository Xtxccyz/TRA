"""The published body must name the MODULE each import belongs to.

Two losses compounded, so both ends are locked here.

`reporting.build_pe_basics_projection` flattened
`{"module": "advapi32.dll", "functions": [...]}` into bare function strings; the store is where the
attribution died, so no renderer could recover it:

    ledger `pe_structure.imports`        9 descriptors / 136 names / 8 distinct modules
    document `pe_basics.imports`         bare names, module gone
    published body                       a single `（未限定模块）` bucket

`tests/test_report_import_modules.py` asserts the render half against a hand-built document. This
module asserts the PRODUCER half against `build_report_document` and locks the anti-starvation and
truncation-visibility properties that only exist on the producer side. A function test on either end
alone would have passed while the published artifact stayed wrong.
"""
from __future__ import annotations

from threat_report_agent.analyst_report import _notable_imports
from threat_report_agent.report.reporting import (
    _PE_IMPORT_NAME_CAP,
    _pe_import_entries,
    _pe_import_name_groups,
    _pe_import_symbols,
    build_pe_basics_projection,
)

# A real `pe_structure.imports` entry shape, copied from the evidence table of task `ce7e310e`.
IMPORTS = [
    {"functions": ["RegCloseKey", "RegOpenKeyExW", "RegSetValueExW"], "module": "advapi32.dll",
     "thunk_rva": 386384, "thunk_width": 8},
    {"functions": ["CloseHandle", "CreateProcessW", "CreateThread", "OpenProcess"],
     "module": "kernel32.dll", "thunk_rva": 386432, "thunk_width": 8},
    {"functions": ["ShellExecuteW", "ShellExecuteExW"], "module": "shell32.dll",
     "thunk_rva": 387000, "thunk_width": 8},
    {"functions": ["ShowWindow"], "module": "user32.dll", "thunk_rva": 387024, "thunk_width": 8},
    {"functions": ["NtCreateNamedPipeFile", "NtReadFile"], "module": "ntdll.dll",
     "thunk_rva": 387040, "thunk_width": 8},
]
TOTAL_NAMES = 12
MODULES = ["advapi32.dll", "kernel32.dll", "shell32.dll", "user32.dll", "ntdll.dll"]


class _Evidence:
    """Minimal stand-in for `models.Evidence`; the projection reads `.kind` and `.value`."""

    def __init__(self, kind: str, value: dict, module: str = "static_triage", ident: str = "ev-x") -> None:
        self.kind = kind
        self.value = value
        self.module = module
        self.id = ident


def _pe_evidence() -> dict:
    return {
        "ev-pe": _Evidence(
            "pe_structure",
            {
                "format": "PE32+",
                "machine": "0x8664",
                "entry_rva": 5152,
                "subsystem": 2,
                "sections": [{"name": ".text"}, {"name": ".rdata"}],
                "imports": IMPORTS,
            },
        )
    }


def test_projection_keeps_module_attribution() -> None:
    """The store must carry the module, or every render is unqualified by construction."""
    pe = build_pe_basics_projection(_pe_evidence())
    assert pe is not None
    assert pe["import_name_total"] == TOTAL_NAMES
    assert pe["import_count"] == TOTAL_NAMES
    assert [entry["module"] for entry in pe["import_entries"]] == MODULES
    assert [entry["function_count"] for entry in pe["import_entries"]] == [3, 4, 2, 1, 2]
    assert pe["imports_truncated"] is False
    # qualified, so a consumer that only has the flat list can still split the module back out
    assert "advapi32.dll!RegSetValueExW" in pe["imports"]
    assert not any(str(symbol).startswith("!") for symbol in pe["imports"])


def test_the_real_stored_document_renders_no_unqualified_bucket() -> None:
    """Integration on REAL data: the accepted revision's own stored document.

    Building a document through `build_report_document` in a fixture needs the whole case/task/gate
    graph and asserts the fixture's shape more than the product's, so this instead takes the accepted
    revision's stored `document` (persisted at `.data/logs/official-document.json`) and applies the
    real projection from the real `pe_structure` evidence. That is exactly the pair the pipeline
    performs, without inventing any input.

    Before the fix the rendered body carried one `（未限定模块）` bucket holding every function name;
    the ledger's own 136 import names across eight modules were unreadable. Skipped when the captured
    artifacts are absent, so the suite stays runnable without the database.
    """
    import json
    from pathlib import Path

    from threat_report_agent.analyst_report import render_official_markdown

    document_path = Path(".data/logs/official-document.json")
    if not document_path.exists():
        import pytest

        pytest.skip("captured official document not present")

    document = json.loads(document_path.read_text(encoding="utf-8"))
    pe = build_pe_basics_projection(_pe_evidence())
    assert pe is not None and pe["import_entries"]

    # Inject the projection the way a fresh run would store it.
    injected = False
    for module in document.get("modules") or []:
        if not isinstance(module, dict):
            continue
        for row in module.get("rows") or []:
            if isinstance(row, dict) and row.get("type") == "pe_basics":
                row.update(pe)
                injected = True
    assert injected, "the captured document has no pe_basics row to grade"

    body = render_official_markdown(document)
    assert "（未限定模块）" not in body, (
        "the body still prints an unqualified import bucket although the PE table names its modules"
    )
    for module in MODULES:
        assert f"`{module}`：" in body, f"module {module} is not named in the rendered body"


def test_flat_list_is_round_robined_so_the_cap_cannot_starve_a_module() -> None:
    """`kernel32.dll` alone holds 70 of the sample's 136 names, so descriptor order hides modules.

    A `[:cap]` over a descriptor-ordered flat list looks complete while representing only the first
    few modules. Measured: the first four entries of the real table are advapi32 (3 names),
    api-ms-win-core-synch (3), kernel32 (70), ntdll (4), so a cap of 80 saw four modules and the rest
    were absent by luck of ordering, not by any judgement about relevance.
    """
    groups = _pe_import_name_groups(IMPORTS)
    flat = _pe_import_symbols(groups, cap=5)
    assert len(flat) == 5
    assert len({symbol.split("!")[0] for symbol in flat}) == 5, (
        "a five-symbol prefix must touch five modules, not one module's first five names"
    )
    # and the whole list keeps every name from every module
    assert len(_pe_import_symbols(groups, cap=TOTAL_NAMES)) == TOTAL_NAMES


def test_grouped_view_sees_modules_the_flat_cap_would_drop() -> None:
    """The renderer reads `import_entries`, so a capped flat list cannot lose a module."""
    groups = _pe_import_name_groups(IMPORTS)
    flat = _pe_import_symbols(groups, cap=4)
    rows = [{"type": "pe_basics", "import_entries": _pe_import_entries(groups), "imports": flat}]
    named = {module for module, _names in _notable_imports(rows, limit=50) if module}
    assert "ntdll.dll" in named, "a module dropped by the flat cap vanished from the grouped view"


def test_flat_list_without_entries_still_groups() -> None:
    """Backward compatibility: a document built before the fix carries only the flat list."""
    rows = [{"type": "pe_basics", "imports": ["advapi32.dll!RegSetValueExW", "ShellExecuteW"]}]
    grouped = dict(_notable_imports(rows, limit=50))
    assert "advapi32.dll" in grouped
    assert "" in grouped  # a genuinely unqualified name keeps the explicit unqualified label


def test_cap_is_a_reported_boundary_not_a_silent_truncation() -> None:
    """R3: the bound stays, and a consumer can tell it was applied."""
    groups = _pe_import_name_groups(
        [{"module": "big.dll", "functions": [f"Api{i:04d}Process" for i in range(400)]}]
    )
    flat = _pe_import_symbols(groups)
    assert len(flat) == _PE_IMPORT_NAME_CAP
    assert sum(len(names) for _m, names in groups) > _PE_IMPORT_NAME_CAP
    assert flat[0] == "big.dll!Api0000Process"


def test_a_descriptor_without_a_module_is_not_silently_merged() -> None:
    """An unnamed descriptor keeps its own group, so the label stays honest."""
    groups = _pe_import_name_groups([{"functions": ["CreateProcessW"]}, {"module": "ntdll.dll",
                                                                        "functions": ["NtReadFile"]}])
    assert groups == [("", ["CreateProcessW"]), ("ntdll.dll", ["NtReadFile"])]


def test_no_module_is_starved_by_a_larger_sibling() -> None:
    """The defect that matters most: a small module vanishing because a big one is big.

    Measured shape on task `ce7e310e`: `kernel32.dll` holds 70 of 136 names, `shell32.dll`,
    `user32.dll` and `ntdll.dll` hold one or two each. Greedy allocation in module order spent all 20
    slots inside `kernel32.dll` and never reached the others, so the section read as if the sample
    imported nothing from `ntdll` - the opposite of what the PE table says.

    The big module's names are real kernel32 exports, because the behaviour filter decides what
    reaches the section and invented names (`CreateThing00W`) legitimately do not.
    """
    kernel32 = [
        "CreateFileW", "CreateProcessW", "CreateThread", "CreateDirectoryW", "CreateFileMappingA",
        "CreateToolhelp32Snapshot", "CreateWaitableTimerExW", "OpenProcess", "ReadFile", "WriteFile",
        "VirtualProtect", "VirtualAlloc", "LoadLibraryW", "GetProcAddress", "DuplicateHandle",
        "CreateMutexW", "CreateEventW", "CreatePipe", "SetFilePointer", "WriteProcessMemory",
        "ReadProcessMemory", "ResumeThread", "SuspendThread", "CreateRemoteThread",
    ]
    rows = [
        {
            "type": "pe_basics",
            "import_entries": [
                {"module": "kernel32.dll", "functions": kernel32},
                {"module": "shell32.dll", "functions": ["ShellExecuteW"]},
                {"module": "ntdll.dll", "functions": ["NtCreateNamedPipeFile"]},
                {"module": "user32.dll", "functions": ["ShowWindow"]},
            ],
        }
    ]
    grouped = dict(_notable_imports(rows, limit=20))
    for module in ("shell32.dll", "ntdll.dll", "user32.dll"):
        assert grouped.get(module), f"{module} was starved out of the bounded overview by kernel32.dll"
    assert len(grouped["kernel32.dll"]) < len(kernel32), (
        "kernel32.dll still took every name it had rather than a fair share"
    )
    assert sum(len(names) for names in grouped.values()) <= 20


def test_module_spellings_of_one_module_are_merged() -> None:
    """`kernel32.dll` and `KERNEL32.dll` are one module and must not spend two slots.

    Measured: the split cost 17 of the 20 slots (`kernel32.dll` 15 + `KERNEL32.dll` 2), which is what
    pushed `shell32.dll` and `ntdll.dll` out.
    """
    rows = [
        {
            "type": "pe_basics",
            "import_entries": [
                {"module": "kernel32.dll", "functions": ["CreateProcessW", "CreateThread"]},
                {"module": "KERNEL32.dll", "functions": ["VirtualProtect", "ReadFileEx"]},
                {"module": "ntdll.dll", "functions": ["NtCreateNamedPipeFile"]},
            ],
        }
    ]
    grouped = dict(_notable_imports(rows, limit=20))
    folded = [module.casefold() for module in grouped]
    assert folded.count("kernel32.dll") == 1, "one module occupies two rows"
    merged = next(names for module, names in grouped.items() if module.casefold() == "kernel32.dll")
    assert {"CreateProcess", "CreateThread", "VirtualProtect", "ReadFileEx"} <= set(merged)
    assert "ntdll.dll" in grouped


def test_the_body_lists_every_module_in_the_import_table() -> None:
    """A module whose imports are all runtime symbols must still be named.

    Measured on task `ce7e310e`: the PE table names `msvcrt.dll` (28 functions) and
    `api-ms-win-core-synch-l1-2-0.dll` (3), and the behaviour filter legitimately drops their
    functions - so the body listed neither module, and a reader concluded the sample never imported
    from either. The complete module list is what makes the filtered list safe to bound.
    """
    from threat_report_agent.analyst_report import _document_import_modules

    document = {
        "modules": [
            {
                "id": "static_triage",
                "rows": [
                    {
                        "type": "pe_basics",
                        # Descriptor shapes as the projection emits them.
                        "import_entries": [
                            {"module": "kernel32.dll", "functions": ["CreateProcessW"],
                             "function_count": 1},
                            {"module": "KERNEL32.dll", "functions": ["VirtualProtect"],
                             "function_count": 1},
                            {"module": "msvcrt.dll",
                             "functions": ["__iob_func", "memcpy"], "function_count": 2},
                            {"module": "api-ms-win-core-synch-l1-2-0.dll",
                             "functions": ["WaitOnAddress"], "function_count": 1},
                        ],
                        "import_name_total": 5,
                    }
                ],
            }
        ]
    }
    modules = _document_import_modules(document)
    by_key = {key: (display, count) for display, key, count in modules}
    # Two descriptors for one module collapse, and their counts add up.
    assert by_key["kernel32.dll"] == ("kernel32.dll", 2)
    assert by_key["msvcrt.dll"][1] == 2
    assert "api-ms-win-core-synch-l1-2-0.dll" in by_key

    """An honestly unqualified descriptor keeps the explicit label; a named one never gets it."""
    rows = [
        {
            "type": "pe_basics",
            "import_entries": [
                {"module": "", "functions": ["ShellExecuteW"]},
                {"module": "advapi32.dll", "functions": ["RegSetValueExW"]},
            ],
        }
    ]
    grouped = dict(_notable_imports(rows, limit=50))
    assert "" in grouped
    assert "advapi32.dll" in grouped
    assert "" not in {module.casefold() for module in grouped if module}

