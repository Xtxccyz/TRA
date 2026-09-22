"""The published report must name the MODULE an imported API belongs to.

MEASURED GAP, on task `ce7e310e` (the accepted 24/24 revision's task), found by the new
`.scratch/check-projection-fidelity.py` instrument:

    ledger `code_api_call` rows                     606
    of which module-qualified (`.dll!Name`)         606
    distinct modules in the ledger                  advapi32.dll, api-ms-win-core-synch-l1-2-0.dll,
                                                    kernel32.dll, KERNEL32.dll, msvcrt.dll,
                                                    ntdll.dll, shell32.dll, user32.dll
    distinct modules in the published body          NONE

The body lists bare function names - `RegSetValueEx`, `CreateProcess`, `NtCreateNamedPipeFile`,
`WaitOnAddress` - so a reader cannot tell `ntdll.dll!NtCreateNamedPipeFile` from a WinINet or
WinHTTP import. That distinction is the analyst's first triage question: the import MODULE says which
capability family the call belongs to. `ntdll` means direct syscall-adjacent file I/O; `winhttp`
means HTTP; `advapi32` means registry. The benchmark report this product is graded against names its
modules explicitly.

`analyst_report._notable_imports` strips the qualifier before rendering. The ledger carries it on
every row, so this is a projection/render loss (R2), not missing evidence.

Assertions are on the PUBLISHED body, because that is what the objective grades ("正式报告本身必须携带").
"""

from __future__ import annotations

from threat_report_agent.analyst_report import render_official_markdown
from threat_report_agent.reporting import REPORT_V3_REQUIRED_SECTIONS


def _import_row(module: str, name: str, kind: str = "import_symbol") -> dict[str, object]:
    """An evidence row as the ledger stores a module-qualified import."""
    return {
        "id": f"ev-{module}-{name}",
        "kind": kind,
        "module": "static_triage",
        "nature": "STATIC_OBSERVED",
        "value": {"api": f"{module}!{name}", "name": name, "module": module},
        "anchor": {"type": kind},
    }


def _document(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "report_version": "3.0",
        "report_sections": list(REPORT_V3_REQUIRED_SECTIONS),
        "case_id": "case-imports",
        "task_id": "task-imports",
        "analysis_outcome": "PARTIAL",
        "analysis_class": "BOUNDED_STATIC_ANALYSIS",
        "analysis_coverage": {"mechanism_count": 1, "verified_mechanism_count": 0},
        "modules": [
            {
                "id": "static_triage",
                "title": "Static Triage",
                "summary": "",
                "rows": [
                    {
                        "type": "pe_basics",
                        "format": "PE32+",
                        "machine": "0x8664",
                        "path": "sample.exe",
                        # The shape `pe_basics` actually carries, as `build_report_document` emits it:
                        # module-qualified names. The FIRST version of this fixture put `imports` on a
                        # bare `pe_basics` row with an empty list and on separate `import_symbol`
                        # evidence rows, so it rendered nothing and the "failure" was the fixture.
                        "imports": [
                            "advapi32.dll!RegSetValueExW",
                            "advapi32.dll!RegOpenKeyExW",
                            "ntdll.dll!NtCreateNamedPipeFile",
                            "ntdll.dll!NtReadFile",
                            "winhttp.dll!WinHttpCrackUrl",
                            "kernel32.dll!CreateProcessW",
                            "shell32.dll!ShellExecuteW",
                            "user32.dll!ShowWindow",
                        ],
                    }
                ],
            }
        ],
        "trace": {},
    }


def _rows() -> list[dict[str, object]]:
    return [
        _import_row("advapi32.dll", "RegSetValueExW"),
        _import_row("advapi32.dll", "RegOpenKeyExW"),
        _import_row("ntdll.dll", "NtCreateNamedPipeFile"),
        _import_row("ntdll.dll", "NtReadFile"),
        _import_row("winhttp.dll", "WinHttpCrackUrl"),
        _import_row("kernel32.dll", "CreateProcessW"),
        _import_row("shell32.dll", "ShellExecuteW"),
        _import_row("user32.dll", "ShowWindow"),
    ]


def test_the_body_names_the_module_of_a_recovered_import() -> None:
    """`advapi32.dll!RegSetValueExW` must not degrade to a bare `RegSetValueExW`."""
    body = render_official_markdown(_document(_rows()))
    folded = body.casefold()
    for module in ("advapi32", "ntdll", "winhttp", "shell32"):
        assert module in folded, (
            f"the body never names the module `{module}`, so the reader cannot tell which capability "
            "family an imported API belongs to; the ledger qualifies all 606 of its code_api_call rows"
        )


def test_a_ntdll_file_api_is_distinguishable_from_a_winhttp_one() -> None:
    """The distinction that matters most: native file I/O vs network transport.

    Note the assertion is on the MODULE, not on a bare name: `_strip_aw_suffix` removes a trailing
    A/W from any name longer than two characters, so `NtReadFile` legitimately renders as
    `NtReadFil` and `ShowWindow` as `ShowWindo`. That is pre-existing presentation behaviour and not
    what this fix is about; the module qualifier is what makes the distinction readable.
    """
    body = render_official_markdown(_document(_rows()))
    folded = body.casefold()
    assert "ntdll" in folded and "winhttp" in folded, (
        "ntdll and winhttp are not both named, so `NtReadFile` and `WinHttpCrackUrl` are "
        "indistinguishable in the published body"
    )
    # The module-qualified grouping must be what carries the distinction.
    assert "`ntdll.dll`：" in body or "ntdll.dll`" in body, (
        "ntdll is mentioned but not as the grouping label for its imports, so the reader cannot tell "
        "which functions belong to it"
    )


def test_named_pipe_imports_are_not_filtered_out() -> None:
    """Measured: `NtCreateNamedPipeFile`/`NtReadFile`/`NtWriteFile` were dropped from the list.

    The `nt*` branch required a marker word, and `NtCreateNamedPipeFile` contains none of them, so
    the sample's named-pipe primitives vanished from a section that claims to list behaviour imports.
    """
    rows = [
        _import_row("ntdll.dll", "NtCreateNamedPipeFile"),
        _import_row("ntdll.dll", "NtReadFile"),
        _import_row("ntdll.dll", "NtWriteFile"),
        _import_row("shell32.dll", "ShellExecuteW"),
    ]
    body = render_official_markdown(_document(rows))
    folded = body.casefold()
    for token in ("ntcreatenamedpipe", "ntreadfil", "shell"):
        assert token in folded, (
            f"{token!r} is absent from the import list, so the sample's named-pipe / launch "
            "primitives are not reported"
        )


def test_the_import_section_still_stays_readable() -> None:
    """Naming modules must not turn the section into a 606-line dump.

    The bound matters: this section already truncates, and the fix must keep a per-module grouping
    rather than one line per imported function.
    """
    body = render_official_markdown(_document(_rows()))
    section = [
        line for line in body.splitlines()
        if line.strip().startswith("- `") and "!" in line
    ]
    assert len(section) <= 120, f"the import section grew to {len(section)} qualified lines"
