"""One large string class must not crowd every other class out of the published facts.

MEASURED STARVATION. `build_string_fact_projection` ranks by (class-order, longest-first) and keeps the top
`limit`. Class order is a priority list, so a class that is EARLY in the list and has MANY members consumes
the entire budget. On the 白象 sample `64da3378` (task `b482617e`) the raw string layer holds:

    78  VB6 runtime symbols   -> class `compiler_fingerprint`
     1  `Wscript.Shell`       -> class `execution_api`   (a script host: an execution capability)

All 24 published facts were compiler symbols, and the body's own count line ("classified 43 of 1034") was
true while the single operationally interesting string stayed invisible. The section exists to surface
operational strings, so publishing only the compiler's symbol table defeats its purpose.

The fix is a per-class quota applied before rank order fills the remainder.
"""
from __future__ import annotations

from threat_report_agent.report.reporting import build_string_fact_projection


def _row(text: str, index: int) -> dict:
    return {"id": f"ev-{index}", "kind": "string", "value": {"text": text}}


def test_a_large_early_class_does_not_hide_a_small_late_class() -> None:
    """78 compiler symbols plus one script host must still publish the script host."""
    evidence = [_row(f"__vbaSymbol{index:03d}", index) for index in range(78)]
    evidence.append(_row("Wscript.Shell", 900))
    projection = build_string_fact_projection(evidence, limit=24)
    values = [str(item.get("value")) for item in projection]
    assert "Wscript.Shell" in values, (
        "the only operational string in the layer was crowded out by the compiler's symbol table"
    )
    assert len(projection) == 24


def test_every_populated_class_is_represented() -> None:
    """Four classes, one of them 60 members: all four must appear."""
    evidence = [_row(f"__vbaSymbol{index:03d}", index) for index in range(60)]
    evidence += [
        _row("Wscript.Shell", 100),
        _row("http://example.invalid/payload.exe", 101),
        _row("schtasks /create /tn x /tr y", 102),
    ]
    projection = build_string_fact_projection(evidence, limit=12)
    classes = {str(item.get("fact_class")) for item in projection}
    assert {"compiler_fingerprint", "execution_api", "remote_executable", "scheduled_task"} <= classes
    assert len(projection) <= 12


def test_the_budget_is_still_respected_and_filled() -> None:
    """A quota must not shrink the section: the remainder is filled in rank order."""
    evidence = [_row(f"__vbaSymbol{index:03d}", index) for index in range(40)]
    efficiency = build_string_fact_projection(evidence, limit=24)
    assert len(efficiency) == 24


def test_the_counts_still_describe_the_whole_layer() -> None:
    evidence = [_row(f"__vbaSymbol{index:03d}", index) for index in range(78)]
    evidence.append(_row("Wscript.Shell", 900))
    projection = build_string_fact_projection(evidence, limit=24)
    head = projection[0]
    assert head["published_count"] == len(projection)
    assert head["classified_count"] == 79
    assert head["total_string_rows"] == 79


def test_results_are_deterministic() -> None:
    """Rendering the same layer twice must give the same body."""
    evidence = [_row(f"__vbaSymbol{index:03d}", index) for index in range(30)]
    evidence += [_row("Wscript.Shell", 100), _row("schtasks /create", 101)]
    first = [item["value"] for item in build_string_fact_projection(evidence, limit=12)]
    second = [item["value"] for item in build_string_fact_projection(evidence, limit=12)]
    assert first == second


def test_a_script_host_is_classified_as_an_execution_capability() -> None:
    """`Wscript.Shell` + `.Exec` starts a process without importing CreateProcess."""
    from threat_report_agent.report.reporting import string_fact_class

    assert string_fact_class("Wscript.Shell") == "execution_api"
    assert string_fact_class("WScript.Shell.Exec") == "execution_api"
    assert string_fact_class("objShell.Exec(cmd)") == "execution_api"


def test_ordinary_prose_is_not_an_execution_api() -> None:
    """A bare `exec` token must not label English text as a capability."""
    from threat_report_agent.report.reporting import string_fact_class

    for value in ("executive summary", "execution is unobserved", "exec", "Exec", "shell32.dll"):
        assert string_fact_class(value) != "execution_api", f"{value!r} was read as an execution API"
