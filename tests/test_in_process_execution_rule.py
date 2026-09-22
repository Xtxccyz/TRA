"""One definition decides whether this process may run isolated-emulation bytes.

Why this exists: the answer was computed at one call site but HARDCODED `True` at two others
(`service.py:18386`, `service.py:18838`). Both were correct only because of guards far away - an early
return and an `elif` respectively - so a reader at either site saw `True` and could not tell what made it
safe, and a refactor moving the guard would silently make the host execute sample bytes.

The tests below pin the RULE, not a blanket "docker implies worker": the `allow_local_process` flag exists
to express a legitimate "docker API + host worker" development topology, and a blanket rule would break it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from threat_report_agent.simulation_adapters import may_execute_in_process

SERVICE = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent" / "service.py"


def _policy(**kwargs):
    from threat_report_agent.simulation_adapters import SimulationExecutionPolicy

    fields = {"isolation_kind": "process", "allow_local_process": False}
    fields.update(kwargs)
    return SimulationExecutionPolicy(**fields)


def test_production_never_executes_in_process() -> None:
    """The absolute standard, made explicit rather than left to `config.py`'s separate production check."""
    for isolation in ("process", "docker"):
        for allow in (False, True):
            assert may_execute_in_process(
                _policy(isolation_kind=isolation, allow_local_process=allow),
                environment="production",
            ) is False, f"production allowed in-process execution under {isolation}/{allow}"


def test_a_non_docker_isolation_executes_here() -> None:
    assert may_execute_in_process(_policy(isolation_kind="process"), environment="test") is True


def test_docker_defers_to_the_worker_by_default() -> None:
    assert may_execute_in_process(_policy(isolation_kind="docker"), environment="test") is False


def test_the_development_topology_is_preserved() -> None:
    """`allow_local_process` exists to express this; a blanket docker rule would break it.

    Pinned deliberately, because the obvious-looking "docker => always False" test is the WRONG fix and
    would fail here.
    """
    assert (
        may_execute_in_process(
            _policy(isolation_kind="docker", allow_local_process=True), environment="development"
        )
        is True
    )


def test_case_and_whitespace_do_not_change_the_verdict() -> None:
    for value in ("Production", " production ", "PRODUCTION"):
        assert may_execute_in_process(_policy(), environment=value) is False


def test_the_runner_default_agrees_with_the_single_definition() -> None:
    """The defect two independent reviewers found while the guard test above passed.

    `IsolatedSimulationRunner.__init__` had its own `execute_in_process = self.policy.isolation_kind !=
    "docker"` default - a SECOND rule ignoring both `allow_local_process` and the production veto. The two
    disagreed exactly on the topology `allow_local_process` exists to express, and no test compared them.
    This one does, over the whole matrix, for every environment.
    """
    from threat_report_agent.simulation_adapters import (
        IsolatedSimulationRunner,
        default_simulation_runner,
    )

    disagreements: list[str] = []
    for isolation in ("process", "docker", "local-process"):
        for allow in (False, True):
            for environment in ("production", "test", "development", ""):
                policy = _policy(isolation_kind=isolation, allow_local_process=allow)
                expected = may_execute_in_process(policy, environment=environment)
                got = IsolatedSimulationRunner(policy=policy, environment=environment).execute_in_process
                if got != expected:
                    disagreements.append(
                        f"{isolation}/allow_local={allow}/env={environment!r}: runner={got} helper={expected}"
                    )
                forwarded = default_simulation_runner(
                    policy, environment=environment
                ).execute_in_process
                if forwarded != expected:
                    disagreements.append(
                        f"default_simulation_runner {isolation}/allow_local={allow}/env={environment!r}: "
                        f"runner={forwarded} helper={expected}"
                    )
    assert not disagreements, (
        "the runner still decides in-process execution by a second rule: " + "; ".join(disagreements)
    )


def test_no_call_site_hardcodes_the_flag() -> None:
    """The actual regression guard: the value must be COMPUTED wherever it is used.

    Scope is stated honestly: this checks `service.py`, the module that composes the analysis. The
    emu-worker's own hardcoded `True` in `tool_execution.py` is a DIFFERENT question (the worker is the
    isolated side, so running there is the point) and is deliberately not asserted here.
    """
    source = SERVICE.read_text(encoding="utf-8")
    offenders = list(re.finditer(r"execute_in_process\s*=\s*True", source))
    assert not offenders, (
        f"service.py hardcodes execute_in_process=True at {len(offenders)} site(s); route it through "
        f"`may_execute_in_process` so the condition is visible where it is used"
    )
    assert "may_execute_in_process(" in source, "the helper is no longer used by service.py"


def test_every_service_call_site_passes_the_environment() -> None:
    """The production veto only exists if the call site supplies the environment.

    A reviewer's point: all three sites pass `environment=self.settings.environment` today, but NOTHING
    pinned that wiring, so dropping the argument would silently restore the pre-P0 behaviour and no test
    would fail. This is the missing half of the fix.
    """
    source = SERVICE.read_text(encoding="utf-8")
    calls = re.findall(r"may_execute_in_process\(([^)]*)\)", source, flags=re.S)
    assert calls, "service.py no longer calls the helper at all"
    missing = [call.strip() for call in calls if "environment" not in call]
    assert not missing, (
        f"{len(missing)} call site(s) omit the environment, which silently disables the production veto: "
        f"{missing}"
    )


def test_the_helper_is_the_only_definition() -> None:
    """No second rule derives `execute_in_process` from the isolation kind anywhere in the package.

    MEASURED before this test: the predicate was written out SIX times in `service.py` (five deferral
    sites plus the execution site), and `IsolatedSimulationRunner.__init__` carried a seventh, DIFFERENT
    version - `isolation_kind != "docker"` with NO trailing `or`. An earlier version of this guard grepped
    only for the `... != "docker" or` spelling, so it PASSED with that duplicate present: a guard test that
    blessed the defect it existed to catch. Two independent reviewers found the duplicate, not the test.

    The needle is deliberately "same line mentions both `isolation_kind` and `execute_in_process`" rather
    than a spelling. A raw `isolation_kind == "docker"` match is too broad - `service.py` legitimately uses
    it to choose between `WORKER_REQUIRED` and `FAILED` for an ungranted window, which is a reporting
    question and not an execution decision. Requiring the operator would be too narrow, since the duplicate
    that got through had no operator.
    """
    root = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
    offenders: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "isolation_kind" in line and "execute_in_process" in line:
                offenders.setdefault(str(path.relative_to(root)), []).append(f"{number}: {stripped}")
    assert list(offenders) == ["simulation_adapters.py"] or not offenders, (
        f"`execute_in_process` is derived from `isolation_kind` outside the single definition: {offenders}"
    )


def test_an_empty_environment_is_not_treated_as_production() -> None:
    """`environment=""` must not silently disable emulation; only the literal production does."""
    assert may_execute_in_process(_policy(isolation_kind="process"), environment="") is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
