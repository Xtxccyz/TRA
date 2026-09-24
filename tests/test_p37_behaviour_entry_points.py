"""P3.7 contract: the six PHASE DRIVERS are reachable through public behaviour entry points, and the tests use them.

WHY THIS FILE EXISTS. Plan P3.7's requirement is that the test surface stop reaching into `AnalysisService` by private
name. Forty-six test call sites did exactly that for six phase drivers, and the reason they did is that the drivers had no
public entry point at all - so the fix had two halves, and this file pins both:

  * the public facade exists and is FAITHFUL: same parameters (including keyword-only ones and their defaults) and the
    same return annotation as the private implementation it delegates to. A facade whose signature drifts is a different
    interface, and the drift would be invisible to every other gate;
  * the facade really DELEGATES: calling it must reach the private implementation with the arguments forwarded as
    written, proven by replacing the private attribute with a recorder rather than by reading the source;
  * the MIGRATION IS COMPLETE: no test CALLS one of the six private names any more. This is the assertion that makes the
    step self-enforcing - a future test that reaches for `service._run_investigation_loop` fails here, with the reason.

WHAT IS DELIBERATELY NOT ASSERTED: production code still calls the private methods, and one test REPLACES
`_run_post_static_emulation` by attribute (`tests/test_analysis_task_orchestration.py`), which only works while the
production caller keeps using the private name. The completeness check therefore looks at CALL-shaped references only -
rewriting an assignment target would silently disconnect that patch, which is the failure this file is written to avoid.
"""
from __future__ import annotations

import ast
import inspect
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from threat_report_agent.service import AnalysisService  # noqa: E402

#: private driver -> the public behaviour entry point that must exist on the service.
FACADE = {
    "_run_investigation_loop": "run_investigation_loop",
    "_run_post_static_emulation": "run_post_static_emulation",
    "_run_gap_driven_model_rounds": "run_gap_driven_model_rounds",
    "_run_controlled_emulator": "run_controlled_emulator",
    "_record_ghidra_evidence": "record_ghidra_evidence",
    "_record_function_similarity": "record_function_similarity",
    "_derive_investigation_observations": "derive_investigation_observations",
    "_run_model_planning": "run_model_planning",
    "_run_simulation_window": "run_simulation_window",
    "_audit": "audit",
    "_analysis_progress": "analysis_progress",
    "_create_report_revision": "create_report_revision",
    "_freeze_snapshot": "freeze_snapshot",
    "_materialize_recovered_bytes_child": "materialize_recovered_bytes_child",
}


def _signature(function: object) -> list[tuple[str, str, object]]:
    return [
        (parameter.name, str(parameter.kind), parameter.default)
        for parameter in inspect.signature(function).parameters.values()  # type: ignore[arg-type]
    ]


@pytest.mark.parametrize("private,public", sorted(FACADE.items()))
def test_each_driver_has_a_public_entry_point_with_the_same_signature(private: str, public: str) -> None:
    assert hasattr(AnalysisService, private), f"{private} is gone, so the facade wraps nothing"
    assert hasattr(AnalysisService, public), (
        f"AnalysisService has no public `{public}`; plan P3.7 requires the test surface to call a behaviour entry point "
        f"rather than `{private}`"
    )
    assert _signature(getattr(AnalysisService, public)) == _signature(getattr(AnalysisService, private)), (
        f"`{public}` and `{private}` do not have the same parameters (names, kinds and defaults all count); a facade that "
        "drifts is a different interface"
    )
    assert inspect.signature(getattr(AnalysisService, public)).return_annotation == \
        inspect.signature(getattr(AnalysisService, private)).return_annotation, (
        f"`{public}` returns a different type than `{private}`"
    )


@pytest.mark.parametrize("private,public", sorted(FACADE.items()))
def test_the_public_entry_point_really_delegates(private: str, public: str) -> None:
    """Proven by REPLACING the private attribute, not by reading the source.

    `object.__new__` avoids a database fixture: the facade only needs an instance to resolve `self.<private>` on, and an
    instance attribute shadows the method, so the recorder sees exactly what the facade forwarded.

    The expected shape is positional-then-keyword, because that is how the facades forward: positional parameters
    positionally, keyword-only parameters by keyword. Asserting the two sequences separately is what makes a DROPPED or
    REORDERED argument fail here rather than in whatever the driver does with it.
    """
    signature = inspect.signature(getattr(AnalysisService, private))
    positional = [
        name for name, parameter in signature.parameters.items()
        if name != "self" and parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    ]
    keyword = [
        name for name, parameter in signature.parameters.items()
        if name != "self" and parameter.kind == parameter.KEYWORD_ONLY
    ]
    # A sentinel for EVERY parameter, optional ones included: the facades forward keyword-only parameters unconditionally
    # (with their defaults when the caller omits them), so passing only the required ones leaves the rest unverified -
    # which is how the first version of this test failed, on a facade that was in fact correct.
    sentinels = {name: f"<{name}>" for name in [*positional, *keyword]}

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def recorder(*args: object, **kwargs: object) -> str:
        calls.append((args, kwargs))
        return "DELEGATED"

    instance = object.__new__(AnalysisService)
    setattr(instance, private, recorder)
    result = getattr(instance, public)(**sentinels)

    assert result == "DELEGATED", f"`{public}` did not return what the implementation returned"
    assert calls, f"`{public}` never reached `{private}`"
    args, kwargs = calls[0]
    assert args == tuple(sentinels[name] for name in positional), (
        f"`{public}` forwarded positional arguments {args}, expected "
        f"{tuple(sentinels[name] for name in positional)}"
    )
    assert kwargs == {name: sentinels[name] for name in keyword}, (
        f"`{public}` forwarded keyword arguments {kwargs}, expected "
        f"{ {name: sentinels[name] for name in keyword} }"
    )


def _private_calls_in_tests() -> list[str]:
    """Every CALL-shaped reference to a driver under `tests/`, as `path:line:name`.

    Assignment targets are deliberately excluded: `tests/test_analysis_task_orchestration.py` replaces
    `_run_post_static_emulation` on a fake runtime so the PRODUCTION caller picks up the fake, and rewriting that
    reference would silently disconnect it.
    """
    found: list[str] = []
    for path in sorted((REPO / "tests").rglob("*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue  # this file mentions the names on purpose, in the mapping above
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in FACADE:
                found.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}:{node.func.attr}")
    return found


def test_no_test_calls_a_phase_driver_by_its_private_name() -> None:
    """The migration's completeness check - this is what keeps plan P3.7 from regressing one call site at a time."""
    offenders = _private_calls_in_tests()
    assert not offenders, (
        "these tests call a phase driver by its PRIVATE name; use the public entry point instead "
        f"({', '.join(sorted(FACADE.values()))}): {offenders}"
    )
