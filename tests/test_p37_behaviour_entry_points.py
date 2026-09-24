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


#: The same contract for CLASS/STATIC private members: the facade is a classmethod/staticmethod, so the
#: delegation proof patches the CLASS rather than an instance (a class-level lookup ignores instances).
CLASS_FACADE = {
    "_recovered_config_consumer_links": "recovered_config_consumer_links",
    "_selector_is_anchored_in_evidence": "selector_is_anchored_in_evidence",
    "_semantic_action_result": "semantic_action_result",
    "_specialized_verifier_context": "specialized_verifier_context",
    "_static_decode_recovery_from_evidence": "static_decode_recovery_from_evidence",
    "_t6_revision_diff_payload": "t6_revision_diff_payload",
    "_wait_continuation": "wait_continuation",
    "_stage_persist_how_claims": "stage_persist_how_claims",
    "_instruction_indices_referencing_addresses": "instruction_indices_referencing_addresses",
    "_is_http_transport_seed_row": "is_http_transport_seed_row",
    "_persist_ready_emulation_actions": "persist_ready_emulation_actions",
    "_pin_config_consumer_seed_rows": "pin_config_consumer_seed_rows",
    "_select_config_consumer_seed_rows": "select_config_consumer_seed_rows",
    "_action_is_model_or_human": "action_is_model_or_human",
    "_canonical_json_chunks": "canonical_json_chunks",
    "_canonical_sha256": "canonical_sha256",
    "_matching_simulation_results": "matching_simulation_results",
    "_recovered_http_how_fields": "recovered_http_how_fields",
    "_baseline_specialist_tools": "baseline_specialist_tools",
    "_canonical_json": "canonical_json",
    "_persist_time_seed_result": "persist_time_seed_result",
    "_select_report_evidence_rows": "select_report_evidence_rows",
    "_persist_how_claim_specs": "persist_how_claim_specs",
    "_select_ghidra_function_rows": "select_ghidra_function_rows",
    "_simulation_covers_request": "simulation_covers_request",
    "_stamp_persist_how_snapshot": "stamp_persist_how_snapshot",
    "_failed_tool_run_limitations": "failed_tool_run_limitations",
    "_gate_for_seed_playbook": "gate_for_seed_playbook",
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


def _looks_like_the_service(receiver: ast.AST) -> bool:
    """Whether a call's receiver plausibly IS the service, so the completeness rule is about the right object.

    WHY RECEIVER-AWARE, and this is a MEASURED correction rather than a refinement: a blanket rewrite of `._name(` in this
    batch also changed `revision_writer._select_report_evidence_rows(...)` - a module-level function in the P3.6-1 slice
    module with the same name - and broke a passing test. The rule's intent is "a test must not reach the SERVICE's
    privates", so a receiver that is another module is out of scope.

    LIMITATION, stated rather than hidden: this is a name heuristic, not resolution. A test that bound the service to an
    unrelated local name and called a private through it would slip past - the alternative is real import resolution, which
    belongs in the gate rather than in a contract test.
    """
    if isinstance(receiver, ast.Name):
        name = receiver.id.lower()
        return name == "analysisservice" or "service" in name or name in {"svc", "analysis", "subject"}
    if isinstance(receiver, ast.Attribute):
        return receiver.attr == "AnalysisService" or "service" in receiver.attr.lower()
    return False


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
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {**FACADE, **CLASS_FACADE}
                    and _looks_like_the_service(node.func.value)):
                found.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}:{node.func.attr}")
    return found


def test_no_test_calls_a_phase_driver_by_its_private_name() -> None:
    """The migration's completeness check - this is what keeps plan P3.7 from regressing one call site at a time."""
    offenders = _private_calls_in_tests()
    assert not offenders, (
        "these tests call a phase driver by its PRIVATE name; use the public entry point instead "
        f"({', '.join(sorted(FACADE.values()))}): {offenders}"
    )


@pytest.mark.parametrize("private,public", sorted(CLASS_FACADE.items()))
def test_each_class_level_member_has_a_public_entry_point_with_the_same_signature(private: str, public: str) -> None:
    """Same parity rule as the instance facades, applied to the class/static group.

    The declaration is compared including the FIRST parameter (`cls` for a classmethod), because a facade that drops it is
    a staticmethod pretending to be a classmethod - the kind is part of the interface here.
    """
    assert hasattr(AnalysisService, private), f"{private} is gone, so the facade wraps nothing"
    assert hasattr(AnalysisService, public), (
        f"AnalysisService has no public `{public}`; plan P3.7 requires the test surface to call a behaviour entry point "
        f"rather than `{private}`"
    )
    assert _signature(getattr(AnalysisService, public)) == _signature(getattr(AnalysisService, private)), (
        f"`{public}` and `{private}` do not have the same parameters (names, kinds and defaults all count)"
    )
    assert inspect.signature(getattr(AnalysisService, public)).return_annotation == \
        inspect.signature(getattr(AnalysisService, private)).return_annotation, (
        f"`{public}` returns a different type than `{private}`"
    )


@pytest.mark.parametrize("private,public", sorted(CLASS_FACADE.items()))
def test_the_class_level_entry_point_really_delegates(private: str, public: str,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """The delegation proof for a CLASS-level member: patch the CLASS, call through the CLASS.

    MEASURED why this cannot reuse the instance test: a class-level attribute is found on the class, so setting it on an
    instance changes nothing - the recorder would never see a call and the test would fail on a correct facade (or worse,
    pass vacuously if the assertion were written loosely). Patching the class with a plain function means both the
    classmethod and staticmethod facades reach it with exactly the arguments they forward.
    """
    signature = inspect.signature(getattr(AnalysisService, private))
    positional = [
        name for name, parameter in signature.parameters.items()
        if name not in {"self", "cls"} and parameter.kind in (parameter.POSITIONAL_ONLY,
                                                              parameter.POSITIONAL_OR_KEYWORD)
    ]
    keyword = [
        name for name, parameter in signature.parameters.items()
        if name not in {"self", "cls"} and parameter.kind == parameter.KEYWORD_ONLY
    ]
    sentinels = {name: f"<{name}>" for name in [*positional, *keyword]}

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def recorder(*args: object, **kwargs: object) -> str:
        calls.append((args, kwargs))
        return "DELEGATED"

    monkeypatch.setattr(AnalysisService, private, recorder)
    result = getattr(AnalysisService, public)(**sentinels)

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
