"""The execution seam's contract (P3.3e-move-2a), tested by BEHAVIOUR rather than by reading the code.

WHY THIS FILE EXISTS. The seam's one real question is whether the simulation runner may be built once per WINDOW
instead of once per action, because that is the only difference the step introduces into the giant's
`CONTROLLED_EMULATE` branch. Two hostile reviews of the step asked for a probe instead of an argument from reading
`IsolatedSimulationRunner.__init__`, and this phase's own record says why: an instrument (or a claim) whose scope is
too narrow produces confident wrong answers, and six of those were found in the two preceding steps alone.

WHAT IS PROBED, and what each test would catch:

  * two FRESHLY CONSTRUCTED runners agree on the same window - the property the design's shape change depends on. A
    runner that accumulated state across `run` calls would fail here, and so would a member that built the runner from
    different arguments than the giant used to pass;
  * constructing a runner does not mutate the (frozen) policy it was given;
  * the outcome the member returns has the shape `SimulationWindowOutcome` declares, checked against the real object
    AND against the Protocol's own declarations (a Protocol that has drifted from the implementation is a lie only a
    type checker would otherwise read);
  * `_qiling_unavailable_observation` returns exactly what the module function it wraps returns;
  * the giant reaches `simulation_adapters` ONLY through these two members - the negative test that blocks the old
    path, so a future edit cannot quietly re-import an implementation module into the derivation slice.
"""
from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from threat_report_agent.content_store import LocalContentStore
from threat_report_agent.database import Database
from threat_report_agent.emulation.policy import SimulationExecutionPolicy
from threat_report_agent.service import AnalysisService
from threat_report_agent.simulation_adapters import qiling_unavailable_observation

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "threat_report_agent"
SERVICE_MODULE = SOURCE_ROOT / "service.py"
DERIVATION_MODULE = SOURCE_ROOT / "investigation" / "derivation.py"
GIANT = "_derive_investigation_observations"
SEAM_MEMBERS = ("_run_simulation_window", "_qiling_unavailable_observation")

#: An isolated-worker policy: it defers execution to the emu-worker, so these tests never execute anything in-process
#: and the outcome is deterministic.
ISOLATED_POLICY = SimulationExecutionPolicy(
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
#: A policy that also allows qiling with no pinned rootfs, which is the branch that produces the honest UNSUPPORTED row.
QILING_POLICY = dataclasses.replace(ISOLATED_POLICY, allowed_simulators=("unicorn", "qiling"), qiling_rootfs="")
WINDOW = {
    "simulator": "unicorn",
    "entry_address": 0x401000,
    "input_bytes": b"\x90\xc3",
    "architecture": "x86_64",
}


@pytest.fixture
def facade(test_settings) -> AnalysisService:  # noqa: ANN001 - conftest's Settings fixture
    service = AnalysisService(
        test_settings, Database(test_settings.database_url), LocalContentStore(test_settings.content_store_path)
    )
    service.database.create_schema()
    return service


def _protocol_members() -> set[str]:
    """The Protocol's four member names, read at its NEW home, with the re-export's identity asserted.

    MIGRATED (P3.5-0 M-5), not weakened: this used to parse `derivation.py` for the `ClassDef`. The class moved to
    `emulation/policy.py` and `derivation.py` re-exports it as `X as X`, so the guard reads the DECLARATION where it now
    lives AND asserts that the re-export hands the moved code the identical object - which is the property the original
    "declared here" check protected.
    """
    import threat_report_agent.emulation.policy as policy_module
    import threat_report_agent.investigation.derivation as derivation_module

    assert derivation_module.SimulationWindowOutcome is policy_module.SimulationWindowOutcome, (
        "derivation.py no longer re-exports the same Protocol object, so the moved code and this guard could drift"
    )
    tree = ast.parse((DERIVATION_MODULE.parent.parent / "emulation" / "policy.py").read_text(encoding="utf-8", errors="replace"))
    protocol = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SimulationWindowOutcome"
    )
    return {
        child.target.id for child in protocol.body if isinstance(child, ast.AnnAssign)
    } | {child.name for child in protocol.body if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _giant() -> ast.AST:
    """The giant's IMPLEMENTATION, which moved to `derivation.py` in P3.3e's final step.

    MIGRATED, not deleted: this guard used to read `AnalysisService`'s body because that is where the code lived. The
    step that moved the body moved this target with it - the same migration the coordinator's contract test records
    ("the state it pinned changed by design"), and the negative property it guards is exactly the one that must keep
    holding at the new home.
    """
    tree = ast.parse(DERIVATION_MODULE.read_text(encoding="utf-8", errors="replace"))
    return next(
        n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == GIANT
    )


def test_the_member_forwards_the_callers_policy_and_not_a_default_one(facade: AnalysisService) -> None:
    """THE DISCRIMINATING PROBE, and it exists because the first version of this file was not one.

    MEASURED: `default_simulation_runner(None, ...)` quietly substitutes a default policy, and a first draft that only
    compared two runs against each other passed with the policy replaced by `None` - `.scratch/p33e-seam-test-canfail.py`
    caught that, which is the whole reason that proof is run. The outcome values below are policy-driven, so they pin the
    ARGUMENT, not just self-consistency: the isolated policy defers to the worker, `None` would be disabled by policy,
    and a simulator outside `allowed_simulators` is rejected.
    """
    worker_required = facade.run_simulation_window(ISOLATED_POLICY, WINDOW)
    assert worker_required.status == "WORKER_REQUIRED"
    assert worker_required.stop_reason == "WORKER_REQUIRED"

    denied = facade.run_simulation_window(ISOLATED_POLICY, {**WINDOW, "simulator": "speakeasy"})
    assert denied.status == "REJECTED", "the policy's allowed-simulators list did not reach the runner"
    assert denied.stop_reason == "POLICY_DENIED"


def test_two_freshly_constructed_runners_agree_on_the_same_window(facade: AnalysisService) -> None:
    """The property the seam's shape depends on: the runner carries nothing between constructions."""
    first = facade.run_simulation_window(ISOLATED_POLICY, WINDOW)
    second = facade.run_simulation_window(ISOLATED_POLICY, WINDOW)
    assert first.as_dict() == second.as_dict()
    assert first.status == second.status
    assert first.stop_reason == second.stop_reason
    assert first.output_bytes == second.output_bytes


def test_the_window_contents_reach_the_outcome(facade: AnalysisService) -> None:
    """A member that dropped or reordered the window argument would still return a plausible row; this pins the value."""
    granted = facade.run_simulation_window(ISOLATED_POLICY, {**WINDOW, "simulator": "unicorn"})
    payload = granted.as_dict()
    assert isinstance(payload, dict) and payload, "the outcome must carry the runner's payload"
    assert payload.get("simulator") == "unicorn"


def test_constructing_a_runner_does_not_mutate_the_policy(facade: AnalysisService) -> None:
    before = dataclasses.asdict(ISOLATED_POLICY)
    facade.run_simulation_window(ISOLATED_POLICY, WINDOW)
    assert dataclasses.asdict(ISOLATED_POLICY) == before


def test_the_outcome_matches_the_protocol_the_moved_code_will_use(facade: AnalysisService) -> None:
    outcome = facade.run_simulation_window(ISOLATED_POLICY, WINDOW)
    assert isinstance(outcome.status, str)
    assert outcome.stop_reason is None or isinstance(outcome.stop_reason, str)
    assert isinstance(outcome.output_bytes, bytes)
    assert isinstance(outcome.as_dict(), dict)
    assert _protocol_members() == {"status", "stop_reason", "output_bytes", "as_dict"}, (
        "SimulationWindowOutcome declares something other than the four members the moved code uses"
    )


def test_the_qiling_probe_member_returns_what_the_module_function_returns(facade: AnalysisService) -> None:
    assert facade._qiling_unavailable_observation(QILING_POLICY) == qiling_unavailable_observation(QILING_POLICY)
    assert facade._qiling_unavailable_observation(ISOLATED_POLICY) is None


def test_the_giant_reaches_the_implementation_module_only_through_the_seam() -> None:
    """The negative test that blocks the old path: no direct reference, and both members are called."""
    giant = _giant()
    bare = {
        child.id for child in ast.walk(giant)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }
    assert not bare & {"default_simulation_runner", "qiling_unavailable_observation"}, (
        "the giant reaches simulation_adapters directly again; the seam's whole purpose is that it does not"
    )
    runner_calls = [
        child for child in ast.walk(giant)
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
        and child.func.attr == "run" and isinstance(child.func.value, ast.Name) and child.func.value.id == "runner"
    ]
    assert not runner_calls, "the giant still runs a runner object it built itself"
    # STRICT AGAIN, after a review caught this guard being WIDENED by the move: the first migration accepted `self` as
    # well as `host` ("the receiver is host now that the body lives in derivation.py"), which is strictly weaker - it
    # would no longer notice a `self.X` reintroduced into a module function, where `self` is not defined at all. The
    # moved body must reach its host ONLY as `host`, and must hold no `self`/`cls` reference whatever.
    host_attrs = {
        child.attr for child in ast.walk(giant)
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "host"
    }
    leftover = {
        (child.value.id, child.attr) for child in ast.walk(giant)
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id in {"self", "cls"}
    }
    assert not leftover, f"the moved body still uses a receiver that does not exist there: {sorted(leftover)}"
    assert set(SEAM_MEMBERS) <= host_attrs, f"the giant does not call {sorted(set(SEAM_MEMBERS) - host_attrs)}"
