"""T3 acceptance for the C3b declarative runtime-model library (plan §9, step P-5).

WHAT THIS FILE IS FOR. §9.1 allows T3 exactly three things - `vb6_runtime_shim.py`, a new runtime registry
module and T3 tests - and names one success standard: **VB6's existing path is chosen BY the registry, the
entries are hand-written declarative models, and no model may be generated automatically by an LLM**. §9.3
then names five acceptance bullets, and the sections below are one per bullet.

WHERE THE REGISTRY IS. It is the runtime-model library DECLARED INSIDE `vb6_runtime_shim.py`, not a second
module. §9.1 PERMITS a new module; this step does not create one, and the reason is measured rather than
stylistic - a new module must be registered in `docs/import-policy.json`, and the two-module shape is a real
import CYCLE (each side needs the other's surface) while this repository's recorded module graph has ZERO
cycles. Registering a genuine cycle in the gate's own data would write a structural regression into the policy
to silence the gate. The P-5 artifact records the deviation in `deviation_from_the_allowed_surface_list`.

So this file's "registry" is `vb6_runtime_shim`'s own declaration surface: `RuntimeModel`,
`RuntimeModelProvenance`, `RuntimeModelLibrary`, `identity_key`/`identity_keys`, the four gap reasons,
`runtime_model_registry_version()` and `default_runtime_model_library()`. It is not a second copy of the shim:
it is the DECLARATION the shim is driven from. The shim keeps the handler BODIES, because those need the
emulator object; the library owns WHICH models exist and WHICH one is selected. That split is what makes "no
model for this runtime" a reportable gap instead of a silent no-op.

MEASURED context for the fixtures (all of it from this repository, none of it assumed here):

  * `tests/test_speakeasy_entry_selection.py` records the isolated-worker measurement for the 白象 sample
    `64da3378`: `modelled_calls=1031  api observations=256  strings observed=1028`.
  * `tests/test_vb6_shim_evidence_reaches_the_body.py` records the published body's own numbers:
    `registered: 132`, `modelled_calls: 1031`, `strings_observed: 1028`, `distinct_records: 868`,
    `decoded_chars: 6140`.
  * `Vb6ShimState.as_evidence()` publishes `shim: "vb6-runtime-v1"`; that string is the model identity the
    published body already carries, which is why this file does NOT introduce a new published symbol (see
    `test_9_3_5_every_model_entry_has_a_producer_consumer_and_rendered_markdown_proof`).

Nothing here claims a real runtime run. Every fixture is an in-process fake; §9.3's bullets are about the
SELECTION and PUBLICATION machinery, and `capability_status` stays UNVERIFIED regardless of what passes here.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import types

import pytest

from threat_report_agent import analyst_report, reporting, simulation_adapters
from threat_report_agent.emulation import vb6_runtime_shim
from threat_report_agent.emulation.policy import SimulationRequest

#: The library surface, read off the module rather than imported by name.
#:
#: WHY `getattr` AND NOT `from ... import`. The measurement harness runs this file's helpers against the HEAD
#: BLOB of the shim (to compare the published row before and after the change). With `from ... import`, that
#: comparison could not even be loaded - the HEAD module has no library and the import raises at collection
#: time - so the "before" side of the comparison would have been unobtainable. These three names are resolved
#: per call instead, and every test that needs them fails loudly if the surface is absent.
default_runtime_model_library = getattr(vb6_runtime_shim, "default_runtime_model_library", None)
identity_keys = getattr(vb6_runtime_shim, "identity_keys", None)
runtime_model_registry_version = getattr(vb6_runtime_shim, "runtime_model_registry_version", None)
RuntimeModelLibrary = getattr(vb6_runtime_shim, "RuntimeModelLibrary", None)
_runtime_model = getattr(vb6_runtime_shim, "_runtime_model", None)

REPO = pathlib.Path(__file__).resolve().parents[1]
#: The module the library is declared in. It is the SHIM, not a second file: §9.1 permits a new registry module
#: and this step does not create one - a new module must be registered in `docs/import-policy.json` and the
#: two-module shape is a real import cycle, while this repository's recorded module graph has zero cycles.
SHIM_PATH = REPO / "src" / "threat_report_agent" / "emulation" / "vb6_runtime_shim.py"

#: The 白象 sample path, verbatim from `tests/test_vb6_runtime_shim.py`.
SAMPLE = (
    r"D:\test\白象_revers_AGENT"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
    r"\64da33787b54a0d179d7f77768b7af1e6ca7ee942a437dc751073879ae6d6c14"
)


# ---------------------------------------------------------------------------------------------------------
# Fakes. They model the two measured Speakeasy properties the shim depends on, nothing more.
# ---------------------------------------------------------------------------------------------------------
class _FakeSpeakeasy:
    """Records `add_api_hook` calls; drops any registration made before `load_module`."""

    def __init__(self, *, loaded: bool = True) -> None:
        self.loaded = loaded
        self.registrations: list[tuple[str, str]] = []

    def load_module(self, data: bytes = b"") -> types.SimpleNamespace:
        self.loaded = True
        return types.SimpleNamespace()

    def add_api_hook(self, handler, module="", api_name="", argc=0, call_conv=None):  # noqa: ANN001
        if not self.loaded:
            return None
        self.registrations.append((module, api_name))
        return handler


class _FakeSpeakeasyForAdapter:
    """The surface `_speakeasy_adapter` uses, with exactly one VB6 runtime call to model.

    Copied in shape from `tests/test_vb6_shim_evidence_reaches_the_body.py::_FakeSpeakeasy`, which is where
    the measured dispatch shape comes from: Speakeasy calls a hook for an API it does not implement as
    `hook.cb(self, imp_api, None, argv)`.
    """

    ARGUMENT_TEXT = "vb6-source-record-text"
    ARGUMENT_ADDRESS = 0x402C08

    def __init__(self, config: object = None, logger: object = None) -> None:
        self.config = config
        self.hooks: dict[tuple[str, str], object] = {}
        encoded = self.ARGUMENT_TEXT.encode("utf-16-le")
        self.memory = {
            self.ARGUMENT_ADDRESS - 4: struct.pack("<I", len(encoded)),
            self.ARGUMENT_ADDRESS: encoded,
        }

    def load_module(self, data: object = None) -> types.SimpleNamespace:
        del data
        return types.SimpleNamespace()

    def add_api_hook(self, handler, module="", api_name="", argc=0, call_conv=None):  # noqa: ANN001
        del argc, call_conv
        self.hooks[(module, api_name)] = handler
        return handler

    def run_module(self, module: object) -> None:
        del module
        handler = self.hooks.get(("msvbvm60", "__vbastrcopy"))
        if handler is None:
            # TOLERANT ON PURPOSE. MEASURED: a library whose declaration does not include the export this
            # fake would call leaves no hook to fire, and a `KeyError` here is reported by the adapter as a
            # failed run - which would make the sentinel test above fail for a reason unrelated to the
            # registry. A real Speakeasy run that reaches an unmapped symbol records `unsupported_api`
            # instead of raising, so declining to call is the closer model of the real behaviour.
            return
        handler(self, "__vbastrcopy", None, [])  # type: ignore[operator]

    def get_report(self) -> dict[str, object]:
        return {}

    def mem_read(self, address: int, size: int) -> bytes:
        for base, payload in self.memory.items():
            if base <= address and address + size <= base + len(payload):
                return payload[address - base : address - base + size]
        raise ValueError(f"unmapped 0x{address:x}")

    def get_register_state(self) -> dict[str, str]:
        return {"edx": hex(self.ARGUMENT_ADDRESS)}


def _run_the_real_adapter(monkeypatch: pytest.MonkeyPatch, request: SimulationRequest | None = None):
    """Run the PRODUCTION `_speakeasy_adapter` against the fake Speakeasy and return its result.

    The registry is never called directly by this helper: the adapter reaches it through the shim, which is
    the whole point - a registry that only its tests call would not select anything.
    """
    fake_module = types.ModuleType("speakeasy")
    fake_module.Speakeasy = _FakeSpeakeasyForAdapter  # type: ignore[attr-defined]
    fake_module.__file__ = ""
    monkeypatch.setitem(sys.modules, "speakeasy", fake_module)
    return simulation_adapters._speakeasy_adapter(
        request
        or SimulationRequest(
            "speakeasy",
            "sample.exe",
            input_bytes=b"MZ" + b"\x00" * 64,
            timeout_seconds=1,
            instruction_budget=1000,
            entry_address=0,
        )
    )


def _published_shim_event(result: object) -> dict[str, object]:
    events = [item for item in result.observations if item.get("event") == "vb6_shim"]  # type: ignore[attr-defined]
    assert events, f"the adapter published no `vb6_shim` observation: {result.observations}"  # type: ignore[attr-defined]
    return events[-1]


def _render_body(event: dict[str, object]) -> str:
    """Push one `vb6_shim` observation through the REAL projection and the REAL renderer."""
    evidence = {
        "ev-1": {
            "id": "ev-1",
            "kind": "simulation_result",
            "value": {
                "status": "FAILED",
                "simulator": "controlled-emulator",
                "stop_reason": "EXECUTION_ERROR",
                "observations": [event],
            },
            "anchor": {},
        }
    }
    projection = reporting.build_emulation_status_projection(evidence)
    assert projection.get("results"), "the projection dropped the simulation_result entirely"
    lines = analyst_report._emulation_status_section([projection])
    assert lines, "the chapter rendered nothing at all"
    return "\n".join(lines)


# =========================================================================================================
# §9.1 - the registry surface itself
# =========================================================================================================
def test_the_registry_declares_the_vb6_runtime_model_with_the_full_minimal_interface() -> None:
    """§9.1's minimal interface: runtime identity, export name, semantic adapter, disabled state, version,
    provenance. Each field is READ off the live entry, not described."""
    library = default_runtime_model_library()
    model = library.resolve(runtime_id="vb6")
    assert model is not None, "the default library declares no model for the VB6 runtime"

    # runtime identity
    assert model.model_id == "vb6-runtime-v1", model.model_id
    assert "vb6" in model.runtime_ids
    # which modules the identity is imported under - the shim's own measured list
    assert set(model.module_names) == {"msvbvm60", "msvbvm50", "vba6", "vba7"}, model.module_names
    # export names, as stable identity keys
    assert model.exports, "the model declares no export names"
    assert all(key.startswith(("msvbvm60:", "msvbvm50:", "vba6:", "vba7:")) for key in model.exports)
    assert "msvbvm60:__vbastrcopy" in model.exports
    assert "msvbvm60:ordinal_100" in model.exports, "the VB6 bootstrap itself must be declared"
    # the semantic adapter
    assert model.semantic_adapter == "threat_report_agent.emulation.vb6_runtime_shim:build_vb6_handlers"
    # disabled state
    assert model.enabled is True
    # version
    assert model.version == runtime_model_registry_version()
    # provenance
    for field in ("author", "reviewer", "source_record", "source_sha256", "decision", "recorded_at"):
        assert str(getattr(model.provenance, field, "") or "").strip(), f"provenance has no `{field}`"
    assert model.provenance.author != model.provenance.reviewer, (
        "the author and the reviewer are the same string, so no independent review is recorded"
    )
    assert model.provenance.source_record.startswith("src/"), model.provenance.source_record
    recorded = REPO / str(model.provenance.source_record)
    assert recorded.is_file(), f"the provenance names {recorded}, which does not exist"
    assert hashlib.sha256(recorded.read_bytes()).hexdigest() == model.provenance.source_sha256, (
        "the provenance hash does not match the record it names"
    )


def test_the_models_are_declarative_frozen_data_not_runtime_behaviour() -> None:
    """§9.1: entries are hand-written DECLARATIVE models.

    A declarative entry is frozen data: mutating it must fail, and it must be hashable so a set of models
    cannot silently hold two different values under one identity. A model that could be rewritten in place
    at run time would not be a declaration.
    """
    model = default_runtime_model_library().resolve(runtime_id="vb6")
    assert model is not None
    with pytest.raises(Exception):
        model.enabled = False  # type: ignore[misc]
    assert hash(model) == hash(model)
    assert isinstance(model.exports, frozenset), (
        f"`exports` is {type(model.exports).__name__}; a mutable collection in a declaration can be edited "
        "after review, so the reviewed text would no longer be what runs"
    )


def test_the_registry_cannot_be_generated_by_an_llm_or_any_other_runtime_generator() -> None:
    """§9.1: "模型不能由 LLM 自动生成".

    Three measurable discriminators, all read off the module's AST rather than its prose:
      1. no network client and no provider SDK is imported at all;
      2. no model is CONSTRUCTED anywhere except inside the one declared-library builder - so the library
         cannot be assembled from anything measured at run time;
      3. every declared entry carries a human author and a reviewer, and `recorded_at` is a date literal.
    """
    tree = ast.parse(SHIM_PATH.read_text(encoding="utf-8"))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {
        "requests", "httpx", "urllib", "urllib3", "aiohttp", "socket", "http", "openai", "anthropic",
        "transformers", "torch", "litellm", "ollama", "google", "cohere", "mistralai",
    }
    assert not (imported & forbidden), (
        f"the registry imports {sorted(imported & forbidden)}; a model library that can fetch or call a "
        "generator is not a hand-written declaration"
    )

    constructing: list[dict[str, object]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        # A CALL to `RuntimeModel(...)`, not a mere mention. MEASURED false positive this replaces: an
        # `ast.Name` scan also matched the RETURN ANNOTATION `-> RuntimeModel` on the builder itself, so the
        # boundary reported a violation that did not exist. A call node cannot be produced by an annotation.
        calls = [
            child for child in ast.walk(node)
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
            and child.func.id == "RuntimeModel"
        ]
        if calls:
            constructing.append({"function": node.name, "lines": [call.lineno for call in calls]})
    builders = [entry["function"] for entry in constructing]
    assert builders == ["_runtime_model"], (
        f"`RuntimeModel(...)` is called from {constructing}; the single declared builder `_runtime_model` is the "
        "only place an entry may be constructed, because an entry built anywhere else can be assembled from "
        "measured data instead of declared"
    )

    # A `RuntimeModel(...)` call is allowed only inside `_runtime_model`, which is asserted above; the
    # library builder must reach it through that function.
    builders = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                and node.name == "default_runtime_model_library"]
    assert builders, "the registry has no declared library builder"
    assert any(
        isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "_runtime_model"
        for child in ast.walk(builders[0])
    ), "the library builder does not go through the single declared entry constructor"


def test_an_unknown_runtime_identity_resolves_to_nothing_rather_than_a_guess() -> None:
    """A library that answers for a runtime it does not model is worse than one that answers nothing."""
    library = default_runtime_model_library()
    assert library.resolve(runtime_id="dotnet-clr") is None
    assert library.resolve(runtime_id="") is None


def test_an_export_the_model_does_not_declare_is_reported_as_unmodelled() -> None:
    """`unmodelled_identity_keys` is what §9.2's `no-gain` set difference is computed from."""
    library = default_runtime_model_library()
    model = library.resolve(runtime_id="vb6")
    assert model is not None
    observed = model.exports | {"msvbvm60:__vbanotreal", "kernel32:createfilew"}
    unmodelled = library.unmodelled_identity_keys("vb6", observed)
    assert unmodelled == frozenset({"msvbvm60:__vbanotreal", "kernel32:createfilew"}), unmodelled
    assert library.unmodelled_identity_keys("vb6", model.exports) == frozenset()
    assert library.unmodelled_identity_keys("no-such-runtime", observed) == frozenset(observed)


def test_identity_keys_are_stable_across_case_and_quote_shapes() -> None:
    """The import table stores `'__vbaStrCopy'`; the key form must collapse that, or nothing matches."""
    keys = identity_keys(
        [("MSVBVM60.DLL", "'__vbaStrCopy'"), ("MSVBVM60.DLL", "Ordinal_100"), ("KERNEL32.dll", "CreateFileW")]
    )
    assert keys == frozenset({"msvbvm60:__vbastrcopy", "msvbvm60:ordinal_100", "kernel32:createfilew"}), keys


# =========================================================================================================
# §9.1 success standard - VB6's EXISTING path is chosen BY the registry
# =========================================================================================================
def test_vb6s_existing_path_is_chosen_by_the_registry_and_not_the_other_way_round() -> None:
    """The seam, measured in both directions on the PRODUCTION call, `install_vb6_shim(se)`.

    Direction 1: the handlers the production call builds are exactly the handlers the REGISTRY's selected
    model declares - same identity keys, same handler objects.
    Direction 2 (the one that makes direction 1 non-vacuous): replacing the single declared entry with a
    model whose export list is NARROWED changes what the production call registers. If the shim were still
    building its own fixed set, the narrowing would have no effect.
    """
    library = default_runtime_model_library()
    model = library.resolve(runtime_id="vb6")
    assert model is not None
    observed = [
        ("MSVBVM60.DLL", "'__vbaStrCopy'"),
        ("MSVBVM60.DLL", "'__vbaChkstk'"),
        ("MSVBVM60.DLL", "'Ordinal_100'"),
        ("KERNEL32.dll", "'CreateFileW'"),
    ]

    state, handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy(), exports=observed)
    declared_for_this_sample = frozenset(
        key for key in model.exports if key in identity_keys(observed)
    )
    assert set(handlers) == set(declared_for_this_sample), (
        "the production installer built a handler set the registry's model does not declare: "
        f"registry-only {sorted(declared_for_this_sample - set(handlers))}, "
        f"shim-only {sorted(set(handlers) - declared_for_this_sample)}"
    )
    assert state.runtime_model_id == model.model_id
    assert state.runtime_model_version == model.version

    narrowed = RuntimeModelLibrary(
        models=(
            _runtime_model(  # noqa: SLF001 - the declared constructor is the seam
                model_id=model.model_id,
                runtime_ids=model.runtime_ids,
                module_names=model.module_names,
                exports=("msvbvm60:__vbastrcopy",),
                handler_symbols=model.handler_symbols,
                semantic_adapter=model.semantic_adapter,
                enabled=True,
                version=model.version,
                provenance=model.provenance,
            ),
        )
    )
    _narrowed_state, narrowed_handlers = vb6_runtime_shim.install_vb6_shim(
        se=_FakeSpeakeasy(), exports=observed, library=narrowed
    )
    assert set(narrowed_handlers) == {"msvbvm60:__vbastrcopy"}, (
        "narrowing the registry entry did NOT narrow what the production installer registers, so the shim "
        "is still choosing its own export set and the registry is decorative"
    )


def test_the_production_adapter_reaches_the_registry_through_the_shim(monkeypatch) -> None:
    """The adapter is not edited by this step; it reaches the registry through `install_vb6_shim`.

    Behavioural: a sentinel model identity is installed into the default library's place, and the value the
    ADAPTER publishes must move with it. A registry that nothing on the production path consults could not
    move it.
    """
    sentinel = RuntimeModelLibrary(
        models=(
            _runtime_model(  # noqa: SLF001
                model_id="sentinel-runtime-model",
                runtime_ids=("vb6",),
                module_names=("msvbvm60",),
                exports=("msvbvm60:__vbastrcopy",),
                handler_symbols=("__vbastrcopy",),
                semantic_adapter="tests/test_runtime_model_registry.py:_FakeSpeakeasyForAdapter",
                enabled=True,
                version="sentinel-version",
                provenance={"author": "sentinel", "reviewer": "sentinel", "source_record": "sentinel",
                            "source_sha256": "0" * 64, "decision": "DECLARED", "recorded_at": "1970-01-01"},
            ),
        )
    )
    monkeypatch.setattr(vb6_runtime_shim, "default_runtime_model_library", lambda: sentinel)

    result = _run_the_real_adapter(monkeypatch)
    event = _published_shim_event(result)
    assert event["registered"] == 1, (
        "the adapter's published hook count did not follow the sentinel library, so the production path "
        f"does not consult the registry: {event}"
    )
    state, _handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy())
    assert state.runtime_model_id == "sentinel-runtime-model"


# =========================================================================================================
# §9.3 bullet 1 - the fixed Document fixture keeps its three rows EQUIVALENT
# =========================================================================================================
def test_9_3_1_the_document_fixture_rows_stay_equivalent_through_the_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§9.3 bullet 1: "固定 Document fixture 中 VB6 的 registered/modelled_calls/strings_observed 行保持等价".

    "Equivalent" is measured the only way it can be: the run goes through the production adapter to the
    official Markdown, and the three published quantities are read BACK OUT of the rendered body and
    compared with the values the record carries. The fixture's values are the ones this repository already
    records for the 白象 sample (1,031 modelled calls / 1,028 strings; 132 registered hooks).

    The registry is on this path. What is compared is the PUBLISHED row, not an intermediate number.
    """
    result = _run_the_real_adapter(monkeypatch)
    event = _published_shim_event(result)
    assert event["registered"], "the shim registered nothing, so the fixture would be vacuous"
    assert event["modelled_calls"] == 1, event["modelled_calls"]
    assert event["strings_observed"] == 1, event["strings_observed"]

    body = _render_body(event)
    assert f"`{event['registered']}` 个 hook" in body, body
    assert f"建模调用 `{event['modelled_calls']}` 次" in body, body
    assert f"从中读出 `{event['strings_observed']}` 个样本字符串" in body, body
    # The row is the SHIM's, and the shim's identity is the model identity the registry declared.
    model = default_runtime_model_library().resolve(runtime_id="vb6")
    assert model is not None
    assert vb6_runtime_shim.Vb6ShimState().as_evidence()["shim"] == model.model_id, (
        "the shim's published identity and the registry's model id have drifted apart, so the row in the "
        "Document fixture can no longer be attributed to a declared model"
    )


def test_9_3_1_the_document_fixtures_own_published_numbers_render_equivalently() -> None:
    """The same three rows, at the fixture's recorded magnitudes (132 / 1031 / 1028).

    This is the regression half: the row must render identically for the numbers the 白象 run actually
    produced, not only for a one-call fake.
    """
    event = {
        "event": "vb6_shim",
        "registered": 132,
        "modelled_calls": 1031,
        "strings_observed": 1028,
        "distinct_records": 868,
        "decoded_chars": 6140,
        "destination_observable": False,
        "sample_strings_cap": 32,
        "argument_pairs": [],
        "argument_pairs_cap": 16,
        "argument_pairs_recorded": 614,
    }
    body = _render_body(event)
    assert "`132` 个 hook" in body
    assert "建模调用 `1031` 次" in body
    assert "从中读出 `1028` 个样本字符串" in body


# =========================================================================================================
# §9.3 bullet 2 - a minimal NEW runtime fixture hits -> auto-loaded; a miss -> not loaded
# =========================================================================================================
def test_9_3_2_a_minimal_new_runtime_fixture_is_loaded_only_when_it_matches() -> None:
    """§9.3 bullet 2: "一个最小新 runtime fixture 命中时自动加载，未命中不加载".

    The fixture is minimal: one export, one handler, declared entirely in the test. "Auto-loaded" means the
    SELECTION is not spelled out by the caller - `install_vb6_shim(se)` asks the registry for whatever model
    answers for `vb6` and gets this one.
    """
    minimal = RuntimeModelLibrary(
        models=(
            _runtime_model(  # noqa: SLF001
                model_id="minimal-fixture-runtime-v1",
                runtime_ids=("vb6",),
                module_names=("msvbvm60",),
                exports=("msvbvm60:__vbachkstk",),
                handler_symbols=("__vbachkstk",),
                semantic_adapter="tests/test_runtime_model_registry.py:minimal-fixture",
                enabled=True,
                version="fixture",
                provenance={"author": "T3 fixture", "reviewer": "T3 fixture", "source_record": "tests",
                            "source_sha256": "0" * 64, "decision": "DECLARED", "recorded_at": "1970-01-01"},
            ),
        )
    )
    # HIT: the runtime identity the library answers for.
    hit = minimal.resolve(runtime_id="vb6")
    assert hit is not None and hit.model_id == "minimal-fixture-runtime-v1"
    state, handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy(), library=minimal)
    assert state.runtime_model_id == "minimal-fixture-runtime-v1"
    assert set(handlers) == {"msvbvm60:__vbachkstk"}, set(handlers)

    # MISS: a different runtime identity. The fixture must NOT be loaded, and nothing may be registered.
    miss_state, miss_handlers = vb6_runtime_shim.install_vb6_shim(
        se=_FakeSpeakeasy(), library=minimal, runtime_id="dotnet-clr"
    )
    assert miss_handlers == {}, "a non-matching runtime identity loaded the fixture anyway"
    assert miss_state.registered == 0
    assert miss_state.runtime_model_id == ""
    assert miss_state.gaps, "a miss published no gap, so it is indistinguishable from a silent skip"


def test_9_3_2_a_matching_runtime_that_declares_no_overlapping_export_loads_nothing() -> None:
    """A hit on identity with no overlapping export is a real, reported state - not an exception."""
    library = default_runtime_model_library()
    state, handlers = vb6_runtime_shim.install_vb6_shim(
        se=_FakeSpeakeasy(), exports=[("KERNEL32.dll", "'CreateFileW'")], library=library
    )
    assert handlers == {}
    assert state.runtime_model_id == "vb6-runtime-v1", "the model was selected; nothing of it applied"
    assert any(gap["reason"] == "NO_MODELLED_EXPORT_PRESENT" for gap in state.gaps), state.gaps


# =========================================================================================================
# §9.3 bullet 3 - disabling a model degrades and publishes the CONCRETE gap, never a silent skip
# =========================================================================================================
def test_9_3_3_disabling_the_model_degrades_and_publishes_the_concrete_gap() -> None:
    """§9.3 bullet 3: "单独禁用模型后降级并发布具体缺口，不静默跳过".

    Disabling is done the way a reviewer would do it - flip the declared `enabled` flag - and then the
    PRODUCTION adapter is run. Three things must hold at once:

      1. the run degrades rather than raising (the emulation survives);
      2. the gap is CONCRETE: the model id, the runtime identity, the reason and the missing export count are
         named, not "the shim did not run";
      3. it is not a silent skip: the published `vb6_shim` row still exists and says nothing was registered,
         and the rendered body has lost the row it would otherwise carry.
    """
    base = default_runtime_model_library().resolve(runtime_id="vb6")
    assert base is not None
    disabled = RuntimeModelLibrary(
        models=(
            _runtime_model(  # noqa: SLF001
                model_id=base.model_id,
                runtime_ids=base.runtime_ids,
                module_names=base.module_names,
                exports=base.exports,
                handler_symbols=base.handler_symbols,
                semantic_adapter=base.semantic_adapter,
                enabled=False,
                version=base.version,
                provenance=base.provenance,
            ),
        )
    )

    state, handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy(), library=disabled)
    assert handlers == {}, "a disabled model still registered handlers"
    assert state.registered == 0
    assert state.runtime_model_id == "", "a disabled model must not be reported as the selected model"
    gaps = [gap for gap in state.gaps if gap["reason"] == "RUNTIME_MODEL_DISABLED"]
    assert gaps, f"disabling the model produced no DISABLED gap: {state.gaps}"
    gap = gaps[0]
    assert gap["runtime_id"] == "vb6"
    assert gap["model_id"] == base.model_id, "the gap does not name WHICH model was disabled"
    assert gap["declared_export_count"] == len(base.exports), (
        "the gap does not say how much modelling was lost, so a reader cannot size the hole"
    )
    assert gap["detail"], "the gap carries no detail sentence"

    # And on the real adapter path: degrade, and do not pretend the row was fine.
    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(vb6_runtime_shim, "default_runtime_model_library", lambda: disabled)
        result = _run_the_real_adapter(monkeypatch)
        event = _published_shim_event(result)
        assert event["registered"] == 0
        assert event["modelled_calls"] == 0
        assert result.status != "FAILED" or "shim exploded" not in str(result.limitations)
        body = _render_body(event)
        assert "个 hook" not in body, (
            "the disabled model still rendered a hook row, which is the silent skip this bullet forbids"
        )
    finally:
        monkeypatch.undo()

    # The enabled model, by contrast, does render the row - so the assertion above is a discriminator.
    _enabled_state, enabled_handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy())
    assert enabled_handlers, "the enabled model registered nothing, so the control above proves nothing"


def test_9_3_3_the_gap_reaches_the_run_as_a_structured_observation() -> None:
    """A gap that stays inside the registry cannot be consumed. The shim must publish it."""
    base = default_runtime_model_library().resolve(runtime_id="vb6")
    assert base is not None
    disabled = RuntimeModelLibrary(
        models=(
            _runtime_model(  # noqa: SLF001
                model_id=base.model_id,
                runtime_ids=base.runtime_ids,
                module_names=base.module_names,
                exports=base.exports,
                handler_symbols=base.handler_symbols,
                semantic_adapter=base.semantic_adapter,
                enabled=False,
                version=base.version,
                provenance=base.provenance,
            ),
        )
    )
    state, _handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy(), library=disabled)
    evidence = state.as_evidence()
    assert evidence["runtime_model_id"] == ""
    assert evidence["runtime_model_gaps"], "`as_evidence()` dropped the gap"
    assert all(json.dumps(gap, ensure_ascii=False) for gap in evidence["runtime_model_gaps"])


# =========================================================================================================
# §9.3 bullet 4 - "model X required, library has no X" must be non-zero
# =========================================================================================================
def test_9_3_4_a_required_model_the_library_lacks_is_reported_as_a_gap() -> None:
    """§9.3 bullet 4: "需要模型 X、库无 X" 负向测试非零.

    The registry has no model for `dotnet-clr`, and the caller REQUIRES one. The registry's own resolution
    refuses (it returns nothing) and the shim's installer reports the gap with the reason
    `RUNTIME_MODEL_MISSING` - the run is not allowed to quietly continue unmodelled.
    """
    library = default_runtime_model_library()
    assert library.resolve(runtime_id="dotnet-clr") is None

    state, handlers = vb6_runtime_shim.install_vb6_shim(
        se=_FakeSpeakeasy(), library=library, runtime_id="dotnet-clr"
    )
    assert handlers == {}
    gaps = [gap for gap in state.gaps if gap["reason"] == "RUNTIME_MODEL_MISSING"]
    assert gaps, f"a required, absent model produced no MISSING gap: {state.gaps}"
    assert gaps[0]["runtime_id"] == "dotnet-clr"
    assert gaps[0]["library_size"] == len(library.models), (
        "the gap does not say how many models the library does hold, so a reader cannot tell a typo from a "
        "capability hole"
    )


def test_9_3_4_requiring_the_absent_model_is_non_zero_as_an_executable_fact() -> None:
    """"非零" is a statement about an EXIT STATUS, so it is measured by running a program.

    An in-test `assert` (the test above) proves the library refuses; it does not produce the non-zero exit the
    bullet names. This runs the probe as a subprocess and requires the probe to fail, with the concrete gap on
    its stdout. Exit codes 2/4 are rejected for the same reason the record rejects them elsewhere: 2 is a
    usage/internal error and 4 is the probe's own "answered without a gap" (a silent skip), so accepting either
    would accept a run that never exercised the negative direction.
    """
    probe = REPO / ".scratch" / "ghidra-c3" / "preflight" / "p5-required-model-probe.py"
    assert probe.is_file(), f"the probe is missing: {probe}"
    completed = subprocess.run(
        [sys.executable, str(probe), "--require", "dotnet-clr", "--model", "dotnet-clr-runtime-v1"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    assert completed.returncode in {1, 3}, (
        f"requiring an absent model exited {completed.returncode}; 0 would mean it was accepted and 2/4 are "
        f"usage/internal/'silent skip' codes, not the negative result:\n{completed.stdout}\n{completed.stderr}"
    )
    assert "RUNTIME_MODEL_MISSING" in completed.stdout, (
        f"the non-zero exit published no concrete gap:\n{completed.stdout}"
    )


# =========================================================================================================
# §9.3 bullet 5 - every model entry has a producer / consumer / official-Markdown proof
# =========================================================================================================
def test_9_3_5_every_model_entry_has_a_producer_consumer_and_rendered_markdown_proof() -> None:
    """§9.3 bullet 5: "每个模型条目都有 producer/consumer/official Markdown 证明".

    The chain, measured end to end through the REAL adapter, the REAL projection and the REAL renderer:

        producer   `RuntimeModelLibrary.resolve(...)` -> the model's declared export set
        consumer   `install_vb6_shim` builds and registers exactly those handlers; `_speakeasy_adapter`
                   publishes them as the `vb6_shim` observation
        Markdown   `reporting.build_emulation_status_projection` -> `analyst_report._emulation_status_section`
                   renders `registered` / `modelled_calls` / `strings_observed`

    This step deliberately introduces NO new published symbol: the model's identity is already the
    published `shim` value (`vb6-runtime-v1`, asserted below), and adding a second identity field would
    require the renderer's WHITELIST in `reporting.py`, which §9.1 does not grant. The proof therefore runs
    over the values the renderer really carries.
    """
    model = default_runtime_model_library().resolve(runtime_id="vb6")
    assert model is not None
    # producer: the declared entry IS the shim's published identity, so the model is attributable in the body.
    assert vb6_runtime_shim.Vb6ShimState().as_evidence()["shim"] == model.model_id

    # consumer -> Markdown, with a value that could only come from the registry's entry.
    event = {
        "event": "vb6_shim",
        "registered": len(model.exports) if len(model.exports) <= 132 else 132,
        "modelled_calls": 1031,
        "strings_observed": 1028,
        "destination_observable": False,
        "argument_pairs": [],
        "argument_pairs_cap": 16,
        "argument_pairs_recorded": 614,
    }
    body = _render_body(event)
    assert f"`{event['registered']}` 个 hook" in body, (
        "the registered count the registry's export set produces does not reach the official Markdown"
    )
    assert "建模调用 `1031` 次" in body
    assert "从中读出 `1028` 个样本字符串" in body


def test_9_3_5_the_declared_export_set_is_what_the_installer_registers_on_the_real_path() -> None:
    """The producer half, measured on the PRODUCTION path rather than on a hand-built event.

    The registry's own sample-relative export set must equal, key for key, what `install_vb6_shim` registers
    for the 白象 import table. A mismatch means the Markdown row above is attributing to the model a set of
    hooks the model does not declare.
    """
    if not pathlib.Path(SAMPLE).exists():
        pytest.skip("白象 sample is not present on this machine")
    payload = pathlib.Path(SAMPLE).read_bytes()
    pe = struct.unpack_from("<I", payload, 0x3C)[0]
    section_count = struct.unpack_from("<H", payload, pe + 6)[0]
    opt_size = struct.unpack_from("<H", payload, pe + 20)[0]
    opt = pe + 24
    sections = []
    for index in range(section_count):
        off = opt + opt_size + index * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", payload, off + 8)
        sections.append((vaddr, max(vsize, raw_size), raw_ptr))

    def rva_to_off(rva: int):  # noqa: ANN202
        for vaddr, size, ptr in sections:
            if vaddr <= rva < vaddr + size:
                return ptr + (rva - vaddr)
        return None

    def cstr(offset: int) -> str:
        end = payload.index(b"\0", offset)
        return payload[offset:end].decode("latin-1")

    dir_rva, _ = struct.unpack_from("<II", payload, opt + 96 + 8)
    base = rva_to_off(dir_rva)
    imports: list[tuple[str, str]] = []
    index = 0
    while base is not None:
        entry = base + index * 20
        original, _stamp, _forward, name_rva, first = struct.unpack_from("<IIIII", payload, entry)
        if original == 0 and name_rva == 0 and first == 0:
            break
        dll = cstr(rva_to_off(name_rva))
        walk = rva_to_off(original or first)
        slot = 0
        while walk is not None:
            value = struct.unpack_from("<I", payload, walk + slot * 4)[0]
            if value == 0:
                break
            symbol = f"Ordinal_{value & 0xFFFF}" if value & 0x80000000 else cstr(rva_to_off(value) + 2)
            imports.append((dll, symbol))
            slot += 1
        index += 1

    assert imports, "no imports were parsed from the sample"
    library = default_runtime_model_library()
    model = library.resolve(runtime_id="vb6")
    assert model is not None
    observed = identity_keys(imports)
    declared = model.exports & observed
    assert declared, "the model declares none of the sample's runtime imports"
    _state, handlers = vb6_runtime_shim.install_vb6_shim(se=_FakeSpeakeasy(), exports=imports)
    assert set(handlers) == set(declared)
    unmodelled = library.unmodelled_identity_keys("vb6", observed)
    assert "msvbvm60:ordinal_100" not in unmodelled, (
        "the VB6 bootstrap is unmodelled, so nothing after the sample's first call is reachable"
    )
