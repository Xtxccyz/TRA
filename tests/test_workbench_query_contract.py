"""P3.6 contract: the read-only query slice's host pin, its layer, its delegations AND that it stays read-only.

WHY THIS FILE EXISTS. Same reasons as `tests/test_report_revision_writer_contract.py` (the pin's authority must be a
TRACKED test, not a gitignored instrument), plus one that is specific to this slice: plan §P3.6's success criterion is
that **a query never changes a snapshot or a revision**, so "read-only" is asserted here rather than described in a
docstring. A later slice that turns a reader into a writer would still import cleanly and pass every structural gate -
this test is what stops that.

WHAT IT PINS DOWN:
* the pin is EXACTLY the receiver set, in both directions (a missing member is a runtime `NameError`; an unused one is
  dead interface), and it is exactly 14 members - the P3.6-2 additions are asserted as a COUNT as well as by name,
  because "three names the earlier slice deliberately left off" is the whole content of that step;
* the Protocol declares exactly the pin;
* the module never imports `service`, and - added by P3.6-2 - never imports the `investigation` or `emulation`
  IMPLEMENTATION modules either. That second assertion is the one the import gate CANNOT provide: the gate is a flat
  node registry plus a deny-list of edges, and `workbench_query` is a source in none of them, so an unlisted
  `workbench_query -> investigation.investigation` edge is invisible to `--strict` (docs/import-policy.json
  `_recorded_allowed_edges_note` states the blind spot; `.scratch/p36-canfail.py`-style proof: see
  `.scratch/p36-2-canfail.py` T4);
* the module's LAYER is pinned: `workbench_query` is registered by `recorded_allowed_edges` and is a source in no
  `forbidden_edges` pair, so a later step cannot quietly declare the module a different layer;
* every delegation forwards every signature parameter (this phase shipped a dropped parameter twice);
* each delegation's `__doc__` equals its implementation's (the mover dropped docstrings for eleven of eleven members
  until P3.4-2 fixed it);
* the P3.6-2 body's `catalog` parameter is a real parameter, not a module-level import: option (c) of the design's
  section 6.3, asserted directly so a revert to option (b) cannot pass by re-importing;
* **no moved body writes to the session** - the read-only property, as a behavioural assertion on the AST.
"""

from __future__ import annotations

import ast
import inspect
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from threat_report_agent import service, workbench_query  # noqa: E402

MODULE_PATH = pathlib.Path(workbench_query.__file__)
MODULE_TREE = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
POLICY_PATH = pathlib.Path(__file__).resolve().parents[1] / "docs" / "import-policy.json"
MOVED_MEMBERS = (
    "task_view",
    "workbench_domain_view",
    "workbench_query_evidence",
    "model_configuration_view",
    "workbench_thread",
    "_config_route_view",
    "_unique_execution_threads_for_view",
    "workbench_capabilities",
)
#: MEASURED, DO NOT EDIT WITHOUT RE-MEASURING (`py .scratch/p36-2-capability-keys.py`): 11 pinned members before
#: P3.6-2, + `THREAT_CONTEXT_PROTOCOL`, + `THREAT_TOOL_CONTRACT_VERSION`, + `_analysis_planner_payload` (the three
#: names the P3.6-1 slice deliberately left off because its bodies did not read them) = 14. The MEASURED bodies agree:
#: the bidirectional assertion below fails if this count and the receiver set disagree.
HOST_PIN_SIZE = 14
#: `execute` and `text` are included because the Standards review of P3.6-1 measured that banning only the ORM #: session verbs would let `session.execute(update(...))` through - and the same measurement showed NO moved body #: calls `execute` at all, so the wider list cannot produce a false positive here. KNOWN LIMIT, recorded rather than #: hidden: the receiver match accepts `session`, `host` and `*.database`, so a derived handle (`handle = #: session.connection(); handle.add(...)`) still escapes; widening further needs a receiver analysis of its own.
WRITES = ("add", "delete", "flush", "commit", "merge", "execute", "text")


#: The implementation modules this slice must NOT import, by name. See the header and
#: `test_the_module_never_imports_investigation_or_emulation_implementations` for why this cannot be delegated to
#: `check-import-graph.py --strict`.
BLOCKED_IMPLEMENTATION_MODULES: tuple[str, ...] = (
    "threat_report_agent.investigation.investigation",
    "threat_report_agent.investigation.coordinator",
    "threat_report_agent.investigation.derivation",
    "threat_report_agent.emulation.controlled_emulation",
    "threat_report_agent.emulation.emulation_plan",
    "threat_report_agent.emulation.vb6_runtime_shim",
)


#: The module-level functions that are NOT moved slice bodies, because they are this module's own machinery. Both are
#: `travelling` names from P3.6-1 (`docs/p36-workbench-query-design-20260922.md` section 3): their only readers are the
#: moved bodies, so they are module functions here rather than host-pin members. They are listed rather than pattern
#: matched, so adding a THIRD undeclared public function to the module fails
#: `test_moved_members_are_exactly_the_modules_public_functions`.
SLICE_MACHINERY: tuple[str, ...] = (
    "_config_route_view",
    "_unique_execution_threads_for_view",
)


def _module_functions() -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in MODULE_TREE.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _imported_names() -> set[str]:
    """Every imported dotted name, normalised to its ABSOLUTE form.

    MEASURED defect this normalisation fixes: the module imports the pure policy function RELATIVELY
    (`from .emulation.policy import simulation_policy_from_settings`), so the raw AST spelling is
    `emulation.policy.simulation_policy_from_settings` - and an assertion written against the absolute spelling
    failed with a message that read as "the import is missing" when the import was present. The package name is
    therefore prepended for `ImportFrom` nodes that carry a level, using the module's own `__package__`.
    """
    package = workbench_query.__package__ or "threat_report_agent"
    absolute: set[str] = set()
    for node in ast.walk(MODULE_TREE):
        if isinstance(node, ast.Import):
            absolute.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                keep = len(parts) - (node.level - 1)
                base = ".".join([*parts[:keep], base]) if base else ".".join(parts[:keep])
            absolute.add(base)
            absolute.update(f"{base}.{alias.name}" for alias in node.names)
    return absolute


def _host_receivers() -> set[str]:
    receivers: set[str] = set()
    for node in _module_functions().values():
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Name)
                and child.value.id == "host"
            ):
                receivers.add(child.attr)
    return receivers


def _protocol_members() -> set[str]:
    for node in MODULE_TREE.body:
        if isinstance(node, ast.ClassDef) and node.name == "WorkbenchQueryReaderHost":
            declared = set()
            for body in node.body:
                if isinstance(body, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    declared.add(body.name)
                elif isinstance(body, ast.AnnAssign) and isinstance(body.target, ast.Name):
                    declared.add(body.target.id)
            return declared
    raise AssertionError("WorkbenchQueryReaderHost is not declared in workbench_query.py")


def test_pin_equals_the_receivers_the_moved_bodies_actually_read() -> None:
    pin = set(workbench_query.WORKBENCH_QUERY_HOST_MEMBERS)
    receivers = _host_receivers()
    assert pin == receivers, (
        f"pin and bodies disagree: only in pin {sorted(pin - receivers)}, only in bodies "
        f"{sorted(receivers - pin)}"
    )


def test_moved_members_are_exactly_the_modules_public_functions() -> None:
    """`MOVED_MEMBERS` is EXACTLY the module's function set - asserted in BOTH directions.

    MEASURED COVERAGE HOLE this closes, found by `.scratch/p36-2-canfail.py` tamper T3 and NOT by any other check:
    dropping `"workbench_capabilities"` from `MOVED_MEMBERS` made the whole contract suite PASS. The reason is that
    every other loop in this file iterates `MOVED_MEMBERS`, so removing an entry does not fail a loop - it REMOVES
    COVERAGE from the delegation gate, the docstring gate and the read-only sweep, silently. That is the same class of
    defect as the P3.6-1 pin deviation: a list that is trusted as the definition of the slice, with nothing holding it
    to the slice.
    """
    declared = set(MOVED_MEMBERS)
    public_functions = {
        name for name in _module_functions() if not name.startswith("_")
    }
    machinery = {name for name in SLICE_MACHINERY}
    measured = public_functions | machinery
    assert measured == declared, (
        "MOVED_MEMBERS and the module's function set disagree: only in MOVED_MEMBERS "
        f"{sorted(declared - measured)}, only in the module {sorted(measured - declared)}. A new moved body must be "
        "declared (or listed in SLICE_MACHINERY if it is private machinery), and a member that moved away must be "
        "removed - a loop over a shorter MOVED_MEMBERS would simply stop checking"
    )
    # The private helpers are not assertions-free either: they must at least be REAL module functions.
    assert machinery <= set(_module_functions()), (
        f"SLICE_MACHINERY names something that is not a module-level function: {sorted(machinery - set(_module_functions()))}"
    )


def test_protocol_declares_exactly_the_pin() -> None:
    assert _protocol_members() == set(workbench_query.WORKBENCH_QUERY_HOST_MEMBERS)


def test_module_never_imports_service() -> None:
    offenders = sorted(name for name in _imported_names() if "service" in name.split("."))
    assert not offenders, f"workbench_query.py imports the service layer: {offenders}"


def test_the_module_never_imports_investigation_or_emulation_implementations() -> None:
    """P3.6-2's central negative assertion: the slice gets `ActionCatalog` as a PARAMETER, never as an import.

    WHY THIS TEST EXISTS AND NOT ONLY THE IMPORT GATE (measured by the design's section 8.2, re-measured on this
    tree): `scripts/check-import-graph.py` polices a DENY-LIST of edges plus a per-NODE registry.
    `workbench_query` appears as a SOURCE in no `forbidden_edges` pair, and it is registered (through
    `recorded_allowed_edges`, `["workbench_query", "models"]`), so
    `from threat_report_agent.investigation.investigation import ActionCatalog` inside this module makes
    `--strict` print "no new cycles and no new reverse edges" and stay GREEN.
    `docs/import-policy.json`'s `_recorded_allowed_edges_note` says so itself: "an unlisted edge cannot be
    machine-checked at all". This assertion is therefore the only machine check of the design's option (c), and
    `.scratch/p36-2-canfail.py` tamper T4 is the proof that it FAILS when the import is added back.

    The membership test is deliberately BOTH directions (`name == blocked` or `name.startswith(blocked + ".")` for
    a submodule target, and `blocked.startswith(name + ".")` for a package re-export reached as
    `threat_report_agent.investigation`), because `from threat_report_agent.investigation import ActionCatalog`
    reads the package facade rather than the implementation module and is the same defect in a shorter spelling.
    """
    imports = _imported_names()
    offenders = sorted(
        name
        for name in imports
        if any(
            name == blocked
            or name.startswith(f"{blocked}.")
            or blocked.startswith(f"{name}.")
            or name.startswith("threat_report_agent.investigation")
            for blocked in BLOCKED_IMPLEMENTATION_MODULES
        )
    )
    assert not offenders, (
        f"workbench_query.py imports an implementation module it must receive as a parameter: {offenders}. "
        "P3.6-2 design section 6.3 option (c) requires the host to construct `ActionCatalog` and hand it over; "
        "importing it here adds an edge `check-import-graph.py --strict` cannot see"
    )
    # The allowed `emulation` import is the PURE policy module only (`docs/p36-workbench-query-design-20260922.md`
    # line 44 records that decision: policy.py is stdlib-only, so importing it drags nothing in). Pin it so a later
    # edit cannot widen it silently. Both the module and the FROM-name appear in the set, which is why the check is a
    # pair rather than one string - MEASURED, after the first version of this assertion failed on the second spelling.
    policy_module = "threat_report_agent.emulation.policy"
    policy_name = f"{policy_module}.simulation_policy_from_settings"
    emulation_imports = sorted(name for name in imports if "emulation" in name.split("."))
    assert set(emulation_imports) <= {policy_module, policy_name}, (
        f"the only emulation import allowed in this slice is the pure policy module and its from-name; "
        f"measured {emulation_imports}"
    )
    assert policy_name in emulation_imports, (
        "the pure-policy import disappeared, so the capability payload's emulation section must have changed source"
    )


def test_the_layer_of_this_module_is_pinned_by_the_policy() -> None:
    """`workbench_query`'s layer decision lives in `docs/import-policy.json`, so it is asserted from there.

    MEASURED: the module is NOT in `known_modules` (it is a root-package module, and the registry is the UNION of
    every policy entry - `scripts/check-import-graph.py` lines 274-285), it IS in `recorded_allowed_edges` through
    `["workbench_query", "models"]`, and it is a SOURCE in NO `forbidden_edges` pair. Those three readings together
    are the layer: the design's section 2 line 46-49 assigns it the `report/` rule as its row, with the single
    recorded exception being `models`. A later step that changes the layer must change this file deliberately, and
    this assertion makes that visible instead of silent.
    """
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    allowed = {tuple(str(item) for item in pair) for pair in policy.get("recorded_allowed_edges", [])}
    assert ("workbench_query", "models") in allowed, (
        "the `workbench_query -> models` decision is no longer registered in docs/import-policy.json"
    )
    forbidden_sources = {
        str(pair[0]) for pair in policy.get("forbidden_edges", []) if len(pair) == 2
    }
    assert "workbench_query" not in forbidden_sources, (
        "workbench_query became a source in `forbidden_edges`; re-measure the layer before changing that"
    )
    assert (MODULE_PATH.parent / "workbench_query.py").is_file() and MODULE_PATH.name == "workbench_query.py", (
        "the module's HOME is src/threat_report_agent/workbench_query.py (a root-package module); it has not moved"
    )


def test_the_host_pin_is_exactly_the_fourteen_members_this_slice_needs() -> None:
    """The pin's SIZE is pinned too, because P3.6-2's whole content is the three members it ADDS.

    MEASURED before adding them (design section 5.4, re-run on this tree by `.scratch/p36-2-hostpins-now.py`):
    `THREAT_CONTEXT_PROTOCOL`, `THREAT_TOOL_CONTRACT_VERSION` and `_analysis_planner_payload` appear in ZERO of the
    five `*_HOST_MEMBERS` tuples in the repository, so pinning them cannot break another module's pin read - which is
    exactly the accident that cost 37 tests when `_CATALOG_HOW_SEED_SCAN_LIMIT` was judged to travel. 11 + 3 = 14.
    """
    pin = workbench_query.WORKBENCH_QUERY_HOST_MEMBERS
    assert len(pin) == HOST_PIN_SIZE, (
        f"the host pin has {len(pin)} members, expected {HOST_PIN_SIZE}; P3.6-2 added exactly "
        "THREAT_CONTEXT_PROTOCOL, THREAT_TOOL_CONTRACT_VERSION and _analysis_planner_payload to the 11 recorded by "
        "P3.6-1"
    )
    assert len(set(pin)) == len(pin), "the pin has a duplicate member"
    added_by_this_step = {"THREAT_CONTEXT_PROTOCOL", "THREAT_TOOL_CONTRACT_VERSION", "_analysis_planner_payload"}
    assert added_by_this_step <= set(pin), (
        f"the members P3.6-2 is named for are missing from the pin: {sorted(added_by_this_step - set(pin))}"
    )


def test_the_capability_body_takes_the_catalog_as_a_parameter() -> None:
    """Option (c) asserted as a SHAPE: `workbench_capabilities(host, catalog)`, both real parameters.

    A version that imported the catalog and took only `host` would still satisfy the pin/receiver assertions (it would
    not read `host.catalog`), so this is the check that distinguishes option (c) from option (b) without reading the
    prose. The `ActionCatalogProjection` Protocol is asserted to exist for the same reason: the module needs the
    catalog's SHAPE, and it must describe that shape locally rather than import the class.
    """
    body = _module_functions()["workbench_capabilities"]
    parameters = [argument.arg for argument in body.args.args]
    assert parameters == ["host", "catalog"], (
        f"the moved body takes {parameters}; P3.6-2 design section 6.3 option (c) requires the catalog to arrive as "
        "a parameter from the delegation"
    )
    assert "catalog" in MODULE_PATH.read_text(encoding="utf-8"), "unreachable"
    protocols = {
        node.name: node for node in MODULE_TREE.body if isinstance(node, ast.ClassDef)
    }
    assert "ActionCatalogProjection" in protocols, (
        "the catalog's local shape Protocol is gone; the module must describe the catalog without importing it"
    )
    projection_members = {
        member.name for member in protocols["ActionCatalogProjection"].body if isinstance(member, ast.FunctionDef)
    }
    assert projection_members == {"names", "require"}, (
        f"ActionCatalogProjection declares {sorted(projection_members)}; it must declare exactly what the body uses"
    )


def test_the_capability_delegation_supplies_the_catalog() -> None:
    """The OTHER half of option (c): the service constructs the catalog and passes it in.

    BEHAVIOURAL, and it does NOT use `getsource`: a stand-in catalog that reports its own emptiness is handed to the
    real method, with the moved body replaced by a recorder, and the assertion is on what the delegation actually
    passed. Two directions, so neither half can pass alone:

    * `catalog=None` (what the single production caller, `main.py:789`, does) must reach the moved body with a REAL
      `ActionCatalog` whose name list is non-empty - otherwise the payload's 18 actions silently disappear;
    * an explicit catalog must be forwarded AS GIVEN rather than replaced, which is the property the earlier-slice
      delegation gate (`test_every_delegation_forwards_every_parameter`) checks by sentinel and which a
      `catalog or ActionCatalog.default()` written the other way round would break.
    """
    import threat_report_agent.investigation as investigation_package

    real_catalog_type = investigation_package.investigation.ActionCatalog
    sentinel = object()
    seen: dict[str, object] = {}

    def fake(host, catalog):
        seen["host"] = host
        seen["catalog"] = catalog
        return {"DELEGATED": True}

    original = workbench_query.workbench_capabilities
    workbench_query.workbench_capabilities = fake
    try:
        instance = object.__new__(service.AnalysisService)
        assert service.AnalysisService.workbench_capabilities(instance) == {"DELEGATED": True}
        assert seen["host"] is instance, "the delegation passed something other than itself as the host"
        assert isinstance(seen["catalog"], real_catalog_type), (
            "the delegation did not construct an ActionCatalog when none was supplied; the production caller "
            "(main.py:789) passes nothing, so a lazy/None default would empty the advertised action list"
        )
        assert list(seen["catalog"].names()), "the constructed catalog is empty, so the payload would lose its actions"

        service.AnalysisService.workbench_capabilities(instance, sentinel)
        assert seen["catalog"] is sentinel, (
            "an explicitly supplied catalog was replaced instead of forwarded; the delegation must pass it through"
        )
    finally:
        workbench_query.workbench_capabilities = original


def test_moved_names_exist_in_both_homes() -> None:
    for name in MOVED_MEMBERS:
        assert hasattr(workbench_query, name), f"{name} is not defined in workbench_query.py"
        assert hasattr(service.AnalysisService, name), f"service.AnalysisService lost its {name} delegation"


def test_the_slice_is_read_only() -> None:
    """Plan §P3.6's success criterion, asserted rather than described: no moved body writes to the session.

    MEASURED AT DESIGN TIME: all seven bodies contain zero `session.add`/`delete`/`flush`/`commit`/`merge` calls; the
    `scalars`/`scalar` calls they do contain are SELECT reads. The `workbench_*` members that DO write (submit_action,
    write_report_file, start_static_analysis, model_complete, link_session, evidence purge, unbind_analysis) and the one
    that DRIVES analysis (wait_for_analysis_update) were deliberately left in `service.py`, so this assertion also
    documents the boundary of the slice.
    """
    offenders: list[str] = []
    for name, node in _module_functions().items():
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            if not isinstance(func, ast.Attribute) or func.attr not in WRITES:
                continue
            owner = func.value
            if isinstance(owner, ast.Name) and owner.id in {"session", "host"}:
                offenders.append(f"{name}: {ast.unparse(child)[:60]}")
            elif isinstance(owner, ast.Attribute) and owner.attr == "database":
                offenders.append(f"{name}: {ast.unparse(child)[:60]}")
    assert not offenders, f"the read-only slice now writes to the session: {offenders}"


def test_every_delegation_forwards_every_parameter(monkeypatch) -> None:
    """The delegation-shape gate, checked BEHAVIOURALLY (a sentinel per parameter), never with `getsource`."""
    for name in MOVED_MEMBERS:
        original = getattr(workbench_query, name)
        static = inspect.getattr_static(service.AnalysisService, name)
        raw = static.__func__ if isinstance(static, (classmethod, staticmethod)) else static
        signature = inspect.signature(original)
        takes_host = "host" in signature.parameters
        record: dict[str, object] = {}

        def fake(*args, **kwargs):
            record["args"] = args
            record["kwargs"] = kwargs
            return "DELEGATED"

        monkeypatch.setattr(workbench_query, name, fake)
        sentinels = {
            parameter.name: object()
            for parameter in signature.parameters.values()
            if parameter.name != "host"
        }
        receiver = object()
        args: list[object] = [receiver] if not isinstance(static, staticmethod) else []
        kwargs: dict[str, object] = {}
        for parameter in signature.parameters.values():
            if parameter.name == "host":
                continue
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD):
                args.append(sentinels[parameter.name])
            else:
                kwargs[parameter.name] = sentinels[parameter.name]
        assert raw(*args, **kwargs) == "DELEGATED", f"{name}: the delegation did not reach the moved function"
        expected = ([receiver] if takes_host else []) + [
            sentinels[p.name] for p in signature.parameters.values()
            if p.name != "host" and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        assert record["args"] == tuple(expected), (
            f"{name}: the moved function received {len(record['args'])} positional argument(s), expected {len(expected)}"
        )
        assert record["kwargs"] == kwargs, f"{name}: keyword-only parameters were not forwarded verbatim"
        monkeypatch.undo()


def test_delegations_keep_the_implementations_docstring() -> None:
    for name in MOVED_MEMBERS:
        assert getattr(service.AnalysisService, name).__doc__ == getattr(workbench_query, name).__doc__, (
            f"{name}: the delegation and the implementation document themselves differently"
        )


def test_lifecycle_delegations_are_plain_instance_methods() -> None:
    for name in MOVED_MEMBERS:
        attribute = inspect.getattr_static(service.AnalysisService, name)
        assert not isinstance(attribute, (classmethod, staticmethod)), f"{name} gained a decorator"


#: The capability payload's TOP-LEVEL keys, MEASURED at runtime by `.scratch/p36-2-capability-keys.py` (captured in
#: `.scratch/p36-2-keys-after.txt`, which also shows the payload byte-identical across the P3.6-2 move). The design's
#: section 6.4 asked for this assertion and the step left it optional; it is a SUPERSET check for the same reason the
#: view pins are: an added key must stay free, while a dropped or renamed one fails loudly.
REQUIRED_CAPABILITY_KEYS = {
    "action_submission_tool",
    "actions",
    "analysis_planner_model",
    "api_version",
    "backend_static_action_catalog",
    "capability_profile",
    "isolated_emulation",
    "model_callable_tools",
    "network_access",
    "profiles",
    "sample_execution",
    "session_context_protocol",
    "static_only",
    "tool_contract_version",
    "unavailable_capabilities",
    "workspace",
}


def test_the_capability_payload_keeps_its_top_level_key_set(test_settings) -> None:
    """The capability contract's field set must not silently shrink - the same rule the two view projections follow."""
    from threat_report_agent.content_store import LocalContentStore
    from threat_report_agent.database import Database

    database = Database(test_settings.database_url)
    database.create_schema()
    instance = service.AnalysisService(
        test_settings, database, LocalContentStore(test_settings.content_store_path)
    )
    payload = instance.workbench_capabilities()
    missing = REQUIRED_CAPABILITY_KEYS - set(payload)
    assert not missing, (
        f"workbench_capabilities dropped or renamed top-level key(s) {sorted(missing)}; the measured key set is "
        f"{sorted(REQUIRED_CAPABILITY_KEYS)} and the payload returned {sorted(payload)}"
    )
    # The two keys whose CONTENT the design measured alongside the key set, so a payload that kept the keys but emptied
    # the values is caught here rather than by a reader noticing.
    assert len(payload["actions"]) == 18, (
        f"`actions` should carry the full static action catalog (18 names, measured); it carries {len(payload['actions'])}"
    )
    assert payload["model_callable_tools"], "`model_callable_tools` is empty"
    assert payload["analysis_planner_model"], "`analysis_planner_model` is empty"
