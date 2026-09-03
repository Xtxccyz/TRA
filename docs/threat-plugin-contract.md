# Threat Plugin Contract v1

Threat plugins are out-of-tree modules loaded by a DSH profile. They expose
one or more of these roles:

`ThreatToolProvider`, `ThreatContextProvider`, `ThreatViewProvider`,
`ThreatEventProjector`, `ThreatReportSectionProvider`, and
`ThreatModelGatewayAdapter`.

Every plugin has a manifest with `id`, semantic `version`, `plugin_api: 1`,
capabilities, compatible backend/event versions, and permitted security
profiles. Registration is effect based: disposing the plugin unregisters its
tools, listeners, views, and event declarations.

Model-facing tools must use DSH `defineTool`, return a bounded JSON value, and
call `/api/v1/workbench/*`. They must never open database/object-store
connections or invoke workers directly. Action requests include a hypothesis,
reason, target selector, expected evidence kinds, success condition, and
failure interpretation.

The template plugin adds a read-only evidence summary tool, a session event,
and a keyed view. `tests/pluginability_acceptance.py` verifies load, use,
replay, and unload without changing the DSH upstream checkout.
